"""Disk images and virtual machine disks: `logharvest image DISK --case C`.

Reads the image directly with the pure-Python `dissect.target` library (pip install "dissect.target[full]"):
  * no mounting, no root/Administrator, no drivers, the same on Linux, Windows and macOS hosts
  * formats: raw/dd/img, E01/Ex01 (EnCase), qcow2, vmdk, vhd, vhdx, vdi, VM folders (ova/vmx/...)
  * partition tables (MBR, GPT, LVM, ...) and file systems: NTFS, ext2/3/4, XFS, btrfs, FAT/exFAT, APFS, FFS, ...
The image is only ever opened for reading. Its SHA-256 is taken before and after (`--hash`), so the case proves it
did not change. Every file collected keeps its own access / modified / changed / created times from the guest file
system (not the host's), and its `source` reads image://<image>/fsN:type/<path inside the guest>.

Not supported (reported, never silently skipped): encrypted volumes (BitLocker, LUKS, FileVault) without keys,
HFS+ (use a Mac, or mount it and pass --source), and anything dissect does not recognise.
"""
import getpass, hashlib, json, platform, re, struct, sys
from datetime import datetime, timezone
from pathlib import Path

from . import desktop as D
from .detect import identify_os
from .progress import Progress, Spinner
from .rules import rules_for, add_profile_args
from .smartwalk import smart_walk, SweepStats, DEFAULT_MAX_DEPTH, add_scope_args, scope_from_args

def now(): return datetime.now(timezone.utc).isoformat()

INSTALL_HINT = 'Disk-image support needs the dissect library:  pip install "dissect.target[full]"'


# ------------------------------------------------------------------ what is this file?
def detect_format(path):
    try:
        with open(path, "rb") as f:
            head = f.read(4096); size = path.stat().st_size
            f.seek(max(size - 512, 0)); tail = f.read(512)
    except OSError: return "unreadable"
    if head[:4] == b"QFI\xfb": return "qcow2"
    if head[:4] == b"KDMV" or head.startswith(b"# Disk DescriptorFile"): return "vmdk"
    if head[:8] == b"vhdxfile": return "vhdx"
    if head[:8] == b"conectix" or tail[:8] == b"conectix" or tail[-512:-504] == b"conectix": return "vhd"
    if head[64:68] == b"\x7f\x10\xda\xbe": return "vdi"
    if head[:8] == b"EVF\x09\x0d\x0a\xff\x00": return "e01"
    if head[:8] == b"EVF2\x0d\x0a\x81\x00": return "ex01"
    if path.suffix.lower() in (".ova", ".ovf", ".vmx", ".vbox"): return path.suffix.lower().lstrip(".")
    return "raw"


def image_files(path, _seen=None):
    """The image plus every file it depends on, so all of them get hashed: E01 segments, VMDK extents, qcow2 backing files."""
    _seen = _seen if _seen is not None else set()
    path = path.resolve()
    if path in _seen or not path.is_file(): return []
    _seen.add(path); out = [path]; fmt = detect_format(path)
    if fmt in ("e01", "ex01"):
        for sib in sorted(path.parent.glob(path.stem + ".[Ee][0-9][0-9]")) + sorted(path.parent.glob(path.stem + ".[Ee]x[0-9][0-9]")):
            if sib.resolve() not in _seen: _seen.add(sib.resolve()); out.append(sib.resolve())
    elif fmt == "vmdk" and path.stat().st_size < 65536:
        try:
            for m in re.finditer(r'^(?:RW|RDONLY|NOACCESS)\s+\d+\s+\w+\s+"([^"]+)"', path.read_text("utf-8", "replace"), re.M):
                out += image_files(path.parent / m.group(1), _seen)
        except OSError: pass
    elif fmt == "qcow2":
        try:
            with open(path, "rb") as f:
                h = f.read(32); off, ln = struct.unpack(">QI", h[8:20])
                if off and ln:
                    f.seek(off); name = f.read(ln).decode("utf-8", "replace"); out += image_files(path.parent / name, _seen)
        except (OSError, struct.error): pass
    return out


def hash_files(files, label):
    """SHA-256 of each file, with a progress bar. -> {path: hexdigest}"""
    res = {}
    total = sum(max(f.stat().st_size >> 20, 1) for f in files)
    with Progress(label, total, "MB") as bar:
        for f in files:
            h = hashlib.sha256()
            with open(f, "rb") as fh:
                while chunk := fh.read(1 << 20): h.update(chunk); bar.update(1, 0, f.name)
            res[f] = h.hexdigest()
    return res


# ------------------------------------------------------------------ opening
def open_target(path):
    try: from dissect.target import Target
    except ImportError: raise SystemExit(INSTALL_HINT)
    import logging
    logging.getLogger("dissect").setLevel(logging.ERROR)                 # dissect warns about optional plugins; not useful here
    return Target.open(path)


def find_roots(t):
    """-> (roots, notes). roots: dicts(root, os, label, fstype). notes: things found but not collectable."""
    roots, notes = [], []
    t_os = str(getattr(t, "os", "") or "")
    unified = None
    if t_os in ("linux", "osx", "macos", "unix", "bsd"):
        try:
            r = t.fs.path("/"); o = identify_os(r)
            if o in ("linux", "macos"): unified = dict(root=r, os=o, label="fs:unified", fstype="mounted tree (all partitions as the guest mounts them)")
        except Exception as e: notes.append(f"unified view failed: {type(e).__name__}: {e}")
    if unified: roots.append(unified)
    else:
        for i, fs in enumerate(t.filesystems):
            ftype = str(getattr(fs, "__type__", type(fs).__name__))
            try: r = fs.path("/"); o = identify_os(r)
            except Exception as e: notes.append(f"fs{i}:{ftype}: could not be read ({type(e).__name__}: {e})"); continue
            if o in ("linux", "windows", "macos"): roots.append(dict(root=r, os=o, label=f"fs{i}:{ftype}", fstype=ftype))
            else: notes.append(f"fs{i}:{ftype}: no Linux/Windows/macOS system found on it (data or boot partition?)")
    for v in t.volumes:
        if getattr(v, "fs", None) is None:
            notes.append(f"volume {getattr(v, 'name', '?')} ({getattr(v, 'size', 0) >> 20} MB): no recognised file system "
                         "(encrypted with BitLocker/LUKS/FileVault, empty, or an unsupported type). NOT collected.")
    return roots, notes


def describe(img, t, roots, notes):
    L = [f"{img.name}: {detect_format(img)}, {img.stat().st_size >> 20} MB, {len(t.disks)} disk(s), {len(t.volumes)} volume(s)"]
    for i, v in enumerate(t.volumes):
        L.append(f"  volume {i}: {getattr(v, 'name', '?')}  {getattr(v, 'size', 0) >> 20} MB  fs={'yes' if getattr(v, 'fs', None) is not None else 'none'}")
    for r in roots: L.append(f"  -> {r['os']:8} {r['label']}")
    L += [f"  note: {n}" for n in notes]
    return L


# ------------------------------------------------------------------ collecting
def collect_rules(rec, root, os_name, cap, scope=None, profile=None):
    matches, seen = [], set()
    rules = rules_for(os_name, profile)
    with Progress("Matching log rules", len(rules), "rules") as bar:
        for category, pattern in rules:
            bar.update(1, 0, pattern)
            try:
                for p in root.glob(pattern, case_sensitive=False):
                    if p in seen or p.is_symlink() or not p.is_file(): continue
                    if scope and not scope.allows_rule_match(p.relative_to(root).as_posix().lower()): continue
                    seen.add(p); matches.append((category, p))
            except Exception as e: rec.nc("image:rule", f"{rec.prefix}/{pattern}", f"{type(e).__name__}: {e}")
    with Progress("Copying logs", len(matches), "files") as bar:
        for category, p in matches:
            bar.update(1, 0, p.name)
            got = rec.copy_rule(p, root, category, f"image:{category}", cap)
            if got: bar.bytes += got
    return seen


def sweep(rec, root, os_name, seen, cap, max_files, max_depth=DEFAULT_MAX_DEPTH, scope=None):
    """Smart walk of the whole guest file system for log-like files the rules did not name (see smartwalk.py)."""
    found, stats, unreadable = [], SweepStats(), []
    with Spinner("Sweeping image for other log-like files", unit="dirs") as sp:
        def tick(_d): sp.n = stats["dirs_visited"]
        for p in smart_walk(root, os_name, (), unreadable, stats, max_depth, tick, scope=scope):
            if p not in seen: found.append(p)
    for u in unreadable: rec.nc("image:sweep", f"{rec.prefix}/{u['path']}", u["error"])
    rec.audit("SWEEP " + " ".join(f"{k}={v}" for k, v in stats.items()) + f" limit={max_files}")
    for line in stats.skipped_examples[:40]: rec.audit(f"SWEEP skipped {line}")
    with Progress("Copying swept files", min(len(found), max_files), "files") as bar:
        for i, p in enumerate(sorted(found, key=str)):
            if i >= max_files:
                rec.nc("image:sweep", f"{rec.prefix}/", f"{len(found) - max_files} further candidates not copied (limit {max_files}; raise --max-files)"); break
            bar.update(1, 0, p.name)
            got = rec.copy_rule(p, root, "discovered", "image:sweep", cap)
            if got: bar.bytes += got


def process_image(a, img):
    img = img.resolve()
    if not img.exists(): print(f"ERROR: {img} not found"); return 1
    files = image_files(img); fmt = detect_format(img)
    print(f"{img.name}: {fmt}" + (f" (+{len(files) - 1} linked files)" if len(files) > 1 else ""))
    t0 = now(); before = hash_files(files, f"Hashing {img.name}") if a.hash != "none" else {}
    t = open_target(img)
    roots, notes = find_roots(t)
    if a.list:
        for line in describe(img, t, roots, notes): print(line)
        return 0
    if not roots:
        print("No Linux, Windows or macOS system found inside this image." + "".join(f"\n  note: {n}" for n in notes)); return 1
    a.case.mkdir(parents=True, exist_ok=True)
    cap = a.max_size_mb << 20; summary = []
    multi = len(roots) > 1
    for i, r in enumerate(roots):
        dev = re.sub(r"[^\w.-]+", "_", f"{r['os']}-{img.stem}" + (f"-{r['label'].split(':')[0]}" if multi else ""))
        print(f"\n== {dev}  ({r['label']}) ==")
        with D.Rec(a.case, r["os"], dev) as rec:
            rec.prefix = f"image://{img.name}/{r['label']}"
            rec.audit(f"START image={img} format={fmt} root={r['label']} os={r['os']} user={getpass.getuser()} host={platform.node()} "
                      f"python={sys.version.split()[0]} authority={getattr(a, 'authority', '')!r}")
            rec.audit("NOTE image opened read-only through dissect.target; timestamps below are the guest file system's own")
            scope = scope_from_args(a); bound = scope.bind(r["root"]) if scope else None
            if bound: rec.audit(f"SCOPE dirs={list(bound.dirs)} exclude={list(bound.exclude)} only_dirs={bound.only_dirs}")
            rec.audit(f"PROFILE {getattr(a, 'profile', None) or 'default'}")
            seen = collect_rules(rec, r["root"], r["os"], cap, bound, getattr(a, 'profile', None))
            if a.sweep or (bound and bound.dirs): sweep(rec, r["root"], r["os"], seen, cap, a.max_files, a.max_depth, scope)
            rec.audit(f"RULES done ok={rec.ok} not_collected={rec.nc_count}")
            summary.append((dev, rec.ok, rec.nc_count))
        try: D.post_collect(a.case, r["root"], r["os"], dev, a, source_prefix=f"image://{img.name}/{r['label']}")
        except Exception as e: print(f"  suspect analysis failed: {type(e).__name__}: {e}")
    after = hash_files(files, f"Re-hashing {img.name} (proof it was not changed)") if a.hash == "both" else {}
    unchanged = (before == after) if a.hash == "both" else None
    info = dict(image=str(img), format=fmt, files=[dict(path=str(f), size=f.stat().st_size, sha256_before=before.get(f), sha256_after=after.get(f)) for f in files],
                image_unchanged=unchanged, hash_mode=a.hash, started=t0, finished=now(), dissect=_ver(), partitions=describe(img, t, roots, notes),
                collected=[dict(device=d, files=ok, not_collected=nc) for d, ok, nc in summary])
    with D.Rec(a.case, roots[0]["os"], re.sub(r"[^\w.-]+", "_", f"{roots[0]['os']}-{img.stem}" + ("-fs0" if multi else ""))) as rec:
        adir = a.case / "analysis"; adir.mkdir(exist_ok=True); f = adir / f"image-{img.stem}.json"
        f.write_text(json.dumps(info, indent=1))
        rec.generated(f, "analysis", "image:source", f"analysis://image/{img.name}", derived=True)
        rec.audit(f"IMAGE {img.name} sha256_before={ {k.name: v for k, v in before.items()} } unchanged={unchanged}")
    if unchanged is False: print("WARNING: the image's hash CHANGED while it was being read. Treat the collection as unreliable.")
    elif unchanged: print(f"Image hash verified unchanged: {before[files[0]]}")
    return 0


def _ver():
    try:
        from importlib.metadata import version; return version("dissect.target")
    except Exception: return "unknown"


# ------------------------------------------------------------------ CLI
def add_args(ap):
    ap.add_argument("image", nargs="+", type=Path, help="disk image or VM disk (raw/dd, E01, qcow2, vmdk, vhd, vhdx, vdi, ...)")
    ap.add_argument("--case", type=Path, help="case folder (created if missing); not needed with --list")
    ap.add_argument("--list", action="store_true", help="only show the disks, partitions and systems found in the image")
    ap.add_argument("--hash", choices=["both", "before", "none"], default="both",
                    help="SHA-256 of the image: before and after reading (default), only before, or none (large images take a long time)")
    ap.add_argument("--sweep", "--all-dirs", dest="sweep", action="store_true", help="also look in EVERY directory of the guest for log-like files no rule covers (smart: skips caches, WinSxS, node_modules...)")
    add_scope_args(ap); add_profile_args(ap)
    ap.add_argument("--max-depth", type=int, default=DEFAULT_MAX_DEPTH, help="--sweep/--all-dirs: directory depth limit (log-named folders are always searched fully)")
    ap.add_argument("--max-files", type=int, default=5000, help="limit for --sweep (default 5000)")
    ap.add_argument("--max-size-mb", type=int, default=512, help="skip single files larger than this (default 512)")
    ap.add_argument("--authority", default="", help="warrant / consent reference, recorded in audit.log")
    D.add_collect_args(ap)


def run(a):
    if not a.list and not a.case: print("ERROR: --case is required (or use --list)"); return 2
    rc = 0
    for img in a.image: rc = max(rc, process_image(a, img))
    return rc
