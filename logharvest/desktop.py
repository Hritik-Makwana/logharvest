"""Suspect programs and their folders for Linux / Windows / macOS sources (live host or mounted image).

  * `logharvest collect` calls post_collect() after the normal log collection: it reads crash/hang/OOM evidence
    from the source (procsuspects.py), writes a ranked report to analysis/, then copies each suspect program's
    own folders (config, data, logs) with the same hash-before/hash-after verification as the rest of the case.
  * `logharvest desktop-apps` copies the folders of ALL programs found in the standard per-app locations.

What counts as a program's folder (matched case-insensitively on the program, exe folder or bundle id):
  Linux    ~/.config/<app>  ~/.local/share/<app>  ~/.var/app/<id>  ~/snap/<app>  ~/.<app>  /var/log/<app>
  Windows  Users\\*\\AppData\\{Roaming,Local,LocalLow}\\<app>   ProgramData\\<app>
  macOS    ~/Library/{Application Support,Containers,Group Containers,Logs,Saved Application State}/<app|bundle id>
           ~/Library/Preferences/<bundle id>*.plist   /Library/{Application Support,Logs}/<app>
Caches are skipped unless --include-cache. Install directories (the program's binaries) are not copied.
"""
import getpass, hashlib, json, os, platform, re, shutil, subprocess, sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import procsuspects as P
from .progress import Progress, say

UTC = timezone.utc
def now(): return datetime.now(UTC).isoformat()
def utc(ts): return datetime.fromtimestamp(ts, UTC).isoformat()

CACHE_DIRS = {"cache", "caches", "code cache", "gpucache", "shadercache", "cacheddata", "cache_data", "dawncache", "grshadercache"}
GENERIC = {"bin", "usr", "local", "lib", "sbin", "opt", "system32", "windows", "program files", "programfiles", "microsoft", "apple",
           "library", "applications", "contents", "macos", "common", "system", "share", "libexec", "x64", "x86", "unknown"}


def _sha(path, bufsize=1 << 20):
    h = hashlib.sha256()
    with path.open("rb") as f:                      # Path.open: works for real paths and for files inside disk images
        while chunk := f.read(bufsize): h.update(chunk)
    return h.hexdigest()


def norm(s): return re.sub(r"[^a-z0-9]", "", (s or "").lower())


class Rec:
    """Manifest + audit writer and verified copier for one source."""
    def __init__(self, case, os_name, dev):
        self.case, self.os, self.dev = case, os_name, dev
        self.ev = case / "evidence" / dev; self.ev.mkdir(parents=True, exist_ok=True)
        self.ok = self.nc_count = 0; self.copied = set()
        self.prefix = ""          # e.g. "image://disk.qcow2!/" so manifest sources say where a file came from inside an image
    def __enter__(self):
        self.mf = open(self.case / "manifest.jsonl", "a"); self.al = open(self.case / "audit.log", "a"); return self
    def __exit__(self, *e): self.mf.close(); self.al.close()
    def log(self, r): self.mf.write(json.dumps(r) + "\n"); self.mf.flush()
    def audit(self, m): self.al.write(f"{now()} {m}\n"); self.al.flush()
    def nc(self, rule, source, error, **extra):
        self.log(dict(device=self.dev, os=self.os, category="not_collected", rule=rule, source=str(source), collected_at=now(), error=error, **extra))
        self.nc_count += 1
    def generated(self, f, category, rule, source, **extra):
        """Record a file this tool produced inside the case (command output, analysis)."""
        t = now(); st = f.stat()
        self.log(dict(device=self.dev, os=self.os, category=category, rule=rule, source=source, collected_at=t, size=st.st_size,
                      modified=t, accessed=t, changed_or_created=t, sha256=_sha(f), dest=str(f.relative_to(self.case)), verified=True, **extra))
        self.ok += 1
    def copy(self, src, root, rule, per_file_cap, **extra):
        """Verified copy of one source file to evidence/<dev>/apps/<path relative to root>. -> bytes copied or None."""
        try: dest = self.ev / "apps" / Path(*src.relative_to(root).parts)
        except ValueError: self.nc(rule, self.prefix + str(src), "path is outside the source root", **extra); return None
        return self.copy_to(src, dest, rule, self.prefix + str(src), per_file_cap, **extra)

    def copy_rule(self, src, root, category, rule, per_file_cap, **extra):
        """Verified copy to evidence/<dev>/<path relative to root> (the layout `collect` uses)."""
        try: dest = self.ev / Path(*src.relative_to(root).parts)
        except ValueError: self.nc(rule, self.prefix + str(src), "path is outside the source root"); return None
        return self.copy_to(src, dest, rule, self.prefix + str(src), per_file_cap, category=category, **extra)

    def copy_to(self, src, dest, rule, source, per_file_cap, category="application", **extra):
        """Hash src, copy it to dest (inside the case), hash dest, record. -> bytes or None (a not_collected row is written)."""
        try:
            st = src.stat()                                     # before reading (atime)
            if st.st_size > per_file_cap: self.nc(rule, source, f"NOT COLLECTED: {st.st_size} bytes is over the per-file size cap", **extra); return None
            before = _sha(src)
            dest.parent.mkdir(parents=True, exist_ok=True)
            with src.open("rb") as fi, open(dest, "wb") as fo: shutil.copyfileobj(fi, fo, 1 << 20)
            os.utime(dest, (st.st_atime, st.st_mtime))
            after = _sha(dest)
            birth = getattr(st, "st_birthtime", None)
            if birth: extra.setdefault("created", utc(birth))                      # NTFS / APFS / ext4 creation time when the source has one
            self.log(dict(device=self.dev, os=self.os, category=category, rule=rule, source=source, collected_at=now(), size=st.st_size,
                          modified=utc(st.st_mtime), accessed=utc(st.st_atime), changed_or_created=utc(st.st_ctime), sha256=after,
                          dest=str(dest.relative_to(self.case)), verified=(before == after == _sha(src)), **extra))
            self.ok += 1; self.copied.add(source); return st.st_size
        except Exception as e:                                  # PermissionError, vanished file, long path ...
            self.nc(rule, source, f"{type(e).__name__}: {e}", **extra); return None

    def register(self, f, category, rule, source, **extra):
        """Record a file a tool already wrote inside the case (e.g. pulled by pymobiledevice3). Times are the file's own."""
        st = f.stat()
        self.log(dict(device=self.dev, os=self.os, category=category, rule=rule, source=source, collected_at=now(), size=st.st_size,
                      modified=utc(st.st_mtime), accessed=None, changed_or_created=None, sha256=_sha(f),
                      dest=str(f.relative_to(self.case)), verified=True, **extra))
        self.ok += 1


# ------------------------------------------------------------------ locating folders
def _children(d):
    try: return [c for c in d.iterdir()]
    except OSError: return []


def _homes(root, os_name):
    pats = {"linux": ["home/*", "root"], "macos": ["Users/*", "private/var/root"], "windows": ["Users/*"]}[os_name]
    out = []
    for pat in pats:
        try: out += [p for p in root.glob(pat, case_sensitive=False) if p.is_dir() and not p.is_symlink()]
        except OSError: pass
    return [h for h in out if h.name.lower() not in ("shared", "public", "default", "default user", "all users")] if os_name != "linux" else out


def _sub(base, rel):
    cur = base
    for part in rel.split("/"):
        nxt = next((c for c in _children(cur) if c.name.lower() == part.lower()), None)
        if nxt is None: return None
        cur = nxt
    return cur if cur.is_dir() else None


def app_roots(root, os_name, include_install=False):
    """-> list of (container directory, is_cache_root). Children of these are per-app folders."""
    r = []
    def add(base, rel, cache=False):
        d = _sub(base, rel)
        if d: r.append((d, cache))
    for h in _homes(root, os_name):
        if os_name == "linux":
            for rel in (".config", ".local/share", ".var/app", "snap"): add(h, rel)
            add(h, ".cache", True)
        elif os_name == "windows":
            for rel in ("AppData/Roaming", "AppData/Local", "AppData/LocalLow"): add(h, rel)
        else:
            for rel in ("Library/Application Support", "Library/Containers", "Library/Group Containers", "Library/Logs",
                        "Library/Saved Application State"): add(h, rel)
            add(h, "Library/Caches", True)
    if os_name == "linux": add(root, "var/log")
    if os_name == "windows": add(root, "ProgramData")
    if os_name == "macos":
        add(root, "Library/Application Support"); add(root, "Library/Logs")
    if include_install:                       # the programs' own install folders (binaries, bundled files)
        for rel in {"linux": ["opt"], "windows": ["Program Files", "Program Files (x86)"], "macos": ["Applications"]}[os_name]: add(root, rel)
    return r


def candidates(name, exe=None, bundle=None):
    """Names a program's folder could carry."""
    c = set()
    stem = re.sub(r"\.(exe|app|service)$", "", name or "", flags=re.I)
    if stem: c.add(norm(stem))
    if exe:
        parts = [x for x in re.split(r"[\\/]", exe) if x]
        if parts: c.add(norm(re.sub(r"\.(exe|app)$", "", parts[-1], flags=re.I)))
        for x in reversed(parts[:-1][-3:]):           # parent folders such as Program Files\Vendor\App\app.exe
            if norm(x) not in GENERIC and not re.fullmatch(r"[a-z]:", x.lower()): c.add(norm(re.sub(r"\.app$", "", x, flags=re.I))); break
    if bundle:
        c.add(norm(bundle)); c.add(norm(bundle.split(".")[-1]))
    return {x for x in c if len(x) >= 3 and x not in GENERIC}, bundle


def _matches(child, cands, bundle):
    n = norm(re.sub(r"\.app$", "", child.name, flags=re.I))
    if not n: return False
    if n in cands: return True
    if bundle and norm(child.name).startswith(norm(bundle)): return True
    return False


def folders_for(root, os_name, name, exe=None, bundle=None, include_cache=False, include_install=False):
    cands, bundle = candidates(name, exe, bundle); out = []
    if not cands: return out
    install = {d for d, _ in app_roots(root, os_name, True)} - {d for d, _ in app_roots(root, os_name, False)}
    for base, is_cache in app_roots(root, os_name, include_install):
        if is_cache and not include_cache: continue
        for c in _children(base):
            if c.is_symlink() or not c.is_dir(): continue
            if _matches(c, cands, bundle): out.append(c)
            elif base in install and os_name == "windows":           # Program Files\Vendor\App: look one level down
                out += [g for g in _children(c) if g.is_dir() and not g.is_symlink() and _matches(g, cands, bundle)]
    for h in _homes(root, os_name):                                 # ~/.appname, preference plists
        if os_name == "linux":
            out += [c for c in _children(h) if c.is_dir() and not c.is_symlink() and c.name.startswith(".") and norm(c.name) in cands]
        if os_name == "macos":
            pr = _sub(h, "Library/Preferences")
            if pr: out += [c for c in _children(pr) if c.is_file() and c.suffix == ".plist" and bundle and c.name.lower().startswith(bundle.lower())]
    return sorted(set(out))


def all_app_folders(root, os_name, include_cache=False, include_install=False):
    """{display name: [folders]} for every per-app folder found in the standard locations."""
    skip = {"microsoft", "temp", "packages", "apple", "crashpad", "connecteddevicesplatform", "comms", "d3dscache", "history"}
    out = {}
    for base, is_cache in app_roots(root, os_name, include_install):
        if is_cache and not include_cache: continue
        for c in _children(base):
            if c.is_symlink() or not c.is_dir() or c.name.lower() in skip: continue
            if os_name == "macos" and c.name.lower().startswith("com.apple."): continue
            out.setdefault(c.name, []).append(c)
    return out


# ------------------------------------------------------------------ copying
def list_files(folders, include_cache):
    """Regular files under folders (symlinks never followed), cache directories pruned. Unreadable dirs are returned too."""
    files, unreadable = [], []
    for f in folders:
        if f.is_file(): files.append(f); continue
        def onerr(e): unreadable.append(getattr(e, "filename", None) and f.__class__(e.filename) or f)
        for dp, dn, fn in f.walk(top_down=True, on_error=onerr):                   # Path.walk: works inside disk images too
            if not include_cache: dn[:] = [d for d in dn if d.lower() not in CACHE_DIRS]
            for n in fn:
                p = dp / n
                if not p.is_symlink(): files.append(p)
    return files, unreadable


def copy_app(rec, root, name, files, unreadable, per_file_cap, max_files, max_bytes, group, rule="desktop:app_folder", bar=None):
    n = total = skipped = 0; over = 0
    for p in unreadable: rec.nc(rule, p, "directory not readable (permission or error)", app=name); skipped += 1
    for p in sorted(files, key=lambda x: str(x)):
        if bar: bar.update(1, 0, f"{name}: {p.name}")
        if str(p) in rec.copied: continue
        try: size = p.stat().st_size
        except OSError as e: rec.nc(rule, p, f"{type(e).__name__}: {e}", app=name); skipped += 1; continue
        if n >= max_files or total + size > max_bytes: over += 1; continue
        got = rec.copy(p, root, rule, per_file_cap, app=name, app_group=group)
        if got is None: skipped += 1
        else:
            n += 1; total += got
            if bar: bar.bytes += got
    if over:
        skipped += over
        rec.nc(rule, f"{root}::{name}", f"{over} further files not copied (limit {max_files} files / {max_bytes >> 20} MB per program; "
                                         "raise --max-app-files / --max-app-mb)", app=name)
    rec.audit(f"APPCOPY {name} group={group} files={n} bytes={total} skipped={skipped}")
    return dict(files=n, bytes=total, skipped=skipped)


# ------------------------------------------------------------------ live commands
def is_live(root, os_name):
    if not isinstance(root, Path) or type(root).__module__.startswith("dissect"): return False    # a path inside a disk image
    plat = {"linux": "linux", "macos": "darwin", "windows": "win32"}[os_name]
    if not sys.platform.startswith(plat): return False
    try: return Path(root).resolve() == Path(Path(root).anchor)
    except OSError: return False


def _capture(rec, argv, fname, timeout, rule, **extra):
    out = rec.ev / "_commands"; out.mkdir(parents=True, exist_ok=True); f = out / fname
    try:
        with open(f, "wb") as fo: r = subprocess.run(argv, stdout=fo, stderr=subprocess.PIPE, timeout=timeout)
        err = r.stderr.decode("utf-8", "replace").strip()[-300:]
        rec.audit(f"RUN {' '.join(argv)} rc={r.returncode}")
        if r.returncode == 0 and f.stat().st_size:
            rec.generated(f, "volatile", rule, f"cmd://{' '.join(argv)}", command=" ".join(argv), **extra); return f
        rec.nc(rule, f"cmd://{' '.join(argv)}", f"exit code {r.returncode}. {err}", command=" ".join(argv), **extra)
    except (OSError, subprocess.SubprocessError) as e:
        rec.nc(rule, f"cmd://{' '.join(argv)}", f"{type(e).__name__}: {e}", command=" ".join(argv), **extra)
    return None


# ------------------------------------------------------------------ the automatic step
UNIFIED_PREDICATE = ('eventMessage CONTAINS[c] "crash" OR eventMessage CONTAINS[c] "jetsam" OR eventMessage CONTAINS[c] "watchdog" '
                     'OR eventMessage CONTAINS[c] "hang" OR process == "ReportCrash"')


def capture_unified(rec, days=14, archive=None, fname="unified_log_crash_events.txt"):
    """macOS only (`log` is a macOS tool): save crash-related Unified Log lines as evidence. Not parsed into the ranking."""
    if sys.platform != "darwin" or not shutil.which("log"): return None
    argv = ["log", "show", "--style", "syslog", "--predicate", UNIFIED_PREDICATE]
    argv += ["--archive", str(archive)] if archive else ["--last", f"{max(days, 1)}d"]
    return _capture(rec, argv, fname, 900, "desktop:unified_log")


def suspects_for(rec, root, os_name, a, live):
    notes = set(); text, xml = [], []
    if live and os_name == "linux" and shutil.which("journalctl"):
        f = _capture(rec, ["journalctl", "--no-pager", "-o", "short-iso", "-n", "300000"], "journal_for_suspects.txt", 600, "desktop:journal")
        if f: text.append((f, f.name))
    if live and os_name == "windows" and shutil.which("wevtutil"):
        for log, ids, fname in (("Application", "EventID=1000 or EventID=1002", "events_application.xml"),
                                ("System", "EventID=41 or EventID=6008 or EventID=1001", "events_system.xml")):
            f = _capture(rec, ["wevtutil", "qe", log, f"/q:*[System[({ids})]]", "/f:xml", "/c:500", "/rd:true"], fname, 120, "desktop:events")
            if f: xml.append((f, f.name))
    if live and os_name == "macos": capture_unified(rec, getattr(a, "suspect_days", 14))
    if os_name == "linux": events, n = P.scan_linux(root, text, notes)
    elif os_name == "windows": events, n = P.scan_windows(root, xml, notes)
    elif os_name == "macos": events, n = P.scan_macos(root)
    else: return None
    since = None; days = getattr(a, "suspect_days", 14)
    stamped = [e["t"] for e in events if e["t"]]
    if days and stamped: since = max(stamped) - timedelta(days=days)        # relative to the newest evidence, so old images work
    res = P.build(events, notes, n, since)
    adir = rec.case / "analysis"; adir.mkdir(exist_ok=True)
    for fname, body in ((f"suspects-{rec.dev}.txt", P.render(res, rec.dev) + "\n"), (f"suspects-{rec.dev}.json", P.to_json(res, rec.dev))):
        (adir / fname).write_text(body); rec.generated(adir / fname, "analysis", "desktop:suspects", f"analysis://{rec.dev}/{fname}", derived=True)
    return res


def post_collect(case, root, os_name, dev, a, source_prefix=""):
    """Called by `collect` after the normal rules ran (and by `image`, with a root inside a disk image).
    Never raises into the caller's loop for one bad source."""
    if os_name not in ("linux", "windows", "macos") or getattr(a, "no_suspects", False): return
    if isinstance(root, (str, os.PathLike)) and type(root).__module__ in ("builtins", "pathlib", "pathlib._local"): root = Path(root)
    live = is_live(root, os_name) and not source_prefix
    with Rec(case, os_name, dev) as rec:
        rec.prefix = source_prefix
        rec.audit(f"SUSPECTS START os={os_name} root={root} live={live} user={getpass.getuser()}")
        res = suspects_for(rec, root, os_name, a, live)
        if res is None: return
        names = [(n, evs) for n, evs in res["ranked"] if not n.startswith("(")][: getattr(a, "max_suspects", 5)]
        rec.audit(f"SUSPECTS ranked={[n for n, _ in res['ranked']]} chosen={[n for n, _ in names]} since_days={getattr(a, 'suspect_days', 14)}")
        if names: print("  Suspect programs (crashed, hung or killed): " + ", ".join(n for n, _ in names))
        else: print("  No crashed or hung program found in the evidence read" + (f" (last {a.suspect_days} days of it)" if getattr(a, "suspect_days", 14) else "") + ".")
        for n, evs in names:                                                  # service logs for crashed systemd units
            if live and os_name == "linux" and shutil.which("journalctl") and re.fullmatch(r"[\w.@:-]+", n):
                _capture(rec, ["journalctl", "--no-pager", "-o", "short-iso", "-u", n, "-n", "5000"], f"journal_unit_{n}.txt", 120, "desktop:journal_unit", app=n)
        if getattr(a, "no_app_folders", False): return
        cap = getattr(a, "max_size_mb", 512) << 20; inc = getattr(a, "include_cache", False)
        todo = []
        with Progress("Finding program folders", len(names), "programs") as fbar:
            for n, evs in names:
                fbar.update(1, 0, n)
                exe = next((e["exe"] for e in evs if e.get("exe")), None); bundle = next((e["bundle"] for e in evs if e.get("bundle")), None)
                folders = folders_for(root, os_name, n, exe, bundle, inc, getattr(a, "include_install", False))
                if not folders: say(f"    {n}: no folders found in the standard locations"); rec.audit(f"APPCOPY {n}: no folders matched"); continue
                files, unread = list_files(folders, inc); todo.append((n, folders, files, unread))
        if not todo: return
        with Progress("Copying program folders", sum(len(t[2]) for t in todo), "files") as bar:
            for n, folders, files, unread in todo:
                r = copy_app(rec, root, n, files, unread, cap, getattr(a, "max_app_files", 300), getattr(a, "max_app_mb", 500) << 20, "suspect", bar=bar)
                say(f"    {n}: {len(folders)} folders, {r['files']} files, {r['bytes'] / 1048576:.1f} MB"
                    + (f", {r['skipped']} not copied (see not_collected rows)" if r["skipped"] else ""))


def add_collect_args(c):
    """Flags added to `logharvest collect`."""
    c.add_argument("--no-suspects", action="store_true", help="do not look for crashed/hung programs afterwards")
    c.add_argument("--max-suspects", type=int, default=5, help="collect folders of at most this many suspect programs (default 5)")
    c.add_argument("--suspect-days", type=int, default=14, help="only events within N days of the newest evidence count; 0 = no limit (default 14)")
    c.add_argument("--no-app-folders", action="store_true", help="report suspects but do not copy their folders")
    c.add_argument("--include-cache", action="store_true", help="also copy cache folders")
    c.add_argument("--include-install", action="store_true", help="also copy the programs' install folders (/opt, Program Files, /Applications); can be large")
    c.add_argument("--max-app-files", type=int, default=300, help="max files copied per program (default 300)")
    c.add_argument("--max-app-mb", type=int, default=500, help="max MB copied per program (default 500)")


# ------------------------------------------------------------------ `logharvest desktop-apps`
def add_args(ap):
    ap.add_argument("--case", required=True, type=Path)
    ap.add_argument("--source", type=Path, help="root of a mounted image / extracted dir (default: this computer)")
    ap.add_argument("--name", action="append", default=[], metavar="APP", help="only programs whose folder name contains this (repeatable)")
    ap.add_argument("--include-cache", action="store_true", help="also copy cache folders")
    ap.add_argument("--include-install", action="store_true", help="also copy the programs' install folders (/opt, Program Files, /Applications); can be large")
    ap.add_argument("--max-app-files", type=int, default=300, help="max files per program (default 300)")
    ap.add_argument("--max-app-mb", type=int, default=500, help="max MB per program (default 500)")
    ap.add_argument("--max-size-mb", type=int, default=512, help="skip single files larger than this (default 512)")
    ap.add_argument("--yes", action="store_true", help="do not ask for confirmation after showing the plan")
    ap.add_argument("--image", action="append", type=Path, default=[], metavar="DISK",
                    help="read a disk image / VM disk instead (raw, E01, qcow2, vmdk, vhd, vhdx, vdi; needs dissect.target[full]); repeatable")
    ap.add_argument("--hash", choices=["both", "before", "none"], default="both", help="with --image: SHA-256 of the image before/after reading")


def run(a):
    if getattr(a, "image", None):
        from . import images as I
        rc = 0
        for img in a.image:
            img = img.resolve()
            if not img.exists(): print(f"ERROR: {img} not found"); rc = 1; continue
            files = I.image_files(img); before = I.hash_files(files, f"Hashing {img.name}") if a.hash != "none" else {}
            roots, notes = I.find_roots(I.open_target(img))
            if not roots: print(f"{img.name}: no Linux, Windows or macOS system found." + "".join(f"\n  note: {n}" for n in notes)); rc = 1; continue
            for r in roots:
                dev = re.sub(r"[^\w.-]+", "_", f"{r['os']}-{img.stem}" + (f"-{r['label'].split(':')[0]}" if len(roots) > 1 else ""))
                rc = max(rc, _run_root(a, r["root"], r["os"], dev, f"image://{img.name}/{r['label']}"))
            if a.hash == "both":
                after = I.hash_files(files, f"Re-hashing {img.name}")
                print("Image hash verified unchanged." if after == before else "WARNING: the image's hash CHANGED while it was read.")
        return rc
    from .detect import identify_os
    root = a.source or Path(os.path.abspath(os.sep) if os.name != "nt" else os.environ.get("SystemDrive", "C:") + "\\")
    os_name = identify_os(root)
    if os_name not in ("linux", "windows", "macos"): print(f"ERROR: {root} is not a Linux, Windows or macOS system root (detected: {os_name})."); return 1
    dev = re.sub(r"[^\w.-]+", "_", f"{os_name}-{root.name or root.drive.rstrip(':' + chr(92)) or 'root'}")
    return _run_root(a, root, os_name, dev)


def _run_root(a, root, os_name, dev, prefix=""):
    found = all_app_folders(root, os_name, a.include_cache, a.include_install)
    if a.name: found = {k: v for k, v in found.items() if any(x.lower() in k.lower() for x in a.name)}
    if not found: print("No per-program folders found in the standard locations (permissions? try sudo / Administrator)."); return 1
    print(f"Listing {len(found)} programs' folders ...")
    plan, cap = {}, a.max_app_mb << 20; est = 0
    lbar = Progress("Listing files", len(found), "programs")
    for k, folders in sorted(found.items()):
        lbar.update(1, 0, k)
        files, unread = list_files(folders, a.include_cache)
        plan[k] = (files, unread); size = 0
        for p in files:
            try: size += p.stat().st_size
            except OSError: pass
        est += min(size, cap)
    lbar.close()
    print(f"Plan: {len(plan)} programs, about {sum(len(f) for f, _ in plan.values())} files, up to {est / 1048576:.0f} MB "
          f"(caps: {a.max_app_files} files / {a.max_app_mb} MB per program).")
    if not a.yes:
        if not sys.stdin.isatty(): print("Not interactive: re-run with --yes to proceed."); return 2
        if input("Copy these? [y/N] ").strip().lower() not in ("y", "yes"): print("Cancelled."); return 2
    a.case.mkdir(parents=True, exist_ok=True)
    with Rec(a.case, os_name, dev) as rec:
        rec.prefix = prefix
        rec.audit(f"START desktop-apps os={os_name} root={root} user={getpass.getuser()} host={platform.node()} programs={len(plan)}")
        bar = Progress("Copying programs", sum(len(f) for f, _ in plan.values()), "files")
        for i, (k, (files, unread)) in enumerate(sorted(plan.items()), 1):
            r = copy_app(rec, root, k, files, unread, a.max_size_mb << 20, a.max_app_files, cap, "all", bar=bar)
            say(f"  [{i}/{len(plan)}] {k}: {r['files']} files, {r['bytes'] / 1048576:.1f} MB" + (f", {r['skipped']} not copied" if r["skipped"] else ""))
        bar.close()
        rec.audit(f"END desktop-apps ok={rec.ok} not_collected={rec.nc_count}")
        print(f"Done: {rec.ok} files recorded, {rec.nc_count} not collected. See manifest.jsonl.")
    return 0
