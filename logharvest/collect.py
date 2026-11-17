import getpass, hashlib, itertools, json, os, platform, stat, subprocess, sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from .rules import RULES, COMMANDS, EVTX_EXPORT
from .discover import walk_candidates

def utc(ts): return datetime.fromtimestamp(ts, timezone.utc).isoformat()
def now(): return datetime.now(timezone.utc).isoformat()

def lp(p):
    """Windows: extended-length path (\\\\?\\...) so paths over 260 chars can be read/written. No-op elsewhere."""
    if os.name != "nt": return p
    s = os.path.abspath(str(p))
    if s.startswith("\\\\?\\"): return s
    return "\\\\?\\UNC\\" + s[2:] if s.startswith("\\\\") else "\\\\?\\" + s

def open_ro(path):
    """Read-only open; O_NOATIME avoids bumping atime on the source (root/owner only)."""
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    try:
        return os.fdopen(os.open(lp(path), flags | getattr(os, "O_NOATIME", 0)), "rb")
    except PermissionError:
        return open(lp(path), "rb")

def sha256(path, bufsize=1 << 20):
    h = hashlib.sha256()
    with open_ro(path) as f:
        while chunk := f.read(bufsize): h.update(chunk)
    return h.hexdigest()

def copy_hash(src, dest, bufsize=1 << 20):
    h = hashlib.sha256()
    with open_ro(src) as fi, open(lp(dest), "wb") as fo:
        while chunk := fi.read(bufsize):
            h.update(chunk); fo.write(chunk)
    return h.hexdigest()

def xattrs(p):
    try: return {k: os.getxattr(p, k, follow_symlinks=False).hex() for k in os.listxattr(p, follow_symlinks=False)}
    except (AttributeError, OSError): return {}

def file_meta(st):
    return dict(size=st.st_size, modified=utc(st.st_mtime), accessed=utc(st.st_atime),
                changed_or_created=utc(st.st_ctime), mtime_ns=st.st_mtime_ns, atime_ns=st.st_atime_ns,
                ctime_ns=st.st_ctime_ns, mode=oct(st.st_mode), uid=st.st_uid, gid=st.st_gid,
                inode=st.st_ino, nlink=st.st_nlink)

def _err(path, e): return {"path": str(path), "error": f"{type(e).__name__}: {e}"}

def _rule_matches(root, os_name, seen, unreadable):
    """Yield (category, rule, path). Never raises on permission problems: they are
    appended to `unreadable` and reported as not_collected."""
    for category, pattern in RULES[os_name]:
        lit = list(itertools.takewhile(lambda s: not any(c in s for c in "*?["), pattern.split("/")))
        d = root.joinpath(*lit)
        try:
            if d.is_dir() and not os.access(d, os.R_OK | os.X_OK):
                unreadable.append({"path": str(d), "error": "no read/traverse permission (rule prefix)"})
                continue
        except OSError as e:                      # e.g. parent dir not traversable (EACCES/EPERM)
            unreadable.append(_err(d, e)); continue
        it = root.glob(pattern, case_sensitive=False)
        while True:
            try:
                p = next(it)
            except StopIteration:
                break
            except OSError as e:
                unreadable.append(_err(getattr(e, "filename", None) or d, e)); break
            try:
                if os.path.normcase(str(p)) in seen or p.is_symlink() or not p.is_file(): continue
            except OSError as e:
                unreadable.append(_err(p, e)); continue
            seen.add(os.path.normcase(str(p))); yield category, pattern, p

def _live_key(root: Path, os_name: str):
    """'linux' / 'windows' when `root` is the running machine's own system volume, else None."""
    if os_name == "linux" and sys.platform.startswith("linux") and root == Path("/"): return "linux"
    if os_name == "windows" and sys.platform == "win32":
        sd = os.environ.get("SystemDrive", "C:").rstrip("\\/").lower()
        if str(root).rstrip("\\/").lower() == sd: return "windows"
    return None

def collect_tree(root: Path, os_name: str, case: Path, device_id: str, max_mb: int,
                 sweep=False, run_cmds=True):
    ev = case / "evidence" / device_id
    case_str = str(case.resolve()) + os.sep
    by_cat, by_rule, unreadable, seen = Counter(), Counter(), [], set()
    n_ok = n_err = 0
    with open(case / "manifest.jsonl", "a", encoding="utf-8", newline="\n") as mf, \
         open(case / "audit.log", "a", encoding="utf-8", newline="\n") as al:
        al.write(f"{now()} START root={root} os={os_name} user={getpass.getuser()} euid={os.geteuid() if hasattr(os,'geteuid') else '?'} "
                 f"host={platform.node()} python={sys.version.split()[0]} sweep={sweep}\n")

        def log(rec): mf.write(json.dumps(rec) + "\n")

        # 1) volatile commands first (RFC 3227 order of volatility)
        live = _live_key(root, os_name) if run_cmds else None
        if live:
            for name, argv in COMMANDS[live]:
                rec = {"device": device_id, "os": os_name, "category": "volatile", "rule": "command",
                       "source": " ".join(argv), "collected_at": now()}
                try:
                    p = subprocess.run(argv, capture_output=True, timeout=120)
                    out = ev / "_commands" / f"{name}.txt"; out.parent.mkdir(parents=True, exist_ok=True)
                    out.write_bytes(p.stdout); t = now()
                    rec.update(dest=str(out.relative_to(case)), sha256=hashlib.sha256(p.stdout).hexdigest(),
                               size=len(p.stdout), modified=t, accessed=t, changed_or_created=t, verified=True,
                               returncode=p.returncode, stderr=p.stderr[:1000].decode("utf-8", "replace"))
                    n_ok += 1; by_cat["volatile"] += 1
                except Exception as e:
                    rec["error"] = f"{type(e).__name__}: {e}"; n_err += 1
                log(rec)
            if live == "windows":                     # OS-made consistent copy of the live logs (Security needs Administrator)
                for ch in EVTX_EXPORT:
                    out = ev / "_exports" / f"{ch}.evtx"
                    rec = {"device": device_id, "os": os_name, "category": "system", "rule": "wevtutil epl",
                           "source": f"wevtutil epl {ch}", "collected_at": now()}
                    try:
                        out.parent.mkdir(parents=True, exist_ok=True)
                        p = subprocess.run(["wevtutil", "epl", ch, str(out.resolve()), "/ow:true"],
                                           capture_output=True, timeout=600)
                        if p.returncode != 0 or not out.is_file():
                            msg = (p.stderr or p.stdout).decode("utf-8", "replace").strip()[:300]
                            raise RuntimeError(f"wevtutil exit {p.returncode}: {msg}")
                        st = out.stat()
                        rec.update(dest=str(out.relative_to(case)), sha256=sha256(out), size=st.st_size,
                                   modified=utc(st.st_mtime), accessed=utc(st.st_atime),
                                   changed_or_created=utc(st.st_ctime), verified=True)
                        n_ok += 1; by_cat["system"] += 1
                    except Exception as e:
                        rec["error"] = f"{type(e).__name__}: {e}"; n_err += 1
                    log(rec)

        # 2) files
        def do_file(category, rule, src):
            nonlocal n_ok, n_err
            if os.path.normcase(str(src)).startswith(os.path.normcase(case_str)): return                # never collect our own output
            rec = {"device": device_id, "os": os_name, "category": category, "rule": rule,
                   "source": str(src), "collected_at": now()}
            try:
                st = os.lstat(lp(src))
                if not stat.S_ISREG(st.st_mode): return
                rec.update(file_meta(st)); rec["xattrs"] = xattrs(src)   # metadata BEFORE reading
                dest = ev / src.relative_to(root); os.makedirs(lp(dest.parent), exist_ok=True)
                if category == "volatile":                               # /proc etc: read once
                    data = b""
                    with open(src, "rb") as f:                            # small chunks: /proc rejects huge reads
                        while (chunk := f.read(4096)) and len(data) < (8 << 20): data += chunk
                    dest.write_bytes(data); digest = hashlib.sha256(data).hexdigest(); rec["volatile"] = True
                else:
                    if st.st_size > max_mb << 20: raise ValueError(f"NOT COLLECTED: larger than {max_mb} MB")
                    digest = copy_hash(src, dest)                        # hashed while streaming
                    st2 = os.lstat(lp(src))
                    rec["source_was_active"] = (st2.st_size, st2.st_mtime_ns) != (st.st_size, st.st_mtime_ns)
                os.utime(lp(dest), ns=(st.st_atime_ns, st.st_mtime_ns))
                rec.update(sha256=digest, dest=str(dest.relative_to(case)), verified=(sha256(dest) == digest))
                n_ok += 1; by_cat[category] += 1; by_rule[f"{category}|{rule}"] += 1
            except Exception as e:
                rec["error"] = f"{type(e).__name__}: {e}"; n_err += 1
            log(rec)

        for category, pattern, src in _rule_matches(root, os_name, seen, unreadable):
            do_file(category, pattern, src)
        if sweep:
            for src in walk_candidates(root, {case.resolve()}, unreadable):
                try:
                    if os.path.normcase(str(src)) in seen or src.is_symlink(): continue
                except OSError as e:
                    unreadable.append(_err(src, e)); continue
                seen.add(os.path.normcase(str(src))); do_file("discovered", "sweep", src)
        unreadable[:] = list({(u["path"], u["error"]): u for u in unreadable}.values())   # de-duplicate
        for u in unreadable:
            log({"device": device_id, "os": os_name, "category": "not_collected", "rule": "unreadable",
                 "source": u["path"], "error": u["error"], "collected_at": now()})
        al.write(f"{now()} END ok={n_ok} errors={n_err} unreadable_dirs={len(unreadable)}\n")
    (case / f"coverage-{device_id}.json").write_text(json.dumps(
        {"by_category": by_cat, "by_rule": by_rule, "unreadable": unreadable}, indent=1), encoding="utf-8")
    return {"ok": n_ok, "errors": n_err, "by_category": dict(by_cat), "unreadable": len(unreadable)}

def collect_adb(serial: str, case: Path):
    """Live Android: bugreport (rich system logs) + logcat dump."""
    ev = case / "evidence" / f"adb-{serial}"; ev.mkdir(parents=True, exist_ok=True)
    jobs = {"bugreport.zip": ["adb", "-s", serial, "bugreport", str(ev / "bugreport.zip")],
            "logcat.txt": ["adb", "-s", serial, "logcat", "-d", "-b", "all"]}
    with open(case / "manifest.jsonl", "a") as mf:
        for name, cmd in jobs.items():
            out = ev / name
            if name == "logcat.txt":
                with open(out, "wb") as f: subprocess.run(cmd, stdout=f, timeout=300)
            else:
                subprocess.run(cmd, timeout=900)
            if out.exists():
                st = out.stat()
                mf.write(json.dumps({"device": f"adb-{serial}", "os": "android", "category": "system",
                    "source": " ".join(cmd), "collected_at": now(), "size": st.st_size,
                    "modified": utc(st.st_mtime), "accessed": utc(st.st_atime),
                    "changed_or_created": utc(st.st_ctime), "sha256": sha256(out),
                    "dest": str(out.relative_to(case)), "verified": True}) + "\n")
