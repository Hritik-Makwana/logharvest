import getpass, hashlib, json, os, platform, shutil, subprocess, sys
from datetime import datetime, timezone
from pathlib import Path
from .rules import RULES


def utc(ts):
    return datetime.fromtimestamp(ts, timezone.utc).isoformat()


def now():
    return datetime.now(timezone.utc).isoformat()


def is_admin() -> bool:
    try:
        if sys.platform == "win32":
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:
        return False


def _fs(p: Path) -> Path:
    """Windows: paths >= 240 chars need the \\\\?\\ prefix or open/stat fail (MAX_PATH)."""
    s = str(p)
    if sys.platform == "win32" and len(s) >= 240 and not s.startswith("\\\\"):
        return Path("\\\\?\\" + os.path.abspath(s))
    return p


def sha256(path, bufsize=1 << 20):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(bufsize):
            h.update(chunk)
    return h.hexdigest()


def _iter_matches(root: Path, os_name: str):
    """Yield (category, path). Only globbing/dedup happens here; per-file checks
    (symlink, is_file, stat) live in collect_tree's try block so a
    PermissionError / macOS TCC 'Operation not permitted' is recorded in the
    manifest instead of aborting the whole run."""
    seen = set()
    for category, pattern in RULES[os_name]:
        try:
            for p in root.glob(pattern, case_sensitive=False):
                if p in seen:
                    continue
                seen.add(p)
                yield category, p
        except OSError as e:
            print(f"warn: pattern {pattern!r} aborted: {e}", file=sys.stderr)


def collect_tree(root: Path, os_name: str, case: Path, device_id: str, max_mb: int):
    """Copy matched logs to case/evidence/<device>/..., hash source before and
    after copy, and append records to the manifest."""
    ev = case / "evidence" / device_id
    manifest = case / "manifest.jsonl"
    audit = case / "audit.log"
    n_ok = n_err = 0
    case_prefix = (
        os.path.normcase(str(case.resolve())) + os.sep
    )  # never collect our own output
    with (
        open(manifest, "a", encoding="utf-8", newline="\n") as mf,
        open(audit, "a", encoding="utf-8", newline="\n") as al,
    ):
        al.write(
            f"{now()} START root={root} os={os_name} user={getpass.getuser()} "
            f"host={platform.node()} python={sys.version.split()[0]} admin={is_admin()}\n"
        )
        for category, src in _iter_matches(root, os_name):
            rec = {
                "device": device_id,
                "os": os_name,
                "category": category,
                "source": str(src),
                "collected_at": now(),
            }
            try:
                if os.path.normcase(os.path.abspath(src)).startswith(case_prefix):
                    continue
                s = _fs(src)
                if (
                    s.is_symlink()
                    or getattr(s, "is_junction", lambda: False)()
                    or not s.is_file()
                ):
                    continue  # dirs, sockets, symlinks, NTFS junctions
                st = s.stat()  # stat BEFORE reading (atime!)
                if st.st_size > (max_mb << 20):
                    raise ValueError(f"skipped: larger than {max_mb} MB")
                rec.update(
                    size=st.st_size,
                    modified=utc(st.st_mtime),
                    accessed=utc(st.st_atime),
                    changed_or_created=utc(st.st_ctime),
                )
                if hasattr(
                    st, "st_birthtime"
                ):  # macOS (and Windows on 3.12+): real creation time
                    rec["created"] = utc(st.st_birthtime)
                before = sha256(s)
                dest = ev / src.relative_to(root)
                d = _fs(dest)
                d.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(s, d)
                os.utime(d, (st.st_atime, st.st_mtime))
                after = sha256(d)
                # On a live system, files being written (e.g. tracev3) can legitimately
                # change between hashes -> shows as MISMATCH in the viewer.
                rec.update(
                    sha256=after,
                    dest=str(dest.relative_to(case)),
                    verified=(before == after == sha256(s)),
                )
                n_ok += 1
            except Exception as e:
                rec.update(error=f"{type(e).__name__}: {e}")
                n_err += 1
            mf.write(json.dumps(rec) + "\n")
        al.write(f"{now()} END ok={n_ok} errors={n_err}\n")
    return n_ok, n_err


def collect_macos_logarchive(case: Path, days: int = 7):
    """Live Mac only, needs root. Uses Apple's own `log collect` to build a
    .logarchive (openable with Console.app or `log show --archive`), which is
    the easiest way to get decoded Unified Logs from a running system."""
    if sys.platform != "darwin":
        print("logarchive: only available when running on macOS")
        return 0
    if os.geteuid() != 0:
        print("logarchive: needs root (run with sudo)")
        return 0
    ev = case / "evidence" / "macos-live"
    ev.mkdir(parents=True, exist_ok=True)
    out = ev / "system.logarchive"
    cmd = ["log", "collect", "--last", f"{days}d", "--output", str(out)]
    with open(case / "audit.log", "a", encoding="utf-8", newline="\n") as al:
        al.write(f"{now()} RUN {' '.join(cmd)}\n")
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
    if r.returncode != 0 or not out.exists():
        print(f"logarchive failed: {r.stderr.strip() or r.stdout.strip()}")
        return 0
    n = 0
    with open(case / "manifest.jsonl", "a", encoding="utf-8", newline="\n") as mf:
        for f in sorted(out.rglob("*")):
            if not f.is_file() or f.is_symlink():
                continue
            st = f.stat()
            rec = {
                "device": "macos-live",
                "os": "macos",
                "category": "system",
                "source": " ".join(cmd) + f"  ->  {f.relative_to(out)}",
                "collected_at": now(),
                "size": st.st_size,
                "modified": utc(st.st_mtime),
                "accessed": utc(st.st_atime),
                "changed_or_created": utc(st.st_ctime),
                "sha256": sha256(f),
                "dest": str(f.relative_to(case)),
                "verified": True,
            }
            if hasattr(st, "st_birthtime"):
                rec["created"] = utc(st.st_birthtime)
            mf.write(json.dumps(rec) + "\n")
            n += 1
    return n
