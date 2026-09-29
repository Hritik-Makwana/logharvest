import getpass, hashlib, json, os, platform, shutil, subprocess, sys
from datetime import datetime, timezone
from pathlib import Path
from .rules import RULES

def utc(ts): return datetime.fromtimestamp(ts, timezone.utc).isoformat()
def now(): return datetime.now(timezone.utc).isoformat()

def sha256(path, bufsize=1 << 20):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(bufsize):
            h.update(chunk)
    return h.hexdigest()

def _iter_matches(root: Path, os_name: str):
    seen = set()
    for category, pattern in RULES[os_name]:
        for p in root.glob(pattern, case_sensitive=False):
            if p in seen or p.is_symlink() or not p.is_file():
                continue
            seen.add(p)
            yield category, p

def collect_tree(root: Path, os_name: str, case: Path, device_id: str, max_mb: int):
    """Copy matched logs to case/evidence/<device>/..., hash source before and
    after copy, and append records to the manifest."""
    ev = case / "evidence" / device_id
    manifest = case / "manifest.jsonl"
    audit = case / "audit.log"
    n_ok = n_err = 0
    with open(manifest, "a") as mf, open(audit, "a") as al:
        al.write(f"{now()} START root={root} os={os_name} user={getpass.getuser()} "
                 f"host={platform.node()} python={sys.version.split()[0]}\n")
        for category, src in _iter_matches(root, os_name):
            rec = {"device": device_id, "os": os_name, "category": category,
                   "source": str(src), "collected_at": now()}
            try:
                st = src.stat()                       # stat BEFORE reading (atime!)
                if st.st_size > max_mb * 1 << 20:
                    raise ValueError(f"skipped: larger than {max_mb} MB")
                rec.update(size=st.st_size, modified=utc(st.st_mtime),
                           accessed=utc(st.st_atime), changed_or_created=utc(st.st_ctime))
                before = sha256(src)
                dest = ev / src.relative_to(root)
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(src, dest)
                os.utime(dest, (st.st_atime, st.st_mtime))
                after = sha256(dest)
                rec.update(sha256=after, dest=str(dest.relative_to(case)),
                           verified=(before == after == sha256(src)))
                n_ok += 1
            except Exception as e:
                rec.update(error=str(e)); n_err += 1
            mf.write(json.dumps(rec) + "\n")
        al.write(f"{now()} END ok={n_ok} errors={n_err}\n")
    return n_ok, n_err

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
