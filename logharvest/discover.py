"""Sweep for log-like files that no rule covers. Unlike Path.glob, unreadable
directories are RECORDED, not silently skipped."""
import os, re
from pathlib import Path

PRUNE = ["proc", "sys", "dev", "run", "usr/share", "usr/lib", "usr/lib64", "usr/include", "lib", "lib32",
         "lib64", "bin", "sbin", "snap", "mnt", "media", "var/lib/docker/overlay2", "var/lib/docker/vfs",
         "var/lib/containers/storage/overlay", "var/lib/flatpak", "var/lib/snapd/snaps",
         "var/cache/apt", "var/cache/pacman"]
PSEUDO_FS = {"proc", "sysfs", "devtmpfs", "devpts", "cgroup", "cgroup2", "squashfs", "overlay", "securityfs",
             "debugfs", "tracefs", "bpf", "binfmt_misc", "autofs", "mqueue", "hugetlbfs", "configfs",
             "fusectl", "nsfs", "nfs", "nfs4", "cifs", "smb3", "fuse.sshfs", "fuse.gvfsd-fuse", "fuse.portal"}
NAME = re.compile(r"(\.log(\.\d+)?(\.(gz|xz|bz2|zst))?$|\.log-\d{8}(\.(gz|xz|bz2|zst))?$"
                  r"|\.(err|trace|dmp|crash|stacktrace|panic|ips|journal~?)$|^core(\.\d+)?$|^nohup\.out$)", re.I)

def _pseudo_mounts(root: Path):
    if root != Path("/"): return set()
    out = set()
    try:
        for line in open("/proc/self/mounts"):
            dev, mp, fs = line.split()[:3]
            if fs in PSEUDO_FS: out.add(Path(mp.encode().decode("unicode_escape")))
    except OSError: pass
    return out

def walk_candidates(root: Path, skip: set, unreadable: list):
    prune = {root / p for p in PRUNE} | set(skip) | _pseudo_mounts(root)
    def onerror(e): unreadable.append({"path": str(e.filename), "error": str(e)})
    for dirpath, dirnames, filenames in os.walk(root, onerror=onerror, followlinks=False):
        dp = Path(dirpath)
        dirnames[:] = [d for d in dirnames if (dp / d) not in prune and not (dp / d).is_symlink()]
        for f in filenames:
            if NAME.search(f): yield dp / f
