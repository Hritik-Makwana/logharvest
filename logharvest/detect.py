import subprocess
from pathlib import Path
from .rules import MARKERS

def _has(root: Path, rel: str) -> bool:
    try:
        return any(root.glob(rel, case_sensitive=False))
    except (OSError, NotImplementedError, ValueError):
        return False

def identify_os(root: Path) -> str | None:
    for name, marks in MARKERS:
        # ios/android/macos/linux need ALL markers except android (either)
        hits = [_has(root, m) for m in marks]
        if name == "android" and any(hits): return name
        if name == "windows" and all(hits): return name
        if name != "android" and all(hits): return name
    return None

def list_targets(extra_paths=()):
    """Mounted volumes (via psutil if installed) plus user-supplied paths
    (mounted disk images, extracted phone backups, etc.)."""
    found = []
    try:
        import psutil
        for p in psutil.disk_partitions(all=False):
            found.append({"path": p.mountpoint, "fstype": p.fstype or "?", "kind": "volume"})
    except ImportError:
        pass
    for p in extra_paths:
        found.append({"path": str(p), "fstype": "?", "kind": "path"})
    for t in found:
        t["os"] = identify_os(Path(t["path"]))
    for line in _adb_devices():
        found.append({"path": line, "fstype": "-", "kind": "adb", "os": "android"})
    return found

def _adb_devices():
    try:
        out = subprocess.run(["adb", "devices"], capture_output=True, text=True, timeout=10).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    return [l.split()[0] for l in out.splitlines()[1:] if l.strip().endswith("device")]
