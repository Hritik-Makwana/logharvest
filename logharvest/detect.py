import os, plistlib, subprocess, sys
from pathlib import Path
from .rules import MARKERS


def _has(root: Path, rel: str) -> bool:
    try:
        return any(root.glob(rel, case_sensitive=False))
    except (OSError, NotImplementedError, ValueError):
        return False


def _apple_product(root: Path) -> str | None:
    """macOS and iOS both ship SystemVersion.plist; ProductName tells them apart
    reliably (macOS also has /private/var/mobile, so directory markers alone can
    misdetect a Mac as iOS)."""
    try:
        plist = next(
            root.glob(
                "System/Library/CoreServices/SystemVersion.plist", case_sensitive=False
            ),
            None,
        )
        if not plist:
            return None
        with open(plist, "rb") as f:
            name = str(plistlib.load(f).get("ProductName", "")).lower()
    except (OSError, plistlib.InvalidFileException, ValueError, NotImplementedError):
        return None
    if name in ("macos", "mac os x"):
        return "macos"
    if name in ("ios", "iphone os", "ipados"):
        return "ios"
    return None


def identify_os(root: Path) -> str | None:
    apple = _apple_product(root)
    if apple:
        return apple
    for name, marks in MARKERS:
        hits = [_has(root, m) for m in marks]
        # android: either marker is enough; every other OS needs all of them
        if any(hits) if name == "android" else all(hits):
            return name
    return None


def _windows_drives():
    """Live Windows without psutil: every lettered drive (os.listdrives needs 3.12+)."""
    if sys.platform != "win32":
        return []
    try:
        import ctypes

        ctypes.windll.kernel32.SetErrorMode(
            1
        )  # no "insert disk" popups for empty drives
        return [{"path": d, "fstype": "?", "kind": "volume"} for d in os.listdrives()]
    except (OSError, AttributeError):
        return []


def list_targets(extra_paths=()):
    """Mounted volumes (via psutil if installed) plus user-supplied paths
    (mounted disk images, extracted phone backups, etc.)."""
    found = []
    try:
        import psutil

        for p in psutil.disk_partitions(all=False):
            # Live Mac: "/" already exposes the Data volume through firmlinks, and
            # /System/Volumes/* are internal mounts -> collecting them again = duplicates.
            if sys.platform == "darwin" and p.mountpoint.startswith("/System/Volumes/"):
                continue
            if sys.platform == "win32" and "cdrom" in p.opts:  # empty optical drive
                continue
            found.append(
                {"path": p.mountpoint, "fstype": p.fstype or "?", "kind": "volume"}
            )
    except ImportError:
        found.extend(_windows_drives())
    for p in extra_paths:
        found.append({"path": str(p), "fstype": "?", "kind": "path"})
    for t in found:
        t["os"] = identify_os(Path(t["path"]))
    for line in adb_devices():
        found.append({"path": line, "fstype": "-", "kind": "adb", "os": "android"})
    return found


def adb_devices():
    try:
        out = subprocess.run(
            ["adb", "devices"], capture_output=True, text=True, timeout=10
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    return [l.split()[0] for l in out.splitlines()[1:] if l.strip().endswith("device")]
