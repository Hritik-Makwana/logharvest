"""Smart whole-volume sweep (`--sweep` / `--all-dirs`): look in EVERY directory that can plausibly hold logs,
without reading the ones that cannot.

A plain os.walk of a Windows system drive visits 500k+ directories (WinSxS, driver store, installer cache, browser
caches, node_modules, ...) that never contain evidence. This walker keeps the "check everything" promise but
skips, and COUNTS, the following (so the coverage report shows exactly what was not looked at):

  1. known-noise directories by path   (Windows\\WinSxS, Windows\\Installer, DriverStore, WindowsApps, ...)
  2. allow-listed parents              (Windows\\System32: only LogFiles, winevt, wbem, sysprep, config, Tasks, ...)
  3. known-noise directories by name   at any depth (node_modules, .git, site-packages, Cache, GPUCache, ...)
  4. reparse points / symlinks / junctions (loops, and the same files reached twice)
  5. unreadable directories            are recorded, never silently skipped
  6. depth cap (default 12). A directory named log/logs/crash*/dumps/diagnostics is still entered when it is
     reached (i.e. its parent is within the cap), searched to the bottom, and there .txt/.out/.json also count

Works on real folders (fast os.scandir path) and on dissect.target image paths (plain pathlib API).
"""
import os, pathlib, re
from collections import Counter

# ---------------------------------------------------------------- what counts as log-like
NAME = re.compile(
    r"(\.log(\.\d+)?(\.(gz|xz|bz2|zst|zip|old))?$|\.log-\d{8}(\.(gz|xz|bz2|zst))?$|\.log\.old$"
    r"|\.(err|trace|dmp|mdmp|hdmp|crash|stacktrace|panic|ips|etl|wer|evtx|evt|journal~?)$"
    r"|^core(\.\d+)?$|^nohup\.out$|^npm-debug\.log|^hs_err_pid\d+\.log$)", re.I)
IN_LOGDIR = re.compile(r"\.(txt|out|json|jsonl|xml|csv)$", re.I)           # only inside a log-named directory
LOGDIR = re.compile(r"^(logs?|crash(es|pad)?( reports?)?|dumps?|minidumps?|diagnostics?|traces?|wer|reportarchive|reportqueue)$", re.I)

# ---------------------------------------------------------------- what is skipped (all lower-case, '/' separated)
NOISE_NAMES = {
    "node_modules", ".git", ".svn", ".hg", "__pycache__", "site-packages", ".venv", "venv", ".tox",
    ".gradle", ".m2", ".nuget", ".cargo", ".rustup", ".npm", ".yarn",
    "cache", "caches", "cache2", "code cache", "gpucache", "grshadercache", "shadercache", "dawncache", "dawngraphitecache",
    "dawnwebgpucache", "service worker", "indexeddb", "local storage", "session storage", "blob_storage", "file system",
    "inetcache", "thumbnails", "$recycle.bin", "system volume information", "lost+found", "$extend", "$logfile", "$mft",
}
NOISE_PATHS = {
    "windows": {
        "windows/winsxs", "windows/installer", "windows/assembly", "windows/servicing/packages", "windows/servicing/lcu",
        "windows/systemapps", "windows/fonts", "windows/microsoft.net", "windows/syswow64", "windows/softwaredistribution/download",
        "windows/system32/driverstore", "windows/system32/catroot", "windows/system32/catroot2", "windows/system32/spool/drivers",
        "windows/system32/migration", "windows/system32/dism", "windows/system32/oobe", "windows/immersivecontrolpanel",
        "windows/inf/.net data provider for oracle", "windows/diagnostics", "windows/helppane", "windows/globalization",
        "program files/windowsapps", "program files/common files/microsoft shared", "program files/windows kits",
        "program files (x86)/windows kits", "program files/dotnet", "program files/microsoft sdks",
        "programdata/package cache", "programdata/microsoft/windows defender/definition updates",
        "programdata/microsoft/windows defender/platform", "programdata/microsoft/windows/containers",
        "programdata/microsoft/windows/apprepository", "programdata/microsoft/windows/systemdata",
        "$windows.~bt", "$windows.~ws", "recovery", "config.msi", "msocache",
    },
    "linux": {
        "proc", "sys", "dev", "run", "usr/share", "usr/lib", "usr/lib64", "usr/include", "usr/src", "lib", "lib32", "lib64",
        "libx32", "bin", "sbin", "snap", "mnt", "media", "boot", "var/lib/docker/overlay2", "var/lib/docker/vfs",
        "var/lib/containers/storage/overlay", "var/lib/flatpak", "var/lib/snapd/snaps", "var/cache", "var/lib/apt",
        "var/lib/dpkg", "var/lib/rpm", "var/lib/pacman", "var/lib/dnf/repos", "etc/ssl", "etc/alternatives",
    },
    "macos": {
        "system", "applications", "usr", "bin", "sbin", "cores", "private/var/vm", "private/var/db/dyld",
        "private/var/db/oah", "private/var/folders", "library/developer", "library/frameworks", "library/caches",
        "library/updates", "system/volumes",
    },
}
# parent -> the ONLY children worth descending into (everything else under that parent is skipped)
ALLOW_CHILDREN = {
    "windows": {
        "windows/system32": {"logfiles", "winevt", "wbem", "sysprep", "config", "tasks", "grouppolicy", "grouppolicyusers",
                              "dhcp", "dns", "wdi", "lm", "drivers", "spool", "inetsrv", "winrm", "windowspowershell"},
        "windows/system32/config": {"systemprofile", "txr"},
        "windows/system32/spool": {"printers", "logs"},
        "windows/system32/drivers": {"etc"},
    },
}
DEFAULT_MAX_DEPTH = 12


def _is_real(path):
    """True for ordinary on-disk pathlib paths (fast scandir route); False for dissect image paths."""
    return isinstance(path, pathlib.Path)          # (a module-name test breaks on Python 3.13+, where the classes live in pathlib._local)


def _entries(path):
    """-> iterator of (name, is_dir, is_link, child_path). Raises OSError if the directory can't be listed."""
    if _is_real(path):
        with os.scandir(path) as it:
            for e in it:
                try:
                    link = e.is_symlink() or bool(getattr(e, "is_junction", lambda: False)())
                    yield e.name, (not link and e.is_dir(follow_symlinks=False)), link, path / e.name
                except OSError:
                    yield e.name, False, True, path / e.name           # can't classify -> treat as link: never follow
    else:
        for c in path.iterdir():
            try:
                link = c.is_symlink()
                yield c.name, (not link and c.is_dir()), link, c
            except OSError:
                yield c.name, False, True, c


def _pseudo_mounts(root, os_name):
    out = set()
    if os_name != "linux" or str(root) != "/" or not _is_real(root):
        return out
    pseudo = {"proc", "sysfs", "devtmpfs", "devpts", "cgroup", "cgroup2", "squashfs", "overlay", "securityfs", "debugfs", "tracefs",
              "bpf", "binfmt_misc", "autofs", "mqueue", "hugetlbfs", "configfs", "fusectl", "nsfs", "nfs", "nfs4", "cifs", "smb3",
              "fuse.sshfs", "fuse.gvfsd-fuse", "fuse.portal"}
    try:
        with open("/proc/self/mounts") as f:
            for line in f:
                dev, mp, fs = line.split()[:3]
                if fs in pseudo: out.add(mp.encode().decode("unicode_escape"))
    except OSError:
        pass
    return out


class SweepStats(Counter):
    """dirs_visited, dirs_skipped, unreadable, files_seen, candidates, depth_capped + skipped_examples."""
    def __init__(self):
        super().__init__(); self.skipped_examples = []

    def skip(self, rel, why):
        self["dirs_skipped"] += 1
        if len(self.skipped_examples) < 40: self.skipped_examples.append(f"{rel}  [{why}]")

    def as_dict(self):
        d = dict(self); d["skipped_examples"] = self.skipped_examples; return d


# ---------------------------------------------------------------- user-chosen directories: --dir / --exclude-dir / --only-dirs
def norm_rel(s):
    """'C:\\Users\\Bob\\AppData\\' -> 'users/bob/appdata'. Raises ValueError for '..' (paths must stay inside the volume)."""
    s = re.sub(r"^[A-Za-z]:", "", str(s).strip().replace("\\", "/"))
    parts = [p for p in s.split("/") if p not in ("", ".")]
    if ".." in parts: raise ValueError(f"'..' is not allowed in {s!r}")
    return "/".join(parts).lower()


def _under(rel, prefixes):
    return any(rel == p or rel.startswith(p + "/") for p in prefixes)


class Scope:
    """Which directories the user asked for. `dirs`: where the sweep starts (volume-relative, or absolute under the source).
    `exclude`: never entered / never collected. `only_dirs`: the normal rules are limited to `dirs` as well."""
    def __init__(self, dirs=(), exclude=(), only_dirs=False):
        self.raw_dirs, self.raw_exclude, self.only_dirs = list(dirs or []), list(exclude or []), bool(only_dirs)
        self.dirs, self.exclude = (), ()

    def __bool__(self): return bool(self.raw_dirs or self.raw_exclude)

    def bind(self, root):
        """Return a copy whose paths are relative to `root` (an absolute path under the source is accepted too)."""
        b = Scope(self.raw_dirs, self.raw_exclude, self.only_dirs)
        base = str(root).replace("\\", "/").rstrip("/").lower()
        def rel(s):
            n = str(s).replace("\\", "/")
            if base and n.lower().startswith(base + "/"): n = n[len(base):]
            elif base and n.lower() == base: n = ""
            return norm_rel(n)
        b.dirs = tuple(sorted({rel(d) for d in self.raw_dirs}))
        b.dirs = tuple(d for d in b.dirs if not _under(d, [x for x in b.dirs if x != d]))      # nested dirs are covered by their parent
        b.exclude = tuple(sorted({rel(x) for x in self.raw_exclude} - {""}))
        return b

    def excluded(self, rel): return _under(rel, self.exclude)

    def allows_rule_match(self, rel):
        """For --only-dirs: may a file matched by a normal rule be collected? (`rel` is lower-case, volume-relative.)"""
        if self.excluded(rel): return False
        return not (self.only_dirs and self.dirs) or _under(rel, self.dirs)


def add_scope_args(ap):
    ap.add_argument("--dir", action="append", default=[], metavar="DIR",
                    help="only sweep this folder (repeatable; relative to the volume root, e.g. Users\\bob\\AppData, case-insensitive). Implies --sweep")
    ap.add_argument("--exclude-dir", action="append", default=[], metavar="DIR", help="never collect from or enter this folder (repeatable)")
    ap.add_argument("--only-dirs", action="store_true", help="with --dir: also limit the normal rules to those folders (default: rules still run on the whole volume)")


def scope_from_args(a):
    """-> Scope or None. Exits with a message when --only-dirs is given without --dir, or a path contains '..'."""
    s = Scope(getattr(a, "dir", []), getattr(a, "exclude_dir", []), getattr(a, "only_dirs", False))
    if s.only_dirs and not s.raw_dirs: raise SystemExit("--only-dirs needs at least one --dir")
    try: s.bind("/")
    except ValueError as e: raise SystemExit(f"error: {e}")
    return s if (s or s.only_dirs) else None


def resolve_dir(root, rel):
    """Case-insensitive lookup of volume-relative `rel` under `root` (NTFS/APFS images on a case-sensitive host). -> path or None."""
    cur = root
    for comp in [c for c in rel.split("/") if c]:
        try: nxt = next((c for n, is_dir, link, c in _entries(cur) if is_dir and n.lower() == comp), None)
        except Exception: return None
        if nxt is None: return None
        cur = nxt
    return cur


def smart_walk(root, os_name, skip=(), unreadable=None, stats=None, max_depth=DEFAULT_MAX_DEPTH, on_dir=None, scope=None):
    """Yield every log-like file under `root` (see module doc). `skip`: absolute paths never entered (e.g. the case folder).
    `unreadable`: list that receives {"path", "error"} dicts. `stats`: a SweepStats. `on_dir(path)`: progress callback.
    `scope`: a Scope; with dirs, the walk starts only there (and, being an explicit request, ignores the noise-path / allow-list rules)."""
    unreadable = [] if unreadable is None else unreadable
    stats = SweepStats() if stats is None else stats
    noise = NOISE_PATHS.get(os_name, set()); allow = ALLOW_CHILDREN.get(os_name, {})
    skip_abs = {os.path.normcase(str(s)) for s in skip} | {os.path.normcase(m) for m in _pseudo_mounts(root, os_name)}
    root_s = str(root)
    scope = scope.bind(root) if scope else None
    explicit = bool(scope and scope.dirs)
    if explicit:
        stack = []
        for rel in scope.dirs:
            d = None if scope.excluded(rel) else resolve_dir(root, rel)
            if d is None:
                why = "excluded by --exclude-dir" if scope.excluded(rel) else "directory not found"
                unreadable.append({"path": f"{root_s.rstrip('/' + chr(92))}/{rel}", "error": f"{why} (--dir)"}); stats["unreadable"] += 1; continue
            stack.append((d, rel, len(rel.split("/")), any(LOGDIR.match(x) for x in rel.split("/"))))
    else:
        stack = [(root, "", 0, False)]                            # (dir, rel path lower-case posix, depth, inside a log-named dir)
    while stack:
        d, rel, depth, in_log = stack.pop()
        stats["dirs_visited"] += 1
        if on_dir: on_dir(d)
        try:
            entries = list(_entries(d))
        except OSError as e:
            unreadable.append({"path": str(d), "error": f"{type(e).__name__}: {e}"}); stats["unreadable"] += 1; continue
        except Exception as e:                                    # dissect raises its own error types on damaged file systems
            unreadable.append({"path": str(d), "error": f"{type(e).__name__}: {e}"}); stats["unreadable"] += 1; continue
        allowed = None if explicit else allow.get(rel)
        for name, is_dir, is_link, child in entries:
            low = name.lower()
            if is_link:
                continue
            if not is_dir:
                stats["files_seen"] += 1
                if NAME.search(name) or (in_log and IN_LOGDIR.search(name)):
                    stats["candidates"] += 1; yield child
                continue
            crel = f"{rel}/{low}" if rel else low
            if allowed is not None and low not in allowed: stats.skip(crel, "not an allow-listed child"); continue
            if scope and scope.excluded(crel): stats.skip(crel, "--exclude-dir"); continue
            if crel in noise and not explicit: stats.skip(crel, "known noise path"); continue
            if low in NOISE_NAMES and not LOGDIR.match(name): stats.skip(crel, "known noise name"); continue
            if skip_abs and os.path.normcase(str(child)) in skip_abs: stats.skip(crel, "excluded"); continue
            child_in_log = in_log or bool(LOGDIR.match(name))
            if depth + 1 > max_depth and not child_in_log: stats["depth_capped"] += 1; stats.skip(crel, f"deeper than {max_depth}"); continue
            stack.append((child, crel, depth + 1, child_in_log))
