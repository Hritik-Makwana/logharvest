"""Live Android collection over USB debugging (adb).

Access level is detected per device:
  adbroot  adbd runs as root (emulator / userdebug build, or `adb root` worked)
  su       rooted device where `su -c` works
  shell    stock device (uid shell): other apps' private /data is off limits

What each level yields
  all       logcat (main buffer = app logs; system/crash/events/radio = system logs),
            bugreport.zip, getprop, `dumpsys dropbox` (system crashes/ANRs),
            `dumpsys activity exit-info` (per-app exit reasons), package list,
            app log files on shared storage (/sdcard/Android/data/<pkg>/{files,cache}/*.log)
  root/su   + /data/anr, tombstones, dropbox, logd, dmesg,
              /data/data/<pkg>/{files,cache}/*.log
  shell     + `run-as` for *debuggable* apps only (Android blocks everything else)

Needs a recent platform-tools (shell protocol v2: separate stderr + exit codes) and Android 7+.
"""
import getpass, hashlib, json, os, platform, re, shlex, subprocess
from pathlib import Path
from . import detect
from .collect import now, sha256, utc

EXTS = ("log", "txt", "xlog", "trace", "crash", "anr", "err", "dmp")
LOG_NAME = re.compile(r"\.(" + "|".join(EXTS) + r")(\.\d+)?(\.gz)?$", re.I)
NAMES = "\\( " + " -o ".join(f"-iname '*.{e}*'" for e in EXTS) + " \\)"   # shell-side pre-filter
STAT = "-exec stat -c '%s|%Y|%X|%Z|%n' {} +"          # size|mtime|atime|ctime|path
LC = "-d -v threadtime -v year -v UTC"

# dumpsys state snapshots: (file suffix, dumpsys arguments, category)
DUMPSYS = [
    ("battery", "battery", "system"), ("batterystats", "batterystats", "system"),
    ("meminfo", "meminfo", "system"), ("cpuinfo", "cpuinfo", "system"),
    ("diskstats", "diskstats", "system"), ("connectivity", "connectivity", "system"),
    ("netstats", "netstats", "system"), ("wifi", "wifi", "system"), ("input", "input", "system"),
    ("activity_activities", "activity activities", "application"),
    ("activity_processes", "activity processes", "application"),
    ("package", "package", "application"), ("usagestats", "usagestats", "application"),
]

# (output file, candidate commands tried in order, category, needs root)
JOBS = [
    ("getprop.txt", ["getprop"], "system", False),
    ("logcat_system.txt", [f"logcat -b system -b crash -b events -b radio {LC}",
                           f"logcat -b system -b crash -b events {LC}"], "system", False),
    ("logcat_main.txt", [f"logcat -b main {LC}", "logcat -b main -d"], "application", False),
    ("dumpsys_dropbox.txt", ["dumpsys dropbox --print"], "system", False),
    ("dumpsys_exit_info.txt", ["dumpsys activity exit-info"], "application", False),
    ("packages.txt", ["pm list packages -f -U -i", "pm list packages -f -U", "pm list packages -f"],
     "application", False),
    ("packages_user.txt", ["pm list packages -f -3 -U", "pm list packages -f -3"], "application", False),
    ("packages_system.txt", ["pm list packages -f -s -U", "pm list packages -f -s"], "system", False),
    ("logcat_kernel.txt", [f"logcat -b kernel {LC}"], "system", False),   # Android 9+; error row elsewhere
    ("dmesg.txt", ["dmesg"], "system", True),
] + [(f"dumpsys_{n}.txt", [f"dumpsys {c}"], cat, False) for n, c, cat in DUMPSYS]

def _adb(serial, *args, timeout=60):
    try:
        return subprocess.run([*detect.ADB_CMD, "-s", serial, *args], capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(args, 124, b"", b"timeout")

def _sh(serial, cmd, timeout=120):
    """Device shell command -> (exit code, stdout bytes, stderr text)."""
    r = _adb(serial, "shell", "-T", cmd, timeout=timeout)
    return r.returncode, r.stdout, r.stderr.decode("utf-8", "replace").strip()

def _wrap(mode, cmd):
    return "su -c " + shlex.quote(cmd) if mode == "su" else cmd

def _detect_access(serial, try_root):
    def root_id(cmd):
        rc, out, _ = _sh(serial, cmd, timeout=20)
        return rc == 0 and b"uid=0" in out
    if root_id("id"):
        return "adbroot"
    if try_root and _adb(serial, "root", timeout=20).returncode == 0:
        _adb(serial, "wait-for-device", timeout=30)
        if root_id("id"):
            return "adbroot"
    if root_id("su -c id"):            # Magisk may show a grant prompt on the phone
        return "su"
    return "shell"

def _find(serial, mode, paths, only_logs, runas=None):
    name = NAMES + " " if only_logs else ""
    inner = "find " + " ".join(paths) + " -type f " + name + STAT
    cmd = f"run-as {runas} {inner}" if runas else _wrap(mode, inner)
    _, out, err = _sh(serial, cmd, timeout=300)
    rows = []
    for line in out.decode("utf-8", "replace").splitlines():
        p = line.strip().split("|", 4)
        if len(p) == 5 and p[0].isdigit():
            if only_logs and not LOG_NAME.search(p[4]):
                continue
            rows.append((int(p[0]), int(p[1]), int(p[2]), int(p[3]), p[4]))
    return rows, err

def _pull(serial, devcmd, dest):
    """Stream a device file to dest, hashing on the fly. Returns (sha256, bytes)."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    h, n = hashlib.sha256(), 0
    p = subprocess.Popen([*detect.ADB_CMD, "-s", serial, "shell", "-T", devcmd],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        with open(dest, "wb") as f:
            while chunk := p.stdout.read(1 << 20):
                f.write(chunk); h.update(chunk); n += len(chunk)
        err = p.stderr.read().decode("utf-8", "replace").strip()
        rc = p.wait(timeout=60)
    except BaseException:
        p.kill(); raise
    if rc != 0:
        dest.unlink(missing_ok=True)
        raise RuntimeError(err or f"adb exit code {rc}")
    return h.hexdigest(), n

def _files(serial, case, ev, mf, device, category, rows, readcmd, base, srcfmt, max_mb):
    ok = err = 0
    for size, m, a, c, path in rows:
        rec = {"device": device, "os": "android", "category": category,
               "source": srcfmt(path), "collected_at": now(), "size": size,
               "modified": utc(m), "accessed": utc(a), "changed_or_created": utc(c)}
        try:
            if size > (max_mb << 20):
                raise ValueError(f"skipped: larger than {max_mb} MB")
            dest = ev / base / path.lstrip("/")
            if ev.resolve() not in dest.resolve().parents:      # path traversal guard
                raise ValueError("unsafe device path")
            digest, n = _pull(serial, readcmd(path), dest)
            os.utime(dest, (a, m))
            rec.update(sha256=digest, dest=str(dest.relative_to(case)), verified=(n == size))
            ok += 1
        except Exception as e:
            rec.update(error=f"{type(e).__name__}: {e}"); err += 1
        mf.write(json.dumps(rec) + "\n")
    return ok, err

def _dump(serial, mode, case, ev, mf, device, name, cmds, category):
    rec = {"device": device, "os": "android", "category": category,
           "source": "adb shell " + cmds[0], "collected_at": now()}
    last = "no output"
    for cmd in cmds:
        rc, out, e = _sh(serial, _wrap(mode, cmd), timeout=300)
        if rc == 0 and out.strip():
            dest = ev / name; dest.write_bytes(out); t = utc(dest.stat().st_mtime)
            rec.update(source="adb shell " + cmd, size=len(out), modified=t, accessed=t,
                       changed_or_created=t, sha256=hashlib.sha256(out).hexdigest(),
                       dest=str(dest.relative_to(case)), verified=True)
            mf.write(json.dumps(rec) + "\n")
            return True
        last = e or f"exit code {rc}, empty output"
    rec["error"] = last
    mf.write(json.dumps(rec) + "\n")
    return False

def _logcat_live(serial, case, ev, mf, device, secs):
    """Real-time capture: stream logcat (all buffers) for `secs` seconds."""
    cmd = [*detect.ADB_CMD, "-s", serial, "logcat", "-b", "all", "-v", "threadtime", "-v", "year", "-v", "UTC"]
    rec = {"device": device, "os": "android", "category": "application",
           "source": f"adb logcat -b all (live, {secs}s)", "collected_at": now()}
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        out, e = p.communicate(timeout=secs)          # logcat without -d runs until killed
    except subprocess.TimeoutExpired:
        p.kill(); out, e = p.communicate()
    if not out.strip():
        rec["error"] = e.decode("utf-8", "replace").strip() or "no output"
        mf.write(json.dumps(rec) + "\n"); return False
    dest = ev / "logcat_live.txt"; dest.write_bytes(out); t = utc(dest.stat().st_mtime)
    rec.update(size=len(out), modified=t, accessed=t, changed_or_created=t,
               sha256=hashlib.sha256(out).hexdigest(), dest=str(dest.relative_to(case)), verified=True)
    mf.write(json.dumps(rec) + "\n")
    return True

def collect_adb(serial: str, case: Path, max_mb: int = 512, try_root: bool = False,
                bugreport: bool = True, live_secs: int = 0):
    """Returns (access_mode, files_ok, errors)."""
    device = "adb-" + re.sub(r"[^\w.-]+", "_", serial)
    ev = case / "evidence" / device
    ev.mkdir(parents=True, exist_ok=True)
    ok = err = 0
    with open(case / "manifest.jsonl", "a", encoding="utf-8", newline="\n") as mf, \
         open(case / "audit.log", "a", encoding="utf-8", newline="\n") as al:
        mode = _detect_access(serial, try_root)
        al.write(f"{now()} START adb serial={serial} access={mode} adb_root_attempted={try_root} "
                 f"bugreport={bugreport} logcat_live={live_secs}s "
                 f"user={getpass.getuser()} host={platform.node()}\n")

        # 1. command output: logcat, dropbox, exit-info, props ...
        for name, cmds, cat, root_only in JOBS:
            if root_only and mode == "shell":
                continue
            if _dump(serial, mode, case, ev, mf, device, name, cmds, cat): ok += 1
            else: err += 1

        # 2. bugreport (several minutes; includes dumpstate, dropbox, often ANR traces/tombstones)
        if bugreport:
            bug = ev / "bugreport.zip"
            r = _adb(serial, "bugreport", str(bug), timeout=1200)
            rec = {"device": device, "os": "android", "category": "system",
                   "source": "adb bugreport", "collected_at": now()}
            if r.returncode == 0 and bug.exists():
                st = bug.stat()
                rec.update(size=st.st_size, modified=utc(st.st_mtime), accessed=utc(st.st_atime),
                           changed_or_created=utc(st.st_ctime), sha256=sha256(bug),
                           dest=str(bug.relative_to(case)), verified=True)
                ok += 1
            else:
                rec["error"] = r.stderr.decode("utf-8", "replace").strip() or f"exit code {r.returncode}"
                err += 1
            mf.write(json.dumps(rec) + "\n")

        if live_secs > 0:
            if _logcat_live(serial, case, ev, mf, device, live_secs): ok += 1
            else: err += 1

        # 3. log files on the device filesystem
        plans = [("application", ["/storage/emulated/0/Android/data/*/files",      # = /storage/self/primary/...
                                  "/storage/emulated/0/Android/data/*/cache",
                                  "/storage/emulated/0/Android/media/*"], True)]
        if mode in ("adbroot", "su"):
            plans += [("system", ["/data/anr", "/data/tombstones", "/data/system/dropbox",
                                  "/data/misc/logd"], False),
                      ("application", ["/data/data/*/files", "/data/data/*/cache"], True)]
        for category, paths, only_logs in plans:
            rows, e = _find(serial, mode, paths, only_logs)
            if e:
                al.write(f"{now()} NOTE find {paths[0]}: {e.splitlines()[0]}\n")
            o, x = _files(serial, case, ev, mf, device, category, rows,
                          lambda p: _wrap(mode, "cat " + shlex.quote(p)), "files", lambda p: p, max_mb)
            ok += o; err += x

        # 4. stock device: private app logs only reachable for debuggable apps via run-as
        if mode == "shell":
            _, out, _ = _sh(serial, "pm list packages -3", timeout=60)
            pkgs = [l.split(":", 1)[1].strip() for l in out.decode("utf-8", "replace").splitlines()
                    if l.startswith("package:")]
            n_dbg = 0
            for pkg in pkgs:
                rows, _ = _find(serial, mode, ["files", "cache"], True, runas=pkg)
                if not rows:
                    continue                       # not debuggable, or no log files
                n_dbg += 1
                o, x = _files(serial, case, ev, mf, device, "application", rows,
                              lambda p, pkg=pkg: f"run-as {pkg} cat {shlex.quote(p)}",
                              f"run-as/{pkg}", lambda p, pkg=pkg: f"run-as {pkg}:{p}", max_mb)
                ok += o; err += x
            al.write(f"{now()} NOTE run-as: {n_dbg}/{len(pkgs)} third-party apps had readable logs\n")

        al.write(f"{now()} END adb serial={serial} ok={ok} errors={err}\n")
    return mode, ok, err
