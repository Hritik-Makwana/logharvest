"""Android acquisition through the `adb` command line tool (run as a subprocess).

Works on a USB-connected (or wireless-debugging) phone/tablet with USB debugging enabled and the
computer's key authorised on the device. It never needs root, but root unlocks more evidence; every
step that cannot run is recorded as a `not_collected` row with the reason, and collection continues.

Order follows RFC 3227 (most volatile first):
  1. logcat ring buffers   (lost on reboot / overwritten within minutes)
  2. clock, uptime, process list, memory, battery state
  3. crash evidence reachable without root: dumpsys dropbox, exit-info (Android 11+), last ANR
  4. [--adb-root] restart adbd as root (userdebug/emulator builds only)
  5. root-only crash files pulled with `adb pull -a`: /data/anr, /data/tombstones, pstore, ...
  6. app/crash logs on shared storage (/sdcard, /data/local/tmp): found with `find`, pulled one by one
  7. `adb bugreport` (slow; the device writes the zip to its own storage first, so it goes last), then
     unpacked so every member (dumpstate, ANR traces, tombstones, ...) becomes its own hashed row

Requirements: platform-tools (`adb`) on PATH, or set LOGHARVEST_ADB=/path/to/adb.
"""
import argparse, getpass, hashlib, json, os, platform, re, shutil, subprocess, sys, time, zipfile
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

from .progress import Progress, Spinner, say

def now(): return datetime.now(timezone.utc).isoformat()
def utc(ts): return datetime.fromtimestamp(ts, timezone.utc).isoformat()

# (name, category, alternative argv lists tried in order until one works, timeout seconds)
# `adb shell` joins its arguments into one shell string, so nothing user-supplied goes in here
# unvalidated (see PKG_RE).
STEPS = [
    ("logcat", "volatile", [
        ["logcat", "-b", "all", "-d", "-v", "threadtime", "-v", "year", "-v", "UTC"],   # Android 7+: year + UTC
        ["logcat", "-b", "all", "-d", "-v", "threadtime"],
        ["logcat", "-d", "-v", "threadtime"]], 600),
    # logs from BEFORE the last reboot (kept by the kernel); the best non-root evidence after a crash-reboot
    ("logcat_last_boot", "system", [["logcat", "-L", "-b", "all", "-v", "threadtime"], ["logcat", "-L", "-v", "threadtime"]], 300),
    ("device_clock", "context", [["shell", "date", "-u", "+%Y-%m-%dT%H:%M:%SZ"]], 30),
    ("id", "context", [["shell", "id"]], 30),
    ("getprop", "context", [["shell", "getprop"]], 60),
    ("packages", "context", [["shell", "pm", "list", "packages", "-f", "-U", "-i", "--show-versioncode"], ["shell", "pm", "list", "packages", "-f", "-U", "-i"],
                             ["shell", "pm", "list", "packages", "-f", "--show-versioncode"], ["shell", "pm", "list", "packages", "-f"]], 120),
    ("packages_user", "context", [["shell", "pm", "list", "packages", "-f", "-3", "-U"], ["shell", "pm", "list", "packages", "-f", "-3"]], 120),
    ("packages_system", "context", [["shell", "pm", "list", "packages", "-f", "-s", "-U"], ["shell", "pm", "list", "packages", "-f", "-s"]], 120),
    ("uptime", "volatile", [["shell", "uptime"]], 30),
    ("meminfo", "volatile", [["shell", "dumpsys", "meminfo"]], 300),
    ("battery", "volatile", [["shell", "dumpsys", "battery"]], 60),
    ("ps", "volatile", [["shell", "ps", "-A", "-o", "PID,PPID,USER,STAT,RSS,NAME"], ["shell", "ps", "-A"], ["shell", "ps"]], 60),
    ("df", "volatile", [["shell", "df", "-h"]], 60),
    ("proc_meminfo", "volatile", [["shell", "cat", "/proc/meminfo"]], 30),
    ("proc_loadavg", "volatile", [["shell", "cat", "/proc/loadavg"]], 30),
    ("proc_pressure_memory", "volatile", [["shell", "cat", "/proc/pressure/memory"]], 30),
    ("activity_processes", "volatile", [["shell", "dumpsys", "activity", "processes"]], 300),
    ("cpuinfo", "volatile", [["shell", "dumpsys", "cpuinfo"]], 120),
    ("procstats", "volatile", [["shell", "dumpsys", "procstats"]], 300),
    ("power", "volatile", [["shell", "dumpsys", "power"]], 120),
    ("thermal", "volatile", [["shell", "dumpsys", "thermalservice"]], 60),
    ("diskstats", "volatile", [["shell", "dumpsys", "diskstats"]], 120),
    ("jobscheduler", "volatile", [["shell", "dumpsys", "jobscheduler"]], 120),
    ("batterystats", "volatile", [["shell", "dumpsys", "batterystats"]], 300),
    ("connectivity", "volatile", [["shell", "dumpsys", "connectivity"]], 120),
    ("netstats", "volatile", [["shell", "dumpsys", "netstats"]], 120),
    ("wifi", "volatile", [["shell", "dumpsys", "wifi"]], 120),
    ("input", "volatile", [["shell", "dumpsys", "input"]], 120),
    ("activity_activities", "volatile", [["shell", "dumpsys", "activity", "activities"]], 300),
    ("usagestats", "context", [["shell", "dumpsys", "usagestats"]], 300),               # often denied without a privileged shell
    ("package_all", "context", [["shell", "dumpsys", "package"]], 600),                 # installer, versions, permissions of every app
    ("logcat_kernel", "system", [["logcat", "-b", "kernel", "-d", "-v", "threadtime", "-v", "year", "-v", "UTC"]], 120),   # Android 9+
    ("dmesg", "system", [["shell", "dmesg"]], 120),                                   # usually denied without root
    ("dropbox", "crash", [["shell", "dumpsys", "dropbox", "--print"]], 900),          # crashes, ANRs, WTFs, no root
    ("exit_info", "crash", [["shell", "dumpsys", "activity", "exit-info"]], 300),     # Android 11+: why each process died
    ("lastanr", "crash", [["shell", "dumpsys", "activity", "lastanr"]], 120),
]

# Root-only locations. We always try, and record the failure if the shell user is not allowed.
PULLS = [("crash", "/data/anr"), ("crash", "/data/tombstones"), ("crash", "/data/system/dropbox"),
         ("crash", "/sys/fs/pstore"), ("system", "/data/misc/logd"), ("system", "/data/misc/bootstat")]

PKG_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)+$")      # e.g. com.example.app

# ---------------------------------------------------------------- adb plumbing
def adb_cmd():
    from . import detect
    if detect.ADB_CMD != ["adb"]: return list(detect.ADB_CMD)      # tests point this at a fake adb
    env = os.environ.get("LOGHARVEST_ADB")
    if env: return [env]
    exe = shutil.which("adb")
    if exe: return [exe]
    name = "adb.exe" if os.name == "nt" else "adb"
    homes = [os.environ.get("ANDROID_HOME"), os.environ.get("ANDROID_SDK_ROOT"),
             os.path.join(os.environ.get("LOCALAPPDATA", ""), "Android", "Sdk"),
             os.path.expanduser("~/Android/Sdk"), os.path.expanduser("~/Library/Android/sdk")]
    for h in homes:
        if h and os.path.isfile(os.path.join(h, "platform-tools", name)):
            return [os.path.join(h, "platform-tools", name)]
    return [name]

def _adb(args, timeout=30):
    return subprocess.run(adb_cmd() + args, capture_output=True, text=True, timeout=timeout)

def list_devices():
    """Attached Android devices with state. Raises RuntimeError with a human-readable reason."""
    try:
        p = _adb(["devices", "-l"])
    except (OSError, subprocess.SubprocessError) as e:
        raise RuntimeError(f"cannot run adb ({e}). Install Android platform-tools, or set LOGHARVEST_ADB=/path/to/adb")
    if p.returncode != 0:
        raise RuntimeError(f"`adb devices` failed: {(p.stderr or p.stdout).strip()[-300:]}")
    devs = []
    for line in p.stdout.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 2: continue
        d = dict(serial=parts[0], state=parts[1], model="?", release="?", sdk="?", maker="?")
        d.update({k: v for k, v in (x.split(":", 1) for x in parts[2:] if ":" in x) if k in ("model",)})
        if d["state"] == "device":
            try:
                props = dict(re.findall(r"\[([^\]]+)\]: \[([^\]]*)\]", _adb(["-s", d["serial"], "shell", "getprop"], 30).stdout))
                d.update(model=props.get("ro.product.model", d["model"]), release=props.get("ro.build.version.release", "?"),
                         sdk=props.get("ro.build.version.sdk", "?"), maker=props.get("ro.product.manufacturer", "?"))
            except (OSError, subprocess.SubprocessError): pass
        devs.append(d)
    return devs

def _sha256(path, bufsize=1 << 20):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(bufsize): h.update(chunk)
    return h.hexdigest()

def _run(argv, stdout_path, stderr_path, timeout):
    """Run, streaming stdout to a file. On timeout: terminate and keep the partial output."""
    t0, timed_out = time.time(), False
    with open(stdout_path, "wb") as so:
        p = subprocess.Popen(argv, stdout=so, stderr=subprocess.PIPE)
        try:
            _, err = p.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True; p.terminate()
            try: _, err = p.communicate(timeout=10)
            except subprocess.TimeoutExpired: p.kill(); _, err = p.communicate()
    Path(stderr_path).write_bytes(err or b"")
    return p.returncode, (err or b"").decode("utf-8", "replace").strip()[-1500:], timed_out, round(time.time() - t0, 1)

def _files(p: Path):
    if p.is_file(): return [p]
    if p.is_dir(): return sorted(x for x in p.rglob("*") if x.is_file() and not x.is_symlink())
    return []

def prune_empty(root):
    """adb creates the destination folder even when a pull fails; remove empties (rmdir only works on empty dirs)."""
    for dp, _dn, _fn in os.walk(root, topdown=False):
        try: os.rmdir(dp)
        except OSError: pass

class Session:
    """Standalone manifest/audit writer for collectors that run outside collect_android (android-apps).
    Offers the same helpers collect_android shares with apps.py: log audit record nc safe_dest counts by_cat pulled."""
    def __init__(self, case, dev):
        self.case, self.serial = case, dev["serial"]
        self.did = "android-" + re.sub(r"[^\w.-]+", "_", self.serial)[:24]
        self.ev = case / "evidence" / self.did; (self.ev / "_commands").mkdir(parents=True, exist_ok=True)
        self.base = adb_cmd() + ["-s", self.serial]
        self.counts, self.by_cat, self.pulled = {"ok": 0, "nc": 0}, Counter(), set()
    def __enter__(self):
        self.mf = open(self.case / "manifest.jsonl", "a"); self.al = open(self.case / "audit.log", "a"); return self
    def __exit__(self, *exc): self.mf.close(); self.al.close()
    def log(self, rec): self.mf.write(json.dumps(rec) + "\n"); self.mf.flush()
    def audit(self, msg): self.al.write(f"{now()} {msg}\n"); self.al.flush()
    def record(self, f, category, step, argv, kind, remote=None, partial=False, source=None, times=None, **extra):
        st = f.stat(); t = now()
        rec = dict(device=self.did, os="android", category=category, rule=f"adb:{step}", kind=kind,
                   source=source or (f"adb://{self.serial}{remote}" if remote else f"adb://{self.serial}/{f.name}"),
                   collected_at=t, size=st.st_size, sha256=_sha256(f), dest=str(f.relative_to(self.case)),
                   verified=True, command=" ".join(argv))
        if times is not None: rec.update(times)
        elif kind == "pulled_file":
            rec.update(modified=utc(st.st_mtime), accessed=None, changed_or_created=None,
                       timestamps_note="modified = device mtime via adb pull -a; accessed/changed not captured")
        else: rec.update(modified=t, accessed=t, changed_or_created=t)
        if partial: rec["partial"] = True
        rec.update(extra); self.log(rec)
    def nc(self, rule, source, error, command=""):
        self.log(dict(device=self.did, os="android", category="not_collected", rule=rule, source=source,
                      collected_at=now(), command=command, error=error))
        self.counts["nc"] += 1
    @staticmethod
    def safe_dest(root, rel):
        parts = [x for x in rel.replace("\\", "/").split("/") if x not in ("", ".")]
        if not parts or ".." in parts or re.match(r"^[A-Za-z]:", parts[0]): return None
        dest = root.joinpath(*parts)
        return dest if root.resolve() in dest.resolve().parents else None

# ---------------------------------------------------------------- collection
def collect_android(case: Path, dev: dict, a):
    serial = dev["serial"]
    did = "android-" + re.sub(r"[^\w.-]+", "_", serial)[:24]
    ev = case / "evidence" / did; cmds = ev / "_commands"; cmds.mkdir(parents=True, exist_ok=True)
    base = adb_cmd() + ["-s", serial]
    by_cat, counts, uid = Counter(), {"ok": 0, "nc": 0}, None
    packages = list(getattr(a, "package", []) or [])

    with open(case / "manifest.jsonl", "a") as mf, open(case / "audit.log", "a") as al:
        def log(rec): mf.write(json.dumps(rec) + "\n"); mf.flush()
        def audit(msg): al.write(f"{now()} {msg}\n"); al.flush()

        def record(f, category, step, argv, kind, remote=None, partial=False, source=None, times=None, **extra):
            st = f.stat(); t = now()
            rec = dict(device=did, os="android", category=category, rule=f"adb:{step}", kind=kind,
                       source=source or (f"adb://{serial}{remote}" if remote else f"adb://{serial}/{f.name}"),
                       collected_at=t, size=st.st_size, sha256=_sha256(f), dest=str(f.relative_to(case)),
                       verified=True, command=" ".join(argv))
            if times is not None:
                rec.update(times)
            elif kind == "pulled_file":    # adb pull -a restores the device mtime; atime/ctime are NOT the device's
                rec.update(modified=utc(st.st_mtime), accessed=None, changed_or_created=None,
                           timestamps_note="modified = device mtime via adb pull -a; accessed/changed not captured")
            else:                          # output generated at collection time
                rec.update(modified=t, accessed=t, changed_or_created=t)
            if partial: rec["partial"] = True
            rec.update(extra); log(rec)

        def execute(name, category, alts, timeout, capture=None, out=None, remote=None, hint="", allow_empty=False, app=None, live=False):
            nonlocal uid
            so = cmds / (capture or f"{name}.stdout.txt"); se = cmds / f"{name}.stderr.txt"
            rc, err, timed_out, produced, argv = -1, "", False, [], []
            for alt in alts:
                argv = base + alt
                audit(f"RUN {name}: {' '.join(argv)}")
                try: rc, err, timed_out, secs = _run(argv, so, se, timeout)
                except OSError as e: rc, err, timed_out, secs = -1, f"{type(e).__name__}: {e}", False, 0
                produced = [f for f in (_files(out) if out else [so]) if f.stat().st_size or (allow_empty and rc == 0)]
                audit(f"DONE {name}: rc={rc} timed_out={timed_out} files={len(produced)} seconds={secs}"
                      + (f" err={err[-200:]!r}" if rc != 0 else ""))
                if ((rc == 0 and not timed_out) or (live and timed_out)) and produced: break
            ok = ((rc == 0 and not timed_out) or (live and timed_out)) and bool(produced)      # live stream: stopping at the deadline is success
            kind = "pulled_file" if remote else ("tool_export" if out else "command_output")
            for f in produced:
                src_remote = f"{remote}/{f.relative_to(out).as_posix()}" if remote and out and out.is_dir() else remote
                record(f, category, name, argv, kind, src_remote, partial=not ok, **({"app": app} if app else {}))
                counts["ok"] += 1; by_cat[category] += 1
            if produced and out:           # adb's own summary lines are evidence of what was transferred
                for f in (so, se):
                    if f.exists() and f.stat().st_size: record(f, "tool_output", name, argv, "tool_output")
            if name == "id" and ok:
                m = re.search(r"uid=(\d+)", so.read_text("utf-8", "replace")); uid = int(m.group(1)) if m else uid
            if name == "device_clock" and ok:
                audit(f"CLOCK device_utc={so.read_text('utf-8', 'replace').strip()!r} host_utc={now()}")
            if not ok:
                reason = (f"timed out after {timeout}s, output may be partial" if timed_out else
                          "produced no output" if rc == 0 else f"exit code {rc}")
                log(dict(device=did, os="android", category="not_collected", rule=f"adb:{name}",
                         source=f"adb://{serial}{remote or '/' + name}", collected_at=now(),
                         command=" ".join(argv), error=f"{reason}. {err} {hint}".strip(), **({"app": app} if app else {})))
                counts["nc"] += 1

        def nc(rule, source, error, command="", **extra):
            log(dict(device=did, os="android", category="not_collected", rule=rule, source=source,
                     collected_at=now(), command=command, error=error, **extra))
            counts["nc"] += 1

        def safe_dest(root, rel):
            """Join a device- or zip-supplied relative path under root. None if it could escape root."""
            parts = [x for x in rel.replace("\\", "/").split("/") if x not in ("", ".")]
            if not parts or ".." in parts or re.match(r"^[A-Za-z]:", parts[0]): return None
            dest = root.joinpath(*parts)
            return dest if root.resolve() in dest.resolve().parents else None

        def prune_empty(root):
            """adb creates the destination folder even when a pull fails; an empty folder would look like
            'collected but empty', so remove it (rmdir only succeeds on empty directories)."""
            for dp, _dn, _fn in os.walk(root, topdown=False):
                try: os.rmdir(dp)
                except OSError: pass

        def sdcard_sweep():
            """Find log-like files on shared storage (app logs live here), then pull each with a size cap."""
            tail = ("-type f \\( -iname '*.log' -o -iname '*.log.*' -o -iname '*.crash' "
                    "-o -iname '*.trace' -o -iname '*.dmp' -o -iname '*.stacktrace' -o -iname '*.xlog' -o -iname '*.anr' -o -iname '*.err' "
                    "-o -path '*/logs/*' -o -path '*/log/*' -o \\( -iname '*.txt' -path '/sdcard/Android/data/*' \\) \\) "
                    "-exec stat -c '%s %n' {} +")
            # /sdcard is a SYMLINK on Android. Plain `find /sdcard` does not descend into it: exit 0, no output.
            alts = [["shell", "find -H /sdcard /data/local/tmp " + tail],
                    ["shell", "find /sdcard/ /data/local/tmp/ " + tail]]
            execute("sdcard_find", "context", alts, 300, capture="sdcard_candidates.txt", allow_empty=True)
            listing = cmds / "sdcard_candidates.txt"
            if not listing.exists(): return
            cands = {}
            for line in listing.read_text("utf-8", "replace").splitlines():
                sz, _, path = line.partition(" ")
                if sz.isdigit() and path.startswith("/"): cands[path] = int(sz)
            cap = getattr(a, "max_size_mb", 100) << 20; limit = getattr(a, "max_files", 500)
            items = sorted(cands.items()); n_ok = 0
            audit(f"SDCARD candidates={len(items)} limit={limit} size_cap_mb={cap >> 20}")
            bar = Progress("Shared-storage logs", min(len(items), limit) if items else 0, "files")
            for n, (remote, size) in enumerate(items):
                src = f"adb://{serial}{remote}"
                if n < limit and remote not in S.pulled: bar.update(1, 0, remote)
                if remote in S.pulled: continue          # already collected with its app folder
                if n >= limit:
                    nc("adb:sdcard_logs", f"adb://{serial}/sdcard", f"{len(items) - n} further candidates not pulled "
                       f"(limit {limit}, raise --max-files); full list in sdcard_candidates.txt"); break
                if size > cap: nc("adb:sdcard_logs", src, f"NOT COLLECTED: {size} bytes is over --max-size-mb"); continue
                dest = safe_dest(ev / "pulled", remote)
                if dest is None: nc("adb:sdcard_logs", src, "NOT COLLECTED: unsafe path reported by device"); continue
                argv = base + ["pull", "-a", remote, str(dest)]
                try:
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    r = subprocess.run(argv, capture_output=True, timeout=120)
                    ok, err = r.returncode == 0 and dest.is_file(), r.stderr.decode("utf-8", "replace").strip()[-300:]
                except (OSError, subprocess.SubprocessError) as e:
                    ok, err = False, f"{type(e).__name__}: {e}"
                if not ok: nc("adb:sdcard_logs", src, f"pull failed. {err}", " ".join(argv)); continue
                cat = "application" if re.search(r"/Android/(data|media)/", remote) else "discovered"
                record(dest, cat, "sdcard_logs", argv, "pulled_file", remote)
                counts["ok"] += 1; by_cat[cat] += 1; n_ok += 1; bar.bytes += size
            bar.close(); audit(f"SDCARD pulled={n_ok}")

        def extract_bugreport(zpath):
            """Unpack the bugreport so each member is its own hashed, searchable row. The original zip stays
            the evidence; members are derived copies and carry the zip's hash as parent_sha256."""
            parent_sha = _sha256(zpath); root = ev / "bugreport_extracted"; total = n = 0
            try: zf = zipfile.ZipFile(zpath)
            except (zipfile.BadZipFile, OSError) as e:
                nc("adb:bugreport_extract", f"adb://{serial}/bugreport.zip", f"could not unpack: {type(e).__name__}: {e}"); return
            with zf:
                infos = zf.infolist(); ubar = Progress("Unpacking bugreport", len(infos), "members")
                for zi in infos:
                    ubar.update(1, 0, zi.filename)
                    if zi.is_dir(): continue
                    name = zi.filename; src = f"adb://{serial}/bugreport.zip!/{name}"
                    dest = safe_dest(root, name)
                    if dest is None: nc("adb:bugreport_extract", src, "NOT UNPACKED: unsafe path inside zip"); continue
                    if zi.file_size > (2 << 30) or total + zi.file_size > (8 << 30) or n >= 20000:
                        nc("adb:bugreport_extract", src, "NOT UNPACKED: size/count limit"); continue
                    try:
                        dest.parent.mkdir(parents=True, exist_ok=True)
                        with zf.open(zi) as fi, open(dest, "wb") as fo: shutil.copyfileobj(fi, fo, 1 << 20)
                    except Exception as e:
                        nc("adb:bugreport_extract", src, f"NOT UNPACKED: {type(e).__name__}: {e}"); continue
                    total += zi.file_size; n += 1
                    try: mt = datetime(*zi.date_time).isoformat()
                    except ValueError: mt = None
                    cat = "crash" if re.search(r"(^|/)(anr|tombstones?|dropbox)(/|$)|(^|/)(anr_|tombstone_)", name, re.I) else "system"
                    record(dest, cat, "bugreport_extract", ["unpack", "bugreport.zip"], "bugreport_member", source=src,
                           times=dict(modified=mt, accessed=None, changed_or_created=None,
                                      timestamps_note="modified = zip entry time (device local time, no timezone)"),
                           parent_sha256=parent_sha, derived=True)
                    counts["ok"] += 1; by_cat[cat] += 1; ubar.bytes += zi.file_size
                ubar.close()
            audit(f"UNPACK bugreport members={n} bytes={total}")

        # Shared with apps.py (per-app folder collection)
        S = SimpleNamespace(case=case, serial=serial, did=did, ev=ev, base=base, log=log, audit=audit, record=record,
                            nc=nc, safe_dest=safe_dest, counts=counts, by_cat=by_cat, pulled=set())

        def analyse_now():
            """Read what has been collected so far (logcat, dropbox, exit-info, tombstones/ANR files) and rank the
            suspects. Returns (result, installed apps that are suspects, most recent first). Writes nothing."""
            from .suspects import scan
            files = {f"adb:{n}": cmds / f"{n}.txt" for n in ("logcat", "dropbox", "getprop", "device_clock", "exit_info")
                     if (cmds / f"{n}.txt").is_file()}
            crash_files = [x for x in ev.rglob("*") if x.is_file() and "_commands" not in x.parts and
                           re.search(r"(^|/)(tombstones?|anr)/[^/]+$", x.as_posix(), re.I) and not x.name.endswith((".pb", ".proto"))]
            days = getattr(a, "suspect_days", 14); since = None
            if days and "adb:device_clock" in files:
                m = re.match(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)", files["adb:device_clock"].read_text("utf-8", "replace"))
                if m: since = datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc) - timedelta(days=days)
            res = scan(files, since=since, crash_files=crash_files)
            installed = set(); pk = cmds / "packages.txt"
            if pk.is_file():
                for line in pk.read_text("utf-8", "replace").splitlines():
                    if line.startswith("package:") and line[8:].split():
                        installed.add(line[8:].split()[0].rsplit("=", 1)[-1])
            def to_pkg(proc):                      # a process name is not always a package (pkg:service, pkg.sub)
                nm = proc.split(":")[0]
                if not PKG_RE.match(nm): return None
                if not installed or nm in installed: return nm
                return max((q for q in installed if nm.startswith(q + ".")), key=len, default=None)
            chosen = []
            for proc, _evs in res["ranked"]:
                pkg = to_pkg(proc)
                if pkg and pkg not in chosen: chosen.append(pkg)
            chosen = chosen[: getattr(a, "max_suspects", 5)]
            audit(f"SUSPECTS since={since} ranked={[p for p, _ in res['ranked']]} chosen={chosen} crash_files={len(crash_files)}")
            return res, chosen

        def write_report(res):
            from .suspects import render, to_json
            adir = case / "analysis"; adir.mkdir(exist_ok=True)
            for fname, body in ((f"suspects-{did}.txt", render(res, did, limit=3, next_hint=False) + "\n"),
                                (f"suspects-{did}.json", to_json(res, did))):
                (adir / fname).write_text(body)
                record(adir / fname, "analysis", "suspects", ["logharvest", "suspects"], "analysis",
                       source=f"analysis://{did}/{fname}", derived=True)
                counts["ok"] += 1; by_cat["analysis"] += 1

        groups = {}                                     # package -> "requested" | "suspect", in the order they were added

        def add_targets(new):
            """Collect details and shared-storage folders for packages not handled yet."""
            fresh = [(p, g) for p, g in new if p not in groups]
            for p, g in fresh: groups[p] = g
            for p, g in fresh:
                execute(f"exit_info_{p}", "crash", [["shell", "dumpsys", "activity", "exit-info", p]], 120, capture=f"exit_info_{p}.txt", app=p)
                execute(f"package_{p}", "context", [["shell", "dumpsys", "package", p]], 120, capture=f"package_{p}.txt", app=p)
                execute(f"meminfo_{p}", "volatile", [["shell", "dumpsys", "meminfo", p]], 60, capture=f"meminfo_{p}.txt", app=p)
            if fresh and not getattr(a, "no_app_folders", False):
                from .apps import list_app_files, pull_app
                listing = list_app_files(S, [p for p, _ in fresh], include_cache=getattr(a, "include_cache", False), tag="targets_" + "_".join(p[-8:] for p, _ in fresh)[:60])
                abar = Progress("App folders", sum(len(listing.get(p, [])) for p, _ in fresh), "files")
                for p, g in fresh:
                    r = pull_app(S, p, listing.get(p, []), per_file_cap=getattr(a, "max_size_mb", 100) << 20,
                                 max_files=getattr(a, "max_app_files", 300), max_bytes=getattr(a, "max_app_mb", 500) << 20, group=g, bar=abar)
                    say(f"  {p} ({g}): {r['files']} files, {r['bytes'] / 1048576:.1f} MB"
                        + (f", {r['skipped']} not copied (see not_collected rows)" if r["skipped"] else ""))
                abar.close()
            return [p for p, _ in fresh]

        try: ver = _adb(["version"], 20).stdout.strip().replace("\n", " | ")
        except Exception: ver = "unknown"
        audit(f"START android serial={serial} model={dev['model']!r} android={dev['release']} sdk={dev['sdk']} "
              f"user={getpass.getuser()} host={platform.node()} python={sys.version.split()[0]} adb={ver!r} "
              f"authority={getattr(a, 'authority', '')!r} packages={packages}")
        audit("NOTE adb records the USB-debugging authorisation, every shell command and the bugreport on the device; "
              "unavoidable footprint. bugreport/pull write temporary files to device storage.")

        with Progress("Collecting logs", len(STEPS), "steps") as bar:
            for name, category, alts, timeout in STEPS:
                bar.set_item(name)
                execute(name, category, alts, timeout, capture=f"{name}.txt")
                bar.update(1)

        secs = int(getattr(a, "logcat_live", 0) or 0)
        if secs > 0:                                     # real-time capture on top of the buffer dump (-T 1: no replay)
            with Spinner(f"Live logcat ({secs}s)"):
                execute("logcat_live", "volatile", [["logcat", "-b", "all", "-T", "1", "-v", "threadtime", "-v", "year", "-v", "UTC"]],
                        secs, capture="logcat_live.txt", live=True)

        # Apps named with --package, plus (unless --no-suspects) the apps that crashed or hung according to the logs
        res = None
        if not getattr(a, "no_suspects", False):
            res, chosen = analyse_now()
            print("Suspect apps (crashed or hung): " + ", ".join(chosen) if chosen else
                  "No crashed or hung app found in logcat/dropbox/exit-info so far" + (f" (last {a.suspect_days} days)" if getattr(a, "suspect_days", 14) else "") + ".")
        else: chosen = []
        add_targets([(p, "requested") for p in packages] + [(p, "suspect") for p in chosen if p not in packages])

        if getattr(a, "adb_root", False):
            audit("ROOT opt-in: running `adb root` (restarts adbd on the device; only works on userdebug/emulator builds)")
            try:
                r = subprocess.run(base + ["root"], capture_output=True, text=True, timeout=30)
                audit(f"ROOT rc={r.returncode} out={(r.stdout + r.stderr).strip()!r}")
                subprocess.run(base + ["wait-for-device"], timeout=60)
                time.sleep(2)
            except (OSError, subprocess.SubprocessError) as e:
                audit(f"ROOT failed: {e}")
            execute("id_after_root", "context", [["shell", "id"]], 30, capture="id_after_root.txt")
            m = re.search(r"uid=(\d+)", (cmds / "id_after_root.txt").read_text("utf-8", "replace")) if (cmds / "id_after_root.txt").exists() else None
            uid = int(m.group(1)) if m else uid
        audit(f"SHELL uid={uid}")
        su_ok = False
        if uid not in (0, None) and not getattr(a, "no_su", False):     # rooted phone with su: the shell can ask it to read root-only files
            try:
                r = subprocess.run(base + ["shell", "-T", "su -c id"], capture_output=True, timeout=45)
                su_ok = r.returncode == 0 and b"uid=0" in r.stdout
            except (OSError, subprocess.SubprocessError): pass
            audit(f"ACCESS su={'available' if su_ok else 'not available'} (a root manager such as Magisk may show a prompt on the phone; use --no-su to skip)")
            if su_ok:
                execute("dmesg_su", "system", [["shell", "su", "-c", "dmesg"]], 120, capture="dmesg_su.txt")

        hint = f"(adb shell uid={uid}: root is required for this path; the bugreport may still contain it)" if uid not in (0, None) else ""
        with Progress("Crash folders", len(PULLS), "paths") as bar:
            for category, remote in PULLS:
                bar.set_item(remote)
                if su_ok and remote.startswith("/data/"):       # `adb pull` cannot read these as the shell user; stream them through su
                    from .apps import list_via, pull_streamed, wrap_su
                    rows, err = list_via(S, wrap_su, remote)
                    if rows:
                        r = pull_streamed(S, wrap_su, "su", rows, ev / "pulled", lambda p: p.lstrip("/"), lambda p: f"adb://{serial}{p or remote}",
                                          category, "pull_" + remote.strip("/").replace("/", "_"), getattr(a, "max_size_mb", 100) << 20, 5000, 4 << 30)
                        counts["pulled_su"] = counts.get("pulled_su", 0) + r["files"]
                    else: nc("adb:pull_" + remote.strip("/").replace("/", "_"), f"adb://{serial}{remote}", f"su listing found no files. {err}")
                    bar.update(1); continue
                parent = ev / "pulled" / remote.strip("/").rsplit("/", 1)[0] if "/" in remote.strip("/") else ev / "pulled"
                parent.mkdir(parents=True, exist_ok=True)
                execute("pull_" + remote.strip("/").replace("/", "_"), category, [["pull", "-a", remote, str(parent)]], 900,
                        out=parent / remote.rsplit("/", 1)[1], remote=remote, hint=hint)
                bar.update(1)

        prune_empty(ev / "pulled")
        if not getattr(a, "no_sdcard", False):
            sdcard_sweep()
            prune_empty(ev / "pulled")
        if not getattr(a, "no_bugreport", False):
            out = ev / "bugreport.zip"
            with Spinner("Bugreport (the phone builds it; can take several minutes)"):
                execute("bugreport", "system", [["bugreport", str(out)]], 1800, out=out)
            if not getattr(a, "no_unpack", False) and out.is_file() and out.stat().st_size:
                extract_bugreport(out)
        if res is not None:                              # second look: tombstones and ANR traces are now available
            res2, chosen2 = analyse_now()
            more = add_targets([(p, "suspect") for p in chosen2])
            if more: print("Further suspect apps found in tombstones/ANR traces: " + ", ".join(more))
            write_report(res2)
        if groups and uid == 0 and not getattr(a, "no_app_folders", False):
            from .apps import pull_private
            with Progress("Private app data", len(groups), "apps") as bar:
                for p, g in groups.items():
                    bar.set_item(p)
                    r = pull_private(S, p, g, timeout=900); bar.update(1, 0, p)
                    say(f"  {p}: {r['files']} private files (/data/data), {r['skipped']} not copied")
        elif groups and su_ok and not getattr(a, "no_app_folders", False):
            from .apps import pull_private_su
            with Progress("Private app data (su)", len(groups), "apps") as bar:
                for p, g in groups.items():
                    bar.set_item(p)
                    r = pull_private_su(S, p, g, getattr(a, "max_size_mb", 100) << 20, getattr(a, "max_app_files", 300), getattr(a, "max_app_mb", 500) << 20,
                                        getattr(a, "include_cache", False)); bar.update(1, 0, p)
                    say(f"  {p}: {r['files']} private files via su, {r['skipped']} not copied")
        elif groups and uid not in (0, None) and not getattr(a, "no_app_folders", False):
            from .apps import pull_runas
            got = 0
            for p, g in groups.items():                  # stock phone: only debuggable apps allow run-as
                r = pull_runas(S, p, g, getattr(a, "max_size_mb", 100) << 20, getattr(a, "max_app_files", 300), getattr(a, "max_app_mb", 500) << 20,
                               getattr(a, "include_cache", False))
                if r:
                    got += 1; say(f"  {p}: {r['files']} private files via run-as (debuggable app), {r['skipped']} not copied")
            audit(f"NOTE private app data (/data/data) not collected for {len(groups) - got}/{len(groups)} apps: shell uid={uid}, no su; "
                  f"run-as works only for debuggable apps ({got} were). Root (--adb-root on userdebug builds) would allow all.")
        audit(f"END ok={counts['ok']} not_collected={counts['nc']}")
    return dict(device=did, ok=counts["ok"], not_collected=counts["nc"], by_category=dict(by_cat))

# ---------------------------------------------------------------- CLI glue
def add_args(ap):
    ap.add_argument("--case", type=Path, help="case folder (created if missing)")
    ap.add_argument("--list", action="store_true", help="only list attached Android devices")
    ap.add_argument("--serial", help="required when more than one device is attached")
    ap.add_argument("--package", action="append", default=[], metavar="PKG",
                    help="always collect this app's details and folder, e.g. com.example.app (repeatable)")
    ap.add_argument("--no-suspects", action="store_true", help="do not look for crashed/hung apps in the logs")
    ap.add_argument("--max-suspects", type=int, default=5, help="collect at most this many suspect apps (default 5)")
    ap.add_argument("--suspect-days", type=int, default=14, help="only crashes from the last N days count; 0 = no limit (default 14)")
    ap.add_argument("--no-app-folders", action="store_true", help="collect suspect/--package apps' details but not their folders")
    ap.add_argument("--include-cache", action="store_true", help="also copy apps' cache folders (skipped by default)")
    ap.add_argument("--max-app-files", type=int, default=300, help="max files copied per app folder (default 300)")
    ap.add_argument("--max-app-mb", type=int, default=500, help="max MB copied per app (default 500)")
    ap.add_argument("--no-bugreport", action="store_true", help="skip `adb bugreport` (slow, large)")
    ap.add_argument("--no-unpack", action="store_true", help="keep bugreport.zip as one file (do not list its members)")
    ap.add_argument("--no-sdcard", action="store_true", help="skip the search for log files on shared storage")
    ap.add_argument("--max-files", type=int, default=500, help="max shared-storage log files to pull (default 500)")
    ap.add_argument("--max-size-mb", type=int, default=100, help="skip shared-storage files larger than this (default 100)")
    ap.add_argument("--adb-root", action="store_true", help="run `adb root` first (userdebug/emulator builds only; restarts adbd)")
    ap.add_argument("--no-su", action="store_true", help="do not try `su` on a rooted phone (it may show a grant prompt on the phone)")
    ap.add_argument("--logcat-live", type=int, default=0, metavar="SECONDS", help="also stream logcat for SECONDS after the buffer dump")
    ap.add_argument("--authority", default="", help="warrant / consent reference, recorded in audit.log")

def pick_device(a):
    """Print the attached devices and choose one. -> (device or None, exit code)."""
    try: devs = list_devices()
    except RuntimeError as e: print(f"ERROR: {e}"); return None, 1
    for d in devs:
        info = f"{d['maker']} {d['model']}  Android {d['release']} (SDK {d['sdk']})" if d["state"] == "device" else "(details unavailable until authorised)"
        print(f"  {d['serial']}  {info}  [{d['state']}]")
        if d["state"] == "unauthorized": print("    -> unlock the phone and accept 'Allow USB debugging' (tick 'Always allow')")
        elif d["state"] == "offline": print("    -> reconnect the cable or run `adb kill-server`, then try again")
    if getattr(a, "list", False): return None, 0
    if not getattr(a, "case", None): print("ERROR: --case is required"); return None, 2
    serial = getattr(a, "serial", None)
    usable = [d for d in devs if d["state"] == "device" and (not serial or d["serial"] == serial)]
    if not usable:
        print("No usable Android device. Enable Developer options > USB debugging, unlock the phone, use a data cable, "
              "and accept the authorisation prompt." if not devs else "No authorised device matches (see states above).")
        return None, 1
    if len(usable) > 1: print("Several devices attached: pass --serial."); return None, 2
    return usable[0], 0

def run(a):
    bad = [p for p in a.package if not PKG_RE.match(p)]
    if bad: print(f"ERROR: not a valid package name: {bad[0]!r} (expected something like com.example.app)"); return 2
    d, rc = pick_device(a)
    if d is None: return rc
    a.case.mkdir(parents=True, exist_ok=True)
    print(f"Collecting from {d['model']} ({d['serial']}). Keep it unlocked and connected; the bugreport can take minutes.")
    r = collect_android(a.case, d, a)
    print(f"{r['device']}: {r['ok']} files collected, {r['not_collected']} steps not collected")
    print("  by category:", r["by_category"])
    return 0 if r["ok"] else 1

def collect_serial(case: Path, serial: str, authority="", opts=None):
    """Used by `collect --all` / `collect --adb` for adb devices. `opts` may carry adb_root, no_bugreport, logcat_live, max_size_mb ..."""
    d = next((x for x in list_devices() if x["serial"] == serial and x["state"] == "device"), None)
    if not d: print(f"android {serial}: not authorised/online, skipped"); return None
    case.mkdir(parents=True, exist_ok=True)
    o = argparse.Namespace(package=[], no_bugreport=False, adb_root=False, authority=authority)
    for k in ("adb_root", "no_bugreport", "logcat_live", "no_suspects", "max_suspects", "suspect_days", "no_app_folders", "include_cache", "max_app_files", "max_app_mb", "no_su"):
        if opts is not None and hasattr(opts, k): setattr(o, k, getattr(opts, k))
    if opts is not None and getattr(opts, "max_size_mb", None): o.max_size_mb = opts.max_size_mb
    o.authority = authority or getattr(opts, "authority", "")
    r = collect_android(case, d, o)
    print(f"{serial} [android]: {r['ok']} collected, {r['not_collected']} not collected")
    print("  by category:", r["by_category"])
    return r

def main():
    ap = argparse.ArgumentParser(prog="logharvest-android"); add_args(ap); sys.exit(run(ap.parse_args()))

if __name__ == "__main__":
    main()
