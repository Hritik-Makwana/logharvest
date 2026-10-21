"""iPhone acquisition through the `pymobiledevice3` command line tool (run as a subprocess).

iOS exposes no filesystem over USB, so instead of walking directories we ask the phone's own
services for: device info, a unified-log archive, crash reports, and (optionally) a sysdiagnose,
a live syslog window and a full backup. Everything the tool writes is hashed and added to the
same manifest.jsonl the viewer already reads.

Requirements: `pip install pymobiledevice3`; device unlocked and "Trust This Computer" accepted.
  Windows: Apple Devices app or iTunes (USB driver).  Linux: usbmuxd running.  macOS: nothing.
The CLI command names are in STEPS below. They change between pymobiledevice3 releases, so if a
step fails, check `pymobiledevice3 <group> --help` and edit the table, not the logic.
"""
import argparse, getpass, hashlib, json, os, platform, shutil, subprocess, sys, time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

def now(): return datetime.now(timezone.utc).isoformat()
def utc(ts): return datetime.fromtimestamp(ts, timezone.utc).isoformat()

# name -> definition. {out} is replaced with the destination path inside the case folder.
STEPS = {
    "device_info":   dict(category="context",  args=["lockdown", "info"], capture="device_info.json", timeout=60),
    "live_syslog":   dict(category="volatile", args=["syslog", "live"], capture="live_syslog.txt", live=True),
    "logarchive":    dict(category="system",   args=["syslog", "collect", "{out}"], out="system_logs.logarchive", timeout=1800),
    "crash_reports": dict(category="crash",    args=["crash", "pull", "{out}"], out="crash_reports", mkdir=True, timeout=1800),
    "sysdiagnose":   dict(category="system",   args=["crash", "sysdiagnose", "{out}"], out="sysdiagnose.tar.gz", timeout=3600),
    "backup":        dict(category="backup",   args=["backup2", "backup", "--full", "{out}"], out="backup", mkdir=True, timeout=14400),
}

def pmd_cmd():
    env = os.environ.get("LOGHARVEST_PMD")           # e.g. "python -m pymobiledevice3"
    if env: return env.split()
    exe = shutil.which("pymobiledevice3")
    return [exe] if exe else [sys.executable, "-m", "pymobiledevice3"]

def list_devices():
    """USB-attached iPhones/iPads. Raises RuntimeError with a human-readable reason."""
    try:
        p = subprocess.run(pmd_cmd() + ["usbmux", "list"], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError) as e:
        raise RuntimeError(f"cannot run pymobiledevice3 ({e}). Install it with: pip install pymobiledevice3")
    if p.returncode != 0:
        raise RuntimeError(f"`usbmux list` failed: {(p.stderr or p.stdout).strip()[-300:]}")
    try:
        data = json.loads(p.stdout or "[]")
    except json.JSONDecodeError:
        raise RuntimeError(f"unexpected output from `usbmux list`: {p.stdout[:200]!r}")
    devs = []
    for d in data:
        udid = d.get("Identifier") or d.get("SerialNumber") or d.get("UniqueDeviceID")
        if udid: devs.append(dict(udid=udid, name=d.get("DeviceName", "?"), model=d.get("ProductType", "?"),
                                  version=d.get("ProductVersion", "?"), conn=d.get("ConnectionType", "?")))
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

def collect_ios(case: Path, dev: dict, steps: list, live_seconds=0, authority=""):
    udid = dev["udid"]; did = f"ios-{udid[:8]}"
    ev = case / "evidence" / did; cmds = ev / "_commands"; cmds.mkdir(parents=True, exist_ok=True)
    extra = ["--udid", udid] if dev.get("multiple") else []   # only needed when several devices are attached
    by_cat, n_ok, n_err = Counter(), 0, 0
    pmd = pmd_cmd()
    with open(case / "manifest.jsonl", "a") as mf, open(case / "audit.log", "a") as al:
        def log(rec): mf.write(json.dumps(rec) + "\n"); mf.flush()
        def audit(msg): al.write(f"{now()} {msg}\n"); al.flush()

        def record_file(f, category, step, argv, partial=False, kind=None):
            st = f.stat()
            rec = dict(device=did, os="ios", category=category, rule=f"ios:{step}",
                       source=f"ios://{udid}/{step}/{f.relative_to(ev).as_posix()}", collected_at=now(),
                       size=st.st_size, modified=utc(st.st_mtime), accessed=utc(st.st_atime),
                       changed_or_created=utc(st.st_ctime), sha256=_sha256(f), dest=str(f.relative_to(case)),
                       verified=True, command=" ".join(argv))
            if partial: rec["partial"] = True
            log(rec)

        try: ver = subprocess.run(pmd + ["version"], capture_output=True, text=True, timeout=20).stdout.strip()
        except Exception: ver = "unknown"
        audit(f"START ios udid={udid} name={dev['name']!r} model={dev['model']} ios={dev['version']} "
              f"user={getpass.getuser()} host={platform.node()} python={sys.version.split()[0]} "
              f"pymobiledevice3={ver!r} authority={authority!r} steps={','.join(steps)}")
        audit("NOTE iOS records pairing/trust and every service connection on the device; this is unavoidable footprint")

        for name in steps:
            s = STEPS[name]
            timeout = live_seconds if s.get("live") else s["timeout"]
            out = ev / s["out"] if "out" in s else None
            if out is not None and s.get("mkdir"): out.mkdir(parents=True, exist_ok=True)
            argv = pmd + [a.format(out=out) for a in s["args"]] + extra
            so = cmds / (s["capture"] if "capture" in s else f"{name}.stdout.txt")
            se = cmds / f"{name}.stderr.txt"
            audit(f"RUN {name}: {' '.join(argv)}")
            try:
                rc, err, timed_out, secs = _run(argv, so, se, timeout)
            except OSError as e:
                rc, err, timed_out, secs = -1, f"{type(e).__name__}: {e}", False, 0
            produced = [so] if "capture" in s else _files(out)
            ok = bool(produced) and (rc == 0 or (s.get("live") and timed_out))
            audit(f"DONE {name}: rc={rc} timed_out={timed_out} files={len(produced)} seconds={secs}")
            for f in produced:
                if f.stat().st_size or not s.get("live"):
                    record_file(f, s["category"], name, argv, partial=bool(timed_out and not s.get("live")))
                    n_ok += 1; by_cat[s["category"]] += 1
            for f in (so, se):                      # raw tool output is evidence of what the tool said
                if f.exists() and f.stat().st_size and f not in produced:
                    record_file(f, "tool_output", name, argv)
            if not ok or (timed_out and not s.get("live")):
                reason = ("timed out after %ss, output may be partial" % timeout if timed_out and produced else
                          "produced no output" if rc == 0 else f"exit code {rc}")
                log(dict(device=did, os="ios", category="not_collected", rule=f"ios:{name}",
                         source=f"ios://{udid}/{name}", collected_at=now(), command=" ".join(argv),
                         error=f"{reason}. {err}".strip()))
                n_err += 1
        audit(f"END ok={n_ok} not_collected={n_err}")
    return dict(device=did, ok=n_ok, not_collected=n_err, by_category=dict(by_cat))

def add_args(ap):
    ap.add_argument("--case", type=Path, help="case folder (created if missing)")
    ap.add_argument("--list", action="store_true", help="only list connected iOS devices")
    ap.add_argument("--udid", help="required when more than one device is attached")
    ap.add_argument("--live-seconds", type=int, default=0, help="also record N seconds of the live syslog stream first")
    ap.add_argument("--sysdiagnose", action="store_true", help="also pull a sysdiagnose (slow; creates a file on the device)")
    ap.add_argument("--backup", action="store_true", help="also take a full backup (large; changes backup state on the device)")
    ap.add_argument("--authority", default="", help="warrant / consent reference, recorded in audit.log")

def run(a):
    try: devs = list_devices()
    except RuntimeError as e: print(f"ERROR: {e}"); return 1
    for d in devs: print(f"  {d['udid']}  {d['name']}  {d['model']}  iOS {d['version']}  ({d['conn']})")
    if a.list: return 0
    if not a.case: print("ERROR: --case is required"); return 2
    if not devs:
        print("No iOS device found. Check: cable/port, phone UNLOCKED, 'Trust This Computer' accepted, "
              "usbmuxd running (Linux) or Apple Devices/iTunes installed (Windows).")
        return 1
    if a.udid: devs = [d for d in devs if d["udid"] == a.udid]
    if len(devs) != 1 and not a.udid:
        print("Several devices attached: pass --udid."); return 2
    if not devs: print("--udid does not match any attached device."); return 2
    dev = dict(devs[0], multiple=bool(a.udid) and len(list_devices()) > 1)
    steps = ["device_info"] + (["live_syslog"] if a.live_seconds > 0 else []) + ["logarchive", "crash_reports"] \
            + (["sysdiagnose"] if a.sysdiagnose else []) + (["backup"] if a.backup else [])
    a.case.mkdir(parents=True, exist_ok=True)
    print(f"Collecting from {dev['name']} ({dev['udid']}). Keep the phone unlocked and connected.")
    r = collect_ios(a.case, dev, steps, a.live_seconds, a.authority)
    print(f"{r['device']}: {r['ok']} files collected, {r['not_collected']} steps not collected")
    print("  by category:", r["by_category"])
    return 0 if r["ok"] else 1

def main():
    ap = argparse.ArgumentParser(prog="logharvest-ios"); add_args(ap); sys.exit(run(ap.parse_args()))

if __name__ == "__main__":
    main()
