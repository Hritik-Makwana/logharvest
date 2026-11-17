import argparse, os, re, sys
from pathlib import Path
from .detect import identify_os, list_targets, adb_devices
from .collect import collect_tree, collect_macos_logarchive, is_admin
from .android import collect_adb
from .viewer import serve

def _run_adb(serial, case, max_mb, try_root, bugreport, live_secs):
    print(f"adb {serial}: collecting" + (" (bugreport alone can take a few minutes)..." if bugreport else "..."))
    mode, ok, err = collect_adb(serial, case, max_mb, try_root, bugreport, live_secs)
    print(f"adb {serial} [access={mode}]: {ok} collected, {err} errors")

def main():
    if sys.version_info < (3, 12):
        sys.exit("logharvest needs Python 3.12+ (case-insensitive Path.glob)")
    ap = argparse.ArgumentParser(prog="logharvest")
    sub = ap.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("detect", help="list volumes/devices and detected OS")
    d.add_argument("--source", nargs="*", default=[], help="mounted images / extracted dirs")
    c = sub.add_parser("collect", help="collect logs into a case folder")
    c.add_argument("--case", required=True, type=Path)
    c.add_argument("--source", nargs="*", default=[])
    c.add_argument("--all", action="store_true", help="also collect every auto-detected volume")
    c.add_argument("--max-size-mb", type=int, default=512)
    c.add_argument("--logarchive-days", type=int, default=0, metavar="N",
                   help="live Mac + root: also run `log collect --last Nd` into a .logarchive")
    c.add_argument("--adb", nargs="*", default=None, metavar="SERIAL",
                   help="collect from Android over USB debugging; no value = every authorised device")
    c.add_argument("--adb-root", action="store_true",
                   help="try `adb root` first (restarts adbd as root; emulators/userdebug builds only)")
    c.add_argument("--no-bugreport", action="store_true",
                   help="adb: skip `adb bugreport` (saves several minutes; dumpsys/logcat are still collected)")
    c.add_argument("--logcat-live", type=int, default=0, metavar="SECONDS",
                   help="adb: also stream logcat for SECONDS (real-time capture on top of the buffer dump)")
    v = sub.add_parser("view", help="open the web viewer for a case")
    v.add_argument("--case", required=True, type=Path)
    v.add_argument("--port", type=int, default=8765)
    a = ap.parse_args()

    if a.cmd == "detect":
        for t in list_targets(a.source):
            print(f"{t['kind']:7} {t['path']:35} fs={t['fstype']:8} os={t['os']}")
    elif a.cmd == "collect":
        want_fs = bool(a.source or a.all)
        if not (want_fs or a.adb is not None or a.logarchive_days):
            ap.error("nothing to collect: give --source PATH, --all, and/or --adb")
        if want_fs and sys.platform == "darwin" and os.geteuid() != 0:
            print("warning: not root - protected logs (/private/var/db/diagnostics, audit, other users' "
                  "Library) will fail. Use sudo and grant your terminal Full Disk Access.")
        if want_fs and sys.platform == "win32" and not is_admin():
            print("warning: not Administrator - Security.evtx, other users' profiles and WER/Defender "
                  "folders will fail. Open an elevated terminal (Run as administrator).")
        a.case.mkdir(parents=True, exist_ok=True)
        targets = list_targets(a.source) if a.all else \
            [{"path": p, "kind": "path", "os": identify_os(Path(p))} for p in a.source]
        for t in targets:
            if t["kind"] == "adb":
                if a.adb is None: _run_adb(t["path"], a.case, a.max_size_mb, a.adb_root, not a.no_bugreport, a.logcat_live)
                continue
            if not t["os"]: print(f"skip {t['path']}: OS not recognised"); continue
            root = Path(t["path"])
            if t["os"] == "macos" and not (root / "private/var/log").exists():
                print(f"note: {root} looks like a macOS System volume; on 10.15+ the logs are on the "
                      f"paired '- Data' volume - mount it and pass it as another --source")
            label = root.name or root.drive.rstrip(":\\") or "root"     # C:\ -> "C", /mnt/win -> "win"
            dev = re.sub(r"[^\w.-]+", "_", f"{t['os']}-{label}")
            ok, err = collect_tree(root, t["os"], a.case, dev, a.max_size_mb)
            print(f"{t['path']} [{t['os']}]: {ok} collected, {err} errors")
        if a.adb is not None:
            serials = a.adb or adb_devices()
            if not serials:
                print("no authorised adb device found. Enable Developer options > USB debugging, "
                      "plug in, accept the RSA prompt on the phone, and check `adb devices`.")
            for s in serials:
                _run_adb(s, a.case, a.max_size_mb, a.adb_root, not a.no_bugreport, a.logcat_live)
        if a.logarchive_days:
            n = collect_macos_logarchive(a.case, a.logarchive_days)
            print(f"logarchive: {n} files recorded")
    else:
        serve(a.case, a.port)

if __name__ == "__main__":
    main()
