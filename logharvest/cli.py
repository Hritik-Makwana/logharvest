import argparse, re, sys
from pathlib import Path
from .detect import identify_os, list_targets, adb_devices
from .collect import collect_tree, collect_macos_logarchive, is_admin
from .viewer import serve

is_privileged = is_admin

PRIV_HINT = {
    "linux": "System logs, the journal and /proc state will be incomplete. Re-run with sudo.",
    "macos": "Re-run with sudo AND grant your terminal Full Disk Access (System Settings > Privacy & Security), "
             "otherwise system logs and Unified Logging data will be incomplete.",
    "windows": "Re-run from an elevated (Administrator) prompt, otherwise the Security log and other system logs will be incomplete.",
}

def main():
    from . import progress                                                                                  # NEW
    if "--no-progress" in sys.argv:                                  # accepted in any position, before or after the command
        sys.argv = [x for x in sys.argv if x != "--no-progress"]; progress.ENABLED = False
    ap = argparse.ArgumentParser(prog="logharvest", epilog="Add --no-progress to turn off progress bars (or set LOGHARVEST_NO_PROGRESS=1).")
    sub = ap.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("detect", help="list volumes/devices and detected OS")
    d.add_argument("--source", nargs="*", default=[], help="mounted images / extracted dirs")
    c = sub.add_parser("collect", help="collect logs into a case folder")
    c.add_argument("--case", required=True, type=Path)
    c.add_argument("--source", nargs="*", default=[])
    c.add_argument("--all", action="store_true", help="also collect every auto-detected volume")
    c.add_argument("--max-size-mb", type=int, default=512)
    c.add_argument("--sweep", "--all-dirs", dest="sweep", action="store_true",
                   help="also look in EVERY directory for log-like files no rule covers (smart: skips caches, WinSxS, node_modules... and reports what it skipped)")
    c.add_argument("--max-depth", type=int, default=12, help="--sweep/--all-dirs: directory depth limit (log-named folders are always searched fully)")
    c.add_argument("--no-commands", action="store_true", help="live Linux/Windows: skip the volatile commands and wevtutil exports")
    c.add_argument("--authority", default="", help="warrant / consent reference, recorded in audit.log")
    c.add_argument("--logarchive-days", type=int, default=0, metavar="N", help="live Mac + root: also run `log collect --last Nd` into a .logarchive")
    c.add_argument("--adb", nargs="*", default=None, metavar="SERIAL", help="collect from Android over USB debugging; no value = every authorised device")
    c.add_argument("--adb-root", action="store_true", help="adb: try `adb root` first (restarts adbd as root; emulators/userdebug builds only)")
    c.add_argument("--no-bugreport", action="store_true", help="adb: skip `adb bugreport` (saves several minutes; dumpsys/logcat are still collected)")
    c.add_argument("--logcat-live", type=int, default=0, metavar="SECONDS", help="adb: also stream logcat for SECONDS after the buffer dump")
    from .smartwalk import add_scope_args, scope_from_args; add_scope_args(c)
    from .rules import add_profile_args; add_profile_args(c)
    v = sub.add_parser("view", help="open the web viewer for a case")
    v.add_argument("--case", required=True, type=Path)
    v.add_argument("--port", type=int, default=8765)
    i = sub.add_parser("ios", help="collect from a USB-connected iPhone/iPad (needs pymobiledevice3)")
    from .ios import add_args as ios_args; ios_args(i)
    an = sub.add_parser("android", help="collect from a USB-connected Android device (needs adb)")        # NEW
    from .android import add_args as android_args; android_args(an)                                        # NEW
    su = sub.add_parser("suspects", help="re-run the suspect analysis on a collected case (any OS)")      # NEW
    from .suspects import add_args as suspects_args; suspects_args(su)                                   # NEW
    ios_ap = sub.add_parser("ios-apps", help="collect the data of ALL apps from an iPhone/iPad (limits: see ios_apps.py)")    # NEW
    from .ios_apps import add_args as ios_apps_args; ios_apps_args(ios_ap)                                  # NEW
    dk = sub.add_parser("desktop-apps", help="copy the folders of ALL programs from this computer or a mounted image (Linux/Windows/macOS)")   # NEW
    from .desktop import add_args as desktop_args; desktop_args(dk)                                         # NEW
    from .desktop import add_collect_args; add_collect_args(c)                                              # NEW: flags on `collect`
    im = sub.add_parser("image", help="collect from a disk image or VM disk (raw/dd, E01, qcow2, vmdk, vhd, vhdx, vdi) without mounting it")   # NEW
    from .images import add_args as image_args; image_args(im)                                              # NEW
    tl = sub.add_parser("timeline", help="merged, time-sorted events (crashes, boots, errors) across every device and log in a case")   # NEW
    from .events import add_args as tl_args; tl_args(tl)                                                    # NEW
    ex = sub.add_parser("explore", help="local web page: merged timeline + full-text search over everything collected")
    from .explore import add_args as ex_args; ex_args(ex)
    rp = sub.add_parser("report", help="printable findings + chain-of-custody report (HTML, optional JSON)")
    from .report import add_args as rp_args; rp_args(rp)
    ap_apps = sub.add_parser("android-apps", help="copy the folders of ALL installed apps from an Android device")   # NEW
    from .apps import add_args as apps_args; apps_args(ap_apps)                                          # NEW
    a = ap.parse_args()

    if a.cmd == "detect":
        for t in list_targets(a.source):
            print(f"{t['kind']:7} {t['path']:35} fs={t['fstype']:8} os={t['os']}")
    elif a.cmd == "collect":
        want_fs = bool(a.source or a.all)
        if not (want_fs or a.adb is not None or a.logarchive_days):
            ap.error("nothing to collect: give --source PATH, --all, --adb and/or --logarchive-days")
        a.case.mkdir(parents=True, exist_ok=True)
        if a.authority:
            import getpass, platform
            from datetime import datetime, timezone
            with open(a.case / "audit.log", "a", encoding="utf-8", newline="\n") as al:
                al.write(f"{datetime.now(timezone.utc).isoformat()} AUTHORITY authority={a.authority!r} user={getpass.getuser()} host={platform.node()}\n")
        targets = list_targets(a.source) if a.all else \
            [{"path": p, "kind": "path", "os": identify_os(Path(p))} for p in a.source]
        for t in targets:
            if t["kind"] == "adb":
                if a.adb is None:
                    from .android import collect_serial; collect_serial(a.case, t["path"], getattr(a, "authority", ""), a)
                continue
            if not t["os"]: print(f"skip {t['path']}: OS not recognised"); continue
            root = Path(t["path"])
            if t["os"] == "macos" and not (root / "private/var/log").exists():
                print(f"note: {root} looks like a macOS System volume; on 10.15+ the logs are on the "
                      f"paired '- Data' volume - mount it and pass it as another --source")
            label = root.name or root.drive.rstrip(":\\") or "root"        # C:\ -> "C", /mnt/win -> "win"
            dev = re.sub(r"[^\w.-]+", "_", f"{t['os']}-{label}")
            if t["os"] in PRIV_HINT:
                if not is_privileged():
                    print(f"WARNING: not running as root/Administrator. {PRIV_HINT[t['os']]}")
                elif t["os"] == "macos":
                    print("NOTE: on macOS, even sudo can be blocked by privacy protection (TCC). If files show as "
                          "not_collected, grant your terminal Full Disk Access.")
            try:
                with progress.Spinner(f"Collecting {t['path']}", manifest=a.case / "manifest.jsonl", unit="files"):                # NEW
                    r = collect_tree(Path(t["path"]), t["os"], a.case, dev, a.max_size_mb, a.sweep, not a.no_commands, a.max_depth, scope_from_args(a), a.profile)
            except Exception as e:                       # never abort the whole run because one source failed
                print(f"ERROR collecting {t['path']}: {type(e).__name__}: {e}"); continue
            print(f"{t['path']} [{t['os']}]: {r['ok']} collected, {r['errors']} errors, {r['unreadable']} unreadable/not collected")
            print("  by category:", r["by_category"])
            if not a.no_suspects:                                                                          # NEW
                try:
                    from .desktop import post_collect; post_collect(a.case, Path(t["path"]), t["os"], dev, a)
                except Exception as e:
                    print(f"  suspect analysis failed for {t['path']}: {type(e).__name__}: {e}")
        if a.adb is not None:
            from .android import collect_serial
            serials = a.adb or adb_devices()
            if not serials:
                print("no authorised adb device found. Enable Developer options > USB debugging, "
                      "plug in, accept the RSA prompt on the phone, and check `adb devices`.")
            for sn in serials: collect_serial(a.case, sn, getattr(a, "authority", ""), a)
        if a.logarchive_days:
            print(f"logarchive: {collect_macos_logarchive(a.case, a.logarchive_days)} files recorded")
    elif a.cmd == "ios":
        from .ios import run; raise SystemExit(run(a))
    elif a.cmd == "android":                                                                               # NEW
        from .android import run; raise SystemExit(run(a))
    elif a.cmd == "explore":
        from .explore import run; raise SystemExit(run(a))
    elif a.cmd == "report":
        from .report import run; raise SystemExit(run(a))
    elif a.cmd == "timeline":                                                                          # NEW
        from .events import run; raise SystemExit(run(a))
    elif a.cmd == "image":                                                                             # NEW
        from .images import run; raise SystemExit(run(a))
    elif a.cmd == "ios-apps":                                                                          # NEW
        from .ios_apps import run; raise SystemExit(run(a))
    elif a.cmd == "desktop-apps":                                                                      # NEW
        from .desktop import run; raise SystemExit(run(a))
    elif a.cmd == "android-apps":                                                                      # NEW
        from .apps import run; raise SystemExit(run(a))
    elif a.cmd == "suspects":                                                                          # NEW
        from .suspects import run; raise SystemExit(run(a))
    else:
        serve(a.case, a.port)

if __name__ == "__main__":
    main()
