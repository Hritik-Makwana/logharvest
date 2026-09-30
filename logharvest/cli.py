import argparse, os, re
from pathlib import Path
from .detect import identify_os, list_targets
from .collect import collect_tree, collect_adb
from .viewer import serve

def is_privileged():
    if hasattr(os, "geteuid"): return os.geteuid() == 0
    try:
        import ctypes; return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception: return False

PRIV_HINT = {
    "linux": "System logs, the journal and /proc state will be incomplete. Re-run with sudo.",
    "macos": "Re-run with sudo AND grant your terminal Full Disk Access (System Settings > Privacy & Security), "
             "otherwise system logs and Unified Logging data will be incomplete.",
    "windows": "Re-run from an elevated (Administrator) prompt, otherwise the Security log and other system logs will be incomplete.",
}

def main():
    ap = argparse.ArgumentParser(prog="logharvest")
    sub = ap.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("detect", help="list volumes/devices and detected OS")
    d.add_argument("--source", nargs="*", default=[], help="mounted images / extracted dirs")
    c = sub.add_parser("collect", help="collect logs into a case folder")
    c.add_argument("--case", required=True, type=Path)
    c.add_argument("--source", nargs="*", default=[])
    c.add_argument("--all", action="store_true", help="also collect every auto-detected volume")
    c.add_argument("--max-size-mb", type=int, default=512)
    c.add_argument("--sweep", action="store_true", help="also find log-like files no rule covers")
    c.add_argument("--no-commands", action="store_true", help="skip live command capture (dmesg, journalctl...)")
    v = sub.add_parser("view", help="open the web viewer for a case")
    v.add_argument("--case", required=True, type=Path)
    v.add_argument("--port", type=int, default=8765)
    a = ap.parse_args()

    if a.cmd == "detect":
        for t in list_targets(a.source):
            print(f"{t['kind']:7} {t['path']:35} fs={t['fstype']:8} os={t['os']}")
    elif a.cmd == "collect":
        a.case.mkdir(parents=True, exist_ok=True)
        targets = list_targets(a.source) if a.all else \
            [{"path": p, "kind": "path", "os": identify_os(Path(p))} for p in a.source]
        for t in targets:
            if t["kind"] == "adb": collect_adb(t["path"], a.case); continue
            if not t["os"]: print(f"skip {t['path']}: OS not recognised"); continue
            dev = re.sub(r"[^\w.-]+", "_", f"{t['os']}-{Path(t['path']).name or 'root'}")
            if t["os"] in PRIV_HINT:
                if not is_privileged():
                    print(f"WARNING: not running as root/Administrator. {PRIV_HINT[t['os']]}")
                elif t["os"] == "macos":
                    print("NOTE: on macOS, even sudo can be blocked by privacy protection (TCC). If files show as "
                          "not_collected, grant your terminal Full Disk Access.")
            try:
                r = collect_tree(Path(t["path"]), t["os"], a.case, dev, a.max_size_mb, a.sweep, not a.no_commands)
            except Exception as e:                       # never abort the whole run because one source failed
                print(f"ERROR collecting {t['path']}: {type(e).__name__}: {e}"); continue
            print(f"{t['path']} [{t['os']}]: {r['ok']} collected, {r['errors']} errors, {r['unreadable']} unreadable/not collected")
            print("  by category:", r["by_category"])
    else:
        serve(a.case, a.port)

if __name__ == "__main__":
    main()
