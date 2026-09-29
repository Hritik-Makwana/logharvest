import argparse, re
from pathlib import Path
from .detect import identify_os, list_targets
from .collect import collect_tree, collect_adb
from .viewer import serve

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
            ok, err = collect_tree(Path(t["path"]), t["os"], a.case, dev, a.max_size_mb)
            print(f"{t['path']} [{t['os']}]: {ok} collected, {err} errors")
    else:
        serve(a.case, a.port)

if __name__ == "__main__":
    main()
