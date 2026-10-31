"""Check what logharvest's rules actually match, without copying anything.

Put this next to the `logharvest/` folder and run:

    # dry run of the macOS rules against a root (use sudo on a live Mac)
    sudo .venv/bin/python rule_coverage.py coverage / macos

    # summarise a finished collection
    python rule_coverage.py manifest path/to/case/manifest.jsonl
"""
import collections, json, sys
from pathlib import Path
from logharvest.rules import RULES
from logharvest.detect import identify_os


def coverage(root: Path, os_name: str, max_mb: int = 500):
    print(f"root={root}  requested_os={os_name}  detected_os={identify_os(root)}")
    print(f"{'category':12} {'files':>7} {'MB':>9} {'unreadable':>10} {'too_big':>8}  pattern")
    seen = set()
    for category, pattern in RULES[os_name]:
        n = size = bad = big = 0
        for p in root.glob(pattern, case_sensitive=False):
            if p in seen or p.is_symlink() or not p.is_file():
                continue
            seen.add(p)
            try:
                s = p.stat().st_size
                with open(p, "rb") as f:
                    f.read(1)                      # permission / TCC test
                n += 1; size += s
                big += s > max_mb << 20
            except OSError:
                bad += 1
        flag = "  <-- NO MATCH" if n + bad == 0 else ("  <-- BLOCKED" if bad and not n else "")
        print(f"{category:12} {n:>7} {size/1e6:>9.1f} {bad:>10} {big:>8}  {pattern}{flag}")
    print(f"\nunique files matched overall: {len(seen)}")


def manifest(path: Path):
    recs = [json.loads(l) for l in open(path) if l.strip()]
    print(f"{len(recs)} records")
    print("by category:", dict(collections.Counter(r.get("category") for r in recs)))
    print("verified=False:", sum(r.get("verified") is False for r in recs))
    errs = collections.Counter(r["error"] for r in recs if "error" in r)
    print("errors:")
    for e, c in errs.most_common(10):
        print(f"  {c:>5}  {e}")
    for r in recs:
        if r.get("verified") is False:
            print("  changed during copy:", r["source"])


if __name__ == "__main__":
    if len(sys.argv) >= 4 and sys.argv[1] == "coverage":
        coverage(Path(sys.argv[2]), sys.argv[3])
    elif len(sys.argv) == 3 and sys.argv[1] == "manifest":
        manifest(Path(sys.argv[2]))
    else:
        print(__doc__)
