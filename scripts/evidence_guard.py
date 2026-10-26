#!/usr/bin/env python3
"""Fail if git is tracking files that look like collected evidence or case output.

Collected logs contain personal data. The worst realistic accident for this project is
committing a case folder. Put deliberate, synthetic test data under tests/fixtures/ (allowed).
Run from the repository root.
"""
import fnmatch, os, re, subprocess, sys

ALLOWED_PREFIX = "tests/fixtures/"
MAX_BYTES = 5 * 1024 * 1024
BAD_NAMES = ["manifest.jsonl", "audit.log", "coverage-*.json", "*.tracev3", "*.evtx", "*.dmp", "*.mdmp",
             "*.ips", "*.crash", "*.journal", "*.journal~", "core.[0-9]*", "*.logarchive"]
BAD_DIRS = [re.compile(r"evidence"), re.compile(r"case[-_]?\d+.*", re.I), re.compile(r".*\.logarchive")]

def tracked():
    out = subprocess.run(["git", "ls-files", "-z"], capture_output=True, check=True).stdout
    return [p for p in out.decode("utf-8", "surrogateescape").split("\0") if p]

def problems(paths, size=lambda p: os.path.getsize(p) if os.path.isfile(p) else 0):
    found = []
    for p in paths:
        if p.startswith(ALLOWED_PREFIX):
            continue
        parts = p.split("/")
        name = parts[-1]
        if any(fnmatch.fnmatch(name, pat) for pat in BAD_NAMES):
            found.append((p, "file name looks like collected evidence/case output"))
        elif any(rx.fullmatch(d) for d in parts[:-1] for rx in BAD_DIRS):
            found.append((p, "inside an evidence/case folder"))
        elif size(p) > MAX_BYTES:
            found.append((p, f"larger than {MAX_BYTES >> 20} MB"))
    return found

def main():
    bad = problems(tracked())
    if not bad:
        print("evidence guard: OK, no evidence-like files are tracked")
        return 0
    print("evidence guard: FAILED. These tracked files look like collected evidence or case output:\n")
    for p, why in bad:
        print(f"  {p}  ({why})")
    print("\nFix: `git rm -r --cached <path>` and add it to .gitignore. If it is deliberate SYNTHETIC test data,"
          f" move it under {ALLOWED_PREFIX}.\nIf real evidence was ever pushed, deleting it is not enough: it remains in git history."
          " Rewrite history and tell whoever owns the case.")
    return 1

if __name__ == "__main__":
    sys.exit(main())
