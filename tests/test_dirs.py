"""--dir / --exclude-dir / --only-dirs"""
import json, subprocess, sys
from pathlib import Path

import pytest

from logharvest.collect import collect_tree
from logharvest.smartwalk import Scope, smart_walk, norm_rel, scope_from_args

ROOT = Path(__file__).resolve().parents[1]
FILES = ["Windows/System32/winevt/Logs/System.evtx",       # rule match, outside the chosen folders
         "Windows/Logs/CBS/CBS.log",                       # rule match
         "Users/bob/AppData/Local/Vendor/odd.log.1",       # sweep-only, inside --dir
         "Users/bob/AppData/Local/Vendor/sub/deep.err",    # sweep-only, inside --dir
         "Users/bob/AppData/Local/Vendor/skipme/x.log.1",  # inside --dir but excluded
         "Users/bob/Documents/other.log.1",                # sweep-only, OUTSIDE --dir
         "Windows/WinSxS/x/y.log.1"]                       # known noise, but explicitly requested in one test


def build(root):
    for rel in FILES:
        p = root / rel; p.parent.mkdir(parents=True, exist_ok=True); p.write_text(rel)


def srcs(case, cat=None):
    recs = [json.loads(l) for l in (case / "manifest.jsonl").read_text(encoding="utf-8").splitlines()]
    return recs, {r["source"] for r in recs if "dest" in r and (cat is None or r["category"] == cat)}


def run(tmp_path, scope):
    root, case = tmp_path / "C", tmp_path / "case"; build(root); case.mkdir()
    r = collect_tree(root, "windows", case, "windows-C", 512, run_cmds=False, scope=scope)
    recs, _ = srcs(case)
    swept = {Path(x["source"]).relative_to(root).as_posix() for x in recs if x.get("category") == "discovered"}
    ruled = {Path(x["source"]).relative_to(root).as_posix() for x in recs if "dest" in x and x.get("category") != "discovered"}
    return r, recs, swept, ruled


def test_dir_limits_sweep_case_insensitive_and_rules_still_run(tmp_path):
    r, recs, swept, ruled = run(tmp_path, Scope(["users\\BOB\\appdata"]))          # backslashes + wrong case
    assert swept == {"Users/bob/AppData/Local/Vendor/odd.log.1", "Users/bob/AppData/Local/Vendor/skipme/x.log.1",
                     "Users/bob/AppData/Local/Vendor/sub/deep.err"}                # Documents/ never read; --dir implies sweep
    assert {"Windows/Logs/CBS/CBS.log", "Windows/System32/winevt/Logs/System.evtx"} <= ruled   # rules unaffected without --only-dirs


def test_exclude_dir(tmp_path):
    r, recs, swept, ruled = run(tmp_path, Scope(["Users/bob/AppData"], ["Users/bob/AppData/Local/Vendor/skipme"]))
    assert "Users/bob/AppData/Local/Vendor/skipme/x.log.1" not in swept and len(swept) == 2


def test_only_dirs_limits_rules_too(tmp_path):
    r, recs, swept, ruled = run(tmp_path, Scope(["Windows/Logs"], only_dirs=True))
    assert ruled == {"Windows/Logs/CBS/CBS.log"}                                     # System.evtx is outside --dir
    assert swept == set()


def test_missing_dir_is_reported_not_ignored(tmp_path):
    r, recs, swept, ruled = run(tmp_path, Scope(["Users/nobody", "Users/bob/AppData"]))
    nc = [x for x in recs if x.get("category") == "not_collected"]
    assert any("directory not found" in x["error"] and x["source"].endswith("users/nobody") for x in nc)
    assert len(swept) == 3                                                           # the valid --dir still ran


def test_explicit_dir_overrides_noise_list(tmp_path):
    r, recs, swept, ruled = run(tmp_path, Scope(["Windows/WinSxS"]))
    assert swept == {"Windows/WinSxS/x/y.log.1"}                                     # normally skipped, but you asked for it


def test_nested_dirs_deduplicated(tmp_path):
    root = tmp_path / "C"; build(root)
    b = Scope(["Users/bob", "Users/bob/AppData"]).bind(root)
    assert b.dirs == ("users/bob",)
    got = [p for p in smart_walk(root, "windows", scope=Scope(["Users/bob", "Users/bob/AppData"]))]
    assert len(got) == len(set(got))


def test_dotdot_rejected():
    with pytest.raises(ValueError): norm_rel("Users/../Windows")
    class A: dir = ["../etc"]; exclude_dir = []; only_dirs = False
    with pytest.raises(SystemExit): scope_from_args(A)
    class B: dir = []; exclude_dir = []; only_dirs = True
    with pytest.raises(SystemExit): scope_from_args(B)


def test_cli_end_to_end(tmp_path):
    root, case = tmp_path / "C", tmp_path / "case"; build(root)
    p = subprocess.run([sys.executable, "-m", "logharvest", "collect", "--case", str(case), "--source", str(root),
                        "--dir", "Users\\bob\\AppData", "--exclude-dir", "Users/bob/AppData/Local/Vendor/skipme",
                        "--no-commands", "--no-progress"], cwd=ROOT, capture_output=True, text=True)
    assert p.returncode == 0, p.stderr
    cov = json.loads(next(case.glob("coverage-*.json")).read_text(encoding="utf-8"))
    assert cov["sweep"]["candidates"] == 2
    assert "dirs=['users/bob/appdata']" in (case / "audit.log").read_text(encoding="utf-8")
