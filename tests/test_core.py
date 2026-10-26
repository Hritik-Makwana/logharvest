import json, os, sys
from pathlib import Path
import pytest
from logharvest.collect import collect_tree, sha256

def make_linux_tree(root: Path) -> Path:
    (root / "etc").mkdir(parents=True); (root / "etc/os-release").write_text("ID=test\n")
    (root / "var/log").mkdir(parents=True); (root / "var/log/syslog").write_text("boot ok\n")
    return root

def records(case: Path):
    return [json.loads(l) for l in (case / "manifest.jsonl").read_text().splitlines()]

def run(tmp_path):
    src = make_linux_tree(tmp_path / "src"); case = tmp_path / "case"; case.mkdir()
    collect_tree(src, "linux", case, "t", 512, run_cmds=False)
    return src, case

def test_collect_hash_and_verify(tmp_path):
    src, case = run(tmp_path)
    r = next(x for x in records(case) if x["source"].endswith("syslog"))
    assert r["verified"] and r["sha256"] == sha256(src / "var/log/syslog")
    assert (case / r["dest"]).read_bytes() == b"boot ok\n"

def test_tamper_is_detected(tmp_path):
    _, case = run(tmp_path)
    r = next(x for x in records(case) if x["source"].endswith("syslog"))
    (case / r["dest"]).write_bytes(b"tampered\n")
    assert sha256(case / r["dest"]) != r["sha256"]

def test_source_is_not_modified(tmp_path):
    src = make_linux_tree(tmp_path / "src"); f = src / "var/log/syslog"
    before = (f.read_bytes(), f.stat().st_mtime_ns)
    case = tmp_path / "case"; case.mkdir()
    collect_tree(src, "linux", case, "t", 512, run_cmds=False)
    assert (f.read_bytes(), f.stat().st_mtime_ns) == before

def test_size_limit_is_recorded_not_silent(tmp_path):
    src = make_linux_tree(tmp_path / "src"); (src / "var/log/big.log").write_bytes(b"x" * (2 << 20))
    case = tmp_path / "case"; case.mkdir()
    collect_tree(src, "linux", case, "t", 1, run_cmds=False)
    big = next(x for x in records(case) if x["source"].endswith("big.log"))
    assert "NOT COLLECTED" in big["error"]

@pytest.mark.skipif(sys.platform == "win32" or (hasattr(os, "geteuid") and os.geteuid() == 0),
                    reason="needs a non-root POSIX user")
def test_unreadable_dir_is_logged_and_run_continues(tmp_path):
    src = make_linux_tree(tmp_path / "src"); locked = src / "var/lib/docker/containers"
    locked.mkdir(parents=True); (locked / "a.log").write_text("x")
    (src / "var/lib/docker").chmod(0)
    try:
        case = tmp_path / "case"; case.mkdir()
        res = collect_tree(src, "linux", case, "t", 512, sweep=True, run_cmds=False)
    finally:
        (src / "var/lib/docker").chmod(0o755)
    assert res["ok"] >= 1
    assert any(r["category"] == "not_collected" for r in records(case))
