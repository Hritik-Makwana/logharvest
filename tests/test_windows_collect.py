"""Fixture-based Windows collection test: runs on every OS in CI (no real Windows needed)."""
import json
from pathlib import Path

from logharvest.collect import collect_tree
from logharvest.detect import identify_os

FILES = {
    "Windows/System32/winevt/Logs/System.evtx": "system",
    "Windows/System32/winevt/Logs/Security.evtx": "system",
    "Windows/Logs/CBS/CBS.log": "system",
    "Windows/Logs/CBS/CbsPersist_20260101.cab": "system",
    "Windows/Logs/WindowsUpdate/WindowsUpdate.20260101.etl": "system",
    "Windows/INF/setupapi.dev.log": "system",
    "Windows/Minidump/111026-1.dmp": "crash",
    "ProgramData/Acme/app.log": "application",
    "Program Files/OldApp/logs/run.txt": "application",
    "Program Files (x86)/OldApp32/Log/run.txt": "application",
    "Users/bob/AppData/Local/Tool/a.log": "application",
    "Users/bob/AppData/Roaming/Tool/b.log": "application",
}


def build(root: Path):
    for rel in FILES:
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(b"data " + rel.encode())
    (root / "Users/bob/Documents").mkdir(parents=True)
    (root / "Users/bob/Documents/notes.txt").write_text("not a log")


def test_windows_collection(tmp_path):
    root, case = tmp_path / "C", tmp_path / "case"
    build(root); case.mkdir()
    assert identify_os(root) == "windows"
    r = collect_tree(root, "windows", case, "windows-C", 512, run_cmds=False)
    assert r["errors"] == 0
    recs = [json.loads(l) for l in (case / "manifest.jsonl").read_text(encoding="utf-8").splitlines()]
    got = {Path(x["source"]).relative_to(root).as_posix(): x for x in recs if "dest" in x}
    assert set(got) == set(FILES)                      # nothing missed, nothing extra, no duplicates
    assert len(got) == len(recs)
    for rel, cat in FILES.items():
        assert got[rel]["category"] == cat and got[rel]["verified"] is True
        assert (case / got[rel]["dest"]).read_bytes() == (root / rel).read_bytes()
    assert b"\r\n" not in (case / "manifest.jsonl").read_bytes()
