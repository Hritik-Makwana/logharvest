import json
from pathlib import Path
from logharvest.collect import collect_tree
from logharvest.detect import identify_os

FILES = [
    "Windows/System32/winevt/Logs/Security.evtx",
    "Windows/System32/LogFiles/Firewall/pfirewall.log",
    "Windows/Logs/CBS/CBS.log",
    "Windows/INF/setupapi.dev.log",
    "Windows/Minidump/1.dmp",
    "ProgramData/Foo/a.log",
    "Program Files/X/x.log",
    "Users/bob/AppData/Local/App/b.LOG",
    "Users/bob/AppData/Roaming/Code/logs/main.txt",
]

def test_windows_tree(tmp_path: Path):
    root = tmp_path / "img"
    for f in FILES:
        p = root / f
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(b"data")

    assert identify_os(root) == "windows"

    case = tmp_path / "case"
    case.mkdir()

    result = collect_tree(root, "windows", case, "windows-test", 512, run_cmds=False)

    assert result["ok"] == len(FILES)
    assert result["errors"] == 0

    raw = (case / "manifest.jsonl").read_bytes()
    assert b"\r" not in raw
    assert all(
        json.loads(line)["verified"] for line in raw.decode("utf-8").splitlines()
    )


def test_case_inside_source_is_not_collected(tmp_path: Path):
    root = tmp_path / "img"
    (root / "Windows/System32/winevt/Logs").mkdir(parents=True)
    (root / "ProgramData/case").mkdir(parents=True)
    (root / "ProgramData/a.log").write_bytes(b"x")

    result = collect_tree(
        root, "windows", root / "ProgramData/case", "w", 512, run_cmds=False
    )

    assert result["ok"] == 1
    assert result["errors"] == 0
