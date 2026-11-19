"""--sweep / --all-dirs: finds log-like files in unexpected places, skips known-noise directories, reports what it skipped."""
import json
from pathlib import Path

from logharvest.collect import collect_tree
from logharvest.smartwalk import smart_walk, SweepStats

WANTED = ["Windows/Temp/odd.log", "SomeVendor/Agent/trace.err", "Users/bob/AppData/Local/Vendor/App/deep/er/out.log.1",
          "Users/bob/AppData/Local/Vendor/App/Logs/session.txt", "Games/Foo/crashes/report.json"]
NOISE = ["Windows/WinSxS/x/huge.log", "Windows/Installer/i/inst.log", "Users/bob/proj/node_modules/p/debug.log",
         "Users/bob/AppData/Local/Google/Chrome/User Data/Default/Cache/c.log", "Windows/System32/DriverStore/d/setup.log"]


def build(root: Path):
    for rel in ["Windows/System32/winevt/Logs/System.evtx", *WANTED, *NOISE]:
        p = root / rel; p.parent.mkdir(parents=True, exist_ok=True); p.write_text(rel)


def test_smart_walk_finds_and_skips(tmp_path):
    root = tmp_path / "C"; build(root)
    st = SweepStats()
    got = {p.relative_to(root).as_posix() for p in smart_walk(root, "windows", (), None, st)}
    assert set(WANTED) <= got
    assert not got & set(NOISE)
    assert st["dirs_skipped"] >= 5 and st.skipped_examples


def test_depth_cap_but_logdirs_exempt(tmp_path):
    root = tmp_path / "C"
    deep = root / "a/b/c/d/e/f"; deep.mkdir(parents=True); (deep / "x.log").write_text("1")
    logd = root / "a/b/c/logs/g/h/i/j"; logd.mkdir(parents=True); (logd / "y.txt").write_text("2")   # "logs" sits right at the cap
    got = {p.name for p in smart_walk(root, "windows", (), None, None, max_depth=3)}
    assert got == {"y.txt"}                       # x.log is deeper than 3; y.txt is under a log-named folder (searched to the bottom)


def test_collect_sweep_end_to_end(tmp_path):
    root, case = tmp_path / "C", tmp_path / "case"; build(root); case.mkdir()
    r = collect_tree(root, "windows", case, "windows-C", 512, sweep=True, run_cmds=False)
    assert r["errors"] == 0
    recs = [json.loads(l) for l in (case / "manifest.jsonl").read_text(encoding="utf-8").splitlines()]
    swept = {Path(x["source"]).relative_to(root).as_posix() for x in recs if x.get("category") == "discovered"}
    assert swept == set(WANTED)
    cov = json.loads((case / "coverage-windows-C.json").read_text(encoding="utf-8"))
    assert cov["sweep"]["dirs_skipped"] >= 5 and cov["sweep"]["candidates"] >= len(WANTED)
