"""--profile fast | (default) | full"""
import json, subprocess, sys
from pathlib import Path

import pytest

from logharvest.collect import collect_tree
from logharvest.rules import rules_for, RULES_FAST, RULES_FULL, PROFILES

ROOT = Path(__file__).resolve().parents[1]
FAST = ["Windows/System32/winevt/Logs/System.evtx", "Windows/Logs/CBS/CBS.log", "Windows/Minidump/a.dmp", "Windows/System32/LogFiles/Srt/SrtTrail.txt"]
DEFAULT_ONLY = ["ProgramData/Acme/app.log", "Users/bob/AppData/Local/Tool/a.log", "Windows/System32/LogFiles/WMI/trace.etl",
                "Windows/Logs/SIH/sih.etl", "Users/bob/AppData/Local/Google/Chrome/User Data/Crashpad/reports/r.dmp"]
FULL_ONLY = {"Windows/Prefetch/CHROME.EXE-1.pf": "execution", "Windows/System32/config/SYSTEM": "registry", "Users/bob/NTUSER.DAT": "registry",
             "Windows/AppCompat/Programs/Amcache.hve": "execution", "Windows/System32/sru/SRUDB.dat": "execution",
             "Windows/System32/Tasks/Microsoft/Windows/X/Task": "persistence", "Users/bob/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt": "activity",
             "inetpub/logs/LogFiles/W3SVC1/u_ex1.log": "server", "Windows/LiveKernelReports/WATCHDOG/w.dmp": "crash"}
NEVER = ["Users/bob/Documents/notes.txt"]


def build(root):
    for rel in [*FAST, *DEFAULT_ONLY, *FULL_ONLY, *NEVER]:
        p = root / rel; p.parent.mkdir(parents=True, exist_ok=True); p.write_text(rel)


def run(tmp_path, profile, **kw):
    root, case = tmp_path / "C", tmp_path / "case"; build(root); case.mkdir()
    r = collect_tree(root, "windows", case, "windows-C", kw.pop("max_mb", 512), run_cmds=False, profile=profile, **kw)
    recs = [json.loads(l) for l in (case / "manifest.jsonl").read_text(encoding="utf-8").splitlines()]
    got = {Path(x["source"]).relative_to(root).as_posix(): x for x in recs if "dest" in x}
    return r, recs, got, case


def test_tiers_nest_and_are_non_empty():
    for os_name in ("windows", "linux", "macos"):
        fast, default, full = (rules_for(os_name, p) for p in ("fast", None, "full"))
        assert 0 < len(fast) < len(default) < len(full)
        assert rules_for(os_name, "default") == default
        assert set(default) <= set(full)
    assert set(PROFILES) == {"fast", "default", "full"}
    with pytest.raises(ValueError): rules_for("windows", "turbo")


def test_fast_rules_do_not_invent_new_places():
    """every fast pattern should be satisfiable by default rules' territory (no stray category names)"""
    cats = {c for os_ in RULES_FAST.values() for c, _ in os_}
    assert cats <= {"system", "crash", "security", "context"}
    assert {c for os_ in RULES_FULL.values() for c, _ in os_} >= {"registry", "execution", "persistence", "activity"}


def test_windows_fast_default_full(tmp_path):
    _, _, fast, _ = run(tmp_path / "a", "fast")
    assert set(fast) == set(FAST)
    _, _, default, _ = run(tmp_path / "b", None)
    assert set(default) == set(FAST) | set(DEFAULT_ONLY)                      # includes the previously missed .etl / Srt / Crashpad files
    _, _, full, _ = run(tmp_path / "c", "full")
    assert set(full) == set(FAST) | set(DEFAULT_ONLY) | set(FULL_ONLY)
    for rel, cat in FULL_ONLY.items():
        if rel != "Windows/LiveKernelReports/WATCHDOG/w.dmp": assert full[rel]["category"] == cat
    assert "Users/bob/Documents/notes.txt" not in full


def test_full_reports_oversize_memory_dump_not_silently_dropped(tmp_path):
    root, case = tmp_path / "C", tmp_path / "case"; build(root); case.mkdir()
    (root / "Windows/Memory.dmp").write_bytes(b"\0" * (2 << 20))
    collect_tree(root, "windows", case, "windows-C", 1, run_cmds=False, profile="full")
    recs = [json.loads(l) for l in (case / "manifest.jsonl").read_text(encoding="utf-8").splitlines()]
    bad = [r for r in recs if r["source"].endswith("Memory.dmp")]
    assert bad and "NOT COLLECTED" in bad[0]["error"]


def test_profile_recorded_and_composes_with_dirs(tmp_path):
    r, recs, got, case = run(tmp_path, "full", scope=__import__("logharvest.smartwalk", fromlist=["Scope"]).Scope(["Windows/Prefetch"], only_dirs=True))
    assert set(got) == {"Windows/Prefetch/CHROME.EXE-1.pf"}
    assert json.loads((case / "coverage-windows-C.json").read_text(encoding="utf-8"))["profile"] == "full"
    assert "profile=full" in (case / "audit.log").read_text(encoding="utf-8")


def test_linux_and_macos_full_extras(tmp_path):
    for os_name, files in (("linux", ["etc/os-release", "var/log/syslog", "etc/crontab", "home/bob/.bash_history", "var/spool/cron/crontabs/bob", "var/log/other.log"]),
                           ("macos", ["System/Library/CoreServices/SystemVersion.plist", "Users/x/y", "Library/LaunchDaemons/a.plist",
                                      "Users/bob/Library/LaunchAgents/b.plist", "Users/bob/.zsh_history", "private/var/log/system.log", "private/var/log/wifi.log"])):
        root = tmp_path / os_name; case = tmp_path / f"case-{os_name}"; case.mkdir()
        for f in files: (root / f).parent.mkdir(parents=True, exist_ok=True); (root / f).write_text(f)
        res = {}
        for prof in ("fast", None, "full"):
            c = tmp_path / f"{os_name}-{prof}"; c.mkdir()
            collect_tree(root, os_name, c, "d", 512, run_cmds=False, profile=prof)
            res[prof] = {Path(json.loads(l)["source"]).relative_to(root).as_posix() for l in (c / "manifest.jsonl").read_text(encoding="utf-8").splitlines() if "dest" in l}
        assert res["fast"] < res[None] < res["full"]
        extra = res["full"] - res[None]
        assert extra & {"etc/crontab", "home/bob/.bash_history", "var/spool/cron/crontabs/bob", "Library/LaunchDaemons/a.plist", "Users/bob/.zsh_history"}


def test_cli_profile_flag(tmp_path):
    root, case = tmp_path / "C", tmp_path / "case"; build(root)
    p = subprocess.run([sys.executable, "-m", "logharvest", "collect", "--case", str(case), "--source", str(root), "--profile", "fast", "--no-commands", "--no-progress"],
                       cwd=ROOT, capture_output=True, text=True)
    assert p.returncode == 0, p.stderr
    assert "profile=fast" in (case / "audit.log").read_text(encoding="utf-8")
    bad = subprocess.run([sys.executable, "-m", "logharvest", "collect", "--case", str(case), "--source", str(root), "--profile", "turbo"], cwd=ROOT, capture_output=True, text=True)
    assert bad.returncode != 0 and "invalid choice" in bad.stderr
