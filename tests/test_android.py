import json, sys
from argparse import Namespace
from pathlib import Path
import pytest
from logharvest import android, cli, detect

FAKE = Path(__file__).with_name("fake_adb.py")

@pytest.fixture
def fake_device(tmp_path, monkeypatch):
    root = tmp_path / "device"
    app = root / "storage/emulated/0/Android/data/com.example.app/files"
    app.mkdir(parents=True)
    (app / "app.log").write_text("hello\n")
    (app / "app.log.1").write_text("older\n")
    (app / "crash.txt").write_text("boom\n")
    (app / "photo.jpg").write_bytes(b"\xff\xd8")
    priv = root / "data/data/com.example.app"
    (priv / "databases").mkdir(parents=True); (priv / "databases/app.db").write_bytes(b"SQLite format 3\0")
    (priv / "cache").mkdir(); (priv / "cache/skip.tmp").write_text("cache")
    monkeypatch.setenv("FAKE_ROOT", str(root))
    monkeypatch.setattr(detect, "ADB_CMD", [sys.executable, str(FAKE)])
    monkeypatch.setenv("LOGHARVEST_NO_PROGRESS", "1")
    from logharvest import progress; monkeypatch.setattr(progress, "ENABLED", False)
    return root

def args(**kw):
    d = dict(package=[], no_bugreport=False, adb_root=False, authority="t", no_sdcard=False, max_size_mb=100, max_files=500,
             suspect_days=0, max_suspects=5, no_app_folders=False, include_cache=False, max_app_files=300, max_app_mb=500)
    d.update(kw); return Namespace(**d)

def recs(case):
    text = (case / "manifest.jsonl").read_text(encoding="utf-8")
    assert "\r" not in text
    return [json.loads(l) for l in text.splitlines()]

def device():
    return next(d for d in android.list_devices() if d["state"] == "device")

def test_stock_device_collection_and_failures_recorded(fake_device, tmp_path):
    case = tmp_path / "case"; case.mkdir()
    r = android.collect_android(case, device(), args(no_suspects=True))
    rs = recs(case)
    names = {Path(x["dest"]).name for x in rs if "dest" in x}
    for n in ("getprop.txt", "logcat.txt", "packages.txt", "packages_user.txt", "meminfo.txt", "bugreport.zip", "app.log", "app.log.1", "crash.txt"):
        assert n in names, n
    assert "photo.jpg" not in names                                   # not a log: never swept up
    assert all(x["verified"] for x in rs if "dest" in x)
    nc = [x for x in rs if x["category"] == "not_collected"]
    assert r["not_collected"] == len(nc) and any("logcat_kernel" in x["rule"] for x in nc) and any("usagestats" in x["rule"] for x in nc)
    log = (case / "audit.log").read_text(encoding="utf-8")
    assert "SHELL uid=2000" in log and "su=not available" in log

def test_suspect_found_in_logcat_gets_its_folder_but_private_data_needs_root(fake_device, tmp_path):
    case = tmp_path / "case"; case.mkdir()
    android.collect_android(case, device(), args(no_bugreport=True))
    apps = {Path(x["dest"]).name for x in recs(case) if "/apps/com.example.app/" in x.get("dest", "").replace("\\", "/")}
    assert {"app.log", "crash.txt", "photo.jpg"} <= apps               # a suspect app: its whole shared-storage folder
    assert "app.db" not in apps and "NOTE private app data" in (case / "audit.log").read_text(encoding="utf-8")

def test_su_streams_private_data_with_device_times_and_skips_cache(fake_device, tmp_path, monkeypatch):
    monkeypatch.setenv("FAKE_SU", "1")
    case = tmp_path / "case"; case.mkdir()
    android.collect_android(case, device(), args(no_bugreport=True))
    rs = [x for x in recs(case) if x.get("via") == "su"]
    names = {Path(x["dest"]).name for x in rs}
    assert "app.db" in names and "skip.tmp" not in names
    assert all(x["verified"] and x["modified"] and x["app"] == "com.example.app" for x in rs)

def test_run_as_collects_a_debuggable_app(fake_device, tmp_path, monkeypatch):
    monkeypatch.setenv("FAKE_RUNAS", "com.example.app")
    case = tmp_path / "case"; case.mkdir()
    android.collect_android(case, device(), args(no_bugreport=True))
    assert any(x.get("via") == "run-as" and x["dest"].endswith("app.db") for x in recs(case))

def test_live_logcat_and_no_bugreport(fake_device, tmp_path):
    case = tmp_path / "case"; case.mkdir()
    android.collect_android(case, device(), args(no_bugreport=True, logcat_live=1))
    rs = recs(case)
    names = {Path(x["dest"]).name for x in rs if "dest" in x}
    assert "bugreport.zip" not in names and "logcat_live.txt" in names
    assert not any(x["category"] == "not_collected" and "logcat_live" in x["rule"] for x in rs)   # stopping at the deadline is not a failure

def test_cli_collect_adb(fake_device, tmp_path, monkeypatch, capsys):
    case = tmp_path / "case"
    monkeypatch.setattr(sys, "argv", ["logharvest", "collect", "--case", str(case), "--adb", "--no-bugreport", "--authority", "W-1"])
    cli.main()
    assert "[android]" in capsys.readouterr().out
    assert (case / "evidence/android-FAKE123/_commands/getprop.txt").exists()
    assert "AUTHORITY authority='W-1'" in (case / "audit.log").read_text(encoding="utf-8")
