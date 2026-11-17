import json, sys
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
    (app / "photo.jpg").write_bytes(b"\xff\xd8")          # must NOT be collected
    monkeypatch.setenv("FAKE_ROOT", str(root))
    monkeypatch.setattr(detect, "ADB_CMD", [sys.executable, str(FAKE)])
    return root

def recs(case):
    text = (case / "manifest.jsonl").read_text(encoding="utf-8")
    assert "\r" not in text
    return [json.loads(l) for l in text.splitlines()]

def test_collect_adb_stock_device(fake_device, tmp_path):
    case = tmp_path / "case"; case.mkdir()
    mode, ok, err = android.collect_adb("FAKE123", case, 512, False, bugreport=True)
    assert mode == "shell"
    rs = recs(case)
    names = {Path(r["dest"]).name for r in rs if "dest" in r}
    # logcat, getprop, packages, dumpsys, bugreport and app files are all present
    for n in ("getprop.txt", "logcat_system.txt", "logcat_main.txt", "packages.txt", "packages_user.txt",
              "packages_system.txt", "dumpsys_battery.txt", "dumpsys_input.txt", "dumpsys_meminfo.txt",
              "dumpsys_package.txt", "bugreport.zip", "app.log", "app.log.1", "crash.txt"):
        assert n in names, n
    assert "photo.jpg" not in names
    assert all(r["verified"] for r in rs if "dest" in r)
    # failures are recorded, not dropped
    errors = [r for r in rs if "error" in r]
    assert len(errors) == err and err >= 2
    assert any("kernel" in r["source"] for r in errors)
    assert any("usagestats" in r["source"] for r in errors)
    assert ok == sum("dest" in r for r in rs)
    assert "access=shell" in (case / "audit.log").read_text(encoding="utf-8")

def test_no_bugreport_and_live_logcat(fake_device, tmp_path):
    case = tmp_path / "case"; case.mkdir()
    android.collect_adb("FAKE123", case, 512, False, bugreport=False, live_secs=1)
    names = {Path(r["dest"]).name for r in recs(case) if "dest" in r}
    assert "bugreport.zip" not in names
    assert "logcat_live.txt" in names

def test_cli_adb_all_devices(fake_device, tmp_path, monkeypatch, capsys):
    case = tmp_path / "case"
    monkeypatch.setattr(sys, "argv", ["logharvest", "collect", "--case", str(case), "--adb", "--no-bugreport"])
    cli.main()
    assert "adb FAKE123 [access=shell]" in capsys.readouterr().out
    assert (case / "evidence/adb-FAKE123/getprop.txt").exists()
