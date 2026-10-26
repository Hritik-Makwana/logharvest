import json, stat, sys
import pytest
from logharvest import ios

STUB = '''#!/usr/bin/env python3
import sys, json
a = sys.argv[1:]
if a[:2] == ["usbmux", "list"]:
    print(json.dumps([{"Identifier": "UDID1234", "DeviceName": "T", "ProductType": "iPhone17,3", "ProductVersion": "18.1", "ConnectionType": "USB"}]))
elif a[:1] == ["version"]: print("0.0")
elif a[:2] == ["lockdown", "info"]: print("{}")
elif a[:2] == ["crash", "pull"]: open(a[2] + "/x.ips", "w").write("crash")
else: sys.exit(1)
'''

@pytest.mark.skipif(sys.platform == "win32", reason="shell-script stub")
def test_failed_step_is_logged_and_others_continue(tmp_path, monkeypatch):
    stub = tmp_path / "pmd"; stub.write_text(STUB); stub.chmod(stub.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("LOGHARVEST_PMD", str(stub))
    dev = ios.list_devices()[0]
    ios.collect_ios(tmp_path / "case", dev, ["device_info", "logarchive", "crash_reports"])
    recs = [json.loads(l) for l in (tmp_path / "case/manifest.jsonl").read_text().splitlines()]
    assert any(x["category"] == "crash" for x in recs)
    assert any(x["category"] == "not_collected" and "logarchive" in x["rule"] for x in recs)
