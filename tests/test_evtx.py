"""Pure-Python .evtx reader, tested on synthetic files written to the documented format (no real Windows log was available offline)."""
import sys; sys.path.insert(0, str(__import__("pathlib").Path(__file__).parent))
from datetime import datetime, timezone

import pytest

from logharvest.evtx import read_events, Stats, EvtxError
from evtxgen import Chunk, make_evtx

T = datetime(2026, 11, 17, 10, 30, 15, 250000, tzinfo=timezone.utc)


def sample(tmp_path, **kw):
    c = Chunk()
    c.add(100, T, "Application Error", 1000, 2, 4321, "Application", "PC01", "chrome.exe", "120.0.1", embedded="boom <&>")
    c.add(101, T.replace(minute=31), "Microsoft-Windows-Kernel-Power", 41, 1, 4, "System", "PC01", "", "", embedded="")
    c.add(102, T.replace(minute=32), "Service Control Manager", 7034, 2, 800, "System", "PC01", "Spooler", "1", embedded="y")
    c.add(103, T.replace(minute=33), "broken", 1, 2, 1, "System", "PC01", "x", "y", corrupt=True)
    c.add(104, T.replace(minute=34), "Disk", 7, 2, 4, "System", "PC01", "\\Device\\Harddisk0", "", embedded="z")
    p = tmp_path / "t.evtx"; p.write_bytes(make_evtx([c], empty_chunks=1)); return p


def test_reads_fields(tmp_path):
    st = Stats(); evs = list(read_events(sample(tmp_path), stats=st))
    assert [e["event_id"] for e in evs] == [1000, 41, 7034, 7]                   # the corrupt record is skipped, the rest survive
    e = evs[0]
    assert e["provider"] == "Application Error" and e["level"] == 2 and e["channel"] == "Application" and e["computer"] == "PC01"
    assert e["time"] == T and e["record_id"] == 100 and e["pid"] == 4321 and e["tid"] == 4322
    assert e["provider_guid"] == "{12345678-1234-5678-1234-567812345678}" and e["user_sid"] == "S-1-5-32-544"
    assert e["data"]["AppName"] == "chrome.exe" and e["data"]["AppVersion"] == "120.0.1"
    assert e["data"]["Extra"] == "boom <&>"                                      # embedded binary XML value
    assert e["values"][:2] == ["chrome.exe", "120.0.1"]


def test_stats_count_damage(tmp_path):
    st = Stats(); list(read_events(sample(tmp_path), stats=st))
    assert st["records"] == 5 and st["bad_records"] == 1 and st["chunks"] == 1 and st["empty_chunks"] == 1
    assert st.errors and "103" in st.errors[0]


def test_limit_and_newest_first(tmp_path):
    c1, c2 = Chunk(), Chunk()
    c1.add(1, T, "P", 10, 2, 1, "System", "PC", "a", "b"); c1.add(2, T, "P", 11, 2, 1, "System", "PC", "a", "b")
    c2.add(3, T, "P", 12, 2, 1, "System", "PC", "a", "b"); c2.add(4, T, "P", 13, 2, 1, "System", "PC", "a", "b")
    p = tmp_path / "two.evtx"; p.write_bytes(make_evtx([c1, c2]))
    assert [e["event_id"] for e in read_events(p)] == [10, 11, 12, 13]
    assert [e["event_id"] for e in read_events(p, newest_first=True, limit=2)] == [12, 13]      # the newest chunk only


def test_not_evtx_and_truncated(tmp_path):
    bad = tmp_path / "x.evtx"; bad.write_bytes(b"hello" * 1000)
    with pytest.raises(EvtxError): list(read_events(bad))
    p = sample(tmp_path); data = p.read_bytes(); cut = tmp_path / "cut.evtx"; cut.write_bytes(data[:0x1000 + 0x10000 - 500])
    st = Stats(); assert list(read_events(cut, stats=st)) == [] and st["bad_chunks"] == 1                # truncated chunk reported, no crash


def test_garbage_chunk_does_not_abort(tmp_path):
    c = Chunk(); c.add(1, T, "P", 10, 2, 1, "System", "PC", "a", "b")
    raw = bytearray(make_evtx([c])); raw[0x1000 + 0x230:0x1000 + 0x260] = b"\xff" * 0x30        # smash the record body
    p = tmp_path / "g.evtx"; p.write_bytes(bytes(raw)); st = Stats()
    assert list(read_events(p, stats=st)) == [] and st["bad_records"] >= 1


# ------------------------------------------------------------------ timeline + suspects integration
import json
from logharvest import events as EV, procsuspects as PS


def ev(eid, prov, lvl, values=(), channel="System"):
    return dict(event_id=eid, provider=prov, level=lvl, values=list(values), channel=channel, data={}, time=T, pid=None, record_id=1)


def test_classify():
    c = EV.classify_win
    assert c(ev(1000, "Application Error", 2)) is None and c(ev(41, "Microsoft-Windows-Kernel-Power", 1)) is None      # left to the suspect scan
    assert c(ev(12, "Microsoft-Windows-Kernel-General", 4))[0] == "boot" and c(ev(13, "Microsoft-Windows-Kernel-General", 4))[0] == "shutdown"
    assert c(ev(7034, "Service Control Manager", 2, ["Spooler"]))[:2] == ("crash", "Spooler")
    assert c(ev(7, "Disk", 2, ["\\Device\\Harddisk0"]))[0] == "error" and "disk" in c(ev(7, "Disk", 2))[2]
    assert "WHEA" in c(ev(19, "Microsoft-Windows-WHEA-Logger", 3))[2]
    assert "CLEARED" in c(ev(104, "Microsoft-Windows-Eventlog", 4))[2] and "CLEARED" in c(ev(1102, "Microsoft-Windows-Eventlog", 4, channel="Security"))[2]
    assert c(ev(1074, "User32", 4, ["explorer.exe", "PC", "Operating System: Update", "0x80030002", "restart", "bob"]))[0] == "shutdown"
    assert c(ev(5000, "Whatever", 2, ["boom"]))[0] == "error" and c(ev(5000, "Whatever", 4)) is None and c(ev(5000, "Whatever", 3)) is None


def make_case(tmp_path):
    case = tmp_path / "case"; rel = "evidence/windows-C/Windows/System32/winevt/Logs/System.evtx"
    p = case / rel; p.parent.mkdir(parents=True); p.write_bytes(sample(tmp_path).read_bytes())
    (case / "manifest.jsonl").write_text(json.dumps(dict(device="windows-C", os="windows", category="system", rule="r", source="C:/x", dest=rel, verified=True)) + "\n")
    return case


def test_timeline_has_evtx_events(tmp_path):
    case = make_case(tmp_path)
    events, _rank, notes = EV.build(case, write=False, quiet=True)
    by = {(e["kind"], e["app"]): e for e in events}
    assert ("crash", "Spooler") in by and "service terminated" in by[("crash", "Spooler")]["summary"]
    assert any(e["kind"] == "error" and "disk" in e["summary"] for e in events)
    assert any(e["kind"] == "crash" and e["app"] == "chrome.exe" for e in events)             # from the suspect scan, via the same reader
    assert any(e["kind"] == "bugcheck" for e in events)                                       # Kernel-Power 41
    assert sum(1 for e in events if "chrome.exe" in (e["app"] or "")) == 1                   # not reported twice
    assert any("could not be decoded" in n for n in notes)                                    # the deliberately corrupt record is surfaced, not hidden
    assert all(e["t"].startswith("2026-11-17T10:3") for e in events if e["t"])


def test_suspects_read_evtx_from_image_root(tmp_path):
    root = tmp_path / "C"; p = root / "Windows/System32/winevt/Logs/Application.evtx"; p.parent.mkdir(parents=True)
    p.write_bytes(sample(tmp_path).read_bytes())
    evs, n = PS.scan_windows(root, [], set())
    kinds = {(e["kind"], e["pkg"]) for e in evs}
    assert ("crash", "chrome.exe") in kinds and ("bugcheck", "(system)") in kinds


def test_unreadable_evtx_is_noted_not_fatal(tmp_path):
    root = tmp_path / "C"; p = root / "Windows/System32/winevt/Logs/Application.evtx"; p.parent.mkdir(parents=True); p.write_text("evtx")
    notes = set(); PS.scan_windows(root, [], notes)
    assert any("could not be read" in n for n in notes)
