"""One merged, time-sorted timeline across every device and log in a case.

Sources (all read from the collected evidence, never from the original device):
  * the suspect findings (crash / hang / killed / blue screen) from suspects.py and procsuspects.py
  * boot markers: Android dropbox SYSTEM_BOOT / SYSTEM_RESTART, Linux kernel boot banner, Windows events 12/13/6005/6006/1074
  * error-level lines of the text logs: Android logcat (E/F, and W when it names a problem), Linux syslog / messages /
    kern.log / journal, Windows event XML
  * Windows .evtx event logs (built-in reader, logharvest/evtx.py): boots/shutdowns, service crashes, disk / file-system
    and hardware (WHEA) errors, cleared audit logs, and every other Critical/Error event

Each event: t (UTC ISO or null), device, os, kind, app, pid, summary, source (path inside the case), line, level.
Written to analysis/derived/timeline.jsonl (a derived view, regenerated on demand; its SHA-256 is added to audit.log,
and it is never mixed into evidence/).
"""
import gzip, hashlib, json, re
from datetime import datetime, timezone
from pathlib import Path

from . import suspects as S
from . import procsuspects as P
from .progress import Progress
from .evtx import read_events, EvtxError, Stats as EvtxStats

UTC = timezone.utc
MAX_PER_FILE = 20000
KEYWORDS = re.compile(r"\b(error|errors|failed|failure|fatal|panic|oops|segfault|call trace|critical|emerg|alert|out of memory|oom|"
                      r"killed process|watchdog|blocked for more than|i/o error|unable to|permission denied|timed out|timeout|"
                      r"crash(?:ed)?|died|exception|abort(?:ed)?|corrupt(?:ed|ion)?|unexpected)\b", re.I)
LOGCAT = re.compile(r"^(\d{4}-\d\d-\d\d) (\d\d:\d\d:\d\d)(?:\.\d+)?\s+(\d+)\s+(\d+)\s+([VDIWEFS])\s+(.+?)\s*:\s(.*)$")
DROPBOX_BOOT = re.compile(r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d) (SYSTEM_BOOT|SYSTEM_RESTART|SYSTEM_LAST_KMSG|SYSTEM_RECOVERY_LOG)\b")
LINUX_LOGS = re.compile(r"(^|/)(var/log/(syslog|messages|kern\.log|auth\.log|daemon\.log|dmesg)(\.\d+)?(\.gz)?|_commands/journal[^/]*\.txt)$", re.I)
BOOT_LINE = re.compile(r"kernel: .*(Linux version \d|Booting Linux|Command line: )|systemd\[1\]: (Started|Starting) .*(Journal Service|Create System Users)|-- Boot ")
SYS_IDS = {"6005": ("boot", "event log service started (system boot)"), "6006": ("shutdown", "event log service stopped (clean shutdown)"),
           "1074": ("shutdown", "shutdown or restart initiated by a process or user")}


def _iso(t): return t.isoformat() if t else None


def _ev(t, device, os_name, kind, app, pid, summary, source, line, level):
    return dict(t=_iso(t), device=device, os=os_name, kind=kind, app=app, pid=pid, summary=(summary or "")[:240], source=source, line=line, level=level)


def _lines(path):
    try:
        if path.suffix == ".gz":
            with gzip.open(path, "rt", encoding="utf-8", errors="replace") as f:
                yield from enumerate(f, 1)
        else:
            with open(path, encoding="utf-8", errors="replace") as f:
                yield from enumerate(f, 1)
    except (OSError, EOFError): return


def _basename_index(ev_dir):
    idx = {}
    if ev_dir.is_dir():
        for p in ev_dir.rglob("*"):
            if p.is_file(): idx.setdefault(p.name, p)
    return idx


def _suspect_events(case, rows, dev, os_name, rel):
    """Structured events from the suspect scanners (same inputs the `suspects` command uses). -> (events, ranked)"""
    ev_dir = case / "evidence" / dev; idx = _basename_index(ev_dir); out = []
    if os_name == "android":
        files = {r["rule"]: case / r["dest"] for r in rows if r.get("device") == dev and r.get("dest") and
                 (r["rule"] in S.NEED or r["rule"].startswith("adb:exit_info_")) and (case / r["dest"]).is_file()}
        res = S.scan(files, None, None, crash_files=S.find_crash_files(case, rows, dev))
        evs = res["events"]
    else:
        notes = set(); cm = ev_dir / "_commands"
        if os_name == "linux": evs, n = P.scan_linux(ev_dir, [(p, p.name) for p in cm.glob("journal_for_suspects*.txt")], notes)
        elif os_name == "windows": evs, n = P.scan_windows(ev_dir, [(p, p.name) for p in cm.glob("events_*.xml")], notes)
        elif os_name == "macos": evs, n = P.scan_macos(ev_dir)
        elif os_name == "ios":
            fl = sorted(p for p in (ev_dir / "crash_reports").rglob("*") if p.is_file()) if (ev_dir / "crash_reports").is_dir() else []
            evs, n = P.scan_reports(fl), len(fl)
        else: return [], []
        res = P.build(evs, notes, n, None); evs = res["events"]
    for e in evs:
        label, ln = (e["srcs"][0] if e["srcs"] else (None, None))
        p = idx.get(label) or idx.get(f"{label}.txt") if label else None
        out.append(_ev(e["t"], dev, os_name, e["kind"], e["pkg"], e.get("pid"), f"{e.get('tag', '')}: {e['summary']}".strip(": "),
                       rel(p) if p else (label or ""), ln, "error"))
    return out, [(name, len(v)) for name, v in res["ranked"]], res


def _logcat(path, dev, os_name, rel):
    out = []
    for n, line in _lines(path):
        m = LOGCAT.match(line.rstrip("\n"))
        if not m or m.group(5) not in "EFW": continue
        lvl = m.group(5)
        if lvl == "W" and not KEYWORDS.search(m.group(7)): continue
        t = datetime.strptime(f"{m.group(1)} {m.group(2)}", "%Y-%m-%d %H:%M:%S").replace(tzinfo=UTC)      # collected with -v UTC
        out.append(_ev(t, dev, os_name, "error" if lvl != "W" else "warn", m.group(6), int(m.group(3)), m.group(7), rel(path), n, "error" if lvl != "W" else "warn"))
        if len(out) >= MAX_PER_FILE: break
    return out


def _dropbox_boots(path, dev, os_name, rel, tz):
    out = []
    for n, line in _lines(path):
        m = DROPBOX_BOOT.match(line)
        if not m: continue
        t = datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S"); t = t.replace(tzinfo=tz).astimezone(UTC) if tz else t.replace(tzinfo=UTC)
        out.append(_ev(t, dev, os_name, "boot", "(system)", None, f"dropbox {m.group(2)}", rel(path), n, "info"))
    return out


def _linux_text(path, dev, os_name, rel, notes):
    out = []
    try: mtime = datetime.fromtimestamp(path.stat().st_mtime, UTC)
    except OSError: mtime = None
    for n, line in _lines(path):
        line = line.rstrip("\n")
        boot = BOOT_LINE.search(line)
        if not boot and not KEYWORDS.search(line): continue
        t, msg = P._log_time(line, mtime, notes)
        out.append(_ev(t, dev, os_name, "boot" if boot else "error", "(system)" if boot else _proc_of(msg), None, msg, rel(path), n, "info" if boot else "error"))
        if len(out) >= MAX_PER_FILE: break
    return out


def _proc_of(msg):
    m = re.match(r"([\w./@-]+?)(?:\[\d+\])?:", msg.strip())
    return m.group(1) if m else ""


def _win_xml(path, dev, os_name, rel):
    from xml.etree import ElementTree as ET
    txt = re.sub(r"<\?xml[^>]*\?>", "", P._text(path)); txt = re.sub(r' xmlns="[^"]+"', "", txt); out = []
    try: root = ET.fromstring("<Events>" + txt + "</Events>")
    except ET.ParseError: return out
    for i, e in enumerate(root.iter("Event"), 1):
        sysn = e.find("System")
        if sysn is None: continue
        eid = (sysn.findtext("EventID") or "").strip()
        if eid in SYS_IDS:
            tc = sysn.find("TimeCreated"); t = None
            if tc is not None and tc.get("SystemTime"):
                try: t = datetime.strptime(tc.get("SystemTime")[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=UTC)
                except ValueError: pass
            out.append(_ev(t, dev, os_name, SYS_IDS[eid][0], "(system)", None, f"event {eid}: {SYS_IDS[eid][1]}", rel(path), i, "info"))
    return out


# ---- Windows .evtx (what the suspect scan already reports - app crash 1000, hang 1002, Kernel-Power 41, 6008, BugCheck 1001 - is skipped here)
DISK_PROVIDERS = ("disk", "ntfs", "stornvme", "storahci", "storport", "volmgr", "volsnap", "partmgr", "iastor", "refs", "microsoft-windows-ntfs",
                  "microsoft-windows-storport", "microsoft-windows-disk")
SCM_CRASH, SCM_FAIL = {7031, 7034}, {7000, 7001, 7009, 7011, 7022, 7023, 7024, 7026, 7038, 7040}
EVTX_MAX = 200_000


def _first(vals, n=1):
    return " ".join(v.strip().replace("\r", " ").replace("\n", " ") for v in vals if v and v.strip())[:160] if n else ""


def classify_win(e):
    """One decoded event -> (kind, app, summary, level) for the timeline, or None. Pure function; see tests."""
    eid, prov, lvl, v = e["event_id"], (e["provider"] or ""), e["level"], e["values"]; p = prov.lower()
    if (eid == 1000 and "application error" in p) or (eid == 1002 and "hang" in p) or (eid == 41 and "kernel-power" in p) \
            or eid == 6008 or (eid == 1001 and "bugcheck" in p):
        return None
    if "kernel-general" in p and eid == 12: return ("boot", "(system)", "Windows started (Kernel-General 12)", "info")
    if "kernel-general" in p and eid == 13: return ("shutdown", "(system)", "Windows shutting down (Kernel-General 13)", "info")
    if eid == 6005 and "eventlog" in p: return ("boot", "(system)", "event 6005: event log service started (system boot)", "info")
    if eid == 6006 and "eventlog" in p: return ("shutdown", "(system)", "event 6006: event log service stopped (clean shutdown)", "info")
    if eid == 1074: return ("shutdown", v[0] if v else "(system)", f"event 1074: shutdown/restart by {_first(v[:1])} ({_first(v[2:3])}) {_first(v[4:5])}".strip(), "info")
    if (eid == 1102 and "eventlog" in p.replace("-", "")) or (eid == 104 and "eventlog" in p.replace("-", "")) or (eid == 1102 and "security" in e["channel"].lower()):
        return ("error", "(audit)", f"event log CLEARED (event {eid}" + (f", by {_first(v[1:2])}" if len(v) > 1 else "") + ")", "error")
    if "service control manager" in p and eid in SCM_CRASH:
        return ("crash", v[0] if v else "(service)", f"service terminated unexpectedly (event {eid})", "error")
    if "service control manager" in p and eid in SCM_FAIL and lvl in (1, 2, 3, None):
        return ("error", v[0] if v else "(service)", f"service problem (event {eid}): {_first(v[1:3])}", "error")
    if any(p == d or p.startswith(d + "-") or p.endswith("-" + d) for d in DISK_PROVIDERS) and lvl in (1, 2):
        return ("error", prov, f"disk / file system error (event {eid}): {_first(v)}", "error")
    if "whea" in p and lvl in (1, 2, 3): return ("error", prov, f"hardware error reported by WHEA (event {eid}): {_first(v)}", "error")
    if lvl in (1, 2): return ("error", prov or "(unknown)", f"event {eid}: {_first(v)}", "error")
    return None


def _win_evtx(path, dev, os_name, rel, notes):
    out, st = [], EvtxStats()
    try:
        for e in read_events(path, stats=st, limit=EVTX_MAX, newest_first=True):
            c = classify_win(e)
            if not c: continue
            kind, app, summary, level = c
            out.append(_ev(e["time"], dev, os_name, kind, app, e["pid"], summary, rel(path), e["record_id"], level))
            if len(out) >= MAX_PER_FILE: break
    except (EvtxError, OSError) as ex:
        notes.add(f"{rel(path)}: not read as an event log ({ex})"); return []
    if st["bad_records"]: notes.add(f"{rel(path)}: {st['bad_records']} of {st['records']} event records could not be decoded and were skipped")
    return out


# ------------------------------------------------------------------ public API
def build(case, write=True, quiet=False):
    """-> list of events sorted by time (undated last), and per-device suspect rankings."""
    case = Path(case); mf = case / "manifest.jsonl"
    rows = [json.loads(l) for l in open(mf) if l.strip()] if mf.is_file() else []
    devices = sorted({(r["device"], r.get("os")) for r in rows if r.get("device") and r.get("os")})
    rel = lambda p: str(p.relative_to(case)) if p else ""
    events, rankings, notes = [], {}, set()
    with Progress("Building timeline", len(devices), "devices", quiet=quiet) as bar:
        for dev, os_name in devices:
            bar.update(1, 0, dev)
            try:
                se, ranked, res = _suspect_events(case, rows, dev, os_name, rel)
                events += se; rankings[dev] = ranked; tz = res.get("tz") if isinstance(res, dict) else None
            except Exception as e:
                notes.add(f"{dev}: suspect scan failed ({type(e).__name__}: {e})"); tz = None
            for r in rows:
                if r.get("device") != dev or not r.get("dest"): continue
                p = case / r["dest"]
                if not p.is_file(): continue
                d = r["dest"].replace("\\", "/")
                try:
                    if os_name == "android" and re.search(r"(^|/)logcat[^/]*\.txt$", d): events += _logcat(p, dev, os_name, rel)
                    elif os_name == "android" and d.endswith("dropbox.txt"): events += _dropbox_boots(p, dev, os_name, rel, tz)
                    elif os_name == "linux" and LINUX_LOGS.search(d): events += _linux_text(p, dev, os_name, rel, notes)
                    elif os_name == "windows" and re.search(r"(^|/)_commands/events_[^/]*\.xml$", d): events += _win_xml(p, dev, os_name, rel)
                    elif os_name == "windows" and d.lower().endswith(".evtx"): events += _win_evtx(p, dev, os_name, rel, notes)
                except Exception as e: notes.add(f"{d}: {type(e).__name__}: {e}")
    seen, uniq = set(), []
    for e in events:                                        # same line reported by two scanners
        k = (e["t"], e["device"], e["app"], e["summary"], e["pid"])
        if k not in seen: seen.add(k); uniq.append(e)
    uniq.sort(key=lambda e: (e["t"] is None, e["t"] or ""))
    if write:
        d = case / "analysis" / "derived"; d.mkdir(parents=True, exist_ok=True); f = d / "timeline.jsonl"
        with open(f, "w") as fo:
            for e in uniq: fo.write(json.dumps(e) + "\n")
        h = hashlib.sha256(f.read_bytes()).hexdigest()
        with open(case / "audit.log", "a") as al:
            al.write(f"{datetime.now(UTC).isoformat()} DERIVED timeline events={len(uniq)} file={f.relative_to(case)} sha256={h} notes={sorted(notes)}\n")
    return uniq, rankings, sorted(notes)


def add_args(ap):
    ap.add_argument("--case", required=True, type=Path)
    ap.add_argument("--kind", action="append", default=[], help="only these kinds (crash, native_crash, anr, oom_kill, lmk_kill, watchdog, bugcheck, boot, shutdown, error, warn)")
    ap.add_argument("--device", help="only this device")
    ap.add_argument("--since", help="UTC time, e.g. 2026-11-17T10:00")
    ap.add_argument("--until", help="UTC time")
    ap.add_argument("--limit", type=int, default=60, help="lines to print (default 60); the full list is analysis/derived/timeline.jsonl")


def run(a):
    if not (a.case / "manifest.jsonl").is_file(): print(f"ERROR: {a.case} is not a case folder (no manifest.jsonl)"); return 2
    events, _rank, notes = build(a.case)
    sel = [e for e in events if (not a.kind or e["kind"] in a.kind) and (not a.device or e["device"] == a.device)
           and (not a.since or (e["t"] and e["t"] >= a.since)) and (not a.until or (e["t"] and e["t"] <= a.until))]
    print(f"{len(events)} events in total ({len(sel)} match). Full list: {a.case / 'analysis' / 'derived' / 'timeline.jsonl'}")
    for e in notes: print("  note:", e)
    for e in sel[-a.limit:]:
        print(f"{(e['t'] or '(no time)')[:19]:19}  {e['device'][:22]:22} {e['kind']:<11} {(e['app'] or '')[:28]:28} {e['summary'][:90]}")
    return 0
