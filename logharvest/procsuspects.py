"""Find which programs crashed, hung or were killed, from Linux / Windows / macOS / iOS evidence.

Read-only. Works on a source root (live host `/` or `C:\\`, or a mounted image) and on already-collected iOS
crash reports. Every finding keeps the file (and line) it came from.

What is read, and how far each format has been verified:
  Linux    apport /var/crash/*.crash; systemd-coredump file names; syslog / kern.log / messages / dmesg and
           (live host) `journalctl` text: kernel `segfault at`, `traps:`, `Out of memory: Killed process`,
           `dumped core`, `Main process exited, code=dumped`, watchdog failures, `blocked for more than`.
           (standard Ubuntu/Debian/systemd formats; written from the documented formats, not yet seen on your machine)
  Windows  Windows Error Reporting Report.wer files; Application log events 1000 (crash) / 1002 (hang), System
           41 / 6008 / 1001 (unexpected shutdown, bugcheck) via `wevtutil` XML on a live host, or read straight from the
           .evtx files with the built-in reader (logharvest/evtx.py; no extra package).
  macOS    DiagnosticReports: .ips (JSON), .crash/.hang/.spin (text), .panic.
  iOS      crash reports pulled from the phone (.ips), including JetsamEvent (memory kills).
"""
import gzip, json, os, re, shutil
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from xml.etree import ElementTree as ET

from .suspects import merge, fmt, EPOCH

UTC = timezone.utc
SERIOUS = ("crash", "native_crash", "anr", "watchdog", "oom_kill", "bugcheck")
MAX_LINES = 3_000_000


def _glob(root, pattern):
    try:
        yield from (p for p in root.glob(pattern, case_sensitive=False) if p.is_file())
    except OSError:
        return


def _text(path, limit=None):
    """Read text, decoding UTF-16 (Windows) and .gz transparently. Never raises."""
    try:
        if path.suffix == ".gz":
            with path.open("rb") as fh, gzip.GzipFile(fileobj=fh) as f: raw = f.read(limit) if limit else f.read()
        else:
            with path.open("rb") as f: raw = f.read(limit) if limit else f.read()
    except (OSError, EOFError):
        return ""
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"): return raw.decode("utf-16", "replace")
    return raw.decode("utf-8", "replace")


def _ev(t, kind, name, pid=None, tag="", summary="", src=None, exe=None, bundle=None):
    return dict(t=t, kind=kind, pkg=name or "(unknown)", pid=pid, tag=tag, summary=(summary or "")[:200],
                srcs=[src] if src else [], exe=exe, bundle=bundle)


# ------------------------------------------------------------------ Linux
ISO_LINE = re.compile(r"^(\d{4}-\d\d-\d\d)[T ](\d\d:\d\d:\d\d)(?:[.,]\d+)?\s*(Z|[+-]\d\d:?\d\d)?\s+\S+\s+(.*)$")
OLD_LINE = re.compile(r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d\d:\d\d:\d\d)\s+\S+\s+(.*)$")
MONTHS = {m: i for i, m in enumerate("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split(), 1)}
L_SEGV = re.compile(r"(\S+)\[(\d+)\]: segfault at ")
L_TRAP = re.compile(r"traps: (\S+)\[(\d+)\] (general protection|trap [\w ]+)")
L_OOM = re.compile(r"[Oo]ut of memory:? .*?[Kk]illed process (\d+) \((.+?)\)")
L_CORE = re.compile(r"Process (\d+) \((.+?)\) of user (\d+) dumped core")
L_SVC = re.compile(r"(\S+?)\.(?:service|scope): Main process exited, code=(dumped|killed), status=(\S+)")
L_WDOG = re.compile(r"(\S+?)\.service: .*(?:Watchdog timeout|Failed with result 'watchdog')")
L_HUNG = re.compile(r"INFO: task (\S+?):(\d+) blocked for more than (\d+) seconds")
CORE_NAME = re.compile(r"^core\.(.+?)\.(\d+)\.([0-9a-f]{32})\.(\d+)\.(\d+)(?:\.\w+)?$")
notes_tz = "syslog lines without a UTC offset are shown as if UTC (the host's local time zone is not recorded in them)"


def _log_time(line, mtime, notes):
    m = ISO_LINE.match(line)
    if m:
        off = m.group(3)
        try:
            t = datetime.strptime(f"{m.group(1)} {m.group(2)}", "%Y-%m-%d %H:%M:%S")
            if off and off != "Z":
                off = off.replace(":", ""); d = timedelta(hours=int(off[1:3]), minutes=int(off[3:5]))
                return t.replace(tzinfo=timezone(d if off[0] == "+" else -d)).astimezone(UTC), m.group(4)
            if not off: notes.add(notes_tz)
            return t.replace(tzinfo=UTC), m.group(4)
        except ValueError: return None, m.group(4)
    m = OLD_LINE.match(line)
    if m and m.group(1) in MONTHS:
        notes.add(notes_tz + "; year taken from the file's modified time")
        y = mtime.year if mtime else datetime.now(UTC).year
        try:
            t = datetime(y, MONTHS[m.group(1)], int(m.group(2)), *map(int, m.group(3).split(":")), tzinfo=UTC)
            if mtime and t > mtime + timedelta(days=2): t = t.replace(year=y - 1)
            return t, m.group(4)
        except ValueError: return None, m.group(4)
    return None, line


def parse_linux_text(path, label, notes):
    events = []
    try: mtime = datetime.fromtimestamp(path.stat().st_mtime, UTC)
    except OSError: mtime = None
    n = 0
    for n, line in enumerate(_text(path).splitlines(), 1):
        if n > MAX_LINES: break
        if not any(k in line for k in ("segfault", "traps:", "Out of memory", "out of memory", "dumped core",
                                       "Main process exited", "atchdog", "blocked for more")): continue
        t, msg = _log_time(line, mtime, notes); src = (label, n)
        if m := L_SEGV.search(msg): events.append(_ev(t, "native_crash", m.group(1), int(m.group(2)), "kernel", msg[:160], src))
        elif m := L_TRAP.search(msg): events.append(_ev(t, "native_crash", m.group(1), int(m.group(2)), "kernel", msg[:160], src))
        elif m := L_OOM.search(msg): events.append(_ev(t, "oom_kill", m.group(2), int(m.group(1)), "oom-killer", msg[:160], src))
        elif m := L_CORE.search(msg): events.append(_ev(t, "native_crash", m.group(2), int(m.group(1)), "coredump", msg[:160], src))
        elif m := L_SVC.search(msg):
            if m.group(2) == "dumped" or "SEGV" in m.group(3) or "ABRT" in m.group(3):
                events.append(_ev(t, "crash", m.group(1), None, "systemd", msg[:160], src))
        elif m := L_WDOG.search(msg): events.append(_ev(t, "watchdog", m.group(1), None, "systemd", msg[:160], src))
        elif m := L_HUNG.search(msg): events.append(_ev(t, "anr", m.group(1), int(m.group(2)), "hung_task", msg[:160], src))
    return events, n


def parse_apport(path):
    kv = {}
    for line in _text(path, 200_000).splitlines()[:400]:
        k, sep, v = line.partition(": ")
        if sep and re.match(r"^[A-Za-z][\w]*$", k) and k not in kv: kv[k] = v.strip()
    if kv.get("ProblemType") not in ("Crash", "KernelCrash", "Hang", None) and "ExecutablePath" not in kv: return None
    exe = kv.get("ExecutablePath"); name = Path(exe).name if exe else (kv.get("ProcCmdline", "").split() or ["(unknown)"])[0]
    t = None
    if kv.get("Date"):
        try: t = datetime.strptime(kv["Date"], "%a %b %d %H:%M:%S %Y").replace(tzinfo=UTC)
        except ValueError: pass
    if t is None:
        try: t = datetime.fromtimestamp(path.stat().st_mtime, UTC)
        except OSError: pass
    kind = "anr" if kv.get("ProblemType") == "Hang" else "crash"
    return _ev(t, kind, name, None, "apport", f"{kv.get('Package', '')} signal {kv.get('Signal', '?')}".strip(), (path.name, 1), exe=exe)


def scan_linux(root, text_files=(), notes=None):
    """text_files: extra (path, label) text logs, e.g. captured journalctl output."""
    notes = notes if notes is not None else set(); events, n_lines = [], 0
    for p in _glob(root, "var/crash/*.crash"):
        if e := parse_apport(p): events.append(e)
    for p in _glob(root, "var/lib/systemd/coredump/core.*"):
        if m := CORE_NAME.match(p.name):
            t = datetime.fromtimestamp(int(m.group(5)) / 1e6, UTC)
            events.append(_ev(t, "native_crash", m.group(1), int(m.group(4)), "coredump", f"core dump of {m.group(1)}", (p.name, 1)))
    seen = set()
    for pat in ("var/log/syslog*", "var/log/messages*", "var/log/kern.log*", "var/log/dmesg*", "var/log/daemon.log*"):
        for p in _glob(root, pat):
            if p in seen or p.suffix in (".xz", ".bz2", ".zst"): continue
            seen.add(p); e, n = parse_linux_text(p, p.name, notes); events += e; n_lines += n
    for p, label in text_files:
        e, n = parse_linux_text(p, label, notes); events += e; n_lines += n
    return events, n_lines


# ------------------------------------------------------------------ Windows
def _filetime(v):
    try: return datetime(1601, 1, 1, tzinfo=UTC) + timedelta(microseconds=int(v) // 10)
    except (ValueError, OverflowError): return None


def parse_wer(path):
    kv = {}
    for line in _text(path, 300_000).splitlines():
        k, sep, v = line.strip().partition("=")
        if sep and k not in kv: kv[k] = v
    et = kv.get("EventType", ""); app = kv.get("AppName") or ""
    nm = kv.get("NsAppName") or kv.get("Sig[0].Value") or app
    exe = kv.get("AppPath") or None
    if not nm and exe: nm = re.split(r"[\\/]", exe)[-1]
    if not (et or nm): return None
    low = et.lower()
    kind = "anr" if "hang" in low else "bugcheck" if ("bluescreen" in low or "livekernel" in low or "kernel" in low) else "crash"
    if kind == "bugcheck": nm = nm or "(system)"
    return _ev(_filetime(kv.get("EventTime")) if kv.get("EventTime") else None, kind, nm, None, et or "WER",
               kv.get("FriendlyEventName") or et, (str(path.parent.name) + "/Report.wer", 1), exe=exe)


def parse_events_xml(path, label):
    """Concatenated <Event> elements as written by `wevtutil qe ... /f:xml`, or python-evtx output."""
    txt = re.sub(r"<\?xml[^>]*\?>", "", _text(path))
    txt = re.sub(r' xmlns="[^"]+"', "", txt)
    try: root = ET.fromstring("<Events>" + txt + "</Events>")
    except ET.ParseError: return [], False
    out = []
    for i, e in enumerate(root.iter("Event"), 1):
        sysn = e.find("System")
        if sysn is None: continue
        eid = (sysn.findtext("EventID") or "").strip(); prov = (sysn.find("Provider").get("Name") if sysn.find("Provider") is not None else "")
        tc = sysn.find("TimeCreated"); t = None
        if tc is not None and tc.get("SystemTime"):
            s = re.sub(r"(\.\d{1,6})\d*Z?$", r"\1", tc.get("SystemTime").rstrip("Z")).split(".")[0]
            try: t = datetime.strptime(s, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=UTC)
            except ValueError: pass
        data = [(d.text or "") for d in e.findall("./EventData/Data")]
        if eid == "1000" and "Application Error" in prov:
            exe = data[10] if len(data) > 10 else None
            out.append(_ev(t, "crash", data[0] if data else "(unknown)", None, "Application Error 1000",
                           f"exception {data[6] if len(data) > 6 else '?'} in {data[3] if len(data) > 3 else '?'}", (label, i), exe=exe or None))
        elif eid == "1002" and "Hang" in prov:
            out.append(_ev(t, "anr", data[0] if data else "(unknown)", None, "Application Hang 1002", "program stopped interacting with Windows", (label, i)))
        elif (eid in ("41",) and "Kernel-Power" in prov) or eid == "6008" or (eid == "1001" and "BugCheck" in prov):
            out.append(_ev(t, "bugcheck", "(system)", None, f"System {eid}", {"41": "unexpected reboot/power loss", "6008": "unexpected shutdown",
                                                                               "1001": "bugcheck (blue screen)"}[eid], (label, i)))
    return out, True


WANTED_IDS = {"1000", "1002", "41", "6008", "1001"}


def _xml_event(eid, provider, when, data):
    from xml.sax.saxutils import escape
    return (f'<Event><System><Provider Name="{escape(str(provider))}"/><EventID>{eid}</EventID><TimeCreated SystemTime="{escape(str(when))}"/></System>'
            f"<EventData>{''.join('<Data>' + escape(str(d)) + '</Data>' for d in data)}</EventData></Event>")


def parse_evtx(path, notes=None):
    """Event log (.evtx) -> concatenated <Event> XML of the events scan_windows needs, or None if the file is not a readable
    event log. Uses the built-in reader (logharvest/evtx.py): no package to install. Newest 500k records are examined."""
    from .evtx import read_events, EvtxError, Stats
    st, xml = Stats(), []
    try:
        for ev in read_events(path, stats=st, limit=500_000, newest_first=True):
            eid = str(ev["event_id"] or "")
            if eid not in WANTED_IDS: continue
            when = ev["time"].strftime("%Y-%m-%dT%H:%M:%S.%fZ") if ev["time"] else ""
            xml.append(_xml_event(eid, ev["provider"], when, ev["values"]))
    except (EvtxError, OSError): return None
    if notes is not None and st["bad_records"]:
        notes.add(f"{path.name}: {st['bad_records']} of {st['records']} event records could not be decoded and were skipped")
    return "\n".join(xml)


def scan_windows(root, xml_files=(), notes=None):
    notes = notes if notes is not None else set(); events, n = [], 0
    for pat in ("ProgramData/Microsoft/Windows/WER/Report*/*/Report.wer", "Users/*/AppData/Local/Microsoft/Windows/WER/Report*/*/Report.wer"):
        for p in _glob(root, pat):
            n += 1
            if e := parse_wer(p): events.append(e)
    for p, label in xml_files:
        e, _ok = parse_events_xml(p, label); events += e; n += 1
    if not xml_files:                      # offline image: try the optional python-evtx
        have = False
        for name in ("Application", "System"):
            for p in (*_glob(root, f"Windows/System32/winevt/Logs/{name}.evtx"), *_glob(root, f"_exports/{name}.evtx")):   # _exports: live `wevtutil epl`
                x = parse_evtx(p, notes)
                if x is None: continue
                have = True
                import tempfile
                with tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False, encoding="utf-8") as tf: tf.write(x); tn = Path(tf.name)
                try: e, _ = parse_events_xml(tn, p.name); events += e
                finally: tn.unlink(missing_ok=True)
        if not have and (list(_glob(root, "Windows/System32/winevt/Logs/Application.evtx")) or list(_glob(root, "_exports/Application.evtx"))):
            notes.add(".evtx event logs could not be read (damaged, empty or not an event log); Report.wer files were")
    return events, n


# ------------------------------------------------------------------ macOS / iOS reports
TS_RE = re.compile(r"(\d{4}-\d\d-\d\d)[ T](\d\d:\d\d:\d\d)(?:\.\d+)?\s*([+-]\d{4}|Z)?")


def _report_time(s):
    m = TS_RE.search(s or "")
    if not m: return None
    t = datetime.strptime(f"{m.group(1)} {m.group(2)}", "%Y-%m-%d %H:%M:%S")
    off = m.group(3)
    if off and off != "Z":
        d = timedelta(hours=int(off[1:3]), minutes=int(off[3:5])); return t.replace(tzinfo=timezone(d if off[0] == "+" else -d)).astimezone(UTC)
    return t.replace(tzinfo=UTC)


def parse_report(path):
    """-> list of events from one .ips/.crash/.hang/.spin/.panic file."""
    txt = _text(path, 4_000_000); name = path.name; ext = path.suffix.lower()
    if not txt.strip(): return []
    head, body = None, None
    first, _, rest = txt.partition("\n")
    if first.lstrip().startswith("{"):
        try: head = json.loads(first)
        except ValueError: head = None
        if head is not None:
            try: body = json.loads(rest) if rest.strip() else {}
            except ValueError: body = {}
    if ext == ".panic" or "panic" in name.lower() and ext in (".ips", ".panic"):
        return [_ev(_report_time((head or {}).get("timestamp")) or _mtime(path), "bugcheck", "(kernel)", None, "panic", "kernel panic", (name, 1))]
    if head is not None:
        body = body or {}; h = head
        if name.startswith("JetsamEvent") or "processes" in body and "largestProcess" in body:
            t = _report_time(h.get("timestamp") or body.get("date")) or _mtime(path); out = []
            for p in body.get("processes", []):
                if p.get("reason"): out.append(_ev(t, "oom_kill", p.get("name"), p.get("pid"), "jetsam", f"jetsam: {p['reason']}", (name, 1)))
            return out
        pname = body.get("procName") or h.get("app_name") or h.get("name") or "(unknown)"
        bundle = (body.get("bundleInfo") or {}).get("CFBundleIdentifier") or h.get("bundleID") or None
        t = _report_time(body.get("captureTime") or h.get("timestamp")) or _mtime(path)
        exc = body.get("exception") or {}
        if ext in (".hang", ".spin") or "hang" in name.lower() or "spin" in name.lower():
            return [_ev(t, "anr", pname, body.get("pid"), ext or "ips", "hang / spin report", (name, 1), exe=body.get("procPath"), bundle=bundle)]
        if exc or body.get("termination") or h.get("bug_type") in ("309", "109"):
            summ = " ".join(x for x in (exc.get("type"), exc.get("signal"), (body.get("termination") or {}).get("indicator")) if x)
            return [_ev(t, "crash", pname, body.get("pid"), "ips", summ or "crash report", (name, 1), exe=body.get("procPath"), bundle=bundle)]
        return []
    kv = {}
    for line in txt.splitlines()[:80]:
        k, sep, v = line.partition(":")
        if sep and k not in kv and re.match(r"^[A-Za-z /]+$", k): kv[k] = v.strip()
    proc = kv.get("Process") or kv.get("Command")
    if not proc: return []
    m = re.match(r"(.+?)\s*\[(\d+)\]", proc); pname, pid = (m.group(1), int(m.group(2))) if m else (proc.split()[0], None)
    t = _report_time(kv.get("Date/Time") or kv.get("Date")) or _mtime(path)
    kind = "anr" if ext in (".hang", ".spin") else "crash"
    return [_ev(t, kind, pname, pid, ext.lstrip("."), kv.get("Exception Type") or kv.get("Event") or "", (name, 1),
                exe=(kv.get("Path") or None), bundle=(kv.get("Identifier") or None))]


def _mtime(path):
    try: return datetime.fromtimestamp(path.stat().st_mtime, UTC)
    except OSError: return None


def scan_reports(files):
    events = []
    for p in files:
        try: events += parse_report(p)
        except Exception: continue            # one unreadable/odd report must not stop the scan
    return events


def scan_macos(root):
    files = []
    for pat in ("Library/Logs/DiagnosticReports/**/*", "Users/*/Library/Logs/DiagnosticReports/**/*",
                "private/var/root/Library/Logs/DiagnosticReports/**/*"):
        files += [p for p in _glob(root, pat) if p.suffix.lower() in (".ips", ".crash", ".hang", ".spin", ".panic", ".diag")]
    return scan_reports(sorted(set(files))), len(files)


# ------------------------------------------------------------------ ranking + report
def build(events, notes, n_read, since=None, kinds=SERIOUS):
    events = merge(events)
    if since: events = [e for e in events if not e["t"] or e["t"] >= since]
    groups = defaultdict(list)
    for e in events:
        if e["kind"] in kinds: groups[e["pkg"].lower()].append(e)
    ranked = sorted(groups.values(), key=lambda v: max((x["t"] or EPOCH) for x in v), reverse=True)
    return dict(events=events, ranked=[(v[0]["pkg"], v) for v in ranked], notes=sorted(notes), n_read=n_read)


def render(res, dev, limit=3):
    L = [f"== {dev} ==", f"Read: {res['n_read']} log lines / reports" + "".join(f"\n  note: {n}" for n in res["notes"]),
         "\nSUSPECT PROGRAMS (crash / hang / watchdog / killed for memory / bugcheck), most recent first"]
    if not res["ranked"]: L.append("  none found in the sources read")
    for i, (name, evs) in enumerate(res["ranked"], 1):
        c = Counter(x["kind"] for x in evs); last = max((x["t"] or EPOCH) for x in evs)
        L.append(f"{i:>3}. {name}   " + ", ".join(f"{v} {k}" for k, v in c.items()) + f"   last: {fmt(last if last != EPOCH else None)}")
        for x in sorted(evs, key=lambda x: x["t"] or EPOCH, reverse=True)[:limit]:
            L.append(f"       {fmt(x['t'])}  {x['kind']:<10} {x['summary'][:90]}   [{', '.join(f'{s[0]}:{s[1]}' for s in x['srcs'])}]")
        if len(evs) > limit: L.append(f"       ... {len(evs) - limit} more (see the JSON file)")
    return "\n".join(L)


def to_json(res, dev):
    return json.dumps(dict(device=dev, notes=res["notes"], suspects=[dict(app=p, events=len(v)) for p, v in res["ranked"]],
                           events=[dict(e, t=e["t"].isoformat() if e["t"] else None, srcs=[list(s) for s in e["srcs"]]) for e in res["events"]]), indent=1)
