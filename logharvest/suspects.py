"""Find which apps crashed or hung, from an Android case already collected by `logharvest android`.

Read-only: it reads files inside the case folder (located through manifest.jsonl) and never touches the
device or the evidence. Every finding carries file:line so it can be checked by hand. Results are also
written to <case>/analysis/suspects-<device>.json (derived data, kept apart from the evidence).

Sources and how far each is verified:
  dumpsys dropbox  entry header + `Process:` / `PID:` / `Subject:` lines   (format seen on a real Android 13 phone)
  logcat           `FATAL EXCEPTION` + `Process: pkg, PID: n`              (format seen on a real Android 13 phone)
  logcat           `ANR in pkg`, `Fatal signal ... pid N (name)`, lmkd `Kill 'pkg'`   (standard AOSP formats, not yet seen on a device)
Not parsed yet: `dumpsys activity exit-info` and bugreport tombstones (need a sample of the real format first).

Times: logcat is collected with UTC offsets. Dropbox prints device-local time, so it is converted with the
device's own timezone (persist.sys.timezone from getprop). If that is unavailable the times are shown as-is
and flagged.
"""
import json, re
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

try:
    from zoneinfo import ZoneInfo
except ImportError:                      # Python < 3.9
    ZoneInfo = None

UTC = timezone.utc
EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
SERIOUS = ("crash", "native_crash", "anr", "watchdog")
NEED = ("adb:logcat", "adb:dropbox", "adb:getprop", "adb:device_clock", "adb:exit_info")

SEP_RE = re.compile(r"^={20,}\s*$")
DB_HEAD = re.compile(r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d) (\S+) \((.*?)\)\s*$")
EXC_RE = re.compile(r"^\s*((?:[A-Za-z_][\w$]*\.)+[A-Za-z_][\w$]*(?:Exception|Error|Throwable)\b.*)$")
LOG_RE = re.compile(r"^(?:(\d{4})-)?(\d\d)-(\d\d) (\d\d:\d\d:\d\d)\.(\d+)(?: ([+-]\d{4}))?\s+(\d+)\s+(\d+)\s+([VDIWEFA])\s+(.*?)\s*:\s(.*)$")
LOG_PROC = re.compile(r"^Process: (\S+?), PID: (\d+)")
ANR_RE = re.compile(r"^ANR in (\S+)(?: \((.*?)\))?")
SIG_RE = re.compile(r"Fatal signal (\d+) \((\w+)\).*?pid (\d+) \((.*?)\)")
LMK_RE = re.compile(r"Kill '(\S+)' \((\d+)\)")


def classify(tag):
    t = tag.lower()
    if "native_crash" in t or t == "system_tombstone": return "native_crash"
    if "crash" in t: return "crash"
    if "anr" in t: return "anr"
    if "watchdog" in t: return "watchdog"
    if "lowmem" in t: return "lowmem"
    if "wtf" in t: return "wtf"
    if "strictmode" in t: return "strictmode"
    if t in ("system_boot", "system_restart"): return "boot"
    return None


def load_tz(path):
    """-> (tzinfo or None, name or None, note)."""
    if not path: return None, None, "getprop not collected"
    m = re.search(r"\[persist\.sys\.timezone\]: \[([^\]]+)\]", path.read_text("utf-8", "replace"))
    if not m: return None, None, "no persist.sys.timezone in getprop"
    if ZoneInfo is None: return None, m.group(1), "zoneinfo unavailable (Python < 3.9)"
    try: return ZoneInfo(m.group(1)), m.group(1), ""
    except Exception: return None, m.group(1), "timezone database missing (on Windows: pip install tzdata)"


def parse_dropbox(path, tz):
    events, tags, entry, want_head, n_entries = [], Counter(), None, False, 0

    def flush():
        nonlocal entry
        if not entry: return
        kind = classify(entry["tag"]); tags[entry["tag"]] += 1
        if kind:
            summary = entry["exc"] or entry["subj"] or ""
            events.append(dict(t=entry["t"], kind=kind, pkg=entry["pkg"] or "(unknown)", pid=entry["pid"], tag=entry["tag"],
                               summary=summary[:200], srcs=[(path.name, entry["line"])]))
        entry = None

    with open(path, encoding="utf-8", errors="replace") as f:
        for n, line in enumerate(f, 1):
            line = line.rstrip("\n")
            if SEP_RE.match(line): flush(); want_head = True; continue
            if want_head:
                want_head = False; m = DB_HEAD.match(line)
                if m:
                    n_entries += 1
                    naive = datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S")
                    t = naive.replace(tzinfo=tz).astimezone(UTC) if tz else naive.replace(tzinfo=UTC)
                    entry = dict(t=t, tag=m.group(2), line=n, pkg=None, pid=None, subj=None, exc=None, body=0)
                continue
            if not entry: continue
            entry["body"] += 1
            if entry["body"] > 120: continue                      # headers + first stack frames are enough
            if entry["pkg"] is None and line.startswith("Process: "): entry["pkg"] = line[9:].split()[0]
            elif entry["pid"] is None and line.startswith("PID: ") and line[5:].strip().isdigit(): entry["pid"] = int(line[5:])
            elif entry["subj"] is None and line.startswith("Subject: "): entry["subj"] = line[9:].strip()
            elif entry["exc"] is None and (m := EXC_RE.match(line)): entry["exc"] = m.group(1)
            elif entry["pkg"] is None and (m := re.search(r">>> (\S+) <<<", line)): entry["pkg"] = m.group(1)   # tombstone style
    flush()
    return events, tags, n_entries


def parse_logcat(path, tz, year_default):
    events, pend, anr, n_lines = [], None, None, 0

    def ts(m):
        year = int(m.group(1)) if m.group(1) else year_default
        t = datetime.strptime(f"{year}-{m.group(2)}-{m.group(3)} {m.group(4)}", "%Y-%m-%d %H:%M:%S") + timedelta(milliseconds=int(m.group(5)[:3].ljust(3, "0")))
        if m.group(6):
            off = m.group(6); delta = timedelta(hours=int(off[1:3]), minutes=int(off[3:5]))
            return t.replace(tzinfo=timezone(delta if off[0] == "+" else -delta)).astimezone(UTC)
        return t.replace(tzinfo=tz).astimezone(UTC) if tz else t.replace(tzinfo=UTC)

    def flush_crash():
        nonlocal pend
        if pend:
            events.append(dict(t=pend["t"], kind="crash", pkg=pend["pkg"] or f"(pid {pend['pid']})", pid=pend["pid"], tag="FATAL EXCEPTION",
                               summary=(pend["exc"] or f"thread {pend['thread']}")[:200], srcs=[(path.name, pend["n"])]))
        pend = None

    with open(path, encoding="utf-8", errors="replace") as f:
        for n, line in enumerate(f, 1):
            n_lines += 1
            if pend and n - pend["n"] > 60: flush_crash()
            if anr and n - anr["n"] > 40: events.append(anr["ev"]); anr = None
            if not (anr or "AndroidRuntime" in line or "ANR in " in line or "Fatal signal" in line or "lmkd" in line): continue
            m = LOG_RE.match(line.rstrip("\n"))
            if not m: continue
            pid, tag, msg = int(m.group(7)), m.group(10), m.group(11)
            if tag == "AndroidRuntime":
                if msg.startswith("FATAL EXCEPTION"):
                    flush_crash(); pend = dict(t=ts(m), pid=pid, n=n, thread=msg.partition(":")[2].strip(), pkg=None, exc=None)
                elif pend and pid == pend["pid"]:
                    if (p := LOG_PROC.match(msg)): pend["pkg"] = p.group(1)
                    elif pend["exc"] is None and (e := EXC_RE.match(msg)): pend["exc"] = e.group(1)
            elif anr and msg.startswith("Reason: ") and pid == anr["pid"]:
                anr["ev"]["summary"] = (anr["ev"]["summary"] + " | " + msg)[:200]
            elif (a := ANR_RE.match(msg)) and tag == "ActivityManager":
                if anr: events.append(anr["ev"])
                anr = dict(pid=pid, n=n, ev=dict(t=ts(m), kind="anr", pkg=a.group(1), pid=None, tag="ANR", summary=msg[:160], srcs=[(path.name, n)]))
            elif (s := SIG_RE.search(msg)):
                events.append(dict(t=ts(m), kind="native_crash", pkg=s.group(4), pid=int(s.group(3)), tag="Fatal signal",
                                   summary=f"signal {s.group(1)} ({s.group(2)})", srcs=[(path.name, n)]))
            elif tag == "lmkd" and (k := LMK_RE.search(msg)):
                events.append(dict(t=ts(m), kind="lmk_kill", pkg=k.group(1), pid=int(k.group(2)), tag="lmkd", summary=msg[:160], srcs=[(path.name, n)]))
    flush_crash()
    if anr: events.append(anr["ev"])
    return events, n_lines



# ---- dumpsys activity exit-info (Android 11+). Format from the AOSP ApplicationExitInfo dump; NOT yet seen on a real device.
EI_TS = re.compile(r"timestamp=(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)(?:\.\d+)?\s+pid=(\d+)")
EI_PROC = re.compile(r"process=(\S+)\s+reason=(\d+)\s+\((\w+)\)(?:\s+subreason=\d+\s+\((\w+)\))?(?:\s+status=(\d+))?")
EI_DESC = re.compile(r"description=(.*?)(?:\s+state=|\s+trace=|$)")
EI_KIND = {"CRASH": "crash", "CRASH_NATIVE": "native_crash", "ANR": "anr", "LOW_MEMORY": "lmk_kill", "EXCESSIVE_RESOURCE_USAGE": "wtf"}


def parse_exit_info(path, tz):
    events, cur, n_entries = [], None, 0
    with open(path, encoding="utf-8", errors="replace") as f:
        for n, line in enumerate(f, 1):
            if (m := EI_TS.search(line)):
                naive = datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S")
                cur = dict(t=naive.replace(tzinfo=tz).astimezone(UTC) if tz else naive.replace(tzinfo=UTC), pid=int(m.group(2)), n=n); n_entries += 1
            elif cur and (m := EI_PROC.search(line)):
                kind = EI_KIND.get(m.group(3))
                if kind:
                    d = EI_DESC.search(line); events.append(dict(t=cur["t"], kind=kind, pkg=m.group(1), pid=cur["pid"], tag="exit-info",
                        summary=f"{m.group(3)}" + (f" ({m.group(4)})" if m.group(4) else "") + (f": {d.group(1).strip()}" if d and d.group(1).strip() else ""),
                        srcs=[(path.name, cur["n"])]))
                cur = None
    return events, n_entries


# ---- tombstones and ANR traces (bugreport FS/data/tombstones, FS/data/anr; or pulled with root). AOSP text formats; NOT yet seen on a real device.
TS_HEAD = re.compile(r"^Timestamp: (\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)(?:\.\d+)?\s*([+-]\d{4})?")
TS_CMD = re.compile(r"^Cmdline: (\S+)")
TS_PROC = re.compile(r"^pid: (\d+), tid: \d+, name: (.*?)\s+>>> (\S+) <<<")
TS_SIG = re.compile(r"^signal (\d+) \((\w+)\)(?:, code (-?\d+) \((\w+)\))?")
ANR_HEAD = re.compile(r"^----- pid (\d+) at (\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)(?:\.\d+)?\s*([+-]\d{4})? -----")
ANR_CMD = re.compile(r"^Cmd line: (\S+)")


def _stamp(date, off, tz):
    naive = datetime.strptime(date, "%Y-%m-%d %H:%M:%S")
    if off:
        d = timedelta(hours=int(off[1:3]), minutes=int(off[3:5])); return naive.replace(tzinfo=timezone(d if off[0] == "+" else -d)).astimezone(UTC)
    return naive.replace(tzinfo=tz).astimezone(UTC) if tz else naive.replace(tzinfo=UTC)


def parse_crash_file(path, tz):
    """One tombstone_NN or anr_* file -> [event]. Only the header (first ~60 lines) is needed."""
    head = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for i, line in enumerate(f):
            if i >= 60: break
            head.append(line.rstrip("\n"))
    t = pid = cmd = proc = sig = subject = None
    for line in head:
        if (m := TS_HEAD.match(line)): t = _stamp(m.group(1), m.group(2), tz)
        elif (m := ANR_HEAD.match(line)): pid, t = int(m.group(1)), _stamp(m.group(2), m.group(3), tz)
        elif (m := TS_CMD.match(line)) or (m := ANR_CMD.match(line)): cmd = cmd or m.group(1)
        elif (m := TS_PROC.match(line)): pid, proc = int(m.group(1)), m.group(3)
        elif (m := TS_SIG.match(line)): sig = f"signal {m.group(1)} ({m.group(2)})" + (f", {m.group(4)}" if m.group(4) else "")
        elif line.startswith("Subject: "): subject = line[9:].strip()
    name = proc or cmd
    if not name or (t is None and not (sig or subject)): return []
    is_anr = path.name.startswith("anr") or subject is not None or (sig is None and head and head[0].startswith("----- pid"))
    return [dict(t=t, kind="anr" if is_anr else "native_crash", pkg=name, pid=pid, tag="tombstone" if not is_anr else "anr-trace",
                 summary=(subject if is_anr and subject else sig or ""), srcs=[(path.name, 1)])]


def merge(events):
    """Same crash/ANR seen in two sources (same app or pid, within 2 minutes) becomes one incident."""
    out = []
    for e in sorted(events, key=lambda e: e["t"] or EPOCH):
        hit = None
        if e["kind"] in SERIOUS and e["t"]:
            for o in reversed(out[-40:]):
                if (o["kind"] == e["kind"] and o["t"] and abs((e["t"] - o["t"]).total_seconds()) <= 120
                        and (o["pkg"] == e["pkg"] or (o["pid"] and o["pid"] == e["pid"]))
                        and not {s[0] for s in o["srcs"]} & {s[0] for s in e["srcs"]}):
                    hit = o; break
        if hit:
            hit["srcs"] += e["srcs"]; hit["summary"] = hit["summary"] or e["summary"]
            if hit["pkg"].startswith("(") and not e["pkg"].startswith("("): hit["pkg"] = e["pkg"]
        else:
            out.append(e)
    return out


def fmt(t): return t.strftime("%Y-%m-%d %H:%M:%S UTC") if t else "time unknown"
def parse_when(s):
    for f in ("%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try: return datetime.strptime(s, f).replace(tzinfo=UTC)
        except ValueError: pass
    raise SystemExit(f"bad date {s!r}: use YYYY-MM-DD or 'YYYY-MM-DD HH:MM' (UTC)")


def scan(files, since=None, until=None, crash_files=()):
    """files: {'adb:logcat'|'adb:dropbox'|'adb:getprop'|'adb:device_clock': Path}; any may be missing.
    Returns everything needed to print a report or to pick apps to collect."""
    tz, tzname, tznote = load_tz(files.get("adb:getprop"))
    year = datetime.now(UTC).year
    if "adb:device_clock" in files and (m := re.match(r"(\d{4})-", files["adb:device_clock"].read_text("utf-8", "replace"))): year = int(m.group(1))
    events, tags, n_db, n_lines, notes = [], Counter(), 0, 0, []
    if "adb:dropbox" in files: e, tags, n_db = parse_dropbox(files["adb:dropbox"], tz); events += e
    else: notes.append("dropbox.txt not available")
    if "adb:logcat" in files: e, n_lines = parse_logcat(files["adb:logcat"], tz, year); events += e
    else: notes.append("logcat.txt not available")
    if not tz: notes.append(f"dropbox times could not be converted to UTC ({tznote}); they are shown as device-local time labelled UTC")
    for key in sorted(k for k in files if k == "adb:exit_info" or k.startswith("adb:exit_info_")):
        e, _n = parse_exit_info(files[key], tz); events += e
    n_cf = 0
    for p in crash_files:
        try: events += parse_crash_file(p, tz); n_cf += 1
        except (OSError, ValueError): continue
    if crash_files: notes.append(f"{n_cf} tombstone/ANR files read")
    events = merge(events)
    if since: events = [e for e in events if not e["t"] or e["t"] >= since]
    if until: events = [e for e in events if not e["t"] or e["t"] <= until]
    by_pkg = defaultdict(list)
    for e in events:
        if e["kind"] in SERIOUS: by_pkg[e["pkg"]].append(e)
    ranked = sorted(by_pkg.items(), key=lambda kv: max((x["t"] or EPOCH) for x in kv[1]), reverse=True)
    return dict(tzname=tzname, tz=bool(tz), n_db=n_db, n_lines=n_lines, notes=notes, tags=tags, events=events, ranked=ranked)


def render(res, dev, case=None, limit=3, next_hint=True):
    L = [f"== {dev} ==",
         f"Device timezone: {res['tzname'] or 'unknown'}" + (" (dropbox times converted to UTC)" if res["tz"] else ""),
         f"Read: dropbox {res['n_db']} entries, logcat {res['n_lines']} lines" + "".join(f"\n  note: {n}" for n in res["notes"]),
         "\nSUSPECT APPS (crash / ANR / native crash / watchdog), most recent first"]
    if not res["ranked"]: L.append("  none found in the sources read")
    suggest = None
    for i, (pkg, evs) in enumerate(res["ranked"], 1):
        c = Counter(x["kind"] for x in evs); last = max((x["t"] or EPOCH) for x in evs)
        L.append(f"{i:>3}. {pkg}   " + ", ".join(f"{v} {k}" for k, v in c.items()) + f"   last: {fmt(last if last != EPOCH else None)}")
        for x in sorted(evs, key=lambda x: x["t"] or EPOCH, reverse=True)[:limit]:
            L.append(f"       {fmt(x['t'])}  {x['kind']:<12} {x['summary'][:90]}   [{', '.join(f'{s[0]}:{s[1]}' for s in x['srcs'])}]")
        if len(evs) > limit: L.append(f"       ... {len(evs) - limit} more (see the JSON file)")
        if suggest is None and not pkg.startswith("(") and pkg != "system_server": suggest = pkg
    ev = res["events"]
    kills = Counter(e["pkg"] for e in ev if e["kind"] == "lmk_kill")
    if kills: L.append("\nKILLED BY LOW MEMORY (lmkd): " + ", ".join(f"{p} x{n}" for p, n in kills.most_common(5)))
    warn = Counter((e["pkg"], e["kind"]) for e in ev if e["kind"] in ("wtf", "strictmode", "lowmem"))
    if warn: L.append("\nWARNINGS (not crashes): " + "; ".join(f"{p} {k} x{n}" for (p, k), n in warn.most_common(6)))
    if res["tags"]: L.append("Dropbox entry types: " + ", ".join(f"{t} x{n}" for t, n in res["tags"].most_common()))
    boots = [e for e in ev if e["kind"] == "boot"]
    if boots: L.append("DEVICE BOOT/RESTART RECORDS: " + ", ".join(fmt(b["t"]) for b in boots[:5]))
    if next_hint and suggest and case: L.append(f"\nNEXT: logharvest android --case {case} --package {suggest}")
    return "\n".join(L)


def to_json(res, dev):
    return json.dumps(dict(device=dev, timezone=res["tzname"], notes=res["notes"],
                           suspects=[dict(app=p, events=len(v)) for p, v in res["ranked"]],
                           events=[dict(e, t=e["t"].isoformat() if e["t"] else None, srcs=[list(s) for s in e["srcs"]]) for e in res["events"]]), indent=1)


def analyse(case, rows, dev, since, until, limit):
    files = {r["rule"]: case / r["dest"] for r in rows if r.get("device") == dev and r.get("dest") and
             (r["rule"] in NEED or r["rule"].startswith("adb:exit_info_")) and (case / r["dest"]).is_file()}
    res = scan(files, since, until, crash_files=find_crash_files(case, rows, dev))
    print("\n" + render(res, dev, case, limit))
    _save_rerun(case, dev, to_json(res, dev))


def _save_rerun(case, dev, body):
    """Re-runs never overwrite analysis/suspects-<dev>.* (those were hashed into the manifest at collection time)."""
    out = case / "analysis"; out.mkdir(exist_ok=True)
    f = out / f"suspects-{dev}-rerun-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}.json"
    f.write_text(body); print(f"(details: {f})")


def analyse_other(case, dev, os_name, since, limit):
    """Linux / Windows / macOS / iOS: re-read the evidence already inside the case."""
    from . import procsuspects as P
    ev = case / "evidence" / dev; notes = set(); cm = ev / "_commands"
    if os_name == "linux": events, n = P.scan_linux(ev, [(p, p.name) for p in cm.glob("journal_for_suspects*.txt")], notes)
    elif os_name == "windows": events, n = P.scan_windows(ev, [(p, p.name) for p in cm.glob("events_*.xml")], notes)
    elif os_name == "macos": events, n = P.scan_macos(ev)
    elif os_name == "ios":
        files = sorted(p for p in (ev / "crash_reports").rglob("*") if p.is_file()) if (ev / "crash_reports").is_dir() else []
        events, n = P.scan_reports(files), len(files)
    else: return
    res = P.build(events, notes, n, since)
    print("\n" + P.render(res, dev, limit)); _save_rerun(case, dev, P.to_json(res, dev))


def find_crash_files(case, rows, dev):
    """Tombstone / ANR files already collected for this device (unpacked bugreport or root pulls)."""
    out = []
    for r in rows:
        d = r.get("dest")
        if r.get("device") == dev and d and re.search(r"(^|/)(tombstones?|anr)/[^/]+$", d.replace("\\", "/"), re.I) and not d.endswith((".pb", ".proto")):
            p = case / d
            if p.is_file(): out.append(p)
    return out


def add_args(ap):
    ap.add_argument("--case", required=True, type=Path)
    ap.add_argument("--since", help="only events at/after this UTC time: YYYY-MM-DD or 'YYYY-MM-DD HH:MM'")
    ap.add_argument("--until", help="only events at/before this UTC time")
    ap.add_argument("--limit", type=int, default=3, help="events shown per app (default 3)")


def run(a):
    mf = a.case / "manifest.jsonl"
    if not mf.is_file(): print(f"ERROR: {mf} not found"); return 2
    rows = [json.loads(l) for l in open(mf) if l.strip()]
    devs = sorted({(r["device"], r.get("os")) for r in rows if r.get("os") in ("android", "linux", "windows", "macos", "ios") and r.get("device")})
    if not devs: print("No device in this case."); return 1
    since = parse_when(a.since) if a.since else None
    for d, osn in devs:
        if osn == "android": analyse(a.case, rows, d, since, parse_when(a.until) if a.until else None, a.limit)
        else: analyse_other(a.case, d, osn, since, a.limit)
    return 0
