"""`logharvest report`: one self-contained, printable HTML file (plus optional JSON) for a case.

Sections: case + chain of custody (from audit.log), devices and counts, integrity re-check of every evidence file against
the manifest, image provenance, suspects per device with the evidence lines, timeline around the top suspects,
what could not be collected, limits and notes. Nothing in the case is modified except one line appended to audit.log.
"""
import hashlib, html, json, platform, re, sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import events as E
from .progress import Progress

UTC = timezone.utc
e = lambda x: html.escape(str(x if x is not None else ""))


def _sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""): h.update(b)
    return h.hexdigest()


def verify(case, rows, quiet=False):
    """-> (ok, mismatched, missing, unhashed) lists of dest paths."""
    ok, bad, miss, nohash = 0, [], [], []
    ev = [r for r in rows if r.get("dest") and str(r["dest"]).startswith("evidence")]
    with Progress("Verifying evidence hashes", len(ev), "files", quiet=quiet) as bar:
        for r in ev:
            bar.update(1, 0, Path(r["dest"]).name)
            p = case / r["dest"]
            if not p.is_file(): miss.append(r["dest"]); continue
            if not r.get("sha256"): nohash.append(r["dest"]); continue
            bar.bytes += p.stat().st_size
            if _sha(p) == r["sha256"]: ok += 1
            else: bad.append(r["dest"])
    return ok, bad, miss, nohash


def read_audit(case):
    f = case / "audit.log"
    return [l.rstrip("\n") for l in open(f, encoding="utf-8", errors="replace")] if f.is_file() else []


def _field(lines, key):
    for l in lines:
        m = re.search(rf"\b{key}=['\"]([^'\"]*)['\"]", l)
        if m and m.group(1): return m.group(1)
    return ""


def _table(head, rows, cls=""):
    if not rows: return "<p><i>none</i></p>"
    return f"<table class='{cls}'><tr>" + "".join(f"<th>{e(h)}</th>" for h in head) + "</tr>" + \
           "".join("<tr>" + "".join(f"<td>{c}</td>" for c in r) + "</tr>" for r in rows) + "</table>"


CSS = """body{font:13px/1.45 system-ui,sans-serif;max-width:1100px;margin:24px auto;padding:0 16px;color:#111}
h1{font-size:22px}h2{font-size:16px;border-bottom:2px solid #333;margin-top:28px;padding-bottom:2px}h3{font-size:14px;margin-bottom:2px}
table{border-collapse:collapse;width:100%;margin:6px 0}th,td{border:1px solid #bbb;padding:3px 6px;text-align:left;vertical-align:top;font-size:12px}
th{background:#eee}code,.m{font-family:ui-monospace,monospace;font-size:11px;word-break:break-all}.ok{color:#0a6b2d;font-weight:600}.bad{color:#b00020;font-weight:700}
.warn{background:#fff4d6;border:1px solid #d9a400;padding:6px 10px}@media print{h2{break-after:avoid}table{break-inside:auto}tr{break-inside:avoid}}"""


def build(case, window=15, do_verify=True, quiet=False):
    case = Path(case).resolve()
    rows = [json.loads(l) for l in open(case / "manifest.jsonl") if l.strip()]
    audit = read_audit(case)
    evs, rankings, notes = E.build(case, write=True, quiet=quiet)
    coll = [r for r in rows if r.get("dest")]
    nc = [r for r in rows if r.get("not_collected") or r.get("status") == "not_collected" or r.get("reason") and not r.get("dest")]
    ver = verify(case, rows, quiet) if do_verify else None
    devices = sorted({(r["device"], r.get("os")) for r in rows if r.get("device")})
    per_dev = Counter(r["device"] for r in coll); size_dev = Counter()
    for r in coll: size_dev[r["device"]] += int(r.get("size") or 0)
    unverified = [r["dest"] for r in coll if r.get("verified") is False]
    images = []
    for f in sorted((case / "analysis").glob("image-*.json")):
        try: images.append(json.load(open(f)))
        except (OSError, ValueError): pass
    suspects = {}
    for dev, _os in devices:
        for f in sorted((case / "analysis").glob(f"suspects-{dev}.json")):
            try: suspects[dev] = json.load(open(f))
            except (OSError, ValueError): pass
    data = dict(case=case.name, generated=datetime.now(UTC).isoformat(), tool_python=sys.version.split()[0], host=platform.node(),
                authority=_field(audit, "authority"), devices=[{"device": d, "os": o, "files": per_dev[d], "bytes": size_dev[d]} for d, o in devices],
                files=len(coll), not_collected=len(nc), integrity=None if ver is None else dict(ok=ver[0], mismatched=ver[1], missing=ver[2], unhashed=ver[3]),
                copy_unverified=unverified, events=len(evs), suspects={k: v for k, v in suspects.items()})

    h = [f"<!doctype html><meta charset=utf-8><title>LogHarvest report - {e(case.name)}</title><style>{CSS}</style>",
         f"<h1>LogHarvest report: {e(case.name)}</h1><p>Generated {e(data['generated'])} on host {e(data['host'])} (Python {e(data['tool_python'])}).</p>"]

    h.append("<h2>1. Chain of custody</h2>")
    start = [l for l in audit if " START " in l]
    h.append(_table(["Time (UTC)", "Run", "Authority", "Operator / host"],
                    [[e(l.split(" ", 1)[0][:19]), e(l.split(" ", 2)[1] + " " + l.split(" ", 2)[2][:110]), e(_field([l], "authority") or "(not recorded)"),
                      e((re.search(r"user=(\S+) host=(\S+)", l) or [None, "", ""])[1] + " @ " + (re.search(r"user=(\S+) host=(\S+)", l) or [None, "", ""])[2])] for l in start]))
    h.append(f"<p>The full command log is <code>audit.log</code> ({len(audit)} lines); its SHA-256 at report time: <span class=m>{_sha(case / 'audit.log') if (case / 'audit.log').is_file() else 'n/a'}</span></p>")
    foot = [l for l in audit if " NOTE " in l]
    if foot: h.append("<h3>Footprint and notes recorded during collection</h3><ul>" + "".join(f"<li>{e(l.split(' NOTE ', 1)[1])}</li>" for l in dict.fromkeys(foot)) + "</ul>")

    h.append("<h2>2. Sources collected</h2>")
    h.append(_table(["Device", "OS", "Files", "Size (MB)"], [[e(d["device"]), e(d["os"]), d["files"], f"{d['bytes'] / 1048576:.1f}"] for d in data["devices"]]))
    if images:
        h.append("<h3>Disk image provenance</h3>")
        for im in images:
            h.append(f"<pre class=m>{e(json.dumps(im, indent=1)[:3000])}</pre>")

    h.append("<h2>3. Integrity</h2>")
    if ver is None: h.append("<p class=warn>Hash re-verification was skipped (--no-verify). Only the hashes taken at copy time are recorded.</p>")
    else:
        okc = not ver[1] and not ver[2]
        h.append(f"<p>Every evidence file was re-hashed and compared with the SHA-256 recorded in the manifest at collection time: "
                 f"<span class={'ok' if okc else 'bad'}>{ver[0]} match, {len(ver[1])} differ, {len(ver[2])} missing</span>"
                 f"{f', {len(ver[3])} had no hash recorded' if ver[3] else ''}.</p>")
        for lab, lst in (("Differ", ver[1]), ("Missing", ver[2])):
            if lst: h.append(f"<p class=bad>{lab}:</p><ul>" + "".join(f"<li class=m>{e(x)}</li>" for x in lst[:50]) + "</ul>")
    if unverified: h.append(f"<p class=bad>{len(unverified)} file(s) failed the copy-time check (source hash differed from copy hash, e.g. a live log growing while it was read):</p><ul>" +
                            "".join(f"<li class=m>{e(x)}</li>" for x in unverified[:50]) + "</ul>")

    h.append("<h2>4. Findings: programs that crashed or hung</h2>")
    top = []
    for dev, _os in devices:
        s = suspects.get(dev); h.append(f"<h3>{e(dev)} ({e(_os)})</h3>")
        if not s: h.append("<p><i>No suspect analysis for this device.</i></p>"); continue
        byp = defaultdict(list)
        for x in s.get("events") or []: byp[x.get("pkg")].append(x)
        rows_ = []
        for it in s.get("suspects") or []:
            name = it.get("app"); evl = byp.get(name, [])
            kinds = Counter(x.get("kind") for x in evl if isinstance(x, dict))
            times = sorted(x.get("t") for x in evl if isinstance(x, dict) and x.get("t"))
            rows_.append([e(name), ", ".join(f"{k} x{v}" for k, v in kinds.items()), e((times[-1] if times else "")[:19]),
                          "<br>".join(e(f"{x.get('kind')}: {x.get('summary', '')}"[:160]) for x in evl[:3] if isinstance(x, dict))])
            if times and len(top) < 5: top.append((dev, name, times[-1]))
        h.append(_table(["Program", "Events", "Most recent (UTC)", "Evidence"], rows_))
        for n in (s.get("notes") or []): h.append(f"<p class=warn>{e(n)}</p>")

    h.append(f"<h2>5. Timeline around the top findings (±{window} min)</h2>")
    if not top: h.append("<p><i>No dated findings.</i></p>")
    for dev, name, t in top:
        t0 = datetime.fromisoformat(t); lo, hi = (t0 - timedelta(minutes=window)).isoformat(), (t0 + timedelta(minutes=window)).isoformat()
        sel = [x for x in evs if x["device"] == dev and x["t"] and lo <= x["t"] <= hi][:60]
        h.append(f"<h3>{e(name)} at {e(t[:19])} UTC ({e(dev)})</h3>")
        h.append(_table(["Time", "Kind", "App", "What", "Source"], [[e(x["t"][:19]), e(x["kind"]), e(x["app"]), e(x["summary"][:140]),
                  f"<span class=m>{e(x['source'])}{':' + str(x['line']) if x['line'] else ''}</span>"] for x in sel]))

    h.append("<h2>6. Not collected</h2>")
    byr = defaultdict(list)
    for r in nc: byr[str(r.get("reason") or r.get("note") or "unspecified")[:140]].append(r)
    h.append(_table(["Reason", "Count", "Examples"], [[e(k), len(v), "<br>".join(f"<span class=m>{e(x.get('source') or x.get('path') or x.get('rule') or '')[:120]}</span>" for x in v[:3])] for k, v in sorted(byr.items(), key=lambda kv: -len(kv[1]))]))
    lim = [l for l in audit if " LIMIT " in l or " WARN" in l]
    if lim: h.append("<h3>Limits hit</h3><ul>" + "".join(f"<li>{e(l[:300])}</li>" for l in lim[:50]) + "</ul>")
    if notes: h.append("<h3>Timeline build notes</h3><ul>" + "".join(f"<li>{e(n)}</li>" for n in notes) + "</ul>")

    h.append("<h2>7. Method and limits</h2><ul><li>Files were copied read-only and hashed (SHA-256) before and after copying; the table above re-checks them.</li>"
             "<li>Findings and the timeline are derived from the copies, not from the original device. Times are UTC; syslog lines with no zone are shown as UTC and may be offset.</li>"
             "<li>Parsers follow documented log formats; absence of a finding does not prove nothing happened. The raw evidence is in <code>evidence/</code>.</li></ul>")
    return "".join(h), data, case


def add_args(ap):
    ap.add_argument("--case", required=True, type=Path)
    ap.add_argument("--out", type=Path, help="output file (default: <case>/report.html)")
    ap.add_argument("--json", action="store_true", help="also write the summary as JSON next to the HTML")
    ap.add_argument("--no-verify", action="store_true", help="skip re-hashing all evidence (faster on huge cases)")
    ap.add_argument("--window", type=int, default=15, help="minutes either side of each top finding in the timeline section")


def run(a):
    if not (a.case / "manifest.jsonl").is_file(): print(f"ERROR: {a.case} is not a case folder"); return 2
    page, data, case = build(a.case, a.window, not a.no_verify)
    out = a.out or case / "report.html"; out.write_text(page, encoding="utf-8")
    if a.json: out.with_suffix(".json").write_text(json.dumps(data, indent=1, default=str), encoding="utf-8")
    with open(case / "audit.log", "a") as al:
        al.write(f"{datetime.now(UTC).isoformat()} DERIVED report file={out} sha256={hashlib.sha256(page.encode()).hexdigest()} verified={'skipped' if a.no_verify else 'yes'}\n")
    print(f"Report written: {out}")
    return 0
