"""`logharvest explore --case C`: local web page with a Timeline tab and a full-text Search tab.

Listens on 127.0.0.1 only. Read-only: it never writes into the case. Files are served only if they sit inside the case
folder (path traversal is refused).
"""
import gzip, json, re, threading, webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

MAX_FILE_MB = 200
MAX_HITS = 500
MAX_LINE = 400

PAGE = r"""<!doctype html><meta charset=utf-8><title>LogHarvest explore</title>
<style>
body{font:14px system-ui,sans-serif;margin:0;background:#f6f7f9;color:#1b1f24}
header{background:#1f2933;color:#fff;padding:10px 16px;display:flex;gap:16px;align-items:center}
header b{font-size:16px} nav button{background:none;border:0;color:#cbd2d9;font-size:14px;padding:6px 10px;cursor:pointer}
nav button.on{color:#fff;border-bottom:2px solid #5aa9ff}
main{padding:12px 16px} .bar{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:10px}
input,select,button.go{padding:5px 8px;font:inherit} table{border-collapse:collapse;width:100%;background:#fff}
th,td{border-bottom:1px solid #e4e7eb;padding:4px 8px;text-align:left;vertical-align:top;font-size:13px}
th{background:#eef0f3;cursor:pointer;position:sticky;top:0} td.m{font-family:ui-monospace,monospace;white-space:pre-wrap;word-break:break-word}
.k-crash,.k-native_crash,.k-bugcheck{color:#b00020;font-weight:600}.k-anr,.k-watchdog,.k-oom_kill,.k-lmk_kill{color:#b45309;font-weight:600}
.k-boot,.k-shutdown{color:#1d4ed8}.ctx{color:#667}.hit{background:#fff3b0}a{color:#0b5fd1;cursor:pointer}
pre{background:#fff;border:1px solid #ddd;padding:8px;overflow:auto;max-height:70vh}#msg{margin:6px 0;color:#555}
</style>
<header><b>LogHarvest</b><span id=case></span><nav><button id=tt class=on onclick="tab('t')">Timeline</button><button id=ts onclick="tab('s')">Search</button></nav></header>
<main>
<section id=t><div class=bar>
<select id=tk multiple size=4 title="kinds"></select><select id=td><option value="">all devices</option></select>
<input id=tq placeholder="text filter" size=30><input id=tf type=datetime-local><input id=tu type=datetime-local>
<button class=go onclick=loadT()>Apply</button></div><div id=tmsg></div>
<table id=tb><thead><tr><th>Time (UTC)</th><th>Device</th><th>Kind</th><th>App</th><th>PID</th><th>What</th><th>Source</th></tr></thead><tbody></tbody></table></section>
<section id=s hidden><div class=bar>
<input id=sq placeholder="search text in all collected logs" size=40 onkeydown="if(event.key=='Enter')doS()">
<label><input type=checkbox id=sr> regex</label><label><input type=checkbox id=sc> case-sensitive</label>
<select id=sd><option value="">all devices</option></select><input id=sp placeholder="path contains" size=16>
<label>context <input id=sx type=number value=0 min=0 max=10 style="width:50px"></label><button class=go onclick=doS()>Search</button></div>
<div id=msg></div><div id=res></div></section>
<section id=v hidden><div><a onclick="tab(prev)">&larr; back</a> <b id=vp></b></div><pre id=vt></pre></section>
</main>
<script>
let prev='t';const $=i=>document.getElementById(i),esc=s=>String(s??'').replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));
function tab(x){if(x!='v')prev=x;for(const s of['t','s','v'])$(s).hidden=s!=x;$('tt').className=x=='t'?'on':'';$('ts').className=x=='s'?'on':''}
async function j(u){const r=await fetch(u);return r.json()}
async function init(){const m=await j('/api/meta');$('case').textContent=m.case;
for(const d of m.devices){for(const s of['td','sd'])$(s).add(new Option(d,d))}
for(const k of m.kinds)$('tk').add(new Option(k,k));loadT()}
async function loadT(){const p=new URLSearchParams();for(const o of $('tk').selectedOptions)p.append('kind',o.value);
for(const[k,v]of[['device','td'],['q','tq'],['since','tf'],['until','tu']])if($(v).value)p.set(k,$(v).value);
const r=await j('/api/timeline?'+p);$('tmsg').textContent=r.total+' events match'+(r.events.length<r.total?' (showing first '+r.events.length+')':'');
$('tb').tBodies[0].innerHTML=r.events.map(e=>`<tr><td>${esc((e.t||'(no time)').replace('T',' ').slice(0,19))}</td><td>${esc(e.device)}</td><td class="k-${e.kind}">${esc(e.kind)}</td><td>${esc(e.app)}</td><td>${esc(e.pid)}</td><td class=m>${esc(e.summary)}</td><td><a onclick="view('${encodeURIComponent(e.source)}',${e.line||0})">${esc(e.source.split('/').pop())}${e.line?':'+e.line:''}</a></td></tr>`).join('')}
async function doS(){const p=new URLSearchParams({q:$('sq').value,regex:$('sr').checked?1:0,cs:$('sc').checked?1:0,device:$('sd').value,path:$('sp').value,ctx:$('sx').value});
$('msg').textContent='searching...';const r=await j('/api/search?'+p);if(r.error){$('msg').textContent=r.error;return}
$('msg').textContent=r.hits.length+' matching lines in '+r.files_with_hits+' files ('+r.files_searched+' files searched'+(r.truncated?'; stopped at the cap, narrow the search':'')+')'+(r.skipped?'; '+r.skipped+' skipped (binary/too big)':'');
$('res').innerHTML='<table><tbody>'+r.hits.map(h=>`<tr><td><a onclick="view('${encodeURIComponent(h.path)}',${h.line})">${esc(h.path.split('/').slice(1).join('/'))}:${h.line}</a></td><td class=m>${h.before.map(x=>'<span class=ctx>'+esc(x)+'\n</span>').join('')}${esc(h.text)}${h.after.map(x=>'<span class=ctx>\n'+esc(x)+'</span>').join('')}</td></tr>`).join('')+'</tbody></table>'}
async function view(path,line){const r=await j('/api/file?path='+path+'&line='+line);tab('v');$('vp').textContent=decodeURIComponent(path);
$('vt').innerHTML=r.error?esc(r.error):r.lines.map(([n,t])=>`<span id=L${n} class="${n==line?'hit':''}">${esc(n+'  '+t)}\n</span>`).join('');const e=$('L'+line);if(e)e.scrollIntoView({block:'center'})}
init();
</script>"""


class Case:
    def __init__(self, case):
        self.root = Path(case).resolve()
        self.rows = [json.loads(l) for l in open(self.root / "manifest.jsonl") if l.strip()]
        tl = self.root / "analysis" / "derived" / "timeline.jsonl"
        self.events = [json.loads(l) for l in open(tl)] if tl.is_file() else []
        self.devices = sorted({r["device"] for r in self.rows if r.get("device")})
        self.files = [r for r in self.rows if r.get("dest") and (self.root / r["dest"]).is_file()]

    def safe(self, rel):
        p = (self.root / rel).resolve()
        return p if p.is_file() and (self.root == p or self.root in p.parents) else None

    def lines(self, p):
        """Yield text lines, or None if the file looks binary or is too big."""
        try:
            if p.stat().st_size > MAX_FILE_MB << 20: return None
            op = gzip.open if p.suffix == ".gz" else open
            with op(p, "rb") as f:
                head = f.read(4096)
                if b"\0" in head: return None
            return op(p, "rt", encoding="utf-8", errors="replace")
        except (OSError, EOFError): return None

    def timeline(self, q):
        kinds = q.get("kind", []); dev = (q.get("device") or [""])[0]; txt = (q.get("q") or [""])[0].lower()
        since = (q.get("since") or [""])[0]; until = (q.get("until") or [""])[0]
        out = [e for e in self.events if (not kinds or e["kind"] in kinds) and (not dev or e["device"] == dev)
               and (not txt or txt in (e["summary"] + " " + (e["app"] or "")).lower())
               and (not since or (e["t"] and e["t"] >= since)) and (not until or (e["t"] and e["t"] <= until))]
        return {"total": len(out), "events": out[:3000]}

    def search(self, q):
        text = (q.get("q") or [""])[0]
        if not text: return {"error": "type something to search for"}
        flags = 0 if (q.get("cs") or ["0"])[0] == "1" else re.I
        try: rx = re.compile(text if (q.get("regex") or ["0"])[0] == "1" else re.escape(text), flags)
        except re.error as e: return {"error": f"bad regex: {e}"}
        dev = (q.get("device") or [""])[0]; sub = (q.get("path") or [""])[0].lower()
        ctx = max(0, min(10, int((q.get("ctx") or ["0"])[0] or 0)))
        hits, searched, withhits, skipped, trunc = [], 0, 0, 0, False
        for r in self.files:
            if dev and r.get("device") != dev: continue
            if sub and sub not in r["dest"].lower(): continue
            p = self.root / r["dest"]; f = self.lines(p)
            if f is None: skipped += 1; continue
            searched += 1; buf = []; pend = []; got = False
            with f:
                for n, line in enumerate(f, 1):
                    line = line.rstrip("\n")
                    for h in pend[:]:
                        if len(h["after"]) < ctx: h["after"].append(line[:MAX_LINE])
                        else: pend.remove(h)
                    if rx.search(line):
                        h = {"path": r["dest"], "line": n, "text": line[:MAX_LINE], "before": buf[-ctx:] if ctx else [], "after": []}
                        hits.append(h); pend.append(h); got = True
                        if len(hits) >= MAX_HITS: trunc = True; break
                    if ctx: buf.append(line[:MAX_LINE]); buf = buf[-ctx:]
            withhits += got
            if trunc: break
        return {"hits": hits, "files_searched": searched, "files_with_hits": withhits, "skipped": skipped, "truncated": trunc}

    def view(self, q):
        p = self.safe((q.get("path") or [""])[0])
        if not p: return {"error": "file not in this case"}
        f = self.lines(p)
        if f is None: return {"error": "binary or very large file: open it from the case folder instead"}
        line = int((q.get("line") or ["0"])[0] or 0); lo, hi = max(1, line - 150), line + 150 if line else 400
        out = []
        with f:
            for n, t in enumerate(f, 1):
                if n >= lo: out.append([n, t.rstrip("\n")[:2000]])
                if n >= hi: break
        return {"lines": out}


def make_handler(case):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def _send(self, body, ctype="application/json"):
            b = body if isinstance(body, bytes) else body.encode()
            self.send_response(200); self.send_header("Content-Type", ctype + "; charset=utf-8")
            self.send_header("Content-Length", str(len(b))); self.send_header("Cache-Control", "no-store"); self.end_headers(); self.wfile.write(b)
        def do_GET(self):
            u = urlparse(self.path); q = parse_qs(u.query)
            if self.headers.get("Host", "").split(":")[0] not in ("127.0.0.1", "localhost"):
                self.send_error(403); return
            try:
                if u.path == "/": self._send(PAGE, "text/html")
                elif u.path == "/api/meta":
                    kinds = sorted({e["kind"] for e in case.events})
                    self._send(json.dumps({"case": case.root.name, "devices": case.devices, "kinds": kinds}))
                elif u.path == "/api/timeline": self._send(json.dumps(case.timeline(q)))
                elif u.path == "/api/search": self._send(json.dumps(case.search(q)))
                elif u.path == "/api/file": self._send(json.dumps(case.view(q)))
                else: self.send_error(404)
            except Exception as e: self._send(json.dumps({"error": f"{type(e).__name__}: {e}"}))
    return H


def add_args(ap):
    ap.add_argument("--case", required=True, type=Path)
    ap.add_argument("--port", type=int, default=8766)
    ap.add_argument("--no-browser", action="store_true")
    ap.add_argument("--rebuild", action="store_true", help="rebuild the timeline first (default: only if missing)")


def run(a):
    if not (a.case / "manifest.jsonl").is_file(): print(f"ERROR: {a.case} is not a case folder"); return 2
    from . import events
    if a.rebuild or not (a.case / "analysis" / "derived" / "timeline.jsonl").is_file(): events.build(a.case)
    case = Case(a.case)
    srv = ThreadingHTTPServer(("127.0.0.1", a.port), make_handler(case))
    url = f"http://127.0.0.1:{a.port}/"; print(f"Explore {case.root.name}: {url}   (Ctrl+C to stop)")
    if not a.no_browser: threading.Timer(0.5, lambda: webbrowser.open(url)).start()
    try: srv.serve_forever()
    except KeyboardInterrupt: print()
    return 0
