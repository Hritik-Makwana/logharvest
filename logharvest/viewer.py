import json, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse
from .collect import sha256

PAGE = r"""<!doctype html><meta charset=utf-8><title>LogHarvest</title>
<style>body{font:14px system-ui;margin:0;display:flex;height:100vh}
#l{width:58%;overflow:auto;border-right:1px solid #8886}#r{flex:1;display:flex;flex-direction:column}
table{border-collapse:collapse;width:100%}th{position:sticky;top:0;background:#8883;cursor:pointer;text-align:left}
td,th{padding:4px 8px;white-space:nowrap;max-width:280px;overflow:hidden;text-overflow:ellipsis}
tr:hover{background:#8882}pre{flex:1;margin:0;padding:8px;overflow:auto;font-size:12px}
.bad{color:#d33;font-weight:600}.ok{color:#2a2}input,select{margin:6px 4px}</style>
<div id=l><input id=q placeholder="filter path..." size=24>
<select id=os><option value="">all OS</option></select>
<select id=cat><option value="">all</option><option>system</option><option>application</option></select>
<table><thead><tr id=h></tr></thead><tbody id=b></tbody></table></div>
<div id=r><div id=info style="padding:8px"></div><pre id=v>Select a file</pre></div>
<script>
const cols=[["device","Device"],["os","OS"],["category","Type"],["source","Source path"],["size","Size"],
["modified","Modified"],["accessed","Accessed"],["changed_or_created","Changed/Created"],["verified","Hash"]];
let rows=[],key="modified",dir=-1;
const $=id=>document.getElementById(id);
$("h").innerHTML=cols.map(c=>`<th data-k=${c[0]}>${c[1]}</th>`).join("");
$("h").onclick=e=>{const k=e.target.dataset.k;if(!k)return;dir=k==key?-dir:1;key=k;draw()};
["q","os","cat"].forEach(i=>$(i).oninput=draw);
function draw(){const q=$("q").value.toLowerCase();
 let r=rows.filter(x=>(!q||(x.source||"").toLowerCase().includes(q))&&(!$("os").value||x.os==$("os").value)&&(!$("cat").value||x.category==$("cat").value));
 r.sort((a,b)=>((a[key]??"")>(b[key]??"")?1:-1)*dir);
 $("b").innerHTML=r.map(x=>`<tr data-i=${x.i}>`+cols.map(c=>{let v=x[c[0]];
  if(c[0]=="verified")v=x.error?"<span class=bad>error</span>":v?"<span class=ok>ok</span>":"<span class=bad>MISMATCH</span>";
  else v=v==null?"":String(v).replace(/</g,"&lt;");return`<td title="${x[c[0]]??""}">${v}</td>`}).join("")+"</tr>").join("")}
$("b").onclick=async e=>{const tr=e.target.closest("tr");if(!tr)return;const i=tr.dataset.i,x=rows[i];
 $("info").innerHTML=`<b>${x.source}</b><br>sha256 ${x.sha256||"-"} <button id=vb>Re-verify</button> <span id=vr></span>`;
 $("vb").onclick=async()=>{$("vr").textContent=(await (await fetch("/api/verify?i="+i)).json()).result};
 $("v").textContent=x.dest?await (await fetch("/api/file?i="+i)).text():(x.error||"")};
fetch("/api/files").then(r=>r.json()).then(d=>{rows=d;
 [...new Set(d.map(x=>x.os))].forEach(o=>$("os").add(new Option(o,o)));draw()});
</script>"""

def serve(case: Path, port: int):
    case = case.resolve()
    def load():
        recs = [json.loads(l) for l in open(case / "manifest.jsonl")]
        for i, r in enumerate(recs): r["i"] = i
        return recs

    class H(BaseHTTPRequestHandler):
        def _send(self, body, ctype):
            b = body.encode() if isinstance(body, str) else body
            self.send_response(200); self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
        def do_GET(self):
            u = urlparse(self.path); q = parse_qs(u.query)
            if u.path == "/": return self._send(PAGE, "text/html; charset=utf-8")
            if u.path == "/api/files": return self._send(json.dumps(load()), "application/json")
            recs = load(); r = recs[int(q["i"][0])] if "i" in q else None
            if not r or "dest" not in r: return self.send_error(404)
            f = (case / r["dest"]).resolve()
            if case not in f.parents: return self.send_error(403)   # path traversal guard
            if u.path == "/api/verify":
                ok = sha256(f) == r["sha256"]
                return self._send(json.dumps({"result": "MATCH" if ok else "MODIFIED!"}), "application/json")
            if u.path == "/api/file":   # last 200 KB, decoded leniently
                with open(f, "rb") as fh:
                    fh.seek(0, 2); n = fh.tell(); fh.seek(max(0, n - 200_000))
                    return self._send(fh.read().decode("utf-8", "replace"), "text/plain; charset=utf-8")
            self.send_error(404)
        def log_message(self, *a): pass

    print(f"Viewer: http://127.0.0.1:{port}  (Ctrl+C to stop)")
    ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()
