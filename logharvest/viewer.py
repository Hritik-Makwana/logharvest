import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse
from .collect import sha256

PAGE = Path(__file__).with_name("index.html")
LIMIT = 300_000

def hexdump(b: bytes) -> str:
    out = []
    for o in range(0, len(b), 16):
        c = b[o:o + 16]
        out.append(f"{o:08x}  {c.hex(' '):<47}  {''.join(chr(x) if 32 <= x < 127 else '.' for x in c)}")
    return "\n".join(out)

def serve(case: Path, port: int):
    case = case.resolve()

    def load():
        with open(case / "manifest.jsonl") as f:
            recs = [json.loads(l) for l in f if l.strip()]
        for i, r in enumerate(recs): r["i"] = i
        return recs

    class H(BaseHTTPRequestHandler):
        def _send(self, body, ctype, code=200, extra=None):
            b = body.encode() if isinstance(body, str) else body
            self.send_response(code); self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(b))); self.send_header("Cache-Control", "no-store")
            for k, v in (extra or {}).items(): self.send_header(k, v)
            self.end_headers(); self.wfile.write(b)
        def _json(self, obj, code=200): self._send(json.dumps(obj), "application/json", code)

        def do_GET(self):
            u = urlparse(self.path); q = parse_qs(u.query)
            if u.path == "/": return self._send(PAGE.read_bytes(), "text/html; charset=utf-8")
            if u.path == "/api/files": return self._json({"case": case.name, "files": load()})
            try:
                r = load()[int(q["i"][0])]
                f = (case / r["dest"]).resolve()
                if case not in f.parents or not f.is_file(): raise ValueError
            except (KeyError, IndexError, ValueError):
                return self._json({"error": "not found"}, 404)
            if u.path == "/api/verify":
                return self._json({"match": sha256(f) == r["sha256"]})
            if u.path == "/api/raw":
                return self._send(f.read_bytes(), "application/octet-stream",
                                  extra={"Content-Disposition": f'attachment; filename="{f.name}"'})
            if u.path == "/api/file":
                size = f.stat().st_size; head = q.get("mode", ["tail"])[0] == "head"
                with open(f, "rb") as fh:
                    probe = fh.read(8192)
                    if b"\0" in probe:
                        return self._json({"binary": True, "truncated": True, "size": size, "text": hexdump(probe[:4096])})
                    fh.seek(0 if head else max(0, size - LIMIT)); data = fh.read(LIMIT)
                text = data.decode("utf-8", "replace")
                if not head and size > LIMIT: text = text.split("\n", 1)[-1]   # drop partial first line
                return self._json({"binary": False, "truncated": size > LIMIT, "size": size, "text": text})
            self._json({"error": "not found"}, 404)
        def log_message(self, *a): pass

    print(f"Viewer: http://127.0.0.1:{port}  (Ctrl+C to stop)")
    ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()
