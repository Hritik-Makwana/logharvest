"""Progress display for long operations. Standard library only.

  Progress(label, total)   a bar:   label [#########-----]  45%  135/300  12.3 MB  ETA 0:42  current item
  Progress(label)          no known total: counter + elapsed time (a spinner)
  Spinner(label, manifest) elapsed time for ONE long blocking call (e.g. `adb bugreport`, the file walk of
                           `collect`); also shows how many rows have been added to manifest.jsonl meanwhile.

Behaviour
  * On a terminal the bar redraws one line on stderr (no ANSI codes, so it also works in old Windows consoles).
  * When output is not a terminal (piped, redirected, run from a script) there is no redrawing: a plain line is
    printed every 10% (or every 30 s when there is no total), so log files stay readable.
  * `say(msg)` prints a normal line without garbling an active bar. Use it instead of print() inside a loop.
  * `--no-progress` or the environment variable LOGHARVEST_NO_PROGRESS=1 turns everything off.
"""
import os, shutil, sys, threading, time
from pathlib import Path

ENABLED = not os.environ.get("LOGHARVEST_NO_PROGRESS")
_active = []                       # stack of live bars on a terminal


def _tty(): return ENABLED and hasattr(sys.stderr, "isatty") and sys.stderr.isatty()
def _utf8(): return (getattr(sys.stderr, "encoding", "") or "").lower().replace("-", "").startswith("utf")
def _hms(s):
    s = int(max(s, 0)); h, r = divmod(s, 3600); m, s = divmod(r, 60)
    return f"{h}:{m:02d}:{s:02d}" if h else f"{m}:{s:02d}"
def _mb(n): return f"{n / 1048576:.1f} MB" if n < 1 << 30 else f"{n / (1 << 30):.2f} GB"


def say(msg=""):
    """print() that keeps an active bar tidy."""
    if _active: _active[-1]._clear()
    print(msg, flush=True)
    if _active: _active[-1]._draw(force=True)


class Progress:
    def __init__(self, label, total=None, unit="files", quiet=False):
        self.label, self.total, self.unit = label, total, unit
        self.n = self.bytes = 0; self.item = ""; self.t0 = time.time()
        self._last_draw = 0.0; self._last_w = 0; self._next_log = 0.1; self._last_log = self.t0
        self.on = ENABLED and not quiet; self.tty = _tty() and self.on; self._closed = False
        self._lock = threading.RLock()
        if self.tty: _active.append(self)
        elif self.on: print(f"{label}: started" + (f" ({total} {unit})" if total else ""), flush=True)

    # ---- API
    def update(self, n=1, nbytes=0, item=None):
        with self._lock:
            self.n += n; self.bytes += nbytes
            if item is not None: self.item = item
            self._tick()

    def set_total(self, total):
        with self._lock: self.total = total

    def set_item(self, item):
        with self._lock: self.item = item; self._tick()

    def close(self, note=None):
        with self._lock:
            if self._closed: return
            self._closed = True
            if self.tty:
                self.item = note or ""; self._draw(force=True, final=True); sys.stderr.write("\n"); sys.stderr.flush()
                if self in _active: _active.remove(self)
                if _active: _active[-1]._draw(force=True)
            elif self.on:
                print(f"{self.label}: done, {self.n} {self.unit}" + (f", {_mb(self.bytes)}" if self.bytes else "") + f" in {_hms(time.time() - self.t0)}"
                      + (f" ({note})" if note else ""), flush=True)

    def __enter__(self): return self
    def __exit__(self, *exc): self.close("interrupted" if exc[0] else None)

    # ---- drawing
    def _tick(self):
        now = time.time()
        if self.tty: self._draw()
        elif self.on:
            if self.total:
                if self.n / self.total >= self._next_log and now - self._last_log >= 5 and self.n < self.total:   # at most one line per 5 s
                    self._next_log = (int(self.n / self.total * 10) + 1) / 10; self._last_log = now
                    print(f"{self.label}: {self.n}/{self.total} {self.unit} ({self.n * 100 // self.total}%), ETA {_hms(self._eta())}", flush=True)
            elif now - self._last_log >= 30:
                self._last_log = now; print(f"{self.label}: {self.n} {self.unit}, {_hms(now - self.t0)} elapsed", flush=True)

    def _eta(self):
        el = time.time() - self.t0
        return el / self.n * (self.total - self.n) if self.total and self.n else 0

    def _clear(self):
        if self.tty and self._last_w: sys.stderr.write("\r" + " " * self._last_w + "\r"); sys.stderr.flush(); self._last_w = 0

    def _draw(self, force=False, final=False):
        if not self.tty: return
        if _active and _active[-1] is not self: return          # only the innermost bar draws
        now = time.time()
        if not force and now - self._last_draw < 0.1: return
        self._last_draw = now
        cols = max(shutil.get_terminal_size((100, 20)).columns - 1, 40)
        full, empty = ("█", "░") if _utf8() else ("#", "-")
        if self.total:
            frac = min(self.n / self.total, 1.0); w = 24 if cols > 90 else 14
            bar = f"[{full * int(w * frac)}{empty * (w - int(w * frac))}] {frac * 100:3.0f}% {self.n}/{self.total}"
            tail = (f"  {_mb(self.bytes)}" if self.bytes else "") + (f"  ETA {_hms(self._eta())}" if not final else f"  {_hms(now - self.t0)}")
        else:
            spin = "|/-\\"[int(now * 4) % 4]
            bar = f"{spin} {self.n} {self.unit}"; tail = (f"  {_mb(self.bytes)}" if self.bytes else "") + f"  {_hms(now - self.t0)}"
        head = f"{self.label} {bar}{tail}"
        room = cols - len(head) - 2
        item = (" " + (self.item if len(self.item) <= room else "…" + self.item[-(room - 1):])) if self.item and room > 8 else ""
        line = (head + item)[:cols]
        sys.stderr.write("\r" + line + " " * max(self._last_w - len(line), 0)); sys.stderr.flush(); self._last_w = len(line)


class Spinner(Progress):
    """Elapsed-time display for a single blocking call. A background thread redraws it twice a second.
    manifest=<path to manifest.jsonl>: also shows how many rows have been added since the spinner started."""
    def __init__(self, label, manifest=None, unit="rows", quiet=False, watch=None):
        super().__init__(label, None, unit, quiet)
        self._watch = Path(watch) if watch else None; self._wt = 0.0
        self._man = Path(manifest) if manifest else None; self._off = 0; self._stop = threading.Event()
        try: self._off = self._man.stat().st_size if self._man else 0
        except OSError: self._off = 0
        self._thr = threading.Thread(target=self._run, daemon=True)
        if self.on: self._thr.start()

    def _count(self):
        if not self._man: return
        try:
            size = self._man.stat().st_size
            if size > self._off:
                with open(self._man, "rb") as f:
                    f.seek(self._off); chunk = f.read(size - self._off)
                self.n += chunk.count(b"\n"); self._off = size
        except OSError: pass

    def _size(self):
        """Bytes written so far to the watched file or folder (checked every 3 s; a big folder walk is not free)."""
        if not self._watch or time.time() - self._wt < 3: return
        self._wt = time.time(); total = 0
        try:
            if self._watch.is_file(): total = self._watch.stat().st_size
            else:
                for dp, _dn, fn in os.walk(self._watch):
                    for f in fn:
                        try: total += os.lstat(os.path.join(dp, f)).st_size
                        except OSError: pass
        except OSError: return
        self.bytes = total

    def _run(self):
        while not self._stop.wait(0.5):
            with self._lock:
                self._count(); self._size()
                self._tick()
                if self.tty: self._draw(force=True)

    def close(self, note=None):
        self._stop.set()
        if self._thr.is_alive(): self._thr.join(timeout=2)
        with self._lock: self._count()
        super().close(note)
