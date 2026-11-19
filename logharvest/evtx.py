"""Read Windows event logs (.evtx) with no third-party package.

    from logharvest.evtx import read_events, Stats
    st = Stats()
    for ev in read_events("System.evtx", stats=st):      # dicts, see `Event fields`
        ...

Event fields: event_id (int), provider, provider_guid, level (1 critical .. 5 verbose), task, opcode, keywords,
time (aware UTC datetime), record_id, channel, computer, pid, tid, user_sid, data (EventData by name), values
(EventData / UserData values in order, as strings), raw_name (root element name).

Format (file header 0x1000 bytes, then 64 KiB chunks, each "ElfChnk" + 512-byte header + event records; every record
holds a binary-XML fragment that normally is one *template instance*: a shared template definition plus the values to
substitute) as documented by libyal/libevtx. Offsets inside the binary XML are relative to the start of the chunk.

Design rules:
  * read-only, chunk by chunk (a 1 GB log never sits in memory)
  * a damaged record or chunk is COUNTED (Stats.bad_records / bad_chunks) and skipped; it never aborts the file
  * message strings are not available (they live in the provider's DLL on the original machine); the numeric event id,
    provider and the event's own data fields are what is reported
"""
import re
import struct
import uuid
from collections import Counter
from datetime import datetime, timedelta, timezone

UTC = timezone.utc
FILE_MAGIC, CHUNK_MAGIC, REC_MAGIC = b"ElfFile\x00", b"ElfChnk\x00", b"\x2a\x2a\x00\x00"
HEADER_SIZE, CHUNK_SIZE, CHUNK_HEADER = 0x1000, 0x10000, 0x200
_EPOCH = datetime(1601, 1, 1, tzinfo=UTC)
_TIME = re.compile(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d+))?")
_ENTITIES = {"amp": "&", "lt": "<", "gt": ">", "quot": '"', "apos": "'"}


class EvtxError(Exception):
    pass


class Stats(Counter):
    """chunks, empty_chunks, bad_chunks, records, bad_records (+ `errors`: a few example messages)."""
    def __init__(self):
        super().__init__(); self.errors = []

    def err(self, msg):
        if len(self.errors) < 10: self.errors.append(msg)


class _Sub:
    """Placeholder for a substitution value inside a template definition."""
    __slots__ = ("index", "optional")
    def __init__(self, index, optional): self.index, self.optional = index, optional


class _Node:
    __slots__ = ("name", "attrs", "children")
    def __init__(self, name, attrs=None, children=None):
        self.name, self.attrs, self.children = name, attrs or [], children or []

    def text(self):
        """All text below this element (an embedded-XML value arrives as a child element)."""
        return "".join(c if isinstance(c, str) else c.text() for c in self.children)

    def find(self, name):
        for c in self.children:
            if isinstance(c, _Node) and c.name == name: return c
        return None

    def attr(self, name, default=None):
        for k, v in self.attrs:
            if k == name: return v
        return default


def filetime(v):
    try: return _EPOCH + timedelta(microseconds=v // 10)
    except (OverflowError, ValueError): return None


# ------------------------------------------------------------------------------------------------ binary XML
class _Chunk:
    def __init__(self, buf):
        self.b = buf
        self._names, self._templates = {}, {}

    # ---- primitives (struct raises on truncated data; the caller treats that as a bad record)
    def u8(self, p): return self.b[p]
    def u16(self, p): return struct.unpack_from("<H", self.b, p)[0]
    def u32(self, p): return struct.unpack_from("<I", self.b, p)[0]

    def utf16(self, p, nchars):
        if p + nchars * 2 > len(self.b): raise EvtxError("string runs past the chunk")
        return self.b[p:p + nchars * 2].decode("utf-16-le", "replace")

    def name_at(self, pos):
        """Read a name reference at `pos` -> (name, position after the reference)."""
        off = self.u32(pos); pos += 4
        if off not in self._names:
            n = self.u16(off + 6)                                  # next(4) hash(2) nchars(2) chars... NUL
            self._names[off] = self.utf16(off + 8, n)
        if off == pos:                                             # definition is inline: skip over it
            return self._names[off], pos + 8 + self.u16(off + 6) * 2 + 2
        return self._names[off], pos

    # ---- values
    def value(self, vtype, pos, size):
        data = self.b[pos:pos + size]
        base, array = vtype & 0x7F, bool(vtype & 0x80)
        if base == 0 or not data: return ""
        if base == 1:
            s = data.decode("utf-16-le", "replace")
            return ", ".join(x for x in s.split("\x00") if x) if array else s.rstrip("\x00")
        if base == 2:
            s = data.decode("latin-1")
            return ", ".join(x for x in s.split("\x00") if x) if array else s.rstrip("\x00")
        fixed = {3: ("b", 1), 4: ("B", 1), 5: ("<h", 2), 6: ("<H", 2), 7: ("<i", 4), 8: ("<I", 4), 9: ("<q", 8), 10: ("<Q", 8),
                 11: ("<f", 4), 12: ("<d", 8)}
        if base in fixed:
            fmt, n = fixed[base]; vals = [struct.unpack_from(fmt, data, i)[0] for i in range(0, len(data) - n + 1, n)]
            return ", ".join(str(v) for v in vals) if array else (str(vals[0]) if vals else "")
        if base == 13: return "true" if struct.unpack_from("<I", data, 0)[0] else "false"
        if base == 14: return data.hex().upper()
        if base == 15 and len(data) >= 16: return "{" + str(uuid.UUID(bytes_le=bytes(data[:16]))).upper() + "}"
        if base == 16: return "0x%x" % int.from_bytes(data, "little")
        if base == 17:
            out = []
            for i in range(0, len(data) - 7, 8):
                t = filetime(struct.unpack_from("<Q", data, i)[0])
                out.append(t.strftime("%Y-%m-%dT%H:%M:%S.%fZ") if t else "")
            return ", ".join(out)
        if base == 18 and len(data) >= 16:
            y, mo, _dow, d, h, mi, s, ms = struct.unpack_from("<8H", data, 0)
            return f"{y:04d}-{mo:02d}-{d:02d}T{h:02d}:{mi:02d}:{s:02d}.{ms:03d}Z"
        if base == 19 and len(data) >= 8:
            rev, cnt = data[0], data[1]; auth = int.from_bytes(data[2:8], "big")
            subs = [struct.unpack_from("<I", data, 8 + 4 * i)[0] for i in range(cnt) if 8 + 4 * i + 4 <= len(data)]
            return "S-%d-%d" % (rev, auth) + "".join("-%d" % x for x in subs)
        if base == 20: return "0x%08x" % struct.unpack_from("<I", data, 0)[0]
        if base == 21: return "0x%016x" % struct.unpack_from("<Q", data, 0)[0]
        return data.hex().upper()

    # ---- tokens
    def fragment(self, pos, end):
        """Parse binary XML in [pos, end) -> list of nodes / strings."""
        items = []
        while pos < end:
            t = self.b[pos]
            if t == 0x00: break                                    # end of stream
            if t == 0x0F: pos += 4; continue                       # fragment header: token, major, minor, flags
            got, pos = self.token(pos)
            items += got
        return items

    def token(self, pos):
        """One token -> (list of items, new pos)."""
        b = self.b; t = b[pos]; k = t & 0x3F
        if k == 0x01: node, pos = self.element(pos); return [node], pos
        if k == 0x05:                                              # value text: token, type(=1), nchars, chars
            n = self.u16(pos + 2); return [self.utf16(pos + 4, n)], pos + 4 + n * 2
        if k in (0x0D, 0x0E):                                      # substitution: token, id, type
            return [_Sub(self.u16(pos + 1), k == 0x0E)], pos + 4
        if k == 0x07:
            n = self.u16(pos + 1); return [self.utf16(pos + 3, n)], pos + 3 + n * 2
        if k == 0x08: return [chr(self.u16(pos + 1))], pos + 3
        if k == 0x09:
            name, pos = self.name_at(pos + 1); return [_ENTITIES.get(name, "&" + name + ";")], pos
        if k == 0x0A: _name, pos = self.name_at(pos + 1); return [], pos             # processing instruction target
        if k == 0x0B: return [], pos + 3 + self.u16(pos + 1) * 2
        if t == 0x0C: return self.template_instance(pos)
        raise EvtxError(f"unknown token 0x{t:02x} at {pos}")

    def element(self, pos):
        has_attrs = bool(self.b[pos] & 0x40)
        pos += 1 + 2 + 4                                           # token, dependency id, element data size
        name, pos = self.name_at(pos)
        attrs = []
        if has_attrs:
            alen = self.u32(pos); pos += 4; aend = pos + alen
            while pos < aend:
                pos += 1                                           # attribute token (0x06 / 0x46)
                aname, pos = self.name_at(pos); pieces = []
                while pos < aend and self.b[pos] & 0x3F != 0x06:
                    got, pos = self.token(pos); pieces += got
                attrs.append((aname, pieces))
        close = self.b[pos]; pos += 1
        children = []
        if close == 0x02:
            while self.b[pos] != 0x04:
                got, pos = self.token(pos); children += got
            pos += 1
        elif close != 0x03: raise EvtxError(f"bad element close token 0x{close:02x}")
        return _Node(name, attrs, children), pos

    def template_instance(self, pos):
        pos += 2                                                   # token, version
        pos += 4                                                   # template id
        toff = self.u32(pos); pos += 4
        if toff == pos:                                            # definition stored inline right here
            defpos, size = pos, self.u32(pos + 20); pos += 24 + size
        else:
            defpos, size = toff, self.u32(toff + 20)
        if defpos not in self._templates:
            self._templates[defpos] = self.fragment(defpos + 24, defpos + 24 + size)
        nvals = self.u32(pos); pos += 4
        descs = []
        for i in range(nvals):
            descs.append((self.u16(pos), self.b[pos + 2])); pos += 4   # size, type, pad
        vals = []
        for size, vtype in descs:
            vals.append((vtype, pos, size)); pos += size
        out = []
        for x in self._templates[defpos]:
            r = self.fill(x, vals)
            if isinstance(r, list): out += r
            elif r is not None: out.append(r)
        return out, pos

    def fill(self, item, vals):
        if isinstance(item, str): return item
        if isinstance(item, _Sub): return self.resolve(item, vals)
        node = _Node(item.name)
        for an, pieces in item.attrs:
            out = []
            for x in pieces:
                r = x if isinstance(x, str) else self.resolve(x, vals)
                out.append(r if isinstance(r, str) else "")
            node.attrs.append((an, "".join(out)))
        for c in item.children:
            r = self.fill(c, vals)
            if isinstance(r, list): node.children += r
            elif r is not None: node.children.append(r)
        return node

    def resolve(self, sub, vals):
        if sub.index >= len(vals): return ""
        vtype, pos, size = vals[sub.index]
        if vtype == 0x21: return self.fragment(pos, pos + size)    # embedded binary XML
        if vtype == 0 and sub.optional: return None
        return self.value(vtype, pos, size)


# ------------------------------------------------------------------------------------------------ event
def _text_of(node):
    return node.text().strip() if node is not None else ""


def _to_int(s, default=None):
    try: return int(str(s).strip(), 0)
    except (ValueError, TypeError): return default


def _event(root, rec_id, rec_ts):
    sysn = root.find("System")
    ev = dict(event_id=None, provider="", provider_guid="", level=None, task=None, opcode=None, keywords="", time=None,
              record_id=rec_id, channel="", computer="", pid=None, tid=None, user_sid="", data={}, values=[], raw_name=root.name)
    if sysn is not None:
        prov = sysn.find("Provider")
        if prov is not None: ev["provider"], ev["provider_guid"] = prov.attr("Name", ""), prov.attr("Guid", "")
        ev["event_id"] = _to_int(_text_of(sysn.find("EventID")))
        ev["level"] = _to_int(_text_of(sysn.find("Level"))); ev["task"] = _to_int(_text_of(sysn.find("Task")))
        ev["opcode"] = _to_int(_text_of(sysn.find("Opcode"))); ev["keywords"] = _text_of(sysn.find("Keywords"))
        ev["channel"] = _text_of(sysn.find("Channel")); ev["computer"] = _text_of(sysn.find("Computer"))
        rid = _to_int(_text_of(sysn.find("EventRecordID")))
        if rid is not None: ev["record_id"] = rid
        tc = sysn.find("TimeCreated")
        st = tc.attr("SystemTime") if tc is not None else None
        m = _TIME.match(st or "")
        if m:
            try: ev["time"] = datetime.strptime(m.group(1), "%Y-%m-%dT%H:%M:%S").replace(tzinfo=UTC) + timedelta(microseconds=int((m.group(2) or "0").ljust(6, "0")[:6]))
            except ValueError: pass
        ex = sysn.find("Execution")
        if ex is not None: ev["pid"], ev["tid"] = _to_int(ex.attr("ProcessID")), _to_int(ex.attr("ThreadID"))
        sec = sysn.find("Security")
        if sec is not None: ev["user_sid"] = sec.attr("UserID", "")
    if ev["time"] is None: ev["time"] = rec_ts
    for part in root.children:
        if not isinstance(part, _Node) or part.name == "System": continue
        if part.name == "EventData":
            for i, d in enumerate(c for c in part.children if isinstance(c, _Node)):
                val = d.text(); ev["values"].append(val)
                if d.attr("Name"): ev["data"][d.attr("Name")] = val
        else:                                                      # UserData / DebugData / ProcessingErrorData: flatten the leaves
            stack = [part]
            while stack:
                n = stack.pop(0)
                kids = [c for c in n.children if isinstance(c, _Node)]
                if kids: stack = kids + stack
                elif n is not part:
                    val = n.text(); ev["values"].append(val); ev["data"].setdefault(n.name, val)
    return ev


# ------------------------------------------------------------------------------------------------ file
def _chunk_events(chunk, stats):
    c = _Chunk(chunk)
    free = min(struct.unpack_from("<I", chunk, 0x30)[0], len(chunk))
    pos = CHUNK_HEADER
    while pos + 24 <= free:
        if chunk[pos:pos + 4] != REC_MAGIC: break
        size, rec_id, ts = struct.unpack_from("<IQQ", chunk, pos + 4)
        if size < 28 or pos + size > len(chunk): stats["bad_records"] += 1; stats.err(f"record at chunk offset {pos}: bad size {size}"); break
        stats["records"] += 1
        try:
            items = c.fragment(pos + 24, pos + size - 4)
            root = next((i for i in items if isinstance(i, _Node)), None)
            if root is None: raise EvtxError("no element in record")
            yield _event(root, rec_id, filetime(ts))
        except Exception as e:                                     # struct.error, IndexError, EvtxError, RecursionError ...
            stats["bad_records"] += 1; stats.err(f"record {rec_id}: {type(e).__name__}: {e}")
        pos += size


def read_events(source, stats=None, limit=None, newest_first=False):
    """Yield events from an .evtx path / binary file object. Never raises for damaged data (see Stats); raises EvtxError
    only if the file is not an EVTX at all. `limit`: stop after that many events. `newest_first`: visit the chunks with the
    highest record numbers first (records inside one chunk stay oldest-first) - use with `limit` to get the most recent."""
    stats = Stats() if stats is None else stats
    f, close = (open(source, "rb"), True) if isinstance(source, (str, bytes)) or hasattr(source, "__fspath__") else (source, False)
    try:
        head = f.read(HEADER_SIZE)
        if head[:8] != FILE_MAGIC: raise EvtxError("not an EVTX file (bad magic)")
        f.seek(0, 2); body = max(0, f.tell() - HEADER_SIZE); n_chunks = body // CHUNK_SIZE
        if body % CHUNK_SIZE: stats["bad_chunks"] += 1; stats.err(f"file ends {body % CHUNK_SIZE} bytes into a chunk (truncated copy?)")
        offsets = []
        for i in range(n_chunks):
            off = HEADER_SIZE + i * CHUNK_SIZE; f.seek(off); h = f.read(0x40)
            if h[:8] != CHUNK_MAGIC: stats["empty_chunks" if not h.strip(b"\x00") else "bad_chunks"] += 1; continue
            offsets.append((struct.unpack_from("<Q", h, 8)[0], off))
        if newest_first: offsets.sort(reverse=True)
        else: offsets.sort()
        n = 0
        for _num, off in offsets:
            f.seek(off); chunk = f.read(CHUNK_SIZE)
            if len(chunk) < CHUNK_SIZE: stats["bad_chunks"] += 1; stats.err(f"chunk at {off}: truncated"); continue
            stats["chunks"] += 1
            for ev in _chunk_events(chunk, stats):
                yield ev; n += 1
                if limit and n >= limit: return
    finally:
        if close: f.close()
