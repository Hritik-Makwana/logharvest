"""Writes small, valid .evtx files (layout per the libyal/libevtx format description) so the reader can be tested without Windows.

Every record is one template instance. The first record of a chunk carries the template definition inline, later records
refer to it by offset; element/attribute names are written inline once and then referenced by offset. Substitution values:
  0 Provider/@Name str   1 EventID u16     2 Level u8        3 TimeCreated/@SystemTime FILETIME   4 EventRecordID u64
  5 ProcessID u32        6 ThreadID u32    7 Channel str     8 Computer str                        9 Data AppName str
 10 Data AppVersion str 11 Provider/@Guid GUID 12 Security/@UserID SID  13 Data Extra = embedded binary XML (<X>text</X>)
"""
import struct, uuid
from datetime import datetime, timezone

EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
def ft(dt): return int((dt - EPOCH).total_seconds() * 10_000_000)
def u16(x): return struct.pack("<H", x)
def u32(x): return struct.pack("<I", x)
def u64(x): return struct.pack("<Q", x)
def s16(s): return s.encode("utf-16-le") + b"\x00\x00"

SID = bytes([1, 2]) + (5).to_bytes(6, "big") + u32(32) + u32(544)          # S-1-5-32-544


class Chunk:
    def __init__(self):
        self.b = bytearray(0x200); self.names = {}; self.ids = []; self.template_at = None

    def name(self, nm):
        if nm in self.names: self.b += u32(self.names[nm]); return
        off = len(self.b) + 4; self.names[nm] = off
        self.b += u32(off) + u32(0) + u16(0) + u16(len(nm)) + nm.encode("utf-16-le") + b"\x00\x00"

    def text(self, s): self.b += b"\x05\x01" + u16(len(s)) + s.encode("utf-16-le")
    def sub(self, i, typ): self.b += b"\x0d" + u16(i) + bytes([typ])

    def element(self, nm, attrs=(), children=None):
        self.b += bytes([0x41 if attrs else 0x01]) + b"\xff\xff"; size_at = len(self.b); self.b += u32(0)
        self.name(nm)
        if attrs:
            self.b += u32(0); a_at = len(self.b) - 4; a_start = len(self.b)
            for an, val in attrs:
                self.b += b"\x06"; self.name(an)
                if val[0] == "t": self.text(val[1])
                else: self.sub(val[1], val[2])
            self.b[a_at:a_at + 4] = u32(len(self.b) - a_start)
        if children is None: self.b += b"\x03"
        else: self.b += b"\x02"; children(); self.b += b"\x04"
        self.b[size_at:size_at + 4] = u32(len(self.b) - size_at - 4)

    def template(self):
        def system():
            self.element("Provider", [("Name", ("s", 0, 1)), ("Guid", ("s", 11, 15))])
            self.element("EventID", children=lambda: self.sub(1, 6))
            self.element("Level", children=lambda: self.sub(2, 4))
            self.element("TimeCreated", [("SystemTime", ("s", 3, 17))])
            self.element("EventRecordID", children=lambda: self.sub(4, 10))
            self.element("Execution", [("ProcessID", ("s", 5, 8)), ("ThreadID", ("s", 6, 8))])
            self.element("Channel", children=lambda: self.sub(7, 1))
            self.element("Computer", children=lambda: self.sub(8, 1))
            self.element("Security", [("UserID", ("s", 12, 19))])
        def data():
            self.element("Data", [("Name", ("t", "AppName"))], children=lambda: self.sub(9, 1))
            self.element("Data", [("Name", ("t", "AppVersion"))], children=lambda: self.sub(10, 1))
            self.element("Data", [("Name", ("t", "Extra"))], children=lambda: self.sub(13, 0x21))
        self.element("Event", [("xmlns", ("t", "http://schemas.microsoft.com/win/2004/08/events/event"))],
                     children=lambda: (self.element("System", children=system), self.element("EventData", children=data)))

    def add(self, rec_id, when, prov, eid, level, pid, channel, computer, app, ver, embedded="x", corrupt=False):
        start = len(self.b)
        self.b += b"\x2a\x2a\x00\x00" + u32(0) + u64(rec_id) + u64(ft(when))
        self.b += b"\x0f\x01\x01\x00" + b"\x0c\x01" + u32(0x1234)
        if self.template_at is None:                                   # definition inline: offset field == position right after it
            self.b += u32(len(self.b) + 4); self.template_at = len(self.b)          # = where the definition starts
            self.b += u32(0) + uuid.uuid4().bytes_le + u32(0); size_at = len(self.b) - 4; body = len(self.b)
            self.b += b"\x0f\x01\x01\x00"; self.template(); self.b += b"\x00"
            self.b[size_at:size_at + 4] = u32(len(self.b) - body)
        else:
            self.b += u32(self.template_at)
        plain = [(1, s16(prov)), (6, u16(eid)), (4, bytes([level])), (17, u64(ft(when))), (10, u64(rec_id)), (8, u32(pid)), (8, u32(pid + 1)),
                 (1, s16(channel)), (1, s16(computer)), (1, s16(app)), (1, s16(ver)),
                 (15, uuid.UUID("12345678-1234-5678-1234-567812345678").bytes_le), (19, SID)]
        frag_len = 34 + len(embedded) * 2          # 4 header + 23 element start (inline name 12) + 1 close + 4 text hdr + text + end + EOF
        self.b += u32(len(plain) + 1)
        for t, d in plain: self.b += u16(len(d)) + bytes([t, 0])
        self.b += u16(frag_len) + bytes([0x21, 0])
        for _t, d in plain: self.b += d
        frag_abs = len(self.b)
        self.b += b"\x0f\x01\x01\x00" + b"\x01\xff\xff" + u32(0) + u32(frag_abs + 15) + u32(0) + u16(0) + u16(1) + "X".encode("utf-16-le") + b"\x00\x00"
        self.b += b"\x02" + b"\x05\x01" + u16(len(embedded)) + embedded.encode("utf-16-le") + b"\x04" + b"\x00"
        assert len(self.b) - frag_abs == frag_len, (len(self.b) - frag_abs, frag_len)
        size = len(self.b) - start + 4
        self.b += u32(size); self.b[start + 4:start + 8] = u32(size)
        if corrupt: self.b[start + 24] = 0x7E                           # invalid first token
        self.ids.append(rec_id)

    def finish(self):
        h = bytearray(0x200)
        h[0:8] = b"ElfChnk\x00"; h[8:16] = u64(self.ids[0]); h[16:24] = u64(self.ids[-1]); h[24:32] = u64(self.ids[0]); h[32:40] = u64(self.ids[-1])
        h[0x28:0x2C] = u32(128); h[0x2C:0x30] = u32(len(self.b) - 8); h[0x30:0x34] = u32(len(self.b))
        data = bytes(h) + bytes(self.b[0x200:])
        assert len(data) <= 0x10000
        return data + b"\x00" * (0x10000 - len(data))


def make_evtx(chunks, empty_chunks=0):
    head = bytearray(0x1000); head[0:8] = b"ElfFile\x00"; head[0x20:0x24] = u32(128); head[0x26:0x28] = u16(3); head[0x28:0x2A] = u16(0x1000)
    head[0x2A:0x2C] = u16(len(chunks))
    return bytes(head) + b"".join(c.finish() for c in chunks) + b"\x00" * 0x10000 * empty_chunks
