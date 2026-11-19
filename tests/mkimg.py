"""Build test disk images: filesystem image populated from a directory, wrapped in an MBR partition table."""
import struct, subprocess, sys
from pathlib import Path
def run(*a, **k): return subprocess.run(a, check=True, capture_output=True, **k)

def make_ext4(src: Path, out: Path, mb=64):
    run("truncate", "-s", f"{mb}M", str(out)); run("mkfs.ext4", "-q", "-F", "-d", str(src), str(out))

def make_ntfs(src: Path, out: Path, mb=64):
    run("truncate", "-s", f"{mb}M", str(out)); run("mkntfs", "-q", "-F", "-L", "WIN", str(out))
    m = Path(str(out) + ".mnt"); m.mkdir(exist_ok=True)
    run("mount", "-t", "ntfs-3g", "-o", "loop,rw", str(out), str(m))
    try: subprocess.run(["cp", "-a", "--no-preserve=ownership", str(src) + "/.", str(m)], check=True, capture_output=True)
    finally: run("umount", str(m)); m.rmdir()

def wrap_mbr(fsimg: Path, out: Path, ptype=0x83):
    data = fsimg.read_bytes(); start = 2048; sectors = len(data) // 512
    mbr = bytearray(512)
    mbr[446:462] = bytes([0x80, 0, 1, 0, ptype, 0xFE, 0xFF, 0xFF]) + struct.pack("<II", start, sectors)
    mbr[510:512] = b"\x55\xaa"
    with open(out, "wb") as f: f.write(mbr); f.seek(start * 512); f.write(data)

if __name__ == "__main__":
    kind, src, out = sys.argv[1], Path(sys.argv[2]), Path(sys.argv[3])
    tmp = out.with_suffix(".fs")
    (make_ext4 if kind == "ext4" else make_ntfs)(src, tmp)
    wrap_mbr(tmp, out, 0x83 if kind == "ext4" else 0x07); tmp.unlink()
    print("built", out)
