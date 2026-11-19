"""Fake `adb` for CI (runs on any OS): `python fake_adb.py [-s SERIAL] <command...>`.
The fake phone's shared storage lives under $FAKE_ROOT (/sdcard -> $FAKE_ROOT/storage/emulated/0).
Default: a stock phone (shell user, no su, no debuggable apps). Environment switches:
  FAKE_SU=1        `su -c ...` works (rooted phone) and /data/data/<pkg> files under $FAKE_ROOT/data/data are readable through it
  FAKE_RUNAS=pkg   `run-as pkg ...` works for that package (files under $FAKE_ROOT/data/data/<pkg>)"""
import glob, os, re, shlex, shutil, sys, time, zipfile

out = sys.stdout.buffer
def say(text): out.write(text.encode()); out.flush()
def fail(msg, rc=1): sys.stderr.write(msg + "\n"); sys.exit(rc)

args = sys.argv[1:]
root = os.environ.get("FAKE_ROOT", ".")
SU, RUNAS = bool(os.environ.get("FAKE_SU")), os.environ.get("FAKE_RUNAS", "")
if args[:1] == ["-s"]: args = args[2:]
def real(p): return root + ("/storage/emulated/0" + p[7:] if p.startswith("/sdcard") else p)

if args[:1] == ["version"]: say("Android Debug Bridge version 1.0.41\nVersion 35.0.2-fake\n"); sys.exit(0)
if args[:1] == ["devices"]:
    say("List of devices attached\nFAKE123\tdevice" + (" usb:1-1 model:FakePhone transport_id:1" if "-l" in args else "") + "\n"); sys.exit(0)
if args[:1] == ["root"]: fail("adbd cannot run as root in production builds")
if args[:1] == ["wait-for-device"]: sys.exit(0)
if args[:1] == ["bugreport"]:
    with zipfile.ZipFile(args[1], "w") as z:
        z.writestr("bugreport-fake.txt", "dumpstate\n"); z.writestr("FS/data/anr/anr_2026-11-17-10-00-00",
            "----- pid 88 at 2026-11-17 10:00:00.000+0000 -----\nCmd line: com.example.app\nSubject: Input dispatching timed out\n")
    say("[100%] bugreport\n"); sys.exit(0)
if args[:1] == ["logcat"]:
    if "-d" in args or "-L" in args:
        if "kernel" in args: fail("Unable to open log device '/dev/kmsg'")
        say("2026-11-17 10:00:00.000  1000  1000 E AndroidRuntime: FATAL EXCEPTION: main\n"
            "2026-11-17 10:00:00.000  1000  1000 E AndroidRuntime: Process: com.example.app, PID: 4242\n"); sys.exit(0)
    say("2026-11-17 10:00:09.000  1  1 I live: hello\n"); time.sleep(30); sys.exit(0)        # live stream: runs until killed
if args[:2] == ["pull", "-a"]:
    src, dest = args[2], args[3]
    if src.startswith(("/data/", "/sys/")) and not SU or not os.path.exists(real(src)):
        fail("adb: error: failed to stat remote object '%s': No such file or directory" % src)
    if os.path.isdir(real(src)): shutil.copytree(real(src), os.path.join(dest, os.path.basename(src.rstrip("/"))), dirs_exist_ok=True)
    else: os.makedirs(os.path.dirname(dest) or ".", exist_ok=True); shutil.copyfile(real(src), dest)
    say("1 file pulled\n"); sys.exit(0)

if args[:1] != ["shell"]: fail("unknown fake command: " + " ".join(args))
cmd = " ".join(a for a in args[1:] if a != "-T")

def listing(paths, pipe_fmt, only_logs, prune_cache=False):
    lines = []
    for pat in paths:
        for base in glob.glob(real(pat.rstrip("/"))):
            for dp, _, fs in os.walk(base):
                for f in sorted(fs):
                    full = os.path.join(dp, f); st = os.stat(full)
                    rel = os.path.relpath(full, base).replace(os.sep, "/")
                    dev = pat.rstrip("/") + ("/" + rel if rel != "." else "")
                    if only_logs and not (re.search(r"\.(log|crash|trace|dmp|stacktrace|xlog|anr|err)(\.\d+)?$", f, re.I) or (f.endswith(".txt") and "/Android/data/" in dev) or "/logs/" in dev or "/log/" in dev): continue
                    if prune_cache and re.search(r"/(code_)?cache/", dev): continue
                    lines.append(f"{st.st_size}|{int(st.st_mtime)}|{int(st.st_atime)}|{int(st.st_ctime)}|{dev}\n" if pipe_fmt else f"{st.st_size} {dev}\n")
    return lines

def find(c):
    parts = shlex.split(c); paths = []
    for p in [x for x in parts[1:] if x != "-H"]:
        if p.startswith("-") or p in ("(", ")", "\\(", "\\)"): break
        paths.append(p)
    return paths, "%Y" in c, "-iname" in c, "-prune" in c

m = re.match(r"^run-as (\S+) (.*)$", cmd)
if m:                                        # debuggable apps only
    if m.group(1) != RUNAS: fail("run-as: package not debuggable: " + m.group(1))
    base = f"/data/data/{m.group(1)}"; inner = m.group(2)
    if inner.startswith("find "):
        paths, pipe, logs, prune = find(inner); paths = [base + p[1:] if p.startswith(".") else p for p in paths]
        say("".join(listing(paths, pipe, logs, prune)).replace(base + "/", "./")); sys.exit(0)
    if inner.startswith("cat "):
        out.write(open(real(base + "/" + shlex.split(inner)[1]), "rb").read()); out.flush(); sys.exit(0)
    fail("run-as: unsupported in fake")
m = re.match(r"^su -c (.*)$", cmd)
if m:
    if not SU: fail("/system/bin/sh: su: inaccessible or not found", 127)
    cmd = shlex.split(cmd)[2] if cmd.startswith("su -c ") and len(shlex.split(cmd)) > 2 else m.group(1)
    if cmd == "id": say("uid=0(root) gid=0(root)\n"); sys.exit(0)

if cmd == "id": say("uid=2000(shell) gid=2000(shell)\n")
elif cmd.startswith("date -u"): say("2026-11-17T10:30:00Z\n")
elif cmd.startswith("getprop"): say("[ro.product.model]: [FakePhone]\n[ro.build.version.release]: [14]\n[ro.build.version.sdk]: [34]\n")
elif cmd.startswith("dumpsys usagestats"): fail("Permission Denial: can't dump usagestats")
elif cmd.startswith("dumpsys dropbox"): say("2026-11-17 10:00:00 system_app_crash (text, 100 bytes)\n  Process: com.example.app\n  Subject: crash\n")
elif cmd.startswith("dumpsys"): say("DUMP OF SERVICE " + cmd + "\nstate=ok\n")
elif cmd.startswith("pm list packages -f"): say("package:/data/app/com.example.app/base.apk=com.example.app uid:10100\n")
elif cmd.startswith("pm list packages"): say("package:com.example.app\n")
elif cmd.startswith("find "):
    paths, pipe, logs, prune = find(cmd); paths = [p for p in paths]
    if "dmesg" in cmd: fail("x")
    say("".join(listing(paths, pipe, logs, prune)))
elif cmd.startswith("cat "):
    p = shlex.split(cmd)[1]
    if p.startswith("/proc/"): say("1\n")
    else: out.write(open(real(p), "rb").read()); out.flush()
elif cmd.startswith(("uptime", "ps", "df")): say("ok\n")
elif cmd.startswith("dmesg"): fail("dmesg: klogctl: Operation not permitted")
else: fail("unknown fake shell command: " + cmd)
