"""Fake `adb` for CI: run as `python fake_adb.py -s SERIAL shell -T CMD` (any OS).
The fake device's shared storage lives under $FAKE_ROOT. Stock device (uid shell)."""
import glob, os, shlex, sys, time

out = sys.stdout.buffer
def say(text): out.write(text.encode()); out.flush()
def fail(msg, rc=1): sys.stderr.write(msg + "\n"); sys.exit(rc)

args = sys.argv[1:]
if args[:1] == ["devices"]:
    say("List of devices attached\nFAKE123\tdevice\n"); sys.exit(0)
if args[:1] == ["-s"]:
    args = args[2:]
if args[:1] == ["bugreport"]:
    open(args[1], "wb").write(b"PK\x03\x04fake-bugreport"); say("done\n"); sys.exit(0)
if args[:1] == ["root"]:
    fail("adbd cannot run as root in production builds")
if args[:1] == ["logcat"]:                       # live stream: runs until killed
    say("11-17 10:00:00.000 1 1 I live: hello\n"); time.sleep(30); sys.exit(0)
if args[:1] == ["wait-for-device"]:
    sys.exit(0)

cmd = args[-1]
root = os.environ["FAKE_ROOT"]
if cmd == "id": say("uid=2000(shell) gid=2000(shell)\n")
elif cmd.startswith("su "): fail("/system/bin/sh: su: inaccessible or not found", 127)
elif cmd.startswith("getprop"): say("[ro.product.model]: [FakePhone]\n[ro.build.version.release]: [14]\n")
elif cmd.startswith("logcat"):
    if "kernel" in cmd: fail("Unable to open log device '/dev/kmsg'")
    say("2026-11-17 10:00:00.000 1 1 I tag: line\n")
elif cmd.startswith("dumpsys usagestats"): fail("Permission Denial: can't dump usagestats")
elif cmd.startswith("dumpsys"): say("DUMP OF SERVICE " + cmd + "\nstate=ok\n")
elif cmd.startswith("pm list packages -3") and "-f" not in cmd: say("package:com.example.app\n")
elif cmd.startswith("pm list packages"): say("package:/data/app/com.example.app/base.apk=com.example.app uid:10100\n")
elif cmd.startswith("run-as"): fail("run-as: package not debuggable", 1)
elif cmd.startswith("find "):
    parts = shlex.split(cmd)
    paths = []
    for p in parts[1:]:
        if p.startswith("-") or p in ("(", ")", "\\(", "\\)"): break
        paths.append(p)
    for pat in paths:
        for base in glob.glob(root + pat):
            for dp, _, fs in os.walk(base):
                for f in fs:
                    full = os.path.join(dp, f); st = os.stat(full)
                    rel = "/" + os.path.relpath(full, root).replace(os.sep, "/")
                    say(f"{st.st_size}|{int(st.st_mtime)}|{int(st.st_atime)}|{int(st.st_ctime)}|{rel}\n")
elif cmd.startswith("cat "):
    path = shlex.split(cmd)[1]
    out.write(open(root + path, "rb").read()); out.flush()
else: fail("unknown fake command: " + cmd)
