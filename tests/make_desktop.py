"""Build fixture source trees for linux / windows / macos under argv[1]."""
import json, os, sys
from datetime import datetime, timezone
from pathlib import Path

base = Path(sys.argv[1]); base.mkdir(parents=True, exist_ok=True)
def w(p, text="x\n", enc="utf-8", bom=False):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes((b"\xff\xfe" if bom else b"") + text.encode(enc))
def ts(y, mo, d, h, mi): return datetime(y, mo, d, h, mi, tzinfo=timezone.utc).timestamp()

# ---------------- linux
L = base / "linux"
w(L / "etc/os-release", "ID=ubuntu\n")
w(L / "var/log/syslog",
  "2026-11-17T10:00:01.123456+05:30 host kernel: [ 123.4] foo[4321]: segfault at 0 ip 00007f in libfoo.so[7f+1000]\n"
  "Nov 17 10:05:00 host kernel: Out of memory: Killed process 999 (memhog) total-vm:1024kB\n"
  "Nov 17 10:06:00 host systemd[1]: bar.service: Main process exited, code=dumped, status=11/SEGV\n"
  "Nov 17 10:07:00 host kernel: INFO: task hung:55 blocked for more than 120 seconds.\n"
  "Nov 17 10:08:00 host unrelated: all good\n"
  "2026-05-01T10:00:00+00:00 host kernel: old[1]: segfault at 0 ip 0 in x\n")
os.utime(L / "var/log/syslog", (ts(2026, 11, 17, 12, 0),) * 2)
w(L / "var/crash/_usr_bin_foo.1000.crash",
  "ProblemType: Crash\nDate: Tue Nov 17 04:30:05 2026\nExecutablePath: /usr/bin/foo\nPackage: foo 1.0\nSignal: 11\nCoreDump: base64\n junk\n")
w(L / f"var/lib/systemd/coredump/core.baz.1000.{'a' * 32}.777.{int(ts(2026, 11, 17, 5, 0)) * 1000000}.zst", "core")
w(L / "home/alice/.config/foo/settings.ini", "[a]\n")
w(L / "home/alice/.config/foo/Cache/blob", "cache" * 10)
w(L / "home/alice/.local/share/foo/logs/foo.log", "log\n")
w(L / "home/alice/.cache/foo/big.bin", "c" * 100)
w(L / "home/alice/.config/other/o.conf", "o\n")
w(L / "home/alice/.foo/legacy.cfg", "legacy\n")
w(L / "var/log/bar/bar.log", "bar log\n")
w(L / "home/alice/.config/memhog/m.conf", "m\n")
for i in range(5): w(L / f"home/alice/.config/baz/f{i}.txt", f"baz{i}\n")

# ---------------- windows
W = base / "windows"
w(W / "Windows/System32/winevt/Logs/Application.evtx", "evtx")
wer = ("Version=1\nEventType=APPCRASH\nEventTime={ft}\nFriendlyEventName=Stopped working\nAppName=App\n"
       "AppPath=C:\\Program Files\\Vendor\\App\\app.exe\nNsAppName=app.exe\n")
ft = int((ts(2026, 11, 17, 6, 0) + 11644473600) * 10_000_000)
w(W / "ProgramData/Microsoft/Windows/WER/ReportArchive/AppCrash_app.exe_1/Report.wer", wer.format(ft=ft), enc="utf-16-le", bom=True)
w(W / "ProgramData/Microsoft/Windows/WER/ReportArchive/AppHang_slow.exe_1/Report.wer",
  f"EventType=AppHang\nEventTime={ft + 10**9}\nNsAppName=slow.exe\nAppPath=D:\\tools\\Slow\\slow.exe\n", enc="utf-16-le", bom=True)
w(W / "Users/bob/AppData/Roaming/App/config.json", "{}")
w(W / "Users/bob/AppData/Local/App/logs/a.log", "a\n")
w(W / "Users/bob/AppData/Local/App/Cache/c.bin", "cache")
w(W / "Users/bob/AppData/Local/Slow/s.log", "s\n")
w(W / "Users/bob/AppData/Local/Microsoft/Edge/x", "skip")
w(W / "Users/bob/AppData/Local/Temp/t.tmp", "skip")
w(W / "ProgramData/Vendor/v.cfg", "vendor\n")
w(W / "ProgramData/App/p.cfg", "pd\n")
(base / "events_application.xml").write_text(
    '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Application Error"/><EventID>1000</EventID>'
    '<TimeCreated SystemTime="2026-11-17T07:00:00.123456700Z"/></System><EventData><Data>chrome.exe</Data><Data>1</Data><Data>t</Data><Data>ntdll.dll</Data>'
    '<Data>1</Data><Data>t</Data><Data>c0000005</Data><Data>0</Data><Data>1a</Data><Data>t</Data><Data>C:\\Program Files\\Google\\Chrome\\chrome.exe</Data></EventData></Event>\n'
    '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Kernel-Power"/><EventID>41</EventID>'
    '<TimeCreated SystemTime="2026-11-17T08:00:00.0Z"/></System><EventData/></Event>\n')

# ---------------- macOS
M = base / "macos"
w(M / "System/Library/CoreServices/SystemVersion.plist", "<plist/>")
(M / "Users").mkdir(parents=True, exist_ok=True)
dr = M / "Users/carol/Library/Logs/DiagnosticReports"
hd = {"app_name": "Foo", "timestamp": "2026-11-17 10:00:00.00 +0530", "bundleID": "com.vendor.Foo", "bug_type": "309"}
bd = {"procName": "Foo", "pid": 321, "captureTime": "2026-11-17 10:00:00.1234 +0530", "procPath": "/Applications/Foo.app/Contents/MacOS/Foo",
      "bundleInfo": {"CFBundleIdentifier": "com.vendor.Foo"}, "exception": {"type": "EXC_BAD_ACCESS", "signal": "SIGSEGV"}}
w(dr / "Foo-2026-11-17-100000.ips", json.dumps(hd) + "\n" + json.dumps(bd))
w(dr / "Old_2026-11-17-110000.crash", "Process:               Old [55]\nIdentifier:            com.vendor.Old\nDate/Time:             2026-11-17 11:00:00.123 +0530\nException Type:        EXC_CRASH (SIGABRT)\n")
w(dr / "Stuck_2026-11-17-120000.hang", "Process:               Stuck [66]\nDate/Time:             2026-11-17 12:00:00.1 +0530\nEvent: hang\n")
w(M / "Users/carol/Library/Application Support/Foo/data.db", "db")
w(M / "Users/carol/Library/Application Support/Foo/Cache/c", "c")
w(M / "Users/carol/Library/Containers/com.vendor.Foo/Data/a.txt", "container")
w(M / "Users/carol/Library/Preferences/com.vendor.Foo.plist", "<plist/>")
w(M / "Users/carol/Library/Preferences/com.other.plist", "<plist/>")
w(M / "Users/carol/Library/Logs/Foo/foo.log", "l")
w(M / "Users/carol/Library/Application Support/Unrelated/u", "u")

# install folders
w(L / "opt/Foo/bin/foo", "bin")
w(W / "Program Files/Vendor/App/app.exe", "exe")
w(M / "Applications/Foo.app/Contents/Info.plist", "plist")
print("fixtures ok")
