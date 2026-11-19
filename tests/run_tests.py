"""End-to-end checks with fake devices. Run from the project root (the folder that contains logharvest/):

    python tests/run_tests.py

tests/bin/adb and tests/bin/pymobiledevice3 are small stand-ins for the real tools, so no phone is needed.
`collect` is run with the file-collection step stubbed out, so only the suspect/app-folder additions are checked.
Requires Python 3.12+. Exit code 0 = everything passed.
"""
import json, os, re, shutil, subprocess, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]; HERE = Path(__file__).resolve().parent
WORK = Path(tempfile.mkdtemp(prefix="lh_tests_")); FX = WORK / "fx"
ENV = dict(os.environ, PATH=str(HERE / "bin") + os.pathsep + os.environ["PATH"], STUB_STATE=str(WORK))
fails = []

def check(cond, msg):
    print(("  ok   " if cond else "  FAIL ") + msg)
    if not cond: fails.append(msg)

def cli(args, extra_env=None, stdin=subprocess.DEVNULL):
    code = ("import logharvest.cli as c\n"
            "c.collect_tree = lambda *a, **k: dict(ok=0, errors=0, unreadable=0, by_category={})\n"
            "c.main()")
    r = subprocess.run([sys.executable, "-c", code] + args, cwd=ROOT, env=dict(ENV, **(extra_env or {})), capture_output=True, text=True, stdin=stdin)
    return r.returncode, r.stdout + r.stderr

def rows(case):
    f = case / "manifest.jsonl"
    return [json.loads(l) for l in open(f) if l.strip()] if f.is_file() else []
def apps(case, rule=None): return sorted(r["dest"].split("/apps/")[1] for r in rows(case) if "/apps/" in r.get("dest", "") and (rule is None or rule in r["rule"]))
def intact(case):
    import hashlib
    bad = [r["dest"] for r in rows(case) if r.get("dest") and r.get("sha256") and hashlib.sha256((case / r["dest"]).read_bytes()).hexdigest() != r["sha256"]]
    return not bad

subprocess.run([sys.executable, str(HERE / "make_desktop.py"), str(FX)], check=True, capture_output=True)

print("Android: automatic suspects")
c = WORK / "a1"; rc, out = cli(["android", "--case", str(c)])
check(rc == 0 and "Suspect apps (crashed or hung): com.other.app, com.example.app" in out, "suspects found and ranked")
check(re.search(r"Collecting logs: done, \d+ steps", out) and "App folders: done" in out, "progress lines printed when output is not a terminal")
check("Further suspect apps found in tombstones/ANR traces: com.tomb.app" in out, "second scan adds the tombstone app")
check(not any("com.gone.app" in a or "com.old.app" in a for a in apps(c)), "uninstalled and too-old apps are not collected")
check(any("com.example.app/sdcard/Android/data/com.example.app/files/app.log" in a for a in apps(c)), "suspect folder copied")
check(not list(WORK.glob("evil*")) and not any("evil" in a for a in apps(c)), "hostile device paths rejected")
check(len(list((c / "analysis").glob("suspects-*"))) == 2 and intact(c), "report written once; every hash still matches")
c = WORK / "a2"; rc, out = cli(["android", "--case", str(c), "--no-suspects", "--no-bugreport", "--no-progress"])
check(": done," not in out and ": started" not in out, "--no-progress silences the bars")
check("Suspect apps" not in out and not apps(c), "--no-suspects")
c = WORK / "a3"; rc, out = cli(["android", "--case", str(c), "--no-bugreport"], {"STUB_ROOT": "1"})
check(any("data_data" in a for a in apps(c, "app_private")), "root: private /data/data pulled for suspects")
c = WORK / "a4"; cli(["android", "--case", str(c), "--no-bugreport"])
check("private app data (/data/data) not collected" in (c / "audit.log").read_text(), "non-root: limit recorded in audit.log")

print("Android: all apps")
c = WORK / "aa"; rc, out = cli(["android-apps", "--case", str(c)]); check(rc == 2 and "re-run with --yes" in out, "non-interactive without --yes aborts")
rc, out = cli(["android-apps", "--case", str(c), "--yes"]); check(rc == 0 and len(apps(c, "app_folder")) >= 3, "copies every app's shared-storage folder")
rc, out = cli(["android-apps", "--case", str(WORK / "ab"), "--yes", "--package", "a.b;rm"]); check(rc == 2, "bad package name rejected")

for name, osn in (("linux", "linux"), ("windows", "windows"), ("macos", "macos")):
    print(f"{name}: collect -> suspects -> folders")
    c = WORK / f"d_{name}"; rc, out = cli(["collect", "--case", str(c), "--source", str(FX / name)])
    check("Suspect programs" in out, "suspects reported"); check(len(apps(c, "app_folder")) >= 3, "program folders copied"); check(intact(c), "hashes intact")
    check((c / "analysis" / f"suspects-{name}-{name}.json").is_file(), "analysis file written")
    rc, out = cli(["suspects", "--case", str(c)]); check("SUSPECT PROGRAMS" in out, "`suspects` re-runs on the case")
    c2 = WORK / f"di_{name}"; cli(["collect", "--case", str(c2), "--source", str(FX / name), "--include-install"])
    check(any(k in a for a in apps(c2) for k in ("opt/Foo", "Program Files", "Applications")), "--include-install copies install folder")
    c3 = WORK / f"dn_{name}"; cli(["collect", "--case", str(c3), "--source", str(FX / name), "--no-suspects"]); check(not apps(c3), "--no-suspects")
    c4 = WORK / f"dall_{name}"; rc, out = cli(["desktop-apps", "--case", str(c4), "--source", str(FX / name), "--yes"]); check(rc == 0 and apps(c4), "desktop-apps copies all programs' folders")

print("windows: event XML")
sys.path.insert(0, str(ROOT))
from logharvest import procsuspects as P
ev, ok = P.parse_events_xml(WORK / "fx" / "events_application.xml", "x"); check(ok and {e["pkg"] for e in ev} == {"chrome.exe", "(system)"}, "Application Error 1000 and Kernel-Power 41 parsed")

print("iOS")
c = WORK / "i1"; rc, out = cli(["ios", "--case", str(c), "--backup"])
check("Suspect apps: BarExec (com.vendor.Bar), Foo (com.vendor.Foo)" in out, "crash + jetsam reports name the suspects")
check(len(apps(c, "backup_apps")) == 3 and intact(c), "unencrypted backup: app data exported, hashes intact")
check(any("escape" in r.get("source", "") and r["category"] == "not_collected" for r in rows(c)), "path traversal in backup manifest rejected")
c = WORK / "i2"; cli(["ios", "--case", str(c), "--backup"], {"STUB_ENCRYPTED": "1"})
check(any("cannot be read" in r.get("error", "") for r in rows(c)), "encrypted backup reported, not silently skipped")
c = WORK / "i3"; rc, out = cli(["ios-apps", "--case", str(c), "--yes"]); check("com.vendor.Files: 1 files via app service" in out, "ios-apps: file-sharing app pulled")
rc, out = cli(["suspects", "--case", str(WORK / "i1")]); check("BarExec" in out, "`suspects` on an iOS case")


print("Disk images (needs: pip install \"dissect.target[full]\"; mkfs.ext4; optional qemu-img, root + ntfs-3g)")
try: import dissect.target  # noqa
except ImportError: print("  SKIP dissect.target not installed")
else:
    import shutil as _sh
    IMG = WORK / "img"; IMG.mkdir()
    built = {}
    if _sh.which("mkfs.ext4"):
        r = subprocess.run([sys.executable, str(HERE / "mkimg.py"), "ext4", str(FX / "linux"), str(IMG / "linux.raw")], capture_output=True)
        if r.returncode == 0:
            built["linux.raw"] = "linux"
            if _sh.which("qemu-img"):
                for fmt in ("qcow2", "vmdk", "vhdx"):
                    if subprocess.run(["qemu-img", "convert", "-f", "raw", "-O", fmt, str(IMG / "linux.raw"), str(IMG / f"linux.{fmt}")], capture_output=True).returncode == 0:
                        built[f"linux.{fmt}"] = "linux"
    if _sh.which("mkntfs") and _sh.which("ntfs-3g") and os.geteuid() == 0:
        r = subprocess.run([sys.executable, str(HERE / "mkimg.py"), "ntfs", str(FX / "windows"), str(IMG / "win.raw")], capture_output=True)
        if r.returncode == 0:
            built["win.raw"] = "windows"
            if _sh.which("qemu-img") and subprocess.run(["qemu-img", "convert", "-f", "raw", "-O", "qcow2", str(IMG / "win.raw"), str(IMG / "win.qcow2")], capture_output=True).returncode == 0:
                built["win.qcow2"] = "windows"
    if not built: print("  SKIP could not build any test image on this machine")
    for name, osn in built.items():
        rc, out = cli(["image", str(IMG / name), "--list", "--hash", "none"]); check(rc == 0 and osn in out, f"{name}: --list finds the {osn} system")
        c = WORK / f"im_{name}"; rc, out = cli(["image", str(IMG / name), "--case", str(c)])
        check(rc == 0 and "Image hash verified unchanged" in out, f"{name}: collected, image hash unchanged")
        check(len(apps(c, "app_folder")) >= 3 and "Suspect programs" in out, f"{name}: suspects found and their folders copied from inside the image")
        check(intact(c) and all(r.get("source", "").startswith(("image://", "analysis://")) for r in rows(c) if r["category"] != "not_collected"), f"{name}: hashes intact, sources say image://")
        check((c / "analysis" / f"image-{Path(name).stem}.json").is_file(), f"{name}: image record written")
        c2 = WORK / f"imd_{name}"; rc, out = cli(["desktop-apps", "--case", str(c2), "--image", str(IMG / name), "--yes"]); check(rc == 0 and apps(c2), f"{name}: desktop-apps --image")
    (IMG / "junk.img").write_bytes(os.urandom(100000))
    rc, out = cli(["image", str(IMG / "junk.img"), "--case", str(WORK / "imj")]); check(rc == 1 and "No Linux, Windows or macOS system" in out, "non-image file reported, not crashed")

print("\n== timeline / explore / report ==")
import urllib.request, threading
c = WORK / "a1"
rc, out = cli(["timeline", "--case", str(c), "--kind", "anr"]); check(rc == 0 and "com.other.app" in out and "native_crash" not in out, "timeline filters by kind")
tl = [json.loads(l) for l in open(c / "analysis" / "derived" / "timeline.jsonl")]
check(tl == sorted(tl, key=lambda e: (e["t"] is None, e["t"] or "")) and {"crash", "native_crash", "anr", "lmk_kill"} <= {e["kind"] for e in tl}, "timeline sorted, has every suspect kind")
check("DERIVED timeline" in open(c / "audit.log").read(), "timeline hash recorded in audit.log")
n0 = len(rows(c)); rc, out = cli(["report", "--case", str(c), "--json", "--no-progress"])
html_ = (c / "report.html").read_text()
check(rc == 0 and "com.tomb.app" in html_ and "0 differ, 0 missing" in html_ and "Chain of custody" in html_ and len(rows(c)) == n0, "report written, integrity re-check clean, manifest untouched")
vic = next(r for r in rows(c) if r.get("dest", "").startswith("evidence") and r["dest"].endswith("logcat.txt"))
(c / vic["dest"]).write_bytes((c / vic["dest"]).read_bytes() + b"tamper\n")
rc, out = cli(["report", "--case", str(c), "--out", str(WORK / "r2.html"), "--no-progress"]); check("1 differ" in (WORK / "r2.html").read_text(), "report detects a modified evidence file")
(c / vic["dest"]).write_bytes((c / vic["dest"]).read_bytes()[:-7])
from logharvest import explore as X
cs = X.Case(c); srv = X.ThreadingHTTPServer(("127.0.0.1", 0), X.make_handler(cs)); port = srv.server_address[1]
threading.Thread(target=srv.serve_forever, daemon=True).start()
get = lambda u: json.load(urllib.request.urlopen(f"http://127.0.0.1:{port}{u}"))
r = get("/api/search?q=fatal+exception&ctx=1"); check(r["hits"] and r["hits"][0]["after"], "search finds text with context")
check("error" in get("/api/search?q=(&regex=1"), "bad regex reported, not crashed")
check("error" in get("/api/file?path=../../../etc/passwd"), "file viewer refuses paths outside the case")
check(get("/api/timeline?kind=crash")["total"] >= 2, "timeline API filters")
srv.shutdown()

shutil.rmtree(WORK, ignore_errors=True)
print("\nALL PASSED" if not fails else f"\n{len(fails)} FAILED:\n  " + "\n  ".join(fails))
sys.exit(1 if fails else 0)
