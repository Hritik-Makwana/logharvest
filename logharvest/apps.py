"""Copy per-app folders from shared storage on an Android phone.

Used two ways:
  * automatically by `logharvest android` for the apps it finds crashed/hung (see android.auto_suspects)
  * by `logharvest android-apps` to copy the folders of ALL installed apps (this file's run()).

Without root the adb shell can only read an app's folders on shared storage:
    /sdcard/Android/data/<pkg>   /sdcard/Android/media/<pkg>   /sdcard/Android/obb/<pkg>
The private folder /data/data/<pkg> (databases, shared_prefs, internal files) needs root and is NOT reachable;
that limit is stated in the audit log rather than silently skipped.
"""
import os, re, shlex, subprocess, sys, threading
from pathlib import Path

from . import android as A
from .progress import Progress, say

ROOTS = ("/sdcard/Android/data", "/sdcard/Android/media", "/sdcard/Android/obb")
BATCH = 15          # packages per `find` call, keeps the shell command short


def _find_batch(S, pkgs):
    paths = " ".join(f"{r}/{p}/" for p in pkgs for r in ROOTS)       # pkgs are PKG_RE-validated: safe to inline
    cmd = f"find -H {paths} -type f -exec stat -c '%s %n' {{}} + 2>/dev/null"
    r = subprocess.run(S.base + ["shell", cmd], capture_output=True, timeout=600)
    return r.stdout.decode("utf-8", "replace")


def list_app_files(S, pkgs, include_cache=False, tag="apps"):
    """-> {pkg: [(remote_path, size), ...]}; the raw listing is saved and hashed as evidence."""
    pkgs = [p for p in pkgs if A.PKG_RE.match(p)]
    out, raw = {p: [] for p in pkgs}, []
    lbar = Progress("Listing app folders", len(pkgs), "apps") if len(pkgs) > BATCH else None
    for i in range(0, len(pkgs), BATCH):
        batch = pkgs[i:i + BATCH]
        if lbar: lbar.update(len(batch), 0, batch[0])
        try: text = _find_batch(S, batch)
        except (OSError, subprocess.SubprocessError) as e:
            S.nc("adb:app_list", f"adb://{S.serial}/sdcard/Android", f"listing failed for {len(batch)} apps: {type(e).__name__}: {e}")
            continue
        raw.append(text)
        for line in text.splitlines():
            sz, _, path = line.partition(" ")
            if not (sz.isdigit() and path.startswith("/")): continue
            m = re.match(r"/sdcard/Android/(?:data|media|obb)/([^/]+)/", path)
            if not m or m.group(1) not in out: continue
            if not include_cache and re.search(r"/cache/|/code_cache/", path): continue
            out[m.group(1)].append((path, int(sz)))
    if lbar: lbar.close()
    f = S.ev / "_commands" / f"app_files_{tag}.txt"
    f.write_text("".join(raw))
    S.record(f, "context", "app_file_list", ["find", "-H", "/sdcard/Android/{data,media,obb}/<pkg>/"], "command_output",
             source=f"adb://{S.serial}/sdcard/Android")
    S.counts["ok"] += 1; S.by_cat["context"] += 1
    S.audit(f"APPLIST tag={tag} apps={len(pkgs)} files={sum(len(v) for v in out.values())} include_cache={include_cache}")
    return out


def pull_app(S, pkg, files, per_file_cap, max_files, max_bytes, group="requested", bar=None):
    """Pull one app's files (shared-storage folders) into evidence/<device>/apps/<pkg>/ with caps. Never raises."""
    root = S.ev / "apps" / pkg; n = total = skipped = 0; over_cap = []
    for remote, size in sorted(files):
        src = f"adb://{S.serial}{remote}"
        if bar: bar.update(1, 0, f"{pkg}: {remote.rsplit('/', 1)[-1]}")
        if remote in S.pulled: continue
        if n >= max_files or total + size > max_bytes:
            over_cap.append(remote); continue
        if size > per_file_cap:
            skipped += 1; S.nc("adb:app_folder", src, f"NOT COLLECTED: {size} bytes is over --max-size-mb", ""); continue
        dest = S.safe_dest(root, remote.lstrip("/"))
        if dest is None:
            skipped += 1; S.nc("adb:app_folder", src, "NOT COLLECTED: unsafe path reported by device"); continue
        argv = S.base + ["pull", "-a", remote, str(dest)]
        try:
            dest.parent.mkdir(parents=True, exist_ok=True)
            r = subprocess.run(argv, capture_output=True, timeout=300)
            ok, err = r.returncode == 0 and dest.is_file(), r.stderr.decode("utf-8", "replace").strip()[-300:]
        except (OSError, subprocess.SubprocessError) as e:
            ok, err = False, f"{type(e).__name__}: {e}"
        if not ok:
            skipped += 1; S.nc("adb:app_folder", src, f"pull failed. {err}", " ".join(argv)); continue
        S.record(dest, "application", "app_folder", argv, "pulled_file", remote, app=pkg, app_group=group)
        S.pulled.add(remote); S.counts["ok"] += 1; S.by_cat["application"] += 1
        n += 1; total += size
        if bar: bar.bytes += size
    if over_cap:                      # one aggregated row, not thousands
        skipped += len(over_cap)
        S.nc("adb:app_folder", f"adb://{S.serial}/sdcard/Android/*/{pkg}",
             f"{len(over_cap)} further files not pulled (limit {max_files} files / {max_bytes >> 20} MB per app; "
             "raise --max-app-files / --max-app-mb). Listing is in _commands/app_files_*.txt")
    S.audit(f"APPPULL {pkg} group={group} files={n} bytes={total} skipped={skipped}")
    A.prune_empty(S.ev / "apps")
    return dict(files=n, bytes=total, skipped=skipped)


def shell_uid(S):
    try:
        r = subprocess.run(S.base + ["shell", "id"], capture_output=True, timeout=30)
        m = re.search(r"uid=(\d+)", r.stdout.decode("utf-8", "replace")); return int(m.group(1)) if m else None
    except (OSError, subprocess.SubprocessError): return None


def pull_private(S, pkg, group="requested", timeout=900):
    """ROOT ONLY: pull /data/data/<pkg> (databases, shared_prefs, files). No size cap is possible with `adb pull`
    of a directory, so this is only used for suspect/requested apps or when the operator chose --adb-root."""
    parent = S.ev / "apps" / pkg / "data_data"; parent.mkdir(parents=True, exist_ok=True)
    remote = f"/data/data/{pkg}"; argv = S.base + ["pull", "-a", remote, str(parent)]
    S.audit(f"RUN {' '.join(argv)}")
    try:
        r = subprocess.run(argv, capture_output=True, timeout=timeout); rc, err = r.returncode, r.stderr.decode("utf-8", "replace").strip()[-300:]
    except (OSError, subprocess.SubprocessError) as e: rc, err = -1, f"{type(e).__name__}: {e}"
    root = parent / pkg; n = 0
    files = [x for x in sorted(root.rglob("*")) if x.is_file() and not x.is_symlink()] if root.is_dir() else []
    for f in files:
        S.record(f, "application", "app_private", argv, "pulled_file", f"{remote}/{f.relative_to(root).as_posix()}", app=pkg, app_group=group)
        S.counts["ok"] += 1; S.by_cat["application"] += 1; n += 1
    skipped = 0
    if rc != 0 or not files:
        skipped = 1; S.nc("adb:app_private", f"adb://{S.serial}{remote}", f"exit code {rc}, {len(files)} files. Needs root. {err}", " ".join(argv), app=pkg)
    A.prune_empty(S.ev / "apps")
    S.audit(f"APPPRIVATE {pkg} rc={rc} files={n}")
    return dict(files=n, skipped=skipped)


# ---------------------------------------------------------------- streamed reads: su (rooted phone) and run-as (debuggable apps)
# `adb pull` runs as the shell user and cannot read /data/data. Both `su -c` and `run-as <pkg>` can, but only through a command
# that prints the file, so each file is streamed with `cat` and hashed on the fly (binary-safe: `shell -T`, no pty).
STAT = "-exec stat -c '%s|%Y|%X|%Z|%n' {} +"          # size|mtime|atime|ctime|path (the device's own times)


def wrap_su(cmd): return "su -c " + shlex.quote(cmd)
def wrap_runas(pkg): return lambda cmd: f"run-as {pkg} {cmd}"


def list_via(S, wrap, find_args, timeout=600):
    """find + stat run through `wrap`. -> (rows [(size, mtime, atime, ctime, path)], stderr text)."""
    r = subprocess.run(S.base + ["shell", "-T", wrap(f"find {find_args} -type f {STAT}")], capture_output=True, timeout=timeout)
    rows = []
    for line in r.stdout.decode("utf-8", "replace").splitlines():
        q = line.strip().split("|", 4)
        if len(q) == 5 and all(x.isdigit() for x in q[:4]): rows.append((int(q[0]), int(q[1]), int(q[2]), int(q[3]), q[4]))
    return rows, r.stderr.decode("utf-8", "replace").strip()


def stream_file(S, wrap, remote, dest, timeout=900):
    """cat a device file to `dest`, hashing while writing. -> (sha256, bytes). Raises RuntimeError on failure."""
    import hashlib
    dest.parent.mkdir(parents=True, exist_ok=True)
    h, n = hashlib.sha256(), 0
    p = subprocess.Popen(S.base + ["shell", "-T", wrap("cat " + shlex.quote(remote))], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    timer = threading.Timer(timeout, p.kill); timer.start()
    try:
        with open(dest, "wb") as f:
            while chunk := p.stdout.read(1 << 20): f.write(chunk); h.update(chunk); n += len(chunk)
        err = p.stderr.read().decode("utf-8", "replace").strip(); rc = p.wait(timeout=60)
    except BaseException:
        p.kill(); dest.unlink(missing_ok=True); raise
    finally: timer.cancel()
    if rc != 0:
        dest.unlink(missing_ok=True); raise RuntimeError(err or f"exit code {rc}")
    return h.hexdigest(), n


def pull_streamed(S, wrap, how, rows, dest_root, rel, srcfmt, category, step, per_file_cap, max_files, max_bytes, app=None, group=None, bar=None):
    """Stream every listed file into dest_root/rel(remote) with caps. Never raises. -> dict(files, bytes, skipped)."""
    extra = {"app": app, "app_group": group} if app else {}
    n = total = skipped = 0; over = []
    for size, m, a, c, remote in sorted(rows, key=lambda r: r[4]):
        src = srcfmt(remote)
        if bar: bar.update(1, 0, remote.rsplit("/", 1)[-1])
        if n >= max_files or total + size > max_bytes: over.append(remote); continue
        if size > per_file_cap: skipped += 1; S.nc(f"adb:{step}", src, f"NOT COLLECTED: {size} bytes is over --max-size-mb"); continue
        dest = S.safe_dest(dest_root, rel(remote))
        if dest is None: skipped += 1; S.nc(f"adb:{step}", src, "NOT COLLECTED: unsafe path reported by device"); continue
        try:
            digest, got = stream_file(S, wrap, remote, dest)
            os.utime(dest, (a, m))
            ok = got == size and A._sha256(dest) == digest          # size as stat reported it, and the bytes on disk are the bytes streamed
            S.record(dest, category, step, ["adb", "shell", "-T", f"[{how}] cat"], "pulled_file", source=src,
                     times=dict(modified=A.utc(m), accessed=A.utc(a), changed_or_created=A.utc(c)), via=how, verified=ok, **extra)
            S.counts["ok"] += 1; S.by_cat[category] += 1; n += 1; total += got
            if not ok: S.nc(f"adb:{step}", src, f"read {got} bytes but the device reported {size}: file changed while being read (copy kept, flagged unverified)")
            if bar: bar.bytes += got
        except Exception as e:
            skipped += 1; S.nc(f"adb:{step}", src, f"{how} read failed: {type(e).__name__}: {e}")
    if over:
        skipped += len(over)
        S.nc(f"adb:{step}", srcfmt(""), f"{len(over)} further files not copied (limit {max_files} files / {max_bytes >> 20} MB; "
             "raise --max-app-files / --max-app-mb)", **({"app": app} if app else {}))
    A.prune_empty(dest_root)
    return dict(files=n, bytes=total, skipped=skipped)


def pull_private_su(S, pkg, group, per_file_cap, max_files, max_bytes, include_cache=False):
    """ROOTED phone (su works): copy /data/data/<pkg> by streaming each file."""
    prune = "" if include_cache else f"\\( -path /data/data/{pkg}/cache -o -path /data/data/{pkg}/code_cache \\) -prune -o "
    rows, err = list_via(S, wrap_su, f"/data/data/{pkg} {prune}".rstrip())
    if not rows:
        S.nc("adb:app_private", f"adb://{S.serial}/data/data/{pkg}", f"su listing found no files. {err}", app=pkg); return dict(files=0, bytes=0, skipped=1)
    r = pull_streamed(S, wrap_su, "su", rows, S.ev / "apps" / pkg / "data_data", lambda p: p[len("/data/data/"):],
                      lambda p: f"adb://{S.serial}/data/data/{pkg}" + (p[len("/data/data/" + pkg):] if p else ""), "application", "app_private",
                      per_file_cap, max_files, max_bytes, app=pkg, group=group)
    S.audit(f"APPPRIVATE(su) {pkg} files={r['files']} bytes={r['bytes']} skipped={r['skipped']}")
    return r


def pull_runas(S, pkg, group, per_file_cap, max_files, max_bytes, include_cache=False):
    """STOCK phone: only apps built as *debuggable* allow `run-as`. Returns None when this app does not allow it."""
    prune = "" if include_cache else "\\( -path ./cache -o -path ./code_cache \\) -prune -o "
    try: rows, _err = list_via(S, wrap_runas(pkg), f". {prune}".rstrip(), timeout=300)
    except (OSError, subprocess.SubprocessError): return None
    if not rows: return None
    rows = [(a, b, c, d, e[2:] if e.startswith("./") else e) for a, b, c, d, e in rows]
    wrap = wrap_runas(pkg)
    r = pull_streamed(S, wrap, "run-as", rows, S.ev / "apps" / pkg / "run_as", lambda p: p,
                      lambda p: f"adb://{S.serial}/run-as/{pkg}" + (f"/{p}" if p else ""), "application", "app_runas",
                      per_file_cap, max_files, max_bytes, app=pkg, group=group)
    S.audit(f"APPPRIVATE(run-as) {pkg} files={r['files']} bytes={r['bytes']} skipped={r['skipped']}")
    return r


def installed_packages(S, include_system=False):
    p = subprocess.run(S.base + ["shell", "pm", "list", "packages"] + ([] if include_system else ["-3"]),
                       capture_output=True, timeout=120)
    return sorted({l[8:].strip() for l in p.stdout.decode("utf-8", "replace").splitlines()
                   if l.startswith("package:") and A.PKG_RE.match(l[8:].strip())})


# ------------------------------------------------------------------ `logharvest android-apps`
def add_args(ap):
    ap.add_argument("--case", type=Path, help="case folder (created if missing)")
    ap.add_argument("--serial", help="required when more than one device is attached")
    ap.add_argument("--package", action="append", default=[], metavar="PKG", help="only these apps (repeatable); default: all installed apps")
    ap.add_argument("--include-system", action="store_true", help="also system/preinstalled apps (default: user-installed only)")
    ap.add_argument("--include-cache", action="store_true", help="also copy cache folders (skipped by default)")
    ap.add_argument("--max-app-files", type=int, default=300, help="max files per app (default 300)")
    ap.add_argument("--max-app-mb", type=int, default=500, help="max MB per app (default 500)")
    ap.add_argument("--max-size-mb", type=int, default=100, help="skip single files larger than this (default 100)")
    ap.add_argument("--yes", action="store_true", help="do not ask for confirmation after showing the plan")
    ap.add_argument("--adb-root", action="store_true", help="run `adb root` and also pull each app's private /data/data folder (userdebug/emulator builds; no size cap)")
    ap.add_argument("--authority", default="", help="warrant / consent reference, recorded in audit.log")


def run(a):
    bad = [p for p in a.package if not A.PKG_RE.match(p)]
    if bad: print(f"ERROR: not a valid package name: {bad[0]!r}"); return 2
    d, rc = A.pick_device(a)
    if d is None: return rc
    a.case.mkdir(parents=True, exist_ok=True)
    sess = A.Session(a.case, d) if hasattr(A, "Session") else None
    if sess is None: print("ERROR: android.Session missing"); return 1
    with sess as S:
        S.audit(f"START android-apps serial={S.serial} user={A.getpass.getuser()} authority={getattr(a, 'authority', '')!r}")
        S.audit("NOTE only shared-storage app folders are reachable without root; /data/data/<pkg> is not collected.")
        if getattr(a, "adb_root", False):
            S.audit("ROOT opt-in: running `adb root`")
            try:
                r = subprocess.run(S.base + ["root"], capture_output=True, text=True, timeout=30)
                S.audit(f"ROOT rc={r.returncode} out={(r.stdout + r.stderr).strip()!r}")
                subprocess.run(S.base + ["wait-for-device"], timeout=60)
            except (OSError, subprocess.SubprocessError) as e: S.audit(f"ROOT failed: {e}")
        uid = shell_uid(S); S.audit(f"SHELL uid={uid}")
        pkgs = a.package or installed_packages(S, a.include_system)
        if not pkgs: print("No installed apps found (or `pm list packages` was denied)."); return 1
        print(f"{len(pkgs)} apps. Listing their shared-storage folders ...")
        listing = list_app_files(S, pkgs, a.include_cache, tag="all")
        cap = a.max_app_mb << 20
        plan = {p: v for p, v in listing.items() if v}
        est = sum(min(sum(s for _, s in v), cap) for v in plan.values())
        print(f"Plan: {len(plan)} of {len(pkgs)} apps have readable files; about {sum(len(v) for v in plan.values())} files, "
              f"up to {est / 1048576:.0f} MB (caps: {a.max_app_files} files / {a.max_app_mb} MB per app).")
        if not plan and not (getattr(a, "adb_root", False) and uid == 0): print("Nothing to copy."); return 0
        if not a.yes:
            if not sys.stdin.isatty(): print("Not interactive: re-run with --yes to proceed."); S.audit("ABORT android-apps: no confirmation"); return 2
            if input("Copy these? [y/N] ").strip().lower() not in ("y", "yes"): print("Cancelled."); S.audit("CANCELLED by operator"); return 2
        bar = Progress("Copying apps", sum(len(v) for v in plan.values()), "files")
        for i, (p, v) in enumerate(sorted(plan.items()), 1):
            r = pull_app(S, p, v, a.max_size_mb << 20, a.max_app_files, cap, group="all", bar=bar)
            say(f"  [{i}/{len(plan)}] {p}: {r['files']} files, {r['bytes'] / 1048576:.1f} MB"
                + (f", {r['skipped']} not copied" if r["skipped"] else ""))
        bar.close()
        if getattr(a, "adb_root", False):
            if uid == 0:
                pbar = Progress("Private app data", len(pkgs), "apps")
                for p in sorted(pkgs):
                    pbar.set_item(p); r = pull_private(S, p, "all"); pbar.update(1, 0, p)
                    say(f"  {p}: {r['files']} private files, {r['skipped']} failed")
                pbar.close()
            else: print(f"--adb-root given but the shell is uid {uid}: private data not collected (device does not allow adb root).")
        S.audit(f"END android-apps ok={S.counts['ok']} not_collected={S.counts['nc']}")
        print(f"Done: {S.counts['ok']} files recorded, {S.counts['nc']} not collected. See manifest.jsonl.")
    return 0
