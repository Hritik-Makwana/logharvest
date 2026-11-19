"""iPhone/iPad: suspect apps from crash reports, and per-app data.

iOS is much more closed than the other systems, so be clear about what is and is not possible:

  Suspects   crash reports pulled from the phone (.ips) name the crashed app and bundle id, and JetsamEvent
             reports name apps killed for memory. This works on any phone.
  App data   there is no filesystem access. Two routes exist, and each has limits:
             1. `pymobiledevice3 apps pull` (house_arrest): only apps that expose their Documents folder
                (UIFileSharingEnabled) or development-signed apps answer. Most store apps refuse; every refusal is
                recorded as a not_collected row with the tool's message. The command name/arguments are in APP_PULL
                below and are unverified against your pymobiledevice3 version.
             2. A full backup (`logharvest ios --backup`, or `ios-apps --backup`): the backup contains each app's
                data under `AppDomain-<bundle id>`. If the backup is UNENCRYPTED, those files are exported per app
                (derived copies, parent_sha256 = the backup blob's hash). An ENCRYPTED backup cannot be read here
                and is reported as such.
"""
import json, re, sqlite3, subprocess, sys
from datetime import timedelta
from pathlib import Path

from . import procsuspects as P
from . import desktop as D
from .progress import Progress, say

APP_LIST = ["apps", "list"]
APP_PULL = ["apps", "pull", "{bundle}", "/", "{out}"]          # unverified: check `pymobiledevice3 apps --help`
BUNDLE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


def parse_apps_list(text):
    """-> {bundle id: {name, exe, kind}}. Accepts a dict keyed by bundle id or a list of dicts."""
    try: data = json.loads(text)
    except ValueError: return {}
    items = data.items() if isinstance(data, dict) else ((d.get("CFBundleIdentifier"), d) for d in data if isinstance(d, dict))
    out = {}
    for b, d in items:
        if not b or not isinstance(d, dict) or not BUNDLE_RE.match(b): continue
        out[b] = dict(name=d.get("CFBundleDisplayName") or d.get("CFBundleName") or b, exe=d.get("CFBundleExecutable"),
                      kind=d.get("ApplicationType") or "")
    return out


def resolve_bundle(name, bundle, apps):
    if bundle and bundle in apps: return bundle
    if bundle and BUNDLE_RE.match(bundle): return bundle
    n = D.norm(name)
    for b, d in apps.items():
        if n and n in (D.norm(d["name"]), D.norm(d["exe"] or "")): return b
    return None


def scan_crashes(ev, days):
    files = sorted(p for p in (ev / "crash_reports").rglob("*") if p.is_file() and p.suffix.lower() in (".ips", ".crash", ".panic", ".synced")) \
        if (ev / "crash_reports").is_dir() else []
    events = P.scan_reports(files)
    stamped = [e["t"] for e in events if e["t"]]
    since = max(stamped) - timedelta(days=days) if days and stamped else None
    return P.build(events, set(), len(files), since)


def _safe_rel(domain_dir, rel):
    parts = [x for x in rel.replace("\\", "/").split("/") if x not in ("", ".")]
    if not parts or ".." in parts: return None
    dest = domain_dir.joinpath(*parts)
    return dest if domain_dir.resolve() in dest.resolve().parents else None


def find_backup(ev):
    b = ev / "backup"
    if not b.is_dir(): return None
    mdb = next(iter(sorted(b.rglob("Manifest.db"))), None)
    return mdb.parent if mdb else None


def export_backup(rec, backup_dir, bundles, per_file_cap, max_files, max_bytes, group, udid):
    """Copy each bundle's AppDomain files out of an unencrypted iTunes-style backup. -> {bundle: stats} or None."""
    try:
        db = sqlite3.connect(f"file:{backup_dir / 'Manifest.db'}?mode=ro", uri=True)
        db.execute("select count(*) from Files").fetchone()
    except sqlite3.DatabaseError as e:
        rec.nc("ios:backup_apps", f"ios-backup://{udid}/Manifest.db", f"backup cannot be read ({e}); it is probably encrypted, so app data "
               "cannot be exported. Take an unencrypted backup or decrypt it with a tool that has the password.")
        return None
    res = {}
    bar = Progress("Exporting app data from backup", None, "files")
    for b in bundles:
        n = total = skipped = over = 0
        bar.set_item(b)
        rows = db.execute("select fileID, domain, relativePath from Files where flags = 1 and (domain = ? or domain like ? or domain like ?)",
                          (f"AppDomain-{b}", f"AppDomainGroup-%{b}%", f"AppDomainPlugin-{b}%")).fetchall()
        bar.set_total((bar.total or 0) + len(rows))
        for fid, domain, rel in rows:
            bar.update(1, 0, f"{b}: {rel.rsplit('/', 1)[-1]}")
            blob = backup_dir / fid[:2] / fid
            if not blob.is_file(): blob = backup_dir / fid
            src_label = f"ios-backup://{udid}/{domain}/{rel}"
            if not blob.is_file(): rec.nc("ios:backup_apps", src_label, "file listed in Manifest.db but its blob is missing", app=b); skipped += 1; continue
            dest = _safe_rel(rec.ev / "apps" / b / domain, rel)
            if dest is None: rec.nc("ios:backup_apps", src_label, "NOT COLLECTED: unsafe path in manifest", app=b); skipped += 1; continue
            size = blob.stat().st_size
            if n >= max_files or total + size > max_bytes: over += 1; continue
            got = rec.copy_to(blob, dest, "ios:backup_apps", src_label, per_file_cap, app=b, app_group=group, derived=True,
                              parent_sha256=D._sha(blob), timestamps_note="modified = backup blob mtime, not the file's original iOS time")
            if got is None: skipped += 1
            else: n += 1; total += got; bar.bytes += got
        if over:
            skipped += over
            rec.nc("ios:backup_apps", f"ios-backup://{udid}/AppDomain-{b}", f"{over} further files not copied (limits {max_files} files / {max_bytes >> 20} MB per app)", app=b)
        rec.audit(f"APPCOPY(backup) {b} group={group} files={n} bytes={total} skipped={skipped} manifest_rows={len(rows)}")
        res[b] = dict(files=n, bytes=total, skipped=skipped, rows=len(rows))
    bar.close()
    db.close()
    return res


def pull_via_service(rec, pmd, extra, bundle, udid, timeout=600):
    out = rec.ev / "apps" / bundle / "house_arrest"; out.mkdir(parents=True, exist_ok=True)
    argv = pmd + [x.format(bundle=bundle, out=out) for x in APP_PULL] + extra
    rec.audit(f"RUN {' '.join(argv)}")
    try:
        r = subprocess.run(argv, capture_output=True, timeout=timeout); rc, err = r.returncode, r.stderr.decode("utf-8", "replace").strip()[-400:]
    except (OSError, subprocess.SubprocessError) as e:
        rc, err = -1, f"{type(e).__name__}: {e}"
    files = [p for p in sorted(out.rglob("*")) if p.is_file() and not p.is_symlink()]
    for p in files: rec.register(p, "application", "ios:app_pull", f"ios://{udid}/apps/{bundle}/{p.relative_to(out).as_posix()}", app=bundle, command=" ".join(argv))
    if not files:
        try: out.rmdir(); out.parent.rmdir()
        except OSError: pass
        rec.nc("ios:app_pull", f"ios://{udid}/apps/{bundle}", f"no files returned (exit code {rc}). Most apps do not allow this without file sharing or a "
               f"development signature. {err}", command=" ".join(argv), app=bundle)
    rec.audit(f"APPPULL {bundle} rc={rc} files={len(files)}")
    return len(files)


def auto(case, did, udid, ev, pmd, extra, opts, backed_up, audit_outer=None):
    """Run after the normal iOS steps: rank suspects from the crash reports and collect their data."""
    days = getattr(opts, "suspect_days", 14)
    with D.Rec(case, "ios", did) as rec:
        res = scan_crashes(ev, days)
        adir = case / "analysis"; adir.mkdir(exist_ok=True)
        for fname, body in ((f"suspects-{did}.txt", P.render(res, did) + "\n"), (f"suspects-{did}.json", P.to_json(res, did))):
            (adir / fname).write_text(body); rec.generated(adir / fname, "analysis", "ios:suspects", f"analysis://{did}/{fname}", derived=True)
        arch = ev / "system_logs.logarchive"
        if arch.exists():
            if D.capture_unified(rec, days, archive=arch, fname="ios_unified_log_crash_events.txt"): print("Decoded crash-related lines from the log archive (saved, not ranked).")
            elif sys.platform != "darwin": rec.audit("NOTE the log archive was not decoded: `log show` only exists on macOS")
        apps = {}
        lf = ev / "_commands" / "apps_list.json"
        if lf.is_file(): apps = parse_apps_list(lf.read_text("utf-8", "replace"))
        chosen = []
        for name, evs in res["ranked"]:
            if name.startswith("(") or name in ("kernel_task", "launchd"): continue
            b = resolve_bundle(name, next((e["bundle"] for e in evs if e.get("bundle")), None), apps)
            if b and b not in [c[1] for c in chosen]: chosen.append((name, b))
        chosen = chosen[: getattr(opts, "max_suspects", 5)]
        rec.audit(f"SUSPECTS ranked={[n for n, _ in res['ranked']]} chosen={chosen}")
        print(("Suspect apps: " + ", ".join(f"{n} ({b})" for n, b in chosen)) if chosen else
              "No crashed or killed app found in the crash reports" + (f" (last {days} days of them)" if days else "") + ".")
        if not chosen or getattr(opts, "no_app_folders", False): return rec.ok
        collect_apps(rec, pmd, extra, ev, udid, [b for _, b in chosen], opts, "suspect", backed_up)
        return rec.ok


def collect_apps(rec, pmd, extra, ev, udid, bundles, opts, group, backed_up=True):
    cap = getattr(opts, "max_size_mb", 100) << 20; mf = getattr(opts, "max_app_files", 300); mb = getattr(opts, "max_app_mb", 500) << 20
    bdir = find_backup(ev); bres = None
    if bdir: bres = export_backup(rec, bdir, bundles, cap, mf, mb, group, udid)
    pbar = Progress("Asking the phone for app data", len(bundles), "apps")
    for b in bundles:
        pbar.set_item(b)
        pulled = pull_via_service(rec, pmd, extra, b, udid); pbar.update(1, 0, b)
        got = bres.get(b, {}).get("files", 0) if bres else 0
        say(f"  {b}: {pulled} files via app service, {got} files from backup" if bdir else f"  {b}: {pulled} files via app service")
    pbar.close()
    if not bdir:
        rec.audit("NOTE no backup in this case: app data was only attempted through the app service. Re-run with --backup to include it.")
        print("  (no backup in this case: use --backup to export apps' data from it; unencrypted backups only)")


# ------------------------------------------------------------------ `logharvest ios-apps`
def add_args(ap):
    ap.add_argument("--case", type=Path, help="case folder (created if missing)")
    ap.add_argument("--udid", help="required when more than one device is attached")
    ap.add_argument("--bundle", action="append", default=[], metavar="ID", help="only this bundle id (repeatable); default: all installed apps")
    ap.add_argument("--backup", action="store_true", help="take a full backup first (large; the only route to most apps' data)")
    ap.add_argument("--max-app-files", type=int, default=300, help="max files per app (default 300)")
    ap.add_argument("--max-app-mb", type=int, default=500, help="max MB per app (default 500)")
    ap.add_argument("--max-size-mb", type=int, default=100, help="skip single files larger than this (default 100)")
    ap.add_argument("--yes", action="store_true", help="do not ask for confirmation")
    ap.add_argument("--authority", default="", help="warrant / consent reference, recorded in audit.log")


def run(a):
    from . import ios
    bad = [b for b in a.bundle if not BUNDLE_RE.match(b)]
    if bad: print(f"ERROR: not a valid bundle id: {bad[0]!r}"); return 2
    dev, rc = ios.pick_device(a)
    if dev is None: return rc
    a.case.mkdir(parents=True, exist_ok=True)
    if a.backup:
        r = ios.collect_ios(a.case, dev, ["device_info", "apps_list", "backup"], 0, a.authority, opts=None)
        print(f"backup step: {r['ok']} files, {r['not_collected']} not collected")
    did = f"ios-{dev['udid'][:8]}"; ev = a.case / "evidence" / did
    extra = ["--udid", dev["udid"]] if dev.get("multiple") else []
    pmd = ios.pmd_cmd()
    with D.Rec(a.case, "ios", did) as rec:
        lf = ev / "_commands" / "apps_list.json"; (ev / "_commands").mkdir(parents=True, exist_ok=True)
        if not (a.backup and lf.is_file()):
            argv = pmd + APP_LIST + extra
            try:
                with open(lf, "wb") as fo: p = subprocess.run(argv, stdout=fo, stderr=subprocess.PIPE, timeout=120)
                if p.returncode == 0 and lf.stat().st_size: rec.generated(lf, "context", "ios:apps_list", f"ios://{dev['udid']}/apps_list", command=" ".join(argv))
                else: rec.nc("ios:apps_list", f"ios://{dev['udid']}/apps_list", f"exit code {p.returncode}. {p.stderr.decode('utf-8', 'replace')[-300:]}")
            except (OSError, subprocess.SubprocessError) as e: rec.nc("ios:apps_list", f"ios://{dev['udid']}/apps_list", f"{type(e).__name__}: {e}")
        apps = parse_apps_list(lf.read_text("utf-8", "replace")) if lf.is_file() else {}
        bundles = a.bundle or sorted(apps)
        if not bundles: print("No installed apps could be listed."); return 1
        bdir = find_backup(ev)
        print(f"{len(bundles)} apps. App data source: " + ("backup in this case (unencrypted only) + app service" if bdir else "app service only (most apps refuse; use --backup for more)"))
        if not a.yes:
            if not sys.stdin.isatty(): print("Not interactive: re-run with --yes to proceed."); return 2
            if input("Proceed? [y/N] ").strip().lower() not in ("y", "yes"): print("Cancelled."); return 2
        rec.audit(f"START ios-apps udid={dev['udid']} apps={len(bundles)} backup={bool(bdir)} authority={a.authority!r}")
        collect_apps(rec, pmd, extra, ev, dev["udid"], bundles, a, "all")
        rec.audit(f"END ios-apps ok={rec.ok} not_collected={rec.nc_count}")
        print(f"Done: {rec.ok} files recorded, {rec.nc_count} not collected. See manifest.jsonl.")
    return 0
