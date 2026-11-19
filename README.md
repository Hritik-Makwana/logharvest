# LogHarvest

A forensic log collector for crash / hang investigations. It detects volumes, disk images, extracted backups and USB phones,
identifies the operating system (Linux, Windows, macOS, Android, iOS), copies system and application logs into a **case folder**,
hashes every copy (SHA-256 before and after), finds which programs crashed or hung, collects those programs' own folders,
and lets you browse, search and report on everything.

Python 3.12+. Optional: `psutil` (auto-detect mounted drives), `adb` (Android), `pymobiledevice3` (iPhone), `dissect.target[full]` (disk images).
Devices must be lawfully sourced (warrant or consent); `--authority "<reference>"` records it in `audit.log`.
The source is never modified (read-only access; unavoidable device-side footprint on phones is written to `audit.log`).
Run with `sudo` / Administrator for complete system logs; without it the tool says what will be missing and carries on.

## Install

```bash
pip install -e .                 # core
pip install -e ".[full]"         # + psutil
pip install -e ".[image]"        # + disk-image support (dissect.target)
pip install -e ".[ios]"          # + iPhone support
pip install -e ".[all]"          # everything
```

## Quick start

```bash
logharvest detect --source /path/to/source
logharvest collect --case ./case001 --source /mnt/disk --authority "Warrant 2026-114"
logharvest collect --case ./case001 --all                 # every detected volume (+ adb devices)
logharvest android --case ./case001                       # USB phone
logharvest image win10.qcow2 --case ./case001             # disk / VM image, no mounting
logharvest view --case ./case001                          # file browser   http://127.0.0.1:8765
logharvest explore --case ./case001                       # timeline + full-text search
logharvest report --case ./case001                        # printable HTML report
sudo "$(which logharvest)" collect ...                    # with privileges
```

## Case folder

```
case/
  manifest.jsonl     one row per file: source, size, modified/accessed/changed, sha256, dest, verified, app (if any) ...
  audit.log          every command run, every decision (which suspects were chosen and why), every limit hit
  evidence/<device>/ bit-for-bit copies (apps/<program>/... holds per-program folders)
  analysis/          suspects-<device>.txt/.json, image-<name>.json, derived/timeline.jsonl  (derived from the evidence, not evidence itself)
  coverage-<device>.json  what each rule matched and which folders were unreadable (collect)
  report.html        from `logharvest report`
```
Anything that could not be collected is a `not_collected` row with the reason; collection always continues.

## Commands

| Command | What it does |
|---|---|
| `detect` | list volumes / devices and the OS found |
| `collect --case C --source PATH [--all] [--profile fast|full] [--sweep|--all-dirs] [--dir D]... [--exclude-dir D]... [--only-dirs] [--max-depth N] [--no-commands] [--adb [SERIAL]] [--logarchive-days N]` | Linux / Windows / macOS logs (live `/`, `C:\` or a mounted image); `--sweep` / `--all-dirs` also checks every directory for log-like files no rule covers (smart: see below); live runs capture volatile state first (dmesg, journal, processes, netstat... and exported `.evtx` on Windows); then suspects + their folders |
| `image DISK... --case C [--list] [--profile fast|full] [--sweep|--all-dirs] [--dir D]... [--exclude-dir D]... [--only-dirs]` | disk image or VM disk (raw/dd, E01, qcow2, vmdk, vhd, vhdx, vdi) read directly, no mounting or root; then suspects + folders |
| `android --case C [--logcat-live N] [--adb-root] [--no-su]` | USB Android phone: logs, dumps, bugreport; then suspects + their folders |
| `ios --case C [--backup] [--sysdiagnose]` | iPhone/iPad (needs `pymobiledevice3`); then suspects + their data |
| `android-apps --case C` | copy the folders of **all** installed Android apps (plan, then confirm) |
| `desktop-apps --case C [--source ROOT \| --image DISK]` | copy the folders of **all** programs on a Linux/Windows/macOS system |
| `ios-apps --case C [--backup]` | collect data of **all** iPhone apps (see limits) |
| `suspects --case C` | re-run the suspect analysis on any collected case (writes a new `*-rerun-<time>.json`) |
| `timeline --case C [--kind K] [--device D] [--since T]` | one time-sorted list of crashes, hangs, boots and error lines across all devices and logs |
| `explore --case C` | local web page (127.0.0.1): Timeline tab + full-text / regex Search over every collected text log (.gz too), click a hit to see it in context |
| `report --case C [--json] [--no-verify]` | printable HTML: chain of custody, integrity re-check of every file, image provenance, findings with evidence lines, timeline around them, what was not collected |
| `view --case C` | web viewer (sortable by modified / accessed / changed, filter by device, OS, type, app) |

Run with `sudo` / Administrator for complete system logs. Without it the tool says what will be missing and carries on.

## How suspects are found (automatic)

| System | Evidence read | Folders copied for each suspect |
|---|---|---|
| Android | logcat `FATAL EXCEPTION` / ANR / native crash / lmkd, `dumpsys dropbox`, `dumpsys activity exit-info`, tombstones and ANR traces from the bugreport | `/sdcard/Android/{data,media,obb}/<pkg>`; plus `/data/data/<pkg>` when the shell is root |
| Linux | apport `.crash`, systemd coredumps, kernel segfault / OOM / hung-task lines, `journalctl` (live) | `~/.config`, `~/.local/share`, `~/.var/app`, `~/snap`, `~/.<app>`, `/var/log/<app>` |
| Windows | Windows Error Reporting `Report.wer`, Application events 1000/1002 and System 41/6008/1001 (`wevtutil`, live; `.evtx` in images needs `pip install python-evtx`) | `AppData\{Roaming,Local,LocalLow}\<app>`, `ProgramData\<app>` |
| macOS | DiagnosticReports `.ips` `.crash` `.hang` `.spin` `.panic` | `~/Library/{Application Support,Containers,Group Containers,Logs,Saved Application State}`, `Preferences/<bundle id>*.plist` |
| iOS | crash reports (`.ips`) incl. JetsamEvent | via the app service (file-sharing apps) and, with `--backup`, the app's `AppDomain-*` files from an **unencrypted** backup |

Flags (on `android`, `collect`, `ios`): `--no-suspects`, `--max-suspects N` (5), `--suspect-days N` (14, `0` = no limit;
counted back from the newest evidence), `--no-app-folders`, `--include-cache`, `--max-app-files N` (300), `--max-app-mb N` (500).
Desktop also has `--include-install` (copy `/opt`, `Program Files`, `/Applications` folders). Android: `--package PKG` always collects that app.

Caches and install folders are skipped by default. Files over a cap are listed in a single `not_collected` row, not silently dropped.

## Disk images and VM disks

```
pip install "dissect.target[full]"                      # once (or: pip install -e ".[image]")
python -m logharvest image win10.qcow2 --list           # what is inside: partitions, file systems, which OS
python -m logharvest image win10.qcow2 --case case1     # collect logs, find suspects, copy their folders
python -m logharvest image disk.E01 --case case1 --sweep
python -m logharvest desktop-apps --case case1 --image server.vmdk --yes
```
- Formats: raw/dd/img, E01 / Ex01 (all segments), qcow2 (backing files included), vmdk (extents included), vhd, vhdx, vdi.
  File systems: NTFS, ext2/3/4, XFS, btrfs, FAT/exFAT, APFS, FFS and more, inside MBR / GPT / LVM layouts.
- Nothing is mounted and no driver or root is needed, so it behaves the same on Linux, Windows and macOS hosts.
- The image is only read. `--hash both` (default) records its SHA-256 before and after (all linked segments / backing files
  too) in `analysis/image-<name>.json`; `before` or `none` for very large images.
- Collected files keep the guest file system's own times (accessed, modified, changed, and `created` where it exists);
  `source` reads `image://<image>/fsN:type/<path in guest>`. Same rules, suspect detection and folder copying as a live system.
- Not collected, and reported as such: encrypted volumes (BitLocker / LUKS / FileVault), HFS+, unrecognised file systems.
  A Windows or Linux image whose partitions the tool cannot read can still be mounted by you and passed with `--source`.

## Android access levels

| Level | How detected | Extra evidence |
|---|---|---|
| shell | stock phone | logcat, dumpsys snapshots, dropbox, exit-info, bugreport, shared-storage app folders; `run-as` for *debuggable* apps |
| su | `su -c id` works (rooted; Magisk may prompt on the phone; skip with `--no-su`) | + `/data/anr`, `/data/tombstones`, dropbox, logd, and `/data/data/<pkg>` of the suspect apps, streamed through `su` and hashed on the fly |
| adbroot | `--adb-root` on emulator / userdebug builds | same, using `adb pull` |

Every file copied through `su` or `run-as` keeps the device's own modified / accessed / changed times and is flagged `via` in the manifest.

## Known limits

- Android without root cannot read `/data/data`, `/data/anr`, `/data/tombstones`; the bugreport covers the last two.
- iOS offers no filesystem. Most store apps refuse `apps pull`; an encrypted backup cannot be read.
- Log formats for exit-info, tombstones, apport, WER, `.ips` were written from the documented formats; if a format differs on your
  device the suspect list may be incomplete, but the raw evidence is still collected and hashed.
- Image support was tested with raw, qcow2, vmdk, vhdx, vdi and vhd images holding NTFS and ext4. E01, APFS and encrypted
  volumes are handled by the dissect library but have not been tried here.
- Syslog lines without a UTC offset are shown as UTC (flagged in the report).
- macOS/iOS Unified Log (`.tracev3`) is collected; crash-related lines are decoded to a text file only when run on a Mac.

## Timeline, search, report

- `analysis/derived/timeline.jsonl` is derived from the copies (never from the device) and is rebuilt on demand; its SHA-256 goes into `audit.log`.
  Android logcat is read as UTC; syslog lines without a zone are treated as UTC.
- `explore` never writes to the case and refuses any file outside it. `report` re-hashes all of `evidence/` (use `--no-verify` on huge cases) and appends one line to `audit.log`.
- Viewer: `python patch_viewer.py logharvest/index.html` adds a Created column and image origin to the detail panel (makes a `.bak`).

## Project structure

| File | Purpose |
|---|---|
| `detect.py` `rules.py` `discover.py` | find volumes / devices, identify the OS, per-OS log locations, sweep for uncovered logs |
| `collect.py` | copy + hash + manifest for mounted / live systems; live volatile commands; macOS logarchive |
| `android.py` `apps.py` | USB Android collection; per-app folders (shared storage, su, run-as) |
| `ios.py` `ios_apps.py` | iPhone/iPad via pymobiledevice3; app data and unencrypted-backup export |
| `desktop.py` `images.py` | per-program folders on Linux/Windows/macOS; disk-image reading (dissect.target) |
| `suspects.py` `procsuspects.py` | crash / hang detection from logs (all five OS families) |
| `events.py` `explore.py` `report.py` | merged timeline, local search page, printable report |
| `viewer.py` `index.html` | web file browser with hash re-verification |
| `progress.py` `cli.py` | progress bars, command-line entry point |

## Tests and contributing

```bash
uv sync --group dev
uv run ruff check .
uv run pytest -q                      # unit tests, fake adb / pymobiledevice3, run on Linux, Windows, macOS in CI
python tests/run_tests.py             # Linux: full end-to-end run incl. disk images (needs mkfs.ext4; dissect.target[full])
python scripts/evidence_guard.py      # fails if evidence-like files are tracked by git
```
See `CONTRIBUTING.md`. Never commit case folders.

## Viewer helpers

`python add_app_filter.py logharvest/index.html` (All-apps dropdown) and `python patch_viewer.py logharvest/index.html`
(Created column, image origin) are already applied to the shipped page; they are safe to re-run on an edited copy (they make a `.bak`).


## `--all-dirs` (alias `--sweep`): check every directory, without reading all of them

The rules cover known log locations; `--all-dirs` also looks for log-like files (`*.log`, `*.log.1`, `*.etl`, `*.dmp`,
`*.err`, `*.trace`, `*.wer`, `core`, ...) anywhere else. It does not blindly walk the whole volume:

- skips known-noise folders by path (`Windows\WinSxS`, `Installer`, `DriverStore`, `WindowsApps`, Linux `/usr/lib`, macOS `/System`...)
- under `Windows\System32` only enters the log-bearing children (`LogFiles`, `winevt`, `wbem`, `sysprep`, `config`, ...)
- skips noise names at any depth (`node_modules`, `.git`, `site-packages`, `Cache`, `GPUCache`, `IndexedDB`, ...)
- never follows symlinks / junctions; unreadable folders are recorded as `not_collected`
- depth limit `--max-depth` (default 12); folders named `log`/`logs`/`crashes`/`dumps` are searched fully and also yield `.txt/.json/.out`

What was skipped is counted: see `SWEEP` lines in `audit.log` and `"sweep"` in `coverage-<device>.json` (dirs visited, dirs skipped, examples).
Limitation: a log in a skipped folder (for example an unlisted subfolder of `System32`) is not found; add it to `rules.py` if you need it.


## Choosing directories: `--dir`, `--exclude-dir`, `--only-dirs`

```
logharvest collect --case C --source D:\ --dir Users\bob\AppData --dir ProgramData\Acme
logharvest collect --case C --source D:\ --dir Windows\Logs --only-dirs
logharvest collect --case C --source D:\ --all-dirs --exclude-dir Users\bob\Downloads
logharvest image disk.E01 --case C --dir "Windows/Logs" --dir "Users/bob"
```

- `--dir DIR` (repeatable): the sweep starts only in these folders. Implies `--sweep`; nothing else on the volume is read by the sweep.
  Paths are relative to the volume root (a leading `C:`, backslashes, or an absolute path under `--source` are all accepted) and
  matched case-insensitively. Folders inside another `--dir` are covered by it. A `--dir` you name explicitly is searched even if it is
  on the built-in noise list (e.g. `Windows\WinSxS`); noise names inside it (`node_modules`, `Cache`...) are still skipped.
- `--only-dirs`: also limit the normal rules (event logs, CBS, crash dumps...) to the `--dir` folders. Without it, the rules still run on the whole volume.
- `--exclude-dir DIR` (repeatable): never entered by the sweep and never collected by the rules. Works with or without `--dir`.
- A `--dir` that does not exist, or is excluded, is recorded as `not_collected` ("directory not found"), never ignored.
  The chosen folders are written to `audit.log` (`START ... dirs=[...] exclude=[...]`).
- `..` is rejected: paths cannot leave the volume.


## Scan size: `--profile fast | (nothing) | full`

| | what it collects | use it for |
|---|---|---|
| `--profile fast` | quick scan: only the logs that answer "what crashed / rebooted / failed, and when": Windows System/Application/Security/Setup `.evtx`, CBS, setupapi, Panther, Startup Repair, minidumps, WER; Linux syslog/messages/kern/auth/journal/audit/coredumps; macOS unified log + DiagnosticReports | seconds-to-minutes triage |
| *(no flag)* | **default scan**: every well-known log location (the rule list in `rules.py`), including `.etl` traces under `Windows\Logs` and `LogFiles`, `SrtTrail.txt`, and Chrome/Edge Crashpad reports | normal use |
| `--profile full` | default + forensic artefacts, in new categories: **registry** (SYSTEM/SOFTWARE/SECURITY/SAM/DEFAULT, NTUSER.DAT, UsrClass.dat + their `.LOG1/.LOG2`), **execution** (Prefetch, Amcache, SRUDB.dat), **persistence** (scheduled tasks, hosts, cron, systemd units, rc.local, LaunchAgents/Daemons), **activity** (PowerShell/bash/zsh history, Recent items, `.fseventsd`, User Access Logging), **server** (IIS, SQL Server, Defender), plus `Memory.dmp`, `LiveKernelReports`, Powerlog, CrashReporter, receipts, Steam/Proton logs | investigations |

Notes: the profiles only choose *which rules run*; they compose with `--dir/--only-dirs/--exclude-dir` and with `--sweep/--all-dirs` (which is never switched on
by a profile). The chosen profile is written to `audit.log` and `coverage-<device>.json`. In `full`, registry hives and `SRUDB.dat` are locked on a **running**
Windows system (they show up as `not_collected` with the reason: collect from an image instead), and `Memory.dmp` is usually larger than `--max-size-mb`
(it is reported as `not_collected`, not skipped silently; raise the limit if you want it).

## Windows event logs (`.evtx`) in the timeline and suspects

`logharvest/evtx.py` is a self-contained `.evtx` reader (no package to install). `timeline`, `suspects` and `report` now use it on every collected `.evtx`
(including `_exports/*.evtx` from a live system):

- **suspects**: Application Error 1000 (crash), Application Hang 1002, Kernel-Power 41, 6008, BugCheck 1001 - now also from images, not only from live `wevtutil` output
- **timeline**: boots/shutdowns (Kernel-General 12/13, 6005/6006, 1074), service crashes (SCM 7031/7034) and failures (7000/7001/7009/7011/7023/7024...),
  disk / file-system errors (Disk, Ntfs, stornvme, storahci, volmgr, ...), hardware errors (WHEA-Logger), **cleared event logs (104 / Security 1102)**, and every
  other Critical/Error-level event, newest 200,000 records per file
- messages are not decoded: the text lives in the provider's DLL on the original PC, so you get the provider, numeric event id and the event's own data fields
- damaged records are skipped and counted: `timeline` prints `note: <file>: N of M event records could not be decoded`
- verified against synthetic `.evtx` files written to the documented format; if a real log shows many "could not be decoded" notes, send me the file
