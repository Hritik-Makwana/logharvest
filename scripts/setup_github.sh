#!/usr/bin/env bash
# One-time setup: creates labels and a starter backlog of issues in the repo `gh` is pointed at.
#   DRY_RUN=1 ./scripts/setup_github.sh     # print what would happen
#   ./scripts/setup_github.sh               # do it (run ONCE: issues are not de-duplicated)
# Needs the GitHub CLI, already logged in:  gh auth login
set -euo pipefail
DRY="${DRY_RUN:-0}"
run() { if [ "$DRY" = 1 ]; then printf '+'; printf ' %q' "$@"; printf '\n'; else "$@"; fi; }

labels=(
  "bug|d73a4a|Something is broken"
  "feature|a2eeef|New capability"
  "needs-triage|fbca04|Not yet reviewed"
  "blocked|b60205|Waiting on something external"
  "priority:high|b60205|Do next"
  "priority:medium|d93f0b|Soon"
  "priority:low|0e8a16|Someday"
  "area:linux|1d76db|Linux collection"
  "area:windows|1d76db|Windows collection"
  "area:macos|1d76db|macOS collection"
  "area:android|1d76db|Android"
  "area:ios|1d76db|iOS"
  "area:parsers|1d76db|Parsers and analysis"
  "area:viewer|1d76db|Web UI"
  "area:ci|1d76db|Pipeline and build"
  "area:docs|1d76db|Documentation"
)
for l in "${labels[@]}"; do
  IFS='|' read -r name color desc <<<"$l"
  run gh label create "$name" --color "$color" --description "$desc" --force
done

issue() { run gh issue create --title "$1" --label "$2" --body "$3"; }

issue "Windows: add crash and event-log rules" "feature,area:windows,priority:high" \
  "Cover C:\\Windows\\Minidump, MEMORY.DMP, LiveKernelReports, WER ReportArchive/ReportQueue, %LOCALAPPDATA%\\CrashDumps and the key event logs (System, Application, Operational). Handle locked files (VSS or raw read) and record failures. Add a synthetic Windows fixture tree and a test."
issue "Verify macOS rules on a real Mac" "bug,area:macos,priority:high" \
  "Rules exist but have only been exercised on Linux. Check DiagnosticReports, /var/db/diagnostics + uuidtext + timesync, Full Disk Access handling, and the /System/Volumes/Data path mapping."
issue "iOS: verify pymobiledevice3 command names on a real iPhone" "bug,area:ios,priority:high" \
  "STEPS table in ios.py was written without a device. Confirm each subcommand with 'pymobiledevice3 <group> --help', adjust, and document iOS 17+ tunnel/sudo requirements."
issue "iOS: USB detection problem on Linux (no Apple device in lsusb)" "bug,area:ios,priority:medium" \
  "No 05ac device appears when the phone is connected. Check cable/port/usbmuxd versions and document the troubleshooting steps."
issue "Android: dumpsys dropbox and exit-info collection" "feature,area:android,priority:medium" \
  "Add 'dumpsys dropbox --print', 'dumpsys activity exit-info <pkg>', getprop and meminfo to collect_adb, collected volatile-first (logcat before everything else)."
issue "Record tool version in audit.log and manifest" "feature,area:ci,priority:medium" \
  "Every case should say which release produced it. Include version and dependency versions in the START line of audit.log."
issue "Capture file birth time on Linux (statx)" "feature,area:linux,priority:low" \
  "os.stat does not expose birth time on Linux. Use statx via ctypes or an optional helper and record it as 'created'."
issue "Viewer: add --host option (needed for Docker)" "feature,area:viewer,priority:medium" \
  "The viewer binds to 127.0.0.1 only. Add --host with a warning when binding to a non-loopback address, because evidence is exposed and there is no authentication."
issue "Parsers: .evtx and journald to a common event schema" "feature,area:parsers,priority:medium" \
  "Parse binary logs into JSONL events with provenance (artifact id + offset), UTC time and the original timestamp string."
issue "Culprit finder v1: pivot time, boot boundaries, signatures" "feature,area:parsers,priority:medium" \
  "Time-window view around a crash, boot/shutdown detection, a YAML signature list (OOM kill, segfault, ANR, Event IDs 41/1001/1000/1002) and silence detection."
issue "Signed manifest and examiner/case metadata" "feature,area:linux,priority:low" \
  "case.json with examiner and authority reference; sign manifest.jsonl (Ed25519) so later edits are detectable."
issue "Browser tests for the viewer" "feature,area:ci,priority:medium" \
  "Selenium or Playwright tests: sorting, status filter, chips, preview, escaping of hostile log content."
