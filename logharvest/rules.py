"""Per-OS log locations, relative to the root of a mounted volume/image.
Globs are matched case-insensitively (NTFS/APFS images mounted on Linux)."""

RULES = {
    "windows": [
        ("system", "Windows/System32/winevt/Logs/*.evtx"),
        ("system", "Windows/System32/LogFiles/**/*.log"),
        ("system", "Windows/Logs/**/*.log"),
        ("system", "Windows/Panther/*.log"),
        ("application", "ProgramData/**/*.log"),
        ("application", "Users/*/AppData/Local/**/*.log"),
        ("application", "Users/*/AppData/Roaming/**/*.log"),
    ],
    "linux": [
        # --- system & kernel ---
        ("system", "var/log/**/*"),                       # syslog, messages, kern.log, auth, journal (persistent), rotated + .gz
        ("system", "var/adm/**/*"),
        ("system", "run/log/journal/**/*"),               # VOLATILE journal: only copy if persistence is off
        ("system", "var/log/journal/**/*"),
        ("system", "var/lib/systemd/pstore/*"),
        ("system", "var/lib/systemd/timers/*"),
        # --- crash ---
        ("crash", "var/lib/systemd/coredump/*"),
        ("crash", "var/crash/**/*"),                      # apport / kdump
        ("crash", "var/spool/abrt/**/*"),                 # RHEL/Fedora abrt
        ("crash", "var/lib/whoopsie/*"),
        ("crash", "sys/fs/pstore/*"),                     # kernel panic records (live, root)
        ("crash", "tmp/core*"), ("crash", "var/tmp/core*"),
        ("crash", "home/*/.mozilla/firefox/*/crashes/**/*"),
        ("crash", "home/*/.mozilla/firefox/Crash Reports/**/*"),
        ("crash", "home/*/.config/google-chrome/Crash Reports/**/*"),
        ("crash", "home/*/.config/chromium/Crash Reports/**/*"),
        ("crash", "home/*/.local/share/systemd/coredump/*"),
        # --- security / audit ---
        ("security", "var/log/audit/**/*"),
        ("security", "run/utmp"),
        # --- package history ---
        ("package", "var/lib/dnf/history*"), ("package", "var/lib/yum/history/*"),
        ("package", "var/lib/PackageKit/transactions.db"),
        # --- containers & services ---
        ("container", "var/lib/docker/containers/*/*.log"),
        ("container", "var/lib/docker/containers/*/config.v2.json"),
        ("container", "var/lib/containers/storage/overlay-containers/*/userdata/*.log"),
        ("container", "home/*/.local/share/containers/storage/overlay-containers/*/userdata/*.log"),
        ("container", "var/snap/*/common/**/*.log"),
        ("application", "var/lib/mysql/*.err"), ("application", "var/lib/postgresql/*/*/log/*"),
        ("application", "var/lib/pgsql/data/log/*"), ("application", "var/lib/pgsql/data/pg_log/*"),
        # --- application logs, system-wide ---
        ("application", "opt/**/*.log"), ("application", "srv/**/*.log"),
        ("application", "usr/local/**/*.log"),
        ("application", "tmp/**/*.log"), ("application", "var/tmp/**/*.log"),
        # --- application logs, per user (and root) ---
        ("application", "home/*/.local/share/**/*.log"),
        ("application", "home/*/.local/state/**/*.log"),
        ("application", "home/*/.config/**/*.log"),
        ("application", "home/*/.config/*/logs/**/*"),     # Electron apps (VS Code, Slack...)
        ("application", "home/*/.cache/**/*.log"),
        ("application", "home/*/.var/app/*/**/*.log"),     # Flatpak
        ("application", "home/*/snap/**/*.log"),           # Snap
        ("application", "home/*/.xsession-errors*"), ("application", "home/*/.local/share/xorg/*"),
        ("application", "root/.local/share/**/*.log"), ("application", "root/.local/state/**/*.log"),
        ("application", "root/.config/**/*.log"), ("application", "root/.cache/**/*.log"),
        ("application", "root/.xsession-errors*"),
        # --- logging configuration: explains WHY logs may be missing/short ---
        ("context", "etc/os-release"), ("context", "etc/*-release"), ("context", "etc/hostname"),
        ("context", "etc/fstab"), ("context", "etc/timezone"),
        ("context", "etc/systemd/journald.conf"), ("context", "etc/systemd/journald.conf.d/*"),
        ("context", "etc/systemd/coredump.conf"), ("context", "etc/systemd/coredump.conf.d/*"),
        ("context", "etc/rsyslog.conf"), ("context", "etc/rsyslog.d/*"),
        ("context", "etc/logrotate.conf"), ("context", "etc/logrotate.d/*"),
        ("context", "etc/sysctl.conf"), ("context", "etc/sysctl.d/*"),
        ("context", "etc/security/limits.conf"), ("context", "etc/security/limits.d/*"),
        ("context", "etc/audit/auditd.conf"), ("context", "etc/audit/rules.d/*"),
        # --- volatile kernel state (read once, hashed as read) ---
        ("volatile", "proc/version"), ("volatile", "proc/cmdline"), ("volatile", "proc/uptime"),
        ("volatile", "proc/loadavg"), ("volatile", "proc/meminfo"), ("volatile", "proc/vmstat"),
        ("volatile", "proc/mounts"), ("volatile", "proc/cpuinfo"), ("volatile", "proc/pressure/*"),
        ("volatile", "proc/sys/kernel/core_pattern"), ("volatile", "proc/sys/kernel/panic*"),
        ("volatile", "proc/sys/vm/overcommit_memory"), ("volatile", "proc/sys/kernel/dmesg_restrict"),
    ],
    "macos": [
        # --- system ---
        (
            "system",
            "private/var/log/**/*",
        ),  # system.log, install.log, asl/, DiagnosticMessages/ ...
        ("system", "private/var/audit/*"),  # BSM audit trail
        ("system", "private/var/db/diagnostics/**/*"),  # Unified Logging (*.tracev3)
        ("system", "private/var/db/uuidtext/**/*"),  # needed to decode tracev3 offline
        ("system", "private/var/db/timesync/*"),  # needed for tracev3 timestamps
        ("system", "private/var/root/Library/Logs/**/*"),
        ("system", "Library/Logs/**/*"),  # incl. DiagnosticReports (.ips/.crash)
        ("system", "Library/Receipts/InstallHistory.plist"),
        # --- application ---
        (
            "application",
            "Users/*/Library/Logs/**/*",
        ),  # per-user app logs + DiagnosticReports
        (
            "application",
            "Users/*/Library/Containers/*/Data/Library/Logs/**/*",
        ),  # sandboxed apps
        ("application", "Users/*/Library/Group Containers/*/Library/Logs/**/*"),
        ("application", "Users/*/Library/Application Support/**/*.log"),
        (
            "application",
            "Users/*/Library/Containers/*/Data/Library/Application Support/**/*.log",
        ),
        ("application", "Library/Application Support/**/*.log"),
    ],
    "ios": [
        ("system", "private/var/logs/**/*"),
        ("system", "private/var/db/diagnostics/**/*"),
        ("system", "private/var/mobile/Library/Logs/**/*"),
        (
            "application",
            "private/var/mobile/Containers/Data/Application/*/Library/Caches/**/*.log",
        ),
    ],
    "android": [
        ("system", "data/anr/*"),
        ("system", "data/tombstones/*"),
        ("system", "data/system/dropbox/*"),
        ("system", "data/misc/logd/*"),
        ("application", "data/data/*/files/**/*.log"),
        ("application", "data/data/*/cache/**/*.log"),
    ],
}

# Ordered: first match wins (iOS before macOS, both have System/Library/CoreServices)
MARKERS = [
    ("windows", ["Windows/System32/winevt"]),
    ("ios", ["private/var/mobile", "System/Library/CoreServices/SystemVersion.plist"]),
    ("android", ["data/system", "system/build.prop"]),
    ("macos", ["System/Library/CoreServices/SystemVersion.plist", "Users"]),
    ("linux", ["etc/os-release", "var/log"]),
]

# Live commands (local mode only), ordered by volatility. Output stored raw + hashed.
COMMANDS = {"linux": [
    ("date_utc", ["date", "-u", "+%Y-%m-%dT%H:%M:%S%z"]), ("timedatectl", ["timedatectl"]),
    ("dmesg_iso", ["dmesg", "--time-format=iso"]), ("dmesg_raw", ["dmesg", "-r"]),
    ("uptime", ["uptime"]), ("who_boot", ["who", "-b"]), ("uname", ["uname", "-a"]),
    ("journal_list_boots", ["journalctl", "--list-boots", "--no-pager"]),
    ("journal_boot_0", ["journalctl", "-b", "0", "--no-pager", "-o", "short-iso-precise"]),
    ("journal_boot_-1", ["journalctl", "-b", "-1", "--no-pager", "-o", "short-iso-precise"]),
    ("journal_boot_-2", ["journalctl", "-b", "-2", "--no-pager", "-o", "short-iso-precise"]),
    ("journal_kernel_-1", ["journalctl", "-k", "-b", "-1", "--no-pager", "-o", "short-iso-precise"]),
    ("last_x", ["last", "-x", "-F"]), ("lastb", ["lastb", "-F"]),
    ("coredumpctl", ["coredumpctl", "list", "--no-pager"]),
    ("systemd_failed", ["systemctl", "--failed", "--no-pager"]),
    ("ps", ["ps", "auxww"]), ("free", ["free", "-b"]), ("df", ["df", "-hT"]),
    ("mount", ["mount"]), ("lsblk", ["lsblk", "-f"]), ("lsmod", ["lsmod"]),
    ("ip_addr", ["ip", "-br", "addr"]), ("sysctl_all", ["sysctl", "-a"]),
]}
