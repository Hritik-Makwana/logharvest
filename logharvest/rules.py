"""Per-OS log locations, relative to the root of a mounted volume/image.
Globs are matched case-insensitively (NTFS/APFS images mounted on Linux)."""

RULES = {
    "windows": [
        # --- central event logs: System, Application, Security, Setup + every Microsoft-Windows-* channel ---
        ("system", "Windows/System32/winevt/Logs/*.evtx"),
        ("system", "Windows/System32/LogFiles/**/*.log"),
        ("system", "Windows/System32/LogFiles/**/*.etl"),        # WMI / boot traces (were missed: rule was .log only)
        ("system", "Windows/System32/LogFiles/Srt/*"),            # Startup Repair: SrtTrail.txt
        # --- Windows Update & servicing: CBS.log (+ CbsPersist cabs), DISM, WindowsUpdate ETL ---
        ("system", "Windows/Logs/**/*.log"),
        ("system", "Windows/Logs/**/*.etl"),                      # SIH, waasmedic, NetSetup traces
        ("system", "Windows/Logs/CBS/*"),
        ("system", "Windows/Logs/DISM/*"),
        ("system", "Windows/Logs/WindowsUpdate/*"),
        ("system", "Windows/SoftwareDistribution/ReportingEvents.log"),
        ("system", "Windows/WindowsUpdate.log"),
        # --- setup / upgrade / driver installation / WMI ---
        ("system", "Windows/Panther/**/*.log"),
        ("system", "Windows/System32/sysprep/Panther/*.log"),
        ("system", "Windows/INF/setupapi*.log"),
        ("system", "Windows/Debug/*.log"),
        ("system", "Windows/System32/wbem/Logs/*.log"),
        # --- crash ---
        ("crash", "Windows/Minidump/*.dmp"),
        ("crash", "ProgramData/Microsoft/Windows/WER/**/*.wer"),
        ("crash", "Users/*/AppData/Local/CrashDumps/*.dmp"),
        ("crash", "Users/*/AppData/Local/Google/Chrome/User Data/Crashpad/reports/*"),
        ("crash", "Users/*/AppData/Local/Microsoft/Edge/User Data/Crashpad/reports/*"),
        ("crash", "Users/*/AppData/Local/Microsoft/Windows/WER/**/*.wer"),
        # --- shared application data ---
        ("application", "ProgramData/**/*.log"),
        # --- program installation folders (older / portable apps: <App>\logs, <App>\log, <App>\*.log) ---
        ("application", "Program Files/*/logs/**/*"),
        ("application", "Program Files/*/log/**/*"),
        ("application", "Program Files/*/*.log"),
        ("application", "Program Files (x86)/*/logs/**/*"),
        ("application", "Program Files (x86)/*/log/**/*"),
        ("application", "Program Files (x86)/*/*.log"),
        # --- per-user application logs ---
        ("application", "Users/*/AppData/Local/**/*.log"),
        ("application", "Users/*/AppData/Roaming/**/*.log"),
        ("application", "Users/*/AppData/LocalLow/**/*.log"),
        # VS Code application logs
        ("application", "Users/*/AppData/Roaming/Code/logs/**/*.txt"),
    ],
    "linux": [
        # --- system & kernel ---
        (
            "system",
            "var/log/**/*",
        ),  # syslog, messages, kern.log, auth, journal (persistent), rotated + .gz
        ("system", "var/adm/**/*"),
        (
            "system",
            "run/log/journal/**/*",
        ),  # VOLATILE journal: only copy if persistence is off
        ("system", "var/log/journal/**/*"),
        ("system", "var/lib/systemd/pstore/*"),
        ("system", "var/lib/systemd/timers/*"),
        # --- crash ---
        ("crash", "var/lib/systemd/coredump/*"),
        ("crash", "var/crash/**/*"),  # apport / kdump
        ("crash", "var/spool/abrt/**/*"),  # RHEL/Fedora abrt
        ("crash", "var/lib/whoopsie/*"),
        ("crash", "sys/fs/pstore/*"),  # kernel panic records (live, root)
        ("crash", "tmp/core*"),
        ("crash", "var/tmp/core*"),
        ("crash", "home/*/.mozilla/firefox/*/crashes/**/*"),
        ("crash", "home/*/.mozilla/firefox/Crash Reports/**/*"),
        ("crash", "home/*/.config/google-chrome/Crash Reports/**/*"),
        ("crash", "home/*/.config/chromium/Crash Reports/**/*"),
        ("crash", "home/*/.local/share/systemd/coredump/*"),
        # --- security / audit ---
        ("security", "var/log/audit/**/*"),
        ("security", "run/utmp"),
        # --- package history ---
        ("package", "var/lib/dnf/history*"),
        ("package", "var/lib/yum/history/*"),
        ("package", "var/lib/PackageKit/transactions.db"),
        # --- containers & services ---
        ("container", "var/lib/docker/containers/*/*.log"),
        ("container", "var/lib/docker/containers/*/config.v2.json"),
        ("container", "var/lib/containers/storage/overlay-containers/*/userdata/*.log"),
        (
            "container",
            "home/*/.local/share/containers/storage/overlay-containers/*/userdata/*.log",
        ),
        ("container", "var/snap/*/common/**/*.log"),
        ("application", "var/lib/mysql/*.err"),
        ("application", "var/lib/postgresql/*/*/log/*"),
        ("application", "var/lib/pgsql/data/log/*"),
        ("application", "var/lib/pgsql/data/pg_log/*"),
        # --- application logs, system-wide ---
        ("application", "opt/**/*.log"),
        ("application", "srv/**/*.log"),
        ("application", "usr/local/**/*.log"),
        ("application", "tmp/**/*.log"),
        ("application", "var/tmp/**/*.log"),
        # --- application logs, per user (and root) ---
        ("application", "home/*/.local/share/**/*.log"),
        ("application", "home/*/.local/state/**/*.log"),
        ("application", "home/*/.config/**/*.log"),
        (
            "application",
            "home/*/.config/*/logs/**/*",
        ),  # Electron apps (VS Code, Slack...)
        ("application", "home/*/.cache/**/*.log"),
        ("application", "home/*/.var/app/*/**/*.log"),  # Flatpak
        ("application", "home/*/snap/**/*.log"),  # Snap
        ("application", "home/*/.xsession-errors*"),
        ("application", "home/*/.local/share/xorg/*"),
        ("application", "root/.local/share/**/*.log"),
        ("application", "root/.local/state/**/*.log"),
        ("application", "root/.config/**/*.log"),
        ("application", "root/.cache/**/*.log"),
        ("application", "root/.xsession-errors*"),
        # --- logging configuration: explains WHY logs may be missing/short ---
        ("context", "etc/os-release"),
        ("context", "etc/*-release"),
        ("context", "etc/hostname"),
        ("context", "etc/fstab"),
        ("context", "etc/timezone"),
        ("context", "etc/systemd/journald.conf"),
        ("context", "etc/systemd/journald.conf.d/*"),
        ("context", "etc/systemd/coredump.conf"),
        ("context", "etc/systemd/coredump.conf.d/*"),
        ("context", "etc/rsyslog.conf"),
        ("context", "etc/rsyslog.d/*"),
        ("context", "etc/logrotate.conf"),
        ("context", "etc/logrotate.d/*"),
        ("context", "etc/sysctl.conf"),
        ("context", "etc/sysctl.d/*"),
        ("context", "etc/security/limits.conf"),
        ("context", "etc/security/limits.d/*"),
        ("context", "etc/audit/auditd.conf"),
        ("context", "etc/audit/rules.d/*"),
        # --- volatile kernel state (read once, hashed as read) ---
        ("volatile", "proc/version"),
        ("volatile", "proc/cmdline"),
        ("volatile", "proc/uptime"),
        ("volatile", "proc/loadavg"),
        ("volatile", "proc/meminfo"),
        ("volatile", "proc/vmstat"),
        ("volatile", "proc/mounts"),
        ("volatile", "proc/cpuinfo"),
        ("volatile", "proc/pressure/*"),
        ("volatile", "proc/sys/kernel/core_pattern"),
        ("volatile", "proc/sys/kernel/panic*"),
        ("volatile", "proc/sys/vm/overcommit_memory"),
        ("volatile", "proc/sys/kernel/dmesg_restrict"),
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

# Windows live mode (running on the machine being collected). Ordered by volatility.
COMMANDS["windows"] = [
    ("date_utc", ["powershell", "-NoProfile", "-Command", "(Get-Date).ToUniversalTime().ToString('o')"]),
    ("netstat", ["netstat", "-ano"]), ("tasklist", ["tasklist", "/v", "/fo", "csv"]),
    ("ipconfig", ["ipconfig", "/all"]), ("whoami", ["whoami", "/all"]), ("quser", ["quser"]),
    ("systeminfo", ["systeminfo"]), ("services", ["sc", "query", "type=", "service", "state=", "all"]),
    ("schtasks", ["schtasks", "/query", "/fo", "csv", "/v"]), ("driverquery", ["driverquery", "/v", "/fo", "csv"]),
    ("wevtutil_channels", ["wevtutil", "el"]),
]

# Live Windows: also ask the OS to export these channels (consistent .evtx, unlike a raw copy of an open file).
EVTX_EXPORT = ["System", "Application", "Security", "Setup"]


# =====================================================================================================================
# Scan profiles:  --profile fast | (default: not passed) | full
#   fast     small, high-value set: the logs that answer "what crashed / rebooted / failed and when" in seconds.
#   default  RULES above (every well-known log location).
#   full     default + RULES_FULL: forensic artefacts (registry hives, Prefetch, Amcache, SRUM, scheduled tasks, shell
#            history, launch agents, server logs, full memory dumps). Larger, slower, and some files are locked on a live OS.
# The categories "registry", "execution", "persistence", "activity" and "server" only occur in the full profile.
# =====================================================================================================================
PROFILES = ("fast", "default", "full")

RULES_FAST = {
    "windows": [
        ("system", "Windows/System32/winevt/Logs/System.evtx"),
        ("system", "Windows/System32/winevt/Logs/Application.evtx"),
        ("system", "Windows/System32/winevt/Logs/Security.evtx"),
        ("system", "Windows/System32/winevt/Logs/Setup.evtx"),
        ("system", "Windows/Logs/CBS/CBS.log"),
        ("system", "Windows/INF/setupapi.dev.log"),
        ("system", "Windows/Panther/setupact.log"),
        ("system", "Windows/Panther/setuperr.log"),
        ("system", "Windows/System32/LogFiles/Srt/SrtTrail.txt"),
        ("crash", "Windows/Minidump/*.dmp"),
        ("crash", "ProgramData/Microsoft/Windows/WER/**/*.wer"),
        ("crash", "Users/*/AppData/Local/Microsoft/Windows/WER/**/*.wer"),
    ],
    "linux": [
        ("system", "var/log/syslog*"),
        ("system", "var/log/messages*"),
        ("system", "var/log/kern.log*"),
        ("system", "var/log/auth.log*"),
        ("system", "var/log/secure*"),
        ("system", "var/log/dmesg*"),
        ("system", "var/log/boot.log*"),
        ("system", "var/log/journal/**/*"),
        ("system", "run/log/journal/**/*"),
        ("security", "var/log/audit/audit.log*"),
        ("crash", "var/lib/systemd/coredump/*"),
        ("crash", "var/crash/**/*"),
        ("context", "etc/os-release"),
        ("context", "etc/hostname"),
    ],
    "macos": [
        ("system", "private/var/log/system.log*"),
        ("system", "private/var/log/install.log*"),
        ("system", "private/var/db/diagnostics/**/*"),         # unified log (tracev3) ...
        ("system", "private/var/db/uuidtext/**/*"),            # ... and the string tables needed to decode it
        ("system", "private/var/db/timesync/*"),
        ("crash", "Library/Logs/DiagnosticReports/*"),
        ("crash", "Users/*/Library/Logs/DiagnosticReports/*"),
        ("system", "Library/Receipts/InstallHistory.plist"),
    ],
}

RULES_FULL = {
    "windows": [
        # --- crash / memory ---
        ("crash", "Windows/Memory.dmp"),                       # can be many GB: over --max-size-mb it is reported as not_collected
        ("crash", "Windows/LiveKernelReports/**/*.dmp"),
        ("crash", "Windows/LiveKernelReports/**/*.wer"),
        # --- registry hives (+ transaction logs, needed to replay uncommitted changes). Locked on a live system: use an image ---
        ("registry", "Windows/System32/config/SYSTEM"), ("registry", "Windows/System32/config/SYSTEM.LOG*"),
        ("registry", "Windows/System32/config/SOFTWARE"), ("registry", "Windows/System32/config/SOFTWARE.LOG*"),
        ("registry", "Windows/System32/config/SECURITY"), ("registry", "Windows/System32/config/SECURITY.LOG*"),
        ("registry", "Windows/System32/config/SAM"), ("registry", "Windows/System32/config/SAM.LOG*"),
        ("registry", "Windows/System32/config/DEFAULT"), ("registry", "Windows/System32/config/DEFAULT.LOG*"),
        ("registry", "Users/*/NTUSER.DAT"), ("registry", "Users/*/NTUSER.DAT.LOG*"),
        ("registry", "Users/*/AppData/Local/Microsoft/Windows/UsrClass.dat"), ("registry", "Users/*/AppData/Local/Microsoft/Windows/UsrClass.dat.LOG*"),
        # --- what ran, when ---
        ("execution", "Windows/Prefetch/*.pf"),
        ("execution", "Windows/AppCompat/Programs/Amcache.hve"), ("execution", "Windows/AppCompat/Programs/Amcache.hve.LOG*"),
        ("execution", "Windows/System32/sru/SRUDB.dat"),       # SRUM: per-app CPU / network / memory per hour
        ("execution", "Windows/System32/sru/*.log"),
        # --- persistence ---
        ("persistence", "Windows/System32/Tasks/**/*"),
        ("persistence", "Windows/Tasks/*"),
        ("persistence", "Windows/System32/drivers/etc/hosts"),
        # --- user activity ---
        ("activity", "Users/*/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/*.txt"),
        ("activity", "Users/*/AppData/Roaming/Microsoft/Windows/Recent/**/*"),
        ("activity", "Windows/System32/LogFiles/Sum/*"),       # User Access Logging (servers)
        # --- server / security software ---
        ("server", "inetpub/logs/LogFiles/**/*"),
        ("server", "Program Files/Microsoft SQL Server/*/MSSQL/Log/*"),
        ("server", "ProgramData/Microsoft/Windows Defender/Support/*"),
        ("server", "ProgramData/Microsoft/Windows Defender/Scans/History/**/*"),
    ],
    "linux": [
        ("persistence", "etc/crontab"), ("persistence", "etc/cron.d/*"), ("persistence", "etc/cron.hourly/*"),
        ("persistence", "etc/cron.daily/*"), ("persistence", "etc/cron.weekly/*"), ("persistence", "etc/cron.monthly/*"),
        ("persistence", "var/spool/cron/**/*"), ("persistence", "etc/anacrontab"),
        ("persistence", "etc/systemd/system/**/*.service"), ("persistence", "etc/systemd/system/**/*.timer"),
        ("persistence", "etc/rc.local"),
        ("context", "etc/hosts"), ("context", "etc/resolv.conf"), ("context", "etc/netplan/*"),
        ("context", "etc/passwd"), ("context", "etc/group"), ("context", "etc/sudoers"), ("context", "etc/sudoers.d/*"),
        ("context", "etc/machine-id"), ("context", "var/lib/logrotate/status"),
        ("context", "etc/kubernetes/*.conf"), ("context", "etc/kubernetes/manifests/*"),
        ("activity", "home/*/.bash_history"), ("activity", "home/*/.zsh_history"),
        ("activity", "root/.bash_history"), ("activity", "root/.zsh_history"),
        ("application", "home/*/.local/share/Steam/logs/*"), ("application", "home/*/.steam/steam/logs/*"),
        ("application", "home/*/steam-*.log"),
    ],
    "macos": [
        ("persistence", "Library/LaunchDaemons/*.plist"), ("persistence", "Library/LaunchAgents/*.plist"),
        ("persistence", "Users/*/Library/LaunchAgents/*.plist"),
        ("system", "private/var/db/powerlog/**/*"),            # Powerlog: app / power / battery history
        ("activity", ".fseventsd/*"), ("activity", "System/Volumes/Data/.fseventsd/*"),     # file-system change journal
        ("crash", "Library/Application Support/CrashReporter/*"), ("crash", "Users/*/Library/Application Support/CrashReporter/*"),
        ("context", "private/var/db/receipts/*.plist"),
        ("context", "Library/Preferences/SystemConfiguration/*.plist"),
        ("activity", "Users/*/.zsh_history"), ("activity", "Users/*/.bash_history"),
    ],
}


def add_profile_args(ap):
    ap.add_argument("--profile", choices=["fast", "full"], default=None,
                    help="scan size. fast: quick scan of the key crash/boot/failure logs. (not given): default scan, every well-known log location. "
                         "full: default + forensic artefacts (registry, Prefetch, Amcache, SRUM, scheduled tasks, shell history, launch agents, "
                         "server logs, full memory dumps)")


def rules_for(os_name, profile=None):
    """[(category, glob)] for one OS under a scan profile. profile None / 'default' = RULES; unknown OS -> []."""
    base = RULES.get(os_name, [])
    if profile == "fast": return list(RULES_FAST.get(os_name, base))
    if profile == "full": return list(base) + list(RULES_FULL.get(os_name, []))
    if profile in (None, "default"): return list(base)
    raise ValueError(f"unknown profile {profile!r}; choose from {PROFILES}")
