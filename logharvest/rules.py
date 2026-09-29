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
        ("system", "var/log/**/*"),
        ("system", "var/log/journal/**/*.journal*"),
        ("application", "home/*/.local/share/**/*.log"),
        ("application", "home/*/.cache/**/*.log"),
        ("application", "root/.local/share/**/*.log"),
        ("application", "opt/**/*.log"),
    ],
    "macos": [
        ("system", "private/var/log/**/*"),
        ("system", "private/var/db/diagnostics/**/*"),   # Unified Logging tracev3
        ("system", "Library/Logs/**/*"),
        ("application", "Users/*/Library/Logs/**/*"),
    ],
    "ios": [
        ("system", "private/var/logs/**/*"),
        ("system", "private/var/db/diagnostics/**/*"),
        ("system", "private/var/mobile/Library/Logs/**/*"),
        ("application", "private/var/mobile/Containers/Data/Application/*/Library/Caches/**/*.log"),
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
