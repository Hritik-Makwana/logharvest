A Python tool for forensic collection of system and application logs. It detects connected volumes and devices, identifies the operating system, collects logs from known locations, hashes everything, and lets you browse the results in a simple web interface.

## Features

- Detects mounted volumes, disk images, extracted backups, and Android devices connected over `adb`
- Identifies the OS: Windows, Linux, macOS, iOS, Android
- Finds system and application logs using per-OS rules (`logharvest/rules.py`)
- Copies logs into a case folder and records SHA-256 hashes before and after copying
- Saves original timestamps (modified, accessed, changed/created) in a manifest
- Web viewer with sorting, filtering, log preview, and hash re-verification

## Requirements

- Python 3.12 or newer
- Optional: `psutil` (auto-detects mounted drives), `adb` (live Android collection)
- Optional: Use as sudo (administrator) to ensure permissions to read files are met and all log files on the system are found and readable. Without sudo, files like /var/log/auth.log and /var/log/journal/* are unreadable, so they show up as errors in the manifest.


## Install

```bash
pip install -e .            # core
pip install -e ".[full]"    # with psutil
```

## Usage

```bash
# List volumes and detected OS
logharvest detect --source /path/to/source

# Collect logs from specific sources
logharvest collect --case ./case001 --source /path/to/source /path/to/destination

# Collect from every auto-detected volume and connected adb device
# (Will also detect host operating system)
logharvest collect --case ./case001 --all

# Browse results at http://127.0.0.1:8765
logharvest view --case ./case001

# For sudo 
sudo "$(which logharvest)" collect/detect/view ...
```

## Case folder layout

```
case001/
├── evidence/       # copied log files, grouped by device
├── manifest.jsonl  # one record per file: paths, timestamps, size, SHA-256
└── audit.log       # who ran the tool, when, and on what
```

## Project structure

| File | Purpose |
|---|---|
| `detect.py` | Finds volumes/devices and identifies the OS |
| `rules.py` | Log locations for each OS |
| `collect.py` | Copying, hashing, manifest, and adb collection |
| `viewer.py` | Web interface |
| `cli.py` | Command-line entry point |

