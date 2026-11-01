"""VigilShield extra guards: USB, startup programs, hosts file.

All Windows-only actions are guarded so the module imports cleanly on
Linux/macOS. Every change is reversible:
  - USB scan never deletes, only reports.
  - Startup entries are backed up to data/startup_backup.json before disable.
  - Hosts restore uses the baseline backup copy.
"""
import hashlib
import json
import os

try:
    import psutil
except ImportError:  # pragma: no cover
    psutil = None

from vigilshield import common

HOSTS_BACKUP = os.path.join(common.DATA_DIR, "hosts_baseline.txt")
STARTUP_BACKUP = os.path.join(common.DATA_DIR, "startup_backup.json")


# ---------------------------------------------------------------- USB guard
def list_removable_drives():
    """Return mountpoints of removable drives (Windows). Empty elsewhere."""
    if not common.IS_WINDOWS or psutil is None:
        return []
    out = []
    try:
        for part in psutil.disk_partitions(all=False):
            opts = (part.opts or "").lower()
            if "removable" in opts:
                out.append(part.mountpoint)
    except Exception as e:
        common.log_event("WARN", "disk_partitions failed: %s" % e)
    return out


def scan_usb_drive(mountpoint):
    """Look for autorun.inf and executables at the drive root. Reports only."""
    findings = []
    try:
        entries = os.listdir(mountpoint)
    except Exception as e:
        return ["Could not read drive %s: %s" % (mountpoint, e)]
    names_lower = [e.lower() for e in entries]
    if "autorun.inf" in names_lower:
        findings.append("autorun.inf found at drive root (classic USB malware trick).")
    for e in entries:
        if e.lower().endswith((".exe", ".scr", ".bat", ".vbs", ".lnk")):
            findings.append("Executable at drive root: %s" % e)
    if not findings:
        findings.append("No autorun.inf or suspicious files at the drive root.")
    return findings


# ------------------------------------------------------------ startup guard
def _run_key_paths():
    return [
        (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKCU"),
        (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKLM"),
    ]


def list_startup_entries():
    """Return [{'name','command','location'}]. Windows only; [] elsewhere."""
    entries = []
    if not common.IS_WINDOWS:
        return entries
    try:
        import winreg
    except ImportError:
        return entries
    hives = [(winreg.HKEY_CURRENT_USER, "HKCU"),
             (winreg.HKEY_LOCAL_MACHINE, "HKLM")]
    for path in (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",):
        for hive, label in hives:
            try:
                key = winreg.OpenKey(hive, path)
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        entries.append({"name": name, "command": str(value),
                                        "location": "%s\\%s" % (label, path)})
                        i += 1
                    except OSError:
                        break
                winreg.CloseKey(key)
            except OSError:
                pass
    # Startup folder
    try:
        startup = os.path.join(os.environ.get("APPDATA", ""),
                               r"Microsoft\Windows\Start Menu\Programs\Startup")
        if os.path.isdir(startup):
            for f in os.listdir(startup):
                entries.append({"name": f, "command": os.path.join(startup, f),
                                "location": "Startup folder"})
    except Exception:
        pass
    return entries


def _looks_suspicious(entry):
    cmd = (entry.get("command") or "").lower()
    name = (entry.get("name") or "").lower()
    reasons = []
    for bad in ("\\temp\\", "\\tmp\\", "appdata\\local\\temp"):
        if bad in cmd:
            reasons.append("runs from a temp folder")
    if name.endswith((".exe", ".bat", ".vbs", ".js")) and len(name.split(".")[0]) >= 10:
        core = name.split(".")[0]
        if sum(c.isdigit() for c in core) >= 4 and sum(c.isalpha() for c in core) >= 4:
            reasons.append("random-looking name")
    return reasons


def flag_suspicious_startups(entries):
    out = []
    for e in entries:
        reasons = _looks_suspicious(e)
        if reasons:
            e2 = dict(e)
            e2["reasons"] = reasons
            out.append(e2)
    return out


def disable_startup_entry(entry):
    """Disable a Run-key entry after backing it up. Returns (ok, message)."""
    if not common.IS_WINDOWS:
        return False, "Startup guard needs Windows."
    loc = entry.get("location", "")
    name = entry.get("name", "")
    if "Startup folder" in loc:
        return False, "Delete the shortcut from the Startup folder manually."
    try:
        import winreg
    except ImportError:
        return False, "winreg unavailable."
    hive = winreg.HKEY_CURRENT_USER if loc.startswith("HKCU") else winreg.HKEY_LOCAL_MACHINE
    sub = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    try:
        # backup the value first
        bak = {}
        if os.path.exists(STARTUP_BACKUP):
            with open(STARTUP_BACKUP, encoding="utf-8") as f:
                bak = json.load(f)
        key = winreg.OpenKey(hive, sub, 0, winreg.KEY_READ)
        try:
            val, typ = winreg.QueryValueEx(key, name)
            bak[name] = {"command": str(val), "location": loc}
            with open(STARTUP_BACKUP, "w", encoding="utf-8") as f:
                json.dump(bak, f, indent=2)
        finally:
            winreg.CloseKey(key)
        key = winreg.OpenKey(hive, sub, 0, winreg.KEY_SET_VALUE)
        try:
            winreg.DeleteValue(key, name)
        finally:
            winreg.CloseKey(key)
        common.log_event("INFO", "disabled startup entry '%s' (backed up)" % name)
        return True, "Disabled '%s'. A backup was saved; it can be restored." % name
    except FileNotFoundError:
        return False, "Entry '%s' not found." % name
    except PermissionError:
        return False, ("Access denied - run VigilShield as administrator. "
                       "No changes were made.")
    except Exception as e:
        return False, "Could not disable entry: %s" % e


# -------------------------------------------------------------- hosts guard
def _hosts_path():
    if common.IS_WINDOWS:
        sysroot = os.environ.get("SystemRoot", r"C:\Windows")
        return os.path.join(sysroot, r"System32\drivers\etc\hosts")
    return "/etc/hosts"


def _sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def ensure_hosts_baseline():
    """Save a baseline copy on first run. Returns (ok, message)."""
    if os.path.exists(HOSTS_BACKUP):
        return True, "Baseline already exists."
    try:
        with open(_hosts_path(), "rb") as src, open(HOSTS_BACKUP, "wb") as dst:
            dst.write(src.read())
        common.log_event("INFO", "hosts baseline saved")
        return True, "Hosts baseline saved."
    except Exception as e:
        return False, "Could not read hosts file: %s" % e


def check_hosts():
    """Compare current hosts file with baseline. Returns dict."""
    ensure_hosts_baseline()
    try:
        cur = _sha256_file(_hosts_path())
        base = _sha256_file(HOSTS_BACKUP)
    except Exception as e:
        return {"ok": False, "changed": False, "message": str(e)}
    if cur == base:
        return {"ok": True, "changed": False,
                "message": "Hosts file unchanged since baseline."}
    # show added lines
    try:
        with open(_hosts_path(), encoding="utf-8", errors="replace") as f:
            cur_lines = [l.rstrip() for l in f]
        with open(HOSTS_BACKUP, encoding="utf-8", errors="replace") as f:
            base_lines = set(l.rstrip() for l in f)
        added = [l for l in cur_lines
                 if l.strip() and not l.strip().startswith("#")
                 and l not in base_lines]
    except Exception:
        added = []
    return {"ok": True, "changed": True,
            "message": "Hosts file CHANGED since baseline!",
            "added": added}


def restore_hosts():
    """Restore hosts file from baseline backup. Returns (ok, message)."""
    try:
        with open(HOSTS_BACKUP, "rb") as src:
            data = src.read()
        with open(_hosts_path(), "wb") as dst:
            dst.write(data)
        common.log_event("INFO", "hosts file restored from baseline")
        return True, "Hosts file restored from the saved baseline."
    except PermissionError:
        return False, ("Access denied - run VigilShield as administrator. "
                       "No changes were made.")
    except Exception as e:
        return False, "Could not restore hosts file: %s" % e
