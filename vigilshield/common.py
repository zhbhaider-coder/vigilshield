"""VigilShield shared helpers: paths, logging, platform guards.

Cross-platform. Windows-only behavior lives in the modules that need it
and is always guarded so imports never crash on Linux/macOS.

When running as a PyInstaller onefile bundle (frozen), writable files
(logs, quarantine, blocklist, whitelist) live in the user's app-data dir
because the bundle extracts to a read-only temp folder. Read-only assets
(mascot PNGs, bundled sample blocklist) are read via resource_path().
"""
import datetime
import os
import shutil
import sys

IS_WINDOWS = sys.platform == "win32"
FROZEN = getattr(sys, "frozen", False)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))  # the package dir


def resource_path(*parts):
    """Path to a read-only bundled asset (works in dev and in the exe)."""
    if FROZEN:
        base = getattr(sys, "_MEIPASS", BASE_DIR)
        return os.path.join(base, "vigilshield", "data", *parts)
    return os.path.join(BASE_DIR, "data", *parts)


def _writable_base():
    if IS_WINDOWS:
        appdata = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
        return os.path.join(appdata, "VigilShield")
    return os.path.join(os.path.expanduser("~"), ".vigilshield")


if FROZEN:
    RUNTIME_DIR = _writable_base()
else:
    RUNTIME_DIR = BASE_DIR

DATA_DIR = os.path.join(RUNTIME_DIR, "data")
LOG_DIR = os.path.join(RUNTIME_DIR, "logs")
QUARANTINE_DIR = os.path.join(RUNTIME_DIR, "quarantine")
BLOCKLIST_PATH = os.path.join(DATA_DIR, "blocklist.txt")
WHITELIST_PATH = os.path.join(DATA_DIR, "whitelist.txt")
EVENTS_LOG = os.path.join(LOG_DIR, "events.log")

for _d in (DATA_DIR, LOG_DIR, QUARANTINE_DIR):
    os.makedirs(_d, exist_ok=True)

# seed the writable blocklist from the bundled sample on first run
try:
    if not os.path.exists(BLOCKLIST_PATH):
        seed = resource_path("blocklist.txt")
        if os.path.exists(seed):
            shutil.copy(seed, BLOCKLIST_PATH)
except Exception:
    pass


def now_stamp():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def log_event(kind, message):
    """Append a timestamped line to events.log. Never raises."""
    try:
        with open(EVENTS_LOG, "a", encoding="utf-8") as f:
            f.write("%s [%s] %s\n" % (now_stamp(), kind, message))
    except Exception:
        pass


def load_blocklist():
    """Return a set of blocked IP strings from blocklist.txt (ignores comments)."""
    ips = set()
    try:
        with open(BLOCKLIST_PATH, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    ips.add(line.split()[0])
    except FileNotFoundError:
        log_event("WARN", "blocklist.txt not found; using empty list")
    return ips


def require_admin_note():
    return ("VigilShield needs administrator rights for auto-blocking. "
            "Right-click VigilShield.exe and choose 'Run as administrator'.")


def load_whitelist():
    """Return a set of whitelisted IP/program strings (ignores comments)."""
    items = set()
    try:
        with open(WHITELIST_PATH, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    items.add(line.split()[0].lower())
    except FileNotFoundError:
        pass
    return items


def add_whitelist(item):
    """Add an IP or program name to the whitelist. Returns (ok, message)."""
    item = (item or "").strip().lower()
    if not item:
        return False, "Nothing to whitelist."
    items = load_whitelist()
    if item in items:
        return True, "'%s' is already whitelisted." % item
    try:
        with open(WHITELIST_PATH, "a", encoding="utf-8") as f:
            f.write(item + "\n")
        log_event("INFO", "whitelisted '%s'" % item)
        return True, "Whitelisted '%s'. It will no longer be blocked or flagged." % item
    except Exception as e:
        return False, "Could not update whitelist: %s" % e


def remove_whitelist(item):
    """Remove an entry from the whitelist. Returns (ok, message)."""
    item = (item or "").strip().lower()
    items = load_whitelist()
    if item not in items:
        return False, "'%s' is not whitelisted." % item
    items.discard(item)
    try:
        with open(WHITELIST_PATH, "w", encoding="utf-8") as f:
            for i in sorted(items):
                f.write(i + "\n")
        log_event("INFO", "removed '%s' from whitelist" % item)
        return True, "Removed '%s' from the whitelist." % item
    except Exception as e:
        return False, "Could not update whitelist: %s" % e


HONESTY_NOTE = (
    "VigilShield cannot predict cyber attacks before they happen, and it is "
    "not an antivirus replacement. It watches your PC, blocks connections to "
    "known attacker servers, and alerts you fast. Use it alongside "
    "Windows Defender or your antivirus."
)
