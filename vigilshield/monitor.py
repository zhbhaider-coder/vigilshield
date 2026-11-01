"""VigilShield core monitor.

Watches (via psutil):
  1. Outbound network connections -> remote IP checked against the
     local threat blocklist.
  2. Newly started processes -> flags ones launched from Temp/AppData
     with suspicious traits (double extensions, random-looking names).
  3. Ransomware behavior -> canary files in Documents/Desktop; detects
     mass renames/modifications in a short window.

Emits events as dicts via a callback. Runs in its own thread.
All Windows-only actions are the blocker's job; the monitor only
detects and reports.
"""
import hashlib
import os
import random
import string
import threading
import time

try:
    import psutil
except ImportError:  # pragma: no cover - guarded at runtime
    psutil = None

from vigilshield import common

SUSPICIOUS_DIRS = ("\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\",
                   "/tmp/", "/var/tmp/")
DOUBLE_EXTS = (".exe.exe", ".pdf.exe", ".doc.exe", ".jpg.exe", ".zip.exe",
               ".txt.exe", ".png.exe")
CANARY_NAMES = ("~vigil_canary_1.docx", "~vigil_canary_2.xlsx",
                "~vigil_canary_3.pdf")
RENAME_WINDOW_SEC = 60
RENAME_ALERT_THRESHOLD = 15


def _looks_random(name):
    core = os.path.splitext(name)[0]
    if len(core) < 8:
        return False
    letters = sum(c.isalpha() for c in core)
    digits = sum(c.isdigit() for c in core)
    return letters > 4 and digits > 4


def _canary_dirs():
    home = os.path.expanduser("~")
    cands = [os.path.join(home, "Documents"), os.path.join(home, "Desktop"),
             home]
    return [d for d in cands if os.path.isdir(d)]


class Monitor(threading.Thread):
    def __init__(self, on_event, poll_interval=3.0):
        super().__init__(daemon=True)
        self.on_event = on_event
        self.poll_interval = poll_interval
        self._stop = threading.Event()
        self._known_pids = set()
        self._canary_hashes = {}
        self._rename_log = []  # list of (timestamp, path)
        self._scanned_connections = 0
        self._known_drives = set()
        self._place_canaries()

    # ---- canary files -------------------------------------------------
    def _place_canaries(self):
        for d in _canary_dirs():
            for name in CANARY_NAMES:
                path = os.path.join(d, name)
                try:
                    if not os.path.exists(path):
                        blob = "".join(random.choice(string.ascii_letters)
                                       for _ in range(256)).encode()
                        with open(path, "wb") as f:
                            f.write(b"VIGILSHIELD-CANARY-DO-NOT-TOUCH\n" + blob)
                    with open(path, "rb") as f:
                        self._canary_hashes[path] = hashlib.sha256(f.read()).hexdigest()
                except Exception as e:
                    common.log_event("WARN", "canary setup failed for %s: %s" % (path, e))
        if self._canary_hashes:
            common.log_event("INFO", "placed %d canary files" % len(self._canary_hashes))

    def _check_canaries(self):
        now = time.time()
        for path, old in list(self._canary_hashes.items()):
            try:
                if not os.path.exists(path):
                    self._rename_log.append((now, path + " [DELETED]"))
                else:
                    with open(path, "rb") as f:
                        new = hashlib.sha256(f.read()).hexdigest()
                    if new != old:
                        self._rename_log.append((now, path + " [MODIFIED]"))
                        self._canary_hashes[path] = new
            except Exception:
                pass
        # mass-change detection inside the window
        self._rename_log = [(t, p) for t, p in self._rename_log
                            if now - t < RENAME_WINDOW_SEC]
        if len(self._rename_log) >= RENAME_ALERT_THRESHOLD:
            paths = [p for _, p in self._rename_log]
            self._rename_log.clear()
            self._emit("ransomware",
                       "Mass file changes detected (%d files in %d seconds). "
                       "This looks like ransomware encrypting files." % (
                           len(paths), RENAME_WINDOW_SEC),
                       detail="; ".join(paths[:5]))

    # ---- connection watch ----------------------------------------------
    def _check_connections(self, blocklist):
        if psutil is None:
            return
        whitelist = common.load_whitelist()
        try:
            conns = psutil.net_connections(kind="inet")
        except Exception as e:
            common.log_event("WARN", "net_connections failed: %s" % e)
            return
        for c in conns:
            if not c.raddr:
                continue
            self._scanned_connections += 1
            ip = c.raddr.ip
            if ip in blocklist and ip.lower() not in whitelist:
                try:
                    proc = psutil.Process(c.pid) if c.pid else None
                    pname = proc.name() if proc else "unknown"
                except Exception:
                    pname = "unknown"
                self._emit("blocklist_hit",
                           "Connection to known-threat IP %s blocked (process: %s, pid %s)." % (
                               ip, pname, c.pid),
                           detail=ip, pid=c.pid, process=pname)

    # ---- process watch ---------------------------------------------------
    def _check_processes(self):
        if psutil is None:
            return
        whitelist = common.load_whitelist()
        try:
            procs = list(psutil.process_iter(["pid", "name", "exe", "cmdline"]))
        except Exception:
            return
        current = set()
        for p in procs:
            try:
                pid = p.info["pid"]
                current.add(pid)
                if pid in self._known_pids:
                    continue
                exe = (p.info.get("exe") or "").lower()
                name = (p.info.get("name") or "")
                if name.lower() in whitelist:
                    continue
                reasons = []
                if any(d in exe for d in SUSPICIOUS_DIRS):
                    reasons.append("launched from a temp folder")
                if name.lower().endswith(DOUBLE_EXTS):
                    reasons.append("suspicious double extension")
                if _looks_random(name):
                    reasons.append("random-looking file name")
                if reasons:
                    self._emit("suspicious_process",
                               "Suspicious new process: %s (pid %s) - %s." % (
                                   name, pid, ", ".join(reasons)),
                               detail=exe, pid=pid, process=name)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            except Exception:
                continue
        self._known_pids = current

    # ---- USB drive watch ------------------------------------------------
    def _check_usb(self):
        try:
            from vigilshield import guards
        except Exception:
            return
        try:
            drives = set(guards.list_removable_drives())
        except Exception:
            return
        new = drives - self._known_drives
        self._known_drives = drives
        for d in sorted(new):
            self._emit("usb_inserted",
                       "USB drive connected: %s. Offer to scan it for threats." % d,
                       detail=d)

    # ---- thread loop ------------------------------------------------------
    def _emit(self, kind, message, **extra):
        common.log_event(kind.upper(), message)
        try:
            self.on_event({"kind": kind, "message": message,
                           "time": common.now_stamp(), **extra})
        except Exception as e:
            common.log_event("WARN", "event callback failed: %s" % e)

    def stop(self):
        self._stop.set()

    @property
    def stats(self):
        return {"connections_scanned": self._scanned_connections,
                "canaries": len(self._canary_hashes)}

    def run(self):
        common.log_event("INFO", "monitor started")
        # seed known pids so we don't flag everything at startup
        if psutil is not None:
            try:
                self._known_pids = set(psutil.pids())
            except Exception:
                pass
        # seed known drives so already-plugged USB sticks don't alert
        try:
            from vigilshield import guards
            self._known_drives = set(guards.list_removable_drives())
        except Exception:
            pass
        while not self._stop.is_set():
            try:
                blocklist = common.load_blocklist()
                self._check_connections(blocklist)
                self._check_processes()
                self._check_canaries()
                self._check_usb()
            except Exception as e:
                common.log_event("ERROR", "monitor loop error: %s" % e)
            self._stop.wait(self.poll_interval)
        common.log_event("INFO", "monitor stopped")
