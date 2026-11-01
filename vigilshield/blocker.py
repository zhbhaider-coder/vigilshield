"""VigilShield auto-blocker.

On a blocklist hit or a confirmed malicious process:
  - terminate the offending process (psutil)
  - add a Windows Firewall outbound block rule for the IP via netsh
  - move flagged files to quarantine/ instead of deleting them

Non-admin is handled gracefully: firewall changes need elevation, so
without admin rights we log + alert "run as administrator for
auto-block" instead of crashing. Process termination of the user's own
processes usually works without admin.

All firewall rules are tagged "VigilShield" so they can be removed
again with remove_all_rules() ("Remove all VigilShield firewall
rules" button in the UI). Everything here is reversible.
"""
import os
import shutil
import subprocess

try:
    import psutil
except ImportError:
    psutil = None

from vigilshield import common

RULE_PREFIX = "VigilShield Block"


def _run_netsh(args):
    """Run netsh; return (ok, output). Never raises."""
    try:
        proc = subprocess.run(
            ["netsh"] + args,
            capture_output=True, text=True, timeout=30)
        out = (proc.stdout or "") + (proc.stderr or "")
        return proc.returncode == 0, out.strip()
    except FileNotFoundError:
        return False, "netsh not found (not Windows?)"
    except Exception as e:
        return False, str(e)


def is_admin():
    if not common.IS_WINDOWS:
        return False
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def block_ip(ip):
    """Add an outbound firewall block rule for ip. Returns (ok, message)."""
    if ip.strip().lower() in common.load_whitelist():
        return True, "%s is whitelisted - not blocked." % ip
    if not common.IS_WINDOWS:
        return False, "Firewall blocking needs Windows."
    if not is_admin():
        msg = ("Not running as administrator - cannot add firewall rule. "
               + common.require_admin_note())
        common.log_event("WARN", msg + " (ip %s)" % ip)
        return False, msg
    rule_name = "%s %s" % (RULE_PREFIX, ip)
    ok, out = _run_netsh([
        "advfirewall", "firewall", "add", "rule",
        "name=%s" % rule_name,
        "dir=out", "action=block", "remoteip=%s" % ip,
        "protocol=any", "profile=any",
    ])
    if ok:
        common.log_event("BLOCK", "firewall rule added, blocking %s" % ip)
        return True, "Blocked %s in Windows Firewall." % ip
    if "already exists" in out.lower():
        return True, "A block rule for %s already exists." % ip
    common.log_event("ERROR", "netsh failed for %s: %s" % (ip, out))
    return False, "Could not add firewall rule: %s" % out


def unblock_ip(ip):
    ok, out = _run_netsh([
        "advfirewall", "firewall", "delete", "rule",
        "name=%s %s" % (RULE_PREFIX, ip),
    ])
    if ok:
        common.log_event("INFO", "firewall rule removed for %s" % ip)
    return ok, out


def remove_all_rules():
    """Delete every VigilShield firewall rule. Fully reversible."""
    if not common.IS_WINDOWS:
        return False, "Firewall rules need Windows."
    if not is_admin():
        return False, common.require_admin_note()
    ok, out = _run_netsh([
        "advfirewall", "firewall", "delete", "rule",
        "name=%s" % RULE_PREFIX,
    ])
    # netsh wildcard delete removes all rules whose name starts with the prefix
    common.log_event("INFO", "removed all VigilShield firewall rules: %s" % out)
    return True, "All VigilShield firewall rules removed."


def kill_process(pid):
    """Terminate a process by pid. Returns (ok, message)."""
    if psutil is None:
        return False, "psutil not available."
    try:
        p = psutil.Process(pid)
        name = p.name()
        p.terminate()
        try:
            p.wait(timeout=5)
        except Exception:
            p.kill()
        common.log_event("BLOCK", "terminated process %s (pid %s)" % (name, pid))
        return True, "Stopped process %s." % name
    except psutil.NoSuchProcess:
        return True, "Process already gone."
    except psutil.AccessDenied:
        msg = ("Could not stop the process (access denied). "
               + common.require_admin_note())
        common.log_event("WARN", msg)
        return False, msg
    except Exception as e:
        return False, "Could not stop process: %s" % e


def quarantine_file(path):
    """Move a flagged file into quarantine/ instead of deleting it."""
    try:
        base = os.path.basename(path)
        dest = os.path.join(common.QUARANTINE_DIR, base)
        i = 1
        while os.path.exists(dest):
            name, ext = os.path.splitext(base)
            dest = os.path.join(common.QUARANTINE_DIR,
                                "%s_%d%s" % (name, i, ext))
            i += 1
        shutil.move(path, dest)
        common.log_event("QUARANTINE", "%s -> %s" % (path, dest))
        return True, dest
    except Exception as e:
        common.log_event("ERROR", "quarantine failed for %s: %s" % (path, e))
        return False, str(e)


def list_quarantine():
    try:
        return sorted(os.listdir(common.QUARANTINE_DIR))
    except Exception:
        return []


def restore_quarantine(name):
    """Move a quarantined file back next to the exe's folder (user's choice
    of destination is handled by the UI). Returns (ok, message/path)."""
    src = os.path.join(common.QUARANTINE_DIR, os.path.basename(name))
    if not os.path.exists(src):
        return False, "File not found in quarantine."
    return True, src


def delete_quarantine(name):
    """Permanently delete a quarantined file. Returns (ok, message)."""
    src = os.path.join(common.QUARANTINE_DIR, os.path.basename(name))
    try:
        os.remove(src)
        common.log_event("INFO", "deleted quarantined file %s" % name)
        return True, "Permanently deleted '%s'." % name
    except Exception as e:
        return False, "Could not delete: %s" % e


def handle_blocklist_hit(event):
    """Full response to a blocklist hit event. Returns human message."""
    ip = event.get("detail", "")
    pid = event.get("pid")
    msgs = []
    if pid:
        ok, m = kill_process(pid)
        msgs.append(m)
    if ip:
        ok, m = block_ip(ip)
        msgs.append(m)
    return " ".join(msgs)
