"""VigilShield exposure scanner - the honest "pre-attack warning".

This does NOT predict attacks (nothing can). It tells you, in plain
language, where your computer is exposed RIGHT NOW so you can fix it
BEFORE attackers come: outdated Windows, firewall off, Defender
real-time protection off, risky ports listening (RDP/SMB), UAC off.

Output: a list of findings, each a dict:
  {"level": "ok"|"warn"|"risk", "title": str, "detail": str, "fix": str}
Windows-only checks are skipped gracefully on other platforms.
"""
import platform
import subprocess

try:
    import psutil
except ImportError:
    psutil = None

from vigilshield import common

RISKY_PORTS = {
    23: ("Telnet", "Unencrypted remote login. Turn it off."),
    135: ("RPC", "Windows RPC exposed. Block at the firewall if not needed."),
    139: ("NetBIOS", "Old file-sharing protocol. Disable if unused."),
    445: ("SMB", "File sharing. Targeted by ransomware worms - block inbound if you don't share files."),
    1433: ("MS SQL", "Database port open. Restrict to trusted hosts."),
    3306: ("MySQL", "Database port open. Restrict to trusted hosts."),
    3389: ("RDP Remote Desktop", "Remote access. A top brute-force target - use a strong password or disable."),
    5900: ("VNC", "Remote desktop. A common brute-force target - disable if unused."),
}


def _ps(cmd):
    """Run a PowerShell command, return stdout ('' on failure). Never raises."""
    try:
        p = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd],
            capture_output=True, text=True, timeout=30)
        return (p.stdout or "").strip()
    except Exception:
        return ""


def _netsh_state():
    try:
        p = subprocess.run(["netsh", "advfirewall", "show", "allprofiles",
                            "state"], capture_output=True, text=True,
                           timeout=30)
        return (p.stdout or "") + (p.stderr or "")
    except Exception:
        return ""


def scan():
    findings = []

    # ---- OS version ---------------------------------------------------
    if common.IS_WINDOWS:
        ver = platform.version()
        findings.append({
            "level": "ok" if int(platform.win32_ver()[1].split(".")[0]) >= 10 else "warn",
            "title": "Windows version: %s" % platform.platform(),
            "detail": "Build %s." % ver,
            "fix": ("Keep Windows Update turned on so security patches install "
                    "automatically."),
        })
    else:
        findings.append({
            "level": "warn",
            "title": "Not running on Windows",
            "detail": "Exposure checks for firewall/Defender need Windows.",
            "fix": "Run this scan on your Windows PC.",
        })
        return findings

    # ---- firewall ------------------------------------------------------
    state = _netsh_state().lower()
    if "on" in state and "off" not in state.replace("turn off", ""):
        findings.append({"level": "ok", "title": "Windows Firewall is ON",
                         "detail": "All profiles report ON.",
                         "fix": "Leave it on."})
    elif "off" in state:
        findings.append({"level": "risk", "title": "Windows Firewall is OFF",
                         "detail": "Your PC accepts unsolicited network traffic.",
                         "fix": "Turn it on: Settings > Privacy & Security > Windows Security > Firewall."})
    else:
        findings.append({"level": "warn", "title": "Could not read firewall status",
                         "detail": "netsh gave no clear answer.",
                         "fix": "Check it manually in Windows Security."})

    # ---- defender real-time protection ----------------------------------
    rt = _ps("(Get-MpComputerStatus).RealTimeProtectionEnabled")
    if rt.lower() == "true":
        findings.append({"level": "ok",
                         "title": "Defender real-time protection is ON",
                         "detail": "Windows Defender is actively watching.",
                         "fix": "VigilShield works alongside it - keep both on."})
    elif rt.lower() == "false":
        findings.append({"level": "risk",
                         "title": "Defender real-time protection is OFF",
                         "detail": "No built-in antivirus is watching right now.",
                         "fix": "Turn it on: Windows Security > Virus & threat protection > Manage settings."})
    else:
        findings.append({"level": "warn",
                         "title": "Could not read Defender status",
                         "detail": "PowerShell query failed.",
                         "fix": "Open Windows Security and check manually."})

    # ---- UAC -------------------------------------------------------------
    uac = _ps("(Get-ItemProperty HKLM:\\SOFTWARE\\Microsoft\\Windows\\"
              "CurrentVersion\\Policies\\System).EnableLUA")
    if uac == "1":
        findings.append({"level": "ok", "title": "User Account Control is ON",
                         "detail": "Programs must ask before changing the system.",
                         "fix": "Leave it on."})
    elif uac == "0":
        findings.append({"level": "risk", "title": "User Account Control is OFF",
                         "detail": "Malware can change system settings silently.",
                         "fix": "Turn it on: search 'UAC' > Change User Account Control settings."})
    else:
        findings.append({"level": "warn", "title": "Could not read UAC status",
                         "detail": "", "fix": "Check it manually (search 'UAC')."})

    # ---- listening ports ---------------------------------------------------
    if psutil is not None:
        try:
            listening = {}
            for c in psutil.net_connections(kind="inet"):
                if c.status == "LISTEN" and c.laddr:
                    listening[c.laddr.port] = True
            risky = [(p, RISKY_PORTS[p]) for p in sorted(listening)
                     if p in RISKY_PORTS]
            if risky:
                for port, (name, fix) in risky:
                    findings.append({
                        "level": "risk",
                        "title": "Risky port open: %d (%s)" % (port, name),
                        "detail": "Something on your PC is listening on this port.",
                        "fix": fix})
            else:
                findings.append({"level": "ok",
                                 "title": "No risky ports listening",
                                 "detail": "%d ports listening, none high-risk." % len(listening),
                                 "fix": "Nothing to do."})
        except Exception as e:
            findings.append({"level": "warn",
                             "title": "Could not list open ports",
                             "detail": str(e), "fix": "Run as administrator and retry."})

    common.log_event("INFO", "exposure scan: %d findings" % len(findings))
    return findings


def render_text(findings):
    """Plain-language report for the UI / console."""
    lines = ["VIGILSHIELD EXPOSURE REPORT", "=" * 40,
             "Fix the RISKS below BEFORE attackers come.",
             "This scan cannot predict attacks - it shows where you are exposed right now.", ""]
    for f in findings:
        tag = {"ok": "[OK]", "warn": "[CHECK]", "risk": "[RISK]"}[f["level"]]
        lines.append("%s %s" % (tag, f["title"]))
        if f["detail"]:
            lines.append("    %s" % f["detail"])
        lines.append("    Fix: %s" % f["fix"])
        lines.append("")
    risks = sum(1 for f in findings if f["level"] == "risk")
    lines.append("Summary: %d risk(s) found. %s" % (
        risks, "Your PC needs attention." if risks else "Looking good - keep everything updated."))
    return "\n".join(lines)
