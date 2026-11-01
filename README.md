# VigilShield v2 — your PC's guard

VigilShield watches your Windows computer for signs of a cyber attack,
blocks connections to known-bad servers automatically, and warns you
immediately with a big red alert when it stops something.

**What it does NOT do:** it cannot predict an attack before it starts
(nothing can — not even the big security companies). It watches,
blocks known threats, and alerts you fast. It is not an antivirus
replacement — keep Windows Defender or your antivirus turned ON.

## Install (no technical skill needed)

You need a Windows 10 or Windows 11 PC.

1. Put **`VigilShield.exe`** and **`install.bat`** in the same folder.
2. Double-click **`install.bat`**.
3. Find **VigilShield** in your Start Menu, right-click it →
   **"Run as administrator"** (admin rights let it block attackers in
   the firewall; without admin it still watches and warns).

The installer also sets VigilShield to start with Windows and runs a
daily exposure scan at 9:00 AM.

### Build it yourself (optional)
1. Install Python from https://www.python.org/downloads/
   (tick **"Add python.exe to PATH"** on the first screen).
2. Double-click **`build.bat`** and wait for DONE.
3. Your program is at `dist\VigilShield.exe`.

## What's new in v2

- **Guardian mascot interface** — the cyber-girl Guardian sits at the
  center of the dashboard. Blue = protected, red = threat blocked,
  pulsing cyan = scanning.
- **Live threat map** — blocked attacker servers appear as markers on
  a world map (positions approximate), with a radar sweep.
- **Attack timeline** — your recent security events as a visual strip.
- **USB guard** — warns the second a USB drive is plugged in and
  offers to scan it (autorun.inf and suspicious files at the drive root).
- **Startup guard** — lists programs that start with Windows, flags the
  suspicious ones, disables them with one click (backup saved first).
- **Hosts-file guard** — watches for hijacks of your hosts file, shows
  what changed, restores the clean version with one click.
- **Quarantine manager** — restore or permanently delete quarantined files.
- **Whitelist** — one click to never block/flag a trusted IP or program again.
- **One-click installer + uninstaller** — everything VigilShield changes
  (firewall rules, scheduled tasks, shortcuts) is removed by
  `install.bat uninstall`.

## Daily use

- **Guardian blue / pulsing / red** — your threat level right now.
- **Exposure scan** — plain-language report of where your PC is exposed
  (firewall off? risky ports open?) so you can fix it *before* attackers come.
- **Update threat list** — downloads the latest known-attacker servers
  (needs internet). Do this weekly.
- **Quarantine manager / Whitelist / Startup guard / Hosts file check** —
  see the buttons on the dashboard.
- **Remove firewall rules** — undoes every block VigilShield ever added.

## Files (installed)

- `%LOCALAPPDATA%\VigilShield\logs\events.log` — everything it saw and did.
- `%LOCALAPPDATA%\VigilShield\quarantine\` — suspicious files are *moved*
  here, never deleted.
- `%LOCALAPPDATA%\VigilShield\data\last_exposure_report.txt` — latest
  daily scan report.

## Honesty notes

- Keep **Windows Defender** (or your antivirus) turned ON.
- No software stops 100% of attacks. VigilShield blocks *known*
  threats fast and warns you about suspicious behaviour.
- If an alert appears for a program you trust, whitelist it — but only
  if you're sure.

## Uninstall

Run **`install.bat uninstall`**. It removes the firewall rules,
scheduled tasks, shortcut, and program folder.
