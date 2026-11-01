"""VigilShield blocklist updater.

Downloads public threat-intel text feeds and merges them into
data/blocklist.txt. Feeds used (all free, no key needed):
  - abuse.ch URLhaus online-URL IPs:  https://urlhaus.abuse.ch/downloads/text/
  - abuse.ch Feodo Tracker IPs:       https://feodotracker.abuse.ch/downloads/ipblocklist.txt
  - FireHOL level1:                   https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset

On any failure (offline, feed down, parse error) we keep the bundled
list, log the problem, and report the list's age ("staleness") instead
of crashing. The bundled list is honest sample data; real protection
comes from running the updater regularly.
"""
import datetime
import os

try:
    import requests
except ImportError:
    requests = None

from vigilshield import common

FEEDS = [
    ("urlhaus", "https://urlhaus.abuse.ch/downloads/text/"),
    ("feodotracker", "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"),
    ("firehol_level1",
     "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/"
     "firehol_level1.netset"),
]

META_PATH = os.path.join(common.DATA_DIR, "blocklist_meta.txt")


def _parse_ips(text):
    ips = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        token = line.split()[0].split("/")[0]  # strip CIDR suffix
        parts = token.split(".")
        if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255
                                   for p in parts):
            ips.add(token)
    return ips


def _write_meta(source_counts):
    try:
        with open(META_PATH, "w", encoding="utf-8") as f:
            f.write("updated: %s\n" % common.now_stamp())
            for name, count in source_counts:
                f.write("%s: %d ips\n" % (name, count))
    except Exception:
        pass


def update():
    """Fetch feeds, merge into blocklist.txt. Returns (ok, message)."""
    if requests is None:
        msg = "requests library not installed; cannot update."
        common.log_event("WARN", msg)
        return False, msg

    merged = set()
    counts = []
    any_ok = False
    for name, url in FEEDS:
        try:
            r = requests.get(url, timeout=25,
                             headers={"User-Agent": "VigilShield/1.0"})
            r.raise_for_status()
            ips = _parse_ips(r.text)
            counts.append((name, len(ips)))
            merged |= ips
            any_ok = True
            common.log_event("INFO", "feed %s: %d ips" % (name, len(ips)))
        except Exception as e:
            counts.append((name, 0))
            common.log_event("WARN", "feed %s failed: %s" % (name, e))

    if not any_ok or not merged:
        msg = ("Could not reach any threat feed (offline?). "
               "Keeping the existing blocklist.")
        common.log_event("WARN", msg)
        return False, msg + " " + staleness_note()

    # keep any manually-added entries that are not comments
    existing = common.load_blocklist()
    merged |= existing
    try:
        with open(common.BLOCKLIST_PATH, "w", encoding="utf-8") as f:
            f.write("# VigilShield blocklist - updated %s\n" % common.now_stamp())
            f.write("# Sources: %s\n" % ", ".join(n for n, _ in FEEDS))
            for ip in sorted(merged):
                f.write(ip + "\n")
    except Exception as e:
        return False, "Could not write blocklist: %s" % e

    _write_meta(counts)
    msg = "Threat list updated: %d blocked IPs." % len(merged)
    common.log_event("INFO", msg)
    return True, msg


def staleness_note():
    """Human-readable note about how fresh the blocklist is."""
    try:
        with open(META_PATH, encoding="utf-8") as f:
            first = f.readline().strip()
        if first.startswith("updated:"):
            return "Last successful update: %s." % first.split("updated:")[1].strip()
    except Exception:
        pass
    return "The list has never been updated from the internet (bundled samples only)."
