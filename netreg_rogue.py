"""netreg_rogue.py -- pure rogue-AP / evil-twin heuristics over the scanned
network list.

The scan already collects every nearby network's name, security and (where the
OS exposes it) BSSID. This flags the two patterns most worth a second look on a
network you care about:

  * the SAME name advertised as both secured AND open -- a classic evil-twin
    lure, since an open clone of your network will silently capture anything
    that auto-joins "the strongest one";
  * the same name on several different BSSIDs -- usually a legit mesh/extender,
    but also how an impostor AP hides, so it's worth confirming.

Pure and unit-tested: analyze() takes the row dicts the scan window already
holds (NETWORK_COLUMNS keys) and returns human-readable alerts. No scanning,
no network. On macOS other networks' BSSIDs are hidden, so the multi-BSSID
check mostly fires on Windows/Linux; the secured-vs-open check works anywhere.
"""
from __future__ import annotations

import re

_CONNECTED_MARKER = re.compile(r"\s*\(connected\)\s*$", re.IGNORECASE)
# Values the scan may use for "no encryption".
_OPEN = {"", "open", "opn", "none", "--", "off", "no", "nopass"}


def _name(essid) -> str:
    """ESSID without the UI's '(connected)' marker, trimmed."""
    return _CONNECTED_MARKER.sub("", (essid or "").strip()).strip()


def _is_open(privacy) -> bool:
    return (privacy or "").strip().lower() in _OPEN


def analyze(networks) -> list[str]:
    """Return a list of alert strings for suspicious patterns (empty = clean).

    `networks` is an iterable of dicts with at least ESSID/Privacy/BSSID keys
    (as the scan window's rows have)."""
    by_name: dict[str, list[dict]] = {}
    for n in networks or []:
        name = _name(n.get("ESSID", ""))
        if not name:
            continue
        by_name.setdefault(name, []).append(n)

    alerts: list[str] = []
    for name, rows in sorted(by_name.items()):
        bssids = {(r.get("BSSID", "") or "").strip().lower() for r in rows}
        bssids.discard("")
        has_open = any(_is_open(r.get("Privacy", "")) for r in rows)
        has_secured = any(not _is_open(r.get("Privacy", "")) for r in rows)
        if has_open and has_secured:
            alerts.append(
                f"“{name}” appears BOTH secured and open — an open "
                f"clone of a known network is a classic evil-twin lure. Don't let "
                f"devices auto-join the open one.")
        elif len(bssids) >= 2:
            alerts.append(
                f"“{name}” is broadcast by {len(bssids)} access points "
                f"({', '.join(sorted(bssids))}). Usually a mesh or extender — "
                f"but confirm none of them is an impostor.")
    return alerts


if __name__ == "__main__":
    demo = [
        {"ESSID": "Home  (connected)", "Privacy": "WPA2", "BSSID": "aa:bb:cc:dd:ee:01"},
        {"ESSID": "Home", "Privacy": "Open", "BSSID": "aa:bb:cc:dd:ee:02"},
        {"ESSID": "Cafe", "Privacy": "WPA2", "BSSID": "11:22:33:44:55:66"},
        {"ESSID": "Cafe", "Privacy": "WPA2", "BSSID": "11:22:33:44:55:77"},
    ]
    for a in analyze(demo):
        print("ALERT:", a)
