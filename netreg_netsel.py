"""netreg_netsel.py -- pure helpers for the scan window's network-selection
gating.

The device list can only scan the Wi-Fi this machine is actually joined to, so
the UI must only offer "View devices" for the connected network and must name
that network honestly. The backend marks the connected row's ESSID with a
suffix (MacBackend.CONNECTED_SUFFIX, e.g. "  (connected)"). These helpers decide
whether a given ESSID value is that connected row and strip the marker for
display. Kept out of the Tk module so they're unit-testable without a display.
"""
from __future__ import annotations


def is_connected_row(essid_value, suffix: str) -> bool:
    """True when `essid_value` is the connected network's row. Only meaningful
    when the backend provides a non-empty `suffix`; with no suffix we can't tell
    which network is connected, so this returns False (callers then don't gate)."""
    return bool(suffix) and isinstance(essid_value, str) and essid_value.endswith(suffix)


def strip_suffix(essid, suffix: str) -> str:
    """The ESSID without the connected marker, for a clean display name."""
    if suffix and isinstance(essid, str) and essid.endswith(suffix):
        return essid[: -len(suffix)].strip()
    return essid if isinstance(essid, str) else ""
