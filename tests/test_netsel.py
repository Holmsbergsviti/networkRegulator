"""Unit tests for the network-selection gating (offline, no Tk/display).

The device list can only scan the Wi-Fi this machine is joined to, so the scan
window must only enable "View devices" for the connected network and must name
it honestly. These cover the pure decision helpers and the backend contract
they rely on. Run: python3 test_netsel.py
"""
# Ensure the repo root is importable when this suite is run from tests/.
import os as _os, sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))

import netreg_netsel as ns
import netreg_backend as b

fails, total = [], 0


def check(name, cond):
    global total
    total += 1
    print(("  ok   " if cond else "  FAIL ") + name)
    if not cond:
        fails.append(name)


SUF = b.MacBackend.CONNECTED_SUFFIX  # "  (connected)"

print("is_connected_row:")
check("the connected row is recognised", ns.is_connected_row("HomeWiFi" + SUF, SUF))
check("a different network is not", not ns.is_connected_row("Neighbour", SUF))
check("no suffix -> can't tell -> False (don't gate)",
      not ns.is_connected_row("HomeWiFi", ""))
check("empty-suffix case is False", ns.is_connected_row("HomeWiFi", "") is False)
check("non-string essid is safe", not ns.is_connected_row(None, SUF))

print("strip_suffix:")
check("marker stripped from the connected name",
      ns.strip_suffix("HomeWiFi" + SUF, SUF) == "HomeWiFi")
check("plain name unchanged", ns.strip_suffix("Neighbour", SUF) == "Neighbour")
check("no-suffix leaves it alone", ns.strip_suffix("HomeWiFi", "") == "HomeWiFi")
check("non-string -> empty string", ns.strip_suffix(None, SUF) == "")

print("backend connected-SSID contract:")
check("base backend exposes empty suffix", b.Backend.CONNECTED_SUFFIX == "")
check("base backend connected_ssid is ''", b.Backend().connected_ssid() == "")
check("mac backend marks the connected row", b.MacBackend.CONNECTED_SUFFIX.strip() == "(connected)")
check("mac backend exposes connected_ssid()", callable(getattr(b.MacBackend, "connected_ssid", None)))

print("gating decision (what the UI will do):")
# With a known suffix, only the connected row is actionable.
for essid, expect in [("Home" + SUF, True), ("Cafe", False), ("", False)]:
    gate = ns.is_connected_row(essid, SUF)
    check(f"essid {essid!r} -> view-devices enabled={expect}", gate is expect)
# With no suffix (e.g. a backend that can't tell), we never gate: any selection
# stays actionable so we don't break Linux/Windows.
check("no suffix -> never gated (stays actionable)",
      ns.is_connected_row("anything", "") is False)

print()
if fails:
    print(f"{len(fails)}/{total} FAILED: {fails}")
    raise SystemExit(1)
print(f"All {total} checks passed.")
