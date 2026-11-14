"""
mac_native.py -- macOS CoreWLAN / CoreLocation access via pyobjc.

Everything here is best-effort and soft-failing: if pyobjc or the frameworks
aren't available, or a call is denied, functions return None/"" and the caller
falls back to the system_profiler path. This is what lets the packaged .app
read real Wi-Fi names once Location Services is granted — a plain script or a
denied app simply degrades to the old behavior.
"""
from __future__ import annotations


def _band_from_channel(ch) -> str:
    try:
        ch = int(ch)
    except Exception:
        return "?"
    if 1 <= ch <= 14:
        return "2.4"
    if ch >= 36:
        return "5"
    return "?"


def request_location(timeout: float = 2.5) -> None:
    """Trigger the Location-permission prompt and register the app in the
    Location Services list. No-op (silently) if CoreLocation isn't usable."""
    try:
        import CoreLocation
        import Foundation
    except Exception:
        return
    try:
        mgr = CoreLocation.CLLocationManager.alloc().init()
        try:
            mgr.requestWhenInUseAuthorization()
        except Exception:
            pass
        # Pump a runloop briefly so the system prompt can be presented.
        try:
            Foundation.NSRunLoop.currentRunLoop().runUntilDate_(
                Foundation.NSDate.dateWithTimeIntervalSinceNow_(timeout)
            )
        except Exception:
            pass
    except Exception:
        return


def connected_ssid() -> str:
    """Current network's SSID via CoreWLAN (needs Location granted on macOS 14+)."""
    try:
        import CoreWLAN
    except Exception:
        return ""
    try:
        iface = CoreWLAN.CWWiFiClient.sharedWiFiClient().interface()
        if iface is None:
            return ""
        return iface.ssid() or ""
    except Exception:
        return ""


def scan_networks():
    """Active scan via CoreWLAN. Returns a list of dicts with keys
    ESSID/CH/Band/PWR/BSSID/connected, or None if CoreWLAN is unavailable or
    the scan fails/returns nothing (caller then falls back to system_profiler)."""
    try:
        import CoreWLAN
    except Exception:
        return None
    try:
        iface = CoreWLAN.CWWiFiClient.sharedWiFiClient().interface()
        if iface is None:
            return None
        current = ""
        try:
            current = iface.ssid() or ""
        except Exception:
            pass
        networks, _err = iface.scanForNetworksWithName_error_(None, None)
        if networks is None:
            return None
        out = []
        for n in networks:
            try:
                ssid = n.ssid() or ""
            except Exception:
                ssid = ""
            if not ssid:
                continue
            try:
                rssi = str(int(n.rssi()))
            except Exception:
                rssi = ""
            ch, band = "", "?"
            try:
                wch = n.wlanChannel()
                if wch is not None:
                    ch = str(int(wch.channelNumber()))
                    band = {1: "2.4", 2: "5", 3: "6"}.get(
                        int(wch.channelBand()), _band_from_channel(ch))
            except Exception:
                band = _band_from_channel(ch)
            try:
                bssid = n.bssid() or ""   # usually None on modern macOS
            except Exception:
                bssid = ""
            out.append({"ESSID": ssid, "CH": ch, "Band": band, "PWR": rssi,
                        "BSSID": bssid, "connected": ssid == current and bool(current)})
        return out or None
    except Exception:
        return None
