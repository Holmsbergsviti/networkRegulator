"""
netreg_oui.py -- tiny built-in OUI (MAC prefix -> vendor) table.

This is a *convenience* table so the Vendor column shows something useful with
zero setup and no network: it covers the vendors most common on a home/LAN
(phones, Pis, IoT boards, TVs, routers). It is intentionally small and is NOT
authoritative -- for full coverage, install `mac-vendor-lookup` or `manuf`
(netreg_integrations prefers those when present and falls back to this table).

Keys are the 24-bit OUI as upper-case "AA:BB:CC". Entries here are well-known,
widely documented prefixes; treat anything not found as simply unknown ("").
"""
from __future__ import annotations

COMMON_OUI: dict[str, str] = {
    # Raspberry Pi
    "B8:27:EB": "Raspberry Pi Foundation",
    "DC:A6:32": "Raspberry Pi (Trading)",
    "E4:5F:01": "Raspberry Pi (Trading)",
    "28:CD:C1": "Raspberry Pi (Trading)",
    "D8:3A:DD": "Raspberry Pi (Trading)",
    "2C:CF:67": "Raspberry Pi (Trading)",
    # Espressif (ESP8266 / ESP32 -- very common in DIY IoT)
    "24:0A:C4": "Espressif",
    "30:AE:A4": "Espressif",
    "3C:71:BF": "Espressif",
    "5C:CF:7F": "Espressif",
    "84:0D:8E": "Espressif",
    "84:F3:EB": "Espressif",
    "A0:20:A6": "Espressif",
    "AC:67:B2": "Espressif",
    "BC:DD:C2": "Espressif",
    "CC:50:E3": "Espressif",
    "DC:4F:22": "Espressif",
    "7C:9E:BD": "Espressif",
    "E0:98:06": "Espressif",
    # Apple
    "3C:07:54": "Apple",
    "A4:83:E7": "Apple",
    "AC:BC:32": "Apple",
    "F0:18:98": "Apple",
    "DC:A9:04": "Apple",
    "88:66:5A": "Apple",
    "F8:FF:C2": "Apple",
    # Google / Nest
    "54:60:09": "Google",
    "F4:F5:D8": "Google",
    "F4:F5:E8": "Google",
    "3C:5A:B4": "Google",
    "DA:A1:19": "Google",
    "18:B4:30": "Google Nest",
    # Amazon (Echo / Fire / Kindle)
    "34:D2:70": "Amazon",
    "44:65:0D": "Amazon",
    "68:37:E9": "Amazon",
    "74:C2:46": "Amazon",
    "FC:65:DE": "Amazon",
    "0C:47:C9": "Amazon",
    "68:54:FD": "Amazon",
    # Samsung
    "5C:0A:5B": "Samsung",
    "78:1F:DB": "Samsung",
    "8C:77:12": "Samsung",
    "BC:20:A4": "Samsung",
    "E8:50:8B": "Samsung",
    "FC:A1:3E": "Samsung",
    "34:23:BA": "Samsung",
    # Philips Hue / Signify
    "00:17:88": "Philips (Signify)",
    "EC:B5:FA": "Philips (Signify)",
    # TP-Link
    "50:C7:BF": "TP-Link",
    "A4:2B:B0": "TP-Link",
    "AC:84:C6": "TP-Link",
    "C0:06:C3": "TP-Link",
    "EC:08:6B": "TP-Link",
    "98:DA:C4": "TP-Link",
    # Ubiquiti
    "00:15:6D": "Ubiquiti",
    "24:5A:4C": "Ubiquiti",
    "44:D9:E7": "Ubiquiti",
    "78:8A:20": "Ubiquiti",
    "F0:9F:C2": "Ubiquiti",
    "FC:EC:DA": "Ubiquiti",
    # Netgear
    "20:E5:2A": "Netgear",
    "2C:30:33": "Netgear",
    "A0:40:A0": "Netgear",
    "C0:3F:0E": "Netgear",
    "9C:3D:CF": "Netgear",
    # Asus
    "2C:56:DC": "ASUS",
    "50:46:5D": "ASUS",
    "AC:9E:17": "ASUS",
    "D8:50:E6": "ASUS",
    "1C:B7:2C": "ASUS",
    # Intel (laptops / NICs)
    "3C:A9:F4": "Intel",
    "7C:7A:91": "Intel",
    "8C:A9:82": "Intel",
    "A0:A8:CD": "Intel",
    "94:65:9C": "Intel",
    # Microsoft (Xbox / Surface / Hyper-V)
    "00:15:5D": "Microsoft (Hyper-V)",
    "28:18:78": "Microsoft",
    "7C:1E:52": "Microsoft",
    "C0:33:5E": "Microsoft",
    # Roku
    "B0:A7:37": "Roku",
    "CC:6D:A0": "Roku",
    "DC:3A:5E": "Roku",
    "AC:3A:7A": "Roku",
    # Sonos
    "5C:AA:FD": "Sonos",
    "94:9F:3E": "Sonos",
    "B8:E9:37": "Sonos",
    "78:28:CA": "Sonos",
    # Dell / HP
    "18:66:DA": "Dell",
    "34:17:EB": "Dell",
    "B8:AC:6F": "Dell",
    "70:5A:0F": "HP",
    "94:57:A5": "HP",
    "D0:BF:9C": "HP",
    # locally-administered (randomized MACs set the 2nd-least-significant bit
    # of the first octet; phones use this for privacy). Flagged specially.
}


def _norm_prefix(mac: str) -> str:
    """Return the 'AA:BB:CC' upper-case OUI of a MAC, or '' if unparseable."""
    mac = (mac or "").strip().upper().replace("-", ":")
    parts = mac.split(":")
    if len(parts) < 3:
        return ""
    try:
        return ":".join(f"{int(p, 16):02X}" for p in parts[:3])
    except ValueError:
        return ""


def is_locally_administered(mac: str) -> bool:
    """True if the MAC is locally-administered (e.g. a randomized phone MAC),
    in which case the vendor is meaningless."""
    prefix = _norm_prefix(mac)
    if not prefix:
        return False
    try:
        first = int(prefix.split(":")[0], 16)
    except ValueError:
        return False
    return bool(first & 0b10)  # 2nd-least-significant bit of first octet


def lookup(mac: str) -> str:
    """Vendor for a MAC from the built-in table, or '' if unknown.
    Randomized/locally-administered MACs return 'randomized (private)'."""
    prefix = _norm_prefix(mac)
    if not prefix:
        return ""
    if is_locally_administered(mac):
        return "randomized (private)"
    return COMMON_OUI.get(prefix, "")
