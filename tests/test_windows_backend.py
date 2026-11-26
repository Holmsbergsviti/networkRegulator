"""Unit tests for the Windows backend's pure parsers in netreg_backend.py.

These exercise the two locale/format-sensitive bits that are easy to get wrong
and impossible to run in the Linux/no-Wi-Fi cloud container:
  * `_parse_netsh_networks` -- turns `netsh wlan show networks mode=bssid`
    output into the shared NETWORK_COLUMNS rows.
  * `_arp_rows_windows`      -- turns Windows `arp -a` output into device rows.
Both are static/pure, so no real Wi-Fi, admin rights, or Windows is needed.

Run: python3 -m pytest test_windows_backend.py   (or: python3 test_windows_backend.py)
"""
# Ensure the repo root is importable when this suite is run from tests/.
import os as _os, sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))

import ipaddress

from netreg_backend import WindowsBackend, NETWORK_COLUMNS


# A realistic sample of `netsh wlan show networks mode=bssid` on Windows 11:
# two SSIDs, one with two BSSIDs (an extender/mesh), one hidden (blank name),
# plus 2.4 / 5 / 6 GHz bands and a channel-only entry with no Band line.
NETSH_SAMPLE = """
Interface name : Wi-Fi
There are 3 networks currently visible.

SSID 1 : HomeNet
    Network type            : Infrastructure
    Authentication          : WPA2-Personal
    Encryption              : CCMP
    BSSID 1                 : aa:bb:cc:dd:ee:01
         Signal             : 92%
         Radio type         : 802.11ac
         Band               : 5 GHz
         Channel            : 44
         Basic Rates (Mbps) : 6 12 24
    BSSID 2                 : aa:bb:cc:dd:ee:02
         Signal             : 55%
         Radio type         : 802.11n
         Band               : 2.4 GHz
         Channel            : 6

SSID 2 : Neighbour-6E
    Network type            : Infrastructure
    Authentication          : WPA3-Personal
    Encryption              : CCMP
    BSSID 1                 : 11:22:33:44:55:66
         Signal             : 40%
         Radio type         : 802.11ax
         Band               : 6 GHz
         Channel            : 37

SSID 3 : OldRouter
    Network type            : Infrastructure
    Authentication          : WPA2-Personal
    Encryption              : CCMP
    BSSID 1                 : 99:99:99:99:99:99
         Signal             : 70%
         Radio type         : 802.11n
         Channel            : 11

SSID 4 :
    Network type            : Infrastructure
    Authentication          : WPA2-Personal
    Encryption              : CCMP
    BSSID 1                 : 77:77:77:77:77:77
         Signal             : 30%
         Radio type         : 802.11n
         Band               : 2.4 GHz
         Channel            : 1
"""


def test_parse_netsh_counts_and_keys():
    rows = WindowsBackend._parse_netsh_networks(NETSH_SAMPLE)
    # 5 BSSIDs total; the hidden (blank-SSID) one is dropped -> 4 rows.
    assert len(rows) == 4
    for r in rows:
        # Every row must carry the full shared column set so the table is stable.
        assert set(NETWORK_COLUMNS).issubset(r.keys())


def test_parse_netsh_fields():
    rows = WindowsBackend._parse_netsh_networks(NETSH_SAMPLE)
    by_bssid = {r["BSSID"]: r for r in rows}

    strong = by_bssid["aa:bb:cc:dd:ee:01"]
    assert strong["ESSID"] == "HomeNet"
    assert strong["CH"] == "44"
    assert strong["Band"] == "5"
    assert strong["Privacy"] == "WPA2-Personal"
    assert strong["Cipher"] == "CCMP"
    # 92% -> 92//2 - 100 = -54 dBm
    assert strong["PWR"] == "-54"

    weak = by_bssid["aa:bb:cc:dd:ee:02"]
    assert weak["ESSID"] == "HomeNet"      # same SSID, kept as a separate AP row
    assert weak["Band"] == "2.4"
    assert weak["CH"] == "6"

    sixe = by_bssid["11:22:33:44:55:66"]
    assert sixe["Band"] == "6"
    assert sixe["Auth"] == "WPA3-Personal"


def test_parse_netsh_band_falls_back_to_channel():
    # SSID 3's single BSSID has a Channel but no Band line -> derive 2.4 from ch 11.
    rows = WindowsBackend._parse_netsh_networks(NETSH_SAMPLE)
    by_bssid = {r["BSSID"]: r for r in rows}
    assert by_bssid["99:99:99:99:99:99"]["Band"] == "2.4"


def test_parse_netsh_hidden_ssid_dropped():
    rows = WindowsBackend._parse_netsh_networks(NETSH_SAMPLE)
    assert all(r["ESSID"] for r in rows)
    # The genuinely hidden network (blank SSID) and its BSSID are dropped.
    assert "77:77:77:77:77:77" not in {r["BSSID"] for r in rows}


def test_parse_netsh_empty_and_garbage():
    assert WindowsBackend._parse_netsh_networks("") == []
    assert WindowsBackend._parse_netsh_networks("no wlan here\nblah") == []


# ---- ARP parsing ---------------------------------------------------------- #
ARP_SAMPLE = """
Interface: 192.168.1.17 --- 0x6
  Internet Address      Physical Address      Type
  192.168.1.1           a0-11-22-33-44-55     dynamic
  192.168.1.42          de-ad-be-ef-00-11     dynamic
  192.168.1.255         ff-ff-ff-ff-ff-ff     static
  224.0.0.22            01-00-5e-00-00-16     static
  239.255.255.250       01-00-5e-7f-ff-fa     static
  10.0.0.9              aa-bb-cc-dd-ee-ff     dynamic
"""


def test_arp_rows_filters_and_parses():
    net = ipaddress.IPv4Network("192.168.1.0/24")
    rows = WindowsBackend._arp_rows_windows(ARP_SAMPLE, net)
    ips = {r["IP"] for r in rows}
    # Real hosts kept; broadcast, multicast, and the off-subnet 10.0.0.9 dropped.
    assert ips == {"192.168.1.1", "192.168.1.42"}
    gw = next(r for r in rows if r["IP"] == "192.168.1.1")
    assert gw["MAC"] == "a0:11:22:33:44:55"   # dashes -> colons, lowercased
    assert "Vendor" in gw and "Hostname" in gw


def test_arp_rows_dedupes():
    net = ipaddress.IPv4Network("192.168.1.0/24")
    doubled = ARP_SAMPLE + "\n  192.168.1.1   a0-11-22-33-44-55   dynamic"
    rows = WindowsBackend._arp_rows_windows(doubled, net)
    assert [r["IP"] for r in rows].count("192.168.1.1") == 1


def test_arp_rows_empty():
    net = ipaddress.IPv4Network("192.168.1.0/24")
    assert WindowsBackend._arp_rows_windows("", net) == []


# ---- failure diagnosis (why a scan read nothing) -------------------------- #
def test_classify_no_wireless_interface():
    # The most common cause on a wired desktop: no Wi-Fi radio.
    msg = WindowsBackend._classify_netsh_failure(
        "There is no wireless interface on the system.", 1)
    assert "no wireless interface" in msg.lower() or "no wi-fi adapter" in msg.lower()
    assert "ethernet" in msg.lower()  # tells the user why + that wired still works


def test_classify_service_off():
    msg = WindowsBackend._classify_netsh_failure(
        "The Wireless AutoConfig Service (wlansvc) is not running.", 1)
    assert "wlansvc" in msg.lower() or "autoconfig" in msg.lower()


def test_classify_access_denied():
    msg = WindowsBackend._classify_netsh_failure("Access is denied.", 1)
    assert "administrator" in msg.lower()


def test_classify_unknown_returns_blank():
    # Unknown text yields "" so the caller appends the raw exit/snippet instead.
    assert WindowsBackend._classify_netsh_failure("something weird happened", 5) == ""


def test_diagnose_iface_no_adapter():
    msg = WindowsBackend._diagnose_iface_text(
        "There is no wireless interface on the system.")
    assert "no wi-fi adapter" in msg.lower()


def test_diagnose_iface_disconnected_is_blank():
    # A present-but-disconnected adapter still scans once Location is on, so it
    # must NOT be flagged as the problem (that was the real red herring in the
    # field: the fix was enabling Location, not connecting Wi-Fi).
    txt = """
    There is 1 interface on the system:

        Name                   : Wi-Fi
        Description            : Qualcomm QCA9377 802.11ac Wireless Adapter
        State                  : disconnected
        Radio status           : Hardware On
                                 Software On
    """
    assert WindowsBackend._diagnose_iface_text(txt) == ""


def test_diagnose_iface_connected_is_blank():
    txt = """
        Name                   : Wi-Fi
        State                  : connected
        SSID                   : HomeNet
    """
    assert WindowsBackend._diagnose_iface_text(txt) == ""


# ---- capabilities contract ----------------------------------------------- #
def test_capabilities_scan_and_devices_on_deauth_off():
    caps = WindowsBackend().capabilities()
    assert caps.can_scan is True
    assert caps.can_list_devices is True
    assert caps.can_deauth is False
    assert "monitor mode" in caps.deauth_note


def test_device_columns():
    assert WindowsBackend().device_columns() == ("IP", "MAC", "Vendor", "Hostname")


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items())
           if k.startswith("test_") and callable(v)]
    passed = 0
    for fn in fns:
        fn()
        print(f"  ok  {fn.__name__}")
        passed += 1
    print(f"\n{passed}/{len(fns)} passed")
