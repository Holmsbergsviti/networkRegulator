"""
netreg_integrations.py -- optional, net-new library integrations.

Each capability here wraps an open-source library or tool that is *not* part of
the core stack (sockets / nmap / scapy / aircrack-ng). Everything is behind
availability detection, so NetworkRegulator runs with none of these installed
and simply gets richer as each one is added. Nothing here ever raises on a
missing dependency -- callers get an empty / fallback result instead.

Wiring order (what plugs in, in logical layers):

  Layer 1  enrich what we already discover
             * getmac            -> MAC for an IP the ARP table missed
             * mac-vendor-lookup -> vendor name from a MAC (OUI)
             * manuf (optional)  -> offline vendor fallback
             * zeroconf (mDNS)   -> friendly device names

  Layer 2  faster / deeper scanning (external binaries, optional)
             * naabu / rustscan  -> fast port sweep, falls back to the
                                     built-in socket connect-scan

  Layer 3  active tools (own-network, authorized use only; gated in the UI)
             * pywifi            -> scan / connect-disconnect this machine's Wi-Fi
             * bettercap         -> ARP-spoof / MITM via its REST API
             * mdk4 / wifite2    -> richer deauth on top of aircrack-ng

Only Layers 1-2 are implemented here; Layer 3 is represented by availability
probes so the GUI can show what's installed and plan the next step.

This module is import-safe on any platform and needs no third-party package to
load.
"""
from __future__ import annotations

import importlib.util
import shutil
import socket
import subprocess
from typing import Optional


# --------------------------------------------------------------------------- #
#  availability probes
# --------------------------------------------------------------------------- #
def have_module(name: str) -> bool:
    """True if `name` can be imported, without importing it."""
    try:
        return importlib.util.find_spec(name) is not None
    except Exception:
        return False


def have_binary(name: str) -> bool:
    """True if an executable `name` is on PATH."""
    return bool(shutil.which(name))


def availability() -> dict:
    """What optional integrations are usable on this machine right now.
    The GUI can render this as a 'capabilities' panel and to decide which
    buttons to enable."""
    return {
        # Layer 1 -- enrichment
        "getmac": have_module("getmac"),
        "mac_vendor_lookup": have_module("mac_vendor_lookup"),
        "manuf": have_module("manuf"),
        "zeroconf": have_module("zeroconf"),
        # Layer 2 -- scanning
        "naabu": have_binary("naabu"),
        "rustscan": have_binary("rustscan"),
        "masscan": have_binary("masscan"),
        "nmap": have_binary("nmap"),
        # Layer 3 -- active (own-network only)
        "pywifi": have_module("pywifi"),
        "bettercap": have_binary("bettercap"),
        "mitmproxy": have_binary("mitmdump") or have_module("mitmproxy"),
        "mdk4": have_binary("mdk4"),
        "wifite2": have_binary("wifite") or have_binary("wifite2"),
    }


# --------------------------------------------------------------------------- #
#  Layer 1 -- vendor lookup (OUI)
# --------------------------------------------------------------------------- #
class VendorLookup:
    """MAC -> vendor name, using whichever library is installed.

    Prefers manuf (ships an offline OUI table) when present, then
    mac-vendor-lookup (bundles a snapshot, may refresh over the network).
    Results are cached in-process. Returns "" when nothing can resolve it,
    so the caller can just show a blank column."""

    def __init__(self):
        self._cache: dict[str, str] = {}
        self._manuf = None
        self._mvl = None
        self._loaded = False

    def _load(self):
        if self._loaded:
            return
        self._loaded = True
        # manuf: offline, preferred
        if have_module("manuf"):
            try:
                import manuf  # type: ignore
                self._manuf = manuf.MacParser()
            except Exception:
                self._manuf = None
        # mac-vendor-lookup: bundled snapshot + optional refresh
        if have_module("mac_vendor_lookup"):
            try:
                from mac_vendor_lookup import MacLookup  # type: ignore
                self._mvl = MacLookup()
            except Exception:
                self._mvl = None

    @staticmethod
    def _normalize(mac: str) -> str:
        return (mac or "").strip().lower()

    def lookup(self, mac: str) -> str:
        mac = self._normalize(mac)
        if not mac or len(mac) < 8:
            return ""
        if mac in self._cache:
            return self._cache[mac]

        # 0) built-in offline table -- always available, no deps, no network.
        #    Also catches randomized/private MACs so we don't mislabel them.
        try:
            import netreg_oui
            if netreg_oui.is_locally_administered(mac):
                self._cache[mac] = "randomized (private)"
                return self._cache[mac]
            vendor = netreg_oui.lookup(mac)
        except Exception:
            vendor = ""

        # 1) manuf (offline, full table) if the built-in table missed it.
        if not vendor:
            self._load()
            if self._manuf is not None:
                try:
                    vendor = self._manuf.get_manuf_long(mac) or self._manuf.get_manuf(mac) or ""
                except Exception:
                    vendor = ""
            # 2) mac-vendor-lookup (needs a one-time OUI download; blank offline).
            if not vendor and self._mvl is not None:
                try:
                    vendor = self._mvl.lookup(mac) or ""
                except Exception:
                    vendor = ""
        self._cache[mac] = vendor
        return vendor


# one shared instance; cheap to keep around
_VENDOR = VendorLookup()


def vendor_for_mac(mac: str) -> str:
    """Best-effort vendor name for a MAC. "" if unknown or no library."""
    return _VENDOR.lookup(mac)


# --------------------------------------------------------------------------- #
#  Layer 1 -- MAC for an IP (getmac)
# --------------------------------------------------------------------------- #
def mac_for_ip(ip: str) -> str:
    """MAC address for a host IP via getmac, "" if unknown / not installed.
    Useful to fill in a MAC the ARP table didn't have yet."""
    if not ip or not have_module("getmac"):
        return ""
    try:
        from getmac import get_mac_address  # type: ignore
        return (get_mac_address(ip=ip) or "").lower()
    except Exception:
        return ""


def local_mac(interface: Optional[str] = None) -> str:
    """MAC of a local interface (or the default) via getmac."""
    if not have_module("getmac"):
        return ""
    try:
        from getmac import get_mac_address  # type: ignore
        if interface:
            return (get_mac_address(interface=interface) or "").lower()
        return (get_mac_address() or "").lower()
    except Exception:
        return ""


# --------------------------------------------------------------------------- #
#  Layer 1 -- mDNS / Bonjour friendly names (zeroconf)
# --------------------------------------------------------------------------- #
# Common service types home devices advertise. Browsing these for a short
# window maps IP -> a human name (e.g. "Living Room TV").
_MDNS_SERVICES = (
    "_http._tcp.local.",
    "_airplay._tcp.local.",
    "_raop._tcp.local.",        # AirPlay audio
    "_googlecast._tcp.local.",  # Chromecast
    "_spotify-connect._tcp.local.",
    "_printer._tcp.local.",
    "_ipp._tcp.local.",
    "_ssh._tcp.local.",
    "_smb._tcp.local.",
    "_homekit._tcp.local.",
    "_companion-link._tcp.local.",
    "_device-info._tcp.local.",
)


def mdns_names(timeout: float = 3.0) -> dict:
    """Browse mDNS for a few seconds and return {ip: friendly_name}.

    Returns {} if zeroconf isn't installed or nothing answers. Safe to call
    from a background thread; it tears the browser down before returning."""
    if not have_module("zeroconf"):
        return {}
    try:
        from zeroconf import Zeroconf, ServiceBrowser  # type: ignore
    except Exception:
        return {}

    import threading
    import time

    results: dict[str, str] = {}
    lock = threading.Lock()
    zc = Zeroconf()

    def _friendly(info, service_type: str) -> str:
        # Prefer the instance name (e.g. "Living Room"), fall back to server.
        name = ""
        try:
            full = info.name or ""
            if full.endswith("." + service_type):
                name = full[: -(len(service_type) + 1)]
            elif full.endswith(service_type):
                name = full[: -len(service_type)].rstrip(".")
        except Exception:
            name = ""
        if not name:
            name = (getattr(info, "server", "") or "").rstrip(".")
        return name

    class _Listener:
        def add_service(self, zeroconf, service_type, name):
            try:
                info = zeroconf.get_service_info(service_type, name, timeout=1500)
            except Exception:
                info = None
            if not info:
                return
            friendly = _friendly(info, service_type)
            if not friendly:
                return
            try:
                addrs = info.parsed_addresses()
            except Exception:
                addrs = []
            with lock:
                for addr in addrs:
                    if ":" in addr:  # skip IPv6 for the LAN table
                        continue
                    results.setdefault(addr, friendly)

        # zeroconf calls these too; we only care about additions
        def update_service(self, *a, **k):
            pass

        def remove_service(self, *a, **k):
            pass

    listener = _Listener()
    browsers = [ServiceBrowser(zc, svc, listener) for svc in _MDNS_SERVICES]
    try:
        time.sleep(max(0.5, timeout))
    finally:
        try:
            zc.close()
        except Exception:
            pass
    with lock:
        return dict(results)


def enrich_devices(rows: list, vendor: bool = True, mdns: bool = True,
                   fill_mac: bool = False, mdns_timeout: float = 3.0) -> list:
    """Add 'Vendor' and better 'Hostname' to LAN device rows in place.

    rows: list of dicts with at least 'IP' and (usually) 'MAC'. Each dict is
    updated with a 'Vendor' key, and 'Hostname' is filled from mDNS when it was
    blank. Missing libraries are simply skipped. Returns the same list."""
    names = mdns_names(mdns_timeout) if mdns else {}
    for r in rows:
        ip = r.get("IP", "")
        mac = r.get("MAC", "") or r.get("Station MAC", "")
        if fill_mac and not mac and ip:
            mac = mac_for_ip(ip)
            if mac:
                r["MAC"] = mac
        if vendor:
            r["Vendor"] = vendor_for_mac(mac) if mac else ""
        if mdns and not r.get("Hostname"):
            friendly = names.get(ip, "")
            if friendly:
                r["Hostname"] = friendly
    return rows


# --------------------------------------------------------------------------- #
#  Layer 2 -- fast port scan adapter (naabu / rustscan -> socket fallback)
# --------------------------------------------------------------------------- #
def fast_port_scan(ip: str, ports: Optional[list] = None,
                   full: bool = False, timeout: int = 60) -> Optional[list]:
    """Try an installed fast scanner and return a sorted list of open ports.

    Returns None when no external scanner is available, so the caller can fall
    back to the built-in socket scan (netreg_backend.scan_ports). Own-network
    use only."""
    if have_binary("naabu"):
        return _scan_naabu(ip, ports, full, timeout)
    if have_binary("rustscan"):
        return _scan_rustscan(ip, full, timeout)
    return None


def _scan_naabu(ip, ports, full, timeout) -> list:
    cmd = ["naabu", "-host", ip, "-silent"]
    if full:
        cmd += ["-p", "-"]
    elif ports:
        cmd += ["-p", ",".join(str(p) for p in ports)]
    else:
        cmd += ["-top-ports", "1000"]
    out = _run(cmd, timeout)
    found = []
    for line in out.splitlines():
        line = line.strip()
        if ":" in line:
            try:
                found.append(int(line.rsplit(":", 1)[1]))
            except ValueError:
                pass
    return sorted(set(found))


def _scan_rustscan(ip, full, timeout) -> list:
    cmd = ["rustscan", "-a", ip, "--greppable"]
    cmd += ["-r", "1-65535"] if full else ["--top"]
    out = _run(cmd, timeout)
    found = []
    for line in out.splitlines():
        # greppable: "ip -> [22,80,443]"
        if "->" in line and "[" in line:
            inside = line[line.find("[") + 1: line.find("]")]
            for tok in inside.split(","):
                tok = tok.strip()
                if tok.isdigit():
                    found.append(int(tok))
    return sorted(set(found))


def _run(cmd: list, timeout: int) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout or ""
    except Exception:
        return ""


# --------------------------------------------------------------------------- #
#  self-check (runs anywhere, no network needed)
# --------------------------------------------------------------------------- #
if __name__ == "__main__":
    avail = availability()
    print("Optional integrations available on this machine:")
    for k, v in avail.items():
        print(f"  {'yes' if v else ' no'}  {k}")
    # exercise the safe bits
    print("\nVendor for 00:1A:2B:xx (Ayecom/known OUI test):",
          vendor_for_mac("00:1A:2B:00:00:01") or "(unknown / no lib)")
    print("Local MAC via getmac:", local_mac() or "(n/a)")
