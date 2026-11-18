"""
netreg_backend.py -- cross-platform backend for NetworkRegulator.

All OS-specific Wi-Fi logic lives behind a small interface so the GUI never
has to know which platform it runs on. Call get_backend() to get the right
one for the current machine.

Status:
  * macOS  -- implemented (native scan + LAN device discovery; deauth needs a
              monitor-mode-capable USB adapter + the aircrack-ng suite).
  * Linux  -- implemented (aircrack-ng: airmon-ng / airodump-ng / aireplay-ng).
  * Windows-- scan not yet wired; clear message instead of a silent failure.

Network rows share these keys so the GUI table is stable across platforms:
  ESSID, PWR, CH, Band, Privacy, Cipher, Auth, BSSID, Beacons, IV
Device listings return their own column spec, because what a platform can see
differs (airodump stations vs. a LAN scan).
"""
from __future__ import annotations

import csv
import gzip
import ipaddress
import os
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

NETWORK_COLUMNS = (
    "ESSID", "PWR", "CH", "Band", "Privacy", "Cipher", "Auth", "BSSID", "Beacons", "IV",
)


def current_os() -> str:
    if sys.platform == "darwin":
        return "macos"
    if os.name == "nt" or sys.platform.startswith("win"):
        return "windows"
    return "linux"


def _channel_to_band(ch_str: str) -> str:
    try:
        ch = int(ch_str)
    except Exception:
        return "?"
    if 1 <= ch <= 14:
        return "2.4"
    if ch >= 36:
        return "5"
    return "?"


def _empty_net(**kw) -> dict:
    row = {k: "" for k in NETWORK_COLUMNS}
    row.update(kw)
    return row


# Common TCP ports probed by the device-detail window, with a friendly service
# name. getservbyport fills in the rest where the OS knows it.
COMMON_PORTS = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpcbind", 123: "ntp", 135: "msrpc",
    139: "netbios", 143: "imap", 161: "snmp", 389: "ldap", 443: "https",
    445: "smb", 515: "printer", 548: "afp", 554: "rtsp", 587: "smtp-sub",
    631: "ipp", 993: "imaps", 995: "pop3s", 1433: "mssql", 1723: "pptp",
    1883: "mqtt", 3306: "mysql", 3389: "rdp", 5000: "upnp/flask", 5353: "mdns",
    5432: "postgres", 5900: "vnc", 6379: "redis", 7000: "airplay",
    8008: "http-alt", 8009: "chromecast", 8080: "http-alt", 8443: "https-alt",
    8883: "mqtt-tls", 9100: "printer-jd", 32400: "plex", 49152: "upnp",
}


def service_name(port: int) -> str:
    """Best-effort service label for a TCP port."""
    try:
        return socket.getservbyport(port, "tcp")
    except Exception:
        return COMMON_PORTS.get(port, "")


def scan_ports(ip: str, ports=None, timeout: float = 0.6, on_open=None) -> list[int]:
    """Plain TCP connect-scan of `ip`. Works on any platform (sockets only), so
    it lives outside the per-OS backends. Calls on_open(port) as each open port
    is found and returns the sorted list of open ports. Own-network use only."""
    ports = list(ports if ports is not None else COMMON_PORTS.keys())
    open_ports: list[int] = []

    def check(p: int):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            return p, s.connect_ex((ip, p)) == 0
        except Exception:
            return p, False
        finally:
            try:
                s.close()
            except Exception:
                pass

    with ThreadPoolExecutor(max_workers=100) as ex:
        for p, is_open in ex.map(check, ports):
            if is_open:
                open_ports.append(p)
                if on_open:
                    try:
                        on_open(p)
                    except Exception:
                        pass
    return sorted(open_ports)


def ping_host(ip: str, timeout_s: int = 1) -> tuple[bool, str]:
    """One ICMP ping, cross-platform. Returns (reachable, latency_text)."""
    if current_os() == "windows":
        cmd = ["ping", "-n", "1", "-w", str(timeout_s * 1000), ip]
    else:
        cmd = ["ping", "-c", "1", "-t", str(timeout_s), ip]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s + 2)
    except Exception:
        return False, ""
    if r.returncode != 0:
        return False, ""
    m = re.search(r"time[=<]\s*([\d.]+)\s*ms", r.stdout)
    return True, (f"{m.group(1)} ms" if m else "reachable")


def resolve_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


# --- MAC -> manufacturer, from the bundled IEEE OUI registry --------------- #
_OUI_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                         "data", "oui_vendors.tsv.gz")
_oui_cache: dict | None = None
_oui_lock = threading.Lock()


def _load_oui() -> dict:
    """Load the bundled OUI prefix->vendor table once (lazy, cached)."""
    global _oui_cache
    if _oui_cache is not None:
        return _oui_cache
    with _oui_lock:
        if _oui_cache is not None:
            return _oui_cache
        d: dict = {}
        try:
            with gzip.open(_OUI_PATH, "rt", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    pfx, _, vendor = line.rstrip("\n").partition("\t")
                    if pfx:
                        d[pfx] = vendor
        except Exception:
            d = {}
        _oui_cache = d
        return d


def vendor_for_mac(mac: str) -> str:
    """Best-effort manufacturer for a MAC address, from the bundled IEEE OUI
    data. Returns a vendor name, a note for randomized/private addresses, or ""
    when it genuinely can't be identified."""
    if not mac:
        return ""
    hexs = mac.replace(":", "").replace("-", "").upper()
    if len(hexs) < 6:
        return ""
    vendor = _load_oui().get(hexs[:6], "")
    if vendor and vendor.lower() != "private":
        return vendor
    # Locally-administered bit (bit 1 of the first octet) => a randomized or
    # privately-assigned MAC. Modern phones randomize their MAC per network, so
    # this is the honest reason they can't be identified by maker.
    try:
        if int(hexs[:2], 16) & 0x02:
            return "Randomized / private MAC"
    except Exception:
        pass
    if vendor.lower() == "private":
        return "Private (unregistered)"
    return ""


class Capabilities:
    """What the active backend can actually do on this machine, and why not."""

    def __init__(self, can_scan=False, can_list_devices=False, can_deauth=False,
                 scan_note="", device_note="", deauth_note=""):
        self.can_scan = can_scan
        self.can_list_devices = can_list_devices
        self.can_deauth = can_deauth
        self.scan_note = scan_note
        self.device_note = device_note
        self.deauth_note = deauth_note


# --------------------------------------------------------------------------- #
#  Base backend
# --------------------------------------------------------------------------- #
class Backend:
    name = "base"

    def prepare(self):
        """Called once at GUI startup for any one-time setup (e.g. permissions)."""
        pass

    def capabilities(self) -> Capabilities:
        return Capabilities()

    # --- network scanning (lifecycle: start -> snapshot* -> stop) ---------- #
    def start_scan(self):
        pass

    def snapshot_networks(self) -> tuple[list[dict], str]:
        """Return (rows, status_note). Each row uses NETWORK_COLUMNS keys."""
        return [], "Not supported on this platform."

    def stop_scan(self):
        pass

    # --- device listing for one target network ----------------------------- #
    def device_columns(self) -> tuple[str, ...]:
        return ("Station MAC", "BSSID", "Packets", "PWR", "Probed ESSIDs")

    def start_devices(self, target: dict):
        pass

    def snapshot_devices(self) -> tuple[list[dict], str]:
        return [], "Not supported on this platform."

    def stop_devices(self):
        pass

    # --- disconnect / deauth ------------------------------------------------ #
    def deauth(self, bssid: str, station: str | None = None) -> tuple[bool, str]:
        return False, self.capabilities().deauth_note or "Not supported on this platform."

    # --- restore normal Wi-Fi ---------------------------------------------- #
    def recover(self) -> tuple[bool, str]:
        return True, "Nothing to recover on this platform."


# --------------------------------------------------------------------------- #
#  macOS backend
# --------------------------------------------------------------------------- #
class MacBackend(Backend):
    name = "macos"

    def __init__(self):
        self._lock = threading.Lock()
        self._nets: list[dict] = []
        self._net_note = "Ready."
        self._scan_thread = None
        self._scanning = False

        self._devices: list[dict] = []
        self._dev_note = "Ready."
        self._dev_thread = None
        self._dev_scanning = False
        self._dev_target: dict = {}

        self._has_aircrack = bool(shutil.which("airodump-ng") and shutil.which("aireplay-ng"))

    # ---- display helpers -------------------------------------------------- #
    CONNECTED_SUFFIX = "  (connected)"

    @staticmethod
    def _display_name(name: str, connected: bool, fallback: str = "") -> str:
        """One place that builds the ESSID shown in the table, so the
        '(connected)' marker is consistent and blank names never leak through.
        A non-connected network with no name returns "" so the caller drops it;
        the connected network always keeps a name so its row stays visible."""
        name = (name or "").strip()
        if connected and not name:
            name = (fallback or "").strip() or "<hidden by macOS>"
        if connected:
            return name + MacBackend.CONNECTED_SUFFIX
        return name

    @staticmethod
    def _collapse_connected(rows: list[dict]) -> list[dict]:
        """macOS can report the current network under more than one interface
        block, which would tag two rows '(connected)'. Keep only one: prefer a
        row with a real/redacted name over the '<hidden by macOS>' placeholder,
        then the strongest signal."""
        suffix = MacBackend.CONNECTED_SUFFIX
        conn = [r for r in rows if r["ESSID"].endswith(suffix)]
        if len(conn) <= 1:
            return rows
        keep = max(conn, key=lambda r: (not r["ESSID"].startswith("<hidden by macOS>"), _pwr(r)))
        return [r for r in rows if not r["ESSID"].endswith(suffix) or r is keep]

    # ---- one-time setup --------------------------------------------------- #
    def prepare(self):
        """Request Location Services so CoreWLAN can return real SSIDs.
        Only meaningful when running from the packaged .app; harmless otherwise."""
        try:
            import mac_native
            threading.Thread(target=mac_native.request_location, daemon=True).start()
        except Exception:
            pass

    # ---- capabilities ----------------------------------------------------- #
    def capabilities(self) -> Capabilities:
        mon = os.environ.get("NETREG_MON_IFACE", "")
        can_deauth = bool(self._has_aircrack and mon)
        if can_deauth:
            deauth_note = (
                f"Deauth will use monitor interface '{mon}' — make sure that "
                f"adapter is in monitor mode."
            )
        elif self._has_aircrack:
            deauth_note = (
                "aircrack-ng is installed, but disconnecting still needs a "
                "monitor-mode USB adapter (the built-in Mac card cannot inject). "
                "Put it in monitor mode and set NETREG_MON_IFACE to that interface."
            )
        else:
            deauth_note = (
                "Disconnecting a device needs the aircrack-ng suite plus a "
                "monitor-mode-capable USB Wi-Fi adapter. Install aircrack-ng "
                "(brew install aircrack-ng) and plug in a compatible adapter."
            )
        return Capabilities(
            can_scan=True,
            can_list_devices=True,
            can_deauth=can_deauth,
            scan_note="Scanning nearby networks with macOS system tools.",
            device_note=(
                "Listing devices on the network you are connected to (LAN scan). "
                "Seeing clients of other nearby networks needs a monitor-mode adapter."
            ),
            deauth_note=deauth_note,
        )

    # ---- network scanning ------------------------------------------------- #
    def start_scan(self):
        self._scanning = True
        # Set an immediate "working" note so the UI shows activity before the
        # first (heavy) scan pass returns, instead of the stale previous note.
        with self._lock:
            self._net_note = "Scanning nearby networks… (first pass can take a few seconds)"
        if self._scan_thread and self._scan_thread.is_alive():
            return
        self._scan_thread = threading.Thread(target=self._scan_loop, daemon=True)
        self._scan_thread.start()

    def _scan_loop(self):
        while self._scanning:
            rows, note = self._scan_once()
            with self._lock:
                self._nets = rows
                self._net_note = note
            # system_profiler is heavy; don't hammer it.
            for _ in range(20):
                if not self._scanning:
                    break
                time.sleep(0.1)

    def _scan_once(self) -> tuple[list[dict], str]:
        # Prefer CoreWLAN (real names when Location is granted); fall back to
        # system_profiler, which redacts names on recent macOS.
        cw = self._scan_corewlan()
        if cw is not None:
            return cw
        return self._scan_system_profiler()

    def _scan_corewlan(self):
        try:
            import mac_native
            nets = mac_native.scan_networks()
        except Exception:
            nets = None
        if not nets:
            return None
        rows = []
        for n in nets:
            essid = self._display_name(n.get("ESSID", ""), n.get("connected"))
            rows.append(_empty_net(ESSID=essid, CH=n.get("CH", ""),
                                   Band=n.get("Band", "?"), PWR=n.get("PWR", ""),
                                   BSSID=n.get("BSSID", "")))
        # drop nameless (hidden) non-connected networks so no blank row shows
        rows = [r for r in rows if r["ESSID"]]
        rows = self._collapse_connected(rows)
        best: dict[str, dict] = {}
        for r in rows:
            prev = best.get(r["ESSID"])
            if prev is None or _pwr(r) > _pwr(prev):
                best[r["ESSID"]] = r
        out = sorted(best.values(), key=_pwr, reverse=True)
        return out, f"Found {len(out)} network(s) via CoreWLAN (real names)."

    def _scan_system_profiler(self) -> tuple[list[dict], str]:
        import json
        try:
            r = subprocess.run(
                ["system_profiler", "-json", "SPAirPortDataType"],
                capture_output=True, text=True, timeout=25,
            )
            if r.returncode != 0 or not r.stdout.strip():
                return [], "Could not read Wi-Fi info from system_profiler."
            data = json.loads(r.stdout)
        except Exception as e:
            return [], f"Scan error: {e}"

        connected_ssid = self._connected_ssid()
        rows: list[dict] = []
        try:
            for blk in data.get("SPAirPortDataType", []):
                for iface in blk.get("spairport_airport_interfaces", []):
                    cur = iface.get("spairport_current_network_information")
                    if isinstance(cur, dict):
                        rows.append(self._net_from_sp(cur, connected=True,
                                                      connected_ssid=connected_ssid))
                    for net in iface.get("spairport_airport_other_local_wireless_networks", []) or []:
                        rows.append(self._net_from_sp(net, connected=False))
        except Exception as e:
            return rows, f"Parsed partially: {e}"

        # drop entries with no usable name (macOS sometimes returns blank rows)
        rows = [r for r in rows if r["ESSID"]]
        # macOS can list the current network under two interface blocks; keep one
        rows = self._collapse_connected(rows)

        # de-dupe by ESSID keeping strongest
        best: dict[str, dict] = {}
        for n in rows:
            key = n["ESSID"]
            prev = best.get(key)
            if prev is None or _pwr(n) > _pwr(prev):
                best[key] = n
        out = sorted(best.values(), key=_pwr, reverse=True)
        redacted = any(r["ESSID"] == "<redacted>" for r in out)
        note = f"Found {len(out)} network(s)."
        if redacted:
            note += (" Some names show <redacted> — grant Location Services to see "
                     "them. macOS hides other networks' BSSIDs regardless.")
        else:
            note += " macOS does not expose other networks' BSSIDs."
        return out, note

    def _connected_ssid(self) -> str:
        """Real SSID of the network we're on. Tries CoreWLAN (works in the
        packaged app with Location granted), then the legacy networksetup."""
        try:
            import mac_native
            ssid = mac_native.connected_ssid()
            if ssid:
                return ssid
        except Exception:
            pass
        try:
            r = subprocess.run(
                ["networksetup", "-getairportnetwork", self._default_iface()],
                capture_output=True, text=True, timeout=5,
            )
            m = re.search(r"Current Wi-Fi Network:\s*(.+)", r.stdout)
            if m:
                return m.group(1).strip()
        except Exception:
            pass
        return ""

    @staticmethod
    def _net_from_sp(net: dict, connected: bool, connected_ssid: str = "") -> dict:
        raw = net.get("_name", "")
        # macOS 26 redacts SSIDs without Location Services and newer builds
        # broke `networksetup -getairportnetwork`, so the connected network's
        # name may be unavailable. _display_name still marks the row you're on
        # (falling back to "<hidden by macOS>") so it's obvious which is yours.
        essid = MacBackend._display_name(connected_ssid or raw, connected, fallback=raw)
        ch_raw = str(net.get("spairport_network_channel", ""))
        m = re.match(r"\s*(\d+)", ch_raw)
        ch = m.group(1) if m else ""
        band = "2.4"
        if "6GHz" in ch_raw:
            band = "6"
        elif "5GHz" in ch_raw:
            band = "5"
        elif "2GHz" in ch_raw:
            band = "2.4"
        elif ch:
            band = _channel_to_band(ch)
        sig = net.get("spairport_signal_noise", "")
        pm = re.search(r"(-?\d+)\s*dBm", str(sig))
        pwr = pm.group(1) if pm else ""
        sec = str(net.get("spairport_security_mode", ""))
        sec = sec.replace("spairport_security_mode_", "").replace("_", " ").strip() or ""
        return _empty_net(ESSID=essid, CH=ch, Band=band, PWR=pwr, Privacy=sec,
                          BSSID=net.get("bssid", ""))

    def snapshot_networks(self) -> tuple[list[dict], str]:
        with self._lock:
            return list(self._nets), self._net_note

    def stop_scan(self):
        self._scanning = False

    # ---- device listing (LAN scan of the connected network) --------------- #
    def device_columns(self) -> tuple[str, ...]:
        return ("IP", "MAC", "Vendor", "Hostname")

    def start_devices(self, target: dict):
        self._dev_target = target or {}
        self._dev_scanning = True
        with self._lock:
            self._dev_note = "Scanning the local network… (pinging every address, ~10–15s)"
        if self._dev_thread and self._dev_thread.is_alive():
            return
        self._dev_thread = threading.Thread(target=self._dev_loop, daemon=True)
        self._dev_thread.start()

    def _dev_loop(self):
        while self._dev_scanning:
            rows, note = self._lan_scan()
            with self._lock:
                self._devices = rows
                self._dev_note = note
            for _ in range(30):
                if not self._dev_scanning:
                    break
                time.sleep(0.1)

    def _default_iface(self) -> str:
        try:
            r = subprocess.run(["route", "-n", "get", "default"],
                               capture_output=True, text=True, timeout=5)
            m = re.search(r"interface:\s*(\S+)", r.stdout)
            if m:
                return m.group(1)
        except Exception:
            pass
        return "en0"

    def _lan_scan(self) -> tuple[list[dict], str]:
        iface = self._default_iface()
        try:
            ip = subprocess.run(["ipconfig", "getifaddr", iface],
                                capture_output=True, text=True, timeout=5).stdout.strip()
            mask = subprocess.run(["ipconfig", "getoption", iface, "subnet_mask"],
                                  capture_output=True, text=True, timeout=5).stdout.strip()
        except Exception as e:
            return [], f"Could not read local network: {e}"
        if not ip:
            return [], "Not connected to a Wi-Fi/LAN network."
        try:
            net = ipaddress.IPv4Network(f"{ip}/{mask or '255.255.255.0'}", strict=False)
        except Exception:
            net = ipaddress.IPv4Network(f"{ip}/24", strict=False)

        hosts = list(net.hosts())
        if len(hosts) > 254:
            hosts = hosts[:254]

        def ping(h):
            subprocess.run(["ping", "-c", "1", "-t", "1", str(h)],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        with ThreadPoolExecutor(max_workers=64) as ex:
            list(ex.map(ping, hosts))

        rows: list[dict] = []
        try:
            arp = subprocess.run(["arp", "-a", "-n"], capture_output=True, text=True, timeout=10).stdout
        except Exception as e:
            return [], f"ARP read failed: {e}"
        seen = set()
        for line in arp.splitlines():
            m = re.search(r"\((\d+\.\d+\.\d+\.\d+)\) at ([0-9a-fA-F:]{11,17})", line)
            if not m:
                continue
            dip, mac = m.group(1), m.group(2).lower()
            if "incomplete" in line or mac in ("ff:ff:ff:ff:ff:ff",):
                continue
            try:
                if ipaddress.IPv4Address(dip) not in net:
                    continue
            except Exception:
                continue
            if dip in seen:
                continue
            seen.add(dip)
            rows.append({"IP": dip, "MAC": mac, "Vendor": vendor_for_mac(mac),
                         "Hostname": ""})

        # best-effort reverse DNS, bounded
        def resolve(row):
            try:
                row["Hostname"] = socket.gethostbyaddr(row["IP"])[0]
            except Exception:
                row["Hostname"] = ""
        with ThreadPoolExecutor(max_workers=32) as ex:
            list(ex.map(resolve, rows))

        rows.sort(key=lambda r: tuple(int(x) for x in r["IP"].split(".")))
        note = f"{len(rows)} device(s) on {net.with_prefixlen} (via {iface})."
        return rows, note

    def snapshot_devices(self) -> tuple[list[dict], str]:
        with self._lock:
            return list(self._devices), self._dev_note

    def stop_devices(self):
        self._dev_scanning = False

    # ---- deauth ------------------------------------------------------------ #
    def deauth(self, bssid: str, station: str | None = None) -> tuple[bool, str]:
        if not self._has_aircrack:
            return False, self.capabilities().deauth_note
        mon = os.environ.get("NETREG_MON_IFACE", "")
        if not mon:
            return False, ("Set NETREG_MON_IFACE to your monitor-mode adapter "
                           "(e.g. en1) before disconnecting.")
        count = "10" if station else "0"
        cmd = ["sudo", "aireplay-ng", "-0", count, "-a", bssid]
        if station:
            cmd += ["-c", station]
        cmd += [mon]
        try:
            subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True, "Sent deauth: " + " ".join(cmd)
        except Exception as e:
            return False, f"Deauth failed: {e}"

    def recover(self) -> tuple[bool, str]:
        iface = self._default_iface()
        try:
            subprocess.run(["networksetup", "-setairportpower", iface, "off"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(1)
            subprocess.run(["networksetup", "-setairportpower", iface, "on"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True, f"Cycled Wi-Fi power on {iface}."
        except Exception as e:
            return False, f"Recovery failed: {e}"


# --------------------------------------------------------------------------- #
#  Linux backend (aircrack-ng) -- ported from the original scripts
# --------------------------------------------------------------------------- #
class LinuxBackend(Backend):
    name = "linux"

    def __init__(self, interface: str | None = None):
        self.interface = interface or os.environ.get("NETREG_IFACE", "wlp0s20f3")
        self.mon = self.interface + "mon"
        self._net_prefix = "network_scan"
        self._dev_prefix = "network_scan_devices"
        self._net_proc = None
        self._dev_proc = None
        self._dev_target: dict = {}
        self._has_aircrack = bool(shutil.which("airmon-ng") and shutil.which("airodump-ng"))

    def capabilities(self) -> Capabilities:
        if not self._has_aircrack:
            note = "Install the aircrack-ng suite (airmon-ng, airodump-ng, aireplay-ng)."
            return Capabilities(scan_note=note, device_note=note, deauth_note=note)
        return Capabilities(
            can_scan=True, can_list_devices=True, can_deauth=True,
            scan_note=f"Monitor mode on {self.interface} via airmon-ng/airodump-ng.",
            device_note="Capturing station MACs with airodump-ng.",
            deauth_note="aireplay-ng deauth (needs monitor mode + injection support).",
        )

    @staticmethod
    def _interface_exists(name: str) -> bool:
        try:
            r = subprocess.run(["ip", "link", "show", name],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return r.returncode == 0
        except Exception:
            return False

    @staticmethod
    def _run_quiet(cmd: list[str]) -> int:
        try:
            return subprocess.run(cmd, stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL).returncode
        except Exception:
            return 1

    def _clean(self, prefix):
        for suffix in ("-01.csv", "-01.kismet.csv", "-01.kismet.netxml", "-01.cap"):
            p = prefix + suffix
            if os.path.exists(p):
                try:
                    os.remove(p)
                except Exception:
                    pass

    def start_scan(self):
        self._clean(self._net_prefix)
        self._run_quiet(["sudo", "airmon-ng", "check", "kill"])
        self._run_quiet(["sudo", "airmon-ng", "start", self.interface])
        self._net_proc = subprocess.Popen(
            ["sudo", "airodump-ng", "--band", "abg", self.mon,
             "-w", self._net_prefix, "--output-format", "csv"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )

    def snapshot_networks(self) -> tuple[list[dict], str]:
        rows = self._parse_networks(self._net_prefix + "-01.csv")
        return rows, f"Scanning... {len(rows)} network(s)."

    def stop_scan(self):
        if self._net_proc and self._net_proc.poll() is None:
            try:
                self._net_proc.terminate()
            except Exception:
                pass
        self._net_proc = None

    def device_columns(self) -> tuple[str, ...]:
        return ("Station MAC", "BSSID", "Packets", "PWR", "Probed ESSIDs")

    def start_devices(self, target: dict):
        self._dev_target = target or {}
        self._clean(self._dev_prefix)
        bssid = target.get("BSSID", "")
        ch = target.get("CH", "")
        cmd = ["sudo", "airodump-ng"]
        if bssid:
            cmd += ["--bssid", bssid]
        if ch:
            cmd += ["-c", ch]
        cmd += ["-w", self._dev_prefix, "--output-format", "csv", self.mon]
        self._dev_proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def snapshot_devices(self) -> tuple[list[dict], str]:
        rows = self._parse_stations(self._dev_prefix + "-01.csv")
        return rows, f"Scanning... {len(rows)} device(s)."

    def stop_devices(self):
        if self._dev_proc and self._dev_proc.poll() is None:
            try:
                self._dev_proc.terminate()
            except Exception:
                pass
        self._dev_proc = None

    def deauth(self, bssid: str, station: str | None = None) -> tuple[bool, str]:
        count = "10" if station else "1"
        cmd = ["sudo", "aireplay-ng", "-0", count, "-a", bssid]
        if station:
            cmd += ["-c", station]
        cmd += [self.mon]
        try:
            subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True, "Sent deauth: " + " ".join(cmd)
        except Exception as e:
            return False, f"Deauth failed: {e}"

    def recover(self) -> tuple[bool, str]:
        try:
            subprocess.run(["sudo", "airmon-ng", "stop", self.mon],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["sudo", "systemctl", "restart", "NetworkManager"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True, "Stopped monitor mode and restarted NetworkManager."
        except Exception as e:
            return False, f"Recovery failed: {e}"

    # --- parsers (from the original code) ----------------------------------- #
    @staticmethod
    def _parse_networks(path: str) -> list[dict]:
        if not os.path.exists(path):
            return []
        nets = []
        try:
            with open(path, newline="", encoding="utf-8", errors="ignore") as f:
                for row in csv.reader(f):
                    if not row:
                        continue
                    if row[0].strip() == "Station MAC":
                        break
                    if row[0].strip() == "BSSID":
                        continue
                    if len(row) < 14:
                        continue
                    bssid = row[0].strip()
                    if len(bssid.split(":")) != 6:
                        continue
                    nets.append(_empty_net(
                        BSSID=bssid, CH=row[3].strip(), Band=_channel_to_band(row[3].strip()),
                        Privacy=row[5].strip(), Cipher=row[6].strip(), Auth=row[7].strip(),
                        PWR=row[8].strip(), Beacons=row[9].strip(), IV=row[10].strip(),
                        ESSID=row[13].strip(),
                    ))
        except Exception:
            return []
        nets.sort(key=_pwr, reverse=True)
        return nets

    @staticmethod
    def _parse_stations(path: str) -> list[dict]:
        if not os.path.exists(path):
            return []
        devices, index, in_station = [], {}, False
        try:
            with open(path, newline="", encoding="utf-8", errors="ignore") as f:
                for row in csv.reader(f):
                    if not row:
                        continue
                    if row[0].strip() == "Station MAC":
                        index = {n.strip(): i for i, n in enumerate(row)}
                        in_station = True
                        continue
                    if not in_station or (index and len(row) < len(index)):
                        continue

                    def get(col):
                        i = index.get(col)
                        return row[i].strip() if i is not None and i < len(row) else ""

                    smac = get("Station MAC")
                    if len(smac.split(":")) != 6:
                        continue
                    devices.append({
                        "Station MAC": smac, "BSSID": get("BSSID"),
                        "Packets": get("# packets"), "PWR": get("Power"),
                        "Probed ESSIDs": get("Probed ESSIDs"),
                    })
        except Exception:
            return []
        devices.sort(key=lambda s: int(s["Packets"]) if s["Packets"].isdigit() else 0, reverse=True)
        return devices


# --------------------------------------------------------------------------- #
#  Windows backend (placeholder with an honest message)
# --------------------------------------------------------------------------- #
class WindowsBackend(Backend):
    name = "windows"

    def capabilities(self) -> Capabilities:
        msg = ("Windows support is not wired up yet. Standard Windows Wi-Fi "
               "drivers cannot do monitor mode or packet injection, so "
               "disconnecting devices will require a specific USB adapter. "
               "Scanning/LAN discovery is planned next.")
        return Capabilities(scan_note=msg, device_note=msg, deauth_note=msg)


def _pwr(n: dict) -> int:
    try:
        return int(n.get("PWR", ""))
    except Exception:
        return -999


def get_backend() -> Backend:
    osname = current_os()
    if osname == "macos":
        return MacBackend()
    if osname == "windows":
        return WindowsBackend()
    return LinuxBackend()


if __name__ == "__main__":
    # Lightweight self-check that runs anywhere (parsers only, no Wi-Fi needed).
    b = get_backend()
    caps = b.capabilities()
    print(f"OS={current_os()} backend={b.name}")
    print(f"  scan={caps.can_scan} devices={caps.can_list_devices} deauth={caps.can_deauth}")
    print(f"  deauth_note: {caps.deauth_note}")
