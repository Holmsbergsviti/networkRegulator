# Network Libraries & Tools — Research Catalog (net-new finds)

> **Scope & authorization.** This project operates **only on networks the owner controls** (own home/lab network, for defensive testing and self-administration). Several tools below (ARP/LLMNR spoofing, MITM, deauth) are *lawful only on networks you own or are explicitly authorized to test*. Using them elsewhere is illegal in most jurisdictions. Everything here is catalogued for own-network, authorized use.

**Focus of this doc: libraries we do _not_ already use.** Our current stack is nmap, scapy, aircrack-ng, and raw sockets (summarized at the very bottom for reference). Everything in the numbered sections below is a **net-new** candidate — grouped by task, with key functions, how it'd plug into our GUI backend, and macOS/Windows/Linux notes (our priority order). The handful of already-in-use tools that appear are only there as a baseline to compare against, and are labeled **[IN USE]**.

---

## Quick answer: "the library that lets a computer imitate the router so all traffic goes through it"

This is **ARP spoofing / gateway impersonation** (man-in-the-middle). Since we only have scapy today, the net-new recommendation is:

### ⭐ bettercap — https://github.com/bettercap/bettercap  (Go; MIT) — **NET-NEW**
Modern successor to ettercap. `arp.spoof` does the gateway impersonation; it also has a **REST API + scriptable caplets**, so we can drive it from our GUI without a terminal.
- `net.probe on` — discover every host on the subnet.
- `set arp.spoof.targets <ip,…>` + `set arp.spoof.fullduplex true` + `arp.spoof on` — impersonate the gateway; target traffic now flows through this machine.
- `net.sniff on` (+ `net.sniff.filter`, `net.sniff.output`) — inspect / save the redirected traffic.
- `dns.spoof`, `http.proxy`/`https.proxy` — act on traffic once it's flowing through you.
- `api.rest` module — our Python backend POSTs commands instead of parsing stdout (cleanest integration).

> On "**especially IP 211**": most likely you mean *targeting the gateway* (often `192.168.x.1`, but on your LAN it may end in `.211`, or `.211` is the device whose traffic you want routed). **Tell me what `192.168.x.211` is (a device, or the router) and I'll give exact bettercap commands / a ready caplet.**

Net-new alternatives covered in §4: **mitmproxy**, **Responder**, **dnschef**, plus the classics ettercap / arpspoof.

---

## 1. Device discovery — net-new

| Library | Lang | Install | Why it's new/useful |
|---|---|---|---|
| **getmac** | Python | `pip install getmac` | Cross-platform MAC lookup for **local interfaces AND remote hosts** — pure-Python, no nmap dependency. Great portable fallback. |
| **pywifi** | Python | `pip install pywifi` | Programmatic **wifi scanning + connect/disconnect** control (SSID list, signal, connect). Windows/Linux first-class; macOS limited (see note). |
| **python-zeroconf** | Python | `pip install zeroconf` | **mDNS/Bonjour** discovery — names Chromecasts, printers, AirPlay, HomeKit, `_http._tcp`, etc. Gives friendly names to devices with no reverse DNS. |
| **async-upnp-client** / **upnpclient** | Python | `pip install async-upnp-client` | **UPnP/SSDP** discovery — routers, smart TVs, media servers; can also read device descriptions. |
| **netdisco** | Python | `pip install netdisco` | High-level UPnP+mDNS roll-up (used by Home Assistant) → friendly device *types* (Sonos, Roku, Hue). |
| **impacket** | Python | `pip install impacket` | **NetBIOS/SMB** name resolution → hostnames + OS hints for Windows devices the mDNS/UPnP sweeps miss. Huge protocol toolkit. |
| **ifaddr** / **netifaces2** / **psutil** | Python | `pip install ifaddr psutil` | Enumerate our own interfaces/subnets cleanly and cross-platform (what to scan, which gateway). Replaces brittle shell parsing. |

**getmac** — `get_mac_address(ip="192.168.1.5")`, `get_mac_address(interface="en0")`, `get_mac_address(hostname="host.local")`. Works macOS/Windows/Linux. The simplest portable way to attach a MAC to every discovered IP without shelling out to `arp`.

**pywifi** — `PyWiFi().interfaces()`, `iface.scan()` → `iface.scan_results()` (each has `.ssid`, `.bssid`, `.signal`), `iface.connect(profile)` / `iface.disconnect()`. This is the clean cross-platform way to build the "scan wifi networks" and "connect/disconnect *this machine*" UI.
> **macOS note:** pywifi's macOS backend is limited. The native route on macOS is **CoreWLAN** via **pyobjc** (`CWWiFiClient.sharedWiFiClient().interface().scanForNetworks_error_(...)`) — net-new, first-class Apple API for SSID scan + signal. Worth a thin macOS adapter.

**python-zeroconf / UPnP** — these fill the biggest gap in our current sweep: a device answers a ping but shows as a bare IP. mDNS/UPnP turn that into "Living Room TV (Samsung)".

---

## 2. Port / service scanning — net-new

| Library | Lang | Install | Why it's new/useful |
|---|---|---|---|
| **naabu** | Go (ProjectDiscovery) | `brew install naabu` | Fast SYN/CONNECT scanner with **JSON output** and host-discovery; built for scripting/pipelines. Can hand results to nmap for `-sV`. Actively maintained. |
| **RustScan** | Rust | `brew install rustscan` | **Ultra-fast** full-range scan, then auto-pipes open ports **into nmap** for service detection. Best "find everything in seconds" front-end. |
| **masscan** | C | `brew install masscan` | Asynchronous, internet-scale rate; good for a whole-subnet "what's listening anywhere" sweep. |

**naabu** — `naabu -host 192.168.1.0/24 -top-ports 1000 -json`. The JSON output parses straight into our backend (no stdout scraping), and its design (discovery → port list → hand to nmap) matches how we'd want the GUI to work: fast first pass, detailed second pass on click.

**RustScan** — `rustscan -a 192.168.1.10 --range 1-65535 -- -sV`. Everything after `--` is passed to nmap, so we get speed *and* version detection in one call.

> Pattern for us: **naabu/RustScan for the fast sweep, nmap `-sV` for the deep dive.** This replaces our plain `connect()` loop (which has no banner/version info) while keeping nmap only where it adds value.

---

## 3. MAC → vendor (OUI) lookup — net-new

| Library | Lang | Install | Notes |
|---|---|---|---|
| **mac-vendor-lookup** | Python | `pip install mac-vendor-lookup` | `MacLookup().lookup(mac)` → "Cisco Systems". `AsyncMacLookup` for non-blocking GUI. `update_vendors()` refreshes the IEEE OUI DB. |
| **manuf** | Python | `pip install manuf` | Offline (ships Wireshark's OUI table): `MacParser().get_manuf_long(mac)`. No network call at scan time. |
| **netaddr** | Python | `pip install netaddr` | Bonus OUI org name (`EUI(mac).oui.registration().org`) **plus** subnet math (`IPNetwork(...).iter_hosts()`) we already need to enumerate a /24. |

Pair with **getmac** (§1) to get the address, then one of these to name the vendor. Note **MAC randomization** on modern phones → no/variable vendor; worth a UI tooltip.

---

## 4. Traffic redirection / MITM — net-new (we only have scapy)

**Lawful only on your own / authorized network.** Ordered best-fit first.

- **bettercap** — primary, see Quick Answer. ARP spoof + sniff + DNS/HTTP tampering + REST/caplets.
- **mitmproxy** — `pip install mitmproxy`. The Python-native way to **inspect and modify HTTP/HTTPS** once traffic routes through us (install its CA cert on the device for TLS). Scriptable with Python addons → fits our backend perfectly. Cross-platform.
- **Responder** — https://github.com/SpiderLabs/Responder. A *different* MITM vector than ARP: poisons **LLMNR / NBT-NS / mDNS** name resolution so Windows devices talk to us. Useful on mixed home networks; net-new.
- **dnschef** — a configurable **DNS proxy/spoofer**; redirect chosen domains once you're in-path (or as the LAN's DNS). Lightweight, scriptable.
- **ettercap** / **arpspoof (dsniff)** — the classic ARP-MITM tools; bettercap supersedes ettercap, arpspoof is the minimal one-liner (`arpspoof -i <if> -t <target> <gateway>` + IP forwarding).

**Cross-platform MITM reality:** Linux cleanest; **macOS** works for ARP spoof/sniff on the built-in interface (`sysctl -w net.inet.ip.forwarding=1`, needs sudo); **Windows** needs **Npcap** + IP forwarding via `netsh`/registry (lowest priority).

---

## 5. Wifi deauth / disconnect — net-new (we have aircrack-ng)

Disconnecting over wifi = sending **deauth frames**, which needs **monitor mode + injection**.

| Tool | Lang | Why it's new/useful |
|---|---|---|
| **bettercap** `wifi.deauth` | Go | Deauth inside the same framework we'd use for MITM — one dependency for both. |
| **mdk4** | C | Beyond aircrack: **deauth, auth floods, beacon floods, disassociation** — a fuller wireless-stress toolkit. `mdk4 <mon> d -B <BSSID>`. |
| **wifite2** | Python | **Automation wrapper** that drives aircrack-ng/others end-to-end (pick target → attack). Good model for our "one-click disconnect" flow. |
| **airgeddon** | Bash | Menu-driven framework wrapping the suite; useful reference for how to orchestrate the tools cleanly. |
| **kismet** | C++ | Passive wireless **detection/monitoring** (not deauth) — maps APs/clients/signal; good recon layer. |

**Hard platform limits (unchanged):** macOS built-in card **can't inject** → needs a USB monitor-mode adapter; Windows standard drivers can't do monitor mode (scan-only); Linux works with injection-capable chipsets. These apply to mdk4/bettercap/wifite2 the same as to aircrack-ng.

---

## 6. Traffic / flow analysis — net-new (supporting)

| Library | Lang | Why it's new/useful |
|---|---|---|
| **nfstream** | Python | Turns live traffic or a pcap into **flows with 90+ statistical features** (+ optional app/protocol ID). Ideal for a "what is this device actually talking to" view. `NFStreamer(source="en0")`. |
| **pyshark** | Python | tshark wrapper — parse live/offline captures with **Wireshark's dissectors** (deep protocol decode) without reimplementing them. |
| **p0f** | C | **Passive** OS/device fingerprinting from observed traffic — identify devices without sending a single probe. Stealthy, safe on your own LAN. |
| **dpkt** | Python | Fast, low-level pcap parsing when we want speed over convenience. |

---

## Recommended net-new additions (shortlist)

1. **getmac** + **mac-vendor-lookup** — portable MAC + vendor column. Cheap, high value, cross-platform. *(start here)*
2. **python-zeroconf** (+ UPnP) — friendly device names in the device list.
3. **naabu** or **RustScan** — fast port sweep, handing to nmap `-sV` on click.
4. **pywifi** (+ **CoreWLAN/pyobjc** on macOS) — scan/connect wifi from the GUI.
5. **bettercap** — router-impersonation / MITM, driven via its REST API + a caplet; **mitmproxy** to act on the traffic.
6. **mdk4** / **wifite2** — richer/automated deauth on top of our aircrack-ng base.
7. **nfstream** — per-device traffic view.

Gate anything in §4/§5 behind an explicit "I own / authorize this network" confirmation, and auto-restore state (ARP tables) on stop.

---

## Already in use (reference only — not the focus)

| Task | Tool we already have |
|---|---|
| Device discovery | raw `socket` ping + ARP-table parse (`network_scanner_devices.py`) |
| Port scanning | raw `socket` TCP connect scan (`device_detail.py`) |
| Discovery/MITM primitives | **scapy** |
| Wifi scan + deauth | **aircrack-ng** suite + macOS built-in tools |

The net-new tools above are meant to *layer on top of* these, not replace them wholesale.

---

## Sources
- bettercap: https://www.bettercap.org/modules/ · https://github.com/bettercap/bettercap
- naabu (ProjectDiscovery): https://github.com/projectdiscovery/naabu · https://docs.projectdiscovery.io/tools/naabu · RustScan: https://github.com/RustScan/RustScan · masscan: https://github.com/robertdavidgraham/masscan
- getmac: https://pypi.org/project/getmac/ · pywifi: https://pypi.org/project/pywifi/ · CoreWLAN (pyobjc): https://developer.apple.com/documentation/corewlan
- python-zeroconf: https://pypi.org/project/zeroconf/ · async-upnp-client: https://pypi.org/project/async-upnp-client/ · netdisco: https://pypi.org/project/netdisco/ · impacket: https://github.com/fortra/impacket
- mac-vendor-lookup: https://pypi.org/project/mac-vendor-lookup/ · manuf: https://pypi.org/project/manuf/ · netaddr: https://pypi.org/project/netaddr/
- mitmproxy: https://mitmproxy.org/ · Responder: https://github.com/SpiderLabs/Responder · dnschef: https://github.com/iphelix/dnschef · ettercap: https://www.ettercap-project.org · dsniff/arpspoof: https://www.monkey.org/~dugsong/dsniff/
- mdk4: https://github.com/aircrack-ng/mdk4 · wifite2: https://github.com/kimocoder/wifite2 · airgeddon: https://github.com/v1s1t0r1sh3r3/airgeddon · kismet: https://www.kismetwireless.net/
- nfstream: https://www.nfstream.org/ · pyshark: https://pypi.org/project/pyshark/ · p0f: https://lcamtuf.coredump.cx/p0f3/ · dpkt: https://pypi.org/project/dpkt/

*Capabilities reflect each project's documented feature set; naabu, getmac, pywifi, nfstream, Responder, mdk4/wifite2/airgeddon, and dnschef were cross-checked against current sources during this research. Exact flags/function names should be re-confirmed against the installed version at implementation time.*
