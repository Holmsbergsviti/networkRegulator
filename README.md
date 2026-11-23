# NetworkRegulator

A GUI for scanning and managing **your own** Wi-Fi network — no terminal
commands required. It wraps existing open-source tooling behind one interface
so you can see nearby networks, see the devices on your network, and (with the
right hardware) disconnect a device.

> ⚠️ Use this only on networks you own or are authorized to test. Deauthing
> devices on networks you don't control is illegal in most places.

## Running

**Easiest (macOS, no Terminal):** double-click **`run.command`** in Finder.
The app launches in a window; you don't type anything. (First time only: if
macOS blocks it as an "unidentified developer", right-click `run.command` →
**Open** → **Open**.)

**From a terminal (any platform):**

```bash
python3 network_scanner.py
```

Double-click a network to open its devices window, and double-click a device to
see its details and open ports.

## Platform support

All OS-specific logic lives in `netreg_backend.py`, selected automatically at
startup. Check what your machine can do:

```bash
python3 netreg_backend.py
```

| Capability            | macOS                              | Linux                         | Windows        |
|-----------------------|------------------------------------|-------------------------------|----------------|
| Scan nearby networks  | ✅ `system_profiler`               | ✅ airodump-ng                | ✅ `netsh wlan` |
| List devices          | ✅ LAN scan (your network)         | ✅ airodump-ng stations       | ✅ LAN scan     |
| Disconnect (deauth)   | ⚠️ needs monitor-mode USB adapter  | ✅ aireplay-ng                | ❌ driver wall  |

### macOS notes (current focus)
- **Scanning** and **device discovery** work out of the box with built-in
  macOS tools — no extra install.
- macOS does **not** expose other networks' BSSIDs, so that column may be blank.
- On recent macOS (14+), Wi-Fi **names** are hidden (`<redacted>`) from
  unprivileged tools — the network you're on is still labelled `(connected)`.

#### Seeing real Wi-Fi names (optional, macOS 14+)
To unlock real SSIDs you must run the app as a bundle that holds Location
Services permission (a plain script can't). No paid Apple account needed:

```bash
./build_macapp.sh         # packages + ad-hoc-signs dist/NetworkRegulator.app
open dist/NetworkRegulator.app
```

Allow **Location** when macOS prompts on first launch. The app then reads
names via Apple's CoreWLAN API. Requires `pyobjc` (the build script installs
`pyobjc-framework-CoreWLAN` and `pyobjc-framework-CoreLocation` for you).
- **Disconnecting** a device needs packet injection, which the **built-in Mac
  card cannot do**. To enable it:
  1. `brew install aircrack-ng`
  2. Plug in a monitor-mode-capable USB Wi-Fi adapter.
  3. Put it in monitor mode and set `NETREG_MON_IFACE` to that interface
     (e.g. `export NETREG_MON_IFACE=en1`).

### Windows notes
- **Scanning** uses the built-in `netsh wlan show networks` — nothing to
  install. Unlike macOS, Windows **does** show neighbouring networks' BSSIDs,
  so a mesh/extender shows one row per access point.
- **Device discovery** is a LAN ping-sweep that fills the Windows ARP table,
  then reads it with `arp -a` — same approach as macOS. No admin rights needed.
- **Disconnecting (deauth)** is **not possible** with standard Windows Wi-Fi
  drivers: they can't do monitor mode or packet injection. That needs a special
  USB adapter with injection-capable drivers (and in practice a Linux/aircrack
  setup). The app says so instead of failing silently.
- Scan parsing anchors on the English `netsh` labels; on a non-English Windows
  the SSID/BSSID/signal still parse, but channel/auth labels may not.

### Linux notes
Set `NETREG_IFACE` if your wireless interface isn't `wlp0s20f3`. Run with the
privileges aircrack-ng needs. "Restore Wi-Fi" stops monitor mode and restarts
NetworkManager.

## Inspecting traffic (own network only)

Double-click a device → **Inspect print traffic** to check whether the print
jobs you send to a printer are encrypted. Tick the authorization box, press
**Start capture**, then print a test page or document from this Mac. The tool
captures the traffic on the print ports (raw/9100, IPP/631, LPD/515, IPPS/443)
with the built-in `tcpdump` and tells you plainly:

- **PLAINTEXT** — the job was sent in the clear; anyone sniffing the LAN could
  read it. The window shows the document/job name and a readable snippet.
- **Encrypted (TLS)** — the job used IPPS/TLS; observers see only that you
  printed, not what.

This reads *this Mac's own* jobs, so no ARP spoofing is needed. (To inspect
another device's jobs to the printer, use **Route via this Mac** first, then
capture.) `tcpdump` ships with macOS; you'll be prompted for your password
because capturing needs root.

## Roadmap
1. ✅ Cross-platform backend split; macOS scan + device discovery.
2. ✅ Windows backend (native `netsh` scan + LAN device discovery).
3. GUI polish: per-device actions, setup helper, richer device info.
4. Extra libraries: Scapy (custom packets), python-nmap (vendor/service info),
   per-device bandwidth monitoring.
