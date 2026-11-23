# LanLens

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
| Scan nearby networks  | ✅ `system_profiler`               | ✅ airodump-ng                | ⏳ planned     |
| List devices          | ✅ LAN scan (your network)         | ✅ airodump-ng stations       | ⏳ planned     |
| Disconnect (deauth)   | ⚠️ needs monitor-mode USB adapter  | ✅ aireplay-ng                | ❌ driver wall |

### macOS notes (current focus)
- **Scanning** and **device discovery** work out of the box with built-in
  macOS tools — no extra install.
- macOS does **not** expose other networks' BSSIDs, so that column may be blank.
- On recent macOS (14+), Wi-Fi **names** are hidden (`<redacted>`) from
  unprivileged tools — the network you're on is still labelled `(connected)`.

#### Build the double-click app (free, no Apple account)
macOS only shows the **Location** prompt (which unlocks real Wi-Fi names) and
the **Local Network** prompt (which fills the device list) to an app *bundle*
carrying the right `Info.plist` — a plain script can't get them. You can build
that bundle for free: no paid Apple Developer account, no notarization, just
ad-hoc signing. Run this **on your Mac**, in `~/dev/networkRegulator`:

```bash
./build_macapp.sh         # packages + ad-hoc-signs dist/LanLens.app
```

**First launch — get past Gatekeeper (one time):** because the app is ad-hoc
signed (not signed with a paid Developer ID), the very first double-click shows
*"LanLens can't be opened because it is from an unidentified developer."* That's
expected. To open it the first time:

> **right-click (or Control-click) `dist/LanLens.app` → Open → Open**

After that one time, a normal double-click works forever.

On first launch, **allow Location** (reveals Wi-Fi names, read via Apple's
CoreWLAN API) and **allow Local Network** (lists devices) when macOS asks. The
build script installs the `pyobjc` frameworks it needs
(`pyobjc-framework-CoreWLAN`, `pyobjc-framework-CoreLocation`) for you.

*Self-contained alternative:* `python3 -m pip install --user py2app && python3
setup.py py2app` builds a standalone `dist/LanLens.app` that bundles its own
Python (runs on a Mac with no dev tools). Same free ad-hoc signing, same
one-time Gatekeeper step.

> **What the free path does and doesn't do:** ad-hoc signing + the usage-string
> `Info.plist` is enough for the Location/Local-Network prompts to appear and
> for real Wi-Fi names to show on **your own Mac**. Notarization (which needs a
> paid account) is only required to *distribute* the app to other Macs without
> the Gatekeeper warning — it is **not** needed for the permissions to work
> locally.
- **Disconnecting** a device needs packet injection, which the **built-in Mac
  card cannot do**. To enable it:
  1. `brew install aircrack-ng`
  2. Plug in a monitor-mode-capable USB Wi-Fi adapter.
  3. Put it in monitor mode and set `NETREG_MON_IFACE` to that interface
     (e.g. `export NETREG_MON_IFACE=en1`).

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
2. Windows backend (scan/LAN discovery; adapter-gated deauth).
3. GUI polish: per-device actions, setup helper, richer device info.
4. Extra libraries: Scapy (custom packets), python-nmap (vendor/service info),
   per-device bandwidth monitoring.
