# NetworkRegulator

A GUI for scanning and managing **your own** Wi-Fi network — no terminal
commands required. It wraps existing open-source tooling behind one interface
so you can see nearby networks, see the devices on your network, and (with the
right hardware) disconnect a device.

> ⚠️ Use this only on networks you own or are authorized to test. Deauthing
> devices on networks you don't control is illegal in most places.

## Running

```bash
python3 network_scanner.py
```

Double-click a network to open its devices window.

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

## Roadmap
1. ✅ Cross-platform backend split; macOS scan + device discovery.
2. Windows backend (scan/LAN discovery; adapter-gated deauth).
3. GUI polish: per-device actions, setup helper, richer device info.
4. Extra libraries: Scapy (custom packets), python-nmap (vendor/service info),
   per-device bandwidth monitoring.
