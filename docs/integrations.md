# Library integrations — how the net-new tools are wired in

This is the implementation companion to [`libraries.md`](libraries.md). It
describes how the recommended open-source libraries are connected into
LanLens so they can actually be used, and how to enable each one.

## Design: optional layers with graceful fallback

Everything is routed through **`netreg_integrations.py`**, a single module that:

- **detects** what's installed (`availability()`), and
- **wraps** each capability so it returns a safe empty/fallback result when the
  library or binary is missing.

The app therefore runs with **none** of these installed, and gets richer as each
is added. Nothing new is a hard dependency.

```
netreg_backend.py ─┬─ imports netreg_integrations (best-effort)
                   │
netreg_integrations.py ─┬─ netreg_oui.py        (bundled offline OUI table)
                        ├─ getmac               (optional)
                        ├─ mac-vendor-lookup    (optional)
                        ├─ zeroconf / mDNS       (optional)
                        └─ naabu / rustscan      (optional, external binaries)
```

## What's wired in now (Layer 1–2)

| Capability | Library | Where it shows up | Fallback if absent |
|---|---|---|---|
| **Vendor name** per device | bundled `netreg_oui.py` → `manuf` → `mac-vendor-lookup` | New **Vendor** column in the devices window; Vendor field in the device-detail window | Built-in table still names common vendors; else blank |
| **Randomized-MAC flag** | `netreg_oui.py` | Vendor shows `randomized (private)` | — (always available) |
| **Friendly device names** | `zeroconf` (mDNS) | Fills the **Hostname** column when reverse-DNS is blank | Reverse DNS only |
| **MAC for an IP** | `getmac` | Fills a missing MAC on a discovered host | ARP table only |
| **Fast port scan** | `naabu` / `rustscan` | Device-detail "Scan Ports" uses them when on PATH | Built-in socket connect-scan |

The devices window and device-detail window render whatever columns the active
backend reports, so the **Vendor** column appears automatically on macOS (LAN
scan) and Linux (airodump stations).

## Layer 3 — active tools (own-network / authorized only)

These are **active / intrusive** and lawful only on a network you own or are
authorized to test. They are gated in the UI behind an explicit confirmation.

- **bettercap — route a device's traffic through this machine (WIRED IN).**
  `netreg_mitm.py` drives bettercap's `arp.spoof` to impersonate the gateway;
  `mitm_window.py` is the UI (opened from the devices window via **"Route via
  this Mac"**). The Start button stays disabled until you tick the
  "I own/authorized" box; closing the window restores the ARP tables. bettercap
  needs root, so on macOS it launches through the system password prompt.
- **pywifi** — installed + probed; scan / connect-disconnect this machine's Wi-Fi
  (UI not wired yet).
- **mitmproxy** — installed + probed; inspect / modify redirected HTTP(S)
  (pairs with the bettercap route above).
- **mdk4 / wifite2** — richer / automated deauth. Note **mdk4 is Linux-only**
  (not in Homebrew); on macOS deauth goes through aircrack-ng's `aireplay-ng`.

## Enabling everything (one click)

**`run.command` installs everything on the first run** — double-click it in
Finder and it will: pip-install the Python libraries (getmac, mac-vendor-lookup,
zeroconf, scapy, pywifi, mitmproxy, pyobjc), download the IEEE vendor database,
and `brew install` the command-line tools (aircrack-ng, bettercap, nmap, naabu,
rustscan). Later runs skip whatever's already installed. If Homebrew is missing
it prints the one-line install command and launches anyway.

To do it by hand instead:

```bash
pip install -r requirements.txt      # Layer 1 Python libs
brew install aircrack-ng bettercap nmap naabu rustscan
pip install pywifi mitmproxy
```

Two things no installer can provide: a **monitor-mode USB adapter** (hardware,
needed for Wi-Fi deauth on macOS), and **Homebrew** itself (install once from
https://brew.sh). `mac-vendor-lookup` downloads the IEEE OUI database on first
use; until then the bundled `netreg_oui.py` table covers common vendors offline.

## Verifying

```bash
python3 netreg_integrations.py   # prints what's available + sample lookups
python3 tests/test_integrations.py     # 32 offline unit checks (OUI table, enrichment, fallbacks, MITM command build)
python3 netreg_backend.py        # backend self-check (parsers only, no Wi-Fi needed)
```

> **Authorization.** Device discovery, port scanning and vendor lookup are
> passive and safe on your own LAN. The Layer-3 tools (MITM, deauth) are for
> networks you own or are explicitly authorized to test only.
