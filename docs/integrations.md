# Library integrations — how the net-new tools are wired in

This is the implementation companion to [`libraries.md`](libraries.md). It
describes how the recommended open-source libraries are connected into
NetworkRegulator so they can actually be used, and how to enable each one.

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

## What's probed but not yet active (Layer 3 — own-network only)

`availability()` already reports these so the GUI can show what's installed and
plan the next step. They are **active / intrusive** tools, lawful only on a
network you own or are authorized to test, and will be gated behind an explicit
confirmation when wired up:

- **pywifi** — scan / connect-disconnect this machine's Wi-Fi
- **bettercap** — ARP-spoof / gateway impersonation + MITM (via its REST API)
- **mitmproxy** — inspect / modify redirected HTTP(S)
- **mdk4 / wifite2** — richer / automated deauth on top of aircrack-ng

## Enabling the optional libraries

```bash
# Layer 1 (recommended; pure Python, cross-platform)
pip install -r requirements.txt      # getmac, mac-vendor-lookup, zeroconf

# Layer 2 fast scanners (external binaries)
brew install naabu rustscan nmap     # macOS (use your package manager elsewhere)

# Layer 3 active tools (own-network/authorized only)
brew install bettercap mdk4 aircrack-ng
pip install pywifi mitmproxy
```

`mac-vendor-lookup` downloads the IEEE OUI database on first use (needs network
once); until then, the bundled `netreg_oui.py` table covers common vendors
offline.

## Verifying

```bash
python3 netreg_integrations.py   # prints what's available + sample lookups
python3 test_integrations.py     # 25 offline unit checks (OUI table, enrichment, fallbacks)
python3 netreg_backend.py        # backend self-check (parsers only, no Wi-Fi needed)
```

> **Authorization.** Device discovery, port scanning and vendor lookup are
> passive and safe on your own LAN. The Layer-3 tools (MITM, deauth) are for
> networks you own or are explicitly authorized to test only.
