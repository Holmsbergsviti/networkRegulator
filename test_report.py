"""Unit tests for netreg_report. Run: python3 test_report.py  (offline)."""
import datetime
import os
import tempfile

import netreg_report as rep

fails = []
total = 0


def check(name, cond):
    global total
    total += 1
    print(("  ok   " if cond else "  FAIL ") + name)
    if not cond:
        fails.append(name)


FIXED = datetime.datetime(2026, 11, 23, 14, 0, 0)
devs = [
    {"IP": "192.168.1.190", "MAC": "7c:d1:ad:4c:d0:54", "Vendor": "Apple",
     "Hostname": "Vlad-iPhone"},
    {"IP": "192.168.1.1", "MAC": "60:32:b1:d:bb:d2", "Vendor": "TP-Link Technologies",
     "Hostname": "", "_ports": [53, 80]},
]
nets = [{"ESSID": "UGA008", "CH": "36", "Band": "5", "PWR": "-55", "BSSID": "aa:bb"}]

print("netreg_report.build_report:")
r = rep.build_report(networks=nets, devices=devs,
                     meta={"network": "UGA008", "iface": "en0"},
                     gateway_ip="192.168.1.1", now=FIXED)
check("has a title", r.startswith("# LanLens snapshot"))
check("includes the fixed timestamp", "2026-11-23 14:00:00" in r)
check("counts devices", "**Devices found:** 2" in r)
check("lists both device IPs", "192.168.1.1" in r and "192.168.1.190" in r)
check("devices sorted by IP (.1 before .190)",
      r.index("192.168.1.1 |") < r.index("192.168.1.190"))
check("classifies the gateway as a router", "Router / gateway" in r)
check("classifies the apple host as a phone", "Phone / tablet" in r)
check("includes the networks section", "## Wi-Fi networks seen" in r and "UGA008" in r)
check("own-network footer present", "Own-network use only" in r)

print("empty input:")
r0 = rep.build_report(now=FIXED)
check("no devices -> placeholder", "_No devices recorded._" in r0)
check("no crash, still has title", r0.startswith("# LanLens snapshot"))

print("default_filename + save_report:")
fn = rep.default_filename(now=FIXED)
check("filename has timestamp + .md", fn == "netreg-snapshot-20261123-140000.md")
path = os.path.join(tempfile.gettempdir(), fn)
rep.save_report(r, path)
check("file written with content", os.path.exists(path) and open(path).read() == r)
os.remove(path)

print()
if fails:
    print(f"{len(fails)}/{total} FAILED: {fails}")
    raise SystemExit(1)
print(f"All {total} checks passed.")
