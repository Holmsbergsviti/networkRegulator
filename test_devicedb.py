"""Unit tests for netreg_devicedb (pure, offline, temp-file store).
Covers the new is_private_mac() / seen_info() plus label & known/new basics.
Run: python3 test_devicedb.py"""
import os
import tempfile

import netreg_devicedb as db

fails, total = [], 0
def check(name, cond):
    global total; total += 1
    print(("  ok   " if cond else "  FAIL ") + name)
    if not cond: fails.append(name)

print("is_private_mac (locally-administered 0x02 bit):")
check("randomized MAC flagged (0x66)", db.is_private_mac("66:b9:33:06:a8:93") is True)
check("hardware Apple MAC not flagged (0x7c)", db.is_private_mac("7c:d1:ad:4c:d0:54") is False)
check("short first octet handled (0x0a)", db.is_private_mac("a:ff:fa:b2:a9:f2") is True)
check("dash format handled", db.is_private_mac("66-b9-33-06-a8-93") is True)
check("globally-unique even first octet not flagged (0x60)", db.is_private_mac("60:32:b1:0d:bb:d2") is False)
check("empty -> False", db.is_private_mac("") is False)
check("garbage -> False", db.is_private_mac("not-a-mac") is False)

print("seen_info + known/new on a temp store:")
p = os.path.join(tempfile.mkdtemp(), "devices.json")
d = db.DeviceDB(p, clock=lambda: 1000.0)
check("unknown MAC -> (None, None)", d.seen_info("aa:bb:cc:dd:ee:ff") == (None, None))
check("first mark_seen is new", d.mark_seen("aa:bb:cc:dd:ee:ff") is True)
check("second mark_seen is not new", d.mark_seen("aa:bb:cc:dd:ee:ff") is False)
first, last = d.seen_info("AA:BB:CC:DD:EE:FF")
check("seen_info records first_seen", first == 1000.0)
check("seen_info records last_seen", last == 1000.0)
check("is_known true after mark_seen", d.is_known("aa:bb:cc:dd:ee:ff") is True)

print("labels persist + case-insensitive key:")
d.set_label("aa:bb:cc:dd:ee:ff", "Test TV")
check("label set and read back", d.label("AA:BB:CC:DD:EE:FF") == "Test TV")
d2 = db.DeviceDB(p)
check("label survives reload", d2.label("aa:bb:cc:dd:ee:ff") == "Test TV")

print()
if fails:
    print(f"{len(fails)}/{total} FAILED: {fails}"); raise SystemExit(1)
print(f"All {total} checks passed.")
