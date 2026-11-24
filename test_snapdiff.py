"""Unit tests for netreg_snapdiff (pure, offline). Run: python3 test_snapdiff.py"""
import netreg_report as rep
import netreg_snapdiff as sd

fails, total = [], 0
def check(name, cond):
    global total; total += 1
    print(("  ok   " if cond else "  FAIL ") + name)
    if not cond: fails.append(name)

# Parser must read back exactly what build_report writes.
devs = [
    {"IP": "192.168.1.1", "MAC": "aa:bb:cc:00:00:01", "Vendor": "TP-Link", "Hostname": ""},
    {"IP": "192.168.1.50", "MAC": "de:ad:be:ef:00:02", "Vendor": "Apple", "Hostname": "Vlad"},
]
md = rep.build_report(devices=devs, meta={"network": "Home"})
parsed = sd.parse_devices(md)
print("parse_devices round-trips build_report:")
check("finds both device rows", len(parsed) == 2)
check("reads IP + MAC", parsed[0]["IP"] == "192.168.1.1" and parsed[0]["MAC"] == "aa:bb:cc:00:00:01")
check("skips header and separator rows",
      all(d["IP"] not in ("IP", "") for d in parsed))
check("ignores the Wi-Fi-networks table",
      all(d["MAC"].startswith(("aa", "de")) for d in parsed))

print("diff_devices:")
old = [{"IP": "192.168.1.1", "MAC": "aa:bb:cc:00:00:01", "Vendor": "TP-Link"},
       {"IP": "192.168.1.50", "MAC": "de:ad:be:ef:00:02", "Vendor": "Apple", "Hostname": "Vlad"}]
new = [{"IP": "192.168.1.1", "MAC": "aa:bb:cc:00:00:01", "Vendor": "TP-Link"},
       {"IP": "192.168.1.51", "MAC": "de:ad:be:ef:00:02", "Vendor": "Apple", "Hostname": "Vlad"},
       {"IP": "192.168.1.77", "MAC": "99:99:99:99:99:99", "Vendor": "Samsung"}]
r = sd.diff_devices(old, new)
check("new device detected as added",
      len(r["added"]) == 1 and r["added"][0]["MAC"] == "99:99:99:99:99:99")
check("nothing removed", r["removed"] == [])
check("IP change detected as changed",
      len(r["changed"]) == 1 and r["changed"][0][1]["IP"] == ("192.168.1.50", "192.168.1.51"))

print("identical lists -> no changes:")
r2 = sd.diff_devices(old, old)
check("no added/removed/changed", not (r2["added"] or r2["removed"] or r2["changed"]))
check("format says no changes", "No changes" in sd.format_diff(r2))

print("removed device:")
r3 = sd.diff_devices(old, [old[0]])
check("one removed", len(r3["removed"]) == 1 and not r3["added"])

print("key fallback + Station MAC:")
check("IP-keyed when MAC blank",
      sd.diff_devices([{"IP": "10.0.0.5", "MAC": ""}], [{"IP": "10.0.0.5", "MAC": ""}])["added"] == [])
check("Linux 'Station MAC' column is used as the key",
      sd.diff_devices([{"Station MAC": "ab:cd:ef:01:02:03"}],
                      [{"Station MAC": "ab:cd:ef:01:02:03"}])["added"] == [])

print("format_diff is readable:")
txt = sd.format_diff(r)
check("mentions new + changed", "New since" in txt and "Changed" in txt)

print()
if fails:
    print(f"{len(fails)}/{total} FAILED: {fails}"); raise SystemExit(1)
print(f"All {total} checks passed.")
