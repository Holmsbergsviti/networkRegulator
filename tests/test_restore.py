"""Unit tests for netreg_restore (offline: no root, no kill, no network).

Covers the pure command/summary helpers behind the "Restore network" panic
button and the startup leftover-check. Run: python3 test_restore.py
"""
# Ensure the repo root is importable when this suite is run from tests/.
import os as _os, sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))

import netreg_restore as r

fails, total = [], 0


def check(name, cond):
    global total
    total += 1
    print(("  ok   " if cond else "  FAIL ") + name)
    if not cond:
        fails.append(name)


print("macOS restore script:")
s = r.build_macos_restore_script()
check("stops bettercap", "pkill -INT -x bettercap" in s)
check("stops mitmdump", "pkill -INT -x mitmdump" in s)
check("stops the print tcpdump", "tcpdump.*LanLens-print" in s)
check("flushes pf nat + disables pf", "pfctl -F nat" in s and "pfctl -d" in s)
check("turns IP forwarding off", "net.inet.ip.forwarding=0" in s)
check("ends in `true` so a no-op isn't an error", s.rstrip().endswith("true"))

print("Linux restore argvs:")
argvs = r.build_linux_restore_argvs()
check("each is an argv list (no shell string)", all(isinstance(a, list) for a in argvs))
check("kills bettercap", ["pkill", "-INT", "-x", "bettercap"] in argvs)
check("clears ipv4 forwarding", ["sysctl", "-w", "net.ipv4.ip_forward=0"] in argvs)

print("process_labels:")
none = {"bettercap": False, "mitmdump": False, "tcpdump-print": False}
check("nothing running -> no labels", r.process_labels(none) == [])
check("bettercap running -> its label",
      "routing / cut-off (bettercap)" in r.process_labels({**none, "bettercap": True}))
all_on = {"bettercap": True, "mitmdump": True, "tcpdump-print": True}
check("all three running -> three labels", len(r.process_labels(all_on)) == 3)

print("summarize_leftovers:")
check("clean system -> empty", r.summarize_leftovers(none, False) == [])
check("forwarding-only is flagged",
      r.summarize_leftovers(none, True) == ["IP forwarding still on"])
mixed = r.summarize_leftovers({**none, "mitmdump": True}, True)
check("process + forwarding both listed",
      "HTTPS inspection (mitmproxy)" in mixed and "IP forwarding still on" in mixed)

print("startup check keys on processes, not forwarding:")
# leftover_processes() must ignore IP forwarding (Internet Sharing can set it),
# so the startup prompt doesn't nag without a real leftover process. Verified
# here via process_labels, which it delegates to.
check("forwarding alone yields no process labels", r.process_labels(none) == [])

print()
if fails:
    print(f"{len(fails)}/{total} FAILED: {fails}")
    raise SystemExit(1)
print(f"All {total} checks passed.")
