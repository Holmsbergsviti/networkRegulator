"""Unit tests for the security hardening (offline: no root, no network).

Covers:
  * AppleScript-literal escaping in the osascript wrappers (a " or \\ in an
    argument can't break out of `do shell script "..."`),
  * IP validation on the spoof / redirect / capture targets,
  * MAC/BSSID validation before a value reaches aireplay-ng.

Run: python3 test_security_hardening.py
"""
# Ensure the repo root is importable when this suite is run from tests/.
import os as _os, sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))

import netreg_mitm as m
import netreg_https as h
import netreg_printcap as p
import netreg_backend as b

fails, total = [], 0


def check(name, cond):
    global total
    total += 1
    print(("  ok   " if cond else "  FAIL ") + name)
    if not cond:
        fails.append(name)


print("AppleScript-literal escaping:")
# A raw " or \ must be escaped so it can't terminate the do-shell-script literal.
for mod in (m, h, p):
    esc = mod._osa_escape('a"b\\c')
    check(f"{mod.__name__}: quote escaped", '\\"' in esc)
    check(f"{mod.__name__}: backslash escaped", "\\\\" in esc)
    check(f"{mod.__name__}: no bare quote remains",
          '"' not in esc.replace('\\"', ""))

# End to end: a hostile interface name with a quote stays inside the literal.
cmd = m._mac_admin_command(["bettercap", "-iface", 'e"n0'], None)
literal = cmd[-1]
check("mitm wrapper is an osascript do-shell-script",
      cmd[0] == "osascript" and literal.startswith('do shell script "'))
check("embedded quote is escaped in the final literal", '\\"' in literal)

print("target IP validation:")
try:
    m.build_eval("not-an-ip; rm -rf /")
    check("build_eval rejects non-IP", False)
except ValueError:
    check("build_eval rejects non-IP", True)
check("build_eval accepts a real IP", "192.168.1.5" in m.build_eval("192.168.1.5"))

try:
    h.build_pf_rules('1.2.3.4" evil')
    check("build_pf_rules rejects non-IP", False)
except ValueError:
    check("build_pf_rules rejects non-IP", True)
check("build_pf_rules accepts a real IP",
      "from 10.0.0.9 " in h.build_pf_rules("10.0.0.9"))

try:
    p.build_filter("garbage")
    check("build_filter rejects non-IP", False)
except ValueError:
    check("build_filter rejects non-IP", True)
check("build_filter accepts a real IP", "host 192.168.0.4" in p.build_filter("192.168.0.4"))

print("MAC/BSSID validation:")
check("valid colon MAC accepted", b._valid_mac("aa:bb:cc:dd:ee:ff"))
check("valid dash MAC accepted", b._valid_mac("AA-BB-CC-DD-EE-FF"))
check("empty rejected", not b._valid_mac(""))
check("flag-looking value rejected", not b._valid_mac("-c eth0"))
check("too short rejected", not b._valid_mac("aa:bb:cc"))

# deauth refuses a bad BSSID before building any command (no hardware needed:
# both backends check the MAC first and return (False, msg)).
for backend_cls in (b.MacBackend, b.LinuxBackend):
    try:
        inst = backend_cls.__new__(backend_cls)  # skip __init__ (no hardware)
        inst._has_aircrack = True
        inst.mon = "mon0"
        import os as _os
        _os.environ["NETREG_MON_IFACE"] = "en1"
        ok, msg = inst.deauth("not-a-mac")
        check(f"{backend_cls.__name__}.deauth refuses a bad BSSID",
              ok is False and "valid" in msg.lower())
    except Exception as e:
        check(f"{backend_cls.__name__}.deauth refuses a bad BSSID (raised {e!r})", False)

print()
if fails:
    print(f"{len(fails)}/{total} FAILED: {fails}")
    raise SystemExit(1)
print(f"All {total} checks passed.")
