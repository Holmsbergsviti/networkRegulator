"""Regression test: a gated feature button (Route / Cut off / Disconnect) must
stay CLICKABLE and explain what's missing when clicked, instead of being a dead
greyed button that does nothing. Static checks run anywhere; the live check runs
only if a Tk display is available (e.g. under Xvfb).
Run: python3 test_locked_buttons.py"""
# Ensure the repo root is importable when this suite is run from tests/.
import os as _os, sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))

import os

fails = []
total = 0


def check(name, cond):
    global total
    total += 1
    print(("  ok   " if cond else "  FAIL ") + name)
    if not cond:
        fails.append(name)


HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
dev = open(os.path.join(HERE, "network_scanner_devices.py")).read()
uisrc = open(os.path.join(HERE, "netreg_ui.py")).read()

print("static: gated buttons stay clickable, not disabled:")
check("a Locked.TButton style exists", 'Locked.TButton' in uisrc)
check("route button is locked, not disabled",
      'self.route_btn.config(style="Locked.TButton"' in dev)
check("cut button is locked, not disabled",
      'self.cut_btn.config(style="Locked.TButton"' in dev)
check("disconnect button is locked, not disabled",
      'self.disc_btn.config(style="Locked.TButton"' in dev)
check("no state=disabled left on the three gated buttons",
      'self.route_btn.config(state="disabled")' not in dev
      and 'self.cut_btn.config(state="disabled")' not in dev
      and 'self.disc_btn.config(state="disabled")' not in dev)
check("locked click shows a 'Why this is locked' explanation",
      dev.count('"Why this is locked"') >= 2)
check("route explanation names the brew install fix", "brew install bettercap" in dev)

print("live (skipped if no display):")
try:
    import tkinter as tk
    from tkinter import messagebox
    root = tk.Tk()
    root.withdraw()
except Exception as e:
    print(f"  skip  no Tk display ({e.__class__.__name__}) — static checks only")
else:
    captured = {}
    messagebox.showinfo = lambda title, msg: captured.update(title=title, msg=msg)
    import network_scanner_devices as nd
    w = nd.DevicesUI(root, essid="LAB")
    # Force the "no bettercap" gate deterministically (Linux backend differs).
    w._can_route = False
    w.route_btn.config(style="Locked.TButton", text="\U0001f512 Route via this Mac")
    root.update()
    check("live: route button is clickable (state normal)",
          str(w.route_btn["state"]) == "normal")
    check("live: route button carries the lock cue",
          "\U0001f512" in w.route_btn["text"])
    w.route_selected()           # exactly what a click does
    check("live: clicking a locked route button explains why",
          captured.get("title") == "Why this is locked"
          and "bettercap" in captured.get("msg", ""))
    root.destroy()

print()
if fails:
    print(f"{len(fails)}/{total} FAILED: {fails}")
    raise SystemExit(1)
print(f"All {total} checks passed.")
