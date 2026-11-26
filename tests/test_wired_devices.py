"""Regression test: "View devices" must still work when there are no Wi-Fi
networks to pick (a wired-only PC, or Wi-Fi disconnected). Instead of a
dead-end "Pick a network" prompt, it should scan this computer's own LAN.

Static checks run anywhere; the live check runs only if a Tk display is
available (e.g. under Xvfb).
Run: python3 tests/test_wired_devices.py
"""
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
src = open(os.path.join(HERE, "network_scanner.py")).read()

print("static: empty-list falls back to a local LAN scan, not a dead end:")
check("open_selected_devices has the no-networks fallback branch",
      "if not self._current_networks() and self.caps.can_list_devices:" in src)
check("the fallback calls _open_local_devices",
      "self._open_local_devices()" in src)
check("a _open_local_devices method is defined",
      "def _open_local_devices(self):" in src)
check("it opens the devices window with a blank (local) target",
      'network_scanner_devices.open_devices(self, "", "", "")' in src)
check("the 'Pick a network' prompt is still there for the forgot-to-select case",
      '"Pick a network"' in src)

print("live (skipped if no display):")
try:
    import tkinter as tk
    from tkinter import messagebox
    root = tk.Tk()
    root.withdraw()
except Exception as e:
    print(f"  skip  no Tk display ({e.__class__.__name__}) — static checks only")
else:
    import network_scanner as ns
    import network_scanner_devices as nd

    # Capture what open_selected_devices decides to do, without opening windows.
    calls = {"local": 0, "picked": 0, "prompt": None}
    messagebox.showinfo = lambda title, msg: calls.update(prompt=title)

    # Build a NetworksUI without running its heavy __init__: we only exercise
    # the decision method against a couple of stubbed attributes.
    w = ns.NetworksUI.__new__(ns.NetworksUI)

    class _Caps:
        can_list_devices = True
    w.caps = _Caps()
    w._empty_iid = "EMPTY"

    class _Tree:
        def __init__(self, sel):
            self._sel = sel
        def selection(self):
            return self._sel
    w.tree = _Tree(())  # nothing selected

    w._current_networks = lambda: []          # no networks to pick
    w._open_local_devices = lambda: calls.update(local=calls["local"] + 1)

    ns.NetworksUI.open_selected_devices(w)
    check("no networks + nothing selected -> local LAN scan (no prompt)",
          calls["local"] == 1 and calls["prompt"] is None)

    # With networks present but none selected, it should still prompt, not scan.
    calls.update(local=0, prompt=None)
    w._current_networks = lambda: [{"ESSID": "HomeNet"}]
    ns.NetworksUI.open_selected_devices(w)
    check("networks present + nothing selected -> 'Pick a network' prompt",
          calls["local"] == 0 and calls["prompt"] == "Pick a network")

print()
if fails:
    print(f"{len(fails)}/{total} FAILED: {fails}")
    _sys.exit(1)
print(f"{total}/{total} passed")
