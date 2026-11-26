"""Regression test: the device window must not crash when a background port
scan / probe finishes AFTER the window is closed. Static checks run anywhere;
the live check runs only if a Tk display is available (e.g. under Xvfb).
Run: python3 test_device_detail_guard.py"""
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
src = open(os.path.join(HERE, "device_detail.py")).read()

print("static: worker callbacks go through the guarded _post:")
check("defines a guarded _post helper", "def _post(self, func" in src)
check("_on_close marks the window not-alive", "self._alive = False" in src)
check("scan-done dispatch uses _post (not raw after)",
      "self._post(self._scan_done" in src and "self.after(0, self._scan_done" not in src)
check("add-port dispatch uses _post", "self._post(self._add_port" in src)
check("no raw worker self.after(0, ...) left",
      "self.after(0," not in src)

print("live (skipped if no display):")
try:
    import tkinter as tk
    root = tk.Tk()
    root.withdraw()
except Exception as e:
    print(f"  skip  no Tk display ({e.__class__.__name__}) — static checks only")
else:
    import device_detail as dd
    w = dd.DeviceDetailUI(root, ip="")  # ip="" => no network threads spawned
    root.update()
    ran = {"n": 0}
    w._post(lambda: ran.__setitem__("n", ran["n"] + 1))
    root.update()
    check("live: _post runs while window is alive", ran["n"] == 1)
    w._on_close()                      # close the window
    root.update()
    crashed = False
    try:
        # exactly the call that used to crash: late scan-done after close
        w._post(w._scan_done, "late", "idle")
        root.update()
        w._post(lambda: w.scan_btn.config(state="normal"))  # gone widget
        root.update()
    except Exception:
        crashed = True
    check("live: late callback after close does not crash", not crashed)
    root.destroy()

print()
if fails:
    print(f"{len(fails)}/{total} FAILED: {fails}")
    raise SystemExit(1)
print(f"All {total} checks passed.")
