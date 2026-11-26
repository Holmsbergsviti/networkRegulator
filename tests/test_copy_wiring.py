"""Static checks that table copy support is wired in. Run: python3
test_copy_wiring.py (offline, no display needed -- it reads source, it does not
build a GUI; the live copy behaviour is verified under Xvfb separately)."""
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


def src(name):
    return open(os.path.join(HERE, name)).read()


print("enable_copy helper:")
ui = src("netreg_ui.py")
check("netreg_ui defines enable_copy", "def enable_copy(tree):" in ui)
check("binds Cmd+C (macOS)", "<Command-c>" in ui)
check("binds Ctrl+C (win/linux)", "<Control-c>" in ui)
check("has a right-click menu (Button-2/3)", "<Button-2>" in ui and "<Button-3>" in ui)
check("exposes copy_selection for use/tests", "tree.copy_selection = copy_rows" in ui)

print("every results table enables copy:")
for f in ("mitm_window.py", "network_scanner.py", "network_scanner_devices.py",
          "device_detail.py"):
    s = src(f)
    # each Treeview that gets styled should also get copy enabled
    n_style = s.count("ui.style_tree(")
    n_copy = s.count("ui.enable_copy(")
    check(f"{f}: every styled tree enables copy ({n_copy}/{n_style})",
          n_copy >= n_style and n_copy > 0)

print()
if fails:
    print(f"{len(fails)}/{total} FAILED: {fails}")
    raise SystemExit(1)
print(f"All {total} checks passed.")
