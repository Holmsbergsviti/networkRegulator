#!/bin/bash
# pick_python.sh -- print the best python3 to run LanLens's Tk GUI with.
#
# Why: macOS ships, and users install, Pythons with very different Tk versions.
# Tk < 8.6.13 is broken on recent macOS (Sonoma / Sequoia / macOS 26): the
# window opens but its content never paints -- you get a blank dark window. The
# bug is fixed in Tk 8.6.13+. The old system-ish python.org 3.9 build carries
# Tk 8.6.11, so launching LanLens with it shows nothing.
#
# This picks the first interpreter whose Tk is >= 8.6.13, preferring newer
# python.org / Homebrew installs, and falls back to any python3 with tkinter so
# the app still launches if nothing modern is installed.
#
# Sourced by the app bundle launcher and by run.command; defines one function.

lanlens_pick_python() {
  local cand
  for cand in \
    /Library/Frameworks/Python.framework/Versions/3.13/bin/python3 \
    /Library/Frameworks/Python.framework/Versions/3.12/bin/python3 \
    /Library/Frameworks/Python.framework/Versions/3.11/bin/python3 \
    /opt/homebrew/bin/python3 \
    /usr/local/bin/python3 \
    "$(command -v python3 2>/dev/null)"; do
    [ -n "$cand" ] || continue
    { [ -x "$cand" ] || command -v "$cand" >/dev/null 2>&1; } || continue
    # Ask this interpreter for its Tk patchlevel; accept it only if >= 8.6.13.
    if "$cand" - <<'PY' >/dev/null 2>&1
import sys, tkinter
r = tkinter.Tk(); r.withdraw()
v = tuple(int(x) for x in str(r.tk.call("info", "patchlevel")).split(".")[:3])
r.destroy()
sys.exit(0 if v >= (8, 6, 13) else 1)
PY
    then
      printf '%s\n' "$cand"
      return 0
    fi
  done
  # Nothing modern found: fall back to any python3 that at least has tkinter, so
  # the app launches (it may render blank on an old Tk -- best effort).
  for cand in "$(command -v python3 2>/dev/null)" /usr/bin/python3; do
    [ -n "$cand" ] || continue
    if "$cand" -c 'import tkinter' >/dev/null 2>&1; then
      printf '%s\n' "$cand"
      return 0
    fi
  done
  printf 'python3\n'
}
