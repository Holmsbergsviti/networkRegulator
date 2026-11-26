"""Regression test: bettercap must be found even when it's not on PATH, because
a macOS app launched from Finder doesn't inherit the Homebrew PATH. Pure/offline.
Run: python3 test_bettercap_path.py"""
# Ensure the repo root is importable when this suite is run from tests/.
import os as _os, sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))

import os
import shutil
import stat
import tempfile

import netreg_mitm as m

fails = []
total = 0


def check(name, cond):
    global total
    total += 1
    print(("  ok   " if cond else "  FAIL ") + name)
    if not cond:
        fails.append(name)


print("bettercap detection:")

# 1) When it's on PATH, use that.
orig_which = shutil.which
shutil.which = lambda n: "/some/path/bettercap" if n == "bettercap" else None
try:
    check("uses PATH when available", m.bettercap_path() == "/some/path/bettercap")
    check("available() true when on PATH", m.available() is True)
finally:
    shutil.which = orig_which

# 2) When NOT on PATH, fall back to a known install dir (simulate Homebrew).
tmp = tempfile.mkdtemp()
fake = os.path.join(tmp, "bettercap")
with open(fake, "w") as f:
    f.write("#!/bin/sh\n")
os.chmod(fake, os.stat(fake).st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)

shutil.which = lambda n: None            # nothing on PATH
orig_dirs = m._BETTERCAP_DIRS
m._BETTERCAP_DIRS = (tmp,)               # pretend Homebrew lives here
try:
    check("falls back to a known install dir off PATH", m.bettercap_path() == fake)
    check("available() true via fallback", m.available() is True)
finally:
    shutil.which = orig_which
    m._BETTERCAP_DIRS = orig_dirs

# 3) Nothing anywhere -> not available (and preflight explains).
shutil.which = lambda n: None
m._BETTERCAP_DIRS = ("/no/such/dir",)
try:
    check("empty when truly absent", m.bettercap_path() == "")
    check("available() false when absent", m.available() is False)
    ready, msg = m.preflight()
    check("preflight explains the install", (ready is False) and ("bettercap" in msg))
finally:
    shutil.which = orig_which
    m._BETTERCAP_DIRS = orig_dirs

# 4) The real Apple-Silicon Homebrew dir is in the checked list.
check("checks /opt/homebrew/bin (Apple Silicon Homebrew)",
      "/opt/homebrew/bin" in m._BETTERCAP_DIRS)
check("checks /usr/local/bin (Intel Homebrew)",
      "/usr/local/bin" in m._BETTERCAP_DIRS)

try:
    os.remove(fake)
    os.rmdir(tmp)
except OSError:
    pass

print()
if fails:
    print(f"{len(fails)}/{total} FAILED: {fails}")
    raise SystemExit(1)
print(f"All {total} checks passed.")
