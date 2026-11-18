#!/bin/bash
#
# run.command -- double-click this in Finder to launch NetworkRegulator.
#
# macOS runs a .command file in Terminal when you double-click it, so you don't
# have to type anything. (First time only: if macOS blocks it as being from an
# "unidentified developer", right-click the file -> Open, then click Open.)
#
cd "$(dirname "$0")"

# Pull the latest version if this is a git checkout. Best-effort: --ff-only so
# it never makes surprise merge commits, and it never blocks launch -- if you
# have local edits or no network, it just runs the version you already have.
if [ -d .git ] && command -v git >/dev/null 2>&1; then
  echo "Checking for updates…"
  git pull --ff-only 2>&1 || echo "(couldn't update — launching the current version)"
fi

# First-run convenience: make sure the Wi-Fi-name libraries are present so real
# SSIDs can show. Harmless if they're already installed or the install fails.
if ! python3 -c "import CoreWLAN, CoreLocation" >/dev/null 2>&1; then
  echo "Setting up Wi-Fi support (first run only)…"
  python3 -m pip install --user --quiet \
    pyobjc-framework-CoreWLAN pyobjc-framework-CoreLocation >/dev/null 2>&1 || true
fi

echo "Launching NetworkRegulator…"
exec python3 network_scanner.py
