#!/bin/bash
#
# run.command -- double-click this in Finder to launch NetworkRegulator.
#
# macOS runs a .command file in Terminal when you double-click it, so you don't
# have to type anything. (First time only: if macOS blocks it as being from an
# "unidentified developer", right-click the file -> Open, then click Open.)
#
cd "$(dirname "$0")"

# First-run convenience: make sure the Wi-Fi-name libraries are present so real
# SSIDs can show. Harmless if they're already installed or the install fails.
if ! python3 -c "import CoreWLAN, CoreLocation" >/dev/null 2>&1; then
  echo "Setting up Wi-Fi support (first run only)…"
  python3 -m pip install --user --quiet \
    pyobjc-framework-CoreWLAN pyobjc-framework-CoreLocation >/dev/null 2>&1 || true
fi

echo "Launching NetworkRegulator…"
exec python3 network_scanner.py
