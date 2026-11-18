#!/bin/bash
#
# build_macapp.sh -- package NetworkRegulator as a signed macOS .app so it can
# request Location Services and read real Wi-Fi names (CoreWLAN).
#
# Usage:   ./build_macapp.sh
# Then:    open dist/NetworkRegulator.app   (grant Location on first launch)
#
# No paid Apple Developer account needed: this uses free ad-hoc signing, which
# is enough to run the app on your own Mac.
set -euo pipefail
cd "$(dirname "$0")"

APP="dist/NetworkRegulator.app"
BUNDLE_ID="com.networkregulator.app"
USAGE="NetworkRegulator reads the Wi-Fi network name for networks you are on."

echo "==> Checking Python Wi-Fi/location support (pyobjc)…"
if ! python3 -c "import CoreWLAN, CoreLocation" >/dev/null 2>&1; then
  echo "    Installing pyobjc frameworks (CoreWLAN, CoreLocation)…"
  python3 -m pip install --user --quiet \
    pyobjc-framework-CoreWLAN pyobjc-framework-CoreLocation 2>/dev/null \
    || echo "    (pip install failed — install manually: python3 -m pip install pyobjc-framework-CoreWLAN pyobjc-framework-CoreLocation)"
fi

echo "==> Assembling $APP"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"

cp netreg_backend.py network_scanner.py network_scanner_devices.py \
   device_detail.py recovery.py mac_native.py "$APP/Contents/Resources/"

cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>NetworkRegulator</string>
  <key>CFBundleDisplayName</key><string>NetworkRegulator</string>
  <key>CFBundleIdentifier</key><string>${BUNDLE_ID}</string>
  <key>CFBundleVersion</key><string>1.0</string>
  <key>CFBundleShortVersionString</key><string>1.0</string>
  <key>CFBundleExecutable</key><string>NetworkRegulator</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>LSMinimumSystemVersion</key><string>12.0</string>
  <key>NSHighResolutionCapable</key><true/>
  <key>NSLocationWhenInUseUsageDescription</key><string>${USAGE}</string>
  <key>NSLocationUsageDescription</key><string>${USAGE}</string>
</dict>
</plist>
PLIST

cat > "$APP/Contents/MacOS/NetworkRegulator" <<'LAUNCH'
#!/bin/bash
DIR="$(cd "$(dirname "$0")/../Resources" && pwd)"
cd "$DIR"
exec /usr/bin/env python3 network_scanner.py
LAUNCH
chmod +x "$APP/Contents/MacOS/NetworkRegulator"

echo "==> Ad-hoc code-signing"
codesign --force --deep --sign - "$APP" || {
  echo "    codesign failed — the app may still run but Location may not prompt."
}

echo ""
echo "Done: $APP"
echo "Launch it with:   open \"$APP\""
echo "On first launch, allow Location when macOS asks — that's what reveals Wi-Fi names."
