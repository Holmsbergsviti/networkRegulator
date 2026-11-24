#!/bin/bash
#
# build_macapp.sh -- package LanLens as a double-clickable macOS .app.
#
# This is the FREE path. It needs no paid Apple Developer account and no
# notarization. It uses ad-hoc code signing ("sign with -"), which is enough to
# run the app on your own Mac and -- crucially -- enough for macOS to show the
# Location Services prompt that unlocks real Wi-Fi network names, plus the Local
# Network prompt that lets the device list populate.
#
# RUN THIS ON A MAC (it produces a .app and uses macOS-only tools: codesign,
# sips, iconutil). It will not produce a usable bundle on Linux.
#
#   Usage:   ./build_macapp.sh
#   Then:    open dist/LanLens.app
#
# FIRST LAUNCH / Gatekeeper: because the app is ad-hoc signed (not signed with a
# paid Developer ID and not notarized), a normal double-click the very first time
# shows "LanLens can't be opened because it is from an unidentified developer".
# That is expected. To get past it ONCE:
#     right-click (or Control-click) LanLens.app  ->  Open  ->  Open
# After that first time, a normal double-click works forever.
#
set -euo pipefail
cd "$(dirname "$0")"

# ---- metadata (single source of truth: packaging/appinfo.py) ----------------
PY="${PYTHON:-python3}"
APP_NAME="$("$PY" -m packaging.appinfo name)"
ENTRY="$("$PY" -m packaging.appinfo entry)"
APP="dist/${APP_NAME}.app"

echo "==> Building ${APP_NAME}.app (free / ad-hoc path)"

# ---- pyobjc check (CoreWLAN + CoreLocation give real Wi-Fi names) ------------
echo "==> Checking macOS Wi-Fi/location Python support (pyobjc)…"
if ! "$PY" -c "import CoreWLAN, CoreLocation" >/dev/null 2>&1; then
  echo "    Installing pyobjc frameworks (CoreWLAN, CoreLocation)…"
  "$PY" -m pip install --user --quiet \
    pyobjc-framework-CoreWLAN pyobjc-framework-CoreLocation 2>/dev/null \
    || echo "    (pip install failed — install manually: $PY -m pip install pyobjc-framework-CoreWLAN pyobjc-framework-CoreLocation)"
fi

# ---- assemble the bundle ----------------------------------------------------
echo "==> Assembling $APP"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources/data"

# Bundle every application Python module (everything except the test_*.py files
# and the packaging helpers). Globbing keeps this correct as modules are added.
shopt -s nullglob
for f in *.py; do
  case "$f" in
    test_*.py) continue ;;
    *) cp "$f" "$APP/Contents/Resources/" ;;
  esac
done
# Bundle the OUI (MAC -> manufacturer) database so vendor lookup works.
cp data/oui_vendors.tsv.gz "$APP/Contents/Resources/data/"
# Bundle the interpreter picker so the launcher can choose a modern-Tk python3.
cp packaging/pick_python.sh "$APP/Contents/Resources/"

# ---- Info.plist (from packaging/appinfo.py) ---------------------------------
echo "==> Writing Info.plist"
"$PY" -m packaging.appinfo plist > "$APP/Contents/Info.plist"

# ---- icon -------------------------------------------------------------------
echo "==> Building app icon"
"$PY" packaging/make_icon.py packaging/LanLens.png || true
if [ -f packaging/LanLens.png ] && command -v iconutil >/dev/null 2>&1 \
   && command -v sips >/dev/null 2>&1; then
  ICONSET="$(mktemp -d)/${APP_NAME}.iconset"
  mkdir -p "$ICONSET"
  for s in 16 32 128 256 512; do
    sips -z "$s" "$s"       packaging/LanLens.png --out "$ICONSET/icon_${s}x${s}.png"     >/dev/null
    sips -z "$((s*2))" "$((s*2))" packaging/LanLens.png --out "$ICONSET/icon_${s}x${s}@2x.png" >/dev/null
  done
  iconutil -c icns "$ICONSET" -o "packaging/${APP_NAME}.icns"
  cp "packaging/${APP_NAME}.icns" "$APP/Contents/Resources/${APP_NAME}.icns"
  # Point the plist at the icon file (add the key if the builder omitted it).
  /usr/libexec/PlistBuddy -c "Add :CFBundleIconFile string ${APP_NAME}" \
     "$APP/Contents/Info.plist" 2>/dev/null \
    || /usr/libexec/PlistBuddy -c "Set :CFBundleIconFile ${APP_NAME}" \
     "$APP/Contents/Info.plist" 2>/dev/null || true
  echo "    icon: ${APP_NAME}.icns"
else
  echo "    (skipped .icns — need sips + iconutil on macOS; app still works)"
fi

# ---- launcher ---------------------------------------------------------------
cat > "$APP/Contents/MacOS/${APP_NAME}" <<LAUNCH
#!/bin/bash
DIR="\$(cd "\$(dirname "\$0")/../Resources" && pwd)"
cd "\$DIR"
# Pick a python3 whose Tk is >= 8.6.13; an older Tk paints a blank window on
# recent macOS. Falls back to env python3 if the picker isn't present.
PY="/usr/bin/env python3"
if [ -f "\$DIR/pick_python.sh" ]; then
  . "\$DIR/pick_python.sh"
  PICKED="\$(lanlens_pick_python)"
  [ -n "\$PICKED" ] && PY="\$PICKED"
fi
exec \$PY ${ENTRY}.py
LAUNCH
chmod +x "$APP/Contents/MacOS/${APP_NAME}"

# ---- ad-hoc code signing (free) ---------------------------------------------
echo "==> Ad-hoc code-signing (free; no Developer account)"
ENT="packaging/${APP_NAME}.entitlements"
if [ -f "$ENT" ]; then
  codesign --force --deep --sign - --entitlements "$ENT" "$APP" \
    || echo "    codesign failed — the app may still run but Location may not prompt."
else
  codesign --force --deep --sign - "$APP" \
    || echo "    codesign failed — the app may still run but Location may not prompt."
fi

echo ""
echo "Done: $APP"
echo ""
echo "FIRST launch (gets past Gatekeeper, once):"
echo "    right-click ${APP}  ->  Open  ->  Open"
echo "After that, just double-click it like any app."
echo ""
echo "On first launch, allow Location (reveals Wi-Fi names) and Local Network"
echo "(lists devices) when macOS asks."
