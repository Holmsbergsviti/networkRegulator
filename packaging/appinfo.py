"""
appinfo.py -- single source of truth for the LanLens macOS app bundle.

Both the hand-rolled bundler (build_macapp.sh, via `python3 -m packaging.appinfo
plist`) and the py2app build (setup.py) read their metadata from here, so the
app name, bundle id, version and the Info.plist usage strings are defined in
exactly one place.

Why the usage strings matter: macOS only shows the Location Services prompt (the
thing that unlocks real Wi-Fi network names instead of "<redacted>") when the
app bundle carries an Info.plist with the NSLocation* usage-description keys.
The Local Network prompt (needed to list devices) needs NSLocalNetworkUsage
Description + NSBonjourServices. None of this needs a paid Apple Developer
account or notarization -- an ad-hoc-signed bundle with this plist is enough for
the prompts to appear on the Mac that built it.
"""
from __future__ import annotations

APP_NAME = "LanLens"
BUNDLE_ID = "com.lanlens.app"
VERSION = "1.0"
# Entry-point module run by the app launcher (the main scan window).
ENTRY_MODULE = "network_scanner"
MIN_MACOS = "12.0"

# User-facing reasons shown in the macOS permission prompts.
LOCATION_USAGE = (
    "LanLens needs your location to read the names of the Wi-Fi networks "
    "around you. macOS hides network names from apps without this permission."
)
LOCAL_NETWORK_USAGE = (
    "LanLens needs Local Network access to find the devices on the Wi-Fi "
    "network you are on."
)
# Bonjour service types LanLens may browse while discovering devices.
BONJOUR_SERVICES = ["_http._tcp", "_workstation._tcp", "_device-info._tcp"]


def info_plist() -> dict:
    """The Info.plist contents as a plain dict (plistlib-serialisable)."""
    return {
        "CFBundleName": APP_NAME,
        "CFBundleDisplayName": APP_NAME,
        "CFBundleIdentifier": BUNDLE_ID,
        "CFBundleVersion": VERSION,
        "CFBundleShortVersionString": VERSION,
        "CFBundleExecutable": APP_NAME,
        "CFBundlePackageType": "APPL",
        "LSMinimumSystemVersion": MIN_MACOS,
        "NSHighResolutionCapable": True,
        # Location -> real Wi-Fi names
        "NSLocationWhenInUseUsageDescription": LOCATION_USAGE,
        "NSLocationUsageDescription": LOCATION_USAGE,
        # Local Network -> device list
        "NSLocalNetworkUsageDescription": LOCAL_NETWORK_USAGE,
        "NSBonjourServices": list(BONJOUR_SERVICES),
    }


def info_plist_xml() -> str:
    """Info.plist serialised as an XML string (for the shell bundler)."""
    import plistlib
    return plistlib.dumps(info_plist()).decode("utf-8")


if __name__ == "__main__":
    import sys
    what = sys.argv[1] if len(sys.argv) > 1 else "plist"
    if what == "plist":
        sys.stdout.write(info_plist_xml())
    elif what == "name":
        sys.stdout.write(APP_NAME)
    elif what == "bundle_id":
        sys.stdout.write(BUNDLE_ID)
    elif what == "entry":
        sys.stdout.write(ENTRY_MODULE)
    elif what == "version":
        sys.stdout.write(VERSION)
    else:
        sys.stderr.write(f"unknown field: {what}\n")
        sys.exit(2)
