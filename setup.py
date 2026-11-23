"""
setup.py -- py2app build for LanLens (the self-contained macOS .app).

This is the OTHER free path. Where build_macapp.sh makes a thin bundle that runs
against the Mac's own `python3`, py2app produces a standalone .app with its own
bundled Python, so it runs on a Mac that has no developer tools installed. It is
still the FREE path: ad-hoc signing, no Apple Developer account, no notarization.

Build it (on a Mac):

    python3 -m pip install --user py2app
    python3 setup.py py2app
    # -> dist/LanLens.app   (ad-hoc signed by py2app)

First launch still needs the one-time Gatekeeper step (right-click -> Open),
same as the shell-built bundle. See README / build_macapp.sh for details.

The Info.plist (including the Location + Local Network usage strings that unlock
real Wi-Fi names and the device list) comes from packaging/appinfo.py, so both
build paths stay in sync.
"""
from setuptools import setup

from packaging import appinfo

APP = [f"{appinfo.ENTRY_MODULE}.py"]

# Every application module except the test files and packaging helpers. py2app
# follows imports, but listing them keeps the dynamically-imported child windows
# (imported lazily inside the GUI) from being dropped.
DATA_FILES = [("data", ["data/oui_vendors.tsv.gz"])]

OPTIONS = {
    "argv_emulation": False,
    "plist": appinfo.info_plist(),
    "iconfile": "packaging/LanLens.icns",  # built by build_macapp.sh / iconutil
    # The GUI imports these lazily (import inside a method) so name them so
    # py2app bundles them.
    "includes": [
        "network_scanner_devices",
        "device_detail",
        "channel_window",
        "mitm_window",
        "print_capture_window",
        "netreg_backend",
        "netreg_ui",
        "netreg_probe",
        "netreg_channels",
        "netreg_devicedb",
        "netreg_fingerprint",
        "netreg_report",
        "netreg_bandwidth",
        "netreg_speedtest",
        "netreg_https",
        "netreg_https_addon",
        "netreg_mitm",
        "netreg_traffic",
        "netreg_printcap",
        "netreg_integrations",
        "netreg_oui",
        "netreg_seen",
        "mac_native",
        "mac_wifi_helper",
        "recovery",
    ],
}

setup(
    name=appinfo.APP_NAME,
    app=APP,
    data_files=DATA_FILES,
    options={"py2app": OPTIONS},
    setup_requires=["py2app"],
)
