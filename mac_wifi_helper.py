"""
mac_wifi_helper.py -- run macOS CoreWLAN / CoreLocation in a SEPARATE process.

Why this exists: importing pyobjc frameworks (CoreWLAN, CoreLocation) pulls in
AppKit, which sets up the process's shared NSApplication. Tkinter on macOS ALSO
sets up its own NSApplication for its event loop. Doing both in one process --
especially from different threads at startup -- makes the two run-loop/NSApp
setups collide and the whole GUI beachballs (the "asked for Location, then it's
just stuck" hang).

The fix: the GUI process never imports pyobjc. Instead it shells out to this
tiny helper, which does the CoreWLAN/CoreLocation work in its own throwaway
process and prints the result as JSON. Because the helper is a child of the
LanLens .app bundle, the Location Services grant made to the bundle applies to
it too, so real SSID names still come through.

Usage (the backend calls these; a human normally won't):
    python3 mac_wifi_helper.py location   # trigger/refresh the Location prompt
    python3 mac_wifi_helper.py scan        # -> JSON list of networks (or null)
    python3 mac_wifi_helper.py ssid        # -> JSON string of connected SSID

Everything is soft-failing: on any error, or off macOS, it prints a safe empty
value and exits 0, so the caller just falls back to system_profiler.
"""
import json
import sys


def main(argv):
    cmd = argv[1] if len(argv) > 1 else ""
    try:
        import mac_native
    except Exception:
        # No pyobjc / not macOS: emit the empty value for the command.
        print(json.dumps(None if cmd == "scan" else ""))
        return 0

    if cmd == "location":
        try:
            mac_native.request_location()
        except Exception:
            pass
        print(json.dumps("ok"))
    elif cmd == "scan":
        try:
            nets = mac_native.scan_networks()
        except Exception:
            nets = None
        print(json.dumps(nets))
    elif cmd == "ssid":
        try:
            ssid = mac_native.connected_ssid()
        except Exception:
            ssid = ""
        print(json.dumps(ssid or ""))
    else:
        print(json.dumps(None))
        return 2
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except Exception:
        # Never let the helper crash noisily; the caller handles empty output.
        try:
            print(json.dumps(None))
        except Exception:
            pass
        sys.exit(0)
