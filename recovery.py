"""
recovery.py -- restore normal Wi-Fi after scanning/monitor mode.

Cross-platform: delegates to the active backend so it does the right thing on
macOS (cycle Wi-Fi power) and Linux (stop monitor mode, restart NetworkManager).
Can be run directly or called from the GUI.
"""
from netreg_backend import get_backend

if __name__ == "__main__":
    ok, msg = get_backend().recover()
    print(msg)
