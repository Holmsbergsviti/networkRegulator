"""netreg_restore.py -- undo any network manipulation LanLens can start.

Routing / cut-off (bettercap ARP spoof), HTTPS inspection (pf redirect +
mitmdump + IP forwarding) and print capture (tcpdump) each run as background
*root* processes. Normally each window's stop()/close tears its own down, but a
crash or force-quit can leave them running — a cut-off device stays offline, a
pf redirect stays up, and the user is none the wiser.

This module is the safety net:

  * active_manipulations() / leftover_processes(): detect what's live right now,
    using only unprivileged `pgrep`/`sysctl` reads, so the UI can offer a
    cleanup on startup (after a crash) or before quitting, with no password
    prompt just to look.
  * restore_all(): a *stateless* "panic" teardown — it kills those processes by
    name and flushes pf + IP forwarding, independent of any live session
    objects, so it works even after the window that started them is gone. One
    osascript admin prompt on macOS; sudo elsewhere.

The command strings are pure functions (unit-tested). Executing them needs root.
"""
from __future__ import annotations

import subprocess
import sys

# Processes LanLens may have started, as (key, detection argv, human label).
_PROCS = (
    ("bettercap", ["pgrep", "-x", "bettercap"], "routing / cut-off (bettercap)"),
    ("mitmdump", ["pgrep", "-x", "mitmdump"], "HTTPS inspection (mitmproxy)"),
    ("tcpdump-print", ["pgrep", "-f", "tcpdump.*LanLens-print"],
     "print capture (tcpdump)"),
)


def _osa_escape(s: str) -> str:
    """Escape for an AppleScript double-quoted literal (osascript runs
    `do shell script "<this>"`)."""
    return s.replace("\\", "\\\\").replace('"', '\\"')


def _forwarding_key() -> str:
    return "net.inet.ip.forwarding" if sys.platform == "darwin" else "net.ipv4.ip_forward"


# ---- detection (unprivileged) ------------------------------------------- #
def _running(cmd) -> bool:
    try:
        return subprocess.run(cmd, stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL).returncode == 0
    except Exception:
        return False


def _ip_forwarding_on() -> bool:
    try:
        out = subprocess.run(["sysctl", "-n", _forwarding_key()],
                             capture_output=True, text=True, timeout=4).stdout.strip()
        return out == "1"
    except Exception:
        return False


def _proc_states() -> dict:
    return {key: _running(cmd) for key, cmd, _ in _PROCS}


# ---- pure helpers (unit-tested) ----------------------------------------- #
def process_labels(running: dict) -> list[str]:
    """The labels of LanLens processes that `running` marks as live."""
    return [label for key, _cmd, label in _PROCS if running.get(key)]


def summarize_leftovers(running: dict, forwarding: bool) -> list[str]:
    """Everything that looks active: our processes, plus IP forwarding if it's
    still on. Pure, so it's testable without touching the system."""
    items = process_labels(running)
    if forwarding:
        items.append("IP forwarding still on")
    return items


def build_macos_restore_script() -> str:
    """One root shell line that stops every manipulation and clears pf +
    forwarding. `true` at the end keeps a non-zero from a no-op from surfacing
    as an error in the GUI."""
    return (
        "pkill -INT -x bettercap 2>/dev/null; "
        "pkill -INT -x mitmdump 2>/dev/null; "
        "pkill -INT -f 'tcpdump.*LanLens-print' 2>/dev/null; "
        "pfctl -F nat 2>/dev/null; pfctl -d 2>/dev/null; "
        "sysctl -w net.inet.ip.forwarding=0 2>/dev/null; true")


def build_linux_restore_argvs() -> list[list[str]]:
    """Per-command argvs for Linux (each run under sudo -n)."""
    return [
        ["pkill", "-INT", "-x", "bettercap"],
        ["pkill", "-INT", "-x", "mitmdump"],
        ["pkill", "-INT", "-f", "tcpdump.*LanLens-print"],
        ["sysctl", "-w", "net.ipv4.ip_forward=0"],
    ]


# ---- public API --------------------------------------------------------- #
def active_manipulations() -> list[str]:
    """Human-readable list of everything that looks active (procs + forwarding).
    Used for the panic-button confirmation and the startup prompt's wording."""
    return summarize_leftovers(_proc_states(), _ip_forwarding_on())


def leftover_processes() -> list[str]:
    """Just the LanLens *processes* that are live. The startup check keys on
    this (not on IP forwarding, which can legitimately be on for Internet
    Sharing) so it doesn't nag without a real leftover."""
    return process_labels(_proc_states())


def restore_all() -> tuple[bool, str]:
    """Stop every manipulation and clear pf + forwarding, regardless of whether
    a live session object owns them. Needs root."""
    before = active_manipulations()
    if sys.platform == "darwin":
        script = build_macos_restore_script()
        try:
            subprocess.run(
                ["osascript", "-e",
                 f'do shell script "{_osa_escape(script)}" '
                 f'with administrator privileges'],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as e:
            return False, f"Couldn't run the restore: {e}"
    elif sys.platform.startswith("linux"):
        for argv in build_linux_restore_argvs():
            try:
                subprocess.run(["sudo", "-n"] + argv,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception:
                pass
    else:
        return True, "Nothing to restore on this platform."
    after = active_manipulations()
    if after:
        return False, ("Restore ran, but these may still be active: "
                       + ", ".join(after) + ". Try again, or stop them by hand.")
    if before:
        return True, ("Restored — stopped " + ", ".join(before)
                      + " and cleared pf / IP forwarding.")
    return True, "Nothing was active; the network is clean."


if __name__ == "__main__":
    print("active manipulations:", active_manipulations() or "(none)")
    print("macOS restore script:", build_macos_restore_script())
