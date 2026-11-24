"""netreg_attest.py -- a local consent/authorization log.

The "I own this network / authorized" checkbox in the Route, Cut-off, HTTPS and
print-capture windows is a CONSENT gate, not a technical control: it records
that the user affirmed ownership, it can't verify it. This module leaves a
local, timestamped, append-only record of each affirmation and the target it
was made against, so there's an audit trail of what was authorized and when.

Best-effort only: it never raises and never blocks the action.
"""
import os
import sys
import tempfile
import time


def _log_path() -> str:
    mac_logs = os.path.join(os.path.expanduser("~"), "Library", "Logs")
    if sys.platform == "darwin" and os.path.isdir(mac_logs):
        return os.path.join(mac_logs, "LanLens-attestations.log")
    return os.path.join(tempfile.gettempdir(), "lanlens-attestations.log")


def record(action: str, target: str) -> None:
    """Append one 'the user affirmed authorization' line. Never raises."""
    try:
        ts = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        line = f"{ts}\t{action}\ttarget={target}\tauthorized=yes\n"
        fd = os.open(_log_path(), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.write(fd, line.encode("utf-8", "replace"))
        finally:
            os.close(fd)
    except Exception:
        pass
