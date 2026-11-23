"""
netreg_bandwidth.py -- per-device bandwidth / data usage from the same
bettercap sniff log the traffic view already reads.

While a device's traffic is routed through this Mac ("Route via this Mac"),
every packet to/from it passes through here, so we can tally how much it has
sent and received and how fast it's going *right now*.

  - download = bytes the device received (remote -> device)
  - upload   = bytes the device sent     (device -> remote)

Pure parsing/aggregation, no network calls -> fully unit-testable. The GUI
feeds it the same cleaned log chunks it feeds TrafficSummary.

What it can and can't see (honest about scope):
  * It measures the ONE device currently being routed. A switched LAN doesn't
    deliver other devices' packets to us, so this isn't whole-network metering
    unless each device is routed in turn.
  * HTTPS stays encrypted: these are byte counts and directions, not contents.
"""
from __future__ import annotations

from collections import deque

from netreg_traffic import parse_line, remote_endpoint


def _parse_ts(line: str):
    """Pull the leading [HH:MM:SS] bettercap timestamp as seconds-of-day
    (float), or None if the line has no such stamp."""
    s = line or ""
    i = s.find("[")
    if i < 0:
        return None
    j = s.find("]", i)
    if j < 0:
        return None
    body = s[i + 1:j].strip()
    parts = body.split(":")
    if len(parts) != 3:
        return None
    try:
        h, m, sec = (int(p) for p in parts)
    except ValueError:
        return None
    if not (0 <= h < 24 and 0 <= m < 60 and 0 <= sec < 60):
        return None
    return h * 3600 + m * 60 + sec


def _advance(prev, now):
    """Monotonic delta between two seconds-of-day stamps, tolerating a single
    midnight wrap so a rate near 00:00 doesn't go negative."""
    if prev is None or now is None:
        return 0.0
    d = now - prev
    if d < 0:
        d += 86400  # crossed midnight
    return d


class BandwidthMeter:
    """Tallies download/upload bytes for one routed device and reports a
    windowed throughput. Feed it log lines with add_line()/add_text()."""

    def __init__(self, target_ip: str | None = None, window: float = 5.0):
        self.target_ip = target_ip
        self.window = float(window)
        self.down_bytes = 0          # device received
        self.up_bytes = 0            # device sent
        self.packets = 0
        self._first_ts = None
        self._last_ts = None
        self._elapsed = 0.0          # seconds of log time seen
        # ring of (elapsed_time, down_delta, up_delta) for the live rate
        self._ring: deque = deque()

    # -- ingest ----------------------------------------------------------- #
    def add_line(self, line: str) -> bool:
        pkt = parse_line(line)
        if not pkt:
            return False
        rem = remote_endpoint(pkt, self.target_ip)
        if not rem:
            return False
        remhost, _ = rem
        n = pkt["bytes"]
        down = up = 0
        if pkt["src"] == remhost:
            down = n            # remote -> device
        elif pkt["dst"] == remhost:
            up = n              # device -> remote
        else:
            # remote_endpoint returned the dst as remote by convention
            down = n
        self.down_bytes += down
        self.up_bytes += up
        self.packets += 1

        ts = _parse_ts(line)
        if ts is not None:
            if self._first_ts is None:
                self._first_ts = ts
            self._elapsed += _advance(self._last_ts, ts)
            self._last_ts = ts
        self._ring.append((self._elapsed, down, up))
        self._trim()
        return True

    def add_text(self, text: str) -> int:
        n = 0
        for line in (text or "").splitlines():
            if self.add_line(line):
                n += 1
        return n

    def _trim(self):
        cutoff = self._elapsed - self.window
        while self._ring and self._ring[0][0] < cutoff:
            self._ring.popleft()

    # -- read ------------------------------------------------------------- #
    def totals(self) -> dict:
        return {
            "down": self.down_bytes,
            "up": self.up_bytes,
            "total": self.down_bytes + self.up_bytes,
            "packets": self.packets,
            "elapsed": self._elapsed,
        }

    def rate(self) -> dict:
        """Current throughput in BYTES/sec over the window, from the packets
        still inside it. Returns zeros before there's any time span."""
        self._trim()
        if len(self._ring) < 2:
            return {"down": 0.0, "up": 0.0}
        span = self._ring[-1][0] - self._ring[0][0]
        if span <= 0:
            return {"down": 0.0, "up": 0.0}
        # The first sample only marks the window's start; count the bytes that
        # arrived *after* it, so N samples spanning T seconds give bytes/T.
        rest = list(self._ring)[1:]
        d = sum(x[1] for x in rest)
        u = sum(x[2] for x in rest)
        return {"down": d / span, "up": u / span}

    def average_rate(self) -> dict:
        """Average throughput in BYTES/sec over the whole capture."""
        if self._elapsed <= 0:
            return {"down": 0.0, "up": 0.0}
        return {"down": self.down_bytes / self._elapsed,
                "up": self.up_bytes / self._elapsed}


def human_rate(bytes_per_sec: float) -> str:
    """Throughput as people expect to read it: bits/sec (Kbps/Mbps/Gbps)."""
    bps = float(bytes_per_sec) * 8
    for unit in ("bps", "Kbps", "Mbps", "Gbps"):
        if bps < 1000 or unit == "Gbps":
            return f"{bps:.0f} {unit}" if unit == "bps" else f"{bps:.1f} {unit}"
        bps /= 1000
    return f"{bps:.1f} Gbps"


if __name__ == "__main__":
    import netreg_traffic as nt
    sample = [
        "[00:13:16] [net.sniff.tcp] tcp 17.8.136.52:https > host.local.:51983 1400 bytes",
        "[00:13:16] [net.sniff.tcp] tcp host.local.:51983 > 17.8.136.52:https 120 bytes",
        "[00:13:18] [net.sniff.tcp] tcp 17.8.136.52:https > host.local.:51983 1400 bytes",
        "[00:13:20] [net.sniff.udp] udp 192.178.24.10:https > host.local.:53273 800 bytes",
    ]
    m = BandwidthMeter(window=5.0)
    for ln in sample:
        m.add_line(ln)
    t = m.totals()
    r = m.rate()
    print(f"down {nt.human_bytes(t['down'])}  up {nt.human_bytes(t['up'])}  "
          f"over {t['elapsed']:.0f}s")
    print(f"now: down {human_rate(r['down'])}  up {human_rate(r['up'])}")
