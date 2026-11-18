"""
netreg_seen.py -- keep scan results stable across repeated sweeps.

The network and device scanners re-run every couple of seconds and return only
what responded *that* round. Wi-Fi networks fade in and out and devices (phones
especially) sleep their radios, so a raw sweep-by-sweep view flickers badly.

`SeenTracker` merges each sweep into a kept set keyed by a stable id (MAC/BSSID,
falling back to IP/ESSID) and only drops an entry after it has been missing for
`ttl` seconds. That turns a flickering list into a steady one that still removes
things once they're genuinely gone. Pure logic; the clock is injectable so it's
unit-testable without waiting.
"""
from __future__ import annotations

import time


class SeenTracker:
    def __init__(self, ttl: float = 25.0, keys=("MAC",), clock=time.monotonic):
        self.ttl = ttl
        self.keys = tuple(keys)
        self.clock = clock
        self._items: dict[str, tuple[dict, float]] = {}

    def reset(self):
        """Forget everything (call when a fresh scan starts)."""
        self._items.clear()

    def _key(self, row: dict) -> str:
        for k in self.keys:
            v = (row.get(k) or "").strip() if isinstance(row.get(k), str) else row.get(k)
            if v:
                return f"{k}={v}"
        # no stable id on this row: fall back to the whole row so it still shows,
        # but can't be de-duplicated across sweeps
        return "row=" + repr(sorted(row.items()))

    def update(self, rows: list[dict]) -> list[dict]:
        """Merge this sweep's rows in, drop anything not seen within ttl, and
        return the surviving rows (freshest field values win)."""
        now = self.clock()
        for r in rows or []:
            self._items[self._key(r)] = (dict(r), now)
        live = {k: (r, t) for k, (r, t) in self._items.items()
                if now - t <= self.ttl}
        self._items = live
        return [r for (r, _t) in live.values()]


if __name__ == "__main__":
    clk = {"t": 0.0}
    tr = SeenTracker(ttl=5.0, keys=("MAC", "IP"), clock=lambda: clk["t"])
    print(len(tr.update([{"MAC": "a", "IP": "1"}, {"MAC": "b", "IP": "2"}])))  # 2
    clk["t"] = 3
    print(len(tr.update([{"MAC": "a", "IP": "1"}])))  # 2 (b still within ttl)
    clk["t"] = 9
    print(len(tr.update([{"MAC": "a", "IP": "1"}])))  # 1 (b expired)
