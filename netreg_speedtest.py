"""
netreg_speedtest.py -- a built-in internet speed test (download, upload,
latency) for the Mac the app runs on.

This measures *this computer's* connection to the internet, not a single LAN
device (for a routed device's throughput see netreg_bandwidth). It talks to
Cloudflare's public speed endpoints, which exist for exactly this purpose and
return/accept arbitrary-sized payloads:

    https://speed.cloudflare.com/__down?bytes=N
    https://speed.cloudflare.com/__up      (POST N bytes)

Design for testability: the arithmetic and formatting are pure functions with
unit tests; the network calls are isolated in measure_* functions that take an
injectable transport, so tests feed a fake and never touch the network. The
GUI calls run_speedtest() on a background thread.

Nothing private is sent -- the upload body is throwaway zero bytes.
"""
from __future__ import annotations

import socket
import time
from dataclasses import dataclass

DOWN_URL = "https://speed.cloudflare.com/__down?bytes={n}"
UP_URL = "https://speed.cloudflare.com/__up"


# --- pure arithmetic / formatting (unit-tested) --------------------------- #
def throughput_bps(nbytes: int, seconds: float) -> float:
    """Bytes per second, guarding divide-by-zero."""
    if seconds <= 0:
        return 0.0
    return float(nbytes) / seconds


def mbps(bytes_per_sec: float) -> float:
    """Bytes/sec -> megabits/sec (the number people quote)."""
    return float(bytes_per_sec) * 8 / 1_000_000


def summarize_latency(samples_ms) -> dict:
    """From a list of per-attempt round-trip times (ms): the best (min), the
    median, and jitter (mean gap between consecutive samples)."""
    xs = [float(x) for x in samples_ms if x is not None and x >= 0]
    if not xs:
        return {"min": 0.0, "median": 0.0, "jitter": 0.0, "count": 0}
    ordered = sorted(xs)
    n = len(ordered)
    mid = n // 2
    median = ordered[mid] if n % 2 else (ordered[mid - 1] + ordered[mid]) / 2
    if n >= 2:
        jitter = sum(abs(xs[i] - xs[i - 1]) for i in range(1, n)) / (n - 1)
    else:
        jitter = 0.0
    return {"min": ordered[0], "median": median, "jitter": jitter, "count": n}


@dataclass
class SpeedResult:
    download_bps: float = 0.0     # bytes/sec
    upload_bps: float = 0.0
    latency_ms: float = 0.0       # median
    jitter_ms: float = 0.0
    ok: bool = False
    error: str = ""

    def describe(self) -> str:
        if not self.ok:
            return f"Speed test failed: {self.error or 'unknown error'}"
        return (f"Download {mbps(self.download_bps):.1f} Mbps · "
                f"Upload {mbps(self.upload_bps):.1f} Mbps · "
                f"Ping {self.latency_ms:.0f} ms (±{self.jitter_ms:.0f})")


# --- network measurement (transport injectable) -------------------------- #
def _tcp_connect_ms(host: str, port: int, timeout: float) -> float:
    """Round-trip to open a TCP connection, in ms. Raises on failure."""
    start = time.perf_counter()
    s = socket.create_connection((host, port), timeout=timeout)
    s.close()
    return (time.perf_counter() - start) * 1000.0


def measure_latency(host: str = "1.1.1.1", port: int = 443, attempts: int = 5,
                    timeout: float = 2.0, _connect=_tcp_connect_ms) -> dict:
    """Open `attempts` short TCP connections and summarize the round-trips.
    Failed attempts are skipped, not counted as 0."""
    samples = []
    for _ in range(max(1, attempts)):
        try:
            samples.append(_connect(host, port, timeout))
        except Exception:
            samples.append(None)
    return summarize_latency(samples)


def _http_get_bytes(url: str, timeout: float) -> int:
    from urllib.request import urlopen, Request
    req = Request(url, headers={"User-Agent": "LanLens-speedtest"})
    total = 0
    with urlopen(req, timeout=timeout) as resp:
        while True:
            chunk = resp.read(65536)
            if not chunk:
                break
            total += len(chunk)
    return total


def measure_download(nbytes: int = 25_000_000, timeout: float = 30.0,
                     _get=_http_get_bytes, _clock=time.perf_counter) -> float:
    """Download ~nbytes and return throughput in bytes/sec."""
    start = _clock()
    got = _get(DOWN_URL.format(n=nbytes), timeout)
    return throughput_bps(got, _clock() - start)


def _http_post_bytes(url: str, nbytes: int, timeout: float) -> int:
    from urllib.request import urlopen, Request
    body = b"\x00" * nbytes
    req = Request(url, data=body, method="POST",
                  headers={"User-Agent": "LanLens-speedtest",
                           "Content-Type": "application/octet-stream"})
    with urlopen(req, timeout=timeout) as resp:
        resp.read()
    return nbytes


def measure_upload(nbytes: int = 10_000_000, timeout: float = 30.0,
                   _post=_http_post_bytes, _clock=time.perf_counter) -> float:
    """Upload nbytes of throwaway data and return throughput in bytes/sec."""
    start = _clock()
    sent = _post(UP_URL, nbytes, timeout)
    return throughput_bps(sent, _clock() - start)


def run_speedtest(down_bytes: int = 25_000_000, up_bytes: int = 10_000_000,
                  progress=None) -> SpeedResult:
    """Full test: latency, then download, then upload. Never raises -- failures
    come back in SpeedResult.error. `progress` is an optional callback(str)."""
    def say(msg):
        if progress:
            try:
                progress(msg)
            except Exception:
                pass

    r = SpeedResult()
    try:
        say("Measuring latency…")
        lat = measure_latency()
        r.latency_ms = lat["median"]
        r.jitter_ms = lat["jitter"]

        say("Testing download…")
        r.download_bps = measure_download(down_bytes)

        say("Testing upload…")
        r.upload_bps = measure_upload(up_bytes)

        r.ok = True
        say("Done.")
    except Exception as e:  # DNS down, no route, endpoint unreachable, timeout
        r.ok = False
        r.error = f"{type(e).__name__}: {e}"
        say(r.error)
    return r


if __name__ == "__main__":
    print("Running a real speed test (needs internet)…")
    print(run_speedtest().describe())
