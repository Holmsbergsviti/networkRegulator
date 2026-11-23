"""Unit tests for netreg_speedtest. Run: python3 test_speedtest.py  (offline:
all network I/O is injected with fakes, nothing touches the internet)."""
import netreg_speedtest as st

fails = []
total = 0


def check(name, cond):
    global total
    total += 1
    print(("  ok   " if cond else "  FAIL ") + name)
    if not cond:
        fails.append(name)


print("throughput_bps / mbps:")
check("1,000,000 B in 1s -> 1e6 B/s", st.throughput_bps(1_000_000, 1.0) == 1_000_000)
check("divide-by-zero guarded", st.throughput_bps(1000, 0) == 0.0)
check("12.5 MB/s -> 100 Mbps", abs(st.mbps(12_500_000) - 100.0) < 1e-9)

print("summarize_latency:")
s = st.summarize_latency([30, 10, 20])
check("min is best sample", s["min"] == 10)
check("median of 3", s["median"] == 20)
check("jitter = mean consecutive gap", abs(s["jitter"] - 15.0) < 1e-9)  # |10-30|+|20-10|=30 /2
check("empty list -> zeros, no crash", st.summarize_latency([])["count"] == 0)
check("None/negative samples dropped", st.summarize_latency([None, -1, 40])["count"] == 1)
check("median of 4 averages middle two", st.summarize_latency([10, 20, 30, 40])["median"] == 25)

print("measure_latency with injected connect:")
seq = iter([12.0, 14.0, 13.0])
lat = st.measure_latency(attempts=3, _connect=lambda h, p, t: next(seq))
check("median of injected RTTs", lat["median"] == 13.0)

boom = st.measure_latency(attempts=3,
                          _connect=lambda h, p, t: (_ for _ in ()).throw(OSError("no route")))
check("all-fail latency -> count 0, no crash", boom["count"] == 0)

print("measure_download / measure_upload with fakes:")
clk = iter([100.0, 102.0])  # 2.0s elapsed
d = st.measure_download(nbytes=5_000_000,
                        _get=lambda url, to: 5_000_000,
                        _clock=lambda: next(clk))
check("download 5MB / 2s = 2.5 MB/s", d == 2_500_000.0)

clk2 = iter([0.0, 4.0])  # 4.0s
u = st.measure_upload(nbytes=8_000_000,
                      _post=lambda url, n, to: n,
                      _clock=lambda: next(clk2))
check("upload 8MB / 4s = 2.0 MB/s", u == 2_000_000.0)

print("run_speedtest orchestration (all fakes via monkeypatch):")
st.measure_latency = lambda *a, **k: {"min": 9.0, "median": 11.0, "jitter": 2.0, "count": 5}
st.measure_download = lambda *a, **k: 12_500_000.0
st.measure_upload = lambda *a, **k: 1_250_000.0
seen = []
r = st.run_speedtest(progress=seen.append)
check("ok result when all steps succeed", r.ok is True)
check("latency carried through", r.latency_ms == 11.0 and r.jitter_ms == 2.0)
check("download carried through", r.download_bps == 12_500_000.0)
check("progress callback was called", len(seen) >= 3)
check("describe() reads cleanly",
      "Download 100.0 Mbps" in r.describe() and "Ping 11 ms" in r.describe())

st.measure_download = lambda *a, **k: (_ for _ in ()).throw(TimeoutError("slow"))
r2 = st.run_speedtest()
check("failure -> ok False with error text", r2.ok is False and "slow" in r2.error)
check("describe() of failure is friendly", r2.describe().startswith("Speed test failed"))

print()
if fails:
    print(f"{len(fails)}/{total} FAILED: {fails}")
    raise SystemExit(1)
print(f"All {total} checks passed.")
