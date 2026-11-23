"""Unit tests for netreg_bandwidth. Run: python3 test_bandwidth.py  (offline)."""
import netreg_bandwidth as bw

fails = []
total = 0


def check(name, cond):
    global total
    total += 1
    print(("  ok   " if cond else "  FAIL ") + name)
    if not cond:
        fails.append(name)


# host.local. is the routed device; 17.8.136.52 is the remote server.
DOWN = "[00:13:16] [net.sniff.tcp] tcp 17.8.136.52:https > host.local.:51983 {n} bytes"
UP = "[00:13:16] [net.sniff.tcp] tcp host.local.:51983 > 17.8.136.52:https {n} bytes"


def at(ts, tmpl, n):
    return tmpl.replace("00:13:16", ts).format(n=n)


print("netreg_bandwidth.BandwidthMeter:")
m = bw.BandwidthMeter()
m.add_line(DOWN.format(n=1400))
m.add_line(UP.format(n=120))
m.add_line(DOWN.format(n=600))
t = m.totals()
check("download bytes summed (remote -> device)", t["down"] == 2000)
check("upload bytes summed (device -> remote)", t["up"] == 120)
check("total = down + up", t["total"] == 2120)
check("packet count", t["packets"] == 3)

print("timestamps + elapsed:")
m2 = bw.BandwidthMeter()
m2.add_line(at("00:00:00", DOWN, 1000))
m2.add_line(at("00:00:10", DOWN, 1000))
check("elapsed tracks log time", abs(m2.totals()["elapsed"] - 10.0) < 1e-6)

print("midnight wrap doesn't go negative:")
m3 = bw.BandwidthMeter()
m3.add_line(at("23:59:59", DOWN, 500))
m3.add_line(at("00:00:04", DOWN, 500))
check("wrap -> +5s, not -86395s", abs(m3.totals()["elapsed"] - 5.0) < 1e-6)

print("windowed rate:")
m4 = bw.BandwidthMeter(window=5.0)
# 1000 bytes down every second for 4 seconds
for i, ts in enumerate(("00:00:00", "00:00:01", "00:00:02", "00:00:03")):
    m4.add_line(at(ts, DOWN, 1000))
r = m4.rate()
check("down rate ~1000 B/s over window", abs(r["down"] - 1000.0) < 1e-6)
check("up rate 0 when no upload", r["up"] == 0.0)

print("rate falls out of the window:")
m5 = bw.BandwidthMeter(window=3.0)
m5.add_line(at("00:00:00", DOWN, 9000))    # old burst
for ts in ("00:00:10", "00:00:11", "00:00:12"):
    m5.add_line(at(ts, DOWN, 300))         # recent steady 300 B/s
r5 = m5.rate()
check("old burst dropped from window", r5["down"] < 400)

print("average rate over whole capture:")
m6 = bw.BandwidthMeter()
m6.add_line(at("00:00:00", DOWN, 1000))
m6.add_line(at("00:00:10", DOWN, 1000))
avg = m6.average_rate()
check("avg down = total/elapsed (2000/10)", abs(avg["down"] - 200.0) < 1e-6)

print("edge cases:")
m7 = bw.BandwidthMeter()
check("no data -> zero rate, no crash", m7.rate() == {"down": 0.0, "up": 0.0})
check("non-packet line ignored", m7.add_line("[00:00:00] [sys.log] hello") is False)
check("blank line ignored", m7.add_line("") is False)

print("human_rate:")
check("100 B/s -> 800 bps", bw.human_rate(100) == "800 bps")
check("500 B/s -> 4.0 Kbps", bw.human_rate(500) == "4.0 Kbps")
check("125000 B/s -> 1.0 Mbps", bw.human_rate(125000) == "1.0 Mbps")
check("0 -> 0 bps", bw.human_rate(0) == "0 bps")

print()
if fails:
    print(f"{len(fails)}/{total} FAILED: {fails}")
    raise SystemExit(1)
print(f"All {total} checks passed.")
