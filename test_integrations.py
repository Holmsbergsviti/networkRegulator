"""Unit tests for netreg_oui + netreg_integrations. Run: python3 test_integrations.py
Pure-logic + offline; the network-dependent libraries are exercised only for
graceful-fallback behavior, never for live lookups."""
import netreg_oui as oui
import netreg_integrations as ni

fails = []
double = 0


def check(name, cond):
    global double
    double += 1
    if cond:
        print(f"  ok   {name}")
    else:
        print(f"  FAIL {name}")
        fails.append(name)


print("netreg_oui:")
check("Raspberry Pi B8:27:EB", oui.lookup("b8:27:eb:12:34:56") == "Raspberry Pi Foundation")
check("Espressif 24:0A:C4", oui.lookup("24:0A:C4:aa:bb:cc") == "Espressif")
check("prefix normalizes dashes", oui.lookup("3C-07-54-00-00-01") == "Apple")
check("unknown OUI -> ''", oui.lookup("de:ad:be:00:00:00") in ("", "randomized (private)"))
check("garbage -> ''", oui.lookup("not-a-mac") == "")
check("empty -> ''", oui.lookup("") == "")
check("locally-administered detected", oui.is_locally_administered("02:11:22:33:44:55") is True)
check("globally-administered not flagged", oui.is_locally_administered("b8:27:eb:00:00:00") is False)
check("randomized label", oui.lookup("7a:11:22:33:44:55") == "randomized (private)")
check("_norm_prefix bad hex", oui._norm_prefix("zz:yy:xx:00:00:00") == "")

print("netreg_integrations.vendor_for_mac (built-in table path):")
check("vendor_for_mac Pi", ni.vendor_for_mac("b8:27:eb:ff:ff:ff") == "Raspberry Pi Foundation")
check("vendor_for_mac blank mac", ni.vendor_for_mac("") == "")
check("vendor_for_mac short mac", ni.vendor_for_mac("00:11") == "")
check("vendor cache returns same", ni.vendor_for_mac("24:0a:c4:1:2:3") == ni.vendor_for_mac("24:0a:c4:1:2:3"))

print("availability() shape:")
av = ni.availability()
check("availability is dict", isinstance(av, dict))
check("has getmac key", "getmac" in av)
check("has bettercap key", "bettercap" in av)
check("all values bool", all(isinstance(v, bool) for v in av.values()))

print("enrich_devices (mdns off to stay offline/fast):")
rows = [
    {"IP": "192.168.1.10", "MAC": "b8:27:eb:11:22:33", "Hostname": ""},
    {"IP": "192.168.1.11", "MAC": "", "Hostname": "known.local"},
    {"IP": "192.168.1.12", "MAC": "02:aa:bb:cc:dd:ee", "Hostname": ""},
]
out = ni.enrich_devices(rows, vendor=True, mdns=False, fill_mac=False)
check("same list returned", out is rows)
check("Vendor added for Pi", rows[0]["Vendor"] == "Raspberry Pi Foundation")
check("Vendor blank when no MAC", rows[1]["Vendor"] == "")
check("Vendor marks randomized", rows[2]["Vendor"] == "randomized (private)")
check("existing Hostname untouched", rows[1]["Hostname"] == "known.local")

print("fast_port_scan returns None with no scanner installed:")
check("no naabu/rustscan -> None", ni.fast_port_scan("127.0.0.1") is None)

print("mdns_names returns dict (no crash) with zeroconf present:")
try:
    names = ni.mdns_names(timeout=0.6)
    check("mdns_names dict", isinstance(names, dict))
except Exception as e:
    check(f"mdns_names raised {e}", False)

print("netreg_mitm (command construction only, nothing launched):")
import netreg_mitm as mitm
check("eval targets the IP + spoofs gateway",
      mitm.build_eval("192.168.1.211") ==
      "set arp.spoof.targets 192.168.1.211; set arp.spoof.fullduplex true; net.probe on; arp.spoof on")
check("sniff flag adds net.sniff", "net.sniff on" in mitm.build_eval("10.0.0.5", sniff=True))
check("sniff scopes capture to the target (BPF host filter)",
      "set net.sniff.filter host 10.0.0.5" in mitm.build_eval("10.0.0.5", sniff=True))
check("no sniff => no net.sniff", "net.sniff" not in mitm.build_eval("10.0.0.5", sniff=False))
check("fullduplex false honored", "fullduplex false" in mitm.build_eval("10.0.0.5", full_duplex=False))
check("admin cmd with log redirects bettercap output to it",
      "&>" in mitm._mac_admin_command(["bettercap"], "/tmp/t.log")[2]
      and "/tmp/t.log" in mitm._mac_admin_command(["bettercap"], "/tmp/t.log")[2])
check("admin cmd without log discards output",
      "/dev/null" in mitm._mac_admin_command(["bettercap"])[2])
check("default_log_path is a .log file path",
      isinstance(mitm.default_log_path(), str) and mitm.default_log_path().endswith(".log"))
check("argv carries -iface and -eval",
      mitm.build_argv("10.0.0.9", iface="en0")[1:3] == ["-iface", "en0"] and
      "-eval" in mitm.build_argv("10.0.0.9", iface="en0"))
def _empty_refused():
    try:
        mitm.build_eval("   "); return False
    except ValueError:
        return True
check("empty target refused (no subnet-wide spoof)", _empty_refused())
check("mac admin wrapper uses osascript", mitm._mac_admin_command(["bettercap"])[0] == "osascript")
ok, msg = mitm.RouteSession().start("192.168.1.5")
check("start refuses cleanly without bettercap", ok is False and "bettercap" in msg.lower())

print("netreg_probe (risk flags + banner parsing, pure):")
import netreg_probe as probe
check("telnet flagged as risky", "clear text" in probe.risk_for_port(23).lower())
check("plain FTP flagged as risky", bool(probe.risk_for_port(21)))
check("SMB 445 flagged as risky", bool(probe.risk_for_port(445)))
check("https not risky by itself", probe.risk_for_port(443) == "")
check("non-numeric port tolerated", probe.risk_for_port("nope") == "")
check("web 200 with no login is a risk", bool(probe.web_risk({"status": 200})))
check("web 401 (needs login) is NOT flagged", probe.web_risk({"status": 401}) == "")
check("no web info => no web risk", probe.web_risk(None) == "")
check("risk summary lists each risky port + web",
      probe.summarize_risks([22, 23, 445], {"status": 200}) ==
      ["Port 23: " + probe.RISKY_PORTS[23],
       "Port 445: " + probe.RISKY_PORTS[445],
       "Web interface with no login — anyone on the network can open it"])
check("ssh banner parsed", probe.parse_banner(22, b"SSH-2.0-OpenSSH_9.6\r\n") == "SSH-2.0-OpenSSH_9.6")
check("http Server header extracted",
      probe.parse_banner(80, b"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nX: y\r\n\r\n") == "nginx/1.24.0")
check("empty banner => empty string", probe.parse_banner(22, b"") == "")
check("control bytes stripped from banner",
      "\x00" not in probe.parse_banner(21, b"220 \x00\x01FTP ready\r\n"))

print("netreg_traffic (sniff-log parsing + grouping):")
import netreg_traffic as nt
_L = "[00:13:16] [net.sniff.udp] udp 192.178.24.10:https > host.local.:53273 180 bytes"
p = nt.parse_line(_L)
check("parse_line extracts proto/host/bytes",
      p and p["proto"] == "udp" and p["src"] == "192.178.24.10" and p["bytes"] == 180)
check("parse_line strips trailing dot from .local", p and p["dst"] == "host.local")
check("non-packet line -> None", nt.parse_line("[x] mdns host.local. : PTR query") is None)
check("public IP detected", nt._is_public_ip("17.8.136.52") is True)
check("private IP not public", nt._is_public_ip("192.168.1.241") is False)
check("hostname not public", nt._is_public_ip("host.local") is False)
check("remote endpoint is the public side",
      nt.remote_endpoint(nt.parse_line(_L)) == ("192.178.24.10", "https"))
_s = nt.TrafficSummary()
_s.add_line(_L)
_s.add_line("[00:13:16] [net.sniff.udp] udp host.local.:53273 > 192.178.24.10:https 43 bytes")
_s.add_line("[00:13:19] [net.sniff.tcp] tcp 17.8.136.52:https > host.local.:51983 56 bytes")
_s.add_line("[00:13:22] [net.sniff.mdns] mdns host.local. : PTR query for _hap._tcp.local")
rws = _s.rows()
check("groups both directions of one host into one row",
      any(r["host"] == "192.178.24.10" and r["packets"] == 2 and r["bytes"] == 223 for r in rws))
check("mdns/local lines are not counted as remote traffic", len(rws) == 2)
check("rows sorted busiest-first by bytes", rws[0]["bytes"] >= rws[-1]["bytes"])
check("set_name/label resolves a host to its name",
      (_s.set_name("17.8.136.52", "apple.com") or _s.label("17.8.136.52")) == "apple.com")
check("human_bytes formats KB", nt.human_bytes(2048) == "2.0 KB")

print("netreg_seen (stabilize scan results across sweeps):")
import netreg_seen as seen
_clk = {"t": 0.0}
_tr = seen.SeenTracker(ttl=5.0, keys=("MAC", "IP"), clock=lambda: _clk["t"])
r0 = _tr.update([{"MAC": "aa", "IP": "1"}, {"MAC": "bb", "IP": "2"}])
check("both devices present on first sweep", len(r0) == 2)
_clk["t"] = 3.0
r1 = _tr.update([{"MAC": "aa", "IP": "1"}])  # bb missed this sweep
check("missed device kept within ttl", len(r1) == 2)
_clk["t"] = 9.0
r2 = _tr.update([{"MAC": "aa", "IP": "1"}])  # bb now expired (>5s)
check("device dropped after ttl", len(r2) == 1 and r2[0]["MAC"] == "aa")
check("same id not duplicated across sweeps",
      len(_tr.update([{"MAC": "aa", "IP": "1"}])) == 1)
_tr2 = seen.SeenTracker(ttl=5.0, keys=("MAC", "IP"), clock=lambda: _clk["t"])
_tr2.update([{"MAC": "", "IP": "10.0.0.9"}])
check("falls back to IP when MAC is blank",
      len(_tr2.update([{"MAC": "", "IP": "10.0.0.9"}])) == 1)
_tr2.reset()
check("reset clears kept items", len(_tr2.update([])) == 0)

print()
if fails:
    print(f"{len(fails)}/{double} FAILED: {fails}")
    raise SystemExit(1)
print(f"All {double} checks passed.")
