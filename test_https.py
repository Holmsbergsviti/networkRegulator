"""Unit tests for netreg_https. Run: python3 test_https.py  (offline: no proxy,
no root, no network — only command construction and flow parsing)."""
import json

import netreg_https as h

fails = []
total = 0


def check(name, cond):
    global total
    total += 1
    print(("  ok   " if cond else "  FAIL ") + name)
    if not cond:
        fails.append(name)


print("pf rules (target-scoped):")
rules = h.build_pf_rules("192.168.1.50")
check("redirects the target's port 80", "from 192.168.1.50 to any port 80" in rules)
check("redirects the target's port 443", "from 192.168.1.50 to any port 443" in rules)
check("sends to the proxy port", f"127.0.0.1 port {h.PROXY_PORT}" in rules)
check("only the target appears (no whole-subnet rule)", "from any" not in rules)
try:
    h.build_pf_rules("")
    check("empty target refused", False)
except ValueError:
    check("empty target refused", True)

print("mitmdump argv:")
argv = h.build_mitmdump_argv("/tmp/flows.jsonl", port=8080)
check("transparent mode", "--mode" in argv and "transparent" in argv)
check("loads our addon", "-s" in argv and any("netreg_https_addon" in a for a in argv))
check("listens on the chosen port", "8080" in argv)

print("setup script:")
script = h.build_setup_script("192.168.1.50", "/tmp/flows.jsonl",
                              "/tmp/rules.conf", port=8080)
check("enables IP forwarding", "net.inet.ip.forwarding=1" in script)
check("loads pf rules", "pfctl -f '/tmp/rules.conf' -e" in script)
check("passes the flow log via env", "NETREG_HTTPS_LOG='/tmp/flows.jsonl'" in script)
check("backgrounds mitmdump", script.rstrip().endswith("&"))

print("cert guidance:")
g = h.cert_guidance()
check("mentions mitm.it", "mitm.it" in g)
check("names the CA file path", h.ca_cert_path() in g)
check("warns about own-network only", "authorized" in g.lower())

print("parse_flow_line:")
good = json.dumps({"ts": 1.0, "client": "192.168.1.50", "method": "GET",
                   "scheme": "https", "host": "example.com", "path": "/api/v1",
                   "status": 200, "content_type": "application/json",
                   "req_bytes": 100, "resp_bytes": 2000, "snippet": '{"ok":true}'})
rec = h.parse_flow_line(good)
check("parses host/method/path", rec["host"] == "example.com" and rec["method"] == "GET")
check("carries status + snippet", rec["status"] == 200 and rec["snippet"] == '{"ok":true}')
check("blank line -> None", h.parse_flow_line("") is None)
check("garbage -> None", h.parse_flow_line("not json {") is None)
check("error record -> None",
      h.parse_flow_line(json.dumps({"ts": 1, "error": "boom"})) is None)
check("missing host -> None", h.parse_flow_line(json.dumps({"method": "GET"})) is None)

print("HttpsFlowSummary:")
s = h.HttpsFlowSummary()
s.add_line(good)
s.add_line(json.dumps({"host": "example.com", "method": "POST", "path": "/login",
                       "status": 200, "req_bytes": 50, "resp_bytes": 10,
                       "content_type": "text/html", "snippet": "user=bob"}))
s.add_line(json.dumps({"host": "cdn.other.com", "method": "GET", "path": "/a.js",
                       "status": 200, "req_bytes": 10, "resp_bytes": 5000,
                       "content_type": "application/javascript", "snippet": ""}))
check("counts flows", len(s.flows) == 3)
check("recent() is newest-first", s.recent(1)[0]["host"] == "cdn.other.com")
hosts = s.hosts()
check("per-host rollup busiest first (cdn has most bytes)", hosts[0]["host"] == "cdn.other.com")
check("example.com rolled up to 2 requests",
      next(e for e in hosts if e["host"] == "example.com")["requests"] == 2)

print("flow cap:")
s2 = h.HttpsFlowSummary(max_flows=5)
for i in range(20):
    s2.add_line(json.dumps({"host": "h", "method": "GET", "path": f"/{i}",
                            "status": 200, "req_bytes": 1, "resp_bytes": 1,
                            "content_type": "text/plain", "snippet": ""}))
check("list capped at max_flows", len(s2.flows) == 5)
check("cap keeps the newest", s2.recent(1)[0]["path"] == "/19")

print("addon snippet logic:")
import netreg_https_addon as addon
check("textual json is snippetted",
      addon._snippet(b'{"a": 1}', "application/json; charset=utf-8") == '{"a": 1}')
check("binary image is not snippetted",
      addon._snippet(b"\x89PNG\r\n", "image/png") == "")
check("snippet length capped",
      len(addon._snippet(b"x" * 10000, "text/plain")) == addon.SNIPPET_MAX)
check("whitespace collapsed",
      addon._snippet(b"a\n\n   b\tc", "text/plain") == "a b c")

print("addon header/body capture (Burp-style detail):")
check("headers render as Name: value block",
      addon._headers({"Host": "ex.com", "Accept": "*/*"}) == "Host: ex.com\nAccept: */*")
check("textual body kept up to BODY_MAX",
      addon._body(b'{"ok":true}', "application/json") == '{"ok":true}')
check("long textual body capped at BODY_MAX",
      len(addon._body(b"x" * 20000, "text/plain")) == addon.BODY_MAX)
check("binary body noted with size, not dumped",
      addon._body(b"\x89PNG\r\n", "image/png")
      == f"[binary body, 6 bytes — not shown]")
check("headers block capped at HEADERS_MAX",
      len(addon._headers({"X": "y" * 20000})) == addon.HEADERS_MAX)

print("parse_flow_line carries Burp-style detail fields:")
detail = json.dumps({"ts": 1.0, "client": "192.168.1.50", "method": "POST",
                     "scheme": "https", "host": "api.example.com", "path": "/login",
                     "status": 200, "content_type": "application/json",
                     "req_bytes": 20, "resp_bytes": 30, "snippet": "{}",
                     "req_headers": "Host: api.example.com",
                     "req_body": '{"user":"vlad"}',
                     "resp_headers": "Server: nginx",
                     "resp_body": '{"ok":true}'})
drec = h.parse_flow_line(detail)
check("passes req_headers + req_body through",
      drec["req_headers"] == "Host: api.example.com" and drec["req_body"] == '{"user":"vlad"}')
check("passes resp_headers + resp_body through",
      drec["resp_headers"] == "Server: nginx" and drec["resp_body"] == '{"ok":true}')
check("detail fields default to '' when absent",
      rec.get("req_headers") == "" and rec.get("resp_body") == "")

print("preflight degrades gracefully:")
ready, msg = h.preflight()
check("preflight returns (bool, str)", isinstance(ready, bool) and isinstance(msg, str))

print()
if fails:
    print(f"{len(fails)}/{total} FAILED: {fails}")
    raise SystemExit(1)
print(f"All {total} checks passed.")
