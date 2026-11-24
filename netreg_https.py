"""
netreg_https.py -- HTTPS *content* inspection for a routed device, via mitmproxy.

====================  OWN-NETWORK / AUTHORIZED USE ONLY  ====================
The plain Route view (netreg_mitm / netreg_traffic) shows WHO a device talks to
over HTTPS -- the server and how much data -- but not WHAT, because TLS is
encrypted. This module adds the "what": it runs **mitmproxy** as a transparent
proxy that terminates TLS, so the redirected device's requests and responses
become readable. That only works if mitmproxy's CA certificate is installed and
trusted on the TARGET device, which the user must do by hand -- so this is
strictly opt-in, off by default, and gated behind the same "I own this network
/ authorized" confirmation as routing. Use on your own network only.
============================================================================

How it fits together (all on the Mac doing the routing):
  1. bettercap already ARP-spoofs the gateway, so the target's packets arrive
     here (netreg_mitm).
  2. We enable IP forwarding and add pf `rdr` rules that redirect ONLY the
     target IP's tcp/80 and tcp/443 to mitmproxy's transparent port. Scoping to
     the one target is deliberate: we never intercept the whole subnet.
  3. mitmdump runs in transparent mode with netreg_https_addon.py, which writes
     one JSON line per request/response to a log we tail and parse here.

Testable surface: command construction, pf-rule text, and flow parsing are pure
functions with unit tests. Actually starting mitmdump + pf needs root, the
binary and a real device, so that path is exercised on the Mac, not in CI.
"""
from __future__ import annotations

import ipaddress
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading

PROXY_PORT = 8080


def mitmdump_path() -> str:
    return shutil.which("mitmdump") or ""


def available() -> bool:
    return bool(mitmdump_path())


def ca_cert_path() -> str:
    """Where mitmproxy puts the CA cert the target device must trust. mitmproxy
    generates it on first run under ~/.mitmproxy."""
    return os.path.join(os.path.expanduser("~"), ".mitmproxy",
                        "mitmproxy-ca-cert.pem")


def ca_cert_ready() -> bool:
    return os.path.isfile(ca_cert_path())


def addon_path() -> str:
    """The addon shipped beside this module."""
    return os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "netreg_https_addon.py")


def default_flow_log_path() -> str:
    """JSONL file the addon writes and the GUI tails."""
    mac_logs = os.path.join(os.path.expanduser("~"), "Library", "Logs")
    if sys.platform == "darwin" and os.path.isdir(mac_logs):
        return os.path.join(mac_logs, "LanLens-https.jsonl")
    return os.path.join(tempfile.gettempdir(), "netreg_https.jsonl")


def preflight() -> tuple[bool, str]:
    """(ready, message). mitmdump must be installed; the CA cert is generated on
    first run, so its absence is a warning, not a blocker."""
    if not available():
        return False, ("mitmproxy is not installed. Install it with "
                       "`brew install mitmproxy`, then try again.")
    if not ca_cert_ready():
        return True, ("mitmproxy found. Its CA certificate hasn't been "
                      "generated yet — it will be created the first time the "
                      "proxy runs, then you'll need to trust it on the target "
                      "device (see the instructions).")
    return True, "mitmproxy found and CA certificate present."


def cert_guidance(target_hostname: str = "the target device") -> str:
    """Plain-language steps for trusting mitmproxy's CA on the device whose
    HTTPS you want to read. Without this, HTTPS apps on the device will show
    certificate errors and content stays unreadable."""
    return (
        "To read this device's HTTPS traffic, its own operating system must "
        "trust mitmproxy's certificate. On a device you own:\n"
        "  1. With routing on, open http://mitm.it on the target device.\n"
        "  2. Download the certificate for that device's OS (iOS, Android, "
        "macOS, Windows…).\n"
        "  3. Install AND trust it:\n"
        "       • iPhone/iPad: Settings → General → VPN & Device Management → "
        "install the profile, then Settings → General → About → Certificate "
        "Trust Settings → enable it.\n"
        "       • macOS: open the .pem in Keychain Access → set to "
        "\"Always Trust\".\n"
        "       • Android: Settings → Security → Install from storage (user "
        "certs; many apps still won't accept it).\n"
        f"  4. The CA file on this Mac is: {ca_cert_path()}\n"
        "Only do this for a device you own or are authorized to test. Remove "
        "the certificate from the device when you're done. Some apps use "
        "certificate pinning and will refuse interception even then — that's "
        "expected and not a bug.")


# --- command / rule construction (pure, unit-tested) --------------------- #
def build_mitmdump_argv(flow_log: str, port: int = PROXY_PORT,
                        addon: str | None = None,
                        extra: list[str] | None = None) -> list[str]:
    """Full mitmdump argv for transparent interception writing to our addon.
    Verifiable without launching anything."""
    binary = mitmdump_path() or "mitmdump"
    argv = [binary, "--mode", "transparent", "--showhost",
            "--listen-port", str(port),
            "-s", addon or addon_path(),
            # quiet mitmdump's own stdout; our addon does the logging
            "--set", "flow_detail=0", "-q"]
    if extra:
        argv += extra
    return argv


def build_pf_rules(target_ip: str, port: int = PROXY_PORT) -> str:
    """pf ruleset that redirects ONLY `target_ip`'s web ports to the proxy.
    Raises ValueError without a target so we never redirect the whole subnet."""
    target_ip = (target_ip or "").strip()
    if not target_ip:
        raise ValueError("a target IP is required (refusing to redirect the "
                         "whole network)")
    try:
        ipaddress.ip_address(target_ip)
    except ValueError:
        raise ValueError(f"not a valid IP address: {target_ip!r}")
    return (
        f"rdr pass inet proto tcp from {target_ip} to any port 80 -> "
        f"127.0.0.1 port {port}\n"
        f"rdr pass inet proto tcp from {target_ip} to any port 443 -> "
        f"127.0.0.1 port {port}\n")


def _sh_quote(s: str) -> str:
    return "'" + s.replace("'", "'\\''") + "'"


def _osa_escape(s: str) -> str:
    """Escape for an AppleScript double-quoted literal. osascript runs
    `do shell script "<this>"`, so a bare " or \\ in the command would
    break out of the literal; escape both. Applied on top of the shell
    quoting (_sh_quote), which is a separate layer."""
    return s.replace("\\", "\\\\").replace('"', '\\"')


def build_setup_script(target_ip: str, flow_log: str, rules_path: str,
                       port: int = PROXY_PORT,
                       mitm_argv: list[str] | None = None) -> str:
    """The root shell script (run once via one admin prompt): enable IP
    forwarding, load the target-scoped pf redirect, and start mitmdump in the
    background with the flow log in its environment. Pure string construction."""
    argv = mitm_argv or build_mitmdump_argv(flow_log, port)
    quoted = " ".join(_sh_quote(a) for a in argv)
    return (
        "sysctl -w net.inet.ip.forwarding=1; "
        f"pfctl -f {_sh_quote(rules_path)} -e 2>/dev/null; "
        f"NETREG_HTTPS_LOG={_sh_quote(flow_log)} {quoted} "
        f"&> {_sh_quote(flow_log + '.err')} &")


# --- flow log parsing (pure, unit-tested) -------------------------------- #
def parse_flow_line(line: str):
    """Parse one JSONL record the addon wrote into a normalized dict, or None
    if it's blank/garbage/an error record."""
    s = (line or "").strip()
    if not s:
        return None
    try:
        rec = json.loads(s)
    except Exception:
        return None
    if not isinstance(rec, dict) or rec.get("error") or "host" not in rec:
        return None
    return {
        "ts": rec.get("ts", 0),
        "client": rec.get("client", ""),
        "method": rec.get("method", ""),
        "scheme": rec.get("scheme", ""),
        "host": rec.get("host", ""),
        "path": rec.get("path", ""),
        "status": rec.get("status", 0),
        "content_type": rec.get("content_type", ""),
        "req_bytes": rec.get("req_bytes", 0),
        "resp_bytes": rec.get("resp_bytes", 0),
        "snippet": rec.get("snippet", ""),
        # Burp-style detail fields (may be absent in older logs -> "").
        "req_headers": rec.get("req_headers", ""),
        "req_body": rec.get("req_body", ""),
        "resp_headers": rec.get("resp_headers", ""),
        "resp_body": rec.get("resp_body", ""),
    }


class HttpsFlowSummary:
    """Collects parsed flows for the HTTPS content view: a capped list of the
    most recent requests plus a per-host rollup (requests, bytes)."""

    def __init__(self, max_flows: int = 500):
        self.max_flows = max_flows
        self.flows: list[dict] = []
        self._by_host: dict[str, dict] = {}

    def add_line(self, line: str) -> bool:
        rec = parse_flow_line(line)
        if not rec:
            return False
        self.flows.append(rec)
        if len(self.flows) > self.max_flows:
            self.flows = self.flows[-self.max_flows:]
        h = rec["host"]
        e = self._by_host.get(h)
        if e is None:
            e = {"host": h, "requests": 0, "bytes": 0, "last_path": ""}
            self._by_host[h] = e
        e["requests"] += 1
        e["bytes"] += rec["req_bytes"] + rec["resp_bytes"]
        e["last_path"] = rec["path"]
        return True

    def add_text(self, text: str) -> int:
        n = 0
        for line in (text or "").splitlines():
            if self.add_line(line):
                n += 1
        return n

    def recent(self, n: int = 50) -> list[dict]:
        """Most recent requests, newest first."""
        return list(reversed(self.flows[-n:]))

    def hosts(self) -> list[dict]:
        """Per-host rollup, busiest first."""
        return sorted(self._by_host.values(), key=lambda e: e["bytes"],
                      reverse=True)


class InspectSession:
    """Start/stop HTTPS interception for one routed target. Assumes routing
    (bettercap ARP spoof) is already on for the same target.

    Lifecycle: preflight() -> start(target_ip) -> stop(). stop() tears down the
    pf rules and mitmdump so the device goes back to normal TLS."""

    def __init__(self, port: int = PROXY_PORT):
        self.port = port
        self._proc: subprocess.Popen | None = None
        self._target = ""
        self._lock = threading.Lock()
        self.flow_log: str | None = None
        self._rules_path: str | None = None

    def is_running(self) -> bool:
        with self._lock:
            if self._proc is None:
                return False
            return self._proc.poll() is None

    def start(self, target_ip: str) -> tuple[bool, str]:
        ready, msg = preflight()
        if not ready:
            return False, msg
        if sys.platform != "darwin":
            return False, ("HTTPS inspection setup is wired for macOS (pf + "
                           "osascript) only right now.")
        if self.is_running():
            return False, f"Already inspecting {self._target}."
        try:
            rules = build_pf_rules(target_ip, self.port)
        except ValueError as e:
            return False, str(e)

        self.flow_log = default_flow_log_path()
        try:
            # 0600: the flow log holds decrypted request/response content
            # (headers, cookies, bodies) for the target device, so keep it
            # readable only by this user. Start it empty.
            fd = os.open(self.flow_log,
                         os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            os.close(fd)
            try:
                os.chmod(self.flow_log, 0o600)
            except OSError:
                pass
        except Exception:
            return False, f"Can't write the flow log at {self.flow_log}."

        # write the pf ruleset to a temp file the root script loads
        try:
            fd, self._rules_path = tempfile.mkstemp(prefix="netreg_pf_",
                                                    suffix=".conf")
            with os.fdopen(fd, "w") as f:
                f.write(rules)
        except Exception as e:
            return False, f"Can't stage pf rules: {e}"

        script = build_setup_script(target_ip, self.flow_log,
                                    self._rules_path, self.port)
        launch = ["osascript", "-e",
                  f'do shell script "{_osa_escape(script)}" '
                  f'with administrator privileges']
        try:
            self._proc = subprocess.Popen(launch, stdout=subprocess.DEVNULL,
                                          stderr=subprocess.DEVNULL)
            self._target = target_ip
        except Exception as e:
            return False, f"Could not start mitmproxy: {e}"

        note = "" if ca_cert_ready() else (" First run — the CA cert is being "
                                           "generated; trust it on the device.")
        return True, (f"Inspecting {target_ip}'s HTTPS. Requests appear below "
                      f"once the device trusts mitmproxy's certificate.{note}")

    def stop(self) -> tuple[bool, str]:
        with self._lock:
            proc = self._proc
            self._proc = None
        if proc is not None and proc.poll() is None:
            try:
                proc.terminate()
            except Exception:
                pass
        # tear down: stop mitmdump, flush pf rules, restore forwarding default.
        teardown = ("pkill -INT -x mitmdump 2>/dev/null; "
                    "pfctl -F nat 2>/dev/null; pfctl -d 2>/dev/null; "
                    "sysctl -w net.inet.ip.forwarding=0 2>/dev/null; true")
        try:
            subprocess.run(
                ["osascript", "-e",
                 f'do shell script "{_osa_escape(teardown)}" '
                 f'with administrator privileges'],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass
        if self._rules_path and os.path.exists(self._rules_path):
            try:
                os.remove(self._rules_path)
            except Exception:
                pass
        self._rules_path = None
        # The flow log holds decrypted content (cookies, auth headers, login
        # bodies). Don't leave it on disk after the session ends.
        if self.flow_log:
            for p in (self.flow_log, self.flow_log + ".err"):
                try:
                    if os.path.exists(p):
                        os.remove(p)
                except OSError:
                    pass
        self.flow_log = None
        if not self._target:
            return True, "HTTPS inspection wasn't running."
        target, self._target = self._target, ""
        return True, (f"Stopped inspecting {target}. The pf redirect and proxy "
                      f"are removed, and the decrypted-traffic log has been "
                      f"deleted. On the device, remove mitmproxy's certificate "
                      f"now — while it stays trusted, this Mac can read that "
                      f"device's HTTPS. (mitmproxy's CA private key lives in "
                      f"~/.mitmproxy; regenerate it if it is ever exposed.)")


if __name__ == "__main__":
    print("mitmdump available:", available())
    print("CA cert path:", ca_cert_path(), "exists:", ca_cert_ready())
    print("pf rules for 192.168.1.50:\n" + build_pf_rules("192.168.1.50"))
    print("mitmdump argv:", build_mitmdump_argv("/tmp/x.jsonl"))
    try:
        build_pf_rules("")
    except ValueError as e:
        print("empty target refused:", e)
