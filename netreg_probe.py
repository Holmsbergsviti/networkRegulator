"""
netreg_probe.py -- lightweight, own-network service inspection helpers.

Two jobs, both used by the device-detail window:

  * Risk flags  -- point out services that are insecure by nature (Telnet,
    plaintext FTP, exposed SMB/NetBIOS file sharing, an admin web page with no
    login, …) so you can see at a glance what's worth locking down.
  * Banner / version -- a gentle connect-and-read (plus the HTTP Server header)
    that tells you *what* is listening ("OpenSSH 9.6", "nginx 1.24", a device
    login page) without any aggressive scanning.

The pure parsing/classification functions have no network side effects and are
unit-tested; grab_banner() is the only part that opens a socket, and it is
best-effort (returns "" on anything unexpected). Own-network use only.
"""
from __future__ import annotations

import re
import socket

# Ports that speak HTTP in the clear -- we have to send a request first before
# anything comes back, and the Server header is the useful "version".
HTTP_PLAINTEXT_PORTS = {80, 81, 591, 8000, 8008, 8080, 8081, 8888, 631}
# TLS ports: a raw socket read just yields binary, so the GUI fills these from
# probe_web() (which does the TLS handshake) instead of grab_banner().
HTTPS_PORTS = {443, 8443}

# Services that are insecure by their nature, with a short human reason. Keyed
# by TCP port. This is intentionally about design-level risk (plaintext,
# legacy, no-auth), not a CVE scan.
RISKY_PORTS = {
    21:   "FTP — login and files usually sent in clear text",
    23:   "Telnet — everything, including the password, is sent in clear text",
    512:  "rexec — legacy remote exec, unencrypted",
    513:  "rlogin — legacy remote login, unencrypted",
    514:  "rsh — legacy remote shell, unencrypted",
    139:  "SMB/NetBIOS — legacy Windows file sharing exposed to the network",
    445:  "SMB — file sharing exposed to the network (disable SMBv1)",
    69:   "TFTP — no authentication at all",
    161:  "SNMP — often left on a default 'public' community string",
    2323: "Telnet (alt) — clear-text remote login, common on IoT",
    5900: "VNC — screen sharing that is often unencrypted or weakly authed",
    3389: "RDP — only as safe as its password; expose with care",
    1900: "UPnP/SSDP — lets devices open holes in the router automatically",
}


def risk_for_port(port) -> str:
    """Return a short reason this port is risky, or "" if it isn't flagged."""
    try:
        return RISKY_PORTS.get(int(port), "")
    except (TypeError, ValueError):
        return ""


def web_risk(web_info) -> str:
    """Risk reason for a probe_web() result, or "".

    An admin/web page that answers 200 with no login (not 401/403) is reachable
    by anyone on the LAN -- worth flagging for a router/camera/printer."""
    if not web_info:
        return ""
    status = web_info.get("status")
    if status in (401, 403):
        return ""  # it asks for a login -> not an open admin page
    if status and 200 <= int(status) < 400:
        return "Web interface with no login — anyone on the network can open it"
    return ""


def summarize_risks(ports, web_info=None) -> list[str]:
    """Build the list of human risk lines for a device from its open ports and
    its web-probe result. Pure: no network access."""
    lines: list[str] = []
    for p in sorted({int(x) for x in ports if str(x).isdigit()}):
        reason = risk_for_port(p)
        if reason:
            lines.append(f"Port {p}: {reason}")
    wr = web_risk(web_info)
    if wr:
        lines.append(wr)
    return lines


_CTRL = re.compile(rb"[^\x09\x20-\x7e]")
_SERVER_HDR = re.compile(rb"^server:\s*(.+?)\s*$", re.I | re.M)


def parse_banner(port, raw: bytes) -> str:
    """Turn the raw bytes a service sent back into a short, readable version /
    banner string. Pure (no I/O). Returns "" when nothing useful is present."""
    if not raw:
        return ""
    # HTTP response: the Server header is the most useful single line.
    if raw[:5] in (b"HTTP/", b"HTTP ") or raw[:4] == b"HTTP":
        m = _SERVER_HDR.search(raw)
        if m:
            return _clean(m.group(1))
        return ""  # an HTTP reply with no Server header -> nothing to show
    # Everything else: take the first non-empty line, strip control bytes.
    for line in raw.split(b"\r\n"):
        line = line.strip()
        if not line:
            continue
        text = _clean(line)
        if text:
            return text
    return ""


def _clean(b: bytes, limit: int = 80) -> str:
    try:
        s = _CTRL.sub(b" ", b).decode("ascii", "replace")
    except Exception:
        return ""
    return re.sub(r"\s+", " ", s).strip()[:limit]


def grab_banner(ip: str, port, timeout: float = 1.5) -> str:
    """Best-effort banner/version for one open TCP port on `ip`.

    For plaintext-HTTP ports we send a HEAD request first (the server won't
    speak until spoken to); for everything else we just read what the service
    announces on connect (SSH, FTP, SMTP, POP, IMAP, Telnet all do). TLS ports
    are left to probe_web(). Returns "" on any error or silence."""
    try:
        p = int(port)
    except (TypeError, ValueError):
        return ""
    if p in HTTPS_PORTS:
        return ""  # handled by probe_web (needs a TLS handshake)
    try:
        with socket.create_connection((ip, p), timeout=timeout) as s:
            s.settimeout(timeout)
            if p in HTTP_PLAINTEXT_PORTS:
                try:
                    s.sendall(b"HEAD / HTTP/1.0\r\nHost: " + ip.encode("ascii", "ignore")
                              + b"\r\nUser-Agent: NetworkRegulator\r\n\r\n")
                except Exception:
                    return ""
            try:
                raw = s.recv(2048)
            except socket.timeout:
                raw = b""
            return parse_banner(p, raw)
    except Exception:
        return ""


if __name__ == "__main__":
    # Offline self-check: pure functions only.
    print("telnet risk:", risk_for_port(23))
    print("https (not risky by itself):", repr(risk_for_port(443)))
    print("ssh banner:", parse_banner(22, b"SSH-2.0-OpenSSH_9.6\r\n"))
    print("http server:", parse_banner(80, b"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n\r\n"))
    print("risks:", summarize_risks([22, 23, 445], {"status": 200}))
