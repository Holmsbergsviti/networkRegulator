"""
netreg_traffic.py -- turn bettercap's per-packet sniff log into a readable,
grouped summary: "this device <-> remote server, N packets, M data", with the
remote IP resolved to a hostname when possible.

Pure parsing/aggregation (unit-tested). Reverse-DNS is injected by the caller so
this module stays offline and testable; the GUI supplies a real resolver on a
background thread.
"""
from __future__ import annotations

import ipaddress
import re

# e.g. "[00:13:16] [net.sniff.udp] udp 192.178.24.10:https > host.local.:53273 180 bytes"
_PKT = re.compile(
    r"\b(tcp|udp)\s+(\S+):(\S+)\s+>\s+(\S+):(\S+)\s+(\d+)\s+bytes", re.IGNORECASE
)


def _is_public_ip(host: str) -> bool:
    """True only for a routable public IPv4/IPv6 literal (not private, loopback,
    link-local or a hostname)."""
    try:
        ip = ipaddress.ip_address(host.rstrip("."))
    except ValueError:
        return False
    return not (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_multicast or ip.is_unspecified or ip.is_reserved)


def parse_line(line: str):
    """Parse one bettercap tcp/udp sniff line into a dict, or None if it isn't
    one. Keys: proto, src, sport, dst, dport, bytes."""
    m = _PKT.search(line or "")
    if not m:
        return None
    proto, src, sport, dst, dport, nbytes = m.groups()
    try:
        n = int(nbytes)
    except ValueError:
        return None
    return {"proto": proto.lower(), "src": src.rstrip("."), "sport": sport,
            "dst": dst.rstrip("."), "dport": dport, "bytes": n}


def remote_endpoint(pkt: dict, target_ip: str | None = None):
    """Pick the REMOTE (non-local) end of a packet as (host, port). The remote
    is the public IP; if neither side is public, fall back to the side that
    isn't the target. Returns None when both ends look local (e.g. LAN-only)."""
    src_pub = _is_public_ip(pkt["src"])
    dst_pub = _is_public_ip(pkt["dst"])
    if dst_pub and not src_pub:
        return pkt["dst"], pkt["dport"]
    if src_pub and not dst_pub:
        return pkt["src"], pkt["sport"]
    if src_pub and dst_pub:
        # both public: treat the destination as the remote
        return pkt["dst"], pkt["dport"]
    # neither public: use target_ip to decide, else give up (local chatter)
    if target_ip:
        if pkt["src"] == target_ip:
            return pkt["dst"], pkt["dport"]
        if pkt["dst"] == target_ip:
            return pkt["src"], pkt["sport"]
    return None


class TrafficSummary:
    """Aggregates sniff lines by remote host. Feed lines with add_line(); read
    rows() for a sorted summary. Reverse-DNS names are stored in a cache the
    caller fills via set_name()."""

    def __init__(self, target_ip: str | None = None):
        self.target_ip = target_ip
        self._by_host: dict[str, dict] = {}
        self._names: dict[str, str] = {}

    def add_line(self, line: str) -> bool:
        pkt = parse_line(line)
        if not pkt:
            return False
        rem = remote_endpoint(pkt, self.target_ip)
        if not rem:
            return False
        host, port = rem
        e = self._by_host.get(host)
        if e is None:
            e = {"host": host, "packets": 0, "bytes": 0,
                 "protos": set(), "ports": set()}
            self._by_host[host] = e
        e["packets"] += 1
        e["bytes"] += pkt["bytes"]
        e["protos"].add(pkt["proto"])
        e["ports"].add(port)
        return True

    def add_text(self, text: str) -> int:
        """Feed a chunk of log text; returns how many packet lines it counted."""
        n = 0
        for line in (text or "").splitlines():
            if self.add_line(line):
                n += 1
        return n

    def hosts_without_names(self) -> list[str]:
        return [h for h in self._by_host if h not in self._names]

    def set_name(self, host: str, name: str):
        if name:
            self._names[host] = name

    def label(self, host: str) -> str:
        return self._names.get(host, host)

    def rows(self) -> list[dict]:
        """Per-remote-host summary, busiest first."""
        out = []
        for h, e in self._by_host.items():
            out.append({
                "host": h,
                "name": self._names.get(h, ""),
                "packets": e["packets"],
                "bytes": e["bytes"],
                "protos": ",".join(sorted(e["protos"])),
                "ports": ",".join(sorted(e["ports"])),
            })
        out.sort(key=lambda r: r["bytes"], reverse=True)
        return out


def human_bytes(n: int) -> str:
    f = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if f < 1024 or unit == "GB":
            return (f"{int(f)} {unit}" if unit == "B" else f"{f:.1f} {unit}")
        f /= 1024
    return f"{n} B"


if __name__ == "__main__":
    sample = [
        "[00:13:16] [net.sniff.udp] udp 192.178.24.10:https > host.local.:53273 180 bytes",
        "[00:13:16] [net.sniff.udp] udp host.local.:53273 > 192.178.24.10:https 43 bytes",
        "[00:13:19] [net.sniff.tcp] tcp 17.8.136.52:https > host.local.:51983 56 bytes",
        "[00:13:22] [net.sniff.mdns] mdns host.local. : PTR query for _hap._tcp.local",
    ]
    s = TrafficSummary()
    for ln in sample:
        s.add_line(ln)
    for r in s.rows():
        print(f"{r['host']:<16} {r['packets']:>4} pkts  {human_bytes(r['bytes']):>8}  "
              f"{r['protos']}  ports={r['ports']}")
