"""
netreg_printcap.py -- capture and inspect the traffic between this computer and
a printer, and judge whether the print data is sent in the clear.

====================  OWN-NETWORK / AUTHORIZED USE ONLY  ====================
This captures packets flowing to/from a printer so you can see whether your
print jobs are encrypted. Use it ONLY on a network you own or are explicitly
authorized to test. The GUI gates it behind an explicit confirmation.
============================================================================

Why this works without ARP spoofing
------------------------------------
When *this* Mac prints to the printer, the packets originate on this machine,
so a plain local capture (tcpdump on the active interface) sees the whole
job -- no gateway impersonation needed. ARP spoofing ("Route via this Mac")
is only required to capture a *different* device's jobs; for your own machine's
print jobs a direct capture is enough, and it's what this module does.

Design
------
Most of this file is pure, offline, unit-tested logic:
  * a tiny pcap reader (no scapy/tshark needed -- those aren't on a stock Mac),
  * a classifier that decides, per TCP stream, plaintext vs TLS vs opaque,
  * metadata/readable-text extraction from plaintext print jobs.
Actually running tcpdump needs root + a real NIC + a real print job, so that
path is exercised on the target machine, not in CI.

Printing protocols we look at:
  * TCP 9100  -- raw / JetDirect / AppSocket (usually plain PostScript/PCL/PJL)
  * TCP 631   -- IPP (plain) or IPPS (TLS) over HTTP
  * TCP 515   -- LPD/LPR (plain)
  * TCP 443   -- only to the printer host (IPPS / web admin over TLS)
"""
from __future__ import annotations

import ipaddress
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import threading

# port -> (short name, human label)
PRINT_PORTS: dict[int, tuple[str, str]] = {
    9100: ("raw", "Raw / JetDirect (port 9100)"),
    631: ("ipp", "IPP (port 631)"),
    515: ("lpd", "LPD / LPR (port 515)"),
    443: ("https", "HTTPS / IPPS (port 443)"),
}

# BPF ports we ask tcpdump to capture (printer host only).
_CAPTURE_PORTS = (9100, 631, 515, 443)

# Markers that prove we're looking at a real, readable print job / print
# protocol (i.e. NOT encrypted). Bytes, matched case-sensitively.
_PLAINTEXT_MARKERS: list[tuple[bytes, str]] = [
    (b"@PJL", "PJL printer-job-language commands"),
    (b"%!PS-Adobe", "PostScript document"),
    (b"%!PS", "PostScript document"),
    (b"%PDF", "PDF document"),
    (b"\x1b%-12345X", "PCL/PJL universal exit language"),
    (b"\x1bE", "PCL reset (printer control language)"),
    (b"application/ipp", "IPP print request (HTTP)"),
    (b"attributes-charset", "IPP job attributes"),
    (b"printer-uri", "IPP job attributes"),
    (b"document-format", "IPP job attributes"),
    (b"job-name", "IPP job attributes"),
    (b"\x1b@", "ESC/P printer commands"),
]


# --------------------------------------------------------------------------- #
# Classification primitives
# --------------------------------------------------------------------------- #
def looks_like_tls(payload: bytes) -> bool:
    """True if the payload begins with a TLS record header (handshake or
    application data), e.g. a ClientHello. TLS records start with a content
    type byte (0x14-0x17) followed by the version 0x03 0x0X."""
    if len(payload) < 3:
        return False
    content_type = payload[0]
    return content_type in (0x14, 0x15, 0x16, 0x17) and payload[1] == 0x03 \
        and payload[2] <= 0x04


def plaintext_markers(payload: bytes) -> list[str]:
    """Which plaintext print/protocol markers appear in the payload (de-duped,
    order preserved)."""
    found: list[str] = []
    for needle, desc in _PLAINTEXT_MARKERS:
        if needle in payload and desc not in found:
            found.append(desc)
    return found


_JOBNAME_PATTERNS = [
    re.compile(rb"@PJL\s+SET\s+JOBNAME\s*=\s*\"?([^\"\r\n]{1,120})", re.I),
    re.compile(rb"@PJL\s+JOB\s+NAME\s*=\s*\"?([^\"\r\n]{1,120})", re.I),
    # IPP: the job-name / document-name value follows the attribute name after a
    # 2-byte length. Grab a run of printable chars after the attribute name.
    re.compile(rb"(?:job-name|document-name)[^\x20-\x7e]{1,4}([\x20-\x7e]{2,120})", re.I),
    # LPD control file: 'J' record carries the job/banner name.
    re.compile(rb"\nJ([\x20-\x7e]{1,120})\n"),
]


def extract_job_name(payload: bytes) -> str:
    """Best-effort document/job name from a plaintext print job, or ''."""
    for pat in _JOBNAME_PATTERNS:
        m = pat.search(payload)
        if m:
            name = m.group(1).strip().strip(b"\"").decode("latin-1", "replace").strip()
            if name:
                return name
    return ""


def printable_excerpt(payload: bytes, limit: int = 400) -> str:
    """Longest run of printable text in the payload, trimmed to `limit`. Useful
    to *show* the person what leaked when a job is plaintext."""
    best = b""
    for run in re.findall(rb"[\x20-\x7e\r\n\t]{6,}", payload):
        if len(run) > len(best):
            best = run
    text = best.decode("latin-1", "replace").strip()
    if len(text) > limit:
        text = text[:limit] + "…"
    return text


def classify_segment(payload: bytes, sport: int, dport: int) -> dict:
    """Classify one TCP segment's payload.

    Returns {port, port_label, state, markers, job_name, excerpt, bytes}.
    `state` is one of: 'plaintext', 'encrypted', 'opaque', 'empty'.
      * plaintext -- readable print data / protocol (interceptable!)
      * encrypted -- a TLS record (contents protected)
      * opaque    -- data present but neither clearly readable nor TLS
                     (e.g. binary/compressed PCL); who-talks-to-who still leaks
      * empty     -- no payload (pure ACK / handshake)
    """
    # The printer port is whichever side is a known print port (prefer dest,
    # which is the printer when this machine is the client).
    port = dport if dport in PRINT_PORTS else (
        sport if sport in PRINT_PORTS else dport)
    label = PRINT_PORTS.get(port, ("", f"port {port}"))[1]

    if not payload:
        state = "empty"
        markers: list[str] = []
    elif (markers := plaintext_markers(payload)):
        state = "plaintext"
    elif looks_like_tls(payload):
        state = "encrypted"
        markers = []
    else:
        state = "opaque"
        markers = []

    return {
        "port": port,
        "port_label": label,
        "state": state,
        "markers": markers,
        "job_name": extract_job_name(payload) if state == "plaintext" else "",
        "excerpt": printable_excerpt(payload) if state == "plaintext" else "",
        "bytes": len(payload),
    }


# --------------------------------------------------------------------------- #
# Minimal pcap reader (libpcap classic format, no external deps)
# --------------------------------------------------------------------------- #
_PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": "<",   # little-endian, microseconds
    b"\xa1\xb2\xc3\xd4": ">",   # big-endian, microseconds
    b"\x4d\x3c\xb2\xa1": "<",   # little-endian, nanoseconds
    b"\xa1\xb2\x3c\x4d": ">",   # big-endian, nanoseconds
}


def _parse_ip_tcp(data: bytes):
    """From an IP packet, return (src_ip, sport, dst_ip, dport, payload) for TCP
    only, else None."""
    if not data:
        return None
    version = data[0] >> 4
    if version == 4:
        if len(data) < 20:
            return None
        ihl = (data[0] & 0x0F) * 4
        if ihl < 20 or len(data) < ihl:
            return None
        proto = data[9]
        if proto != 6:  # TCP
            return None
        src = ".".join(str(b) for b in data[12:16])
        dst = ".".join(str(b) for b in data[16:20])
        tcp = data[ihl:]
    elif version == 6:
        if len(data) < 40:
            return None
        if data[6] != 6:  # next header must be TCP (we don't walk ext headers)
            return None
        src = _ipv6(data[8:24])
        dst = _ipv6(data[24:40])
        tcp = data[40:]
    else:
        return None

    if len(tcp) < 20:
        return None
    sport, dport = struct.unpack("!HH", tcp[0:4])
    data_off = (tcp[12] >> 4) * 4
    if data_off < 20 or len(tcp) < data_off:
        return None
    return src, sport, dst, dport, tcp[data_off:]


def _ipv6(raw: bytes) -> str:
    parts = [f"{raw[i]<<8 | raw[i+1]:x}" for i in range(0, 16, 2)]
    return ":".join(parts)


def _strip_link_layer(linktype: int, frame: bytes) -> bytes:
    """Return the IP packet inside a captured frame for the link types a Mac
    actually produces."""
    if linktype == 1:  # Ethernet
        if len(frame) < 14:
            return b""
        etype = frame[12] << 8 | frame[13]
        off = 14
        while etype == 0x8100 and len(frame) >= off + 4:  # VLAN tag(s)
            etype = frame[off + 2] << 8 | frame[off + 3]
            off += 4
        if etype in (0x0800, 0x86DD):
            return frame[off:]
        return b""
    if linktype == 0:  # BSD loopback / NULL
        return frame[4:] if len(frame) >= 4 else b""
    if linktype == 101:  # raw IP
        return frame
    # DLT_LINUX_SLL etc. -- not expected on macOS; try a best-effort passthrough
    return frame


def iter_segments(data: bytes):
    """Yield (src, sport, dst, dport, payload) for every TCP segment in a classic
    pcap byte string. Tolerant of truncation."""
    if len(data) < 24:
        return
    endian = _PCAP_MAGICS.get(data[0:4])
    if endian is None:
        return
    linktype = struct.unpack(endian + "I", data[20:24])[0]
    pos = 24
    rec_hdr = struct.Struct(endian + "IIII")
    n = len(data)
    while pos + 16 <= n:
        _ts, _us, incl_len, _orig = rec_hdr.unpack(data[pos:pos + 16])
        pos += 16
        if incl_len == 0 or pos + incl_len > n:
            break
        frame = data[pos:pos + incl_len]
        pos += incl_len
        ip = _strip_link_layer(linktype, frame)
        parsed = _parse_ip_tcp(ip)
        if parsed:
            yield parsed


# --------------------------------------------------------------------------- #
# Whole-capture verdict
# --------------------------------------------------------------------------- #
def analyze(data: bytes, printer_ip: str | None = None) -> dict:
    """Read a pcap and summarize whether print traffic was readable.

    Returns a dict:
      verdict   -- 'plaintext' | 'encrypted' | 'opaque' | 'no_traffic'
      headline  -- one-line human summary
      ports     -- per-port rows: {port, label, state, bytes, packets}
      job_names -- document/job names recovered from plaintext jobs
      excerpt   -- a readable snippet from a plaintext job ('' if none)
      markers   -- protocol/content markers seen in plaintext data
      total_bytes, total_packets
    """
    per_port: dict[int, dict] = {}
    job_names: list[str] = []
    markers: list[str] = []
    excerpt = ""
    total_bytes = 0
    total_packets = 0

    for src, sport, dst, dport, payload in iter_segments(data):
        if printer_ip and printer_ip not in (src, dst):
            continue
        if sport not in PRINT_PORTS and dport not in PRINT_PORTS:
            continue
        info = classify_segment(payload, sport, dport)
        port = info["port"]
        total_packets += 1
        total_bytes += info["bytes"]

        row = per_port.setdefault(port, {
            "port": port, "label": info["port_label"],
            "state": "empty", "bytes": 0, "packets": 0})
        row["bytes"] += info["bytes"]
        row["packets"] += 1
        # escalate the port's state: plaintext > encrypted > opaque > empty
        row["state"] = _worse_state(row["state"], info["state"])

        for m in info["markers"]:
            if m not in markers:
                markers.append(m)
        if info["job_name"] and info["job_name"] not in job_names:
            job_names.append(info["job_name"])
        if not excerpt and info["excerpt"]:
            excerpt = info["excerpt"]

    ports = sorted(per_port.values(), key=lambda r: r["bytes"], reverse=True)

    if total_packets == 0:
        verdict = "no_traffic"
        headline = ("No printer traffic captured yet. Start the capture, then "
                    "print something to the printer.")
    elif any(r["state"] == "plaintext" for r in ports):
        verdict = "plaintext"
        where = ", ".join(sorted({r["label"] for r in ports
                                  if r["state"] == "plaintext"}))
        headline = (f"PLAINTEXT — your print data was sent in the clear on "
                    f"{where}. Anyone on this network who can see the traffic "
                    f"could read it.")
    elif any(r["state"] == "encrypted" for r in ports) and \
            not any(r["state"] == "opaque" for r in ports):
        verdict = "encrypted"
        headline = ("Encrypted — the printer traffic is TLS, so the contents "
                    "are protected. Observers see only that you printed, not "
                    "what.")
    elif any(r["state"] == "encrypted" for r in ports):
        verdict = "encrypted"
        headline = ("Mostly encrypted (TLS) with some non-readable binary "
                    "traffic; no plaintext document content was recovered.")
    else:
        verdict = "opaque"
        headline = ("Printer traffic was captured but isn't plainly readable "
                    "(binary or compressed) and isn't TLS. No document text "
                    "was recovered, but the connection itself is still visible.")

    return {
        "verdict": verdict,
        "headline": headline,
        "ports": ports,
        "job_names": job_names,
        "excerpt": excerpt,
        "markers": markers,
        "total_bytes": total_bytes,
        "total_packets": total_packets,
    }


_STATE_RANK = {"empty": 0, "opaque": 1, "encrypted": 2, "plaintext": 3}


def _worse_state(a: str, b: str) -> str:
    """The 'louder' of two stream states (plaintext is the loudest)."""
    return a if _STATE_RANK.get(a, 0) >= _STATE_RANK.get(b, 0) else b


# --------------------------------------------------------------------------- #
# tcpdump command construction + capture session
# --------------------------------------------------------------------------- #
def tcpdump_path() -> str:
    return shutil.which("tcpdump") or "/usr/sbin/tcpdump"


def available() -> bool:
    """tcpdump ships with macOS; True if we can find it."""
    return bool(shutil.which("tcpdump") or os.path.exists("/usr/sbin/tcpdump"))


def default_iface() -> str:
    """The interface with the default route (en0 on most Macs)."""
    try:
        r = subprocess.run(["route", "-n", "get", "default"],
                           capture_output=True, text=True, timeout=3)
        m = re.search(r"interface:\s*(\S+)", r.stdout)
        if m:
            return m.group(1)
    except Exception:
        pass
    return "en0"


def default_pcap_path() -> str:
    """Where tcpdump writes the capture so the GUI can analyze it."""
    mac_logs = os.path.join(os.path.expanduser("~"), "Library", "Logs")
    if sys.platform == "darwin" and os.path.isdir(mac_logs):
        return os.path.join(mac_logs, "LanLens-print.pcap")
    return os.path.join(tempfile.gettempdir(), "netreg_print.pcap")


def build_filter(printer_ip: str) -> str:
    """A BPF filter: only traffic to/from the printer, only on print ports."""
    printer_ip = (printer_ip or "").strip()
    if not printer_ip:
        raise ValueError("a printer IP is required")
    try:
        ipaddress.ip_address(printer_ip)
    except ValueError:
        raise ValueError(f"not a valid IP address: {printer_ip!r}")
    ports = " or ".join(f"tcp port {p}" for p in _CAPTURE_PORTS)
    return f"host {printer_ip} and ({ports})"


def build_argv(printer_ip: str, iface: str, pcap_path: str) -> list[str]:
    """Full tcpdump argv (without the privilege wrapper). Verifiable.

    -s 0  full packets (we need payloads), -U  flush each packet so the GUI sees
    data promptly, -w  write a pcap we can parse."""
    return [tcpdump_path(), "-i", iface or default_iface(), "-s", "0", "-U",
            "-w", pcap_path, build_filter(printer_ip)]


def preflight() -> tuple[bool, str]:
    if not available():
        return False, ("tcpdump wasn't found. It ships with macOS at "
                       "/usr/sbin/tcpdump; make sure it's on your PATH.")
    return True, "tcpdump found."


def _sh_quote(s: str) -> str:
    return "'" + s.replace("'", "'\\''") + "'"


def _osa_escape(s: str) -> str:
    """Escape for an AppleScript double-quoted literal. osascript runs
    `do shell script "<this>"`, so a bare " or \\ in the command would
    break out of the literal; escape both. Applied on top of the shell
    quoting (_sh_quote), which is a separate layer."""
    return s.replace("\\", "\\\\").replace('"', '\\"')


def _mac_admin_command(argv: list[str]) -> list[str]:
    """Wrap argv so macOS shows one GUI password prompt (osascript) and runs
    tcpdump in the background; stop() kills it by name."""
    quoted = " ".join(_sh_quote(a) for a in argv)
    inner = f"{quoted} &> /dev/null &"
    script = (f'do shell script "{_osa_escape(inner)}" '
              f'with administrator privileges')
    return ["osascript", "-e", script]


class PrintCaptureSession:
    """Start/stop a capture of this machine's traffic to a printer, then read
    the pcap back and judge it.

    Lifecycle: preflight() -> start(printer_ip) -> (print something) ->
    analyze() as often as you like -> stop()."""

    def __init__(self, iface: str | None = None):
        self.iface = iface or default_iface()
        self._proc: subprocess.Popen | None = None
        self._printer = ""
        self._lock = threading.Lock()
        self.pcap_path: str | None = None

    def is_running(self) -> bool:
        with self._lock:
            if self._proc is None:
                return False
            return self._proc.poll() is None

    def start(self, printer_ip: str) -> tuple[bool, str]:
        ready, msg = preflight()
        if not ready:
            return False, msg
        if self.is_running():
            return False, f"Already capturing traffic to {self._printer}."
        printer_ip = (printer_ip or "").strip()
        if not printer_ip:
            return False, "No printer IP to capture."
        self.pcap_path = default_pcap_path()
        try:
            # 0600: the capture can hold plaintext print-job content.
            fd = os.open(self.pcap_path,
                         os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            os.close(fd)
        except Exception:
            pass
        try:
            argv = build_argv(printer_ip, self.iface, self.pcap_path)
        except ValueError as e:
            return False, str(e)

        if sys.platform == "darwin":
            launch = _mac_admin_command(argv)  # GUI password prompt
        else:
            launch = ["sudo"] + argv
        try:
            self._proc = subprocess.Popen(launch, stdout=subprocess.DEVNULL,
                                          stderr=subprocess.DEVNULL)
            self._printer = printer_ip
        except Exception as e:
            return False, f"Could not start tcpdump: {e}"
        return True, (f"Capturing traffic between this computer and the printer "
                      f"at {printer_ip}. Now print a test page or a document, "
                      f"then watch the verdict below.")

    def analyze(self, printer_ip: str | None = None) -> dict:
        """Read whatever has been captured so far and judge it."""
        path = self.pcap_path
        if not path or not os.path.exists(path):
            return analyze(b"", printer_ip or self._printer or None)
        try:
            with open(path, "rb") as f:
                data = f.read()
        except Exception:
            data = b""
        return analyze(data, printer_ip or self._printer or None)

    def stop(self) -> tuple[bool, str]:
        with self._lock:
            proc = self._proc
            self._proc = None
        if proc is not None and proc.poll() is None:
            try:
                proc.terminate()
            except Exception:
                pass
        # tcpdump runs under a different pid, and on macOS as root (osascript
        # "with administrator privileges"), so an unprivileged pkill can't
        # signal it. Kill it the way we started it.
        if sys.platform == "darwin":
            try:
                subprocess.run(
                    ["osascript", "-e",
                     'do shell script "pkill -INT -f \\"tcpdump.*LanLens-print\\"" '
                     'with administrator privileges'],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception:
                pass
        elif shutil.which("pkill"):
            try:
                subprocess.run(["sudo", "-n", "pkill", "-INT", "-f",
                                "tcpdump.*LanLens-print"],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception:
                pass
        # The pcap can hold plaintext print-job content; don't leave it.
        if self.pcap_path:
            try:
                if os.path.exists(self.pcap_path):
                    os.remove(self.pcap_path)
            except OSError:
                pass
        self.pcap_path = None
        printer, self._printer = self._printer, ""
        if not printer:
            return True, "Nothing was running."
        return True, (f"Stopped capturing traffic to {printer}. The capture "
                      f"file has been deleted.")


if __name__ == "__main__":
    # Safe self-check: command construction + classifier only, no capture.
    print("tcpdump available:", available())
    print("default interface:", default_iface())
    print("filter for 192.168.1.50:", build_filter("192.168.1.50"))
    demo = b"\x1b%-12345X@PJL SET JOBNAME=\"Secret Q4 numbers.pdf\"\n%PDF-1.7 hello"
    print("classify raw-9100 job:", classify_segment(demo, 51000, 9100))
