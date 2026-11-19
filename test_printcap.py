"""
Unit tests for netreg_printcap: the pure pcap reader + print-traffic classifier.
No root, no tcpdump, no real network -- we hand-build pcap bytes and assert the
verdict. Run: python -m pytest test_printcap.py   (or: python test_printcap.py)
"""
import struct

import netreg_printcap as pc


# --------------------------------------------------------------------------- #
# helpers to synthesize a classic (Ethernet) pcap with TCP segments
# --------------------------------------------------------------------------- #
def _ipv4_tcp(src, dst, sport, dport, payload):
    def ip4(s):
        return bytes(int(x) for x in s.split("."))
    tcp = struct.pack("!HHIIBBHHH", sport, dport, 0, 0, (5 << 4), 0x18,
                      1024, 0, 0) + payload
    total = 20 + len(tcp)
    ip = struct.pack("!BBHHHBBH", 0x45, 0, total, 0, 0, 64, 6, 0) + ip4(src) + ip4(dst)
    eth = b"\x11\x22\x33\x44\x55\x66" + b"\xaa\xbb\xcc\xdd\xee\xff" + b"\x08\x00"
    return eth + ip + tcp


def _pcap(frames):
    out = struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)  # Ethernet
    for fr in frames:
        out += struct.pack("<IIII", 0, 0, len(fr), len(fr)) + fr
    return out


PRINTER = "192.168.1.50"
ME = "192.168.1.10"


def test_tls_detection():
    client_hello = b"\x16\x03\x01\x00\x2f\x01\x00\x00\x2b\x03\x03" + b"\x00" * 40
    assert pc.looks_like_tls(client_hello)
    assert not pc.looks_like_tls(b"@PJL SET JOBNAME")
    assert not pc.looks_like_tls(b"")


def test_classify_plaintext_raw_job():
    payload = b"\x1b%-12345X@PJL SET JOBNAME=\"Payroll.pdf\"\n%PDF-1.7 hello world"
    info = pc.classify_segment(payload, 51000, 9100)
    assert info["state"] == "plaintext"
    assert info["port"] == 9100
    assert info["job_name"] == "Payroll.pdf"
    assert "PDF document" in info["markers"]
    assert "hello world" in info["excerpt"]


def test_classify_encrypted_ipps():
    payload = b"\x16\x03\x03\x01\x00" + b"\x00" * 200
    info = pc.classify_segment(payload, 52000, 443)
    assert info["state"] == "encrypted"
    assert info["job_name"] == ""


def test_classify_opaque_binary():
    payload = bytes(range(0, 200))  # not TLS, no print markers
    info = pc.classify_segment(payload, 51000, 9100)
    assert info["state"] == "opaque"


def test_classify_empty_is_ack():
    assert pc.classify_segment(b"", 51000, 9100)["state"] == "empty"


def test_analyze_plaintext_capture():
    job = b"\x1b%-12345X@PJL\n@PJL SET JOBNAME=\"Secret.docx\"\n%!PS-Adobe-3.0\nreadable text here"
    data = _pcap([
        _ipv4_tcp(ME, PRINTER, 51000, 9100, b""),          # SYN-ish, no payload
        _ipv4_tcp(ME, PRINTER, 51000, 9100, job),          # the job
        _ipv4_tcp(PRINTER, ME, 9100, 51000, b""),          # printer ACK
    ])
    res = pc.analyze(data, PRINTER)
    assert res["verdict"] == "plaintext"
    assert "Secret.docx" in res["job_names"]
    assert res["total_packets"] == 3
    assert any(r["port"] == 9100 and r["state"] == "plaintext" for r in res["ports"])
    assert "readable text here" in res["excerpt"]


def test_analyze_encrypted_capture():
    tls = b"\x16\x03\x03\x00\x50" + b"\x00" * 120
    appdata = b"\x17\x03\x03\x01\x00" + b"\x11" * 200
    data = _pcap([
        _ipv4_tcp(ME, PRINTER, 52000, 443, tls),
        _ipv4_tcp(PRINTER, ME, 443, 52000, appdata),
    ])
    res = pc.analyze(data, PRINTER)
    assert res["verdict"] == "encrypted"
    assert res["job_names"] == []


def test_analyze_filters_other_hosts_and_ports():
    other = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    data = _pcap([
        _ipv4_tcp(ME, "8.8.8.8", 40000, 80, other),       # wrong host+port
        _ipv4_tcp(ME, PRINTER, 40001, 22, b"SSH-2.0"),     # printer but wrong port
    ])
    res = pc.analyze(data, PRINTER)
    assert res["verdict"] == "no_traffic"
    assert res["total_packets"] == 0


def test_analyze_no_traffic():
    assert pc.analyze(b"", PRINTER)["verdict"] == "no_traffic"
    assert pc.analyze(b"not a pcap at all", PRINTER)["verdict"] == "no_traffic"


def test_build_filter_and_argv():
    f = pc.build_filter(PRINTER)
    assert "host 192.168.1.50" in f
    assert "tcp port 9100" in f and "tcp port 631" in f and "tcp port 515" in f
    argv = pc.build_argv(PRINTER, "en0", "/tmp/x.pcap")
    assert "-w" in argv and "/tmp/x.pcap" in argv and "en0" in argv
    try:
        pc.build_filter("")
        assert False, "empty printer IP should raise"
    except ValueError:
        pass


if __name__ == "__main__":
    import sys
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failed = 0
    for fn in fns:
        try:
            fn()
            print(f"ok   {fn.__name__}")
        except Exception as e:
            failed += 1
            print(f"FAIL {fn.__name__}: {e!r}")
    print(f"\n{len(fns) - failed}/{len(fns)} passed")
    sys.exit(1 if failed else 0)
