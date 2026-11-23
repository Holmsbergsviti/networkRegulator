"""Unit tests for netreg_fingerprint. Run: python3 test_fingerprint.py
Pure logic, offline."""
import netreg_fingerprint as fp

fails = []
total = 0


def check(name, cond):
    global total
    total += 1
    if cond:
        print(f"  ok   {name}")
    else:
        print(f"  FAIL {name}")
        fails.append(name)


print("netreg_fingerprint.classify:")
r = fp.classify(vendor="TP-Link Technologies", ports=[53, 80], is_gateway=True)
check("gateway + DNS + web -> router (high)", r.kind == "Router / gateway" and r.confidence == "high")

r = fp.classify(vendor="Hewlett Packard", ports=[9100, 80], hostname="HP-LaserJet")
check("HP + port 9100 -> printer", r.kind == "Printer" and r.confidence == "high")

r = fp.classify(vendor="Canon", ports=[631])
check("Canon + IPP -> printer", r.kind == "Printer")

r = fp.classify(vendor="Hikvision", ports=[554, 80])
check("Hikvision + RTSP -> camera", r.kind == "IP camera")

r = fp.classify(vendor="Apple", ports=[], hostname="Vlad-iPhone")
check("Apple + iphone hostname -> phone", r.kind == "Phone / tablet")

r = fp.classify(vendor="Randomized / private MAC", ports=[])
check("randomized MAC, no ports -> phone (low)", r.kind == "Phone / tablet" and r.confidence == "low")

r = fp.classify(vendor="Synology", ports=[5000, 445])
check("Synology + 5000 -> NAS", r.kind == "NAS / storage")

r = fp.classify(vendor="Dell Inc", ports=[22, 445])
check("Dell + ssh/smb -> computer", r.kind == "Computer")

r = fp.classify(vendor="Sony Interactive", ports=[])
check("Sony Interactive -> game console", r.kind == "Game console")

r = fp.classify(vendor="Espressif", ports=[80])
check("Espressif -> IoT", r.kind == "Smart-home / IoT")

r = fp.classify(vendor="", ports=[9100])
check("port alone (9100) still -> printer", r.kind == "Printer")

r = fp.classify(vendor="SomeUnknownCo", ports=[12345])
check("unrecognized vendor + odd port -> Unknown", r.kind == "Unknown")

r = fp.classify(vendor="Netgear", ports=[80], hostname="router.local", is_gateway=True)
check("router has explanatory reasons", r.kind == "Router / gateway" and len(r.reasons) >= 1)

r = fp.classify()
check("no signal at all doesn't crash", isinstance(r, fp.Result))

check("Result has kind/confidence/reasons",
      hasattr(r, "kind") and hasattr(r, "confidence") and hasattr(r, "reasons"))

print()
if fails:
    print(f"{len(fails)}/{total} FAILED: {fails}")
    raise SystemExit(1)
print(f"All {total} checks passed.")
