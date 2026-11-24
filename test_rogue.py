"""Unit tests for netreg_rogue (pure, offline). Run: python3 test_rogue.py"""
import netreg_rogue as rg

fails, total = [], 0
def check(name, cond):
    global total; total += 1
    print(("  ok   " if cond else "  FAIL ") + name)
    if not cond: fails.append(name)

def net(essid, privacy="WPA2", bssid=""):
    return {"ESSID": essid, "Privacy": privacy, "BSSID": bssid}

print("clean network set:")
clean = [net("Home  (connected)", "WPA2", "aa:bb:cc:00:00:01"),
         net("Cafe", "WPA2", "11:22:33:44:55:66")]
check("no alerts when nothing is suspicious", rg.analyze(clean) == [])

print("evil-twin (same name secured + open):")
twin = [net("Home  (connected)", "WPA2", "aa:bb:cc:00:00:01"),
        net("Home", "Open", "de:ad:be:ef:00:02")]
a = rg.analyze(twin)
check("flags the secured+open clash", any("secured and open" in x for x in a))
check("'(connected)' marker doesn't split the name", len(a) == 1)
check("open with empty Privacy also counts",
      any("secured and open" in x for x in rg.analyze(
          [net("X", "WPA2", "a1:a1:a1:a1:a1:a1"), net("X", "", "b2:b2:b2:b2:b2:b2")])))

print("duplicate BSSIDs (mesh/impostor):")
dup = [net("Cafe", "WPA2", "11:22:33:44:55:66"),
       net("Cafe", "WPA2", "11:22:33:44:55:77")]
a2 = rg.analyze(dup)
check("flags one name on two BSSIDs", any("broadcast by 2 access points" in x for x in a2))
check("same BSSID twice is NOT flagged",
      rg.analyze([net("Cafe","WPA2","11:22:33:44:55:66"),
                  net("Cafe","WPA2","11:22:33:44:55:66")]) == [])
check("missing BSSIDs (macOS) -> no false multi-AP alert",
      rg.analyze([net("Cafe","WPA2",""), net("Cafe","WPA2","")]) == [])

print("robustness:")
check("empty input -> no alerts", rg.analyze([]) == [])
check("blank ESSID ignored", rg.analyze([net("", "Open", "x")]) == [])
check("secured+open takes priority over multi-BSSID note",
      len(rg.analyze([net("Y","WPA2","a:a"), net("Y","Open","b:b"), net("Y","WPA2","c:c")])) == 1)

print()
if fails:
    print(f"{len(fails)}/{total} FAILED: {fails}"); raise SystemExit(1)
print(f"All {total} checks passed.")
