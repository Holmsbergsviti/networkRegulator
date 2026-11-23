"""Unit tests for the macOS packaging config. Run: python3 test_packaging.py
(offline, no Mac needed -- it only validates the metadata/plist/scripts, not a
real build, which requires macOS)."""
import os
import plistlib
import subprocess
import sys
import tempfile

from packaging import appinfo

fails = []
total = 0


def check(name, cond):
    global total
    total += 1
    print(("  ok   " if cond else "  FAIL ") + name)
    if not cond:
        fails.append(name)


HERE = os.path.dirname(os.path.abspath(__file__))

print("appinfo metadata:")
check("app name is LanLens", appinfo.APP_NAME == "LanLens")
check("bundle id is reverse-dns lanlens", appinfo.BUNDLE_ID == "com.lanlens.app")
check("entry module exists",
      os.path.exists(os.path.join(HERE, appinfo.ENTRY_MODULE + ".py")))

print("Info.plist contents:")
pl = appinfo.info_plist()
check("CFBundleName is LanLens", pl.get("CFBundleName") == "LanLens")
check("has Location (when-in-use) usage string",
      "LanLens" in pl.get("NSLocationWhenInUseUsageDescription", ""))
check("has Location (always) usage string",
      bool(pl.get("NSLocationUsageDescription")))
check("has Local Network usage string",
      "Local Network" in pl.get("NSLocalNetworkUsageDescription", ""))
check("has Bonjour services list",
      isinstance(pl.get("NSBonjourServices"), list)
      and len(pl["NSBonjourServices"]) > 0)
check("declares a minimum macOS version",
      bool(pl.get("LSMinimumSystemVersion")))

print("Info.plist serialises to valid XML plist:")
xml = appinfo.info_plist_xml()
try:
    parsed = plistlib.loads(xml.encode("utf-8"))
    check("round-trips through plistlib", parsed == pl)
except Exception as e:
    check(f"round-trips through plistlib ({e})", False)

print("appinfo CLI fields (used by build_macapp.sh):")
for field, want in [("name", "LanLens"), ("entry", appinfo.ENTRY_MODULE),
                    ("bundle_id", appinfo.BUNDLE_ID)]:
    out = subprocess.run([sys.executable, "-m", "packaging.appinfo", field],
                         cwd=HERE, capture_output=True, text=True)
    check(f"`appinfo {field}` -> {want}", out.stdout.strip() == want)

print("build_macapp.sh:")
bs = os.path.join(HERE, "build_macapp.sh")
check("exists", os.path.exists(bs))
syn = subprocess.run(["bash", "-n", bs], capture_output=True, text=True)
check("passes `bash -n` syntax check", syn.returncode == 0)
body = open(bs).read()
check("bundles all modules via glob (not a stale fixed list)", "for f in *.py" in body)
check("documents the Gatekeeper right-click->Open step",
      "right-click" in body.lower() and "Open" in body)
check("uses free ad-hoc signing (sign -)", "--sign -" in body)
check("explains the free path needs no notarization",
      "notariz" in body.lower() and "ad-hoc" in body.lower())

print("entitlements file:")
ent = os.path.join(HERE, "packaging", "LanLens.entitlements")
check("exists", os.path.exists(ent))
try:
    edict = plistlib.loads(open(ent, "rb").read())
    check("is a valid plist", isinstance(edict, dict))
    check("app-sandbox disabled (needs raw network tools)",
          edict.get("com.apple.security.app-sandbox") is False)
except Exception as e:
    check(f"entitlements valid plist ({e})", False)

print("devicedb config-dir rename + label migration:")
import netreg_devicedb as ddb

check("default path is under a LanLens config dir",
      os.sep + "LanLens" + os.sep in ddb.default_path()
      or ddb.default_path().lower().find("lanlens") != -1)

# Simulate: an old NetworkRegulator devices.json exists, new LanLens one doesn't.
# DeviceDB(new_path) should migrate the label by reading the legacy file.
with tempfile.TemporaryDirectory() as td:
    new_p = os.path.join(td, "LanLens", "devices.json")
    old_p = os.path.join(td, "NetworkRegulator", "devices.json")
    os.makedirs(os.path.dirname(old_p))
    import json
    with open(old_p, "w") as f:
        json.dump({"aa:bb:cc:dd:ee:ff": {"label": "Dad's laptop",
                                          "first_seen": 1.0, "last_seen": 2.0}}, f)
    # Monkeypatch the path helpers so the test is hermetic.
    orig_default, orig_legacy = ddb.default_path, ddb._legacy_path
    ddb.default_path = lambda: new_p
    ddb._legacy_path = lambda: old_p
    try:
        db = ddb.DeviceDB(new_p)
        check("migrated label read from old NetworkRegulator file",
              db.label("aa:bb:cc:dd:ee:ff") == "Dad's laptop")
        db.set_label("11:22:33:44:55:66", "New TV")
        check("save writes to the new LanLens path", os.path.exists(new_p))
        check("old file left untouched (backup)", os.path.exists(old_p))
    finally:
        ddb.default_path, ddb._legacy_path = orig_default, orig_legacy

print()
if fails:
    print(f"{len(fails)}/{total} FAILED: {fails}")
    raise SystemExit(1)
print(f"All {total} checks passed.")
