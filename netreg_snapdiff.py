"""netreg_snapdiff.py -- compare a saved LanLens snapshot to the current device
list, so you can answer "what changed since last time?".

Snapshots are the Markdown reports netreg_report.build_report() writes. This
parses the device table back out and diffs it against the current devices,
keyed by MAC (the stable identity) with an IP fallback:

  * added   -- devices present now but not in the snapshot (new joiners),
  * removed -- devices in the snapshot but gone now,
  * changed -- same device, but its IP / hostname / vendor differs.

Pure and unit-tested. Note: a device using a rotating (private) MAC can show up
as both removed and added across snapshots, because its address changed -- that's
expected, not a fault of the diff.
"""
from __future__ import annotations


def parse_devices(markdown: str) -> list[dict]:
    """Pull the device rows out of a snapshot's '## Devices' table."""
    devices: list[dict] = []
    in_devices = False
    header_seen = False
    for raw in (markdown or "").splitlines():
        line = raw.strip()
        if line.startswith("## "):
            in_devices = line[3:].strip().lower().startswith("devices")
            header_seen = False
            continue
        if not in_devices or not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        if not header_seen:
            # first table line is the header ("IP | MAC | ...")
            header_seen = True
            continue
        if set("".join(cells)) <= set("-: "):
            continue  # separator row |----|----|
        if len(cells) < 2:
            continue
        # columns: IP, MAC, Vendor, Type, Hostname (later ones may be absent)
        devices.append({
            "IP": cells[0],
            "MAC": cells[1] if len(cells) > 1 else "",
            "Vendor": cells[2] if len(cells) > 2 else "",
            "Type": cells[3] if len(cells) > 3 else "",
            "Hostname": cells[4] if len(cells) > 4 else "",
        })
    return devices


def _key(d: dict) -> str:
    mac = (d.get("MAC") or d.get("Station MAC") or "").strip().lower()
    if mac:
        return "mac:" + mac
    return "ip:" + (d.get("IP") or "").strip()


def _get(d: dict, field: str) -> str:
    return (d.get(field, "") or "").strip()


def diff_devices(old: list[dict], new: list[dict]) -> dict:
    """Compare two device lists. Returns {added, removed, changed} where each
    'changed' entry is (current_device, {field: (old_value, new_value)})."""
    o = {_key(d): d for d in (old or [])}
    n = {_key(d): d for d in (new or [])}
    added = [n[k] for k in n if k not in o]
    removed = [o[k] for k in o if k not in n]
    changed = []
    for k, cur in n.items():
        if k not in o:
            continue
        prev = o[k]
        fields = {}
        for f in ("IP", "Hostname", "Vendor"):
            if _get(prev, f) != _get(cur, f):
                fields[f] = (_get(prev, f), _get(cur, f))
        if fields:
            changed.append((cur, fields))
    return {"added": added, "removed": removed, "changed": changed}


def _label(d: dict) -> str:
    ip = _get(d, "IP")
    mac = (d.get("MAC") or d.get("Station MAC") or "").strip()
    host = _get(d, "Hostname")
    bits = [b for b in (ip, host, mac) if b]
    return " / ".join(bits) or "(unknown device)"


def format_diff(result: dict) -> str:
    """A human-readable summary of diff_devices()'s output."""
    added, removed, changed = (result.get("added", []),
                               result.get("removed", []),
                               result.get("changed", []))
    if not (added or removed or changed):
        return "No changes: the same devices, at the same addresses."
    out: list[str] = []
    if added:
        out.append(f"New since the snapshot ({len(added)}):")
        out += [f"  + {_label(d)}" for d in added]
    if removed:
        out.append(f"Gone since the snapshot ({len(removed)}):")
        out += [f"  - {_label(d)}" for d in removed]
    if changed:
        out.append(f"Changed ({len(changed)}):")
        for cur, fields in changed:
            parts = ", ".join(f"{f}: {a or '∅'} → {b or '∅'}"
                              for f, (a, b) in fields.items())
            out.append(f"  ~ {_label(cur)} — {parts}")
    return "\n".join(out)


if __name__ == "__main__":
    snap = ("## Devices\n\n| IP | MAC | Vendor | Type | Hostname |\n"
            "|----|-----|--------|------|----------|\n"
            "| 192.168.1.1 | aa:bb:cc:00:00:01 | TP-Link | router | |\n"
            "| 192.168.1.50 | de:ad:be:ef:00:02 | Apple | phone | Vlad |\n")
    now = [{"IP": "192.168.1.1", "MAC": "aa:bb:cc:00:00:01", "Vendor": "TP-Link"},
           {"IP": "192.168.1.77", "MAC": "99:99:99:99:99:99", "Vendor": "Samsung"}]
    print(format_diff(diff_devices(parse_devices(snap), now)))
