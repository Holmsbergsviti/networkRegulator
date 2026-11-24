"""
netreg_devicedb.py -- tiny persistent store of the devices we've seen.

Keyed by MAC address, it remembers two things the GUI wants to survive
restarts:

  * a custom label you give a device ("Living-room TV", "Dad's laptop"), and
  * whether we've seen this device before, so a brand-new one can be called
    out when it first joins.

It's a single JSON file in the user's config area. All the logic is pure and
unit-tested with a temp path; the only I/O is load()/save() reading and writing
that one file, each wrapped so a missing/corrupt file degrades to "empty" and
never crashes the app.
"""
from __future__ import annotations

import json
import os
import sys
import time


def _config_base(app_name: str) -> str:
    """Per-OS config directory for the given app folder name."""
    if sys.platform == "darwin":
        return os.path.join(os.path.expanduser("~"), "Library",
                            "Application Support", app_name)
    elif os.name == "nt":
        return os.path.join(os.environ.get("APPDATA", os.path.expanduser("~")),
                            app_name)
    else:
        return os.path.join(os.environ.get("XDG_CONFIG_HOME",
                            os.path.join(os.path.expanduser("~"), ".config")),
                            app_name.lower())


def default_path() -> str:
    """Per-user JSON file path for the devices store (app folder: LanLens)."""
    return os.path.join(_config_base("LanLens"), "devices.json")


def _legacy_path() -> str:
    """Old devices-store path from when the app was named NetworkRegulator.
    Used once to migrate saved labels into the new LanLens location."""
    return os.path.join(_config_base("NetworkRegulator"), "devices.json")


def normalize_mac(mac: str) -> str:
    """Lower-case, trim; "" for anything that isn't usable as a key."""
    m = (mac or "").strip().lower()
    return m if m and m != "ff:ff:ff:ff:ff:ff" else ""


def is_private_mac(mac: str) -> bool:
    """True if `mac` is a locally-administered (randomized / "private")
    address. Phones and laptops use these as a privacy feature; such a MAC
    isn't tied to the hardware and can rotate, so a saved label or "known
    device" won't follow it. Detected via the locally-administered bit (0x02)
    of the first octet."""
    m = normalize_mac(mac)
    if not m:
        return False
    first = m.replace("-", ":").split(":")[0]
    try:
        return bool(int(first, 16) & 0x02)
    except ValueError:
        return False


class DeviceDB:
    def __init__(self, path: str | None = None, clock=time.time):
        self.path = path or default_path()
        self._clock = clock
        self._data: dict[str, dict] = {}
        self.load()

    # ---- persistence ------------------------------------------------------
    def load(self):
        self._data = {}
        read_path = self.path
        # One-time migration: if the new (LanLens) file doesn't exist yet but an
        # old NetworkRegulator file does, read labels from the old one. We only
        # read it here; the next save() writes to the new path, so the old file
        # is left untouched as a backup.
        if (self.path == default_path()
                and not os.path.exists(self.path)
                and os.path.exists(_legacy_path())):
            read_path = _legacy_path()
        try:
            with open(read_path, "r", encoding="utf-8") as f:
                raw = json.load(f)
            if isinstance(raw, dict):
                # keep only well-formed entries
                for mac, rec in raw.items():
                    if isinstance(rec, dict):
                        self._data[normalize_mac(mac)] = {
                            "label": str(rec.get("label", "")),
                            "first_seen": rec.get("first_seen"),
                            "last_seen": rec.get("last_seen"),
                        }
        except Exception:
            self._data = {}
        self._data.pop("", None)

    def save(self) -> bool:
        try:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self._data, f, indent=2, sort_keys=True)
            os.replace(tmp, self.path)
            return True
        except Exception:
            return False

    def __len__(self) -> int:
        return len(self._data)

    # ---- labels (feature: custom device labels) ---------------------------
    def label(self, mac: str) -> str:
        return self._data.get(normalize_mac(mac), {}).get("label", "")

    def seen_info(self, mac: str):
        """(first_seen, last_seen) epoch floats for this MAC, or (None, None)
        if we have never recorded it."""
        rec = self._data.get(normalize_mac(mac), {})
        return rec.get("first_seen"), rec.get("last_seen")

    def set_label(self, mac: str, text: str, save: bool = True) -> bool:
        key = normalize_mac(mac)
        if not key:
            return False
        rec = self._data.setdefault(key, {"label": "", "first_seen": None,
                                          "last_seen": None})
        rec["label"] = (text or "").strip()
        if save:
            self.save()
        return True

    # ---- known / new (feature: new-device alerts) -------------------------
    def is_known(self, mac: str) -> bool:
        key = normalize_mac(mac)
        return bool(key) and self._data.get(key, {}).get("first_seen") is not None

    def mark_seen(self, mac: str) -> bool:
        """Record that `mac` is present now. Returns True if this is the FIRST
        time we've ever seen it (i.e. a new device), else False. Does not save
        on its own -- the caller batches a save after a sweep."""
        key = normalize_mac(mac)
        if not key:
            return False
        now = self._clock()
        rec = self._data.setdefault(key, {"label": "", "first_seen": None,
                                          "last_seen": None})
        is_new = rec.get("first_seen") is None
        if is_new:
            rec["first_seen"] = now
        rec["last_seen"] = now
        return is_new


if __name__ == "__main__":
    import tempfile
    p = os.path.join(tempfile.mkdtemp(), "devices.json")
    db = DeviceDB(p)
    print("first mark_seen is new:", db.mark_seen("AA:BB:CC:DD:EE:FF"))
    print("second mark_seen is not:", db.mark_seen("aa:bb:cc:dd:ee:ff"))
    db.set_label("aa:bb:cc:dd:ee:ff", "Test TV")
    db2 = DeviceDB(p)
    print("label persisted:", db2.label("AA:BB:CC:DD:EE:FF"))
    print("known after reload:", db2.is_known("aa:bb:cc:dd:ee:ff"))
