"""
netreg_fingerprint.py -- best-effort guess of what KIND of device something is
(phone, laptop, router, printer, camera, TV, game console, IoT, NAS) from the
cheap signals we already collect: the MAC vendor, which TCP ports are open, the
hostname/mDNS name, and (optionally) the ping TTL.

Pure logic, no network calls -> fully unit-testable. The GUI passes in what a
device scan already found and shows the returned label; nothing here reaches
out on its own.

Return value of classify(): a Result with
  .kind        short label, e.g. "Printer", "Phone / tablet", "Router / gateway"
  .confidence  "high" | "medium" | "low"
  .reasons     list[str] explaining the guess (for a tooltip / detail view)
"""
from __future__ import annotations

from dataclasses import dataclass, field

# --- vendor keyword -> device kind ---------------------------------------- #
# Matched case-insensitively as substrings of the OUI vendor string.
_VENDOR_KIND = [
    ("Router / gateway", ("tp-link", "netgear", "asus", "linksys", "d-link",
                          "ubiquiti", "mikrotik", "zyxel", "arris", "technicolor",
                          "fritz", "avm", "huawei technolog")),
    ("Printer", ("hewlett", " hp ", "hp inc", "canon", "epson", "seiko epson",
                 "brother", "lexmark", "xerox", "kyocera", "ricoh")),
    ("IP camera", ("hikvision", "dahua", "axis comm", "reolink", "amcrest",
                   "wyze", "lorex", "foscam", "hanwha")),
    # Game console before TV so "Sony Interactive" (PlayStation) wins over the
    # generic "sony" TV match below.
    ("Game console", ("nintendo", "sony interactive", "xbox")),
    ("TV / streaming", ("roku", "vizio", "lg electronics", "samsung electro",
                        "sony", "tcl", "hisense", "amazon techn", "amazon.com",
                        "google, inc", "googlecast")),
    ("NAS / storage", ("synology", "qnap", "western digital", "netgear stora")),
    ("Smart-home / IoT", ("espressif", "tuya", "sonoff", "itead", "shelly",
                          "nest", "ecobee", "philips lighting", "signify",
                          "belkin", "wemo", "tp-link techno")),
    ("Phone / tablet", ("apple", "samsung electro", "xiaomi", "oneplus",
                        "oppo", "vivo", "motorola mobility", "huawei device")),
    ("Computer", ("dell", "lenovo", "intel corp", "micro-star", "asustek",
                  "gigabyte", "hewlett packard", "framework")),
]

# --- open port -> what it implies ----------------------------------------- #
_PORT_HINT = {
    9100: "Printer", 515: "Printer", 631: "Printer",   # raw / LPD / IPP
    554: "IP camera", 8554: "IP camera",               # RTSP
    445: "Computer", 139: "Computer", 3389: "Computer", 22: "Computer",
    5000: "NAS / storage", 5001: "NAS / storage",
    32400: "TV / streaming",                           # Plex
    8009: "TV / streaming",                            # Chromecast
    53: "Router / gateway", 67: "Router / gateway",
}

# Ports that, together with a web port, suggest an admin appliance (router).
_ADMIN_WEB = {80, 443, 8080, 8443}


@dataclass
class Result:
    kind: str = "Unknown"
    confidence: str = "low"
    reasons: list = field(default_factory=list)


def _vendor_kind(vendor: str):
    v = (vendor or "").lower()
    if not v or "randomized" in v or "private" in v:
        return None
    for kind, needles in _VENDOR_KIND:
        for n in needles:
            if n in v:
                return kind
    return None


def classify(vendor: str = "", ports=(), hostname: str = "",
             ttl: int | None = None, is_gateway: bool = False) -> Result:
    """Guess the device kind. Every argument is optional; the more you pass the
    better the guess. `is_gateway` True means this IP is the network's gateway."""
    ports = set(int(p) for p in (ports or []) if str(p).isdigit() or isinstance(p, int))
    host = (hostname or "").lower()
    reasons: list[str] = []
    votes: dict[str, int] = {}

    def vote(kind, weight, why):
        votes[kind] = votes.get(kind, 0) + weight
        reasons.append(why)

    # Gateway is the strongest single signal for a router.
    if is_gateway:
        vote("Router / gateway", 3, "it's the network's gateway")
    if any(k in host for k in ("router", "gateway", "gw", "modem")):
        vote("Router / gateway", 2, f"hostname looks like a router ({hostname})")
    if 53 in ports and ports & _ADMIN_WEB:
        vote("Router / gateway", 2, "serves DNS plus a web admin page")

    vk = _vendor_kind(vendor)
    if vk:
        vote(vk, 2, f"maker looks like a {vk.lower()} ({vendor})")

    for p in ports:
        hint = _PORT_HINT.get(p)
        if hint:
            vote(hint, 2, f"port {p} open ({hint.lower()})")

    # hostname keywords
    for kw, kind in (("printer", "Printer"), ("cam", "IP camera"),
                     ("tv", "TV / streaming"), ("roku", "TV / streaming"),
                     ("iphone", "Phone / tablet"), ("ipad", "Phone / tablet"),
                     ("android", "Phone / tablet"), ("macbook", "Computer"),
                     ("desktop", "Computer"), ("nas", "NAS / storage")):
        if kw in host:
            vote(kind, 1, f"hostname mentions '{kw}'")

    # TTL is a weak OS hint, used only to nudge phone vs computer.
    if ttl is not None:
        if ttl <= 0:
            pass
        elif ttl >= 200:
            vote("Router / gateway", 1, f"TTL {ttl} looks like network gear")

    if not votes:
        # Nothing matched. A device with a randomized MAC and no open ports is
        # almost always a phone/laptop hiding itself.
        if (vendor or "").lower().startswith("randomized") or not ports:
            return Result("Phone / tablet", "low",
                          ["private MAC and nothing exposed — likely a phone or laptop"])
        return Result("Unknown", "low", ["not enough signal to tell"])

    best = max(votes, key=votes.get)
    score = votes[best]
    # confidence from the winning score and whether it's a clear lead
    ordered = sorted(votes.values(), reverse=True)
    clear_lead = len(ordered) == 1 or ordered[0] - ordered[1] >= 2
    if score >= 4 and clear_lead:
        conf = "high"
    elif score >= 2:
        conf = "medium"
    else:
        conf = "low"
    # keep only the reasons that argued for the winner, plus any router note
    kept = [r for r in reasons]
    return Result(best, conf, kept)


if __name__ == "__main__":
    cases = [
        dict(vendor="TP-Link Technologies", ports=[53, 80], is_gateway=True),
        dict(vendor="Hewlett Packard", ports=[9100, 80], hostname="HP-LaserJet"),
        dict(vendor="Hikvision", ports=[554, 80]),
        dict(vendor="Apple", ports=[], hostname="iPhone"),
        dict(vendor="Randomized / private MAC", ports=[]),
        dict(vendor="Synology", ports=[5000, 445]),
        dict(vendor="", ports=[]),
    ]
    for c in cases:
        r = classify(**c)
        print(f"{r.kind:<20} [{r.confidence}]  {c}  -> {r.reasons[:2]}")
