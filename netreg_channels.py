"""
netreg_channels.py -- which Wi-Fi channel is congested, and which to switch to.

Pure analysis over the networks the scan already found (each a dict with "CH",
"Band" and "PWR"). No I/O, so it's fully unit-tested; the GUI just renders the
result and offers a Refresh.

2.4 GHz is the interesting band: its channels are only ~5 apart but ~20 MHz
wide, so neighbours overlap. We score each candidate channel by how much the
other APs bleed into it, weighted by their signal strength (a strong neighbour
hurts more than a faint one), and recommend the best of the non-overlapping
1 / 6 / 11. 5 GHz channels don't overlap like that, so there we just count
occupants per channel and suggest the emptiest standard one.
"""
from __future__ import annotations

# The three non-overlapping 2.4 GHz channels (the only sensible choices there).
NON_OVERLAP_24 = (1, 6, 11)
# Common 20 MHz 5 GHz channels to recommend between.
STD_5 = (36, 40, 44, 48, 149, 153, 157, 161)
# How far 2.4 GHz channels bleed into each other (channels, ~20 MHz ≈ 4 apart).
_SPREAD_24 = 5


def _int(v):
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return None


def _weight(pwr) -> float:
    """Turn a dBm signal (e.g. -52) into a positive interference weight: a
    stronger (closer to 0) neighbour counts for more. Unknown -> 1.0."""
    p = _int(pwr)
    if p is None:
        return 1.0
    # -30 dBm (very strong) -> 70; -90 dBm (faint) -> 10; floor at 1.
    return max(1.0, 100.0 + p)


def _band_of(net) -> str:
    band = str(net.get("Band", "")).strip()
    if band in ("2.4", "5", "6"):
        return band
    ch = _int(net.get("CH"))
    if ch is None:
        return "?"
    if 1 <= ch <= 14:
        return "2.4"
    if ch >= 36:
        return "5"
    return "?"


def _overlap(cand: int, ch: int) -> float:
    """Fraction (0..1) that an AP on `ch` bleeds into `cand` on 2.4 GHz."""
    d = abs(cand - ch)
    if d >= _SPREAD_24:
        return 0.0
    return (_SPREAD_24 - d) / _SPREAD_24


def analyze(networks) -> dict:
    """Return a channel-congestion summary for the given scanned networks.

    {
      "aps_24": int, "aps_5": int,
      "load_24":  [(channel, count, score), ...]  # channels 1..11
      "best_24":  (channel, reason),
      "load_5":   [(channel, count), ...]          # channels actually seen
      "best_5":   (channel, reason) | None,
      "summary":  str,
    }
    """
    aps_24, aps_5 = [], []
    for n in networks or []:
        band = _band_of(n)
        ch = _int(n.get("CH"))
        if ch is None:
            continue
        if band == "2.4":
            aps_24.append((ch, _weight(n.get("PWR"))))
        elif band == "5":
            aps_5.append(ch)

    # 2.4 GHz: congestion score per candidate channel 1..11.
    load_24 = []
    for cand in range(1, 12):
        count = sum(1 for ch, _w in aps_24 if _overlap(cand, ch) > 0)
        score = sum(w * _overlap(cand, ch) for ch, w in aps_24)
        load_24.append((cand, count, round(score, 1)))

    best_ch = min(NON_OVERLAP_24, key=lambda c: load_24[c - 1][2])
    best_score = load_24[best_ch - 1][2]
    if not aps_24:
        reason_24 = "no 2.4 GHz networks seen — any of 1 / 6 / 11 is clear."
    elif best_score == 0:
        reason_24 = f"channel {best_ch} is clear of overlap here."
    else:
        reason_24 = (f"channel {best_ch} is the least congested of 1 / 6 / 11 "
                     f"(overlap score {best_score:g}).")
    best_24 = (best_ch, reason_24)

    # 5 GHz: count occupants per channel seen.
    counts_5: dict[int, int] = {}
    for ch in aps_5:
        counts_5[ch] = counts_5.get(ch, 0) + 1
    load_5 = sorted(counts_5.items())
    best_5 = None
    if aps_5:
        cand5 = min(STD_5, key=lambda c: (counts_5.get(c, 0), c))
        n_here = counts_5.get(cand5, 0)
        reason_5 = (f"channel {cand5} is unused here." if n_here == 0
                    else f"channel {cand5} is the least used standard 5 GHz channel.")
        best_5 = (cand5, reason_5)

    bits = [f"{len(aps_24)} network(s) on 2.4 GHz, {len(aps_5)} on 5 GHz.",
            f"Best 2.4 GHz channel: {best_ch} — {reason_24}"]
    if best_5:
        bits.append(f"Best 5 GHz channel: {best_5[0]} — {best_5[1]}")
    elif len(aps_5) == 0:
        bits.append("No 5 GHz networks seen (5 GHz is usually the roomier band).")
    summary = " ".join(bits)

    return {
        "aps_24": len(aps_24), "aps_5": len(aps_5),
        "load_24": load_24, "best_24": best_24,
        "load_5": load_5, "best_5": best_5,
        "summary": summary,
    }


if __name__ == "__main__":
    demo = [
        {"CH": "1", "Band": "2.4", "PWR": "-40"},
        {"CH": "1", "Band": "2.4", "PWR": "-55"},
        {"CH": "6", "Band": "2.4", "PWR": "-70"},
        {"CH": "36", "Band": "5", "PWR": "-50"},
    ]
    r = analyze(demo)
    print(r["summary"])
    print("2.4 load:", r["load_24"])
    print("best 2.4:", r["best_24"])
