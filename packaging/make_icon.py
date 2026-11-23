"""
make_icon.py -- generate the LanLens app icon as a 1024x1024 PNG.

Pure Pillow, no network, no Mac needed. build_macapp.sh calls this to produce
packaging/LanLens.png, then (on a Mac) turns that PNG into a proper multi-size
.icns with `sips` + `iconutil`.

The icon is a simple, recognisable "radar / scan" mark: concentric signal arcs
over a rounded dark tile in the app's accent blue -- readable at Dock size.

Usage:  python3 packaging/make_icon.py [output.png]
"""
from __future__ import annotations

import sys

SIZE = 1024
# Palette (matches the app's light-theme accent).
BG_TOP = (29, 36, 48)        # #1d2430  ink
BG_BOTTOM = (16, 22, 33)     # darker
ACCENT = (47, 111, 237)      # #2f6fed
ACCENT_SOFT = (120, 165, 250)
WHITE = (255, 255, 255)


def _rounded_tile(img, draw):
    """Dark vertical-gradient rounded tile filling the canvas."""
    from PIL import Image
    radius = int(SIZE * 0.22)
    grad = Image.new("RGB", (1, SIZE))
    for y in range(SIZE):
        t = y / (SIZE - 1)
        grad.putpixel((0, y), tuple(
            int(BG_TOP[i] + (BG_BOTTOM[i] - BG_TOP[i]) * t) for i in range(3)))
    grad = grad.resize((SIZE, SIZE))
    mask = Image.new("L", (SIZE, SIZE), 0)
    from PIL import ImageDraw
    ImageDraw.Draw(mask).rounded_rectangle([0, 0, SIZE - 1, SIZE - 1],
                                           radius=radius, fill=255)
    img.paste(grad, (0, 0), mask)


def build(path: str) -> str:
    from PIL import Image, ImageDraw
    img = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    _rounded_tile(img, draw)
    draw = ImageDraw.Draw(img)

    cx, cy = SIZE // 2, int(SIZE * 0.58)
    # three concentric signal arcs, fading outward
    arcs = [
        (int(SIZE * 0.30), ACCENT, 46),
        (int(SIZE * 0.44), ACCENT_SOFT, 40),
        (int(SIZE * 0.58), (90, 130, 210), 34),
    ]
    for r, color, w in arcs:
        box = [cx - r, cy - r, cx + r, cy + r]
        draw.arc(box, start=210, end=330, fill=color, width=w)
    # the "you are here" dot at the apex
    dot = int(SIZE * 0.045)
    draw.ellipse([cx - dot, cy - dot, cx + dot, cy + dot], fill=WHITE)

    img.save(path, "PNG")
    return path


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "packaging/LanLens.png"
    print(build(out))
