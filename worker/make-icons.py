#!/usr/bin/env python3
"""Generate the PWA icons for the monitoring dashboard.

Drawn programmatically with Pillow so the output is reproducible and needs no
SVG delegate. Everything is rendered at 4x and downsampled for clean edges.

    python3 make-icons.py

Writes into ./assets:
    icon-192.png            any purpose
    icon-512.png            any purpose
    icon-maskable-512.png   maskable (Android adaptive icons crop to a circle)
    apple-touch-icon.png    180x180, opaque, for iOS home screen
"""
from __future__ import annotations

import pathlib

from PIL import Image, ImageDraw

OUT = pathlib.Path(__file__).resolve().parent / "assets"
SS = 4  # supersample factor

BG_TOP = (15, 23, 42)  # slate-900
BG_BOT = (30, 41, 59)  # slate-800
LINE = (56, 189, 248)  # sky-400
GRID = (148, 163, 184, 38)
DOT = (255, 255, 255)

# A rising, slightly wiggly line — reads as "sensor history" at any size.
CURVE = [
    (0.00, 0.70),
    (0.17, 0.47),
    (0.34, 0.57),
    (0.52, 0.30),
    (0.70, 0.40),
    (1.00, 0.12),
]


def gradient(size: int) -> Image.Image:
    """Vertical gradient as a square RGB image."""
    px = size * SS
    strip = Image.new("RGB", (1, px))
    for y in range(px):
        t = y / (px - 1)
        strip.putpixel(
            (0, y), tuple(round(BG_TOP[i] + (BG_BOT[i] - BG_TOP[i]) * t) for i in range(3))
        )
    return strip.resize((px, px), Image.BILINEAR)


def rounded_mask(size: int, radius_frac: float) -> Image.Image:
    px = size * SS
    m = Image.new("L", (px, px), 0)
    ImageDraw.Draw(m).rounded_rectangle(
        [0, 0, px - 1, px - 1], radius=int(px * radius_frac), fill=255
    )
    return m.resize((size, size), Image.LANCZOS)


def draw_icon(size: int, *, inset: float, radius_frac: float | None) -> Image.Image:
    """`inset` is the fraction of the canvas left as padding around the glyph.

    Maskable icons need a much larger inset, because platforms crop the outer
    ~20% when masking to a circle or squircle.
    """
    px = size * SS
    base = gradient(size).convert("RGBA")

    overlay = Image.new("RGBA", (px, px), (0, 0, 0, 0))
    d = ImageDraw.Draw(overlay)

    pad = inset * px
    x0, y0, x1, y1 = pad, pad, px - pad, px - pad
    w, h = x1 - x0, y1 - y0

    for i in range(1, 4):
        yy = y0 + h * i / 4
        d.line([x0, yy, x1, yy], fill=GRID, width=max(1, SS))

    pts = [(x0 + w * fx, y0 + h * fy) for fx, fy in CURVE]
    lw = max(2, round(h * 0.085))
    d.line(pts, fill=LINE, width=lw, joint="curve")
    for p in (pts[0], pts[-1]):  # round the caps
        r = lw / 2
        d.ellipse([p[0] - r, p[1] - r, p[0] + r, p[1] + r], fill=LINE)
    r = lw * 1.05  # highlight the final sample
    d.ellipse([pts[-1][0] - r, pts[-1][1] - r, pts[-1][0] + r, pts[-1][1] + r], fill=DOT)

    img = Image.alpha_composite(base, overlay).resize((size, size), Image.LANCZOS)
    if radius_frac is not None:
        img.putalpha(rounded_mask(size, radius_frac))
    return img


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    jobs = [
        ("icon-192.png", 192, 0.20, 0.22),
        ("icon-512.png", 512, 0.20, 0.22),
        ("icon-maskable-512.png", 512, 0.28, None),
        ("apple-touch-icon.png", 180, 0.20, None),  # iOS applies its own corners
    ]
    for name, size, inset, radius in jobs:
        img = draw_icon(size, inset=inset, radius_frac=radius)
        img.save(OUT / name)
        print(f"  {name:26} {size}x{size}  {img.mode}  {(OUT / name).stat().st_size:>6} B")


if __name__ == "__main__":
    print(f"writing icons to {OUT}")
    main()
