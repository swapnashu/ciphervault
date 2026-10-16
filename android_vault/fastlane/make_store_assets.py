"""Render the Play Store / F-Droid image assets from the launcher vector.

Outputs into fastlane/metadata/android/en-US/images/:
  icon.png            512x512  (Play icon spec, 32-bit with alpha)
  featureGraphic.png  1024x500 (Play feature graphic)

Run from anywhere:  python fastlane/make_store_assets.py
Requires Pillow.  The foreground paths mirror
app/src/main/res/drawable/ic_launcher_foreground.xml — keep them in sync.
"""
from __future__ import annotations

import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

VIEWPORT = 108.0
ICON_SIZE = 512
FEATURE = (1024, 500)
SS = 16  # supersampling factor for smooth edges

GREEN = "#0B6B47"
BEVEL = "#B08D1F"
WHITE = "#FFFFFF"
BG = "#FFFFFF"
TEXT_GREEN = "#0B6B47"
TEXT_GRAY = "#4A5560"

FONT_BOLD = Path("C:/Windows/Fonts/segoeuib.ttf")
FONT_REG = Path("C:/Windows/Fonts/segoeui.ttf")


def cubic(p0, p1, p2, p3, steps=64):
    pts = []
    for i in range(steps + 1):
        t = i / steps
        u = 1 - t
        x = u**3 * p0[0] + 3 * u * u * t * p1[0] + 3 * u * t * t * p2[0] + t**3 * p3[0]
        y = u**3 * p0[1] + 3 * u * u * t * p1[1] + 3 * u * t * t * p2[1] + t**3 * p3[1]
        pts.append((x, y))
    return pts


def scale_pts(pts, s, cx=0.0, cy=0.0):
    return [((x + cx) * s, (y + cy) * s) for x, y in pts]


def draw_foreground(size: int) -> Image.Image:
    s = size * SS / VIEWPORT
    img = Image.new("RGBA", (size * SS, size * SS), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)

    # Shield body
    shield = [(54, 26), (74, 34), (74, 54)]
    shield += cubic((74, 54), (74, 68), (65, 78), (54, 83))
    shield += cubic((54, 83), (43, 78), (34, 68), (34, 54))
    shield += [(34, 54), (34, 34)]
    d.polygon(scale_pts(shield, s), fill=GREEN)

    # Shield inner bevel
    bevel = [(54, 32), (68, 38), (68, 54)]
    bevel += cubic((68, 54), (68, 65), (61, 72), (54, 76))
    bevel += cubic((54, 76), (47, 72), (40, 65), (40, 54))
    bevel += [(40, 54), (40, 38)]
    d.polygon(scale_pts(bevel, s), fill=BEVEL)

    # Padlock body
    d.rectangle(scale_pts([(46, 56), (62, 70)], s), fill=WHITE)

    # Padlock shackle: stamped discs along the path give a round-capped,
    # round-joined stroke (PIL's line width sprays on curves).
    shackle = [(49, 56), (49, 50)]
    shackle += cubic((49, 50), (49, 45.6), (51.7, 42), (54, 42))
    shackle += cubic((54, 42), (56.3, 42), (59, 45.6), (59, 50))
    shackle += [(59, 50), (59, 56)]
    r = 2 * s
    pts = scale_pts(shackle, s)
    for i in range(len(pts) - 1):
        x0, y0 = pts[i]
        x1, y1 = pts[i + 1]
        dist = max(abs(x1 - x0), abs(y1 - y0))
        steps = max(1, int(dist / (r / 2)))
        for k in range(steps + 1):
            t = k / steps
            cx, cy = x0 + (x1 - x0) * t, y0 + (y1 - y0) * t
            d.ellipse([cx - r, cy - r, cx + r, cy + r], fill=WHITE)

    # Keyhole
    kx, ky, kr = 54 * s, 60 * s, 3 * s
    d.ellipse([kx - kr, ky - kr, kx + kr, ky + kr], fill=GREEN)
    d.polygon(scale_pts([(52.6, 62), (55.4, 62), (55.8, 67), (52.2, 67)], s), fill=GREEN)

    return img.resize((size, size), Image.LANCZOS)


def make_icon(out: Path) -> Image.Image:
    icon = Image.new("RGB", (ICON_SIZE, ICON_SIZE), BG)
    fg = draw_foreground(ICON_SIZE)
    icon.paste(fg, (0, 0), fg)
    icon.save(out / "icon.png")
    return icon


def make_feature(out: Path, icon: Image.Image) -> None:
    w, h = FEATURE
    g = Image.new("RGB", FEATURE, BG)
    d = ImageDraw.Draw(g)

    glyph = icon.resize((360, 360), Image.LANCZOS)
    g.paste(glyph, (72, (h - 360) // 2))

    tx = 492
    margin = 48
    avail = w - tx - margin

    def fit(font_path: Path, text: str, start: int) -> ImageFont.FreeTypeFont:
        size = start
        while size > 20:
            font = ImageFont.truetype(str(font_path), size)
            width = d.textbbox((0, 0), text, font=font)[2]
            if width <= avail:
                return font
            size -= 2
        return ImageFont.truetype(str(font_path), 20)

    title_font = fit(FONT_BOLD, "CipherVault", 100)
    sub_font = fit(FONT_REG, "Zero-knowledge password manager", 40)
    title_box = d.textbbox((0, 0), "CipherVault", font=title_font)
    sub_box = d.textbbox((0, 0), "Zero-knowledge password manager", font=sub_font)
    gap = 28
    block_h = (title_box[3] - title_box[1]) + gap + (sub_box[3] - sub_box[1])
    ty = (h - block_h) // 2 - title_box[1]
    sy = ty + (title_box[3] - title_box[1]) + gap - sub_box[1]
    d.text((tx, ty), "CipherVault", font=title_font, fill=TEXT_GREEN)
    d.text((tx, sy), "Zero-knowledge password manager", font=sub_font, fill=TEXT_GRAY)

    g.save(out / "featureGraphic.png")


def main() -> int:
    out = Path(__file__).resolve().parent / "metadata" / "android" / "en-US" / "images"
    out.mkdir(parents=True, exist_ok=True)
    icon = make_icon(out)
    make_feature(out, icon)
    for name, size in (("icon.png", (512, 512)), ("featureGraphic.png", FEATURE)):
        img = Image.open(out / name)
        assert img.size == size, f"{name}: {img.size} != {size}"
        print(f"{out / name}  {img.size[0]}x{img.size[1]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
