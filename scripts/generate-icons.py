"""Generates Bastión PWA and Windows desktop PNG icons from the FC-AGY-01 design."""

from pathlib import Path
from PIL import Image, ImageDraw

ROOT = Path(__file__).resolve().parent.parent
PUBLIC_DIR = ROOT / "public"
SUPERSAMPLE = 4
BASE_SIZE = 512


def cubic_bezier(p0, p1, p2, p3, steps=48):
    pts = []
    for i in range(1, steps + 1):
        t = i / steps
        mt = 1.0 - t
        x = (mt**3) * p0[0] + 3 * (mt**2) * t * p1[0] + 3 * mt * (t**2) * p2[0] + (t**3) * p3[0]
        y = (mt**3) * p0[1] + 3 * (mt**2) * t * p1[1] + 3 * mt * (t**2) * p2[1] + (t**3) * p3[1]
        pts.append((x, y))
    return pts


def draw_round_line(draw: ImageDraw.ImageDraw, p0, p1, color: str, width: float):
    draw.line([p0, p1], fill=color, width=round(width))
    r = width / 2.0
    for cx, cy in (p0, p1):
        draw.ellipse([cx - r, cy - r, cx + r, cy + r], fill=color)


def render_emblem(scale: float = 1.0, maskable: bool = False) -> Image.Image:
    size = BASE_SIZE * SUPERSAMPLE
    img = Image.new("RGBA", (size, size), "#0A0C10" if maskable else (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    content_scale = (0.80 if maskable else 1.0) * SUPERSAMPLE * scale
    offset = (size - BASE_SIZE * content_scale) / 2.0

    def tx(x: float, y: float):
        return (x * content_scale + offset, y * content_scale + offset)

    def sw(w: float) -> float:
        return w * content_scale

    if not maskable:
        draw.rounded_rectangle(
            [*tx(0, 0), *tx(512, 512)],
            radius=round(sw(96)),
            fill="#0A0C10",
        )

    draw.rounded_rectangle(
        [*tx(24, 24), *tx(488, 488)],
        radius=round(sw(76)),
        fill="#161B24",
        outline="#242C3A",
        width=round(sw(6)),
    )

    # Shield path: M256 88 L130 138 V238 C130 324 183 404 256 428 C329 404 382 324 382 238 V138 Z
    shield_pts = [
        (256, 88),
        (130, 138),
        (130, 238),
        *cubic_bezier((130, 238), (130, 324), (183, 404), (256, 428)),
        *cubic_bezier((256, 428), (329, 404), (382, 324), (382, 238)),
        (382, 138),
    ]
    shield_px = [tx(x, y) for x, y in shield_pts]
    draw.polygon(shield_px, fill="#0F131A")

    # Smooth stroke around shield polygon
    stroke_w = sw(18)
    closed_px = shield_px + [shield_px[0]]
    draw.line(closed_px, fill="#F59E0B", width=round(stroke_w), joint="curve")
    r_corner = stroke_w / 2.0
    for cx, cy in shield_px:
        draw.ellipse([cx - r_corner, cy - r_corner, cx + r_corner, cy + r_corner], fill="#F59E0B")

    # Key ring (cx=256, cy=222, r=32, stroke=16)
    cx, cy = tx(256, 222)
    outer_r = sw(32 + 8)
    inner_r = sw(32 - 8)
    draw.ellipse([cx - outer_r, cy - outer_r, cx + outer_r, cy + outer_r], fill="#F1F5F9")
    draw.ellipse([cx - inner_r, cy - inner_r, cx + inner_r, cy + inner_r], fill="#0F131A")

    # Key shaft and precision asymmetric teeth
    draw_round_line(draw, tx(256, 254), tx(256, 330), "#F59E0B", sw(18))
    draw_round_line(draw, tx(256, 292), tx(282, 292), "#F59E0B", sw(16))
    draw_round_line(draw, tx(256, 320), tx(272, 320), "#F59E0B", sw(14))
    draw_round_line(draw, tx(256, 306), tx(244, 306), "#F1F5F9", sw(12))

    # Camouflaged FC-AGY-01 maker's mark (Morse F ..-. + C -.-. + elevated Antigravity dot + A dash)
    for x, y, r, color in [
        (170, 457, 2.8, "#64748B"),
        (181, 457, 2.8, "#64748B"),
        (212, 457, 2.8, "#64748B"),
        (252, 457, 2.8, "#64748B"),
        (283, 457, 2.8, "#64748B"),
        (306, 451, 3.4, "#F59E0B"),
        (342, 457, 2.4, "#64748B"),
    ]:
        px, py = tx(x, y)
        pr = sw(r)
        draw.ellipse([px - pr, py - pr, px + pr, py + pr], fill=color)

    draw_round_line(draw, tx(190, 457), tx(203, 457), "#64748B", sw(4.8))
    draw_round_line(draw, tx(230, 457), tx(243, 457), "#64748B", sw(4.8))
    draw_round_line(draw, tx(261, 457), tx(274, 457), "#64748B", sw(4.8))
    draw_round_line(draw, tx(316, 457), tx(332, 457), "#F59E0B", sw(4.8))

    return img


def main():
    standard = render_emblem(maskable=False)
    maskable = render_emblem(maskable=True)

    outputs = [
        (standard, 512, PUBLIC_DIR / "pwa-512x512.png"),
        (standard, 192, PUBLIC_DIR / "pwa-192x192.png"),
        (standard, 180, PUBLIC_DIR / "apple-touch-icon.png"),
        (maskable, 512, PUBLIC_DIR / "pwa-maskable-512x512.png"),
    ]
    for src_img, target_px, out_path in outputs:
        resized = src_img.resize((target_px, target_px), Image.Resampling.LANCZOS)
        resized.save(out_path, format="PNG", optimize=True)
        print(f"Generated {out_path.relative_to(ROOT)} ({target_px}x{target_px})")


if __name__ == "__main__":
    main()
