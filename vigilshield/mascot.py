"""VigilShield cyber-girl mascot — code-drawn PNG assets (v2, refined).

Front-facing bust portrait in three moods:
  calm  - blue/cyan visor (default / protected)
  alert - red visor + red aura + warning chevrons (threat blocked)
  scan  - bright cyan pulse rings (scanning)

Plus mascot.ico (256x256) for the exe.
Original artwork drawn with PIL; no external images.
Run: python -m vigilshield.mascot
"""
import math
import os

from PIL import Image, ImageDraw

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")

W, H = 400, 520

MOODS = {
    "calm":  {"visor": (120, 235, 255), "aura": (35, 90, 200),  "accent": (90, 220, 255),  "hair": (13, 52, 68)},
    "alert": {"visor": (255, 75, 75),   "aura": (200, 35, 35),  "accent": (255, 125, 95), "hair": (66, 20, 24)},
    "scan":  {"visor": (170, 255, 255), "aura": (0, 170, 200),  "accent": (140, 255, 255), "hair": (12, 62, 74)},
}

ARMOR = (24, 32, 56)
ARMOR_E = (72, 112, 165)
FACE = (10, 13, 24)


def _hex(cx, cy, r, rot=0.0):
    return [(cx + r * math.cos(rot + math.pi / 3 * i),
             cy + r * math.sin(rot + math.pi / 3 * i)) for i in range(6)]


def _soft_glow(img, box, color, passes=2, step=16, alpha=34):
    d = ImageDraw.Draw(img, "RGBA")
    for i in range(passes, 0, -1):
        pad = i * step
        b = [box[0] - pad, box[1] - pad, box[2] + pad, box[3] + pad]
        d.ellipse(b, fill=color + (alpha // (passes - i + 1),))


def draw_mascot(mood="calm"):
    m = MOODS[mood]
    img = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    d = ImageDraw.Draw(img, "RGBA")
    cx = W // 2

    # faint aura
    _soft_glow(img, [cx - 105, 60, cx + 105, 330], m["aura"], passes=2,
               step=22, alpha=30)

    if mood == "scan":
        for r, a in ((140, 55), (172, 32), (204, 16)):
            d.ellipse([cx - r, 195 - r, cx + r, 195 + r],
                      outline=m["accent"] + (a,), width=4)

    hair, accent = m["hair"], m["accent"]

    # back hair mass
    d.rounded_rectangle([cx - 118, 96, cx + 118, 480], radius=105,
                        fill=hair + (255,))
    d.rounded_rectangle([cx - 118, 96, cx + 118, 480], radius=105,
                        outline=accent + (110,), width=2)

    # torso: slimmer armored bodice
    d.polygon([(cx - 118, 500), (cx - 58, 350), (cx + 58, 350), (cx + 118, 500)],
              fill=ARMOR + (255,))
    d.polygon([(cx - 118, 500), (cx - 58, 350), (cx + 58, 350), (cx + 118, 500)],
              outline=ARMOR_E + (255,), width=3)
    # shoulder plates
    for s in (-1, 1):
        d.rounded_rectangle([cx + s * 118 - 34, 352, cx + s * 118 + 34, 420],
                            radius=18, fill=(20, 28, 52, 255),
                            outline=ARMOR_E + (255,), width=2)
    # neckline + chest emblem (small hexagon)
    d.polygon([(cx - 44, 356), (cx + 44, 356), (cx + 30, 400), (cx - 30, 400)],
              fill=(14, 20, 38, 255))
    _soft_glow(img, [cx - 30, 402, cx + 30, 448], accent, passes=2, step=10,
               alpha=40)
    d.polygon(_hex(cx, 425, 24), outline=accent + (255,), width=3)
    d.polygon(_hex(cx, 425, 12), fill=accent + (210,))
    # bodice seams
    d.line([(cx - 80, 460), (cx - 40, 380)], fill=ARMOR_E + (255,), width=2)
    d.line([(cx + 80, 460), (cx + 40, 380)], fill=ARMOR_E + (255,), width=2)

    # neck
    d.rectangle([cx - 26, 290, cx + 26, 356], fill=FACE + (255,))
    d.rectangle([cx - 26, 336, cx + 26, 356], fill=ARMOR + (255,))  # collar

    # face (slim, shadowed)
    d.ellipse([cx - 66, 130, cx + 66, 300], fill=FACE + (255,))

    # front hair locks framing the face
    for s in (-1, 1):
        x0 = cx + s * 78
        d.rounded_rectangle([x0 - 26, 120, x0 + 26, 400], radius=24,
                            fill=hair + (255,))
        d.rounded_rectangle([x0 - 26, 120, x0 + 26, 400], radius=24,
                            outline=accent + (130,), width=2)
        d.line([(x0, 170), (x0 + s * 6, 360)], fill=accent + (100,), width=3)

    # helmet: sleek dome + brow band, hair still visible at sides
    d.pieslice([cx - 96, 44, cx + 96, 236], start=180, end=360,
               fill=(18, 26, 52, 255))
    d.arc([cx - 96, 44, cx + 96, 236], start=180, end=360,
          fill=ARMOR_E + (255,), width=4)
    d.rectangle([cx - 96, 128, cx + 96, 150], fill=(18, 26, 52, 255))
    d.line([(cx - 96, 150), (cx + 96, 150)], fill=accent + (170,), width=3)
    # crest fin
    d.polygon([(cx - 10, 48), (cx + 10, 48), (cx, 22)], fill=accent + (230,))
    # side plates
    for s in (-1, 1):
        d.rounded_rectangle([cx + s * 96 - 16, 130, cx + s * 96 + 16, 210],
                            radius=10, fill=(22, 30, 58, 255),
                            outline=ARMOR_E + (255,), width=2)

    # visor: crisp glowing slit (small glow, sharp bar)
    _soft_glow(img, [cx - 56, 200, cx + 56, 228], m["visor"], passes=1,
               step=9, alpha=55)
    d.rounded_rectangle([cx - 50, 200, cx + 50, 228], radius=12,
                        fill=m["visor"] + (255,))
    d.line([(cx - 36, 214), (cx + 36, 214)], fill=(255, 255, 255, 235), width=4)

    # alert chevrons on brow band
    if mood == "alert":
        for yy in (132,):
            for s in (-1, 1):
                x = cx + s * 62
                d.polygon([(x - 14, yy), (x, yy + 8), (x - 14, yy + 16),
                           (x - 8, yy + 8)], fill=(255, 85, 65, 255))

    return img


def render_all(out_dir=None):
    out = out_dir or DATA_DIR
    os.makedirs(out, exist_ok=True)
    paths = {}
    for mood in MOODS:
        p = os.path.join(out, "mascot_%s.png" % mood)
        draw_mascot(mood).save(p)
        paths[mood] = p
    calm = draw_mascot("calm")
    icon = calm.crop((100, 40, 300, 240)).resize((256, 256), Image.LANCZOS)
    ico_path = os.path.join(out, "mascot.ico")
    icon.save(ico_path, sizes=[(256, 256), (128, 128), (64, 64), (48, 48),
                               (32, 32), (16, 16)])
    paths["ico"] = ico_path
    return paths


if __name__ == "__main__":
    for k, v in render_all().items():
        print(k, "->", v)
