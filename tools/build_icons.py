#!/usr/bin/env python3
"""アプリアイコンとナビゲーションバーのロゴを生成する。

ATT&CK のマトリクスを模した格子に、Technique → DET → AN → DC の検知経路を
斜めに走るハイライトを重ねたマークを描く。Pillow のみで完結させる。

    python3 tools/build_icons.py
"""
from __future__ import annotations

import os

from PIL import Image, ImageDraw, ImageFilter, ImageFont

APP_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATIC_DIR = os.path.join(APP_ROOT, "static")

SS = 8  # アンチエイリアス用の拡大率

BG_TOP = (9, 14, 34)
BG_BOTTOM = (26, 39, 102)
GRID_FILL = (52, 74, 148, 120)
GRID_EDGE = (82, 112, 200, 150)
BORDER = (104, 168, 255, 160)
PATH_COLORS = [(0, 231, 255), (70, 170, 255), (140, 110, 255), (255, 86, 170)]

GRID_COLS = 4
GRID_ROWS = 4

FONT_CANDIDATES = [
    "/System/Library/Fonts/Supplemental/Arial Bold.ttf",
    "/System/Library/Fonts/HelveticaNeue.ttc",
    "/System/Library/Fonts/Supplemental/Futura.ttc",
    "/Library/Fonts/Arial Bold.ttf",
]


def load_font(size):
    for path in FONT_CANDIDATES:
        if os.path.exists(path):
            try:
                return ImageFont.truetype(path, size)
            except OSError:
                continue
    return None


def vertical_gradient(size, top, bottom):
    img = Image.new("RGB", size)
    draw = ImageDraw.Draw(img)
    height = size[1]
    for y in range(height):
        t = y / max(height - 1, 1)
        draw.line(
            [(0, y), (size[0], y)],
            fill=tuple(round(a + (b - a) * t) for a, b in zip(top, bottom)),
        )
    return img


def cell_rects(box, cols, rows, gap_ratio=0.22):
    """格子セルの座標を返す。"""
    x0, y0, x1, y1 = box
    cw = (x1 - x0) / cols
    ch = (y1 - y0) / rows
    gx = cw * gap_ratio
    gy = ch * gap_ratio
    out = []
    for r in range(rows):
        for c in range(cols):
            out.append(
                (
                    c,
                    r,
                    (
                        x0 + c * cw + gx / 2,
                        y0 + r * ch + gy / 2,
                        x0 + (c + 1) * cw - gx / 2,
                        y0 + (r + 1) * ch - gy / 2,
                    ),
                )
            )
    return out


def plate(s_w, s_h, radius):
    """濃色のグラデーション土台。明るい背景でも白文字が読めるようにする。"""
    mask = Image.new("L", (s_w, s_h), 0)
    ImageDraw.Draw(mask).rounded_rectangle([0, 0, s_w - 1, s_h - 1], radius=radius, fill=255)
    img = Image.new("RGBA", (s_w, s_h), (0, 0, 0, 0))
    img.paste(vertical_gradient((s_w, s_h), BG_TOP, BG_BOTTOM).convert("RGBA"), (0, 0), mask)
    glow = Image.new("RGBA", (s_w, s_h), (0, 0, 0, 0))
    ImageDraw.Draw(glow).ellipse(
        [-s_w * 0.3, -s_h * 0.5, s_w * 0.7, s_h * 0.45], fill=(90, 150, 255, 70)
    )
    glow = glow.filter(ImageFilter.GaussianBlur(min(s_w, s_h) * 0.08))
    img.alpha_composite(Image.composite(glow, Image.new("RGBA", (s_w, s_h), (0, 0, 0, 0)), mask))
    ImageDraw.Draw(img).rounded_rectangle(
        [1, 1, s_w - 2, s_h - 2],
        radius=radius,
        outline=BORDER,
        width=max(int(min(s_w, s_h) * 0.012), 1),
    )
    return img


def paint_grid(img, box, transparent=False):
    """ATT&CK のマトリクスを模した格子と、対角に走る検知経路を描き込む。"""
    s = int(max(box[2] - box[0], box[3] - box[1]))
    cells = cell_rects(box, GRID_COLS, GRID_ROWS)
    rect_of = {(c, r): rect for c, r, rect in cells}
    cell_radius = max(int(s * 0.04), 1)
    size = img.size

    base_layer = Image.new("RGBA", size, (0, 0, 0, 0))
    draw = ImageDraw.Draw(base_layer)
    for _, _, rect in cells:
        draw.rounded_rectangle(
            rect,
            radius=cell_radius,
            fill=(255, 255, 255, 46) if transparent else GRID_FILL,
            outline=(255, 255, 255, 80) if transparent else GRID_EDGE,
            width=max(int(s * 0.005), 1),
        )

    path_cells = [(i, i) for i in range(min(GRID_COLS, GRID_ROWS))]
    centers = [
        (
            (rect_of[key][0] + rect_of[key][2]) / 2,
            (rect_of[key][1] + rect_of[key][3]) / 2,
        )
        for key in path_cells
    ]

    # 経路の線はセルの下に敷く。
    line_layer = Image.new("RGBA", size, (0, 0, 0, 0))
    ImageDraw.Draw(line_layer).line(
        centers, fill=(150, 220, 255, 190), width=max(int(s * 0.022), 1), joint="curve"
    )

    cell_layer = Image.new("RGBA", size, (0, 0, 0, 0))
    cdraw = ImageDraw.Draw(cell_layer)
    for i, key in enumerate(path_cells):
        cdraw.rounded_rectangle(
            rect_of[key], radius=cell_radius, fill=PATH_COLORS[i % len(PATH_COLORS)] + (255,)
        )

    img.alpha_composite(base_layer)
    img.alpha_composite(line_layer.filter(ImageFilter.GaussianBlur(s * 0.03)))
    img.alpha_composite(line_layer)
    img.alpha_composite(cell_layer.filter(ImageFilter.GaussianBlur(s * 0.045)))
    img.alpha_composite(cell_layer)
    return img


def draw_mark(size, transparent=False):
    """正方形のマークを size x size で描く（内部では SS 倍で描画）。"""
    s = size * SS
    radius = int(s * 0.22)
    base = (
        Image.new("RGBA", (s, s), (0, 0, 0, 0))
        if transparent
        else plate(s, s, radius)
    )
    inset = s * 0.17
    paint_grid(base, (inset, inset, s - inset, s - inset), transparent=transparent)
    return base.resize((size, size), Image.LANCZOS)


def draw_logo(width, height):
    """ナビゲーションバー用の横長ロゴ。濃色の土台込みで描く。"""
    s_w, s_h = width * SS, height * SS
    img = plate(s_w, s_h, int(s_h * 0.26))

    pad = s_h * 0.16
    grid_size = s_h - pad * 2
    paint_grid(img, (pad, pad, pad + grid_size, pad + grid_size))

    draw = ImageDraw.Draw(img)
    x = pad * 2 + grid_size
    font = load_font(int(s_h * 0.36))
    small = load_font(int(s_h * 0.24))
    if font is not None:
        draw.text((x, s_h * 0.17), "ATT&CK", font=font, fill=(255, 255, 255, 255))
    if small is not None:
        draw.text((x, s_h * 0.58), "STIX ANALYSIS", font=small, fill=(140, 205, 255, 240))
    return img.resize((width, height), Image.LANCZOS)


def main():
    os.makedirs(STATIC_DIR, exist_ok=True)
    outputs = {
        "appIcon.png": lambda: draw_mark(36),
        "appIcon_2x.png": lambda: draw_mark(72),
        "appIconAlt.png": lambda: draw_mark(36, transparent=True),
        "appIconAlt_2x.png": lambda: draw_mark(72, transparent=True),
        "appLogo.png": lambda: draw_logo(160, 40),
        "appLogo_2x.png": lambda: draw_logo(320, 80),
        # ランチャーのカード用に大きめのものも置く
        "appIconLarge.png": lambda: draw_mark(256),
    }
    for name, builder in outputs.items():
        path = os.path.join(STATIC_DIR, name)
        builder().save(path, "PNG", optimize=True)
        print(f"  {name:20s} {os.path.getsize(path):6d} bytes")


if __name__ == "__main__":
    main()
