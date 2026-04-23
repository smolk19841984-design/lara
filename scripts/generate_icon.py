#!/usr/bin/env python3
"""
Generate iOS app icon PNGs for build_ipa_wsl.sh (lara/Info.plist: AppIcon60x60).

Design: custom geometric "L" (no system font), diagonal gradient, vignette,
inset card, fine highlight — reads clearly at 60pt.

Usage:
  python3 scripts/generate_icon.py <output_dir>

Requires Pillow (apt install python3-pil / pip install pillow). Fallback: flat PNG.
"""
from __future__ import annotations

import math
import os
import struct
import sys
import zlib

SIZES = {
    "AppIcon60x60.png": 60,
    "AppIcon60x60@2x.png": 120,
    "AppIcon60x60@3x.png": 180,
}

# Rich dark palette (cool indigo, not generic magenta)
C_TOP = (22, 14, 48)
C_BOT = (52, 28, 92)
C_CARD = (16, 10, 38)
C_L_MAIN = (248, 244, 255)
C_L_SHADOW = (8, 4, 20)
C_ACCENT = (80, 220, 200)  # soft teal, single accent stroke


def _write_png_solid_rgba(path: str, w: int, h: int, r: int, g: int, b: int, a: int = 255) -> None:
    raw = bytearray()
    for y in range(h):
        raw.append(0)
        for _x in range(w):
            raw.extend((r, g, b, a))

    def _chunk(t: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + t + data + struct.pack(">I", zlib.crc32(t + data) & 0xFFFFFFFF)

    ihdr = struct.pack(">2I5B", w, h, 8, 6, 0, 0, 0)
    comp = zlib.compress(bytes(raw), 9)
    png = b"\x89PNG\r\n\x1a\n" + _chunk(b"IHDR", ihdr) + _chunk(b"IDAT", comp) + _chunk(b"IEND", b"")
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "wb") as f:
        f.write(png)


def _lerp3(a: tuple[int, int, int], b: tuple[int, int, int], t: float) -> tuple[int, int, int]:
    return tuple(int(a[i] + (b[i] - a[i]) * t) for i in range(3))


def _fill_diagonal_vignette(im, size: int) -> None:
    pix = im.load()
    cx = cy = (size - 1) * 0.5
    max_d = size * 0.72
    for y in range(size):
        for x in range(size):
            t = (x + y) / max(2 * (size - 1), 1)
            base = _lerp3(C_TOP, C_BOT, t)
            d = math.hypot(x - cx, y - cy)
            v = 1.0 - min(1.0, d / max_d) * 0.42
            c = (int(base[0] * v + 0.5), int(base[1] * v + 0.5), int(base[2] * v + 0.5))
            pix[x, y] = (*c, 255)


def _round_rect(
    draw,
    box: tuple[int, int, int, int],
    radius: int,
    fill: tuple[int, int, int, int] | None = None,
    outline: tuple[int, int, int, int] | None = None,
    width: int = 1,
) -> None:
    try:
        draw.rounded_rectangle(box, radius=radius, fill=fill, outline=outline, width=width)
    except TypeError:
        if fill is not None:
            draw.rounded_rectangle(box, radius=radius, fill=fill[:3] if len(fill) == 4 else fill)
        if outline is not None:
            draw.rounded_rectangle(box, radius=radius, outline=outline[:3], width=width)


def _draw_l_monogram(draw: "ImageDraw.ImageDraw", size: int, stroke: int, pad: int) -> None:
    """Thick rounded L: shadow layer first, then main."""
    r_cap = max(1, stroke // 2)
    s = size
    y_join = s - pad - stroke
    off = max(1, size // 64)
    v_box = (pad, pad, pad + stroke, y_join)
    h_box = (pad, s - pad - stroke, s - pad, s - pad)
    shadow = (*C_L_SHADOW, 150)
    v_sh = (v_box[0] + off, v_box[1] + off, v_box[2] + off, v_box[3] + off)
    h_sh = (h_box[0] + off, h_box[1] + off, h_box[2] + off, h_box[3] + off)

    _round_rect(draw, v_sh, r_cap, fill=shadow)
    _round_rect(draw, h_sh, r_cap, fill=shadow)
    _round_rect(draw, v_box, r_cap, fill=(*C_L_MAIN, 255))
    _round_rect(draw, h_box, r_cap, fill=(*C_L_MAIN, 255))

    if size >= 40:
        aw = max(1, stroke // 3)
        ax0 = pad + stroke // 2
        ay0 = y_join - aw * 2
        ax1 = ax0 + stroke * 2
        ay1 = ay0 + aw
        try:
            draw.rounded_rectangle((ax0, ay0, ax1, ay1), radius=aw, fill=(*C_ACCENT, 255))
        except Exception:
            draw.rectangle((ax0, ay0, ax1, ay1), fill=(*C_ACCENT, 255))


# Master artboard — downscaled with LANCZOS for clean edges on 60pt
_MASTER_PX = 512


def _render_master() -> "Image.Image":
    from PIL import Image, ImageDraw

    size = _MASTER_PX
    im = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    _fill_diagonal_vignette(im, size)
    draw = ImageDraw.Draw(im, "RGBA")

    m = int(size * 0.09)
    r_out = int(size * 0.20)
    _round_rect(draw, (m, m, size - m, size - m), r_out, fill=None, outline=(255, 255, 255, 38), width=max(1, size // 90))

    m2 = m + int(size * 0.04)
    r_in = int(size * 0.16)
    _round_rect(draw, (m2, m2, size - m2, size - m2), r_in, fill=(*C_CARD, 255))

    hi_h = max(1, size // 40)
    try:
        draw.rounded_rectangle(
            (m2 + 2, m2 + 2, size - m2 - 2, m2 + 2 + hi_h),
            radius=max(1, r_in // 3),
            fill=(255, 255, 255, 20),
        )
    except Exception:
        pass

    stroke = max(4, int(size * 0.12))
    pad = int(size * 0.25)
    _draw_l_monogram(draw, size, stroke, pad)
    return im


def _lanczos(ip: "Image.Image", size: int) -> "Image.Image":
    from PIL import Image

    r = Image.Resampling.LANCZOS if hasattr(Image, "Resampling") else Image.LANCZOS
    return ip.resize((size, size), r)


def _draw_with_pil(out_dir: str) -> bool:
    try:
        from PIL import Image
    except ImportError:
        return False

    master = _render_master()
    for name, size in SIZES.items():
        if size == _MASTER_PX:
            out_im = master
        else:
            out_im = _lanczos(master, size)
        out = os.path.join(out_dir, name)
        out_im.save(out, "PNG", optimize=True)
        print(f"  wrote {out} ({size}x{size})")
    return True


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: generate_icon.py <output_dir>", file=sys.stderr)
        return 2
    out_dir = sys.argv[1]
    os.makedirs(out_dir, exist_ok=True)

    if _draw_with_pil(out_dir):
        return 0

    print("  (PIL not found — install: pip install pillow  or  apt install python3-pil)", file=sys.stderr)
    r, g, b = 32, 18, 58
    for name, size in SIZES.items():
        path = os.path.join(out_dir, name)
        _write_png_solid_rgba(path, size, size, r, g, b, 255)
        print(f"  wrote {path} ({size}x{size}) [fallback]")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
