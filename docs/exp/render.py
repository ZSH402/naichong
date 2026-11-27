#!/usr/bin/env python3
"""把终端文本渲染成 PNG —— 黑底等宽，ASCII 用 DejaVuSansMono，CJK 用 NotoSansCJK。"""
import re
import sys
from PIL import Image, ImageDraw, ImageFont

MONO = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
MONO_B = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf"
CJK = "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc"

FS = 15
LH = 23
PAD = 22
TOP = 46

BG = (13, 17, 23)
FG = (216, 222, 228)
DIM = (110, 118, 129)
GREEN = (126, 231, 135)
RED = (255, 123, 114)
YELLOW = (240, 200, 105)
CYAN = (121, 192, 255)
BAR = (22, 27, 34)

mono = ImageFont.truetype(MONO, FS)
monob = ImageFont.truetype(MONO_B, FS)
cjk = ImageFont.truetype(CJK, FS, index=0)

ADV = mono.getlength("M")
CJKW = ADV * 1.9   # CJK 字形实际宽度，比 2*ADV 紧一点


def is_wide(ch):
    o = ord(ch)
    return (0x1100 <= o <= 0x115F or 0x2E80 <= o <= 0xA4CF or
            0xAC00 <= o <= 0xD7A3 or 0xF900 <= o <= 0xFAFF or
            0xFE30 <= o <= 0xFE6F or 0xFF00 <= o <= 0xFF60 or
            0xFFE0 <= o <= 0xFFE6 or 0x3000 <= o <= 0x303F)


def color_for(line, ch, x):
    s = line
    if s.startswith("$ ") or s.startswith("# "):
        return GREEN if x < 2 else FG
    if "status=confirmed" in s:
        return GREEN
    if "status=hypothesis" in s or "status=partial" in s:
        return YELLOW
    if "ok=false" in s:
        return RED
    if "残留" in s:
        m = re.search(r"残留[^:：]*[:：]\s*(\d+)", s)
        if m:
            return GREEN if m.group(1) == "0" else RED
    if '"signal":9' in s or '"oom_kill":1' in s:
        return RED
    if '"killed"' in s or '"oom_kill":0' in s:
        return GREEN
    if any(k in s for k in ("peak_mem_kb", "elapsed_ms")):
        return CYAN
    if s.startswith("===") or s.startswith("---"):
        return DIM
    if s.startswith("❯") or s.startswith(">"):
        return GREEN
    return FG


def render(lines, out, title="terminal"):
    # 计算宽度
    maxw = 0
    for ln in lines:
        w = 0
        for ch in ln:
            w += CJKW if is_wide(ch) else ADV
        maxw = max(maxw, w)
    W = int(maxw) + PAD * 2
    H = int(TOP + len(lines) * LH + PAD)
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)

    # 标题栏
    d.rectangle([0, 0, W, TOP - 8], fill=BAR)
    for i, c in enumerate([(255, 95, 86), (255, 189, 46), (39, 201, 63)]):
        d.ellipse([PAD + i * 22, 15, PAD + i * 22 + 13, 28], fill=c)
    tx = PAD + 82
    for ch in title:
        d.text((tx, 13), ch, font=(cjk if is_wide(ch) else mono), fill=DIM)
        tx += (CJKW if is_wide(ch) else ADV)

    y = TOP
    for ln in lines:
        x = PAD
        for ch in ln:
            f = cjk if is_wide(ch) else mono
            d.text((x, y), ch, font=f, fill=color_for(ln, ch, x - PAD))
            x += CJKW if is_wide(ch) else ADV
        y += LH
    img.save(out)
    print(f"{out}  {W}x{H}  {len(lines)} 行")


if __name__ == "__main__":
    src, out = sys.argv[1], sys.argv[2]
    title = sys.argv[3] if len(sys.argv) > 3 else "terminal"
    with open(src, encoding="utf-8") as f:
        lines = f.read().rstrip("\n").split("\n")
    render(lines, out, title)
