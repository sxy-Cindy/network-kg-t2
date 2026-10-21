#!/usr/bin/env python3
"""PDF 排版体检：真实渲染每页，量深色内容的填充率，找出"半页空白"页。

    .venv/bin/python tools/audit_pdf_layout.py                     # 默认查 docs/选题介绍.pdf
    .venv/bin/python tools/audit_pdf_layout.py --pdf docs/学生作业说明.pdf --min-fill 0.55

为什么不用"PDF 内容流字节数"判断：一页放大图/矢量图的流很小，一页纯文字的流很大，
用它当填充率会把图表页误判成空页（本工具开发时实测踩过：p2 内容流只有中位数的 30%，
实际是两张柱状图 + 一张表，真正的空白是别的原因）。渲染成位图再数行，才是页面真实占用。

判定口径：
  深色行  —— 一行里 <130 灰度的像素 ≥20 个（阈值和计数下限都是为了排除卡片左边框那种 3px 细线）
  填充率  —— (最后一个深色行 - 第一个深色行 + 1) / 页高
  偏空页  —— 填充率 < --min-fill（封面/末页/单节短页可能合法，报告中人工确认）
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import numpy as np
import pypdfium2 as pdfium

ROOT = Path(__file__).resolve().parents[1]


def audit(pdf_path: Path, min_fill: float, dpi_scale: float, side_margin: int) -> int:
    doc = pdfium.PdfDocument(str(pdf_path))
    print(f"== {pdf_path.name} · {len(doc)} 页 ==")
    print(f"{'页':>3} {'首行':>5} {'末行':>5} {'填充率':>7} {'底部空白':>8}")
    fills: list[float] = []
    for i in range(len(doc)):
        img = doc[i].render(scale=dpi_scale).to_pil().convert("L")
        a = np.asarray(img)
        h, w = a.shape
        m = max(1, int(w * side_margin / 100))
        core = a[:, m:w - m]
        rows = np.where((core < 130).sum(axis=1) >= 20)[0]
        if not len(rows):
            print(f"{i+1:>3}   空页")
            fills.append(0.0)
            continue
        fill = (rows[-1] - rows[0] + 1) / h
        fills.append(fill)
        print(f"{i+1:>3} {rows[0]:>5} {rows[-1]:>5} {fill:7.1%} {(h - rows[-1]) / h:8.1%}"
              + ("  ← 偏空" if fill < min_fill else ""))
    avg = sum(fills) / len(fills) if fills else 0
    low = [i + 1 for i, f in enumerate(fills) if f < min_fill]
    print(f"\n平均填充 {avg:.1%} · 偏空页 {low if low else '无'}")
    return 0


def main() -> None:
    ap = argparse.ArgumentParser(description="PDF 排版体检")
    ap.add_argument("--pdf", default=str(ROOT / "docs" / "选题介绍.pdf"))
    ap.add_argument("--min-fill", type=float, default=0.60)
    ap.add_argument("--scale", type=float, default=1.0)
    ap.add_argument("--side-margin", type=int, default=4, help="左右各忽略的百分比（排除边框细线）")
    a = ap.parse_args()
    p = Path(a.pdf)
    if not p.exists():
        sys.exit(f"找不到 {p}")
    sys.exit(audit(p, a.min_fill, a.scale, a.side_margin))


if __name__ == "__main__":
    main()
