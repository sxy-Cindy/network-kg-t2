#!/usr/bin/env python3
"""把学生材料导出为 PDF（可复现，不依赖手工打印对话框）。

    .venv/bin/python tools/build_pdf.py                # 导出两份 PDF 到 docs/
    .venv/bin/python tools/build_pdf.py --only onepager
    .venv/bin/python tools/build_pdf.py --font 9.0     # 调一页纸字号（默认 9.5pt）
    .venv/bin/python tools/build_pdf.py --no-header    # 不叠印页码页眉

实现：Markdown → HTML（自建打印样式，A4）→ Chrome headless `--print-to-pdf`。
本机实测：Google Chrome 155.0.8059.41；`markdown` 3.11.1。

页码页眉为什么是"导出后叠印"而不是让 Chrome 打：
    Chrome headless 的页眉页脚只有开关（`--no-pdf-header-footer`），内容固定为
    标题/URL/日期，不可定制；CSS Paged Media 的 `@page { @top-center { content: … } }`
    这类页边距盒子 Chrome 不支持，`counter(page)` 因此也用不上。
    所以做法是：CSS 里为页眉/页脚留出对称页边距，导出后用 PyMuPDF 往留白里叠印文字。
    好处是确定性（给定同一 PDF，叠印结果一致），且叠出来的文字**可选中、可检索**
    （实测 pymupdf 内置简体中文字体 `china-s`，抽取回读校验通过）。

产物：
    docs/学生作业说明.pdf   （一页纸，A4 纵向，默认 9.5pt 紧凑排版）
    docs/选题介绍.pdf       （图文版 8 选题，A4，按卡片与图表分页）
"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
BUILD = ROOT / "build" / "pdf"
CHROME_CANDIDATES = [
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
    "/usr/bin/google-chrome",
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
]

ONEPAGER_CSS = """
@page{size:A4 portrait;margin:13mm 9mm 9mm}
*{box-sizing:border-box}
body{margin:0;color:#0f172a;background:#fff;zoom:__ZOOM__;
  font:__FONT__pt/1.42 -apple-system,BlinkMacSystemFont,"PingFang SC","Hiragino Sans GB","Microsoft YaHei",sans-serif;}
h1{font-size:14.5pt;margin:0 0 1.6mm;padding-bottom:1mm;border-bottom:2px solid #0f172a}
h2{font-size:10pt;margin:2.1mm 0 1mm;padding-bottom:.5mm;border-bottom:1px solid #cbd5e1}
blockquote{margin:0 0 2mm;padding:1mm 2mm;background:#f1f5f9;border-left:3px solid #2563eb;
  font-size:8pt;color:#334155;border-radius:3px}
blockquote p{margin:0}
p{margin:0 0 1mm}
ul{margin:.5mm 0 .5mm 4.4mm;padding:0}
li{margin:0}
table{width:100%;border-collapse:collapse;margin:1mm 0;font-size:7.7pt}
th,td{border:1px solid #cbd5e1;padding:.55mm 1.1mm;text-align:left;vertical-align:top}
th{background:#f1f5f9;font-weight:600}
tr:nth-child(even) td{background:#fbfdff}
code{font-family:ui-monospace,Menlo,monospace;font-size:7.3pt;background:#f1f5f9;
  padding:0 .6mm;border-radius:2px}
pre{background:#0f172a;color:#e2e8f0;padding:1.3mm 2mm;border-radius:3px;margin:1mm 0;
  font-size:7.2pt;line-height:1.3;white-space:pre-wrap}
pre code{background:none;color:inherit;font-size:7.2pt}
hr{border:none;border-top:1px solid #e2e8f0;margin:1.4mm 0}
strong{font-weight:600}
a{color:#0f172a;text-decoration:none}
/* 末两节走双栏，把一页纸真正压进一页 */
.cols2{column-count:2;column-gap:5mm}
.cols2 h2{margin-top:1mm;break-after:avoid;page-break-after:avoid}
.cols2 table{font-size:7.3pt}
.cols2 ul{margin-left:3.8mm}
"""


def chrome_bin() -> str:
    for c in CHROME_CANDIDATES:
        if Path(c).exists() or shutil.which(c):
            return c if Path(c).exists() else shutil.which(c)  # type: ignore[return-value]
    sys.exit("未找到 Chrome/Chromium —— 请安装 Google Chrome，或改用浏览器手动打印为 PDF")


def md_to_html(md_path: Path, out_path: Path, font_pt: float, title: str,
               zoom: float = 0.90) -> Path:
    """Markdown → 打印用 HTML。

    zoom：Chrome 打印同样尊重 CSS zoom，用它把内容整体缩放，从而**确定性地**压到一页
    （实测：字号从 9.5pt 降到 8.0pt 都不改变页数，因为溢出只有 5.8%；改用 zoom 0.93 后
    一次到位）。可用浏览器量出所需 zoom：内容高度 px ÷ A4 可用高度 px（297−18mm → 1054px）。
    """
    import markdown

    html_body = markdown.markdown(
        md_path.read_text(encoding="utf-8"),
        extensions=["tables", "fenced_code", "attr_list", "sane_lists"],
    )
    # 前三节（说明/三件事/选题）用全宽表格排版；其后各节转双栏，把整份真正压进一页
    m = re.search(r"<h2>(四、)", html_body)
    if m:
        html_body = (html_body[:m.start()] + '<div class="cols2">'
                     + html_body[m.start():] + "</div>")
    css = ONEPAGER_CSS.replace("__FONT__", str(font_pt)).replace("__ZOOM__", str(zoom))
    out_path.write_text(
        f"""<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">
<title>{title}</title><style>{css}</style></head><body>{html_body}</body></html>""",
        encoding="utf-8",
    )
    return out_path


def print_to_pdf(src_html: Path, out_pdf: Path) -> Path:
    """Chrome headless 打印为 PDF。

    ⚠ 实测坑：Chrome 是**异步写文件**，若目标 PDF 已存在，进程返回后文件可能仍是上一版——
    直接读取会得到"改了参数但页数不变"的假象（本脚本曾因此在 8.0–9.5pt 之间反复得出
    "2 页"的结论）。因此这里先删除旧文件，并在返回后校验文件确实被重新写出。
    """
    out_pdf.parent.mkdir(parents=True, exist_ok=True)
    if out_pdf.exists():
        out_pdf.unlink()
    cmd = [
        chrome_bin(), "--headless=new", "--disable-gpu", "--no-sandbox",
        "--no-pdf-header-footer", "--virtual-time-budget=5000",
        f"--print-to-pdf={out_pdf}", src_html.as_uri(),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    if not out_pdf.exists() or out_pdf.stat().st_size < 1024:
        print(proc.stdout[-1500:]); print(proc.stderr[-1500:], file=sys.stderr)
        sys.exit(f"Chrome 未能生成 {out_pdf}")
    return out_pdf


def page_count(pdf: Path) -> int:
    """页数统计：优先用 PDF 页树 /Count，其次用 macOS Spotlight 元数据。

    注意：不要用 pypdf 文本抽取来核对内容完整性——Chrome 打印的 PDF 对 CJK 采用子集字体，
    抽取常丢字（实测），据此判断"缺内容"会误导。这里只统计页数。
    """
    data = pdf.read_bytes()
    counts = [int(x) for x in re.findall(rb"/Count\s+(\d+)", data)]
    if counts:
        return max(counts)
    try:
        out = subprocess.run(["mdls", "-name", "kMDItemNumberOfPages", str(pdf)],
                             capture_output=True, text=True).stdout
        m = re.search(r"=\s*(\d+)", out)
        if m:
            return int(m.group(1))
    except Exception:
        pass
    return len(re.findall(rb"/Type\s*/Page[^s]", data))


COURSE = "《知识图谱技术与应用》· 网络工程专业实践作业"
MM = 72 / 25.4
INK = (0.42, 0.45, 0.50)     # #6b7280 页眉页脚文字
RULE = (0.82, 0.85, 0.89)    # #d1d5db 分隔线


def stamp_page_marks(pdf: Path, *, material: str, header_band_mm: float,
                     skip_header_pages: tuple = ()) -> None:
    """往导出好的 PDF 留白里叠印页眉（课程名 + 材料名 + 第 x / y 页）与封面页脚。

    约定：Chrome 已把正文压到 `header_band_mm` 以下（与 CSS `@page` 的 top margin 一致），
    所以页眉只会落进留白，**结构上不可能压到正文**——比"目测不重叠"可靠。

    skip_header_pages：这些页不印页眉只印页脚（图文版第 1 页是深色 hero 区，
    页眉印在深色带上会看不清；页码因此不会缺席）。
    """
    import pymupdf as fitz

    doc = fitz.open(pdf)
    n = doc.page_count
    left = 9 * MM
    for i in range(n):
        page = doc[i]
        num, w, h = i + 1, page.rect.width, page.rect.height
        if num not in skip_header_pages:
            base = header_band_mm * MM - 13
            page.insert_text((left, base), COURSE, fontname="china-s",
                             fontsize=7.2, color=INK)
            right = f"{material} · 第 {num} / {n} 页"
            tw = fitz.get_text_length(right, fontname="china-s", fontsize=7.2)
            page.insert_text((w - left - tw, base), right, fontname="china-s",
                             fontsize=7.2, color=INK)
            page.draw_line(fitz.Point(left, base + 5), fitz.Point(w - left, base + 5),
                           color=RULE, width=0.6)
        else:
            base = h - 15
            page.insert_text((left, base), material, fontname="china-s",
                             fontsize=7.2, color=INK)
            right = f"第 {num} / {n} 页"
            tw = fitz.get_text_length(right, fontname="china-s", fontsize=7.2)
            page.insert_text((w - left - tw, base), right, fontname="china-s",
                             fontsize=7.2, color=INK)
            page.draw_line(fitz.Point(left, base - 9), fitz.Point(w - left, base - 9),
                           color=RULE, width=0.6)
    tmp = pdf.with_suffix(".stamped.pdf")
    doc.save(tmp)
    doc.close()
    tmp.replace(pdf)

    # 回读校验：页码必须真印上去，且页数不变（叠印只加内容、不改结构）
    chk = fitz.open(pdf)
    text = chk[n - 1].get_text()
    chk.close()
    if f"第 {n} / {n} 页" not in text or page_count(pdf) != n:
        sys.exit(f"页眉叠印校验失败：{pdf.name}（末页未找到「第 {n} / {n} 页」）")


def main() -> None:
    ap = argparse.ArgumentParser(description="导出学生材料 PDF")
    ap.add_argument("--only", choices=["onepager", "topics", "all"], default="all")
    ap.add_argument("--font", type=float, default=9.5, help="一页纸正文字号(pt)；实测 9.5 配 zoom 0.90 恰好一页")
    ap.add_argument("--zoom", type=float, default=0.90, help="一页纸整体缩放；有效字号≈font×zoom，实测 ≥8.55pt 会溢出到第 2 页")
    ap.add_argument("--no-header", action="store_true", help="不叠印页码页眉（纯内容版）")
    a = ap.parse_args()

    BUILD.mkdir(parents=True, exist_ok=True)
    results = []

    if a.only in ("onepager", "all"):
        src_md = DOCS / "学生作业说明.md"
        if not src_md.exists():
            sys.exit(f"缺少 {src_md}")
        html = md_to_html(src_md, BUILD / "学生作业说明.html", a.font, "学生作业说明", a.zoom)
        pdf = print_to_pdf(html, DOCS / "学生作业说明.pdf")
        if not a.no_header:
            stamp_page_marks(pdf, material="学生作业说明", header_band_mm=13)
        n = page_count(pdf)
        results.append(("学生作业说明.pdf", pdf, n, a.font))
        if n > 1:
            print(f"  ⚠ 一页纸当前 {n} 页（目标 1 页）——可用 --font {a.font - 0.5:.1f} 继续压缩",
                  file=sys.stderr)

    if a.only in ("topics", "all"):
        src_html = DOCS / "选题介绍.html"
        if not src_html.exists():
            sys.exit(f"缺少 {src_html}")
        pdf = print_to_pdf(src_html, DOCS / "选题介绍.pdf")
        if not a.no_header:
            stamp_page_marks(pdf, material="选题介绍 · 8 选题图文详解",
                             header_band_mm=15, skip_header_pages=(1,))
        results.append(("选题介绍.pdf", pdf, page_count(pdf), None))

    print("== 导出结果 ==")
    for name, pdf, n, font in results:
        extra = f" · 字号 {font}pt" if font else ""
        print(f"  {name}: {n} 页 · {pdf.stat().st_size/1024:.0f} KB{extra} · {pdf}")


if __name__ == "__main__":
    main()
