#!/usr/bin/env python3
"""学生材料评审器：一页纸（md）+ 图文介绍（html）+ 两份 PDF 的一致性/完整性/时效性检查。

    .venv/bin/python tools/check_student_materials.py
    .venv/bin/python tools/check_student_materials.py --verbose

检查分六类（分级：高 = 必改；中 = 应改；低 = 提示）：
  [数字] 与仓库实测数据不符（本体类/关系数、示意语料抽取数、评测 F1、图谱规模、QA 指标）
  [口径] 与已定稿方案（docs/作业方案.md）冲突（金标准条数、评分权重、热身分值、答辩形式、
         T5 扩展要求、T2 切片、提交方式）
  [结构] 每个选题卡缺必需要素（数据集 / 三阶段 / 验收点 / 坑 / **参考文献**）
  [链接] HTML 内相对链接指向不存在的文件；外链（不应有，必须离线可用）
  [时效] PDF 早于源文件（改了 md/html 却没重新导出 PDF）
  [残留] 旧口径文本（kgcourse-starter / 16 周 / 30–60 条 / 8 分钟答辩 / 不向学生开放答案）
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
MD = DOCS / "学生作业说明.md"
HTML = DOCS / "选题介绍.html"
PLAN = DOCS / "作业方案.md"
PDFS = {"onepager": DOCS / "学生作业说明.pdf", "topics": DOCS / "选题介绍.pdf"}

problems: list[tuple[str, str, str]] = []
notes: list[str] = []


def add(sev: str, kind: str, msg: str) -> None:
    problems.append((sev, kind, msg))


def load(p: Path) -> str:
    return p.read_text(encoding="utf-8") if p.exists() else ""


# --------------------------------------------------------------------------- #
# 仓库事实
# --------------------------------------------------------------------------- #
def facts() -> dict:
    out: dict = {"topics": {}}
    for t in sorted(p.name for p in (ROOT / "topics").iterdir() if p.is_dir()):
        seed = json.loads((ROOT / "topics" / t / "ontology.json").read_text(encoding="utf-8"))
        rule = ROOT / "data" / "extraction" / f"{t}_rule.json"
        r = json.loads(rule.read_text(encoding="utf-8")) if rule.exists() else {}
        out["topics"][t] = {"classes": len(seed["classes"]), "rels": len(seed["relations"]),
                            "fx_ent": r.get("entity_count"), "fx_rel": r.get("relation_count")}
    ev = ROOT / "data" / "reports" / "t5-protocol-rfc_eval.json"
    out["eval"] = {m: d["triple"]["f1"] for m, d in
                   json.loads(ev.read_text(encoding="utf-8"))["methods"].items()} if ev.exists() else {}
    kg = ROOT / "data" / "kg" / "t5-protocol-rfc_kg.json"
    out["kg"] = {"nodes": json.loads(kg.read_text(encoding="utf-8"))["node_count"]} if kg.exists() else {}
    qa = ROOT / "data" / "reports" / "t5-protocol-rfc_qa_bench.json"
    out["qa"] = json.loads(qa.read_text(encoding="utf-8")) if qa.exists() else {}
    return out


# --------------------------------------------------------------------------- #
# 1) 数字一致性
# --------------------------------------------------------------------------- #
def check_numbers(html: str, facts_: dict) -> None:
    # 每个选题卡内："脚手架自带：N 类 / M 关系" 与 "示意语料可抽 X 实体 / Y 关系"
    blocks = re.split(r'<section class="topic', html)[1:]
    seen: set[str] = set()
    for b in blocks:
        m_id = re.search(r"<code>(t\d-[a-z0-9\-]+)</code>", b)
        if not m_id:
            add("高", "结构", "有选题卡缺少题目 ID（<code>t…</code>）")
            continue
        tid = m_id.group(1)
        seen.add(tid)
        f = facts_["topics"].get(tid)
        if not f:
            add("高", "数字", f"{tid}: 仓库中不存在该选题")
            continue
        m = re.search(r"脚手架自带：(\d+)\s*类\s*/\s*(\d+)\s*关系", b)
        if m and (int(m.group(1)), int(m.group(2))) != (f["classes"], f["rels"]):
            add("高", "数字", f"{tid}: HTML 称 {m.group(1)} 类/{m.group(2)} 关系，"
                               f"实际 {f['classes']}/{f['rels']}")
        m = re.search(r"示意语料可抽\s*(\d+)\s*实体\s*/\s*(\d+)\s*关系", b)
        if m and f["fx_ent"] is not None and (int(m.group(1)), int(m.group(2))) != (f["fx_ent"], f["fx_rel"]):
            add("高", "数字", f"{tid}: HTML 称示意语料 {m.group(1)} 实体/{m.group(2)} 关系，"
                               f"实际 {f['fx_ent']}/{f['fx_rel']}")
    missing = set(facts_["topics"]) - seen
    if missing:
        add("高", "结构", f"以下选题在 HTML 中没有卡片：{sorted(missing)}")
    notes.append(f"[结构] HTML 选题卡 {len(seen)} 个，覆盖 {len(seen)}/{len(facts_['topics'])}")

    # 评测数字（条形图上标注的值）
    for label, key, expect in (("规则/词典", "rule", "0.182"), ("机器学习", "model", "0.044"),
                               ("LLM", "llm", "0.653"), ("融合", "ensemble", "0.146")):
        if f">{expect}" in html or expect not in html:
            actual = facts_["eval"].get(key)
            if actual is None or f"{actual:.3f}" != expect:
                add("高", "数字", f"HTML 中 {label} 三元组 F1 标为 {expect}，实测 {actual:.3f}")
    if facts_["kg"].get("nodes"):
        m = re.search(r"(\d+)\s*节点\s*/\s*(\d+)\s*边", html)
        if m and int(m.group(1)) != facts_["kg"]["nodes"]:
            add("高", "数字", f"HTML 称图谱 {m.group(1)} 节点，实测 {facts_['kg']['nodes']}")
    if facts_["qa"]:
        m = re.search(r"图谱可回答率</td><td>([\d.]+)</td>", html)
        if m and abs(float(m.group(1)) - facts_["qa"]["answerable_rate"]) > 1e-6:
            add("高", "数字", f"HTML 称可回答率 {m.group(1)}，实测 {facts_['qa']['answerable_rate']}")


# --------------------------------------------------------------------------- #
# 2) 与定稿方案的口径一致性
# --------------------------------------------------------------------------- #
def check_alignment(md: str, html: str, plan: str) -> None:
    both = md + html
    # 金标准条数
    if "20–30 条" not in both:
        add("高", "口径", "学生材料未写明金标准 20–30 条（4 周版口径）")
    for bad in ("30–60 条", "≥60 条金标准"):
        if bad in both:
            add("中", "残留", f"学生材料仍出现旧口径「{bad}」（应改为 20–30 条 / 新增 ≥20 条）")
    # 评分权重
    w_plan = {k: int(v) for k, v in re.findall(r"\| [^|\n]*?([\u4e00-\u9fffA-Za-z][^|\n]*?) \| (\d+) \|", plan)}
    m = re.search(r"本体质量\s*(\d+).*?答辩\s*\**\s*(\d+)", md, re.S)
    if m:
        seg = md[m.start():m.end()]
        nums = [int(x) for x in re.findall(r"(\d+)", seg)]
        if nums and sum(nums) != 100:
            add("高", "口径", f"一页纸评分分项 {nums} 合计 {sum(nums)} ≠ 100")
        notes.append(f"[口径] 一页纸评分分项合计 {sum(nums)}")
    else:
        add("中", "口径", "一页纸未给出评分分项合计（100 分）")
    # 热身分值 / 答辩形式 / T5 扩展 / T2 切片 / 提交方式
    for kw, why in (("5 分", "T5 公共热身计 5 分"),
                    ("讲代码", "答辩=演示+讲代码+提问"),
                    ("个人", "成果提交到个人 GitHub/Gitee"),
                    ("cve", "T2 取 cve 切片"),
                    ("kev", "T2 取 kev 切片")):
        if kw not in both:
            add("中", "口径", f"学生材料缺少口径关键词「{kw}」（{why}）")
    if "公共热身" in html and "实质扩展" not in html:
        add("高", "口径", "HTML 提到 T5 公共热身但未说明「可作正式选题须实质扩展」")
    # 与方案冲突的旧说法
    for bad in ("不向学生开放答案", "8 分钟答辩", "16 周", "kgcourse-starter"):
        if bad in both:
            add("高", "残留", f"学生材料出现与定稿方案冲突的旧表述「{bad}」")


# --------------------------------------------------------------------------- #
# 3) 每个选题卡的必需要素
# --------------------------------------------------------------------------- #
REQUIRED = {
    "数据集": ("数据集", "数据来源", "**数据**", "数据："),
    "阶段①本体构建": ("本体构建",),
    "阶段②三种方法": ("三种方法",),
    "阶段③Agent应用": ("Agent应用",),
    "验收点": ("验收点",),
    "坑": ("坑",),
    "参考文献": ("参考文献", "参考开源", "参考："),
    "代码入口": ("代码入口", "示例代码", "scripts/run_all.sh"),
}


def check_sections(html: str) -> None:
    blocks = re.split(r'<section class="topic', html)[1:]
    for raw in blocks:
        b = re.sub(r"\s+", "", re.sub(r"<svg.*?</svg>", "", raw, flags=re.S))
        b = re.sub(r"<[^>]+>", "", b)
        m_id = re.search(r"(t\d-[a-z0-9\-]+)", b)
        tid = m_id.group(1) if m_id else "?"
        for name, keys in REQUIRED.items():
            if not any(k in b for k in keys):
                add("高" if name in ("数据集", "验收点") or name.startswith("阶段") else "中",
                    "结构", f"{tid}: 选题卡缺少「{name}」")


# --------------------------------------------------------------------------- #
# 4) 链接与外链
# --------------------------------------------------------------------------- #
def check_links(html: str) -> None:
    hrefs = re.findall(r'href="([^"]+)"', html)
    srcs = re.findall(r'src="([^"]+)"', html)
    for u in hrefs + srcs:
        if re.match(r"^(https?:)?//", u):
            add("高", "链接", f"HTML 含外链 {u}（要求离线可用，不得依赖网络）")
            continue
        target = (DOCS / u).resolve()
        if not target.exists():
            add("高", "链接", f"HTML 链接指向不存在的文件：{u}")
    notes.append(f"[链接] HTML 超链接 {len(hrefs)} 个、资源 {len(srcs)} 个，均本地")


# --------------------------------------------------------------------------- #
# 5) PDF 时效性
# --------------------------------------------------------------------------- #
def check_pdf_freshness() -> None:
    for key, pdf in PDFS.items():
        if not pdf.exists():
            add("高", "时效", f"缺少 PDF：{pdf.name}（运行 tools/build_pdf.py）")
            continue
        src = [MD] if key == "onepager" else [HTML]
        newer = [s.name for s in src if s.exists() and s.stat().st_mtime > pdf.stat().st_mtime]
        if newer:
            add("高", "时效", f"{pdf.name} 早于源文件 {newer} —— 改了内容但没重新导出 PDF")
        notes.append(f"[时效] {pdf.name}: {pdf.stat().st_size//1024} KB")
    # 页数/页码声明
    html = load(HTML)
    m = re.search(r"选题介绍\.pdf</a>（A4，本页 (\d+) 页）", html)
    if m:
        notes.append(f"[时效] HTML 声明图文版 PDF {m.group(1)} 页（请与导出结果核对）")


def check_pdf_pages(html: str) -> None:
    try:
        from pypdf import PdfReader
    except Exception:
        notes.append("[时效] 未安装 pypdf，跳过页数核对")
        return
    real = {k: len(PdfReader(str(p)).pages) for k, p in PDFS.items() if p.exists()}
    claims = re.findall(r"本页 (\d+) 页|（(\d+) 页）", html)
    claimed = {int(a or b) for a, b in claims}
    if real.get("topics") and claimed and real["topics"] not in claimed:
        add("高", "时效", f"HTML 声明的页数 {sorted(claimed)} 与实际导出 {real['topics']} 页不一致")
    notes.append(f"[时效] 实际页数：一页纸 {real.get('onepager')} 页 / 图文版 {real.get('topics')} 页")


def check_page_marks() -> None:
    """每页都必须有「第 x / y 页」，且 x 连续、y 与总页数一致。"""
    import pymupdf
    for key, pdf in PDFS.items():
        if not pdf.exists():
            continue
        doc = pymupdf.open(str(pdf))
        n = doc.page_count
        missing = [i + 1 for i in range(n) if f"第 {i + 1} / {n} 页" not in doc[i].get_text()]
        doc.close()
        if missing:
            add("高", "版式", f"{pdf.name}: 缺页码的页 {missing}（应为「第 x / {n} 页）」")
        notes.append(f"[版式] {pdf.name}: {n} 页，页码 {n - len(missing)}/{n} 完整")


def check_difficulty(html: str, plan: str) -> None:
    want = {t: d for t, d in re.findall(r"\| (T[1-8]) \|[^|]*\|[^|]*\| (★[★☆]*)\s*\|", plan)}
    got = {}
    for b in re.split(r'<section class="topic', html)[1:]:
        tid = re.search(r"<code>(t\d-[a-z0-9\-]+)</code>", b)
        idx = re.search(r'<span class="idx">(T\d)</span>', b)
        st = re.search(r'<span class="stars">(★[★☆]*)</span>', b)
        if tid and idx and st:
            got[idx.group(1)] = st.group(1)
    for k, v in want.items():
        if k in got and got[k] != v:
            add("中", "数字", f"{k} 难度星级 HTML={got[k]} 与方案={v} 不一致")
    if len(got) != 8:
        add("高", "结构", f"只解析到 {len(got)} 个选题的难度星级")


def main() -> None:
    ap = argparse.ArgumentParser(description="学生材料评审器")
    ap.add_argument("--verbose", action="store_true")
    a = ap.parse_args()

    if not MD.exists() or not HTML.exists():
        sys.exit("缺少 学生作业说明.md 或 选题介绍.html")
    md, html, plan = load(MD), load(HTML), load(PLAN)
    f = facts()

    check_numbers(html, f)
    check_alignment(md, html, plan)
    check_sections(html)
    check_links(html)
    check_pdf_freshness()
    check_pdf_pages(html)
    check_difficulty(html, plan)
    check_page_marks()

    order = {"高": 0, "中": 1, "低": 2}
    problems.sort(key=lambda x: (order[x[0]], x[1]))
    print("== 学生材料评审 ==")
    if a.verbose:
        for n in notes:
            print("  ·", n)
    if not problems:
        print("\n未发现问题 ✅")
        sys.exit(0)
    print(f"\n共 {len(problems)} 项问题：")
    for sev, kind, msg in problems:
        print(f"  [{sev}] ({kind}) {msg}")
    sys.exit(1 if any(p[0] == "高" for p in problems) else 0)


if __name__ == "__main__":
    main()
