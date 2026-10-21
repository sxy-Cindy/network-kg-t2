#!/usr/bin/env python3
"""LLM 单方法图 vs 融合图：同一题库、同一验证器的幻觉率对照。

    .venv/Scripts/python.exe scripts/compare_single_vs_fusion.py --topic t2-cve-attack

背景：作业题目二验收点要求「幻觉率统计（LLM 单方法 vs 融合）」。主评测
（`kgc.agent_t2 bench`）跑的是融合图，并与无图谱基线对比；本脚本额外用
**方法 C 单独抽取的三元组**建一张旁路图，跑同一套 12 题，输出三列对照：

    LLM 单方法图 | 融合图 | 无图谱基线

旁路产物命名带 `_llm_single`，不会覆盖正式图谱与正式评测报告。
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from kgc import agent_t2, kg, schema as S  # noqa: E402


def _table(single: dict, fused: dict, base: dict) -> str:
    def pct(d: dict, key: str) -> str:
        v = (d or {}).get(key)
        if not isinstance(v, dict):
            return "—"
        return f"{v.get('hit', 0)}/{v.get('total', 0)}（{v.get('rate', 0) * 100:.2f}%）"

    def rate(d: dict) -> str:
        if not d:
            return "—"
        return f"{d.get('hallucination_rate', 0) * 100:.2f}%"

    s_kg, f_kg = single.get("kg_grounded", {}), fused.get("kg_grounded", {})
    return "\n".join([
        f"| 检索覆盖 | {pct(single, 'retrieval_coverage')} | {pct(fused, 'retrieval_coverage')} | — |",
        f"| 答案覆盖 | {pct(single, 'answer_coverage')} | {pct(fused, 'answer_coverage')} | "
        f"{pct(base, 'answer_coverage')} |",
        f"| 可溯源句 | {s_kg.get('supported', 0)}/{s_kg.get('sentences', 0)} | "
        f"{f_kg.get('supported', 0)}/{f_kg.get('sentences', 0)} | "
        f"{base.get('supported', 0)}/{base.get('sentences', 0)} |",
        f"| 不可溯源句 | {s_kg.get('unsupported', 0)} | {f_kg.get('unsupported', 0)} | "
        f"{base.get('unsupported', 0)} |",
        f"| 幻觉率 | {rate(s_kg)} | {rate(f_kg)} | {rate(base)} |",
    ])


def main() -> None:
    import argparse

    ap = argparse.ArgumentParser(description="LLM 单方法图 vs 融合图 幻觉率对照")
    ap.add_argument("--topic", default="t2-cve-attack")
    a = ap.parse_args()
    topic = a.topic

    print("[compare] 构建 LLM 单方法旁路图 ...")
    built = kg.build(topic, "llm", verbose=False, out_name=f"{topic}_kg_llm_single")
    llm_kg = built["json"]
    stats = built["stats"]
    print(f"[compare] LLM 图：{stats['node_count']} 节点 / {stats['edge_count']} 边")

    print("[compare] 在同一题库上跑 LLM 单方法图 ...")
    single = agent_t2.bench(topic, with_baseline=False,
                            out_name=f"{topic}_qa_bench_llm_single", verbose=True)
    s = single["summary"]

    fused_path = S.out_dir("reports", topic) / f"{topic}_qa_bench.json"
    if not fused_path.exists():
        raise SystemExit(f"缺少融合图评测 {fused_path}，先运行 kgc.agent_t2 bench")
    fused = S.read_json(fused_path)
    f = fused["summary"]
    base = f.get("baseline", {}) or {}
    fused_kg = S.read_json(S.out_dir("kg", topic) / f"{topic}_kg.json")

    out = {
        "topic": topic,
        "llm_single_graph": {"json": str(llm_kg),
                             "nodes": stats["node_count"], "edges": stats["edge_count"]},
        "fused_graph": {"nodes": fused_kg["node_count"], "edges": fused_kg["edge_count"]},
        "llm_single": s,
        "fused": f,
        "no_kg_baseline": base,
        "hallucination_reduction": round(
            s["kg_grounded"]["hallucination_rate"] - f["kg_grounded"]["hallucination_rate"], 4),
    }
    stem = f"{topic}_single_vs_fusion"
    S.write_json(S.out_dir("reports", topic) / f"{stem}.json", out)

    lines = [
        f"# {topic} 阶段三：LLM 单方法图 vs 融合图（幻觉率对照）",
        "",
        "> 同一 12 题题库、同一检索器、同一逐句验证器；唯一变量是图谱来源。",
        "> LLM 单方法图只用方法 C 的 985 条三元组建图；融合图用 1572 条融合三元组。",
        f"> LLM 单方法图：{stats['node_count']} 节点 / {stats['edge_count']} 边。",
        "",
        "| 指标 | LLM 单方法图 | 融合图 | 无图谱基线 |",
        "|---|---|---|---|",
        _table(s, f, base),
        "",
        "## 关键结论",
        "",
        f"- LLM 单方法图幻觉率 **{s['kg_grounded']['hallucination_rate'] * 100:.2f}%**"
        f"（{s['kg_grounded']['unsupported']}/{s['kg_grounded']['sentences']} 句不可溯源）；",
        f"- 融合图幻觉率 **{f['kg_grounded']['hallucination_rate'] * 100:.2f}%**"
        f"（{f['kg_grounded']['unsupported']}/{f['kg_grounded']['sentences']} 句不可溯源）；",
        f"- 融合相对 LLM 单方法，幻觉率"
        f"{'下降' if out['hallucination_reduction'] >= 0 else '上升'} "
        f"**{abs(out['hallucination_reduction']) * 100:.2f} 个百分点**"
        "（单方法 − 融合）。",
        "",
        "> 为何两列可能相同：验证器只核对“答案句是否被**当前图谱**的检索三元组支撑”。"
        "本题库涉及的事实两套图都能检索到，生成端因此没有写出无依据的编号，"
        "这是**地板效应**，不代表两图等价。两者的差异在规模与结构：LLM 单方法图"
        f"{stats['node_count']} 节点 / {stats['edge_count']} 边（含重复边），融合图"
        f"{fused_kg['node_count']} 节点 / {fused_kg['edge_count']} 边（去重后保留更多"
        "结构化关系）；若要拉开幻觉率差距，应加入只在某一路图谱中覆盖的问题"
        "（见报告局限）。",
        "",
        "## 口径",
        "",
        "- 单方法图缺少规则/结构化通道导入的 KEV、CPE、战术等边，检索上下文更少；"
        "若其答案覆盖更低或拒答更多，是图谱覆盖差异，不是生成能力差异。",
        "- 无图谱基线不检索图谱，验证器仍以融合图的三元组为参照，因此基线幻觉率"
        "衡量的是“模型记忆相对图谱的不可溯源率”。",
    ]
    md = S.out_dir("reports", topic) / f"{stem}.md"
    md.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"[compare] -> {md}")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
