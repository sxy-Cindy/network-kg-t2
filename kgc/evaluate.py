"""阶段二验收：三方法（+融合）质量评测。

评测口径（全部可复现，无人工干预）：
  1. **实体级** P/R/F1：以 (type, 归一化 label) 为单位，与 topics/<topic>/gold.jsonl 对比。
  2. **三元组级** P/R/F1：以 (头label, 关系, 尾label) 为单位对比（更严格，跨句子别名会失配）。
  3. **本体合规率**：抽取结果中类/关系落在本体内的比例（越界率 = 1 - 合规率）。
  4. **证据覆盖率**：关系条目中带 evidence 的比例（LLM 方法的幻觉代理指标）。
  5. **置信度分档**：融合结果按 1/2/3 票拆开算精度，用于回答
     "两法以上一致时精度有多高" —— 这是 KG 可信度工程的常见做法。

金标准文件格式（topics/<topic>/gold.jsonl，每行一条）：
    {"head": "TCP", "head_type": "Protocol", "relation": "operatesAt",
     "tail": "Transport Layer", "tail_type": "Layer", "doc": "rfc9293"}
    也支持只标实体：{"type":"Protocol","label":"TCP","doc":"rfc9293"}（relation 省略）

建议规模：每个选题 30–60 条（其中关系 ≥20），两人独立标注后交叉核对，Kappa ≥0.7。
"""

from __future__ import annotations

from typing import Dict, Iterable, List, Set, Tuple

from . import schema as S


def _norm(label: str) -> str:
    return S.norm_label(label).lower()


def gold_entities(gold: List[dict]) -> Set[Tuple[str, str]]:
    out = set()
    for g in gold:
        if g.get("type") and g.get("label"):
            out.add((g["type"], _norm(g["label"])))
        if g.get("head_type") and g.get("head"):
            out.add((g["head_type"], _norm(g["head"])))
        if g.get("tail_type") and g.get("tail"):
            out.add((g["tail_type"], _norm(g["tail"])))
    return out


def gold_triples(gold: List[dict]) -> Set[Tuple[str, str, str]]:
    return {( _norm(g["head"]), g["relation"], _norm(g["tail"]) )
            for g in gold if g.get("head") and g.get("relation") and g.get("tail")}


def pred_entities(payload: dict) -> Set[Tuple[str, str]]:
    return {(e["type"], _norm(e["label"])) for e in payload["entities"]}


def pred_triples(payload: dict) -> Set[Tuple[str, str, str]]:
    labels = {e["id"]: e["label"] for e in payload["entities"]}
    out = set()
    for r in payload["relations"]:
        h, t = r["source"], r["target"]
        if h.startswith("doc:") or t.startswith("doc:"):
            continue  # 结构关系不算预测质量
        out.add((_norm(labels.get(h, h)), r["relation"], _norm(labels.get(t, t))))
    return out


def prf(pred: Set, gold: Set) -> dict:
    tp = len(pred & gold)
    p = tp / len(pred) if pred else 0.0
    r = tp / len(gold) if gold else 0.0
    f = 2 * p * r / (p + r) if (p + r) else 0.0
    return {"tp": tp, "pred": len(pred), "gold": len(gold),
            "precision": round(p, 4), "recall": round(r, 4), "f1": round(f, 4),
            "missing_examples": sorted(list(gold - pred))[:5],
            "spurious_examples": sorted(list(pred - gold))[:5]}


def evaluate_method(cfg: dict, payload: dict) -> dict:
    g_ent, g_rel = gold_entities(cfg["gold"]), gold_triples(cfg["gold"])
    p_ent, p_rel = pred_entities(payload), pred_triples(payload)

    rels = payload["relations"]
    with_ev = sum(1 for r in rels if r.get("evidence"))
    unknown_types = payload.get("unknown_types", [])
    unknown_rels = payload.get("unknown_relations", [])
    n_ent_types = len({e["type"] for e in payload["entities"]}) or 1

    per_type: Dict[str, dict] = {}
    for etype in sorted({t for t, _ in p_ent}):
        sub_p = {x for x in p_ent if x[0] == etype}
        sub_g = {x for x in g_ent if x[0] == etype}
        per_type[etype] = prf(sub_p, sub_g)

    return {
        "method": payload.get("method", payload.get("source_method", "?")),
        "entity": prf(p_ent, g_ent),
        "triple": prf(p_rel, g_rel),
        "by_votes": by_votes(payload, g_rel),
        "entity_by_type": per_type,
        "counts": {"entities": len(payload["entities"]), "relations": len(rels)},
        "evidence_coverage": round(with_ev / len(rels), 4) if rels else 0.0,
        "ontology_compliance": round(1 - len(unknown_types) / n_ent_types, 4),
        "unknown_types": unknown_types,
        "unknown_relations": unknown_rels,
        "votes": payload.get("triple_vote_distribution"),
    }


def by_votes(payload: dict, g_rel: Set) -> dict:
    """按"命中方法数"分档评估：回答"几种方法一致时精度有多高"。

    这是把融合置信度**变成可信度**的关键实验：如果 2 票的精度显著高于 1 票，
    就可以给下游 Agent 设置 min_confidence 门槛（见 kgc.agent_tools.triples）。
    """
    labels = {e["id"]: e["label"] for e in payload["entities"]}
    buckets: Dict[int, Set] = {}
    for r in payload["relations"]:
        h, t = r["source"], r["target"]
        if h.startswith("doc:") or t.startswith("doc:"):
            continue
        v = int(r.get("properties", {}).get("votes") or 1)
        buckets.setdefault(v, set()).add((_norm(labels.get(h, h)), r["relation"],
                                          _norm(labels.get(t, t))))
    out = {}
    for v, preds in sorted(buckets.items()):
        out[str(v)] = prf(preds, g_rel)
    return out


def run(topic: str, methods: Iterable[str] = ("rule", "model", "llm", "ensemble"),
        out_name: str | None = None, verbose: bool = True) -> dict:
    """评测并落盘。

    out_name：报告文件名前缀，默认 `<topic>_eval`。**自检/单测必须传独立名字**
    （如 `<topic>_eval_test`），否则会用子集方法覆盖正式报告——这是实测踩过的坑：
    tests/test_pipeline.py 曾把 4 方法报告覆盖成 rule+ensemble 两方法。
    """
    cfg = S.load_topic(topic)
    if not cfg["gold"]:
        raise SystemExit(f"[eval] topics/{topic}/gold.jsonl 为空——没有金标准就没有验收")

    results: Dict[str, dict] = {}
    for m in methods:
        p = S.out_dir("extraction", topic) / f"{topic}_{m}.json"
        if not p.exists():
            continue
        results[m] = evaluate_method(cfg, S.read_json(p))

    report = {"topic": topic, "gold_size": {
        "entities": len(gold_entities(cfg["gold"])), "triples": len(gold_triples(cfg["gold"]))},
        "methods": results}
    name = out_name or f"{topic}_eval"
    S.write_json(S.out_dir("reports", topic) / f"{name}.json", report)

    md = _markdown(topic, report)
    (S.out_dir("reports", topic) / f"{name}.md").write_text(md, encoding="utf-8")
    if verbose:
        print(md)
    return report


def _markdown(topic: str, report: dict) -> str:
    lines = [f"# {topic} 抽取质量评测", "",
             f"金标准规模：实体 {report['gold_size']['entities']} · 三元组 {report['gold_size']['triples']}", ""]
    if topic == "t2-cve-attack":
        lines += [
            "> 口径说明：金标准由官方结构化字段**全量**构造（`scripts/build_gold.py`，不 import 任何抽取方法）。",
            "> 方法 A 的结构化通道读的是同一批字段，其高分反映**数据通道优势**，不应当作抽取能力；",
            "> B/C 只能从渲染文本里抽，三者对比才有意义。",
            "> 表中 precision 是**下界**：方法从正文抽出的、官方字段里没有的正确知识仍会被记为误报。",
        ]
    else:
        lines += [
            "> ⚠ 金标准是**抽样**（几十条量级），因此表中的 precision 是**下界**：",
            "> 方法抽出的正确但不在金标准里的知识会被记为误报。",
            "> 正式报告必须同时给出召回率，并说明 precision 的解读口径。",
        ]
    lines += ["",
             "| 方法 | 实体 P | 实体 R | 实体 F1 | 三元组 P | 三元组 R | 三元组 F1 | 越界类 | 证据覆盖率 |",
             "|---|---|---|---|---|---|---|---|---|"]
    for m, r in report["methods"].items():
        lines.append(
            f"| {m} | {r['entity']['precision']} | {r['entity']['recall']} | {r['entity']['f1']} "
            f"| {r['triple']['precision']} | {r['triple']['recall']} | {r['triple']['f1']} "
            f"| {len(r['unknown_types'])} | {r['evidence_coverage']} |"
        )
    lines += ["", "## 融合置信度分档（回答「几种方法一致时精度有多高」）", "",
              "| 命中方法数 | 三元组数 | 精确率(下界) | 召回 | F1 |", "|---|---|---|---|---|"]
    for m, r in report["methods"].items():
        for votes, s in (r.get("by_votes") or {}).items():
            lines.append(f"| {m} / {votes} 票 | {s['pred']} | {s['precision']} | {s['recall']} | {s['f1']} |")
    for m, r in report["methods"].items():
        lines += ["", f"## {m} — 分类型实体指标"]
        lines.append("| 类型 | P | R | F1 | 漏检示例 |")
        lines.append("|---|---|---|---|---|")
        for t, s in r["entity_by_type"].items():
            lines.append(f"| {t} | {s['precision']} | {s['recall']} | {s['f1']} | "
                         f"{', '.join(str(x[1]) for x in s['missing_examples'][:3])} |")
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="阶段二验收：三方法 + 融合质量评测")
    ap.add_argument("--topic", required=True)
    ap.add_argument("--methods", default="rule,model,llm,ensemble")
    a = ap.parse_args()
    run(a.topic, [m.strip() for m in a.methods.split(",") if m.strip()])
