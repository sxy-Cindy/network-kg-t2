"""阶段三：基于 KG 增强的应用（KG-grounded QA + 答案可验证）。

本模块给出"Agent 用图谱"的最小闭环，四步全部可测：

    ① 检索   retrieve(question)      —— 从问题抽关键词 → 查子图（带证据与置信度）
    ② 组上下文 build_context(...)    —— 只把**检索到的三元组**放进提示词（不塞全文）
    ③ 生成   answer(...)             —— 走 OpenAI 兼容接口，或用外部 Agent 产出的答案文件
    ④ 验证   verify(answer, triples) —— 逐句检查答案是否被三元组支撑，输出未支撑句

第 ④ 步是本作业与"随便接个 LLM"的分水岭：**没有验证的生成不算 KG 增强**。
验证器的做法是把答案切成断言句，逐句与三元组做词面覆盖匹配（实体+关系词是否都
出现在某条三元组里）；未支撑句即"疑似幻觉"，可直接算幻觉率。人工抽检时可逐条回看
证据片段，形成"答案 → 三元组 → 原文"三级溯源链。

    # 检索 + 组上下文（不需 LLM）
    python -m kgc.agent_app --topic t5-protocol-rfc retrieve --question "IPv6 首部有哪些字段？"
    # 完整闭环（有答案文件时不联网）
    python -m kgc.agent_app --topic t5-protocol-rfc verify \
        --question "IPv6 首部有哪些字段？" --answer-file data/qa/t5_answer_demo.md
    # 跑题库，统计图谱可回答率与幻觉检出率
    python -m kgc.agent_app --topic t5-protocol-rfc bench
"""

from __future__ import annotations

import json
import re
from typing import Dict, List

from . import agent_tools as KT
from . import schema as S

STOP = set("""的 了 是 有 哪些 什么 如何 怎么 为什么 请问 请 与 和 及 在 中 上 对 那 这 一个 是否
the a an of in on for to is are what which how why and or with that this do does""".split())


def keywords(question: str) -> List[str]:
    """极简关键词抽取：中英混合按标点/空白切分，去停用词与单字噪声。"""
    toks = re.split(r"[\s,，。？?、；;：:（）()\[\]「」“”\"'/]+", question)
    out = []
    for t in toks:
        t = t.strip()
        if not t or t.lower() in STOP or len(t) < 2:
            continue
        out.append(t)
    return out


def retrieve(topic: str, question: str, limit: int = 12) -> dict:
    """① 检索：关键词 → 实体 → 邻域三元组（按置信度排序）。"""
    v = KT.view(topic)
    kws = keywords(question)
    hit_nodes: List[dict] = []
    for kw in kws:
        r = v.search(kw, limit=5)
        hit_nodes.extend(r["hits"])
    seen, uniq = set(), []
    for h in hit_nodes:
        if h["id"] in seen:
            continue
        seen.add(h["id"])
        uniq.append(h)

    triples: Dict[tuple, dict] = {}
    for h in uniq[:6]:
        nb = v.neighbors(h["id"], depth=1, limit=30)
        for t in nb.get("triples", []):
            key = (t["from"], t["relation"], t["to"])
            triples.setdefault(key, t)
    rows = sorted(triples.values(), key=lambda t: -(t.get("confidence") or 0))
    return {"question": question, "keywords": kws,
            "matched_entities": uniq[:10], "triples": rows[:limit],
            "triple_count": len(rows)}


def build_context(ret: dict, with_evidence: bool = True) -> str:
    """② 组上下文：只放检索到的三元组，附来源文档与证据片段。"""
    lines = [f"问题：{ret['question']}", "", "【知识图谱检索结果】"]
    if not ret["triples"]:
        lines.append("（图谱中未检索到相关三元组）")
    for i, t in enumerate(ret["triples"], 1):
        line = (f"{i}. {t['from']} --{t['relation']}--> {t['to']}"
                f"（来源: {t.get('doc') or '-'}；置信度: {t.get('confidence')}）")
        if with_evidence and t.get("evidence"):
            line += f"\n   证据: {t['evidence']}"
        lines.append(line)
    lines += ["", "【作答要求】",
              "1) 只能依据上面的三元组作答，不得引入图谱外的记忆；",
              "2) 每条结论后标注对应的三元组序号；",
              "3) 图谱未覆盖的部分，明确说「图谱中无此知识」。"]
    return "\n".join(lines)


REFUSAL_RX = re.compile(r"图谱中无此知识|无法回答|不在图谱|未收录")


def verify(answer: str, triples: List[dict], min_overlap: float = 0.5) -> dict:
    """④ 验证：逐句检查是否被三元组支撑，输出未支撑句（疑似幻觉）。"""
    # 图谱本来就没有检索结果时的正确拒答，不应被算成 100% 幻觉。
    if not triples and REFUSAL_RX.search(answer or ""):
        return {"sentences": 0, "supported": 0, "unsupported": 0,
                "hallucination_rate": 0.0, "refusal": True, "detail": []}
    facts = []
    for t in triples:
        facts.append({
            "text": f"{t['from']} {t['relation']} {t['to']}".lower(),
            "tokens": set(re.findall(r"[\w\u4e00-\u9fff]+",
                                     f"{t['from']} {t['relation']} {t['to']}".lower())),
            "raw": t,
        })
    sentences = [s for s in re.split(r"[。；\n]", re.sub(r"^[#>\-\*\d.\s]+", "", answer, flags=re.M))
                 if len(s.strip()) >= 6]
    checked, unsupported = [], []
    for s in sentences:
        toks = set(re.findall(r"[\w\u4e00-\u9fff]+", s.lower()))
        best, best_ratio = None, 0.0
        for f in facts:
            if not f["tokens"]:
                continue
            ratio = len(toks & f["tokens"]) / max(1, min(len(toks), len(f["tokens"])))
            if ratio > best_ratio:
                best, best_ratio = f, ratio
        rec = {"sentence": s.strip()[:160], "best_triple": (best["text"] if best else None),
               "overlap": round(best_ratio, 3), "supported": best_ratio >= min_overlap}
        (checked if rec["supported"] else unsupported).append(rec)
    total = len(checked) + len(unsupported)
    return {"sentences": total, "supported": len(checked), "unsupported": len(unsupported),
            "hallucination_rate": round(len(unsupported) / total, 4) if total else 0.0,
            "detail": checked + unsupported}


def run_verify(topic: str, question: str, answer: str, limit: int = 12) -> dict:
    ret = retrieve(topic, question, limit)
    v = verify(answer, ret["triples"])
    return {"topic": topic, "question": question,
            "retrieved_triples": ret["triple_count"],
            "matched_entities": [h["label"] for h in ret["matched_entities"]],
            "verification": v, "context_preview": build_context(ret)[:600]}


def bench(topic: str, qa_path: str | None = None) -> dict:
    """跑题库：统计图谱可回答率（期望三元组是否被检索到）与验证器表现。"""
    path = S.repo_root() / "data" / "qa" / f"{topic}_qa.jsonl"
    rows = S.read_jsonl(qa_path or path)
    out = []
    for r in rows:
        ret = retrieve(topic, r["question"])
        got = {(t["from"].lower(), t["relation"], t["to"].lower()) for t in ret["triples"]}
        want = {(h.lower(), rel, t.lower()) for h, rel, t in r.get("expect", [])}
        covered = len(got & want)
        rec = {"question": r["question"], "expect": len(want), "covered": covered,
               "coverage": round(covered / len(want), 3) if want else None,
               "retrieved": len(ret["triples"]),
               "answerable": bool(got & want) or not want}
        if r.get("answer"):
            rec["verification"] = {k: v for k, v in verify(r["answer"], ret["triples"]).items()
                                   if k != "detail"}
        out.append(rec)
    covs = [r["coverage"] for r in out if r["coverage"] is not None]
    summary = {"topic": topic, "questions": len(out),
               "answerable_rate": round(sum(1 for r in out if r["answerable"]) / len(out), 4) if out else 0,
               "mean_coverage": round(sum(covs) / len(covs), 4) if covs else None,
               "results": out}
    S.write_json(S.out_dir("reports", topic) / f"{topic}_qa_bench.json", summary)
    return summary


def main() -> None:
    import argparse

    ap = argparse.ArgumentParser(description="阶段三：KG 增强问答 + 答案验证")
    ap.add_argument("--topic", required=True)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("retrieve"); p.add_argument("--question", required=True)
    p = sub.add_parser("verify"); p.add_argument("--question", required=True)
    p.add_argument("--answer-file", required=True)
    sub.add_parser("bench")
    a = ap.parse_args()

    if a.cmd == "retrieve":
        ret = retrieve(a.topic, a.question)
        print(build_context(ret))
        print(f"\n[retrieve] 命中实体 {[h['label'] for h in ret['matched_entities']]} "
              f"· 三元组 {ret['triple_count']}")
    elif a.cmd == "verify":
        answer = (S.repo_root() / a.answer_file).read_text(encoding="utf-8") \
            if not a.answer_file.startswith("/") else __import__("pathlib").Path(a.answer_file).read_text(encoding="utf-8")
        res = run_verify(a.topic, a.question, answer)
        print(f"[verify] 检索到 {res['retrieved_triples']} 条三元组；"
              f"答案断言句 {res['verification']['sentences']} 句，"
              f"被支撑 {res['verification']['supported']} 句，"
              f"未支撑 {res['verification']['unsupported']} 句，"
              f"疑似幻觉率 {res['verification']['hallucination_rate']}")
        for d in res["verification"]["detail"]:
            flag = "OK  " if d["supported"] else "FLAW"
            print(f"  [{flag}] {d['sentence']}")
            print(f"         最匹配三元组: {d['best_triple']} (overlap={d['overlap']})")
    else:
        s = bench(a.topic)
        print(f"[bench] 题目 {s['questions']} · 可回答率 {s['answerable_rate']} "
              f"· 平均三元组覆盖率 {s['mean_coverage']}")
        for r in s["results"]:
            v = r.get("verification")
            extra = f" · 幻觉率 {v['hallucination_rate']}" if v else ""
            print(f"  - {r['question'][:34]:36s} 覆盖 {r['coverage']} 检索 {r['retrieved']}{extra}")


if __name__ == "__main__":
    main()
