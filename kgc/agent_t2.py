"""阶段三 · KG 增强的威胁情报问答 Agent（题目二）。

每一跳都留痕，链路固定为：

    link       问题 -> 图谱节点：官方编号、名称、别名三者都认，最长匹配优先
    retrieve   seed 邻域 + seed 两两最短路径；排除 Document 超级枢纽
    generate   只把检索到的三元组交给 LLM，prompt 明确禁止图谱外知识
    verify     句级核验：句中每个官方编号必须落在某条检索三元组上，引用编号必须有效
    provenance 句子 -> 三元组 -> 文档 -> 来源/许可证（三级溯源）

另外跑一个 **无图谱基线**（同一模型、同一问题、不给三元组），用同一套句级核验
打分。两次结果的差值就是"KG 到底减少了多少不可溯源陈述"的直接证据，而不是只
声明"我们用了 RAG 所以更可信"。

用法：
    python -m kgc.agent_t2 --topic t2-cve-attack ask "CVE-2021-44228 对应哪些 CWE 弱点？"
    python -m kgc.agent_t2 --topic t2-cve-attack bench
"""
from __future__ import annotations

import json
import re
from collections import deque
from itertools import combinations
from typing import Dict, List, Optional, Tuple

import yaml

from . import agent_tools as KT
from . import ids as I
from . import llm_t2
from . import schema as S

REFUSAL = "图谱中无此知识，无法回答。"
REFUSAL_RX = re.compile(r"图谱中无此知识|无法回答|无法确定|没有(?:相关)?(?:信息|记录|数据)"
                        r"|不知道|不存在(?:已知)?漏洞|无已知漏洞|没有已知")
# 对"检索结果本身"的陈述（"图谱未给出更具体的版本"）不是领域事实，不计入幻觉；
# 但它也确实没有三元组支撑，所以单列为 meta，不混进 supported 里充数。
AFFIRM_RX = re.compile(r"^(?:是|否|对|不对|可以|不可以|不是)[。！？!?]?$")
META_RX = re.compile(r"图谱(?:中|里)?(?:未|没有|无|只|仅)|未(?:给出|提供|进一步)"
                     r"|无法(?:判断|确定|区分)"
                     r"|置信度|三元组|检索结果|来源包含|该关系|这[一二三四五六七八九十\d]+条\S*关系")
CITE_RX = re.compile(r"\[(\d{1,2})\]")
CITE_ONLY_RX = re.compile(r"^[\s\[\]\d,，、;；.。]+$")
SENT_RX = re.compile(r"(?<=[。！？!?；;])\s*|\n+")
# 融合层为 KEV 记录生成的派生标签（见 topic.yaml fusion.label_templates）
KEV_LABEL_RX = re.compile(r"^KEV entry for (CVE-\d{4}-\d{4,7})$")
WORD_RX = re.compile(r"[A-Za-z][A-Za-z0-9_.\-]{2,}")

SYS_QA = ("你是网络安全威胁情报知识图谱问答助手。你只能依据用户给出的三元组回答，"
          "不得使用任何外部知识，不得编造编号、版本号、数值或结论。")

PROMPT_QA = """【问题】
{question}

【知识图谱检索结果】共 {n} 条三元组（格式：[编号] 头实体 --关系--> 尾实体）
{context}

【回答要求】
1. 只使用上面的三元组，不要补充图谱外的常识，也不要猜测。
2. 用中文回答，2~4 句，直接给结论。
3. 每个结论后用 [编号] 标注依据的三元组，可同时标多个，例如 [1][3]。
4. 如果三元组不足以回答问题（缺少所需信息），只输出这一句：
   {refusal}
5. 不要编造任何编号；不要输出图谱中没有的 CVE/CWE/CPE/ATT&CK 编号。
"""

PROMPT_BASE = """【问题】
{question}

请直接回答。如果不知道或不确定，回答"不知道"。不要解释你的推理过程。
"""


# --------------------------------------------------------------------------- #
# 文本工具
# --------------------------------------------------------------------------- #
def _wordish(ch: str) -> bool:
    """ASCII 标识符字符。中文不算，避免 "使用PowerShell" 因左侧汉字而匹配失败。"""
    return bool(ch) and (ch.isascii() and (ch.isalnum() or ch in "._-"))


def _find_surface(text: str, surf: str) -> List[Tuple[int, int]]:
    """大小写不敏感地找 surf，并要求两侧不是 ASCII 标识符字符（避免 T1059 命中 T1059.001）。"""
    if not surf:
        return []
    hay, needle = text.lower(), surf.lower()
    spans, start = [], 0
    while True:
        i = hay.find(needle, start)
        if i < 0:
            break
        e = i + len(needle)
        before = hay[i - 1] if i else ""
        after = hay[e] if e < len(hay) else ""
        if not _wordish(before) and not _wordish(after):
            spans.append((i, e))
        start = i + 1
    return spans


_TRAIL_CITE = re.compile(r"([。！？!?；;])((?:\[\d{1,2}\])+)")


def _sentences(text: str) -> List[str]:
    """切句，并把紧跟句末标点的引用（"。[1]"）归到**前一句**。

    LLM 常把引用写在句号之后；先切句会把 [1] 算到下一句开头，导致引用与陈述错位。
    """
    t = _TRAIL_CITE.sub(lambda m: m.group(2) + m.group(1), text or "")
    out: List[str] = []
    for s in SENT_RX.split(t):
        s = s.strip()
        if not s:
            continue
        # 换行后的 "）" 之类纯标点片段不是独立断言，并回上一句，
        # 否则会被当成"无引用、无编号"的不可溯源句。
        if out and not re.search(r"[0-9A-Za-z一-鿿]", s):
            out[-1] += s
        else:
            out.append(s)
    return out


def _is_refusal(text: str) -> bool:
    return bool(REFUSAL_RX.search(text or ""))


# --------------------------------------------------------------------------- #
# 1) 实体链接
# --------------------------------------------------------------------------- #
def surfaces(v: KT.KGView) -> List[Tuple[str, str]]:
    """(表面形式, 节点 id)。标签、官方 id、别名全部参与；Document 节点不参与。"""
    out: List[Tuple[str, str]] = []
    for nid, n in v.nodes.items():
        if n["type"] == "Document":
            continue
        names = {S.norm_label(n["label"]), nid}
        names |= {S.norm_label(a) for a in (n.get("properties") or {}).get("aliases") or []}
        for s in names:
            s = S.norm_label(str(s))
            if len(s) >= 2 and S.is_valid_label(s):
                out.append((s, nid))
    return out


def link(v: KT.KGView, question: str, max_seeds: int = 6) -> List[str]:
    """最长匹配 + 占位去重：先认长编号（T1059.001），再认短名称，避免子串误连。"""
    q = S.norm_label(question)
    occupied = [False] * len(q)
    hits: List[Tuple[int, int, str]] = []
    for surf, nid in sorted(surfaces(v), key=lambda x: -len(x[0])):
        for s, e in _find_surface(q, surf):
            if any(occupied[s:e]):
                continue
            occupied[s:e] = [True] * (e - s)
            hits.append((s, e, nid))
    hits.sort(key=lambda x: x[0])
    seeds: List[str] = []
    for _, _, nid in hits:
        if nid not in seeds:
            seeds.append(nid)
        if len(seeds) >= max_seeds:
            break
    return seeds


# --------------------------------------------------------------------------- #
# 2) 检索
# --------------------------------------------------------------------------- #
def _endpoint_ok(v: KT.KGView, nid: str) -> bool:
    return v.nodes.get(nid, {}).get("type") != "Document"


def _incident(v: KT.KGView, nid: str) -> List[dict]:
    edges = [e for e in v.out.get(nid, []) if e["relation"] != "mentioned_in"]
    edges += [e for e in v.inc.get(nid, []) if e["relation"] != "mentioned_in"]
    edges = [e for e in edges
             if _endpoint_ok(v, e["source"]) and _endpoint_ok(v, e["target"])]
    edges.sort(key=lambda e: (-float(e.get("confidence") or 0), e["relation"]))
    return edges


def _bfs(v: KT.KGView, a: str, b: str, max_hops: int = 4) -> List[dict]:
    """无向最短路径（边上带原始方向）。排除 Document，否则任何两点都能 2 跳连通。"""
    if a == b:
        return []
    q = deque([(a, [])])
    seen = {a}
    while q:
        cur, path = q.popleft()
        if len(path) >= max_hops:
            continue
        for e in _incident(v, cur):
            nxt = e["target"] if e["source"] == cur else e["source"]
            if nxt in seen:
                continue
            seen.add(nxt)
            npath = path + [e]
            if nxt == b:
                return npath
            q.append((nxt, npath))
    return []


def _key(e: dict) -> Tuple[str, str, str]:
    return e["source"], e["relation"], e["target"]


def retrieve(v: KT.KGView, question: str, per_seed: int = 60,
             limit: int = 80) -> Tuple[List[dict], List[str]]:
    seeds = link(v, question)
    if not seeds:
        return [], []

    # (边, 优先级)：路径边 3 > 连接两个 seed 的边 2.5 > seed 直接边 2 > 候选集内边 1
    ranked: Dict[Tuple[str, str, str], Tuple[dict, float]] = {}

    def add(e: dict, prio: float) -> None:
        k = _key(e)
        if k not in ranked or ranked[k][1] < prio:
            ranked[k] = (e, prio)

    seedset = set(seeds)
    cand = set(seeds)
    for s in seeds:
        for e in _incident(v, s)[:per_seed]:
            other = e["target"] if e["source"] == s else e["source"]
            cand.add(other)
            add(e, 2.5 if other in seedset else 2.0)

    for a, b in combinations(seeds, 2):
        for e in _bfs(v, a, b):
            cand.add(e["source"])
            cand.add(e["target"])
            add(e, 3.0)

    for e in v.kg["edges"]:
        if e["relation"] == "mentioned_in":
            continue
        if e["source"] in cand and e["target"] in cand:
            add(e, 1.0)

    ordered = sorted(ranked.values(),
                     key=lambda x: (-x[1], -float(x[0].get("confidence") or 0),
                                    x[0]["relation"], x[0]["source"], x[0]["target"]))
    rows = [_row(v, e, prio) for e, prio in ordered[:limit]]
    return rows, seeds


def _row(v: KT.KGView, e: dict, prio: float) -> dict:
    def lab(nid: str) -> str:
        return v.nodes.get(nid, {}).get("label", nid)

    return {
        "from_id": e["source"], "from_label": lab(e["source"]),
        "relation": e["relation"],
        "to_id": e["target"], "to_label": lab(e["target"]),
        "doc": e.get("doc", ""), "evidence": (e.get("evidence") or "")[:220],
        "confidence": e.get("confidence"),
        "methods": e.get("methods") or [],
        "priority": prio,
    }


# --------------------------------------------------------------------------- #
# 3) 生成
# --------------------------------------------------------------------------- #
def render(rows: List[dict], evidence_chars: int = 90) -> str:
    lines = []
    for i, r in enumerate(rows, 1):
        ev = S.norm_label(r["evidence"])
        if len(ev) > evidence_chars:
            ev = ev[:evidence_chars] + "…"
        lines.append(f"[{i}] {r['from_label']} --{r['relation']}--> {r['to_label']}"
                     f" ｜ 来源 {r['doc'] or '-'} ｜ 置信度 {r['confidence']}"
                     + (f" ｜ 证据：{ev}" if ev else ""))
    return "\n".join(lines)


def answer_with_kg(question: str, rows: List[dict]) -> Tuple[str, dict]:
    prompt = PROMPT_QA.format(question=question, n=len(rows),
                              context=render(rows), refusal=REFUSAL)
    return llm_t2.call_llm(prompt, system=SYS_QA)


def answer_without_kg(question: str) -> Tuple[str, dict]:
    return llm_t2.call_llm(PROMPT_BASE.format(question=question),
                           system="你是网络安全威胁情报分析助手。")


# --------------------------------------------------------------------------- #
# 4) 句级核验 + 三级溯源
# --------------------------------------------------------------------------- #
def _load_sources(topic: str) -> Tuple[Dict[str, dict], str]:
    p = S.topic_dir(topic) / "sources.yaml"
    if not p.exists():
        return {}, ""
    data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    doc2src: Dict[str, dict] = {}
    for src in (data.get("sources") or {}).values():
        for d in src.get("docs") or []:
            doc2src[str(d)] = src
    return doc2src, str(data.get("retrieved") or "")


def _mention(text: str, label: str, v: KT.KGView) -> bool:
    lab = S.norm_label(label)
    if _find_surface(text, lab):
        return True
    # KEV 记录的标签是派生出来的（"KEV entry for CVE-x"），正文里不会原样出现。
    # 只要答案同时写了 KEV 与所属 CVE 编号，就认为答出了这条记录。
    m = KEV_LABEL_RX.match(lab)
    if m and _find_surface(text, "KEV") and _find_surface(text, m.group(1)):
        return True
    # CPE 长串在自然语言答案里常被截断到版本段（"cpe:2.3:a:fortinet:fortiproxy:2.0.0"）。
    # 只要 part:vendor:product:version 这一段出现，就认为答出了该产品版本。
    if lab.lower().startswith("cpe:2.3:"):
        prefix = ":".join(lab.split(":")[:6])
        if _find_surface(text, prefix):
            return True
        # 自然语言答案通常写 "FortiProxy 2.0.0" 而不是整条 CPE；按
        # vendor:product:version 三个可读字段判断（通配版本只要求 product）。
        parts = lab.split(":")
        if len(parts) >= 6:
            product, version = parts[4], parts[5]
            if product and _find_surface(text, product):
                if version in ("*", "-", ""):
                    return True
                if _find_surface(text, version):
                    return True
    for nid, n in v.nodes.items():
        if S.norm_label(n["label"]).lower() != lab.lower():
            continue
        for a in (n.get("properties") or {}).get("aliases") or []:
            if len(a) >= 3 and _find_surface(text, S.norm_label(a)):
                return True
    return False


def verify(text: str, rows: List[dict], resolver: I.IdResolver,
           v: KT.KGView, doc2src: Dict[str, dict]) -> dict:
    """逐句核验。判据只有两条，便于答辩时复现：

      A. 句中出现官方编号 -> 每个编号都必须是某条检索三元组的端点；
      B. 句尾引用 [n] -> n 必须在 1..N；没有引用的句子必须至少锚定一个编号。

    只有同时满足的句子才算"可溯源"。这样做会低估流畅但没标注的句子——这是
    有意为之：宁可把"无法核验"算成不可溯源，也不把没证据的话算成正确。
    """
    known = {}
    for r in rows:
        known[S.norm_label(r["from_label"]).lower()] = r
        known[S.norm_label(r["to_label"]).lower()] = r

    sents, prov = [], []
    context = ""  # 已出现的陈述句，用于解析"该漏洞/该规则"这类跨句回指
    for s in _sentences(text):
        cites = [int(x) for x in CITE_RX.findall(s)]
        cites_ok = [n for n in cites if 1 <= n <= len(rows)]
        bad_cites = [n for n in cites if not (1 <= n <= len(rows))]
        found = resolver.find_all(s)
        ids = [{"type": t, "id": surf, "grounded": surf.lower() in known}
               for t, surf, _, _ in found]
        refused = _is_refusal(s) and not ids
        if refused:
            sents.append({"sentence": s, "supported": True, "refusal": True,
                          "meta": False, "ids": [], "citations": [], "triples": []})
            continue
        if not ids and CITE_ONLY_RX.match(s):
            # 单独一行的 "[1][2][3]" 只是引用列表，不构成领域陈述，不计入分母
            sents.append({"sentence": s, "supported": True, "refusal": False,
                          "meta": True, "ids": [], "citations": [], "triples": []})
            continue
        if not ids and AFFIRM_RX.match(s.strip()):
            # "是。/否。" 只是对问句的肯定/否定，不是独立的领域断言；
            # 真正的依据由后续句子给出，单列 meta，避免误计为幻觉。
            sents.append({"sentence": s, "supported": True, "refusal": False,
                          "meta": True, "ids": [], "citations": [], "triples": []})
            continue
        if not ids and META_RX.search(s):
            # 对检索结果覆盖面的陈述，不是领域结论；单独计数，既不判幻觉也不计为证据
            sents.append({"sentence": s, "supported": True, "refusal": False,
                          "meta": True, "ids": [], "citations": [], "triples": []})
            continue

        def _relevant(row: dict) -> bool:
            """引用必须与句子（或上一句，处理回指）有实体重合，防止"随便挂一个 [n]"。"""
            if ids:
                want = {i["id"].lower() for i in ids if i["grounded"]}
                return any(w in (row["from_label"].lower(), row["to_label"].lower())
                           for w in want)
            if (_mention(s, row["from_label"], v) or _mention(s, row["to_label"], v)):
                return True
            # KEV 记录的标签是派生的；答案常用 "CISA KEV/KEV 条目" 指代，
            # 只要引用的是 known_exploited 且句中出现 KEV，就视为相关。
            if row.get("relation") == "known_exploited" and _find_surface(s, "KEV"):
                return True
            # 回指（"该漏洞…"）必须真的只是回指：句中出现的英文实体名要在被引三元组里
            toks = [t for t in WORD_RX.findall(s) if t.lower() not in ("cve", "cwe", "cpe")]
            blob = f"{row['from_label']} {row['to_label']} {row.get('evidence', '')}".lower()
            if any(t.lower() not in blob for t in toks):
                return False
            return (_mention(context, row["from_label"], v)
                    or _mention(context, row["to_label"], v))

        support: List[dict] = []
        if cites_ok:
            support = [rows[n - 1] for n in dict.fromkeys(cites_ok) if _relevant(rows[n - 1])]
        else:
            support = [r for r in rows
                       if any(i["grounded"] and
                              i["id"].lower() in (r["from_label"].lower(),
                                                  r["to_label"].lower())
                              for i in ids)]
        if ids:
            supported = (all(i["grounded"] for i in ids) and bool(support)
                         and not bad_cites)
        else:
            # 没有编号：必须有一条**与本句相关**的有效引用，否则无法验证
            supported = bool(support) and not bad_cites

        documents = []
        for r in support:
            src = doc2src.get(r["doc"], {})
            documents.append({"doc": r["doc"], "source": src.get("name", ""),
                              "license": src.get("license", "")})
        sents.append({"sentence": s, "supported": supported, "refusal": False,
                      "meta": False, "ids": ids, "citations": cites,
                      "bad_citations": bad_cites, "triples": support})
        prov.append({"sentence": s, "triples": support,
                     "documents": [d for d in documents if d["doc"]]})
        context = (context + " " + s).strip()

    checked = [s for s in sents if not s["refusal"] and not s.get("meta")]
    unsupported = [s for s in checked if not s["supported"]]
    ungrounded = [i["id"] for s in sents for i in s["ids"] if not i["grounded"]]
    return {
        "sentences": sents, "provenance": prov,
        "sentence_count": len(checked),
        "meta_count": sum(1 for s in sents if s.get("meta")),
        "supported_count": len(checked) - len(unsupported),
        "unsupported_count": len(unsupported),
        "hallucination_rate": round(len(unsupported) / max(1, len(checked)), 4),
        "ungrounded_ids": sorted(set(ungrounded)),
        "is_refusal": bool(checked) and all(s["refusal"] for s in checked) or (
            not checked and _is_refusal(text)),
    }


# --------------------------------------------------------------------------- #
# 5) 评测
# --------------------------------------------------------------------------- #
def _coverage(expect: List[list], rows: List[dict]) -> dict:
    if not expect:
        return {"total": 0, "hit": 0, "missing": []}
    got = {(r["from_label"], r["relation"], r["to_label"]) for r in rows}
    missing = [t for t in expect if tuple(t) not in got]
    return {"total": len(expect), "hit": len(expect) - len(missing), "missing": missing}


def _answer_coverage(expect: List[list], text: str, v: KT.KGView,
                     question: str = "") -> dict:
    """不看引用，只看答案里是否答出了期望的头、尾实体（编号或别名）。

    头实体若已在问题里出现（"Sigma 规则 <uuid> 检测哪些技术？"），答案用
    "该规则/该漏洞"回指是自然的，不要求再抄一遍编号；尾实体必须答出。
    """
    if not expect:
        return {"total": 0, "hit": 0, "missing": []}
    missing = [t for t in expect
               if not ((_mention(question, t[0], v) or _mention(text, t[0], v))
                       and _mention(text, t[2], v))]
    return {"total": len(expect), "hit": len(expect) - len(missing), "missing": missing}


def ask(topic: str, question: str, qtype: str = "single") -> dict:
    cfg = S.load_topic(topic)
    v = KT.view(topic)
    resolver = I.IdResolver.from_cfg(cfg)
    doc2src, retrieved = _load_sources(topic)
    rows, seeds = retrieve(v, question)
    if rows:
        text, usage = answer_with_kg(question, rows)
        answered_by = "kg"
    else:
        text, usage = REFUSAL, {"input_tokens": 0, "output_tokens": 0}
        answered_by = "retrieval_gate"
    ver = verify(text, rows, resolver, v, doc2src)
    base_text, base_usage = answer_without_kg(question)
    base_ver = verify(base_text, rows, resolver, v, doc2src)
    return {
        "topic": topic, "question": question, "type": qtype,
        "seeds": seeds, "retrieved_count": len(rows),
        "answer": text, "answered_by": answered_by, "usage": usage,
        "verification": ver,
        "baseline": {"answer": base_text, "usage": base_usage,
                     "verification": base_ver},
    }


def verify_answer(topic: str, question: str, text: str) -> dict:
    """核验**已有答案**，不调用 LLM：给定问题与答案，返回逐句溯源结果。

    用途：答辩时现场改一句答案、或把别人（或另一个 Agent）的回答贴进来，
    立刻看到哪一句没有图谱依据。Skill / MCP 接入时也可作为独立校验步骤。
    """
    cfg = S.load_topic(topic)
    v = KT.view(topic)
    resolver = I.IdResolver.from_cfg(cfg)
    doc2src, retrieved = _load_sources(topic)
    rows, seeds = retrieve(v, question)
    out = verify(text, rows, resolver, v, doc2src)
    return {"topic": topic, "question": question, "answer": text,
            "retrieved_count": len(rows), "retrieved_at": retrieved,
            "seeds": seeds, "verification": out}


def bench(topic: str, qa_file: str | None = None, with_baseline: bool = True,
          verbose: bool = True, reuse: bool = False,
          kg_file: str | None = None, out_name: str | None = None) -> dict:
    """kg_file/out_name 用于旁路对照（LLM 单方法图），默认跑融合图。"""
    cfg = S.load_topic(topic)
    v = KT.view(topic, kg_file=kg_file)
    resolver = I.IdResolver.from_cfg(cfg)
    doc2src, seen_at = _load_sources(topic)
    qpath = S.repo_root() / (qa_file or f"data/qa/{topic}_qa.jsonl")
    qa = S.read_jsonl(qpath)
    stem = out_name or f"{topic}_qa_bench"
    out_json = S.out_dir("reports", topic) / f"{stem}.json"
    prev: Dict[str, dict] = {}
    if reuse and out_json.exists():
        prev = {r["id"]: r for r in (S.read_json(out_json).get("results") or [])}

    out_rows, results = [], []
    for q in qa:
        rows, seeds = retrieve(v, q["question"])
        old = prev.get(q["id"]) or {}
        if old.get("answer") and old.get("retrieved_count") == len(rows):
            text = old["answer"]
            usage = old.get("usage") or {}
            answered_by = old.get("answered_by") or ("kg" if rows else "retrieval_gate")
        elif rows:
            text, usage = answer_with_kg(q["question"], rows)
            answered_by = "kg"
        else:
            text, usage = REFUSAL, {"input_tokens": 0, "output_tokens": 0}
            answered_by = "retrieval_gate"
        ver = verify(text, rows, resolver, v, doc2src)
        item = {
            "id": q["id"], "type": q["type"], "question": q["question"],
            "seeds": seeds, "retrieved_count": len(rows),
            "answer": text, "answered_by": answered_by, "usage": usage,
            "retrieval_coverage": _coverage(q.get("expect") or [], rows),
            "answer_coverage": _answer_coverage(q.get("expect") or [], text, v,
                                                q.get("question") or ""),
            "verification": ver,
        }
        if q["type"] == "refusal":
            item["refusal_correct"] = bool(ver["is_refusal"])
        if with_baseline:
            if old.get("baseline", {}).get("answer") and old.get("retrieved_count") == len(rows):
                btext = old["baseline"]["answer"]
                busage = old["baseline"].get("usage") or {}
            else:
                btext, busage = answer_without_kg(q["question"])
            bver = verify(btext, rows, resolver, v, doc2src)
            item["baseline"] = {
                "answer": btext, "usage": busage, "verification": bver,
                "answer_coverage": _answer_coverage(q.get("expect") or [], btext, v,
                                                    q.get("question") or ""),
            }
            if q["type"] == "refusal":
                item["baseline"]["refusal_correct"] = bool(bver["is_refusal"])
        results.append(item)
        out_rows.append({
            "id": q["id"], "type": q["type"], "question": q["question"],
            "seeds": seeds, "retrieved_count": len(rows),
            "answer": text, "provenance": ver["provenance"],
        })
        if verbose:
            print(f"[agent] {q['id']} 检索 {len(rows):3d} 条 · "
                  f"答案覆盖 {item['answer_coverage']['hit']}/{item['answer_coverage']['total']} · "
                  f"不可溯源句 {ver['unsupported_count']}/{ver['sentence_count']}")

    def agg(key: str) -> dict:
        vals = [r[key] for r in results if key in r]
        return {"correct": sum(1 for x in vals if x), "total": len(vals)} if vals else {}

    def sent_agg(prefix: str = "") -> dict:
        checked = supported = meta = 0
        fab = set()
        for r in results:
            ver = r["baseline"]["verification"] if prefix else r["verification"]
            checked += ver["sentence_count"]
            supported += ver["supported_count"]
            meta += ver.get("meta_count", 0)
            fab |= set(ver.get("ungrounded_ids") or [])
        return {"sentences": checked, "supported": supported, "meta": meta,
                "unsupported": checked - supported,
                "hallucination_rate": round((checked - supported) / max(1, checked), 4),
                "ungrounded_ids": sorted(fab)}

    ans_tot = sum(r["answer_coverage"]["total"] for r in results)
    ans_hit = sum(r["answer_coverage"]["hit"] for r in results)
    ret_tot = sum(r["retrieval_coverage"]["total"] for r in results)
    ret_hit = sum(r["retrieval_coverage"]["hit"] for r in results)
    kg_sent = sent_agg()
    base_sent = sent_agg("baseline") if with_baseline else {}

    summary = {
        "topic": topic, "questions": len(results), "sources_retrieved": seen_at,
        "retrieval_coverage": {"hit": ret_hit, "total": ret_tot,
                               "rate": round(ret_hit / max(1, ret_tot), 4)},
        "answer_coverage": {"hit": ans_hit, "total": ans_tot,
                            "rate": round(ans_hit / max(1, ans_tot), 4)},
        "refusal": agg("refusal_correct"),
        "kg_grounded": kg_sent,
        "baseline": base_sent,
    }
    if with_baseline and base_sent:
        b_hit = sum(r["baseline"]["answer_coverage"]["hit"] for r in results
                    if r.get("baseline"))
        b_tot = sum(r["baseline"]["answer_coverage"]["total"] for r in results
                    if r.get("baseline"))
        b_ref = [r["baseline"]["refusal_correct"] for r in results
                 if r.get("baseline") and "refusal_correct" in r["baseline"]]
        summary["baseline"]["answer_coverage"] = {
            "hit": b_hit, "total": b_tot, "rate": round(b_hit / max(1, b_tot), 4)}
        summary["baseline"]["refusal"] = {
            "correct": sum(1 for x in b_ref if x), "total": len(b_ref)}
        summary["hallucination_reduction"] = round(
            base_sent["hallucination_rate"] - kg_sent["hallucination_rate"], 4)

    payload = {"summary": summary, "results": results}
    S.write_json(out_json, payload)
    answers_name = f"{stem}_answers.jsonl" if out_name else f"{topic}_answers.jsonl"
    S.write_jsonl(S.out_dir("qa", topic) / answers_name, out_rows)
    md = S.out_dir("reports", topic) / f"{stem}.md"
    md.write_text(_markdown(summary, results), encoding="utf-8")
    if verbose:
        print(f"[agent] -> {out_json}")
        print(f"[agent] -> {md}")
    return payload


def _markdown(summary: dict, results: List[dict]) -> str:
    s = summary
    lines = [
        f"# {s['topic']} 阶段三问答评测", "",
        f"- 题目数：{s['questions']}；检索覆盖：{s['retrieval_coverage']['hit']}/"
        f"{s['retrieval_coverage']['total']}（{s['retrieval_coverage']['rate']:.1%}）；"
        f"答案实体覆盖：{s['answer_coverage']['hit']}/{s['answer_coverage']['total']}"
        f"（{s['answer_coverage']['rate']:.1%}）",
        f"- 拒答题：{s.get('refusal', {}).get('correct', 0)}/"
        f"{s.get('refusal', {}).get('total', 0)} 正确",
        f"- KG 接地：可溯源句 {s['kg_grounded']['supported']}/"
        f"{s['kg_grounded']['sentences']}，不可溯源率 "
        f"{s['kg_grounded']['hallucination_rate']:.2%}",
    ]
    if s.get("baseline"):
        b = s["baseline"]
        ac = b.get("answer_coverage") or {}
        rc = b.get("refusal") or {}
        lines.append(f"- 无图谱基线：可溯源句 {b['supported']}/{b['sentences']}，"
                     f"不可溯源率 {b['hallucination_rate']:.2%}；"
                     f"相对下降 {s.get('hallucination_reduction', 0):.2%}")
        lines.append(f"- 无图谱基线：答案实体覆盖 {ac.get('hit', 0)}/{ac.get('total', 0)}"
                     f"（{ac.get('rate', 0):.1%}）；拒答 {rc.get('correct', 0)}/"
                     f"{rc.get('total', 0)}")
    lines += ["", "| 题号 | 类型 | 检索 | 答案覆盖 | 引用 | 不可溯源句 | 拒答正确 |",
              "|---|---|---|---|---|---|---|"]
    for r in results:
        v = r["verification"]
        lines.append(
            f"| {r['id']} | {r['type']} | {r['retrieved_count']} | "
            f"{r['answer_coverage']['hit']}/{r['answer_coverage']['total']} | "
            f"{len(v.get('provenance') or [])} | {v['unsupported_count']}/"
            f"{v['sentence_count']} | "
            f"{r.get('refusal_correct', '-')} |")
    lines += ["", "## 题面与答案", ""]
    for r in results:
        lines.append(f"### {r['id']} · {r['question']}")
        lines.append(f"- 种子节点：{', '.join(r['seeds']) or '（无，检索门控直接拒答）'}")
        lines.append(f"- 答案：{r['answer'].strip()}")
        if r.get("baseline"):
            lines.append(f"- 无图谱基线：{r['baseline']['answer'].strip()}")
        lines.append("")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def main() -> None:
    import argparse

    ap = argparse.ArgumentParser(description="阶段三：KG 增强问答 Agent")
    ap.add_argument("--topic", required=True)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("ask"); p.add_argument("question"); p.add_argument("--type", default="single")
    p = sub.add_parser("bench")
    p.add_argument("--qa", default=None)
    p.add_argument("--no-baseline", action="store_true")
    p.add_argument("--kg-file", default=None, help="旁路图谱 JSON（默认融合图）")
    p.add_argument("--out-name", default=None, help="报告文件名（不含扩展名）")
    p.add_argument("--reuse", action="store_true",
                   help="复用上次答案，只重跑检索与核验（改判据时用，避免重新采样）")
    p = sub.add_parser("verify", help="核验已有答案（不调用 LLM）")
    p.add_argument("question")
    p.add_argument("--answer", default=None, help="答案文本")
    p.add_argument("--answer-file", default=None, help="从文件读答案（UTF-8）")
    a = ap.parse_args()

    if a.cmd == "ask":
        out = ask(a.topic, a.question, a.type)
        print(json.dumps(out, ensure_ascii=False, indent=2))
    elif a.cmd == "verify":
        if a.answer_file:
            from pathlib import Path
            text = Path(a.answer_file).read_text(encoding="utf-8")
        elif a.answer:
            text = a.answer
        else:
            raise SystemExit("[agent] verify 需要 --answer 或 --answer-file")
        print(json.dumps(verify_answer(a.topic, a.question, text),
                         ensure_ascii=False, indent=2))
    else:
        bench(a.topic, a.qa, not a.no_baseline, reuse=a.reuse,
              kg_file=a.kg_file, out_name=a.out_name)


if __name__ == "__main__":
    main()
