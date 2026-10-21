"""阶段二 · 方法 A：规则 / 词典 / 模板驱动抽取（rule-based）。

适用性：语料有强结构信号时（RFC 条款编号、厂商配置块、日志模板、判决文书段落、
CVE 编号、AS 号、IP/掩码……）。优点是可解释、零标注、可复现；缺点是把领域知识
写死，跨语料迁移差。这是本作业的**基线**：任何模型/LLM 方案必须打败它才有意义。

配置来源：topics/<topic>/patterns.yaml + lexicons.yaml
    entity_patterns: 正则型实体（带捕获组，可生成 ID / label）
    lexicons:        词典型实体（type -> [surface, ...]）
    relations:       关系模板（触发词 + 句内共现，按距离取最近实体对）
    structural:      结构关系（每个实体 mention 一条 mentioned_in 指向文档）
"""

from __future__ import annotations

import re
from typing import Dict, Iterable, List, Tuple

from . import schema as S

_SENT_SPLIT = re.compile(r"(?<=[。！？.!?;；])\s+")


def split_sentences(text: str) -> List[Tuple[int, int, str]]:
    """返回 [(start, end, sentence)]。保留偏移以便回填证据。"""
    out: List[Tuple[int, int, str]] = []
    pos = 0
    for part in _SENT_SPLIT.split(text):
        if not part:
            pos += 1
            continue
        start = text.find(part, pos)
        end = start + len(part)
        out.append((start, end, part))
        pos = end
    return out


_BOUNDARY_LABEL = re.compile(r"[A-Za-z0-9 ._/+\-*:]+")


def find_mention(sent: str, label: str) -> int:
    """在句中定位实体标签，返回起始下标（找不到返回 -1）。

    不能直接用 ``label in sent``：ATT&CK 的子技术编号是父编号的前缀
    （T1059.001 里的 T1059 会命中），会把 subtechnique_of 的方向判反、也会造出假共现。
    这里对 ASCII 编号/短语加前后边界，中文等直接子串匹配。
    """
    lab = (label or "").strip()
    if not lab:
        return -1
    if _BOUNDARY_LABEL.fullmatch(lab):
        m = re.search(rf"(?<![A-Za-z0-9_.\-]){re.escape(lab)}(?![A-Za-z0-9_.\-])", sent,
                      re.IGNORECASE)
        return m.start() if m else -1
    return sent.lower().find(lab.lower())


def _flags(names: Iterable[str]) -> int:
    f = 0
    for n in names or []:
        f |= getattr(re, n.upper(), 0)
    return f


def _fmt(template: str, groups: List[str], doc_id: str, n: int) -> str:
    """把 {1}/{2}/... 替换为捕获组；{doc} 替换为文档 ID；{n} 为出现序号。"""
    ctx = {str(i + 1): g for i, g in enumerate(groups)}
    ctx.update({"doc": doc_id, "n": str(n)})
    return re.sub(r"\{(\w+)\}", lambda m: ctx.get(m.group(1), m.group(0)), template)


# --------------------------------------------------------------------------- #
# 实体
# --------------------------------------------------------------------------- #
def _entity_from_match(pat: dict, m: re.Match, doc: dict, counters: Dict[str, int]) -> S.Entity:
    groups = [g or "" for g in m.groups()]
    key = pat["type"]
    counters[key] = counters.get(key, 0) + 1
    eid = _fmt(pat.get("id_template", "{type}:" + "{1}"), groups, doc["doc_id"], counters[key])
    label = _fmt(pat.get("label_template", "{1}"), groups, doc["doc_id"], counters[key])
    label = S.norm_label(label)
    if not label:
        label = S.norm_label(m.group(0))
    return S.Entity(
        id=eid,
        label=label,
        type=key,
        doc=doc["doc_id"],
        evidence=S.snippet(doc["text"], m.start(), m.end()),
        method="rule",
        properties={"match": m.group(0)},
    )


def extract_entities(cfg: dict, docs: List[dict]) -> List[S.Entity]:
    pats = cfg.get("patterns", {}).get("entity_patterns", [])
    lexicons = cfg.get("lexicons", {})
    ents: List[S.Entity] = []
    counters: Dict[str, int] = {}

    for doc in docs:
        text = doc["text"]
        for pat in pats:
            rx = re.compile(pat["regex"], _flags(pat.get("flags", [])))
            for m in rx.finditer(text):
                ents.append(_entity_from_match(pat, m, doc, counters))
        for etype, surfaces in lexicons.items():
            for entry in surfaces:
                # 词典项可以是纯字符串，也可以是 {surface, id, label}：
                # 后者用于把**人类可读名称**归一到**官方 ID**（ATT&CK 的名称会改版，ID 不会）。
                if isinstance(entry, dict):
                    surface = entry.get("surface", "")
                    canon_id = entry.get("id")
                    canon_label = entry.get("label", surface)
                else:
                    surface, canon_id, canon_label = entry, None, entry
                if not surface:
                    continue
                # 英文术语用词边界；含中日韩等非 ASCII 的术语用直接子串匹配
                if re.fullmatch(r"[A-Za-z0-9 ._/+-]+", surface):
                    rx = re.compile(rf"(?<![A-Za-z0-9_]){re.escape(surface)}(?![A-Za-z0-9_])",
                                    re.IGNORECASE)
                else:
                    rx = re.compile(re.escape(surface))
                for m in rx.finditer(text):
                    counters[etype] = counters.get(etype, 0) + 1
                    ents.append(
                        S.Entity(
                            id=canon_id or S.make_id(etype, surface),
                            label=S.norm_label(canon_label or surface),
                            type=etype,
                            doc=doc["doc_id"],
                            evidence=S.snippet(text, m.start(), m.end()),
                            method="rule",
                            properties={"surface": surface, "canonical_id": bool(canon_id)},
                        )
                    )
    return _dedupe_entities(ents)


def _dedupe_entities(ents: List[S.Entity]) -> List[S.Entity]:
    seen: Dict[Tuple[str, str], S.Entity] = {}
    for e in ents:
        k = (e.id, e.doc)
        if k not in seen:
            seen[k] = e
    return list(seen.values())


# --------------------------------------------------------------------------- #
# 关系
# --------------------------------------------------------------------------- #
def extract_relations(cfg: dict, docs: List[dict], entities: List[S.Entity],
                      method: str = "rule") -> List[S.Relation]:
    rules = cfg.get("patterns", {}).get("relations", [])
    structural = cfg.get("patterns", {}).get("structural", {})
    # 默认邻近窗口：0 表示关闭（纯句内共现）。用 topic.yaml 的 fusion.max_gap 覆盖。
    default_gap = int((cfg.get("fusion") or {}).get("max_gap") or 0)
    rels: List[S.Relation] = []

    by_doc: Dict[str, List[S.Entity]] = {}
    for e in entities:
        by_doc.setdefault(e.doc, []).append(e)

    for doc in docs:
        doc_ents = by_doc.get(doc["doc_id"], [])
        if not doc_ents:
            continue
        # 结构关系：实体 -> 文档
        for e in doc_ents:
            if structural.get("mentioned_in", True):
                rels.append(S.Relation(source=e.id, relation="mentioned_in",
                                       target=f"doc:{doc['doc_id']}", doc=doc["doc_id"],
                                       evidence=e.evidence, method=method))
        for _, _, sent in split_sentences(doc["text"]):
            for rule in rules:
                trigger = rule.get("trigger")
                gap = int(rule["max_gap"]) if rule.get("max_gap") is not None else default_gap
                trig_span = (-1, -1)
                if trigger and not re.search(trigger, sent, re.IGNORECASE):
                    continue
                if trigger and gap:
                    tm = re.search(trigger, sent, re.IGNORECASE)
                    trig_span = (tm.start(), tm.end())
                left = [e for e in doc_ents
                        if e.type == rule["source_type"] and find_mention(sent, e.label) >= 0]
                right = [e for e in doc_ents
                         if e.type == rule["target_type"] and find_mention(sent, e.label) >= 0]
                for s_ in left:
                    for t_ in right:
                        if s_.id == t_.id:
                            continue
                        # 有序关系（如 subtechnique_of）：源实体必须在句中先于目标出现，
                        # 否则 A→B 与 B→A 会同时成立，把有向关系变成无向噪声。
                        if rule.get("ordered"):
                            s_pos = find_mention(sent, s_.label)
                            t_pos = find_mention(sent, t_.label)
                            if s_pos < 0 or t_pos < 0 or s_pos >= t_pos:
                                continue
                        # 邻近约束：目标实体必须出现在触发词附近 gap 个字符内。
                        # 这一步专治"同句共现"把无关实体连起来的噪声（实测有效，见报告对比）。
                        if gap and trig_span[0] >= 0:
                            pos = sent.lower().find(t_.label.lower())
                            if pos >= 0:
                                dist = pos - trig_span[1] if pos >= trig_span[1] else trig_span[0] - (pos + len(t_.label))
                                if dist > gap:
                                    continue
                        rels.append(S.Relation(
                            source=s_.id, relation=rule["relation"], target=t_.id,
                            doc=doc["doc_id"], evidence=S.norm_label(sent)[:200],
                            method=method,
                            properties={"trigger": trigger or "", "gap": gap,
                                        "rule": rule.get("name", rule["relation"])},
                        ))
    return dedupe_relations(rels)


def dedupe_relations(rels: List[S.Relation]) -> List[S.Relation]:
    seen: Dict[Tuple[str, str, str], S.Relation] = {}
    for r in rels:
        seen.setdefault(r.key(), r)
    return list(seen.values())


# --------------------------------------------------------------------------- #
# 入口
# --------------------------------------------------------------------------- #
def run(topic: str, verbose: bool = True) -> dict:
    cfg = S.load_topic(topic)
    docs = S.load_corpus(cfg)
    if not docs:
        raise SystemExit(f"[rule] 语料为空：请先运行 scripts/fetch_corpus.py --topic {topic}")
    ents = extract_entities(cfg, docs)
    rels = extract_relations(cfg, docs, ents)

    payload = {
        "topic": topic, "method": "rule", "doc_count": len(docs),
        "entity_count": len(ents), "relation_count": len(rels),
        "entities": S.entities_to_json(ents),
        "relations": S.relations_to_json(rels),
        "unknown_types": S.require_known_types(cfg, ents),
        "unknown_relations": S.require_known_relations(cfg, rels),
    }
    path = S.write_json(S.out_dir("extraction", topic) / f"{topic}_rule.json", payload)
    if verbose:
        print(f"[rule] 文档 {len(docs)} · 实体 {len(ents)} · 关系 {len(rels)} -> {path}")
        if payload["unknown_types"]:
            print(f"[rule] ⚠ 越界类（不在本体中）：{payload['unknown_types']}")
        if payload["unknown_relations"]:
            print(f"[rule] ⚠ 越界关系（不在本体中）：{payload['unknown_relations']}")
    return payload


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="阶段二·方法A：规则/词典/模板抽取")
    ap.add_argument("--topic", required=True)
    run(ap.parse_args().topic)
