"""阶段二 · 方法 B（完整版）：序列标注 + 关系分类，双头都是学习出来的。

与脚手架 ``kgc.model`` 的区别（也是本选题的实验设计）：

1. **实体头**仍是 token 级 BIO，但特征加强了泛化项（前后缀、数字/字母形态、前后两个
   token）。弱监督来自规则在**训练文档**上的输出；CVE/CWE/CPE 这类编号在留出文档里
   是没见过的字符串，模型必须靠“形状”而不是“记住全词”来识别——这才是序列标注。
2. **关系头是分类器**，不是触发词规则：句内候选实体对 → 特征（类型对、字符距离、
   顺序、两端邻近词、句中线索词）→ 多分类（每种关系 + ``__none__``）。触发词不再
   直接决定结果，只是特征的一部分。
3. **文档级 5 折交叉验证**：每篇文档的预测都来自没见过它的模型。避免了脚手架
   ``--eval-doc`` 只留一篇、其余文档仍参与训练造成的乐观偏差。

弱监督的标签来自 ``kgc.rule``（正则+词典），**不含**方法 A 的结构化映射，因此 B 确实
只从文本学习；A 的结构化通道优势才能在对比里体现出来。

输出：
    data/extraction/<topic>_model.json
"""
from __future__ import annotations

import random
import re
from collections import Counter, defaultdict
from typing import Dict, List, Sequence, Tuple

from . import ids as I
from . import rule as R
from . import schema as S

TOKEN_RX = re.compile(r"[A-Za-z]+|\d+(?:\.\d+)*|[一-鿿]|[^\sA-Za-z0-9一-鿿]")

NONE = "__none__"
SEED = 20261021
FOLDS = 5

# 关系分类器的线索词（只是特征，不是判定规则；判定由分类器学出来）
CUES = ("uses", "used", "mitigat", "detect", "coverage", "belongs", "tactic",
        "subtechnique", "implement", "relates", "attack pattern", "capec", "cwe",
        "root cause", "affect", "vulnerab", "identifier", "kev", "catalog",
        "vendor", "produc", "advisory", "exploit")


# --------------------------------------------------------------------------- #
# 基础：分词、特征、词表索引
# --------------------------------------------------------------------------- #
def tokenize(text: str) -> List[Tuple[int, int, str]]:
    return [(m.start(), m.end(), m.group(0)) for m in TOKEN_RX.finditer(text)]


def _shape(tok: str) -> str:
    if tok.isdigit():
        return "D"
    if tok.isupper():
        return "U"
    if tok.islower():
        return "L"
    if tok[:1].isupper():
        return "T"
    return "O"


def token_features(tokens: Sequence[str], i: int) -> Dict[str, float]:
    tok = tokens[i]
    prev = tokens[i - 1] if i else "<BOS>"
    prev2 = tokens[i - 2] if i > 1 else "<BOS2>"
    nxt = tokens[i + 1] if i + 1 < len(tokens) else "<EOS>"
    nxt2 = tokens[i + 2] if i + 2 < len(tokens) else "<EOS2>"
    low = tok.lower()
    feats = {
        f"w={low}": 1.0,
        f"shape={_shape(tok)}": 1.0,
        f"len={min(len(tok), 12)}": 1.0,
        f"prev={prev.lower()}": 1.0,
        f"next={nxt.lower()}": 1.0,
        f"prev2={prev2.lower()}": 1.0,
        f"next2={nxt2.lower()}": 1.0,
        f"has_digit={any(c.isdigit() for c in tok)}": 1.0,
        f"has_alpha={any(c.isalpha() for c in tok)}": 1.0,
    }
    for n in (2, 3, 4, 5):
        if len(tok) >= n:
            feats[f"pre{n}={tok[:n].lower()}"] = 1.0
            feats[f"suf{n}={tok[-n:].lower()}"] = 1.0
    return feats


def lexicon_index(cfg: dict, resolver: I.IdResolver) -> Dict[Tuple[str, str], Tuple[str, str]]:
    """(类, surface 小写) -> (官方 ID, 规范标签)。词典是方法 A 与小模型共享的“外部知识”，
    但模型不直接查表产出实体，只在解码后把名称归一到官方 ID。"""
    idx: Dict[Tuple[str, str], Tuple[str, str]] = {}
    for etype, entries in (cfg.get("lexicons") or {}).items():
        for entry in entries:
            if isinstance(entry, dict):
                surface = entry.get("surface", "")
                eid = entry.get("id") or resolver.canonical(etype, surface)
                label = entry.get("label", surface)
            else:
                surface, eid, label = entry, resolver.canonical(etype, entry), entry
            if surface:
                idx[(etype, S.norm_label(surface).lower())] = (eid, S.norm_label(label))
    return idx


# --------------------------------------------------------------------------- #
# 弱标注 span（正则 + 词典；不做结构化映射）
# --------------------------------------------------------------------------- #
def doc_spans(cfg: dict, doc: dict) -> List[Tuple[int, int, str]]:
    spans: List[Tuple[int, int, str]] = []
    text = doc["text"]
    for pat in (cfg.get("patterns") or {}).get("entity_patterns", []):
        rx = re.compile(pat["regex"], R._flags(pat.get("flags", [])))
        for m in rx.finditer(text):
            # 用捕获组 1 的边界：Sigma 的 "Sigma rule <uuid>" 前缀不属于实体本身，
            # 否则模型会把前缀学进标签，和官方 ID 对不上。
            a, b = m.span(1) if m.groups() else m.span(0)
            spans.append((a, b, pat["type"]))
    for etype, entries in (cfg.get("lexicons") or {}).items():
        for entry in entries:
            surface = entry.get("surface", "") if isinstance(entry, dict) else entry
            if not surface:
                continue
            if re.fullmatch(r"[A-Za-z0-9 ._/+-]+", surface):
                rx = re.compile(rf"(?<![A-Za-z0-9_]){re.escape(surface)}(?![A-Za-z0-9_])",
                                re.IGNORECASE)
            else:
                rx = re.compile(re.escape(surface))
            for m in rx.finditer(text):
                spans.append((m.start(), m.end(), etype))
    return _resolve_overlaps(sorted(set(spans)))


def _resolve_overlaps(spans: List[Tuple[int, int, str]]) -> List[Tuple[int, int, str]]:
    """同一位置既匹配 T1059 又匹配 T1059.001 时保留最长 span（BIO 不能重叠）。"""
    kept: List[Tuple[int, int, str]] = []
    for sp in sorted(spans, key=lambda x: (x[0], -(x[1] - x[0]))):
        if any(sp[0] >= k[0] and sp[1] <= k[1] for k in kept):
            continue
        kept.append(sp)
    return kept


def bio_labels(text: str, spans: List[Tuple[int, int, str]]) -> Tuple[List[Tuple[int, int, str]], List[str]]:
    toks = tokenize(text)
    labels = ["O"] * len(toks)
    for a, b, etype in spans:
        inside = False
        for i, (ts, te, _) in enumerate(toks):
            if ts >= a and te <= b:
                labels[i] = f"{'B' if not inside else 'I'}-{etype}"
                inside = True
    return toks, labels


def training_sentences(cfg: dict, docs: List[dict]) -> List[Tuple[str, List[str]]]:
    out = []
    for doc in docs:
        spans = doc_spans(cfg, doc)
        if not spans:
            continue
        for s0, s1, sent in R.split_sentences(doc["text"]):
            local = [(a - s0, b - s0, t) for a, b, t in spans if a >= s0 and b <= s1]
            _, labels = bio_labels(sent, local)
            if any(l != "O" for l in labels):
                out.append((sent, labels))
    return out


# --------------------------------------------------------------------------- #
# 实体头
# --------------------------------------------------------------------------- #
class Tagger:
    def __init__(self, lex: Dict[Tuple[str, str], Tuple[str, str]], resolver: I.IdResolver):
        self.lex = lex
        self.resolver = resolver
        self.vec = None
        self.clf = None

    def fit(self, samples: List[Tuple[str, List[str]]]) -> "Tagger":
        from sklearn.feature_extraction import DictVectorizer
        from sklearn.linear_model import LogisticRegression

        xs: List[Dict[str, float]] = []
        ys: List[str] = []
        for text, labels in samples:
            toks = [t[2] for t in tokenize(text)]
            if len(toks) != len(labels):
                continue
            xs.extend(token_features(toks, i) for i in range(len(toks)))
            ys.extend(labels)
        if not xs:
            raise SystemExit("[model-B] 无有效训练样本")
        self.vec = DictVectorizer(sparse=True)
        X = self.vec.fit_transform(xs)
        self.clf = LogisticRegression(max_iter=400, class_weight="balanced",
                                      solver="lbfgs")
        self.clf.fit(X, ys)
        return self

    def predict_tags(self, text: str, min_prob: float) -> Tuple[List[Tuple[int, int, str]], List[str], List[str]]:
        import numpy as np

        toks = tokenize(text)
        if not toks:
            return [], [], []
        X = self.vec.transform([token_features([t[2] for t in toks], i) for i in range(len(toks))])
        proba = self.clf.predict_proba(X)
        classes = np.asarray(self.clf.classes_)
        best = proba.argmax(axis=1)
        pred = [str(classes[b]) if proba[i, b] >= min_prob else "O" for i, b in enumerate(best)]
        return toks, pred, [t[2] for t in toks]

    def predict_entities(self, text: str, doc_id: str, min_prob: float) -> List[S.Entity]:
        toks, pred, _ = self.predict_tags(text, min_prob)
        return self._decode(toks, pred, text, doc_id)

    def _decode(self, toks, pred, text: str, doc_id: str) -> List[S.Entity]:
        out: List[S.Entity] = []
        cur: List[int] = []
        cur_type = ""

        def flush() -> None:
            if not cur or not cur_type:
                return
            start, end = toks[cur[0]][0], toks[cur[-1]][1]
            # 解码可能把句末标点并进 span（CPE 后跟逗号/句号），先剥掉再校验
            surface = S.norm_label(text[start:end]).rstrip(" ,;.)")
            canon = self.lex.get((cur_type, surface.lower()))
            if not surface:
                return
            if canon:
                eid, label = canon
            elif self.resolver.types() and cur_type in self.resolver.types():
                # 编号类：解码片段必须本身是合法官方编号，否则是跨 token 切出来的噪声
                if not self.resolver.official(cur_type, surface):
                    return
                eid, label = self.resolver.canonical(cur_type, surface), surface
            else:
                if len(surface) < 2:
                    return
                eid, label = self.resolver.canonical(cur_type, surface), surface
            out.append(S.Entity(id=eid, label=label, type=cur_type, doc=doc_id,
                                evidence=S.snippet(text, start, end), method="model",
                                properties={"surface": surface, "ntok": len(cur),
                                            "canonical_by": "lexicon" if canon else "pattern"}))

        for i, lab in enumerate(pred):
            if lab == "O":
                flush()
                cur, cur_type = [], ""
                continue
            tag, etype = lab.split("-", 1)
            if tag == "B" or etype != cur_type:
                flush()
                cur, cur_type = [], etype
            cur.append(i)
        flush()
        return out


# --------------------------------------------------------------------------- #
# 关系头
# --------------------------------------------------------------------------- #
def _allowed_pairs(cfg: dict) -> Dict[Tuple[str, str], List[str]]:
    """(头类, 尾类) -> 允许的关系列表，直接来自本体的 domain/range。"""
    out: Dict[Tuple[str, str], List[str]] = defaultdict(list)
    for r in cfg["ontology_seed"].get("relations", []):
        if r.get("domain") and r.get("range"):
            out[(r["domain"], r["range"])].append(r["id"])
    return out


def _mentions(sent: str, ents: List[S.Entity]) -> List[Tuple[S.Entity, int, int]]:
    out = []
    for e in ents:
        surface = e.properties.get("surface") or e.label
        pos = R.find_mention(sent, surface)
        if pos >= 0:
            out.append((e, pos, pos + len(surface)))
    return out


def _rel_features(resolver: I.IdResolver, sent: str, head: S.Entity, hs: int, he: int,
                  tail: S.Entity, ts: int, te: int) -> Dict[str, float]:
    between = sent[he:ts] if he <= ts else sent[te:hs]
    words = [w.lower() for w in re.findall(r"[A-Za-z][A-Za-z\-]{3,}", between)]
    feats = {
        f"pair={head.type}>{tail.type}": 1.0,
        f"order={'before' if he <= ts else 'after'}": 1.0,
        f"dist={_bucket(abs(ts - he))}": 1.0,
        f"h_official={bool(resolver.official(head.type, head.label))}": 1.0,
        f"t_official={bool(resolver.official(tail.type, tail.label))}": 1.0,
    }
    for w in words[:6]:
        feats[f"btw={w}"] = 1.0
    low = sent.lower()
    for cue in CUES:
        if cue in low:
            feats[f"cue={cue}"] = 1.0
    # 头尾邻近词（比“句中任意位置”更贴近关系表达）
    after = re.findall(r"[A-Za-z][A-Za-z\-]{2,}", sent[he:he + 40].lower())[:3]
    before = re.findall(r"[A-Za-z][A-Za-z\-]{2,}", sent[max(0, ts - 40):ts].lower())[-3:]
    for w in after:
        feats[f"after_head={w}"] = 1.0
    for w in before:
        feats[f"before_tail={w}"] = 1.0
    return feats


def _bucket(dist: int) -> str:
    for edge in (20, 60, 120, 240):
        if dist <= edge:
            return f"<={edge}"
    return ">240"


def candidate_pairs(cfg: dict, sent: str, ents: List[S.Entity], cap: int = 400):
    allowed = _allowed_pairs(cfg)
    men = _mentions(sent, ents)
    out = []
    for i, (h, hs, he) in enumerate(men):
        for j, (t, ts, te) in enumerate(men):
            if i == j or h.id == t.id:
                continue
            if (h.type, t.type) not in allowed:
                continue
            out.append((h, hs, he, t, ts, te))
            if len(out) >= cap:
                return out
    return out


def build_rel_samples(cfg: dict, docs: List[dict], ents_by_doc: Dict[str, List[S.Entity]],
                      rng: random.Random, resolver: I.IdResolver) -> List[Tuple[Dict[str, float], str]]:
    """用规则关系做弱监督标签；负例按 3:1 截断，避免类别极度不平衡。"""
    labels_by_doc: Dict[str, set] = defaultdict(set)
    for doc in docs:
        rels = R.extract_relations(cfg, [doc], ents_by_doc.get(doc["doc_id"], []))
        for r in rels:
            if r.relation != "mentioned_in":
                labels_by_doc[doc["doc_id"]].add((r.source, r.relation, r.target))
    samples: List[Tuple[Dict[str, float], str]] = []
    for doc in docs:
        ents = ents_by_doc.get(doc["doc_id"], [])
        for _, _, sent in R.split_sentences(doc["text"]):
            pos, neg = [], []
            for h, hs, he, t, ts, te in candidate_pairs(cfg, sent, ents):
                feats = _rel_features(resolver, sent, h, hs, he, t, ts, te)
                hit = next((rel for (a, rel, b) in labels_by_doc.get(doc["doc_id"], ())
                            if a == h.id and b == t.id), None)
                (pos if hit else neg).append((feats, hit or NONE))
            if pos:
                samples.extend(pos)
                rng.shuffle(neg)
                samples.extend(neg[:max(1, 3 * len(pos))])
    return samples


class RelationClassifier:
    def __init__(self) -> None:
        self.vec = None
        self.clf = None

    def fit(self, samples) -> "RelationClassifier":
        from sklearn.feature_extraction import DictVectorizer
        from sklearn.linear_model import LogisticRegression

        xs = [f for f, _ in samples]
        ys = [y for _, y in samples]
        if len(set(ys)) < 2:
            raise SystemExit("[model-B] 关系训练样本只有一个类别")
        self.vec = DictVectorizer(sparse=True)
        X = self.vec.fit_transform(xs)
        self.clf = LogisticRegression(max_iter=400, class_weight="balanced",
                                      solver="lbfgs")
        self.clf.fit(X, ys)
        return self

    def predict(self, feats: Dict[str, float], min_prob: float) -> str:
        import numpy as np

        X = self.vec.transform([feats])
        proba = self.clf.predict_proba(X)[0]
        b = int(proba.argmax())
        return str(self.clf.classes_[b]) if proba[b] >= min_prob else NONE


# --------------------------------------------------------------------------- #
# 5 折交叉验证主流程
# --------------------------------------------------------------------------- #
def _micro_prf(tp: int, n_pred: int, n_gold: int) -> dict:
    p = tp / n_pred if n_pred else 0.0
    r = tp / n_gold if n_gold else 0.0
    f = 2 * p * r / (p + r) if p + r else 0.0
    return {"precision": round(p, 4), "recall": round(r, 4), "f1": round(f, 4)}


def _dedupe(ents: List[S.Entity]) -> List[S.Entity]:
    """BIO 是 mention 级输出；规范实体层按 (id, doc) 合并。"""
    return list({(e.id, e.doc): e for e in ents}.values())


def _predict(tagger: Tagger, rel_clf: RelationClassifier | None, docs: List[dict],
             cfg: dict, resolver: I.IdResolver, min_prob: float,
             rel_prob: float) -> Tuple[List[S.Entity], List[S.Relation]]:
    ents_out: List[S.Entity] = []
    rels_out: List[S.Relation] = []
    for doc in docs:
        ents = tagger.predict_entities(doc["text"], doc["doc_id"], min_prob)
        ents_out.extend(ents)
        if rel_clf is None:
            continue
        for _, _, sent in R.split_sentences(doc["text"]):
            for h, hs, he, t, ts, te in candidate_pairs(cfg, sent, ents):
                feats = _rel_features(resolver, sent, h, hs, he, t, ts, te)
                rel = rel_clf.predict(feats, rel_prob)
                if rel == NONE:
                    continue
                rels_out.append(S.Relation(
                    source=h.id, relation=rel, target=t.id, doc=doc["doc_id"],
                    evidence=S.norm_label(sent)[:200], method="model",
                    properties={"classifier": "LogReg",
                                "head_surface": h.properties.get("surface", ""),
                                "tail_surface": t.properties.get("surface", "")}))
    return _dedupe(ents_out), R.dedupe_relations(rels_out)


def run(topic: str, min_prob: float = 0.55, rel_prob: float = 0.5,
        folds: int = FOLDS, verbose: bool = True) -> dict:
    cfg = S.load_topic(topic)
    docs = sorted(S.load_corpus(cfg), key=lambda d: d["doc_id"])
    if len(docs) < folds:
        raise SystemExit(f"[model-B] 语料只有 {len(docs)} 篇，少于折数 {folds}")
    resolver = I.IdResolver.from_cfg(cfg)
    lex = lexicon_index(cfg, resolver)
    rng = random.Random(SEED)

    weak_set = {(e.type, e.label.lower(), e.doc) for e in _rule_entities(cfg, docs)}
    fold_stats = []
    cv_ents: List[S.Entity] = []
    cv_tp = cv_npred = 0

    for k in range(folds):
        test_docs = [d for i, d in enumerate(docs) if i % folds == k]
        train_docs = [d for i, d in enumerate(docs) if i % folds != k]
        test_ids = {d["doc_id"] for d in test_docs}

        samples = training_sentences(cfg, train_docs)
        tagger = Tagger(lex, resolver).fit(samples)

        # 关系弱标签：训练文档上的规则实体 + 规则关系
        train_ents = _rule_entities(cfg, train_docs)
        by_doc: Dict[str, List[S.Entity]] = defaultdict(list)
        for e in train_ents:
            by_doc[e.doc].append(e)
        rel_samples = build_rel_samples(cfg, train_docs, by_doc, rng, resolver)
        rel_clf = RelationClassifier().fit(rel_samples) if rel_samples else None

        ents, _ = _predict(tagger, rel_clf, test_docs, cfg, resolver, min_prob, rel_prob)
        cv_ents.extend(ents)
        fold_stats.append({"fold": k, "test_docs": sorted(test_ids),
                           "train_sentences": len(samples), "rel_samples": len(rel_samples),
                           "rel_positive": sum(1 for _, y in rel_samples if y != NONE),
                           "rel_class_dist": dict(Counter(y for _, y in rel_samples))})

    # 交叉验证只负责报告泛化指标：每篇文档由没见过它的模型预测。
    # 某些类（Group/Software/Mitigation）在语料里只出现在单一文档中，留出该文档时
    # 训练集完全没见过这个类——这是文档级 CV 的冷启动，必须如实记录。
    cv_ents = _dedupe(cv_ents)
    for e in cv_ents:
        cv_npred += 1
        cv_tp += (e.type, e.label.lower(), e.doc) in weak_set
    cv_metrics = _micro_prf(cv_tp, cv_npred, len(weak_set))

    # 构建 KG 用的最终模型在**全量语料**上训练（标准做法：CV 估泛化，最终模型用全量）。
    full_tagger = Tagger(lex, resolver).fit(training_sentences(cfg, docs))
    full_rule_ents = _rule_entities(cfg, docs)
    by_doc_all: Dict[str, List[S.Entity]] = defaultdict(list)
    for e in full_rule_ents:
        by_doc_all[e.doc].append(e)
    full_rel_samples = build_rel_samples(cfg, docs, by_doc_all, rng, resolver)
    full_rel_clf = RelationClassifier().fit(full_rel_samples)
    pred_ents, pred_rels = _predict(full_tagger, full_rel_clf, docs, cfg, resolver,
                                    min_prob, rel_prob)

    payload = {
        "topic": topic, "method": "model",
        "backend": "sklearn.LogisticRegression(token-BIO) + LogReg(relation multi-class)",
        "protocol": f"document-level {folds}-fold CV 报告泛化；最终产物由全量语料训练",
        "folds": fold_stats, "seed": SEED,
        "min_prob": min_prob, "rel_prob": rel_prob,
        "relation_classes": sorted({r["id"] for r in cfg["ontology_seed"].get("relations", [])
                                    if r["id"] != "mentioned_in"}) + [NONE],
        "cv_entity_metrics_vs_weak_labels": cv_metrics,
        "full_rel_training": {"samples": len(full_rel_samples),
                              "positive": sum(1 for _, y in full_rel_samples if y != NONE),
                              "class_dist": dict(Counter(y for _, y in full_rel_samples))},
        "entity_count": len(pred_ents), "relation_count": len(pred_rels),
        "entity_type_dist": dict(sorted(Counter(e.type for e in pred_ents).items())),
        "relation_dist": dict(sorted(Counter(r.relation for r in pred_rels).items())),
        "entities": S.entities_to_json(pred_ents),
        "relations": S.relations_to_json(pred_rels),
        "unknown_types": S.require_known_types(cfg, pred_ents),
        "unknown_relations": S.require_known_relations(cfg, pred_rels),
    }
    path = S.write_json(S.out_dir("extraction", topic) / f"{topic}_model.json", payload)
    if verbose:
        m = payload["cv_entity_metrics_vs_weak_labels"]
        print(f"[model-B] {folds} 折文档级交叉验证 · 阈值 min_prob={min_prob} rel_prob={rel_prob}")
        print(f"[model-B] 留出实体 P={m['precision']} R={m['recall']} F1={m['f1']}（对标弱标注）")
        print(f"[model-B] 全量模型产出 实体 {len(pred_ents)} · 关系 {len(pred_rels)} -> {path}")
        print("[model-B] 实体类型：" + ", ".join(f"{k}={v}" for k, v in
                                                payload["entity_type_dist"].items()))
        print("[model-B] 关系类型：" + ", ".join(f"{k}={v}" for k, v in
                                                payload["relation_dist"].items()))
        if payload["unknown_types"] or payload["unknown_relations"]:
            print(f"[model-B] ⚠ 越界：{payload['unknown_types']} / {payload['unknown_relations']}")
    return payload


def _rule_entities(cfg: dict, docs: List[dict]) -> List[S.Entity]:
    return R.extract_entities(cfg, docs)


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="阶段二·方法B：序列标注+关系分类（5折CV）")
    ap.add_argument("--topic", required=True)
    ap.add_argument("--min-prob", type=float, default=0.55)
    ap.add_argument("--rel-prob", type=float, default=0.5)
    ap.add_argument("--folds", type=int, default=FOLDS)
    a = ap.parse_args()
    run(a.topic, a.min_prob, a.rel_prob, a.folds)
