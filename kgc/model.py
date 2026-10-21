"""阶段二 · 方法 B：机器学习 / 深度学习模型抽取（model-based）。

本脚手架给出**可离线运行**的最小实现：把实体识别当序列标注任务，用词级特征 +
逻辑回归（token 分类）训练 BIO 标注器。关系头复用触发词规则——教学上先把
"实体识别头可替换"这件事讲清楚，关系头作为进阶任务。

生产/进阶路线（命令行接口不变，只换 backend）：
    * BiLSTM-CRF / BERT 序列标注：`transformers` + `torch`；参考 zjunlp/DeepKE
      （★4484, MIT, 2026-07-13 更新）、zjunlp/OneKE（★197, MIT）。
    * 中文域：`hfl/chinese-roberta-wwm-ext` 微调；安全域可用 SecureBERT。
    * 关系抽取头：句内实体对编码后分类（PCNN / BERT-Softmax / RE 模板），
      替代本脚手架的触发词规则。

训练数据来源（两种，都要求与评估文档不重叠）：
    --train-source rule : 规则方法在**训练文档**上的输出做弱监督（自动、量大）
    --train-source gold : topics/<topic>/gold.jsonl 的标注句（量小、可信）

⚠ 教学结论请诚实记录：小样本弱监督下，模型法不一定打得过规则法。把这个差距
量化出来，本身就是一个验收点（也是"三方法对比"真正的价值所在）。
"""

from __future__ import annotations

import re
from typing import Dict, List, Tuple

from . import rule as rule_mod
from . import schema as S

TOKEN_RX = re.compile(r"[A-Za-z]+|\d+(?:\.\d+)*|[\u4e00-\u9fff]|[^\sA-Za-z0-9\u4e00-\u9fff]")


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


def token_features(tokens: List[str], i: int) -> Dict[str, float]:
    tok = tokens[i]
    prev = tokens[i - 1] if i else "<BOS>"
    nxt = tokens[i + 1] if i + 1 < len(tokens) else "<EOS>"
    return {
        f"w={tok.lower()}": 1.0,
        f"shape={_shape(tok)}": 1.0,
        f"pre3={tok[:3].lower()}": 1.0,
        f"suf3={tok[-3:].lower()}": 1.0,
        f"prev={prev.lower()}": 1.0,
        f"next={nxt.lower()}": 1.0,
        f"prev_w+{tok.lower()}={prev.lower()}": 1.0,
        f"w+{nxt.lower()}={tok.lower()}": 1.0,
    }


def bio_labels(text: str, spans: List[Tuple[int, int, str]]) -> List[str]:
    """把本文本坐标系下的实体 span 转成与 token 对齐的 BIO 序列。"""
    toks = tokenize(text)
    labels = ["O"] * len(toks)
    for span_start, span_end, etype in spans:
        inside = False
        for i, (ts, te, _) in enumerate(toks):
            if ts >= span_start and te <= span_end:
                labels[i] = f"{'B' if not inside else 'I'}-{etype}"
                inside = True
    return labels


def rule_spans(cfg: dict, doc: dict) -> List[Tuple[int, int, str]]:
    """用规则/词典在本篇文档上定位实体 span（绝对偏移），作为弱标注来源。"""
    spans: List[Tuple[int, int, str]] = []
    text = doc["text"]
    for pat in cfg.get("patterns", {}).get("entity_patterns", []):
        rx = re.compile(pat["regex"], rule_mod._flags(pat.get("flags", [])))
        for m in rx.finditer(text):
            spans.append((m.start(), m.end(), pat["type"]))
    for etype, surfaces in cfg.get("lexicons", {}).items():
        for surface in surfaces:
            if re.fullmatch(r"[A-Za-z0-9 ._/+-]+", surface):
                rx = re.compile(rf"(?<![A-Za-z0-9_]){re.escape(surface)}(?![A-Za-z0-9_])", re.IGNORECASE)
            else:
                rx = re.compile(re.escape(surface))
            for m in rx.finditer(text):
                spans.append((m.start(), m.end(), etype))
    return sorted(set(spans))


class LogRegTagger:
    """token 级逻辑回归 + BIO 解码。"""

    def __init__(self) -> None:
        self.vec = None
        self.model = None

    def fit(self, samples: List[Tuple[str, List[str]]]) -> "LogRegTagger":
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
            raise SystemExit("[model] 无有效训练样本")
        self.vec = DictVectorizer(sparse=True)
        X = self.vec.fit_transform(xs)
        self.model = LogisticRegression(max_iter=500, class_weight="balanced")
        self.model.fit(X, ys)
        return self

    def predict_entities(self, text: str, doc_id: str, min_prob: float = 0.5) -> List[S.Entity]:
        import numpy as np

        toks = tokenize(text)
        if not toks:
            return []
        X = self.vec.transform([token_features([t[2] for t in toks], i) for i in range(len(toks))])
        proba = self.model.predict_proba(X)
        classes = np.asarray(self.model.classes_)
        # 阈值化：只有最大类别概率 >= min_prob 才输出非 O 标签，
        # 否则一律视为 O。这是控制"模型法过度召回"最直接的旋钮（验收时需报告阈值）。
        best = proba.argmax(axis=1)
        pred = [classes[b] if proba[i, b] >= min_prob else "O" for i, b in enumerate(best)]
        return self._decode(toks, pred, text, doc_id)

    @staticmethod
    def _decode(toks, pred, text: str, doc_id: str) -> List[S.Entity]:
        out: List[S.Entity] = []
        cur: List[int] = []
        cur_type = ""

        def flush() -> None:
            if not cur or not cur_type:
                return
            start, end = toks[cur[0]][0], toks[cur[-1]][1]
            label = S.norm_label(text[start:end])
            if label:
                out.append(S.Entity(
                    id=S.make_id(cur_type, label), label=label, type=cur_type, doc=doc_id,
                    evidence=S.snippet(text, start, end), method="model",
                    properties={"ntok": len(cur)},
                ))

        for i, ((_, _, _), lab) in enumerate(zip(toks, pred)):
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


def build_samples(cfg: dict, docs: List[dict], train_source: str) -> List[Tuple[str, List[str]]]:
    samples: List[Tuple[str, List[str]]] = []
    for doc in docs:
        if train_source == "rule":
            spans = rule_spans(cfg, doc)
        else:  # gold：金标准里的 mention（含 doc/offset 时才可用）
            spans = [(g["start"], g["end"], g["type"]) for g in cfg.get("gold", [])
                     if g.get("doc") == doc["doc_id"] and "start" in g]
        if not spans:
            continue
        for s_start, s_end, sent in rule_mod.split_sentences(doc["text"]):
            local = [(a - s_start, b - s_start, t) for a, b, t in spans if a >= s_start and b <= s_end]
            labels = bio_labels(sent, local)
            if any(l != "O" for l in labels):
                samples.append((sent, labels))
    return samples


def run(topic: str, train_source: str = "rule", eval_doc: str | None = None,
        min_prob: float = 0.5, verbose: bool = True) -> dict:
    cfg = S.load_topic(topic)
    docs = S.load_corpus(cfg)
    if len(docs) < 2:
        raise SystemExit("[model] 至少需要 2 篇语料（训练 / 评估分离，防止数据泄漏）")

    eval_doc = eval_doc or sorted(d["doc_id"] for d in docs)[-1]
    train_docs = [d for d in docs if d["doc_id"] != eval_doc]

    samples = build_samples(cfg, train_docs, train_source)
    if not samples:
        raise SystemExit("[model] 未从训练文档得到弱标注样本，检查 patterns.yaml / lexicons.yaml")
    types = sorted({l.split("-", 1)[1] for _, labs in samples for l in labs if l != "O"})

    tagger = LogRegTagger().fit(samples)
    all_ents: List[S.Entity] = []
    for doc in docs:
        all_ents.extend(tagger.predict_entities(doc["text"], doc["doc_id"], min_prob))
    rels = rule_mod.extract_relations(cfg, docs, all_ents, method="model")

    payload = {
        "topic": topic, "method": "model",
        "backend": "sklearn.LogisticRegression(token-BIO)",
        "min_prob": min_prob,
        "train_source": train_source, "train_docs": sorted(d["doc_id"] for d in train_docs),
        "eval_doc": eval_doc, "train_sentences": len(samples), "label_types": types,
        "entity_count": len(all_ents), "relation_count": len(rels),
        "entities": S.entities_to_json(all_ents),
        "relations": S.relations_to_json(rels),
        "unknown_types": S.require_known_types(cfg, all_ents),
        "unknown_relations": S.require_known_relations(cfg, rels),
    }
    path = S.write_json(S.out_dir("extraction", topic) / f"{topic}_model.json", payload)
    if verbose:
        print(f"[model] backend=LogReg(BIO) 训练句={len(samples)} 标签类型={types}")
        print(f"[model] 训练文档={payload['train_docs']} 留出评估文档={eval_doc}")
        print(f"[model] 解码阈值 min_prob={min_prob}（提高阈值 → 精度升、召回降，需在报告中给出取舍）")
        print(f"[model] 实体 {len(all_ents)} · 关系 {len(rels)} -> {path}")
    return payload


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="阶段二·方法B：模型抽取（离线最小实现）")
    ap.add_argument("--topic", required=True)
    ap.add_argument("--train-source", default="rule", choices=["rule", "gold"])
    ap.add_argument("--eval-doc", default=None)
    ap.add_argument("--min-prob", type=float, default=0.5)
    a = ap.parse_args()
    run(a.topic, a.train_source, a.eval_doc, a.min_prob)
