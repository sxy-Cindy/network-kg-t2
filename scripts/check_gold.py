#!/usr/bin/env python3
"""金标准自检：确认 gold.jsonl 的每条 label 都在对应文档里真实出现（字面量、忽略大小写）。

    python scripts/check_gold.py --topic t5-protocol-rfc
    python scripts/check_gold.py --all

为什么必须做这一步：金标准若包含"语料里根本没写"的条目，任何方法的 recall 都会被
无理由压低，评测结论直接失效（这也是学生报告里最常见的一类错误）。本脚本把这类
错误在提交前暴露出来——注意它只校验"字面量是否存在"，不校验"关系是否成立"，
后者需要人工依据原文判定。
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def check(topic: str) -> dict:
    gold_path = ROOT / "topics" / topic / "gold.jsonl"
    if not gold_path.exists():
        return {"topic": topic, "ok": False, "problems": ["缺少 gold.jsonl"], "checked": 0}
    corpus = {}
    cdir = ROOT / "data" / "corpus" / topic
    for f in cdir.glob("*"):
        if f.suffix.lower() in (".txt", ".json", ".md"):
            corpus[f.stem] = f.read_text(encoding="utf-8", errors="replace").lower()

    rows = [json.loads(l) for l in gold_path.read_text(encoding="utf-8").splitlines() if l.strip()]
    problems = []
    for i, r in enumerate(rows, 1):
        doc = r.get("doc")
        labels = [x for x in (r.get("label"), r.get("head"), r.get("tail")) if x]
        if doc and doc not in corpus:
            problems.append(f"#{i} doc={doc} 不在 data/corpus/{topic}/")
            continue
        for lb in labels:
            src = corpus.get(doc, "\n".join(corpus.values())) if doc else "\n".join(corpus.values())
            if lb.lower() not in src:
                problems.append(f"#{i} 语料中找不到字面量: {lb!r} (doc={doc})")
    return {"topic": topic, "checked": len(rows), "ok": not problems, "problems": problems}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--topic")
    ap.add_argument("--all", action="store_true")
    a = ap.parse_args()
    topics = sorted(p.name for p in (ROOT / "topics").iterdir() if p.is_dir()) if a.all else [a.topic]
    bad = 0
    for t in topics:
        r = check(t)
        status = "OK" if r["ok"] else "PROBLEM"
        print(f"[gold] {t}: {r['checked']} 条 {status}")
        for p in r["problems"]:
            print("    -", p)
            bad += 1
    raise SystemExit(1 if bad else 0)


if __name__ == "__main__":
    main()
