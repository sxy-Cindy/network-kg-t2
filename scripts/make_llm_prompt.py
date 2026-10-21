#!/usr/bin/env python3
"""生成"可直接粘贴"的 LLM 抽取提示词（应对课程不提供统一 API 的情况）。

    python scripts/make_llm_prompt.py --topic t5-protocol-rfc
    python scripts/make_llm_prompt.py --topic t2-cve-attack --chunk 3000

产物：`data/llm_output/<topic>_prompt.md`
内容 = 本体词汇（类/关系定义 + 域值域）+ 输出 JSON 结构 + 规则 + 语料分块，
每一块都用 `===== 片段 N（doc=<doc_id>）=====` 分隔，学生可逐个粘贴到任意 LLM
（本地 Ollama、云端服务、网页版对话框皆可），把返回的 JSON 收集成
`<topic>_agent_llm.json`，再执行：

    python -m kgc.llm --topic <topic> --from-file data/llm_output/<topic>_agent_llm.json

这样"无统一 API"不影响作业的可复现性与横向可比性。
"""

from __future__ import annotations

import argparse
from pathlib import Path

import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from kgc import llm as L  # noqa: E402
from kgc import schema as S  # noqa: E402

HEADER = """# {topic} — 方法C（LLM 抽取）提示词包

> 用法：把每个片段（连同上面的"角色/本体/输出格式/规则"说明）逐个发给 LLM，
> 收集返回的 JSON，按下面的汇总格式整理成 `{topic}_agent_llm.json`，然后执行
> `.venv/bin/python -m kgc.llm --topic {topic} --from-file data/llm_output/{topic}_agent_llm.json`

## 0. 发给 LLM 的系统提示

```
{system}
```

## 1. 本体词汇（必须严格使用）

【本体类】(id | 中文 | 定义)
{classes}

【关系】(id | 中文 | 定义 | 头类 -> 尾类)
{relations}

## 2. 输出格式与规则

```json
{{
  "doc_id": "<片段所属文档 id，见片段标题>",
  "entities": [{{"id": "类:id后缀", "label": "表面形式", "type": "类名"}}],
  "relations": [{{"source": "实体id", "relation": "关系名", "target": "实体id",
                  "evidence": "支撑该关系的原文片段（连续原文，≤120字）"}}]
}}
```

1. `type` 必须来自上面的类 id；`relation` 必须来自上面的关系 id，否则**不要输出该条**。
2. `id` 用 `类名:标签` 形式；同一实体在不同片段中用同一 id。
3. `evidence` 必须是**原文连续片段**，不得改写、不得翻译。
4. 只抽文本中明确出现的事实，不做推理延伸。

## 3. 语料片段（逐段粘贴）

"""

FOOTER = """
## 4. 汇总文件格式（供 `--from-file` 读取）

```json
{
  "model": "<模型名与版本>",
  "note": "生成日期 <YYYY-MM-DD>；prompt 见本文件；人工复核 <N> 条（另附复核记录）",
  "docs": [
    {{"doc_id": "rfc8200", "entities": [...], "relations": [...]}},
    {{"doc_id": "rfc2119", "entities": [...], "relations": [...]}}
  ]
}
```

⚠ 提交作业时必须一并附上：① 模型名/版本/日期；② 本文件（prompt 原文）；
③ 原始输出 JSON；④ ≥20 条人工复核记录（逐条判断"抽出的三元组是否被原文支持"）。
"""


def main() -> None:
    ap = argparse.ArgumentParser(description="生成可直接粘贴的 LLM 抽取提示词包")
    ap.add_argument("--topic", required=True)
    ap.add_argument("--chunk", type=int, default=3500, help="每个片段的字符数上限")
    ap.add_argument("--max-chunks", type=int, default=12, help="最多输出几个片段（防止提示词过长）")
    a = ap.parse_args()

    cfg = S.load_topic(a.topic)
    docs = S.load_corpus(cfg)
    if not docs:
        raise SystemExit(f"[prompt] 语料为空，先运行 scripts/fetch_corpus.py --topic {a.topic}")

    classes, relations = L._render_schema(cfg)
    out = [HEADER.format(topic=a.topic, system=L.SYSTEM, classes=classes, relations=relations)]

    n = 0
    for doc in docs:
        for i, chunk in enumerate(L._chunk(doc["text"], a.chunk), 1):
            if n >= a.max_chunks:
                break
            n += 1
            out.append(f"\n===== 片段 {n}（doc={doc['doc_id']} #{i}）=====\n\n```\n{chunk}\n```\n")
        if n >= a.max_chunks:
            break
    out.append(FOOTER)

    path = S.repo_root() / "data" / "llm_output" / f"{a.topic}_prompt.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(out), encoding="utf-8")

    print(f"[prompt] 文档 {len(docs)} 篇 · 输出 {n} 个片段 -> {path}")
    print(f"[prompt] 本体注入：{len(cfg['ontology_seed']['classes'])} 类 / "
          f"{len(cfg['ontology_seed']['relations'])} 关系")
    print(f"[prompt] 下一步：把片段发给任意 LLM → 收集 JSON → "
          f"python -m kgc.llm --topic {a.topic} --from-file data/llm_output/{a.topic}_agent_llm.json")


if __name__ == "__main__":
    main()
