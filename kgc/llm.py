"""阶段二 · 方法 C：LLM 抽取（schema-constrained prompting）。

三种可复现路径，按算力/合规条件选一：

  1. `--endpoint` 调用 OpenAI 兼容 HTTP 接口（本地 Ollama / vLLM / 云端均可）：
         KGC_LLM_BASE_URL=http://localhost:11434/v1
         KGC_LLM_API_KEY=ollama
         KGC_LLM_MODEL=qwen2.5:7b-instruct
  2. `--from-file <json>` **离线导入**：把任何 LLM（含 Intellect Agent 本体、
     GPT/DeepSeek/GLM）按本脚本 prompt 产出的 JSON 直接灌进来。教学环境下
     API 不可用时用这条路径，结果同样可复现、可评测。
  3. `--use-cache`：复用 data/llm_cache/<topic>/<doc>.json 的历史输出。

工程要点（这些是验收点，不是可选项）：
  * **本体注入**：prompt 里给出类、关系的 ID/中文名/定义，抽取结果必须落在
    本体词汇内，越界即丢弃并计入 `rejected.out_of_schema`。
  * **证据回填**：每条三元组必须带 `evidence`（原文片段），用于人工抽检与幻觉率统计。
  * **JSON 校验**：LLM 输出经常带 markdown 围栏、注释、尾随逗号；本模块统一清洗后
    再 json.loads，失败即计入 `rejected.parse_error`，不静默丢弃。
  * **零样本 vs 少样本**：配置 `few_shot` 示例可对比两种 prompt 的 F1。
"""

from __future__ import annotations

import json
import os
import re
from typing import Dict, List

from . import rule as rule_mod
from . import schema as S

SYSTEM = "你是知识图谱抽取器。只输出 JSON，不要解释、不要 markdown 代码块。"

PROMPT_TMPL = """从给定网络工程文本中抽取实体与关系，严格使用下面的本体词汇。

【本体类】(id | 中文 | 定义)
{classes}

【关系】(id | 中文 | 定义 | 头类 -> 尾类)
{relations}

【输出 JSON 结构】
{{
  "entities": [{{"id": "类:id后缀", "label": "表面形式", "type": "类名"}}],
  "relations": [{{"source": "实体id", "relation": "关系名", "target": "实体id",
                  "evidence": "支撑该关系的原文片段"}}]
}}

规则：
1. type 必须是上面的类 id；relation 必须是上面的关系 id，否则不要输出该条。
2. id 用 `类名:标签` 形式，同一实体在不同句子中用同一 id。
3. evidence 必须是原文中的连续片段（不超过 120 字），不得改写。
4. 只抽取文本中明确出现的事实，不做推理延伸。

【文本】
{text}
"""


def _render_schema(cfg: dict) -> tuple[str, str]:
    seed = cfg["ontology_seed"]
    classes = "\n".join(
        f"- {c['id']} | {c['label']} | {c.get('definition', '')}" for c in seed.get("classes", [])
    )
    rels = "\n".join(
        f"- {r['id']} | {r['label']} | {r.get('definition', '')} | "
        f"{r.get('domain', '?')} -> {r.get('range', '?')}"
        for r in seed.get("relations", [])
    )
    return classes, rels


def build_prompt(cfg: dict, text: str) -> str:
    classes, rels = _render_schema(cfg)
    return PROMPT_TMPL.format(classes=classes, relations=rels, text=text[:6000])


def _strip_fences(raw: str) -> str:
    raw = raw.strip()
    raw = re.sub(r"^```(?:json)?", "", raw).strip()
    raw = re.sub(r"```$", "", raw).strip()
    start, end = raw.find("{"), raw.rfind("}")
    if start >= 0 and end > start:
        raw = raw[start:end + 1]
    raw = re.sub(r",\s*([}\]])", r"\1", raw)          # 尾随逗号
    raw = re.sub(r"//[^\n]*", "", raw)                 # 行注释
    return raw


def parse_and_validate(cfg: dict, doc_id: str, raw: str) -> tuple[List[S.Entity], List[S.Relation], dict]:
    """清洗 + 解析 + 本体校验。返回 (entities, relations, rejected 统计)。"""
    known_classes = {c["id"] for c in cfg["ontology_seed"].get("classes", [])}
    known_rels = {r["id"] for r in cfg["ontology_seed"].get("relations", [])}
    rejected = {"parse_error": 0, "out_of_schema": 0, "missing_evidence": 0}
    try:
        data = json.loads(_strip_fences(raw))
    except Exception:
        rejected["parse_error"] += 1
        return [], [], rejected

    ents: List[S.Entity] = []
    id2type: Dict[str, str] = {}
    for e in data.get("entities", []) or []:
        etype = str(e.get("type", "")).strip()
        label = S.norm_label(str(e.get("label") or e.get("id") or ""))
        if etype not in known_classes or not label:
            rejected["out_of_schema"] += 1
            continue
        eid = str(e.get("id") or S.make_id(etype, label)).strip()
        id2type[eid] = etype
        ents.append(S.Entity(id=eid, label=label, type=etype, doc=doc_id, method="llm"))

    rels: List[S.Relation] = []
    for r in data.get("relations", []) or []:
        rid = str(r.get("relation", "")).strip()
        s_id, t_id = str(r.get("source", "")).strip(), str(r.get("target", "")).strip()
        if rid not in known_rels or not s_id or not t_id:
            rejected["out_of_schema"] += 1
            continue
        ev = S.norm_label(str(r.get("evidence", "")))
        if not ev:
            rejected["missing_evidence"] += 1
        rels.append(S.Relation(source=s_id, relation=rid, target=t_id, doc=doc_id,
                               evidence=ev[:200], method="llm"))
    return ents, rels, rejected


def call_endpoint(prompt: str, cfg: dict) -> str:
    import requests

    base = os.environ.get("KGC_LLM_BASE_URL", "http://localhost:11434/v1").rstrip("/")
    model = os.environ.get("KGC_LLM_MODEL", "qwen2.5:7b-instruct")
    key = os.environ.get("KGC_LLM_API_KEY", "not-needed")
    resp = requests.post(
        f"{base}/chat/completions",
        headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
        json={
            "model": model,
            "messages": [{"role": "system", "content": SYSTEM},
                         {"role": "user", "content": prompt}],
            "temperature": 0,
            "response_format": {"type": "json_object"},
        },
        timeout=120,
    )
    resp.raise_for_status()
    return resp.json()["choices"][0]["message"]["content"]


def _cache_path(topic: str, doc_id: str):
    return S.repo_root() / "data" / "llm_cache" / topic / f"{doc_id}.json"


def run(topic: str, from_file: str | None = None, use_cache: bool = False,
        chunk_chars: int = 4000, verbose: bool = True) -> dict:
    cfg = S.load_topic(topic)
    docs = S.load_corpus(cfg)
    ents: List[S.Entity] = []
    rels: List[S.Relation] = []
    rejected = {"parse_error": 0, "out_of_schema": 0, "missing_evidence": 0}
    sources: Dict[str, str] = {}

    external: Dict[str, str] = {}
    if from_file:
        payload = S.read_json(from_file)
        if isinstance(payload, dict) and "docs" in payload:
            external = {d["doc_id"]: json.dumps(d, ensure_ascii=False) for d in payload["docs"]}
        elif isinstance(payload, dict):
            external = {k: json.dumps(v, ensure_ascii=False) for k, v in payload.items()}
        elif isinstance(payload, list):
            for item in payload:
                external[str(item.get("doc_id", ""))] = json.dumps(item, ensure_ascii=False)

    for doc in docs:
        if external:
            raw = external.get(doc["doc_id"], '{"entities":[],"relations":[]}')
            sources[doc["doc_id"]] = "from-file"
        elif use_cache and _cache_path(topic, doc["doc_id"]).exists():
            raw = _cache_path(topic, doc["doc_id"]).read_text(encoding="utf-8")
            sources[doc["doc_id"]] = "cache"
        else:
            # 按句窗口分块，避免超长文本被截断（截断会静默丢实体，是最常见的坑）
            chunks = _chunk(doc["text"], chunk_chars)
            pieces = []
            for ch in chunks:
                out = call_endpoint(build_prompt(cfg, ch), cfg)
                _cache_path(topic, doc["doc_id"]).parent.mkdir(parents=True, exist_ok=True)
                pieces.append(out)
            _cache_path(topic, doc["doc_id"]).write_text("\n".join(pieces), encoding="utf-8")
            raw = _merge_chunks(pieces)
            sources[doc["doc_id"]] = "endpoint"

        e, r, rej = parse_and_validate(cfg, doc["doc_id"], raw)
        ents.extend(e)
        rels.extend(r)
        for k in rejected:
            rejected[k] += rej[k]

    payload = {
        "topic": topic, "method": "llm",
        "backend": os.environ.get("KGC_LLM_MODEL", "from-file" if from_file else "endpoint"),
        "sources": sources,
        "entity_count": len(ents), "relation_count": len(rels),
        "entities": S.entities_to_json(ents), "relations": S.relations_to_json(rels),
        "rejected": rejected,
        "unknown_types": S.require_known_types(cfg, ents),
        "unknown_relations": S.require_known_relations(cfg, rels),
    }
    path = S.write_json(S.out_dir("extraction", topic) / f"{topic}_llm.json", payload)
    if verbose:
        print(f"[llm] 实体 {len(ents)} · 关系 {len(rels)} · 拒绝 {rejected} -> {path}")
        print(f"[llm] 证据缺失率 = {rejected['missing_evidence']}/{len(rels) or 1}"
              f"  越界率 = {rejected['out_of_schema']}")
    return payload


def _chunk(text: str, size: int) -> List[str]:
    sents = [s for _, _, s in rule_mod.split_sentences(text)]
    chunks, cur = [], ""
    for s in sents:
        if len(cur) + len(s) > size and cur:
            chunks.append(cur)
            cur = ""
        cur += s + " "
    if cur:
        chunks.append(cur)
    return chunks or [text[:size]]


def _merge_chunks(pieces: List[str]) -> str:
    merged = {"entities": [], "relations": []}
    for p in pieces:
        try:
            d = json.loads(_strip_fences(p))
        except Exception:
            continue
        merged["entities"].extend(d.get("entities", []) or [])
        merged["relations"].extend(d.get("relations", []) or [])
    return json.dumps(merged, ensure_ascii=False)


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="阶段二·方法C：LLM 抽取（本体约束）")
    ap.add_argument("--topic", required=True)
    ap.add_argument("--from-file", default=None, help="离线导入 LLM 输出的 JSON")
    ap.add_argument("--use-cache", action="store_true")
    a = ap.parse_args()
    run(a.topic, a.from_file, a.use_cache)
