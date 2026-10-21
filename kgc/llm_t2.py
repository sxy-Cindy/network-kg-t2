"""阶段二 · 方法 C：LLM 抽取（本体约束 + 证据回填），面向题目二。

与脚手架 ``kgc.llm`` 的差别，都是题目二验收点直接要求的：

1. **官方 ID 对齐**：prompt 明确要求 CVE/CWE/CAPEC/T/TA/G/S/M/CPE/Sigma UUID
   原样抄写，禁止自造编号；模型返回的标签再经 ``IdResolver`` 归一到官方主键。
2. **证据可核验**：每条关系的 evidence 必须是原文连续片段。落盘时逐条做子串校验，
   并把 `evidence_verified=false` 的条目标记为**幻觉候选**，用于“单方法 vs 融合”的
   幻觉率对比（不是只让模型自己保证）。
3. **本体约束**：类/关系必须在 ontology.json 内；关系两端还要通过 domain/range
   （含继承展开）校验，违规条目计数后丢弃。
4. **分块不切断记录**：按空行切块再按 3000 字聚合，避免把一条 CVE 记录（漏洞→CPE→KEV）
   切到两个 prompt 里，导致关系缺头少尾。
5. **缓存与并发**：每个块一个缓存文件，失败重试；多线程调用，可断点续跑。

输出：data/extraction/<topic>_llm.json
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Tuple

import requests

from . import ids as I
from . import schema as S

MODEL = os.environ.get("KGC_LLM_MODEL", os.environ.get("ANTHROPIC_MODEL", ""))
BASE = os.environ.get("ANTHROPIC_BASE_URL", "").rstrip("/")
MAX_CHARS = 3000
WORKERS = 4
RETRIES = 4

SYSTEM = ("你是网络安全知识图谱抽取器。只输出 JSON 对象，不要 markdown、不要解释。"
          "所有事实必须能在给定文本中逐字找到依据。")

PROMPT = """从下面的网络安全情报文本中抽取实体与关系。严格使用给定本体。

【本体类】(id | 名称 | 定义)
{classes}

【关系】(id | 名称 | 头类 -> 尾类)
{relations}

【编号规则 —— 必须遵守】
- 漏洞 CVE-YYYY-NNNN、弱点 CWE-N、攻击模式 CAPEC-N、技术 T#### 或 T####.###、
  战术 TA####、组织 G####、软件 S####、缓解 M####、CPE 2.3 URI、Sigma 规则 UUID：
  **原样抄写正文里的编号**，绝不能自造或补全。
- 正文只给名称、没有编号时，label 用正文名称（例如 PowerShell），id 留空字符串。
- 同一实体在本次输出内只出现一次，用 key 引用。

【输出 JSON】
{{"entities":[{{"key":"e1","type":"类id","label":"原文名称或官方编号","id":"官方编号或空"}}],
  "relations":[{{"source":"e1","relation":"关系id","target":"e2","evidence":"原文连续片段"}}]}}

抽取规则：
1. 只抽文本中**明确陈述**的事实；不推理、不补全、不引用外部知识。
2. evidence 必须是原文中逐字出现的连续片段（<=120 字），不得改写、不得翻译。
3. 关系两端必须是上面 entities 里的 key；type/relation 必须用本体 id。
4. 没有可抽内容就输出 {{"entities":[],"relations":[]}}。

【文本】
{text}
"""


def _render_schema(cfg: dict) -> Tuple[str, str]:
    seed = cfg["ontology_seed"]
    classes = "\n".join(f"- {c['id']} | {c.get('label', '')} | {c.get('definition', '')}"
                        for c in seed.get("classes", []))
    rels = "\n".join(f"- {r['id']} | {r.get('label', '')} | "
                     f"{r.get('domain') or '?'} -> {r.get('range') or '?'}"
                     for r in seed.get("relations", []))
    return classes, rels


def build_prompt(cfg: dict, text: str) -> str:
    classes, rels = _render_schema(cfg)
    return PROMPT.format(classes=classes, relations=rels, text=text)


# --------------------------------------------------------------------------- #
# HTTP
# --------------------------------------------------------------------------- #
def _key() -> str:
    return (os.environ.get("KGC_LLM_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN")
            or os.environ.get("ANTHROPIC_API_KEY") or "")


def _response_cache(prompt: str, system: str):
    """按 (endpoint, model, system, prompt) 缓存原始回答。

    抽取阶段已有逐块缓存；这里补的是**问答/基线**调用——否则同一份报告
    每次重跑都会因模型非确定性得到不同的句子数，指标无法复现。
    设置 KGC_LLM_NO_CACHE=1 可强制重新请求。
    """
    if os.environ.get("KGC_LLM_NO_CACHE"):
        return None
    key = hashlib.sha256(
        f"{BASE}\0{MODEL}\0{system}\0{prompt}".encode("utf-8")).hexdigest()
    return S.repo_root() / "data" / "llm_cache" / "_responses" / f"{key}.json"


def call_llm(prompt: str, system: str = SYSTEM) -> Tuple[str, dict]:
    cache = _response_cache(prompt, system)
    if cache is not None and cache.exists():
        try:
            hit = json.loads(cache.read_text(encoding="utf-8"))
            if hit.get("text", "").strip():
                usage = dict(hit.get("usage") or {})
                usage["cached"] = 1
                return hit["text"], usage
        except Exception:  # noqa: BLE001  缓存坏了就重新请求
            pass
    url = f"{BASE}/v1/messages"
    headers = {
        "x-api-key": _key(),
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
    }
    body = {"model": MODEL, "max_tokens": 8000, "temperature": 0,
            "system": system,
            "messages": [{"role": "user", "content": prompt}]}
    last: Exception | None = None
    for attempt in range(RETRIES):
        try:
            r = requests.post(url, headers=headers, json=body, timeout=240)
            if r.status_code in (429, 500, 502, 503, 504):
                raise RuntimeError(f"HTTP {r.status_code}: {r.text[:200]}")
            r.raise_for_status()
            data = r.json()
            text = "".join(b.get("text", "") for b in data.get("content", [])
                           if b.get("type") == "text")
            if not text.strip():
                raise RuntimeError("空响应（只有 thinking，没有 text 块）")
            usage = data.get("usage", {}) or {}
            if cache is not None:
                cache.parent.mkdir(parents=True, exist_ok=True)
                cache.write_text(json.dumps(
                    {"text": text, "usage": usage, "model": MODEL},
                    ensure_ascii=False), encoding="utf-8")
            return text, usage
        except Exception as exc:  # noqa: BLE001
            last = exc
            time.sleep(2 ** attempt)
    raise RuntimeError(f"LLM 调用失败：{last}")


# --------------------------------------------------------------------------- #
# 分块 / 解析 / 校验
# --------------------------------------------------------------------------- #
def chunk_doc(text: str, max_chars: int = MAX_CHARS) -> List[str]:
    """按空行切块再聚合。语料里一条记录就是一个 block，聚合时不跨记录切断。"""
    blocks = [b.strip() for b in re.split(r"\n\s*\n", text) if b.strip()]
    chunks: List[str] = []
    cur: List[str] = []
    size = 0
    for b in blocks:
        if size + len(b) > max_chars and cur:
            chunks.append("\n\n".join(cur))
            cur, size = [], 0
        cur.append(b)
        size += len(b) + 2
    if cur:
        chunks.append("\n\n".join(cur))
    return chunks or [text[:max_chars]]


def _strip(raw: str) -> str:
    raw = (raw or "").strip()
    raw = re.sub(r"^```(?:json)?", "", raw).strip()
    raw = re.sub(r"```$", "", raw).strip()
    a, b = raw.find("{"), raw.rfind("}")
    if a >= 0 and b > a:
        raw = raw[a:b + 1]
    raw = re.sub(r",\s*([}\]])", r"\1", raw)
    return raw


def _norm_ws(s: str) -> str:
    return re.sub(r"\s+", " ", s or "").strip().lower()


def parse_chunk(cfg: dict, resolver: I.IdResolver, doc_id: str, raw: str,
                chunk_text: str) -> Tuple[List[S.Entity], List[S.Relation], dict]:
    known_classes = {c["id"] for c in cfg["ontology_seed"].get("classes", [])}
    known_rels = {r["id"] for r in cfg["ontology_seed"].get("relations", [])}
    st = {"parse_error": 0, "out_of_schema": 0, "bad_ref": 0,
          "missing_evidence": 0, "entity_unverified": 0, "relation_unverified": 0,
          "domain_range": 0}
    try:
        data = json.loads(_strip(raw))
    except Exception:
        st["parse_error"] += 1
        return [], [], st

    text_norm = _norm_ws(chunk_text)
    ents: List[S.Entity] = []
    by_key: Dict[str, S.Entity] = {}
    doc_keys: set = set()
    for e in data.get("entities", []) or []:
        etype = str(e.get("type", "")).strip()
        # 句末标点会被模型带进标签（"cpe:...,"），先剥掉再做编号校验
        label = S.norm_label(str(e.get("label", "")).strip()).rstrip(" ,;.")
        surface = label
        if etype == "Document":
            # 文档节点由流水线按 doc_id 统一生成，LLM 不需要抽；不参与方法对齐
            doc_keys.add(str(e.get("key", "")).strip())
            continue
        if etype not in known_classes or not label:
            st["out_of_schema"] += 1
            continue
        # Malware/Tool 是 Software 的子类；方法 A/B 只能看到 S#### 编号，
        # 统一落在父类 Software 下，子类信息留在属性里，融合才能对齐。
        fine_type = etype
        if etype in ("Malware", "Tool"):
            etype = "Software"
        # LLM 给的 id 字段经常比 label 更准确（label 写名称、id 写编号）。只要它确实是
        # 该类合法编号，就用它作为规范标签与主键——这样与 A/B 的官方 ID 标签对齐。
        llm_id = str(e.get("id", "")).strip().rstrip(" ,;.")
        official = resolver.official(etype, llm_id)
        if not official and ":" in llm_id:
            official = resolver.official(etype, llm_id.split(":", 1)[1])
        if official:
            eid, label = resolver.canonical(etype, official), official
        else:
            hit = resolver.lookup(etype, label)
            if hit:
                eid, label = hit
            else:
                eid = resolver.canonical(etype, label)
        verified = _norm_ws(label) in text_norm or _norm_ws(str(e.get("label", ""))) in text_norm
        if not verified:
            st["entity_unverified"] += 1
        ent = S.Entity(id=eid, label=label, type=etype, doc=doc_id, method="llm",
                       evidence=S.norm_label(str(e.get("id", "")))[:120],
                       properties={"llm_id": str(e.get("id", "")).strip(),
                                   "llm_type": fine_type,
                                   "surface": surface,
                                   "label_verified": verified})
        ents.append(ent)
        key = str(e.get("key", "")).strip() or eid
        by_key[key] = ent

    rels: List[S.Relation] = []
    for r in data.get("relations", []) or []:
        rid = str(r.get("relation", "")).strip()
        s_key, t_key = str(r.get("source", "")).strip(), str(r.get("target", "")).strip()
        if rid not in known_rels:
            st["out_of_schema"] += 1
            continue
        if s_key in doc_keys or t_key in doc_keys:
            continue
        h, t = by_key.get(s_key), by_key.get(t_key)
        if h is None or t is None:
            st["bad_ref"] += 1
            continue
        ev = S.norm_label(str(r.get("evidence", "")))
        verified = bool(ev) and _norm_ws(ev) in text_norm
        if not ev:
            st["missing_evidence"] += 1
        elif not verified:
            st["relation_unverified"] += 1
        rels.append(S.Relation(source=h.id, relation=rid, target=t.id, doc=doc_id,
                               evidence=ev[:200], method="llm",
                               properties={"evidence_verified": verified}))
    return ents, rels, st


# --------------------------------------------------------------------------- #
# 主流程
# --------------------------------------------------------------------------- #
def _cache_dir(topic: str):
    d = S.repo_root() / "data" / "llm_cache" / topic
    d.mkdir(parents=True, exist_ok=True)
    return d


def _jobs(cfg: dict, docs: List[dict]) -> List[dict]:
    jobs = []
    for doc in docs:
        for i, ch in enumerate(chunk_doc(doc["text"])):
            jobs.append({"doc_id": doc["doc_id"], "idx": i, "text": ch,
                         "prompt": build_prompt(cfg, ch)})
    return jobs


def run(topic: str, limit: int | None = None, force: bool = False,
        workers: int = WORKERS, verbose: bool = True) -> dict:
    cfg = S.load_topic(topic)
    docs = S.load_corpus(cfg)
    if not BASE or not _key():
        raise SystemExit("[llm] 未配置 ANTHROPIC_BASE_URL / AUTH_TOKEN")
    jobs = _jobs(cfg, docs)
    if limit:
        jobs = jobs[:limit]

    cache = _cache_dir(topic)
    tokens = {"input_tokens": 0, "output_tokens": 0}

    def usable(raw: str) -> bool:
        try:
            json.loads(_strip(raw))
            return True
        except Exception:
            return False

    def work(job: dict) -> Tuple[dict, str, dict]:
        path = cache / f"{job['doc_id']}__{job['idx']:02d}.json"
        if path.exists() and not force:
            raw = path.read_text(encoding="utf-8")
            if raw.strip() and usable(raw):
                return job, raw, {"cached": 1}
            # 空文件/截断 JSON 视为无效缓存，自动重试（不要求人工删缓存）
        text, usage = call_llm(job["prompt"])
        path.write_text(text, encoding="utf-8")
        return job, text, usage

    outputs: Dict[Tuple[str, int], str] = {}
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = [pool.submit(work, j) for j in jobs]
        for n, fut in enumerate(as_completed(futs), 1):
            job, text, usage = fut.result()
            outputs[(job["doc_id"], job["idx"])] = text
            for k in tokens:
                tokens[k] += int(usage.get(k, 0) or 0)
            if verbose and n % 10 == 0:
                print(f"[llm] {n}/{len(jobs)} 块完成")

    resolver = I.IdResolver.from_cfg(cfg)
    chunk_of = {(j["doc_id"], j["idx"]): j["text"] for j in jobs}
    ents: List[S.Entity] = []
    rels: List[S.Relation] = []
    rejected = {"parse_error": 0, "out_of_schema": 0, "bad_ref": 0,
                "missing_evidence": 0, "entity_unverified": 0,
                "relation_unverified": 0, "domain_range": 0}
    per_doc: Dict[str, dict] = {}
    n_ent_mentions = 0
    for (doc_id, idx), raw in sorted(outputs.items()):
        e, r, st = parse_chunk(cfg, resolver, doc_id, raw, chunk_of[(doc_id, idx)])
        ents.extend(e)
        rels.extend(r)
        n_ent_mentions += len(e)
        for k in rejected:
            rejected[k] += st.get(k, 0)
        d = per_doc.setdefault(doc_id, {"entities": 0, "relations": 0})
        d["entities"] += len(e)
        d["relations"] += len(r)

    # 实体按 (id, doc) 合并；关系去重（同一条事实只留一条证据）
    ents = list({(e.id, e.doc): e for e in ents}.values())
    rels = list({(r.source, r.relation, r.target, r.doc): r for r in rels}.values())
    # 本体 domain/range 校验（含继承展开），违规关系丢弃
    rels, dropped = _drop_bad_domain_range(cfg, ents, rels)
    rejected["domain_range"] += dropped

    n_rel = len(rels)
    n_ev_ok = sum(1 for r in rels if r.properties.get("evidence_verified"))
    payload = {
        "topic": topic, "method": "llm",
        "backend": {"base_url": BASE, "model": MODEL, "protocol": "anthropic.messages"},
        "chunks": len(jobs), "tokens": tokens,
        "entity_count": len(ents), "relation_count": n_rel,
        "evidence_verified": n_ev_ok,
        "hallucination": {
            "definition": "关系证据不是原文连续片段，或实体名称不在原文中出现",
            "relation_rate": round(1 - n_ev_ok / n_rel, 4) if n_rel else 0.0,
            "entity_rate": round(rejected["entity_unverified"] /
                                 max(1, n_ent_mentions), 4),
        },
        "rejected": rejected, "per_doc": per_doc,
        "entities": S.entities_to_json(ents), "relations": S.relations_to_json(rels),
        "unknown_types": S.require_known_types(cfg, ents),
        "unknown_relations": S.require_known_relations(cfg, rels),
    }
    path = S.write_json(S.out_dir("extraction", topic) / f"{topic}_llm.json", payload)
    if verbose:
        print(f"[llm] 块 {len(jobs)} · 实体 {len(ents)} · 关系 {n_rel} · "
              f"证据核验 {n_ev_ok}/{n_rel} -> {path}")
        print(f"[llm] 拒绝统计 {rejected} · tokens {tokens}")
    return payload


def _drop_bad_domain_range(cfg: dict, ents: List[S.Entity],
                           rels: List[S.Relation]) -> Tuple[List[S.Relation], int]:
    """逐条按 domain/range 校验（schema.check_domain_range 返回的是 label，不便反查 id）。"""
    parents = {c["id"]: c.get("parent") for c in cfg["ontology_seed"].get("classes", [])}

    def is_a(cls: str, want: str) -> bool:
        seen = set()
        cur = cls
        while cur and cur not in seen:
            if cur == want:
                return True
            seen.add(cur)
            cur = parents.get(cur)
        return False

    spec = {r["id"]: (r["domain"], r["range"]) for r in cfg["ontology_seed"].get("relations", [])
            if r.get("domain") and r.get("range")}
    by_id = {e.id: e for e in ents}
    kept, dropped = [], 0
    for r in rels:
        want = spec.get(r.relation)
        if not want:
            kept.append(r)
            continue
        h, t = by_id.get(r.source), by_id.get(r.target)
        if h is None or t is None:
            dropped += 1
            continue
        if is_a(h.type, want[0]) and is_a(t.type, want[1]):
            kept.append(r)
        else:
            dropped += 1
    return kept, dropped


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="阶段二·方法C：LLM 抽取（本体约束+证据）")
    ap.add_argument("--topic", required=True)
    ap.add_argument("--limit", type=int, default=None, help="只跑前 N 块（联调用）")
    ap.add_argument("--force", action="store_true", help="忽略缓存重新调用")
    ap.add_argument("--workers", type=int, default=WORKERS)
    a = ap.parse_args()
    run(a.topic, a.limit, a.force, a.workers)
