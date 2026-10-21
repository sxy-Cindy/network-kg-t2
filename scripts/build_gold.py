#!/usr/bin/env python3
"""构造金标准（topics/<topic>/gold.jsonl）。

金标准从**官方结构化字段**构造，而不是从任何抽取方法的输出里挑：
  * 漏洞→弱点：CVE problemTypes + NVD weaknesses + KEV cwes
  * 漏洞→产品：NVD configurations 的 CPE（与语料同一抽样口径）
  * 漏洞→KEV：KEV catalog 的 cveID
  * CWE→CAPEC：CWE XML Related_Attack_Patterns
  * CAPEC→ATT&CK：本项目分析师映射表（confidence 列已标注）
  * 技术→战术、子技术、uses、mitigates、Sigma detects：ATT&CK STIX / Sigma tags

**本脚本只依赖 kgc.t2_sources（数据装载层），不 import 方法 A**。方法 A 的结构化
通道读的是同一批官方字段，所以 A 的高分是"数据通道优势"，不是抽取能力；
B/C 只能从渲染后的文本里抽，三者对比才有意义。这一点写进评测报告的口径说明。

抽样：固定随机种子 20261021，分层抽样；每条都要求 label 在语料中字面出现，且在
**同一篇文档**里能同时找到头尾（否则跨文档的关系无法从单篇文本抽取）。

用法：
    python scripts/build_gold.py
    python scripts/check_gold.py --topic t2-cve-attack
"""
from __future__ import annotations

import csv
import json
import random
import sys
from pathlib import Path
from typing import Dict, List, Tuple

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from kgc import schema as S  # noqa: E402
from kgc import t2_sources as T  # noqa: E402

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:  # noqa: BLE001
    pass

TOPIC = "t2-cve-attack"
SEED = 20261021
RAW = ROOT / "data" / "raw"

# 全量金标准：实体/关系都取官方字段的**全部**可核对项，不抽样。
# 理由：抽样金标准的 precision 只是下界（抽 4 个 vendor 时，方法抽对 20 个也只算
# 4 个 TP），无法横向比较三种方法。全量参考集让 P/R/F1 都有明确口径；
# 抽检用的 30~60 条人工核对清单另存在 topics/<topic>/gold_sample.jsonl。
FULL = True

ENTITY_QUOTA = {}   # 空 = 不限制
REL_QUOTA = {}


def _official_graph() -> Tuple[List[dict], List[dict]]:
    """从官方字段直接构造 (实体, 关系)，与任何抽取方法的代码路径无关。"""
    cves = T.load_cves(RAW)
    attack = T.load_attack(RAW)
    cwe = T.load_cwe(RAW)
    capec = T.load_capec(RAW)
    kev = T.load_kev(RAW)

    tids = T.technique_ids_for(attack)
    cwes = T.selected_cwes(cves, kev)
    capecs = T.selected_capecs(cwes, cwe, capec)
    sigma = T.load_sigma(RAW, technique_ids=tids, per_technique=2)

    ents: Dict[str, dict] = {}
    rels: List[dict] = []

    def ent(eid: str, label: str, etype: str) -> None:
        ents.setdefault(eid, {"id": eid, "label": S.norm_label(label), "type": etype})

    def rel(src: str, r: str, dst: str) -> None:
        rels.append({"source": src, "relation": r, "target": dst})

    # ---- 漏洞 / 弱点 / 产品 / 厂商 / KEV ---------------------------------- #
    for c in cves:
        ent(f"cve:{c['id']}", c["id"], "Vulnerability")
        for w in c["cwes"]:
            ent(f"cwe:{w}", w, "Weakness")
            rel(f"cve:{c['id']}", "has_weakness", f"cwe:{w}")
        for x in c["cpes"]:
            p = T.parse_cpe(x["cpe"])
            if not p:
                continue
            ent(x["cpe"], x["cpe"], "Product")
            rel(f"cve:{c['id']}", "affects_product", x["cpe"])
            if p["vendor"] not in ("", "*", "-"):
                ent(f"vendor:{p['vendor']}", p["vendor"], "Vendor")
                rel(x["cpe"], "produced_by", f"vendor:{p['vendor']}")
        if c.get("kev"):
            ent(f"kev:{c['id']}", f"KEV entry for {c['id']}", "ExploitationRecord")
            rel(f"cve:{c['id']}", "known_exploited", f"kev:{c['id']}")

    # ---- CWE -> CAPEC ----------------------------------------------------- #
    for cid in cwes:
        w = cwe["by_id"].get(cid) or {}
        for ap in (w.get("related_attack_patterns") or [])[:6]:
            if ap not in capecs:
                continue
            ent(f"capec:{ap}", ap, "AttackPattern")
            rel(f"cwe:{cid}", "relates_to_pattern", f"capec:{ap}")
    for cid in capecs:
        ent(f"capec:{cid}", cid, "AttackPattern")

    # ---- CAPEC -> ATT&CK（分析师映射表） ---------------------------------- #
    cross = ROOT / "topics" / TOPIC / "capec_attck_crosswalk.csv"
    if cross.exists():
        with cross.open(encoding="utf-8-sig", newline="") as fh:
            for row in csv.DictReader(fh):
                cap, tid = (row.get("capec_id") or "").strip(), (row.get("technique_id") or "").strip()
                if cap and tid in tids:
                    ent(f"attck:{tid}", tid, "Technique")
                    rel(f"capec:{cap}", "implemented_by", f"attck:{tid}")

    # ---- ATT&CK 技术 / 战术 / 子技术 -------------------------------------- #
    for tid in tids:
        o = attack["by_ext"][tid]
        ent(f"attck:{tid}", tid, "Technique")
        for ta in T.technique_tactics(attack, o):
            ent(f"tactic:{ta}", ta, "Tactic")
            rel(f"attck:{tid}", "belongs_to_tactic", f"tactic:{ta}")
        parent = next((r for r in attack["relationships"]
                       if r.get("relationship_type") == "subtechnique-of"
                       and r.get("source_ref") == o.get("id")), None)
        if parent:
            p = attack["by_stix"].get(parent.get("target_ref")) or {}
            pe = T._ext_id(p)
            if pe and pe in tids:
                rel(f"attck:{tid}", "subtechnique_of", f"attck:{pe}")

    # ---- 组织 / 软件 / 缓解 ---------------------------------------------- #
    def top_sources(types, limit):
        edges = T.attack_uses_edges(attack, types, tids)
        by_src: Dict[str, List[dict]] = {}
        for e in edges:
            by_src.setdefault(e["source"], []).append(e)
        return sorted(by_src.items(), key=lambda kv: (-len(kv[1]), kv[0]))[:limit]

    for gid, edges in top_sources(("intrusion-set",), 14):
        ent(f"attck:{gid}", gid, "Group")
        for e in edges[:8]:
            rel(f"attck:{gid}", "group_uses", f"attck:{e['target']}")

    for sid, edges in top_sources(("malware", "tool"), 14):
        ent(f"attck:{sid}", sid, "Software")
        for e in edges[:6]:
            rel(f"attck:{sid}", "software_uses", f"attck:{e['target']}")

    by_m: Dict[str, List[dict]] = {}
    for e in T.attack_mitigates_edges(attack, tids):
        by_m.setdefault(e["source"], []).append(e)
    for mid, es in sorted(by_m.items(), key=lambda kv: (-len(kv[1]), kv[0]))[:20]:
        ent(f"attck:{mid}", mid, "Mitigation")
        for e in es[:6]:
            rel(f"attck:{mid}", "mitigates", f"attck:{e['target']}")

    # ---- Sigma 检测规则 --------------------------------------------------- #
    for r in sigma:
        ent(f"sigma:{r['id']}", r["id"], "DetectionRule")
        for t in r["techniques"]:
            rel(f"sigma:{r['id']}", "detects", f"attck:{t}")

    return list(ents.values()), rels


def main() -> int:
    cfg = S.load_topic(TOPIC)
    docs = S.load_corpus(cfg)
    corpus = {d["doc_id"]: d["text"].lower() for d in docs}
    rng = random.Random(SEED)

    ents, rels = _official_graph()
    label = {e["id"]: e["label"] for e in ents}
    etype = {e["id"]: e["type"] for e in ents}

    # entity id -> 出现它的文档集合（标签字面量、忽略大小写）
    where: dict[str, list[str]] = {}
    for e in ents:
        where.setdefault(e["id"], [])
        for doc_id, text in corpus.items():
            if e["label"].lower() in text and doc_id not in where[e["id"]]:
                where[e["id"]].append(doc_id)

    rows: list[dict] = []

    # ---- 实体抽样 ---------------------------------------------------------- #
    by_type: dict[str, list[str]] = {}
    for e in ents:
        if where.get(e["id"]):
            by_type.setdefault(e["type"], []).append(e["id"])
    for t, quota in (ENTITY_QUOTA or {t: None for t in sorted(by_type)}).items():
        ids = sorted(set(by_type.get(t, [])))
        if not ids:
            print(f"[gold] ⚠ 类型 {t} 在官方字段里没有可用实体")
            continue
        picked = ids if quota is None or len(ids) <= quota else rng.sample(ids, quota)
        for eid in sorted(picked):
            rows.append({"type": etype[eid], "label": label[eid],
                         "doc": where[eid][0], "source": "structured"})

    # ---- 关系抽样 ---------------------------------------------------------- #
    by_rel: dict[str, list] = {}
    for r in rels:
        h, t = r["source"], r["target"]
        if h not in label or t not in label:
            continue
        common = [d for d in where.get(h, []) if d in where.get(t, [])]
        if not common:
            continue  # 头尾不在同一篇文档，单篇文本无法支撑，不能进金标准
        by_rel.setdefault(r["relation"], []).append((h, t, common[0]))

    for rel_name, quota in (REL_QUOTA or {k: None for k in sorted(by_rel)}).items():
        cands = sorted(set(by_rel.get(rel_name, [])))
        if not cands:
            print(f"[gold] ⚠ 关系 {rel_name} 没有可用候选")
            continue
        picked = cands if quota is None or len(cands) <= quota else rng.sample(cands, quota)
        for h, t, doc_id in sorted(picked):
            rows.append({"head": label[h], "head_type": etype[h],
                         "relation": rel_name,
                         "tail": label[t], "tail_type": etype[t],
                         "doc": doc_id, "source": "structured"})

    out = ROOT / "topics" / TOPIC / "gold.jsonl"
    out.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in rows) + "\n",
                   encoding="utf-8")

    # 人工抽检清单：从全量里分层抽 35 实体 + 25 关系，答辩时逐条对原文
    srng = random.Random(SEED + 1)
    e_rows = [r for r in rows if "label" in r]
    r_rows = [r for r in rows if "relation" in r]
    sample = (srng.sample(e_rows, min(35, len(e_rows)))
              + srng.sample(r_rows, min(25, len(r_rows))))
    sp = ROOT / "topics" / TOPIC / "gold_sample.jsonl"
    sp.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in sample) + "\n",
                  encoding="utf-8")

    n_ent = sum(1 for r in rows if "label" in r)
    print(f"[gold] {len(rows)} 行（实体 {n_ent} · 关系 {len(rows) - n_ent}）-> {out}")
    print(f"[gold] 人工抽检 {len(sample)} 行 -> {sp}")
    print("[gold] 关系分布：" + ", ".join(f"{k}={v}" for k, v in
                                       sorted({r['relation']: sum(1 for x in rows
                                                                  if x.get('relation') == r['relation'])
                                               for r in rows if 'relation' in r}.items())))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
