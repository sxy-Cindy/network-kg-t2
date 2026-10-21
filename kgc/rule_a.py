"""阶段二 · 方法 A（完整版）：正则/词典 + 结构化映射。

脚手架自带的 ``kgc.rule`` 只做正则与词表，能抽“正文里写出来的编号”。但本选题的一多半
关系并不以文字形式出现：
  * 漏洞→弱点：CVE 记录里只写 “The root cause of CVE-... is CWE-77”，可以正则；
  * 漏洞→产品：NVD 的 configurations 是机器字段，正文里只有 CPE 串，可以正则；
  * 漏洞→KEV 记录：KEV 条目在正文里没有 ID，“The KEV entry for CVE-x” 是渲染出来的，
    真实 API 里只有 cveID 字段 → 纯正则抽不到；
  * 产品→厂商：CPE 的 vendor 段是结构字段，没有独立文字表述。

因此方法 A 的完整版 = 正则/词典（kgc.rule） + 官方字段的结构化映射（本模块）。
两者都是“规则驱动、零训练、可解释”，合起来才是公平的方法 A；只跑正则可以作为消融实验，
用来量化“结构化映射到底贡献了多少”。

输出：
    data/extraction/<topic>_rule.json        正则+词典+结构化（方法 A 正式产物）
    data/extraction/<topic>_rule_regex.json  仅正则+词典（消融）
"""
from __future__ import annotations

import csv
from pathlib import Path
from typing import Dict, List, Tuple

from . import rule as R
from . import schema as S
from . import t2_sources as T


def _index_docs(docs: List[dict]) -> Dict[str, str]:
    """label -> 首次出现的文档 ID（用于给结构化实体补溯源）。"""
    idx: Dict[str, str] = {}

    def put(label: str, doc_id: str) -> None:
        if label and label not in idx:
            idx[label] = doc_id

    for d in docs:
        for tok in set(_tokens(d["text"])):
            put(tok, d["doc_id"])
    return idx


def _tokens(text: str) -> List[str]:
    """粗粒度候选：所有不含空白的“像编号”的词，用于建立 label→doc 索引。"""
    out = []
    for raw in text.replace(",", " ").replace(";", " ").replace("(", " ").replace(")", " ").split():
        out.append(raw.strip(".").strip())
    return out


def _lookup(label: str, idx: Dict[str, str], docs: List[dict]) -> str:
    if label in idx:
        return idx[label]
    for d in docs:
        if label and label.lower() in d["text"].lower():
            return d["doc_id"]
    return ""


def structured(cfg: dict, docs: List[dict]) -> Tuple[List[S.Entity], List[S.Relation]]:
    raw = T.RAW
    cves = T.load_cves(raw)
    attack = T.load_attack(raw)
    cwe = T.load_cwe(raw)
    capec = T.load_capec(raw)
    kev = T.load_kev(raw)

    tids = T.technique_ids_for(attack)
    cwes = T.selected_cwes(cves, kev)
    capecs = T.selected_capecs(cwes, cwe, capec)
    sigma = T.load_sigma(raw, technique_ids=tids, per_technique=2)

    idx = _index_docs(docs)
    ents: List[S.Entity] = []
    rels: List[S.Relation] = []

    def doc_of(label: str) -> str:
        return _lookup(label, idx, docs)

    def ent(eid: str, label: str, etype: str, props: dict | None = None) -> None:
        ents.append(S.Entity(id=eid, label=S.norm_label(label), type=etype,
                             doc=doc_of(label), method="rule",
                             evidence=f"structured:{etype}",
                             properties=props or {}))

    def rel(src: str, r: str, dst: str, doc: str, evidence: str) -> None:
        rels.append(S.Relation(source=src, relation=r, target=dst, doc=doc,
                               evidence=S.norm_label(evidence)[:200], method="rule",
                               properties={"extractor": "structured"}))

    # ---- 漏洞 / 弱点 / 产品 / 厂商 / KEV ---------------------------------- #
    for c in cves:
        vdoc = doc_of(c["id"])
        ent(f"cve:{c['id']}", c["id"], "Vulnerability",
            {"cvss": c.get("cvss") or {}, "published": c.get("published", "")})
        for w in c["cwes"]:
            ent(f"cwe:{w}", w, "Weakness")
            rel(f"cve:{c['id']}", "has_weakness", f"cwe:{w}", vdoc,
                f"problemTypes / weaknesses: {c['id']} -> {w}")
        for x in c["cpes"]:
            p = T.parse_cpe(x["cpe"])
            if not p:
                continue
            # CPE 串本身即主键（含 cpe:2.3: 前缀），不要再加 "cpe:"，否则变成 cpe:cpe:2.3:…
            ent(x["cpe"], x["cpe"], "Product",
                {"part": p["part"], "version": p["version"]})
            rel(f"cve:{c['id']}", "affects_product", x["cpe"], vdoc,
                f"configurations: {x['cpe']}")
            if p["vendor"] not in ("", "*", "-"):
                ent(f"vendor:{p['vendor']}", p["vendor"], "Vendor")
                rel(x["cpe"], "produced_by", f"vendor:{p['vendor']}", vdoc,
                    f"CPE vendor field: {p['vendor']}")
        if c.get("kev"):
            k = c["kev"]
            label = f"KEV entry for {c['id']}"
            ent(f"kev:{c['id']}", label, "ExploitationRecord",
                {"dateAdded": k.get("dateAdded"), "dueDate": k.get("dueDate"),
                 "ransomware": k.get("knownRansomwareCampaignUse")})
            rel(f"cve:{c['id']}", "known_exploited", f"kev:{c['id']}", vdoc,
                f"KEV dateAdded={k.get('dateAdded')} dueDate={k.get('dueDate')}")

    # ---- CWE -> CAPEC ----------------------------------------------------- #
    for cid in cwes:
        w = cwe["by_id"].get(cid) or {}
        for ap in (w.get("related_attack_patterns") or [])[:6]:
            if ap not in capecs:
                continue
            ent(f"capec:{ap}", ap, "AttackPattern")
            rel(f"cwe:{cid}", "relates_to_pattern", f"capec:{ap}", doc_of(cid),
                f"CWE Related_Attack_Patterns: {cid} -> {ap}")

    for cid in capecs:
        ent(f"capec:{cid}", cid, "AttackPattern")

    # ---- CAPEC -> ATT&CK（分析师映射表） ---------------------------------- #
    cross_path = S.repo_root() / "topics" / cfg["topic"] / "capec_attck_crosswalk.csv"
    if cross_path.exists():
        with cross_path.open(encoding="utf-8", newline="") as fh:
            for row in csv.DictReader(fh):
                cid, tid = row["capec_id"], row["technique_id"]
                if tid not in tids:
                    continue
                ent(f"attck:{tid}", tid, "Technique")
                rel(f"capec:{cid}", "implemented_by", f"attck:{tid}", doc_of(cid),
                    f"analyst crosswalk ({row['confidence']}): {row['rationale']}")

    # ---- ATT&CK 技术 / 战术 / 子技术 -------------------------------------- #
    for tid in tids:
        o = attack["by_ext"][tid]
        ent(f"attck:{tid}", tid, "Technique", {"name": o.get("name", "")})
        for ta in T.technique_tactics(attack, o):
            ent(f"tactic:{ta}", ta, "Tactic")
            rel(f"attck:{tid}", "belongs_to_tactic", f"tactic:{ta}", doc_of(tid),
                f"kill_chain_phases: {tid} -> {ta}")
        parent = next((r for r in attack["relationships"]
                       if r.get("relationship_type") == "subtechnique-of"
                       and r.get("source_ref") == o.get("id")), None)
        if parent:
            p = attack["by_stix"].get(parent.get("target_ref")) or {}
            pe = T._ext_id(p)
            if pe and pe in tids:
                rel(f"attck:{tid}", "subtechnique_of", f"attck:{pe}", doc_of(tid),
                    f"subtechnique-of: {tid} -> {pe}")

    # ---- 组织 / 软件 / 缓解 ---------------------------------------------- #
    def top_sources(types, limit):
        edges = T.attack_uses_edges(attack, types, tids)
        by_src: Dict[str, List[dict]] = {}
        for e in edges:
            by_src.setdefault(e["source"], []).append(e)
        return sorted(by_src.items(), key=lambda kv: (-len(kv[1]), kv[0]))[:limit]

    for gid, edges in top_sources(("intrusion-set",), 14):
        o = attack["by_ext"].get(gid) or {}
        ent(f"attck:{gid}", gid, "Group", {"name": o.get("name", "")})
        for e in edges[:8]:
            rel(f"attck:{gid}", "group_uses", f"attck:{e['target']}", doc_of(gid),
                f"ATT&CK uses: {gid} -> {e['target']}")

    for sid, edges in top_sources(("malware", "tool"), 14):
        o = attack["by_ext"].get(sid) or {}
        # S#### 编号本身不区分恶意软件/工具；统一挂在父类 Software 下，子类信息放属性，
        # 这样三种方法产出的类型一致，融合阶段才能按 (type, label) 对齐。
        ent(f"attck:{sid}", sid, "Software", {"name": o.get("name", ""), "kind": o.get("type", "")})
        for e in edges[:6]:
            rel(f"attck:{sid}", "software_uses", f"attck:{e['target']}", doc_of(sid),
                f"ATT&CK uses: {sid} -> {e['target']}")

    mit_edges = T.attack_mitigates_edges(attack, tids)
    by_m: Dict[str, List[dict]] = {}
    for e in mit_edges:
        by_m.setdefault(e["source"], []).append(e)
    for mid, es in sorted(by_m.items(), key=lambda kv: (-len(kv[1]), kv[0]))[:20]:
        o = attack["by_ext"].get(mid) or {}
        ent(f"attck:{mid}", mid, "Mitigation", {"name": o.get("name", "")})
        for e in es[:6]:
            rel(f"attck:{mid}", "mitigates", f"attck:{e['target']}", doc_of(mid),
                f"ATT&CK mitigates: {mid} -> {e['target']}")

    # ---- Sigma 检测规则 --------------------------------------------------- #
    for r in sigma:
        ent(f"sigma:{r['id']}", r["id"], "DetectionRule", {"level": r["level"]})
        for t in r["techniques"]:
            rel(f"sigma:{r['id']}", "detects", f"attck:{t}", doc_of(r["id"]),
                f"Sigma tag: attack.{t.lower()}")

    # 结构化实体也要有 mentioned_in，否则它们的溯源链比正则实体短一截。
    for e in ents:
        if e.doc:
            rel(e.id, "mentioned_in", f"doc:{e.doc}", e.doc, e.evidence)
    return ents, rels


def _dedupe_entities(ents: List[S.Entity]) -> List[S.Entity]:
    seen = {}
    for e in ents:
        seen.setdefault((e.id, e.doc), e)
    return list(seen.values())


def run(topic: str, verbose: bool = True) -> dict:
    cfg = S.load_topic(topic)
    docs = S.load_corpus(cfg)
    if not docs:
        raise SystemExit("[rule] 语料为空")

    regex_ents = R.extract_entities(cfg, docs)
    regex_rels = R.extract_relations(cfg, docs, regex_ents)
    struct_ents, struct_rels = structured(cfg, docs)

    ents = _dedupe_entities(regex_ents + struct_ents)
    rels = R.dedupe_relations(regex_rels + struct_rels)

    payload = {
        "topic": topic, "method": "rule", "doc_count": len(docs),
        "entity_count": len(ents), "relation_count": len(rels),
        "entities": S.entities_to_json(ents),
        "relations": S.relations_to_json(rels),
        "unknown_types": S.require_known_types(cfg, ents),
        "unknown_relations": S.require_known_relations(cfg, rels),
        "components": {
            "regex_entities": len(regex_ents), "regex_relations": len(regex_rels),
            "structured_entities": len(struct_ents), "structured_relations": len(struct_rels),
            "merged_entities": len(ents), "merged_relations": len(rels),
            "entities_without_doc": sum(1 for e in ents if not e.doc),
        },
    }
    out = S.out_dir("extraction", topic)
    path = S.write_json(out / f"{topic}_rule.json", payload)

    # 消融：只保留正则+词典
    S.write_json(out / f"{topic}_rule_regex.json", {
        "topic": topic, "method": "rule_regex", "doc_count": len(docs),
        "entity_count": len(regex_ents), "relation_count": len(regex_rels),
        "entities": S.entities_to_json(regex_ents),
        "relations": S.relations_to_json(regex_rels),
        "unknown_types": S.require_known_types(cfg, regex_ents),
        "unknown_relations": S.require_known_relations(cfg, regex_rels),
    })

    if verbose:
        print(f"[rule-A] 实体 {len(ents)} · 关系 {len(rels)} -> {path}")
        print(f"[rule-A] 正则 {len(regex_ents)}/{len(regex_rels)} · "
              f"结构化 {len(struct_ents)}/{len(struct_rels)} · "
              f"缺溯源 {payload['components']['entities_without_doc']}")
        if payload["unknown_types"]:
            print(f"[rule-A] ⚠ 越界类：{payload['unknown_types']}")
        if payload["unknown_relations"]:
            print(f"[rule-A] ⚠ 越界关系：{payload['unknown_relations']}")
    return payload


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="阶段二·方法A：正则/词典 + 结构化映射")
    ap.add_argument("--topic", required=True)
    run(ap.parse_args().topic)
