#!/usr/bin/env python3
"""题目二：跨源 ID 映射的覆盖率/准确率报告（可复现）。

做法不是"数一数图里有多少条边"，而是拿**官方结构化字段**当参照：

  CVE→CWE      NVD weaknesses[].description[].value
  CVE→CPE      NVD configurations[].nodes[].cpeMatch[].criteria（vulnerable=true）
  CWE→CAPEC    CWE XML  Related_Attack_Patterns/CAPEC_ID
  CAPEC→ATT&CK CAPEC XML Taxonomy_Mapping[@Taxonomy_Name=ATTACK]/Entry_ID
  T→TA         ATT&CK STIX attack-pattern.kill_chain_phases
  Sigma→T      Sigma 规则元数据行 "detects Txxxx ..."
  KEV 覆盖     CISA KEV 清单 ∩ 本切片 CVE

每个映射类型同时给出：
  * recall：官方映射中，图谱里也有的比例（分母只算"头实体已进入图谱"的映射，
    因为未导入的 CVE/技术不在本作业范围内，不能算漏抽）；
  * precision：图谱该关系的边里，能在官方字段中找到依据的比例；
  * sample：固定种子抽 8 条官方映射逐条标注 in_kg，便于答辩时人工复核。

输出 data/reports/<topic>_cross_source.json / .md
"""
from __future__ import annotations

import json
import random
import sys
import zipfile
from pathlib import Path
from xml.etree import ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from kgc import ids as I  # noqa: E402
from kgc import schema as S  # noqa: E402
from kgc import t2_sources as T  # noqa: E402

TOPIC = "t2-cve-attack"
RAW = ROOT / "data" / "raw"
SEED = 20261021
SAMPLE_N = 8


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _walk_nodes(node: dict):
    yield node
    for child in node.get("children") or []:
        yield from _walk_nodes(child)


# --------------------------------------------------------------------------- #
# 官方映射
# --------------------------------------------------------------------------- #
def load_cve_slice() -> tuple[dict[str, set], dict[str, set], set[str]]:
    """以**语料切片**为参照，而不是 NVD 全量。

    语料构建对每个 CVE 的 CPE 做了抽样（按 vendor/product/主次版本去重后取前 4 条），
    这是作业“切片而不是导入全量”的明确要求；若拿 NVD 全量（单 CVE 上百条 CPE）当分母，
    会把“本来就没导入”的 CPE 算成漏抽，结论没有意义。这里复用同一个 loader，
    保证参照集与语料同源、同口径。
    """
    cve_cwe: dict[str, set] = {}
    cve_cpe: dict[str, set] = {}
    cves: set[str] = set()
    for c in T.load_cves(RAW):
        cid = c["id"]
        cves.add(cid)
        cve_cwe[cid] = {x for x in c.get("cwes") or [] if str(x).startswith("CWE-")}
        cve_cpe[cid] = {x["cpe"] for x in c.get("cpes") or [] if x.get("cpe")}
    return cve_cwe, cve_cpe, cves


def load_cwe() -> dict[str, set]:
    out: dict[str, set] = {}
    with zipfile.ZipFile(RAW / "cwec_latest.xml.zip") as z:
        name = next(n for n in z.namelist() if n.endswith(".xml"))
        root = ET.fromstring(z.read(name))
    for el in root.iter():
        if _local(el.tag) != "Weakness":
            continue
        cid = el.get("ID")
        if not cid:
            continue
        for r in el.iter():
            if _local(r.tag) == "Related_Attack_Pattern" and r.get("CAPEC_ID"):
                out.setdefault(f"CWE-{cid}", set()).add(f"CAPEC-{r.get('CAPEC_ID')}")
    return out


def load_capec_crosswalk() -> dict[str, set]:
    """CAPEC→ATT&CK 参照集。

    MITRE 并未发布官方 CAPEC→ATT&CK 映射（CAPEC XML 的 Taxonomy_Mappings 只覆盖极少数
    条目）。本作业采用 `topics/t2-cve-attack/capec_attck_crosswalk.csv`：24 条人工映射，
    标了 confidence（high/medium），许可证 CC BY 4.0。报告里必须把这个参照集的性质写清楚，
    不能伪装成“官方标准”。
    """
    import csv

    out: dict[str, set] = {}
    path = ROOT / "topics" / TOPIC / "capec_attck_crosswalk.csv"
    with path.open(encoding="utf-8-sig", newline="") as fh:
        for row in csv.DictReader(fh):
            cap, tech = (row.get("capec_id") or "").strip(), (row.get("technique_id") or "").strip()
            if cap and tech:
                out.setdefault(cap, set()).add(tech)
    return out


def load_attack() -> tuple[dict[str, set], dict[str, str]]:
    """(技术 -> 战术 ID 集合, 技术 -> 名称)。"""
    data = json.loads((RAW / "enterprise-attack.json").read_text(encoding="utf-8"))
    objs = data.get("objects") or []
    tactic = {}
    for o in objs:
        if o.get("type") == "x-mitre-tactic":
            ext = next((r.get("external_id") for r in o.get("external_references") or []
                        if r.get("source_name") == "mitre-attack"), None)
            if ext and o.get("x_mitre_shortname"):
                tactic[o["x_mitre_shortname"]] = ext
    out: dict[str, set] = {}
    names: dict[str, str] = {}
    for o in objs:
        if o.get("type") != "attack-pattern" or o.get("revoked"):
            continue
        ext = next((r.get("external_id") for r in o.get("external_references") or []
                    if r.get("source_name") == "mitre-attack"), None)
        if not ext:
            continue
        names[ext] = o.get("name", "")
        tas = {tactic[p["phase_name"]] for p in o.get("kill_chain_phases") or []
               if p.get("phase_name") in tactic}
        out[ext] = tas
    return out, names


def load_sigma(resolver: I.IdResolver) -> dict[str, set]:
    out: dict[str, set] = {}
    path = ROOT / "data" / "corpus" / TOPIC / "sigma_rules.txt"
    for line in path.read_text(encoding="utf-8").splitlines():
        if " detects " not in line:
            continue
        hits = resolver.find_all(line)
        uuid = next((surf for typ, surf, _, _ in hits
                     if typ == "DetectionRule"), None)
        techs = {surf for typ, surf, _, _ in hits if typ == "Technique"}
        if uuid and techs:
            out.setdefault(uuid, set()).update(techs)
    return out


def load_kev() -> set[str]:
    data = json.loads((RAW / "known_exploited_vulnerabilities.json").read_text(encoding="utf-8"))
    return {v["cveID"] for v in data.get("vulnerabilities") or [] if v.get("cveID")}


# --------------------------------------------------------------------------- #
# 对比
# --------------------------------------------------------------------------- #
def _tail_id(prefix: str, label: str) -> str:
    # CPE 的标签本身就是完整主键（cpe:2.3:...），不能再加前缀
    return label if prefix == "cpe" else f"{prefix}:{label}"


def compare(name: str, official: dict[str, set], head_prefix: str, tail_prefix: str,
            kg_edges: set[tuple[str, str, str]], relation: str,
            node_ids: set[str], reference: str = "", all_ids: set[str] | None = None) -> dict:
    """official: 标签 -> 尾标签集合；node_ids: 图谱中该类头实体的 id。

    分母只统计**头尾都已进入图谱**的官方映射：没导入的尾实体（例如未选入的 CAPEC）
    不属于"漏抽"。`all_ids` 为空时退化为只要求头实体在图中。
    """
    official_pairs: set[tuple[str, str]] = set()
    for h, tails in official.items():
        if f"{head_prefix}:{h}" not in node_ids:
            continue
        for t in tails:
            tid = _tail_id(tail_prefix, t)
            if all_ids is not None and tid not in all_ids:
                continue  # 尾实体未导入，不计入召回分母
            official_pairs.add((f"{head_prefix}:{h}", tid))
    kg = {(h, t) for (h, r, t) in kg_edges if r == relation}
    hit = official_pairs & kg
    fp = kg - official_pairs
    # 只统计"头实体类型正确"的边作为 precision 分母，避免把结构边或错类节点算进来
    kg_scoped = {(h, t) for h, t in kg if h in node_ids}

    rng = random.Random(SEED + len(name))
    sample_pairs = sorted(official_pairs)
    rng.shuffle(sample_pairs)
    sample = [{"head": h, "tail": t, "in_kg": (h, t) in kg}
              for h, t in sample_pairs[:SAMPLE_N]]
    kg_only = sorted(kg_scoped - official_pairs)
    rng.shuffle(kg_only)
    return {
        "mapping": name, "relation": relation, "reference": reference,
        "official_pairs": len(official_pairs),
        "kg_pairs": len(kg_scoped),
        "matched": len(hit & kg_scoped),
        "recall": round(len(hit & kg_scoped) / max(1, len(official_pairs)), 4),
        "precision": round(len(hit & kg_scoped) / max(1, len(kg_scoped)), 4),
        "kg_only_count": len(kg_only),
        "sample": sample,
        "kg_only_sample": [{"head": h, "tail": t} for h, t in kg_only[:5]],
    }


def _kg() -> tuple[dict, set, set]:
    kg = S.read_json(ROOT / "data" / "kg" / f"{TOPIC}_kg.json")
    nodes = {n["id"]: n for n in kg["nodes"]}
    edges = {(e["source"], e["relation"], e["target"]) for e in kg["edges"]}
    return nodes, edges, set(nodes)


def main() -> None:
    cfg = S.load_topic(TOPIC)
    resolver = I.IdResolver.from_cfg(cfg)
    nodes, edges, _ = _kg()
    node_ids = set(nodes)
    types = {nid: n["type"] for nid, n in nodes.items()}
    by_type = {t: {nid for nid, tt in types.items() if tt == t} for t in set(types.values())}

    cve_cwe, cve_cpe, cves = load_cve_slice()
    cwe_capec = load_cwe()
    capec_attack = load_capec_crosswalk()
    tech_tactic, tech_names = load_attack()
    sigma_attack = load_sigma(resolver)
    kev = load_kev()

    rows = [
        compare("CVE→CWE", cve_cwe, "cve", "cwe", edges, "has_weakness",
                by_type.get("Vulnerability", set()),
                "NVD 2.0 weaknesses（CVE 5.0 problemTypes 合并）", node_ids),
        compare("CVE→CPE", cve_cpe, "cve", "cpe", edges, "affects_product",
                by_type.get("Vulnerability", set()),
                "NVD 2.0 configurations（语料抽样：每 CVE ≤4 条）", node_ids),
        compare("CWE→CAPEC", cwe_capec, "cwe", "capec", edges, "relates_to_pattern",
                by_type.get("Weakness", set()),
                "CWE XML 4.20 Related_Attack_Patterns", node_ids),
        compare("CAPEC→ATT&CK", capec_attack, "capec", "attck", edges, "implemented_by",
                by_type.get("AttackPattern", set()),
                "人工 crosswalk CSV（24 条，CC BY 4.0；MITRE 无官方映射）", node_ids),
        compare("Technique→Tactic", tech_tactic, "attck", "tactic", edges,
                "belongs_to_tactic", by_type.get("Technique", set()),
                "ATT&CK STIX kill_chain_phases", node_ids),
        compare("Sigma→Technique", sigma_attack, "sigma", "attck", edges, "detects",
                by_type.get("DetectionRule", set()),
                "Sigma 规则元数据（DRL 1.1，仅标签）", node_ids),
    ]

    # KEV：只看**本切片 CVE** 的召回；precision 看 known_exploited 的尾实体是否在 KEV
    kg_kev = {(h, t) for h, r, t in edges if r == "known_exploited"}
    kev_slice = {c for c in kev if c in cves}
    kev_nodes = {f"cve:{c}" for c in kev_slice} & by_type.get("Vulnerability", set())
    kev_hit = {(h, t) for h, t in kg_kev if h in kev_nodes and t == f"kev:{h.split(':')[1]}"}
    kev_only = {h for h, t in kg_kev if h not in {f"cve:{c}" for c in kev}}
    kev_row = {
        "mapping": "CVE→KEV", "relation": "known_exploited",
        "reference": "CISA KEV catalog ∩ 本切片 CVE",
        "kev_total": len(kev),
        "kev_in_slice": len(kev_nodes),
        "kg_pairs": len([1 for h, t in kg_kev if h in kev_nodes]),
        "matched": len(kev_hit),
        "recall": round(len(kev_hit) / max(1, len(kev_nodes)), 4),
        "precision": round(len(kev_hit) / max(1, len([1 for h, t in kg_kev
                                                      if h in kev_nodes])), 4),
        "kg_only_count": len(kev_only),
        "sample": [{"head": h, "tail": t, "in_kg": True}
                   for h, t in sorted(kev_hit)[:SAMPLE_N]],
    }
    rows.append(kev_row)

    summary = {
        "topic": TOPIC, "seed": SEED,
        "cve_slice": len(cves), "kev_total": len(kev),
        "kg_nodes": len(nodes), "kg_edges": len(edges),
        "mappings": rows,
    }
    out_json = ROOT / "data" / "reports" / f"{TOPIC}_cross_source.json"
    out_json.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    (ROOT / "data" / "reports" / f"{TOPIC}_cross_source.md").write_text(
        _markdown(summary), encoding="utf-8")
    print(f"[cross] -> {out_json}")
    for r in rows:
        print(f"[cross] {r['mapping']:<18} 官方 {r.get('official_pairs', r.get('kev_in_slice')):>4} · "
              f"图谱 {r['kg_pairs']:>4} · 命中 {r['matched']:>4} · "
              f"R={r['recall']:.3f} P={r['precision']:.3f}")


def _markdown(s: dict) -> str:
    lines = [
        "# 题目二 跨源 ID 映射核验", "",
        f"- 图谱：{s['kg_nodes']} 节点 / {s['kg_edges']} 边；CVE 切片 {s['cve_slice']} 条；"
        f"KEV 清单 {s['kev_total']} 条",
        f"- 抽样种子：{s['seed']}（每类抽 {SAMPLE_N} 条，可复现）",
        "- 分母口径：只统计**头、尾实体都已进入图谱**的官方映射；未导入的实体（例如未选入的 CAPEC）不算漏抽。",
        "- 解读：本切片的官方 ID 映射由图谱的结构化通道完整导入，因此 Recall=100% 是**构造结果**，"
        "不是抽取能力的证据；跨源核验的意义在于验证 ID 归一化没有破坏官方映射、"
        "量化正文抽取带来的额外边（Precision 缺口），并给出可人工复核的抽样。",
        "", "| 映射 | 关系 | 官方映射 | 图谱边 | 命中 | Recall | Precision | 图谱独有 |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for r in s["mappings"]:
        official = r.get("official_pairs", r.get("kev_in_slice"))
        lines.append(f"| {r['mapping']} | `{r['relation']}` | {official} | {r['kg_pairs']} | "
                     f"{r['matched']} | {r['recall']:.1%} | {r['precision']:.1%} | "
                     f"{r['kg_only_count']} |")
    lines += ["", "## 抽样复核", ""]
    for r in s["mappings"]:
        if not r.get("sample"):
            continue
        lines += [f"### {r['mapping']}", "", "| 头实体 | 尾实体 | 图谱中存在 |", "|---|---|---|"]
        lines += [f"| `{x['head']}` | `{x['tail']}` | {'✓' if x['in_kg'] else '✗'} |"
                  for x in r["sample"]]
        lines.append("")
    return "\n".join(lines)


if __name__ == "__main__":
    main()
