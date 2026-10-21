"""阶段一：本体构建。

输入：topics/<topic>/ontology.json（本体种子：类 / 关系 / 数据属性 / 来源标准）
输出：
    data/ontology/<topic>_ontology.ttl    —— OWL 本体，可导入 GraphDB / 打开于 Protégé
    data/ontology/<topic>_ontology.json   —— 同一份本体件的工程视图（抽取阶段的 schema 约束）

设计要点（对学生）：本体不是"画着好看"，它在本作业里承担三件事：
  1. 约束抽取（抽取结果的类/关系必须在本体中定义，否则计入"越界实体"）；
  2. 约束 LLM 提示（把类与关系的定义注入 prompt，减少幻觉）；
  3. 约束查询（图谱查询的路径与关系名来自本体）。
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List

from . import schema as S


def _term(ns: str, name: str) -> str:
    return f"<{ns}{name}>"


def build_ontology_ttl(seed: dict) -> str:
    """把本体种子渲染为 Turtle。不依赖 rdflib，纯文本生成便于阅读与 diff。"""
    ns = seed["namespace"]
    lines: List[str] = [
        "@prefix owl: <http://www.w3.org/2002/07/owl#> .",
        "@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .",
        "@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .",
        "@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .",
        "@prefix skos: <http://www.w3.org/2004/02/skos/core#> .",
        f"@prefix : <{ns}> .",
        "",
        "<> a owl:Ontology ;",
    ]
    if seed.get("version"):
        lines.append(f'    owl:versionInfo "{seed["version"]}" ;')
    if seed.get("source_url"):
        lines.append(f'    rdfs:seeAlso <{seed["source_url"]}> ;')
    lines.append(f'    rdfs:label "{seed.get("title", "")}"@zh ;')
    lines.append(f'    rdfs:comment "{seed.get("description", "")}"@zh .')
    lines.append("")

    # 类
    for cls in seed.get("classes", []):
        parent = cls.get("parent")
        lines.append(f":{cls['id']} a owl:Class ;")
        if parent:
            lines.append(f"    rdfs:subClassOf :{parent} ;")
        lines.append(f'    rdfs:label "{cls["label"]}"@zh ;')
        if cls.get("definition"):
            lines.append(f'    rdfs:comment "{cls["definition"]}"@zh ;')
        if cls.get("source"):
            lines.append(f'    rdfs:isDefinedBy "{cls["source"]}" ;')
        if cls.get("rationale"):
            lines.append(f'    skos:scopeNote "{cls["rationale"]}"@zh ;')
        lines.append("    .")
        lines.append("")

    # 对象属性（关系）
    for rel in seed.get("relations", []):
        lines.append(f":{rel['id']} a owl:ObjectProperty ;")
        if rel.get("parent"):
            lines.append(f"    rdfs:subPropertyOf :{rel['parent']} ;")
        if rel.get("domain"):
            lines.append(f"    rdfs:domain :{rel['domain']} ;")
        if rel.get("range"):
            lines.append(f"    rdfs:range :{rel['range']} ;")
        lines.append(f'    rdfs:label "{rel["label"]}"@zh ;')
        if rel.get("definition"):
            lines.append(f'    rdfs:comment "{rel["definition"]}"@zh ;')
        if rel.get("source"):
            lines.append(f'    rdfs:isDefinedBy "{rel["source"]}" ;')
        if rel.get("rationale"):
            lines.append(f'    skos:scopeNote "{rel["rationale"]}"@zh ;')
        if rel.get("symmetric"):
            lines.append("    a owl:SymmetricProperty ;")
        if rel.get("transitive"):
            lines.append("    a owl:TransitiveProperty ;")
        lines.append("    .")
        lines.append("")

    # 数据属性
    for attr in seed.get("attributes", []):
        lines.append(f":{attr['id']} a owl:DatatypeProperty ;")
        if attr.get("domain"):
            lines.append(f"    rdfs:domain :{attr['domain']} ;")
        if attr.get("range"):
            lines.append(f"    rdfs:range :{attr['range']} ;")
        lines.append(f'    rdfs:label "{attr["label"]}"@zh ;')
        lines.append("    .")
        lines.append("")
    return "\n".join(lines)


def build(topic: str, verbose: bool = True) -> Dict[str, str]:
    cfg = S.load_topic(topic)
    seed = cfg["ontology_seed"]
    out = S.out_dir("ontology", topic)

    ttl_path = out / f"{topic}_ontology.ttl"
    ttl_path.write_text(build_ontology_ttl(seed), encoding="utf-8")

    json_path = S.write_json(
        out / f"{topic}_ontology.json",
        {
            "namespace": seed["namespace"],
            "title": seed.get("title", ""),
            "version": seed.get("version", ""),
            "topic": topic,
            "class_count": len(seed.get("classes", [])),
            "relation_count": len(seed.get("relations", [])),
            **{k: seed.get(k, []) for k in ("classes", "relations", "attributes")},
        },
    )

    if verbose:
        print(f"[ontology] topic={topic}  类 {len(seed.get('classes', []))} · 关系 {len(seed.get('relations', []))}")
        print(f"[ontology] TTL  -> {ttl_path}")
        print(f"[ontology] JSON -> {json_path}")
    return {"ttl": str(ttl_path), "json": str(json_path)}


def validate(topic: str) -> dict:
    """本体自检：重复 ID、孤立父类、关系域/值域指向未定义类。"""
    cfg = S.load_topic(topic)
    seed = cfg["ontology_seed"]
    problems: List[str] = []
    class_ids = [c["id"] for c in seed.get("classes", [])]
    rel_ids = [r["id"] for r in seed.get("relations", [])]

    for name, ids in (("class", class_ids), ("relation", rel_ids)):
        dupes = {i for i in ids if ids.count(i) > 1}
        if dupes:
            problems.append(f"重复 {name} ID: {sorted(dupes)}")
    known = set(class_ids)
    for c in seed.get("classes", []):
        if c.get("parent") and c["parent"] not in known:
            problems.append(f"类 {c['id']} 的父类 {c['parent']} 未定义")
    for r in seed.get("relations", []):
        for slot in ("domain", "range"):
            v = r.get(slot)
            if v and v not in known:
                problems.append(f"关系 {r['id']} 的 {slot}={v} 未定义")
    return {"topic": topic, "ok": not problems, "problems": problems,
            "class_count": len(class_ids), "relation_count": len(rel_ids)}


if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser(description="阶段一：从本体种子生成本体（TTL + JSON）")
    p.add_argument("--topic", required=True)
    p.add_argument("--check", action="store_true", help="只做本体自检")
    a = p.parse_args()
    if a.check:
        print(S.write_json(Path(a.topic + "_ontology_check.json") if False else
                           S.out_dir("reports", a.topic) / f"{a.topic}_ontology_check.json",
                           validate(a.topic)))
    else:
        build(a.topic)
        v = validate(a.topic)
        if not v["ok"]:
            print("[ontology] 自检问题：")
            for p_ in v["problems"]:
                print("   -", p_)
