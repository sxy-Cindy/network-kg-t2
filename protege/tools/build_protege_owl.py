"""把题目二的本体种子与融合知识图谱组装成可在 Protégé 5.6.9 中打开、浏览、
运行 HermiT 的 OWL 2 文件。

输入
    topics/t2-cve-attack/ontology.json       19 类 / 17 关系 / 22 数据属性
    topics/t2-cve-attack/topic.yaml          类/关系约束与官方编号类清单
    topics/t2-cve-attack/sources.yaml        逐文档来源与许可证
    data/kg/t2-cve-attack_kg.json            421 节点 / 1572 边（融合图）
    data/raw/known_exploited_vulnerabilities.json
    data/raw/epss_scores.json
    data/corpus/t2-cve-attack/cve_records_*.txt

输出
    protege/owl/t2-threat-intel-tbox.owl.ttl / .owl
    protege/owl/t2-threat-intel.owl.ttl / .owl
    protege/catalog-v001.xml
    protege/reports/build_report.json / .md
    protege/reports/official_id_check.json
    protege/reports/query_results.json（由 run_queries.py 生成）

设计要点
  1. TBox 完整保留类层次、对象属性 domain/range、数据属性、来源、建模理由；
  2. ABox 的每个图节点是 owl:NamedIndividual，每条图边是对象属性断言；
  3. 每条边的证据、置信度、来源文档、抽取方法用 OWL 2 公理注解（owl:Axiom）
     保留，在 Protégé 的 "Annotations" 面板可逐条查看；
  4. 只补 OWL 语义中明确成立的关系：uses 的三个子属性、used_by 是 group_uses
     的逆属性；不额外声明传递性/函数性，避免超出 ontology.json 的承诺；
  5. 官方编号逐类做正则核验；任何越界类/关系/端点缺失都会进入报告，不静默修补。
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml
from rdflib import BNode, Graph, Literal, Namespace, URIRef
from rdflib.namespace import DCTERMS, OWL, RDF, RDFS, XSD

ROOT = Path(__file__).resolve().parents[2]
TOPIC = "t2-cve-attack"
TOPIC_DIR = ROOT / "topics" / TOPIC
OUT = ROOT / "protege"
OWL_DIR = OUT / "owl"
REPORT_DIR = OUT / "reports"
SKOS = Namespace("http://www.w3.org/2004/02/skos/core#")

INST_NS = "http://kgcourse.org/instance/threat-intel#"


# --------------------------------------------------------------------------- #
# 基础工具
# --------------------------------------------------------------------------- #
def safe_local(value: str, limit: int = 96) -> str:
    """把任意 ID 变成稳定的 IRI 局部名：保留中英文/数字，其余替换为下划线。"""
    s = str(value).strip()
    s = re.sub(r"[^0-9A-Za-z一-鿿_.-]+", "_", s)
    s = re.sub(r"_+", "_", s).strip("_")
    if not s:
        s = "n"
    if len(s) > limit:
        digest = hashlib.sha1(str(value).encode("utf-8")).hexdigest()[:8]
        s = s[: limit - 9] + "_" + digest
    return s


def lit_zh(value: Any) -> Literal:
    return Literal(str(value), lang="zh")


def lit(value: Any) -> Literal:
    return Literal("" if value is None else str(value))


def add_annotation_properties(g: Graph, ns: Namespace) -> None:
    """声明本作业使用的注解属性；它们不参与 DL 推理。"""
    for p, label in [
        (DCTERMS.source, "来源"),
        (DCTERMS.created, "创建时间"),
        (DCTERMS.modified, "修改时间"),
        (ns.evidence, "原文证据"),
        (ns.confidence, "抽取置信度"),
        (ns.sourceDoc, "来源文档"),
        (ns.extractionMethod, "抽取方法"),
        (ns.sourceId, "原始 ID"),
        (ns.officialId, "官方编号"),
        (ns.alias, "别名"),
        (ns.license, "许可证"),
        (ns.licenseCode, "许可证代码"),
        (ns.retrieved, "取数时间"),
        (ns.sourceName, "数据源名称"),
        (ns.sourceUrl, "数据源 URL"),
        (ns.dataSnapshot, "实例快照日期"),
        (ns.ontologyVersion, "本体版本"),
        (ns.modelingNote, "建模备注"),
        (ns.compatibilityNote, "兼容性说明"),
    ]:
        g.add((p, RDF.type, OWL.AnnotationProperty))
        g.add((p, RDFS.label, lit_zh(label)))
    # SKOS 的 scopeNote 是本体用来记录“建模理由”的注解；显式声明后
    # OWL 2 DL Profile 才不会报 “undeclared annotation property”。
    g.add((SKOS.scopeNote, RDF.type, OWL.AnnotationProperty))
    g.add((SKOS.scopeNote, RDFS.label, lit_zh("建模理由")))


def new_graph(ns_uri: str, title: str, description: str, version: str,
              source_url: str) -> tuple[Graph, Namespace]:
    g = Graph()
    ns = Namespace(ns_uri)
    inst = Namespace(INST_NS)
    g.bind("", ns)
    g.bind("inst", inst)
    g.bind("owl", OWL)
    g.bind("rdf", RDF)
    g.bind("rdfs", RDFS)
    g.bind("xsd", XSD)
    g.bind("dcterms", DCTERMS)
    g.bind("skos", SKOS)

    ont = URIRef(ns_uri.rstrip("#/"))
    g.add((ont, RDF.type, OWL.Ontology))
    g.add((ont, RDFS.label, lit_zh(title)))
    g.add((ont, RDFS.comment, lit_zh(description)))
    g.add((ont, OWL.versionInfo, lit(version or "v1.0")))
    g.add((ont, OWL.versionIRI, URIRef(ont + "/" + str(version or "v1.0"))))
    # xsd:date 不在 OWL 2 datatype map 中（HermiT 1.4.3 会直接拒绝），
    # 因此本体元数据与日期字段统一用 xsd:string 保存 ISO 8601 词法值。
    g.add((ont, DCTERMS.created, Literal("2026-10-21", datatype=XSD.string)))
    g.add((ont, DCTERMS.modified, Literal("2026-10-28", datatype=XSD.string)))
    g.add((ont, ns.ontologyVersion, lit(version or "v1.0")))
    g.add((ont, ns.dataSnapshot, Literal("2026-10-28", datatype=XSD.string)))
    g.add((ont, ns.modelingNote,
           lit_zh("实例层（CVE/KEV/EPSS）日更，本体层（CWE/CAPEC/ATT&CK）季度更新；"
                  "本文件把两层时间戳分别记录在 dcterms:modified 与 dataSnapshot。")))
    if source_url:
        g.add((ont, RDFS.seeAlso, URIRef(source_url)))
    return g, ns


def add_class(g: Graph, ns: Namespace, c: dict) -> None:
    cid = c["id"]
    cls = URIRef(str(ns) + cid)
    g.add((cls, RDF.type, OWL.Class))
    g.add((cls, RDFS.label, lit_zh(c.get("label", cid))))
    if c.get("definition"):
        g.add((cls, RDFS.comment, lit_zh(c["definition"])))
    if c.get("parent"):
        g.add((cls, RDFS.subClassOf, URIRef(str(ns) + c["parent"])))
    if c.get("source"):
        g.add((cls, RDFS.isDefinedBy, lit(c["source"])))
        g.add((cls, DCTERMS.source, lit(c["source"])))
    if c.get("rationale"):
        g.add((cls, SKOS.scopeNote, lit_zh(c["rationale"])))


def add_object_property(g: Graph, ns: Namespace, r: dict) -> None:
    pid = r["id"]
    p = URIRef(str(ns) + pid)
    g.add((p, RDF.type, OWL.ObjectProperty))
    g.add((p, RDFS.label, lit_zh(r.get("label", pid))))
    if r.get("definition"):
        g.add((p, RDFS.comment, lit_zh(r["definition"])))
    if r.get("domain"):
        g.add((p, RDFS.domain, URIRef(str(ns) + r["domain"])))
    if r.get("range"):
        g.add((p, RDFS.range, URIRef(str(ns) + r["range"])))
    if r.get("parent"):
        g.add((p, RDFS.subPropertyOf, URIRef(str(ns) + r["parent"])))
    if r.get("source"):
        g.add((p, RDFS.isDefinedBy, lit(r["source"])))
        g.add((p, DCTERMS.source, lit(r["source"])))
    if r.get("rationale"):
        g.add((p, SKOS.scopeNote, lit_zh(r["rationale"])))


def add_data_property(g: Graph, ns: Namespace, a: dict) -> None:
    pid = a["id"]
    p = URIRef(str(ns) + pid)
    g.add((p, RDF.type, OWL.DatatypeProperty))
    g.add((p, RDFS.label, lit_zh(a.get("label", pid))))
    if a.get("domain"):
        g.add((p, RDFS.domain, URIRef(str(ns) + a["domain"])))
    rng = a.get("range", "xsd:string")
    if rng == "xsd:date":
        # 注意：ontology.json 的原始声明是 xsd:date；OWL 2 DL 的 datatype map
        # 不含 xsd:date，HermiT 1.4.3 会拒绝加载。这里保留原声明到注解，
        # 在 OWL 层改用 xsd:string，值仍是 ISO 8601（YYYY-MM-DD）。
        g.add((p, ns.compatibilityNote,
               lit_zh("原始声明 xsd:date；为满足 OWL 2 DL / HermiT，导出为 "
                      "xsd:string，词法值保持 ISO 8601 日期。")))
        rng = "xsd:string"
    if rng.startswith("xsd:"):
        rng_iri = URIRef(str(XSD) + rng.split(":", 1)[1])
    else:
        rng_iri = URIRef(rng)
    g.add((p, RDFS.range, rng_iri))


def add_tbox(g: Graph, ns: Namespace, seed: dict) -> None:
    for c in seed.get("classes", []):
        add_class(g, ns, c)
    for r in seed.get("relations", []):
        add_object_property(g, ns, r)
    for a in seed.get("attributes", []):
        add_data_property(g, ns, a)

    # ontology.json 明确写了 used_by 是 group_uses 的逆关系；只声明这一条，
    # 不把 used_by 当成 uses 的逆（否则 software_uses 会推出 Technique used_by Software）。
    declared = {r["id"] for r in seed.get("relations", [])}
    if "used_by" in declared and "group_uses" in declared:
        g.add((URIRef(str(ns) + "used_by"), OWL.inverseOf,
               URIRef(str(ns) + "group_uses")))


# --------------------------------------------------------------------------- #
# 从原始字段抽取字面值（只用于数据属性，不改变图结构）
# --------------------------------------------------------------------------- #
def parse_cve_text_attributes() -> dict[str, dict]:
    attrs: dict[str, dict] = {}
    for path in sorted((ROOT / "data" / "corpus" / TOPIC).glob("cve_records_*.txt")):
        text = path.read_text(encoding="utf-8", errors="ignore")
        for block in re.split(r"\n\s*\n", text):
            m = re.match(r"\s*(CVE-\d{4}-\d{4,})\b", block)
            if not m:
                continue
            cve = m.group(1)
            a = attrs.setdefault(cve, {})
            m = re.search(r"was published on\s+(\d{4}-\d{2}-\d{2})", block)
            if m:
                a["published"] = m.group(1)
            m = re.search(
                r"CVSS\s+[0-9.]+\s+base score is\s+([0-9.]+)\s+\(([A-Z]+)\),\s+"
                r"vector\s+([^\s]+)", block)
            if m:
                a["cvss_score"], a["cvss_severity"], a["cvss_vector"] = m.groups()
            m = re.search(
                r"FIRST EPSS score for\s+(CVE-\d{4}-\d{4,})\s+is\s+([0-9.]+)\s+"
                r"at percentile\s+([0-9.]+)", block)
            if m and m.group(1) == cve:
                a["epss"], a["epss_percentile"] = m.group(2), m.group(3)
    return attrs


def load_json(path: Path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def load_kev() -> dict[str, dict]:
    data = load_json(ROOT / "data" / "raw" / "known_exploited_vulnerabilities.json", {})
    return {v.get("cveID"): v for v in data.get("vulnerabilities", []) if v.get("cveID")}


def load_epss() -> dict[str, dict]:
    data = load_json(ROOT / "data" / "raw" / "epss_scores.json", {})
    return {v.get("cve"): v for v in data.get("data", []) if v.get("cve")}


def load_doc_sources() -> dict[str, dict]:
    raw = yaml.safe_load((TOPIC_DIR / "sources.yaml").read_text(encoding="utf-8"))
    out: dict[str, dict] = {}
    for key, src in (raw.get("sources") or {}).items():
        for doc in src.get("docs", []) or []:
            out[str(doc)] = {
                "source_key": key,
                "name": src.get("name", key),
                "url": src.get("url", ""),
                "license": src.get("license", ""),
                "license_code": src.get("license_code", ""),
                "note": src.get("note", ""),
                "retrieved": raw.get("retrieved", ""),
            }
    return out


def decimal_literal(value: Any) -> Literal | None:
    try:
        return Literal(str(value), datatype=XSD.decimal)
    except Exception:  # noqa: BLE001
        return None


def date_literal(value: Any) -> Literal | None:
    if not value:
        return None
    try:
        return Literal(str(value), datatype=XSD.date)
    except Exception:  # noqa: BLE001
        return None


def add_data(g: Graph, ns: Namespace, ind: URIRef, pid: str, value: Any,
             datatype=None, counts: Counter | None = None) -> None:
    if value is None or value == "":
        return
    if datatype is not None:
        obj = Literal(str(value), datatype=datatype)
    else:
        obj = lit(value)
    g.add((ind, URIRef(str(ns) + pid), obj))
    if counts is not None:
        counts[pid] += 1


def add_abox(g: Graph, ns: Namespace, kg: dict, seed: dict) -> dict:
    node_types = {n["id"]: n.get("type", "Entity") for n in kg.get("nodes", [])}
    declared_classes = {c["id"] for c in seed.get("classes", [])}
    declared_rels = {r["id"] for r in seed.get("relations", [])}
    rel_spec = {r["id"]: (r.get("domain"), r.get("range"))
                for r in seed.get("relations", [])}
    parents = {c["id"]: c.get("parent") for c in seed.get("classes", [])}

    def is_a(actual: str, want: str) -> bool:
        seen = set()
        cur = actual
        while cur and cur not in seen:
            if cur == want:
                return True
            seen.add(cur)
            cur = parents.get(cur)
        return False

    cve_attrs = parse_cve_text_attributes()
    kev = load_kev()
    epss = load_epss()
    doc_sources = load_doc_sources()

    node_iri: dict[str, URIRef] = {}
    used_locals: set[str] = set()
    auto_classes: list[str] = []
    data_counts: Counter = Counter()
    node_type_counts: Counter = Counter()
    missing_type: list[str] = []

    for n in kg.get("nodes", []):
        nid = n["id"]
        ntype = n.get("type", "Entity")
        if ntype not in declared_classes:
            auto_classes.append(ntype)
            missing_type.append(nid)
            continue
        local = safe_local(nid)
        if local in used_locals:
            local = safe_local(nid, limit=80) + "_" + hashlib.sha1(
                nid.encode("utf-8")).hexdigest()[:6]
        used_locals.add(local)
        ind = URIRef(INST_NS + "node/" + local)
        node_iri[nid] = ind
        node_type_counts[ntype] += 1

        g.add((ind, RDF.type, OWL.NamedIndividual))
        g.add((ind, RDF.type, URIRef(str(ns) + ntype)))
        g.add((ind, RDFS.label, lit(n.get("label", nid))))
        g.add((ind, ns.sourceId, lit(nid)))
        props = n.get("properties") or {}
        methods = props.get("methods") or []
        if methods:
            g.add((ind, ns.extractionMethod, lit(", ".join(sorted(map(str, methods))))))
        for alias in props.get("aliases", []) or []:
            if alias and str(alias) != str(n.get("label", nid)):
                g.add((ind, ns.alias, lit(alias)))

        # --- 数据属性：只在官方字段存在时写入，避免凭标签猜值 ---
        if ntype == "Vulnerability":
            cve = str(n.get("label", "")).strip()
            if not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve):
                cve = nid.split(":", 1)[-1]
            add_data(g, ns, ind, "cve_id", cve, XSD.string, data_counts)
            a = cve_attrs.get(cve, {})
            add_data(g, ns, ind, "published", a.get("published"), XSD.string, data_counts)
            add_data(g, ns, ind, "cvss_score", a.get("cvss_score"), XSD.decimal, data_counts)
            add_data(g, ns, ind, "cvss_vector", a.get("cvss_vector"), XSD.string, data_counts)
            add_data(g, ns, ind, "cvss_severity", a.get("cvss_severity"), XSD.string, data_counts)
            e = epss.get(cve, {})
            add_data(g, ns, ind, "epss", e.get("epss") or a.get("epss"),
                     XSD.decimal, data_counts)
            add_data(g, ns, ind, "epss_percentile",
                     e.get("percentile") or a.get("epss_percentile"),
                     XSD.decimal, data_counts)
        elif ntype == "Weakness":
            add_data(g, ns, ind, "cwe_id", n.get("label", ""), XSD.string, data_counts)
        elif ntype == "AttackPattern":
            add_data(g, ns, ind, "capec_id", n.get("label", ""), XSD.string, data_counts)
        elif ntype == "Technique":
            add_data(g, ns, ind, "tech_id", n.get("label", ""), XSD.string, data_counts)
            aliases = props.get("aliases") or []
            name = next((x for x in aliases if x and not re.fullmatch(r"T\d+.*", str(x))), "")
            add_data(g, ns, ind, "tech_name", name, XSD.string, data_counts)
        elif ntype == "Tactic":
            add_data(g, ns, ind, "tactic_id", n.get("label", ""), XSD.string, data_counts)
        elif ntype == "Group":
            add_data(g, ns, ind, "group_id", n.get("label", ""), XSD.string, data_counts)
        elif ntype == "Software":
            add_data(g, ns, ind, "software_id", n.get("label", ""), XSD.string, data_counts)
        elif ntype == "Mitigation":
            add_data(g, ns, ind, "mitigation_id", n.get("label", ""), XSD.string, data_counts)
        elif ntype == "DetectionRule":
            sigma = str(n.get("label", "")).strip()
            if not re.fullmatch(r"[0-9a-fA-F-]{36}", sigma):
                sigma = nid.split(":", 1)[-1]
            add_data(g, ns, ind, "sigma_id", sigma, XSD.string, data_counts)
        elif ntype == "ExploitationRecord":
            cve = nid.split(":", 1)[-1]
            k = kev.get(cve, {})
            add_data(g, ns, ind, "kev_date_added", k.get("dateAdded"), XSD.string, data_counts)
            add_data(g, ns, ind, "kev_due_date", k.get("dueDate"), XSD.string, data_counts)
            add_data(g, ns, ind, "kev_ransomware",
                     k.get("knownRansomwareCampaignUse"), XSD.string, data_counts)
        elif ntype == "Product":
            cpe = str(n.get("label", nid))
            add_data(g, ns, ind, "cpe_uri", cpe, XSD.string, data_counts)
            parts = cpe.split(":")
            if len(parts) >= 6:
                add_data(g, ns, ind, "cpe_part", parts[2], XSD.string, data_counts)
                add_data(g, ns, ind, "product_version", parts[5], XSD.string, data_counts)
        elif ntype == "Document":
            doc = nid.split(":", 1)[-1]
            meta = doc_sources.get(doc, {})
            if meta:
                g.add((ind, DCTERMS.source, lit(meta.get("name", ""))))
                g.add((ind, ns.sourceName, lit(meta.get("name", ""))))
                g.add((ind, ns.sourceUrl, lit(meta.get("url", ""))))
                g.add((ind, ns.license, lit(meta.get("license", ""))))
                g.add((ind, ns.licenseCode, lit(meta.get("license_code", ""))))
                g.add((ind, ns.retrieved, lit(meta.get("retrieved", ""))))
                if meta.get("note"):
                    g.add((ind, ns.modelingNote, lit_zh(meta["note"])))
            else:
                g.add((ind, ns.modelingNote, lit_zh("sources.yaml 未登记该文档")))

    # --- 关系断言 + 公理注解 ---
    edge_count = 0
    skipped_edges: list[dict] = []
    domain_range_violations: list[dict] = []
    auto_relations: list[str] = []
    relation_counts: Counter = Counter()
    for e in kg.get("edges", []):
        rel = e.get("relation", "")
        s = node_iri.get(e.get("source"))
        o = node_iri.get(e.get("target"))
        if rel not in declared_rels:
            auto_relations.append(rel)
            skipped_edges.append({"edge": e, "reason": "relation not declared"})
            continue
        if s is None or o is None:
            skipped_edges.append({"edge": e, "reason": "endpoint not in graph"})
            continue
        p = URIRef(str(ns) + rel)
        g.add((s, p, o))
        relation_counts[rel] += 1
        edge_count += 1

        want = rel_spec.get(rel)
        if want and want[0] and want[1]:
            st, ot = node_types.get(e["source"]), node_types.get(e["target"])
            if not (is_a(st, want[0]) and is_a(ot, want[1])):
                domain_range_violations.append({
                    "head": e["source"], "head_type": st,
                    "relation": rel,
                    "tail": e["target"], "tail_type": ot,
                    "expected": f"{want[0]} -> {want[1]}",
                })

        ax = BNode()
        g.add((ax, RDF.type, OWL.Axiom))
        g.add((ax, OWL.annotatedSource, s))
        g.add((ax, OWL.annotatedProperty, p))
        g.add((ax, OWL.annotatedTarget, o))
        ev = e.get("evidence")
        if ev:
            g.add((ax, ns.evidence, lit(str(ev)[:800])))
        conf = e.get("confidence")
        if conf is not None:
            try:
                g.add((ax, ns.confidence, Literal(float(conf), datatype=XSD.decimal)))
            except (TypeError, ValueError):
                pass
        if e.get("doc"):
            g.add((ax, ns.sourceDoc, lit(e["doc"])))
        methods = e.get("methods") or []
        if methods:
            g.add((ax, ns.extractionMethod, lit(", ".join(sorted(map(str, methods))))))

    # 补 TBox 中已声明但图中没有实例的类的说明，便于 Protégé 里解释“为什么是空的”
    for c in seed.get("classes", []):
        if c["id"] not in node_type_counts:
            cls = URIRef(str(ns) + c["id"])
            g.add((cls, ns.compatibilityNote,
                   lit_zh("本切片未实例化；类仍保留以对齐官方模型并支持后续扩展。")))

    return {
        "node_iri": node_iri,
        "node_type_counts": dict(node_type_counts),
        "relation_counts": dict(relation_counts),
        "edge_count": edge_count,
        "data_counts": dict(data_counts),
        "auto_classes": sorted(set(auto_classes)),
        "auto_relations": sorted(set(auto_relations)),
        "skipped_edges": skipped_edges,
        "domain_range_violations": domain_range_violations,
        "missing_type_nodes": missing_type,
    }


# --------------------------------------------------------------------------- #
# 官方 ID 核验与文件输出
# --------------------------------------------------------------------------- #
OFFICIAL_PATTERNS = {
    "Vulnerability": r"CVE-\d{4}-\d{4,}",
    "Weakness": r"CWE-\d+",
    "AttackPattern": r"CAPEC-\d+",
    "Technique": r"T\d{4}(?:\.\d{3})?",
    "Tactic": r"TA\d{4}",
    "Group": r"G\d{4}",
    "Software": r"S\d{4}",
    "Mitigation": r"M\d{4}",
    "DetectionRule": r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                     r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
    "Product": r"cpe:2\.3:[aoh]:.+",
    "ExploitationRecord": r"CVE-\d{4}-\d{4,}",
    "Document": r"[A-Za-z0-9_.-]+",
}


def official_id_check(kg: dict) -> dict:
    out: dict[str, dict] = defaultdict(lambda: {"count": 0, "invalid": []})
    for n in kg.get("nodes", []):
        ntype = n.get("type")
        pat = OFFICIAL_PATTERNS.get(ntype)
        if not pat:
            continue
        label = str(n.get("label", ""))
        if ntype == "ExploitationRecord":
            value = str(n.get("id", "")).split(":", 1)[-1]
        elif ntype == "Document":
            value = str(n.get("id", "")).split(":", 1)[-1]
        else:
            value = label
        out[ntype]["count"] += 1
        if not re.fullmatch(pat, value):
            out[ntype]["invalid"].append({"id": n.get("id"), "label": label,
                                          "value": value})
    return {k: {"count": v["count"],
                "valid": v["count"] - len(v["invalid"]),
                "invalid_count": len(v["invalid"]),
                "coverage": round((v["count"] - len(v["invalid"])) /
                                  max(1, v["count"]), 4),
                "invalid_examples": v["invalid"][:8]}
            for k, v in sorted(out.items())}


def write_owl(g: Graph, stem: Path) -> dict:
    stem.parent.mkdir(parents=True, exist_ok=True)
    ttl = stem.with_suffix(".owl.ttl")
    rdfxml = stem.with_suffix(".owl")
    g.serialize(destination=str(ttl), format="turtle")
    g.serialize(destination=str(rdfxml), format="xml")
    return {"turtle": str(ttl), "rdfxml": str(rdfxml), "triples": len(g)}


def write_catalog(entries: list[dict]) -> Path:
    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<catalog xmlns="urn:oasis:names:tc:entity:xmlns:xml:catalog" prefer="public">',
    ]
    for e in entries:
        rel = Path(e["files"]["rdfxml"]).relative_to(OUT).as_posix()
        ont = e["namespace"].rstrip("#/")
        lines.append(f'  <uri id="{e["name"]}" name="{ont}" uri="{rel}"/>')
    lines.append("</catalog>")
    p = OUT / "catalog-v001.xml"
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return p


def main() -> None:
    OWL_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    seed = json.loads((TOPIC_DIR / "ontology.json").read_text(encoding="utf-8"))
    kg = json.loads((ROOT / "data" / "kg" / f"{TOPIC}_kg.json")
                    .read_text(encoding="utf-8"))

    # --- TBox ---
    tbox, ns = new_graph(seed["namespace"], seed.get("title", TOPIC),
                         seed.get("description", ""), seed.get("version", "v1.0"),
                         seed.get("source_url", ""))
    add_annotation_properties(tbox, ns)
    add_tbox(tbox, ns, seed)
    tbox_files = write_owl(tbox, OWL_DIR / "t2-threat-intel-tbox")

    # --- TBox + ABox ---
    full, ns2 = new_graph(seed["namespace"], seed.get("title", TOPIC),
                          seed.get("description", ""), seed.get("version", "v1.0"),
                          seed.get("source_url", ""))
    add_annotation_properties(full, ns2)
    add_tbox(full, ns2, seed)
    abox = add_abox(full, ns2, kg, seed)
    full_files = write_owl(full, OWL_DIR / "t2-threat-intel")
    catalog = write_catalog([{
        "name": "t2-threat-intel", "namespace": seed["namespace"],
        "files": full_files,
    }])

    check = official_id_check(kg)
    report = {
        "topic": TOPIC,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "ontology": {
            "title": seed.get("title"),
            "namespace": seed["namespace"],
            "instance_namespace": INST_NS,
            "version": seed.get("version"),
            "classes": len(seed.get("classes", [])),
            "relations": len(seed.get("relations", [])),
            "attributes": len(seed.get("attributes", [])),
        },
        "kg": {
            "nodes": kg.get("node_count", len(kg.get("nodes", []))),
            "edges": kg.get("edge_count", len(kg.get("edges", []))),
            "node_types": abox["node_type_counts"],
            "relations": abox["relation_counts"],
        },
        "counts": {
            "individuals": len(abox["node_iri"]),
            "asserted_object_edges": abox["edge_count"],
            "data_property_assertions": sum(abox["data_counts"].values()),
            "axiom_annotations": len(list(full.subjects(RDF.type, OWL.Axiom))),
            "tbox_triples": tbox_files["triples"],
            "full_triples": full_files["triples"],
        },
        "data_properties": dict(sorted(abox["data_counts"].items())),
        "official_id_check": check,
        "auto_classes": abox["auto_classes"],
        "auto_relations": abox["auto_relations"],
        "skipped_edges": abox["skipped_edges"][:20],
        "skipped_edge_count": len(abox["skipped_edges"]),
        "domain_range_violations": abox["domain_range_violations"][:20],
        "domain_range_violation_count": len(abox["domain_range_violations"]),
        "files": {"tbox": tbox_files, "full": full_files,
                  "catalog": str(catalog)},
    }
    (REPORT_DIR / "build_report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (REPORT_DIR / "official_id_check.json").write_text(
        json.dumps(check, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    # 人读版
    lines = [
        "# 题目二 OWL 构建报告",
        "",
        f"- 生成时间：{report['generated_at']}",
        f"- 本体：{seed.get('title')}（{seed.get('version')}）",
        f"- 命名空间：`{seed['namespace']}`",
        f"- 实例命名空间：`{INST_NS}`",
        "",
        "## 规模",
        "",
        "| 项目 | 数值 |",
        "|---|---:|",
        f"| 类 | {report['ontology']['classes']} |",
        f"| 对象属性 | {report['ontology']['relations']} |",
        f"| 数据属性 | {report['ontology']['attributes']} |",
        f"| 个体 | {report['counts']['individuals']} |",
        f"| 断言对象属性边 | {report['counts']['asserted_object_edges']} |",
        f"| 数据属性断言 | {report['counts']['data_property_assertions']} |",
        f"| 公理注解（owl:Axiom） | {report['counts']['axiom_annotations']} |",
        f"| TBox 三元组 | {report['counts']['tbox_triples']} |",
        f"| 全量三元组 | {report['counts']['full_triples']} |",
        "",
        "## 官方编号核验",
        "",
        "| 类 | 节点数 | 合法 | 覆盖率 |",
        "|---|---:|---:|---:|",
    ]
    for k, v in check.items():
        lines.append(f"| {k} | {v['count']} | {v['valid']} | {v['coverage']:.1%} |")
    lines += [
        "",
        "## 自动补齐与跳过",
        "",
        f"- 自动补齐类：{report['auto_classes'] or '无'}",
        f"- 自动补齐关系：{report['auto_relations'] or '无'}",
        f"- 跳过边：{report['skipped_edge_count']}",
        f"- 域值域违规：{report['domain_range_violation_count']}",
        "",
        "## 文件",
        "",
        f"- TBox TTL：`{Path(tbox_files['turtle']).relative_to(ROOT)}`",
        f"- TBox RDF/XML：`{Path(tbox_files['rdfxml']).relative_to(ROOT)}`",
        f"- 全量 TTL：`{Path(full_files['turtle']).relative_to(ROOT)}`",
        f"- 全量 RDF/XML：`{Path(full_files['rdfxml']).relative_to(ROOT)}`",
        f"- catalog：`{Path(catalog).relative_to(ROOT)}`",
        "",
    ]
    (REPORT_DIR / "build_report.md").write_text("\n".join(lines), encoding="utf-8")

    print(f"[owl] TBox  {tbox_files['triples']:>7} triples -> {tbox_files['turtle']}")
    print(f"[owl] Full  {full_files['triples']:>7} triples -> {full_files['turtle']}")
    print(f"[owl] 个体 {report['counts']['individuals']} · 边 "
          f"{report['counts']['asserted_object_edges']} · 数据断言 "
          f"{report['counts']['data_property_assertions']} · 公理注解 "
          f"{report['counts']['axiom_annotations']}")
    print(f"[owl] 域值域违规 {report['domain_range_violation_count']} · "
          f"跳过边 {report['skipped_edge_count']} · 自动类 {report['auto_classes']}")
    print(f"[owl] -> {REPORT_DIR / 'build_report.json'}")


if __name__ == "__main__":
    main()
