"""阶段二收尾：把三元组落成知识图谱（多格式导出）+ 阶段三的查询底座。

输入：data/extraction/<topic>_{method}.json（method ∈ rule/model/llm/ensemble）
输出（与参考案例 kgcase 的产物约定保持一致，便于横向对照）：
    data/kg/<topic>_kg.json            节点/边 JSON（Neo4j / 前端可视化友好）
    data/kg/<topic>_kg.ttl             RDF Turtle（GraphDB / SPARQL 端点）
    data/kg/<topic>_kg.graphml         GraphML（Gephi / Cytoscape Desktop）
    data/kg/<topic>_kg_cytoscape.json  Cytoscape.js（Web 可视化）

节点 ID 统一用 `类:标签` 形式，与抽取阶段一致；关系即本体中的关系 ID——
这样"图谱里的每一条边都能在本体里找到定义"，是阶段一二之间的闭环检查。
"""

from __future__ import annotations

import re
from typing import Dict, List

from . import schema as S

_SAFE = re.compile(r"[^0-9A-Za-z_\u4e00-\u9fff]")


def _local(name: str) -> str:
    """把 `proto:TCP` 之类的 ID 转成合法的 RDF local name。"""
    parts = re.split(r"[:\s]+", name)
    return "".join(p[:1].upper() + p[1:] if p else "" for p in parts) or "Anonymous"


def build(topic: str, method: str = "ensemble", verbose: bool = True,
          out_name: str | None = None) -> dict:
    """out_name 用于旁路产物（如 LLM 单方法对照图），避免覆盖正式图谱。"""
    cfg = S.load_topic(topic)
    stem = out_name or f"{topic}_kg"
    src = S.out_dir("extraction", topic) / f"{topic}_{method}.json"
    if not src.exists():
        raise SystemExit(f"[kg] 缺少抽取结果 {src}，先运行 kgc.{method if method != 'ensemble' else 'fuse'}")
    payload = S.read_json(src)

    node_types: Dict[str, str] = {e["id"]: e["type"] for e in payload["entities"]}
    nodes = [
        {"id": e["id"], "label": e["label"], "type": e["type"],
         "properties": e.get("properties", {})}
        for e in payload["entities"]
    ]
    edges: List[dict] = []
    for r in payload["relations"]:
        # 文档节点：结构关系 mentioned_in 的尾实体在抽取阶段是 doc:<id>，这里补齐节点
        for nid in (r["source"], r["target"]):
            if nid not in node_types:
                node_types[nid] = "Document"
                nodes.append({"id": nid, "label": nid.split(":", 1)[-1], "type": "Document",
                              "properties": {}})
        edges.append({
            "source": r["source"], "target": r["target"], "relation": r["relation"],
            "doc": r.get("doc", ""), "evidence": r.get("evidence", "")[:200],
            "confidence": r.get("properties", {}).get("confidence",
                                                      r.get("properties", {}).get("confidence", 1.0)),
            "methods": r.get("properties", {}).get("methods", [method]),
        })

    type_counts: Dict[str, int] = {}
    for n in nodes:
        type_counts[n["type"]] = type_counts.get(n["type"], 0) + 1

    kg = {
        "topic": topic, "source_method": method,
        "ontology": {"namespace": cfg["ontology_seed"]["namespace"],
                     "title": cfg["ontology_seed"].get("title", "")},
        "node_count": len(nodes), "edge_count": len(edges),
        "node_type_counts": dict(sorted(type_counts.items(), key=lambda kv: -kv[1])),
        "edge_relation_counts": _counts(e["relation"] for e in edges),
        "nodes": nodes, "edges": edges,
    }

    out = S.out_dir("kg", topic)
    json_path = S.write_json(out / f"{stem}.json", kg)
    ttl_path = out / f"{stem}.ttl"
    ttl_path.write_text(export_ttl(cfg, kg), encoding="utf-8")
    graphml_path = export_graphml(out / f"{stem}.graphml", kg)
    cyto_path = S.write_json(out / f"{stem}_cytoscape.json", export_cytoscape(kg))

    if verbose:
        print(f"[kg] method={method} 节点 {kg['node_count']} · 边 {kg['edge_count']}")
        print(f"[kg] 节点类型：{kg['node_type_counts']}")
        print(f"[kg] 关系分布：{kg['edge_relation_counts']}")
        print(f"[kg] -> {json_path}")
        print(f"[kg] -> {ttl_path}")
    return {"json": str(json_path), "ttl": str(ttl_path), "graphml": str(graphml_path),
            "cytoscape": str(cyto_path), "stats": kg}


def _counts(items) -> dict:
    out: Dict[str, int] = {}
    for i in items:
        out[i] = out.get(i, 0) + 1
    return dict(sorted(out.items(), key=lambda kv: -kv[1]))


def export_ttl(cfg: dict, kg: dict) -> str:
    ns = kg["ontology"]["namespace"]
    lines = [
        "@prefix owl: <http://www.w3.org/2002/07/owl#> .",
        "@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .",
        "@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .",
        "@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .",
        f"@prefix : <{ns}> .",
        "",
    ]
    for n in kg["nodes"]:
        lines.append(f':{_local(n["id"])} a :{n["type"]} ;')
        lines.append(f'    rdfs:label "{n["label"]}" ;')
        lines.append(f'    rdfs:isDefinedBy <kg:{kg["topic"]}#{n["id"]}> .')
        lines.append("")
    for e in kg["edges"]:
        lines.append(f':{_local(e["source"])} :{e["relation"]} :{_local(e["target"])} .')
    lines.append("")
    lines.append("# 边数/节点数摘要（便于快速核对导入结果）")
    lines.append(f'<kg:{kg["topic"]}> a owl:Ontology ;')
    lines.append(f'    rdfs:label "{kg["topic"]} KG ({kg["source_method"]})" ;')
    lines.append(f'    rdfs:comment "nodes={kg["node_count"]} edges={kg["edge_count"]}" .')
    return "\n".join(lines) + "\n"


def export_graphml(path, kg: dict) -> str:
    try:
        import networkx as nx

        g = nx.DiGraph()
        for n in kg["nodes"]:
            g.add_node(n["id"], label=n["label"], type=n["type"])
        for e in kg["edges"]:
            g.add_edge(e["source"], e["target"], relation=e["relation"])
        p = str(path)
        nx.write_graphml(g, p)
        return p
    except Exception as exc:  # networkx 缺失时不阻塞主流程
        return f"(skip graphml: {exc})"


def export_cytoscape(kg: dict) -> dict:
    return {
        "elements": {
            "nodes": [{"data": {"id": n["id"], "label": n["label"], "type": n["type"]}}
                      for n in kg["nodes"]],
            "edges": [{"data": {"id": f'e{i}', "source": e["source"], "target": e["target"],
                                "label": e["relation"]}}
                      for i, e in enumerate(kg["edges"])],
        },
        "stats": {"nodes": kg["node_count"], "edges": kg["edge_count"]},
    }


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="阶段二收尾：构建知识图谱并多格式导出")
    ap.add_argument("--topic", required=True)
    ap.add_argument("--method", default="ensemble",
                    choices=["rule", "model", "llm", "ensemble"])
    ap.add_argument("--out-name", default=None,
                    help="旁路产物文件名（不含扩展名），默认 <topic>_kg")
    a = ap.parse_args()
    build(a.topic, a.method, out_name=a.out_name)
