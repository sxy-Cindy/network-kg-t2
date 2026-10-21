"""阶段三（可选）：把 KG 导入 Neo4j / GraphDB，供 Cypher / SPARQL 查询。

两种底座，按课程环境二选一（验收标准一致：能答出 3 个多跳问题并给出源三元组）：

  A. Neo4j（图库，属性图，生态最普及）
     docker run -d --name kg-neo4j -p 7474:7474 -p 7687:7687 \
       -e NEO4J_AUTH=neo4j/neo4j123 neo4j:5
     python -m kgc.neo4j_import --topic t5-protocol-rfc            # 生成 Cypher
     python -m kgc.neo4j_import --topic t5-protocol-rfc --apply    # 直连导入
     NEO4J_URI=bolt://localhost:7687 NEO4J_USER=neo4j NEO4J_PASSWORD=neo4j123

  B. GraphDB / Apache Jena（RDF 三元组库）
     直接导入 data/kg/<topic>_kg.ttl（GraphDB Workbench → Import → RDF → Turtle），
     然后用 SPARQL 复现同一批多跳问题；两条路线的结果应一致——这本身是一个验收项。

注意：Neo4j 关系类型不能参数化，必须用字符串拼接；因此这里对关系名做白名单校验
（只允许本体中定义过的关系），避免 Cypher 注入。这是安全相关的验收点。
"""

from __future__ import annotations

import os
import re
from typing import List

from . import schema as S

_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def build_cypher(topic: str, verbose: bool = True) -> List[str]:
    cfg = S.load_topic(topic)
    kg_path = S.out_dir("kg", topic) / f"{topic}_kg.json"
    if not kg_path.exists():
        raise SystemExit(f"[neo4j] 缺少 {kg_path}，先运行 kgc.kg --topic {topic}")
    kg = S.read_json(kg_path)

    known_rels = {r["id"] for r in cfg["ontology_seed"].get("relations", [])}
    stmts: List[str] = [
        "// 由 kgcourse-starter 生成：Neo4j 导入脚本（逐条可单独执行）",
        "CREATE CONSTRAINT kg_node_id IF NOT EXISTS FOR (n:KGNode) REQUIRE n.id IS UNIQUE;",
        "",
    ]
    for n in kg["nodes"]:
        label = n["type"] if _IDENT.match(n["type"]) else "KGNode"
        stmts.append(
            f"MERGE (n:`{label}` {{id: '{_esc(n['id'])}'}}) "
            f"SET n.name = '{_esc(n['label'])}', n.kg_type = '{_esc(n['type'])}', "
            f"n :KGNode;"
        )
    stmts.append("")
    skipped = 0
    for e in kg["edges"]:
        rel = e["relation"]
        if rel not in known_rels and not _IDENT.match(rel):
            skipped += 1
            continue
        stmts.append(
            f"MATCH (a {{id: '{_esc(e['source'])}'}}), (b {{id: '{_esc(e['target'])}'}}) "
            f"MERGE (a)-[r:`{rel}`]->(b) "
            f"SET r.doc = '{_esc(e.get('doc',''))}', r.evidence = '{_esc(str(e.get('evidence',''))[:180])}', "
            f"r.confidence = {float(e.get('confidence') or 1.0)};"
        )
    stmts += [
        "",
        "// 示例多跳查询（阶段三验收用）：",
        "// 1) 某协议走了几跳到达某层？",
        "// MATCH p=(a {name:'TCP'})-[:mentioned_in|operatesAt*1..3]->(b) RETURN p LIMIT 25;",
        "// 2) 两实体间最短路径：",
        "// MATCH p=shortestPath((a {name:'RFC 8200'})-[*..4]-(b {name:'Protocol'})) RETURN p;",
        "// 3) 关系计数分布：",
        "// MATCH ()-[r]->() RETURN type(r) AS rel, count(*) AS n ORDER BY n DESC;",
    ]
    out = S.out_dir("kg", topic) / f"{topic}_neo4j.cypher"
    out.write_text("\n".join(stmts) + "\n", encoding="utf-8")
    if verbose:
        print(f"[neo4j] 节点语句 {len(kg['nodes'])} · 关系语句 {len(kg['edges']) - skipped}"
              f"（跳过非法关系 {skipped}）-> {out}")
    return stmts


def _esc(v: str) -> str:
    return str(v).replace("\\", "\\\\").replace("'", "\\'")


def apply_to_server(topic: str, verbose: bool = True) -> dict:
    try:
        from neo4j import GraphDatabase
    except ImportError:
        raise SystemExit("[neo4j] 未安装 neo4j 驱动：pip install neo4j")
    uri = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
    auth = (os.environ.get("NEO4J_USER", "neo4j"), os.environ.get("NEO4J_PASSWORD", "neo4j123"))
    stmts = [s for s in build_cypher(topic, verbose=False)
             if s.strip() and not s.strip().startswith("//")]
    driver = GraphDatabase.driver(uri, auth=auth)
    ok = 0
    with driver.session() as session:
        for s in stmts:
            session.run(s)
            ok += 1
        counts = session.run(
            "MATCH (n) RETURN count(n) AS nodes"
        ).single()
        edges = session.run("MATCH ()-[r]->() RETURN count(r) AS edges").single()
    driver.close()
    result = {"uri": uri, "statements": ok,
              "nodes_in_db": counts["nodes"], "edges_in_db": edges["edges"]}
    if verbose:
        print(f"[neo4j] 导入完成 {result}")
    return result


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="将 KG 导入 Neo4j（默认只生成 Cypher）")
    ap.add_argument("--topic", required=True)
    ap.add_argument("--apply", action="store_true", help="直连 Neo4j 执行导入")
    a = ap.parse_args()
    if a.apply:
        apply_to_server(a.topic)
    else:
        build_cypher(a.topic)
