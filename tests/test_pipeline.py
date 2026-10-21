"""脚手架自检：一条命令验证三阶段流水线在本机可跑通。

    .venv/bin/python -m pytest tests -q      （或直接 python tests/test_pipeline.py）

覆盖：本体生成与 TTL 合法性、三方法抽取、融合、建图、金标准自检、评测、
图谱查询、答案验证、MCP 工具分发。不依赖网络（RFC 语料需先抓取）。
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

TOPIC = os.environ.get("KGC_TOPIC", "t5-protocol-rfc")


def _has_corpus() -> bool:
    return any((ROOT / "data" / "corpus" / TOPIC).glob("*.txt"))


def test_ontology_and_ttl():
    from kgc import ontology

    out = ontology.build(TOPIC, verbose=False)
    assert Path(out["ttl"]).exists() and Path(out["json"]).exists()
    from rdflib import Graph

    g = Graph()
    g.parse(out["ttl"], format="turtle")
    assert len(g) > 50, "本体 TTL 三元组数量异常"
    report = ontology.validate(TOPIC)
    assert report["ok"], f"本体自检失败: {report['problems']}"


def test_gold_selfcheck():
    from scripts.check_gold import check

    r = check(TOPIC)
    assert r["checked"] > 0, "金标准为空"
    assert r["ok"], f"金标准存在问题: {r['problems']}"


def test_pipeline_rule_fuse_kg_eval():
    if not _has_corpus():
        print(f"[skip] 缺少 {TOPIC} 语料，先跑 scripts/fetch_corpus.py --topic {TOPIC}")
        return
    from kgc import evaluate, fuse, kg

    if TOPIC == "t2-cve-attack":
        from kgc import rule_a as rule
    else:
        from kgc import rule

    r = rule.run(TOPIC, verbose=False)
    assert r["entity_count"] > 0 and r["relation_count"] > 0
    assert not r["unknown_types"], f"抽取出现本体外的类: {r['unknown_types']}"
    assert not r["unknown_relations"], f"抽取出现本体外的关系: {r['unknown_relations']}"

    f = fuse.run(TOPIC, verbose=False)
    assert f["relation_count"] > 0
    assert all(0 < r["properties"]["confidence"] <= 1 for r in f["relations"])

    built = kg.build(TOPIC, "ensemble", verbose=False)
    kgj = json.loads(Path(built["json"]).read_text(encoding="utf-8"))
    assert kgj["node_count"] == len(kgj["nodes"])
    assert kgj["edge_count"] == len(kgj["edges"])
    assert kgj["node_type_counts"]

    # 注意 out_name：自检必须写独立报告名，否则会用子集方法覆盖正式报告
    # （实测踩坑：曾把 4 方法报告覆盖成 rule+ensemble 两方法）
    rep = evaluate.run(TOPIC, methods=("rule", "ensemble"),
                       out_name=f"{TOPIC}_eval_test", verbose=False)
    assert "rule" in rep["methods"]
    assert rep["methods"]["rule"]["triple"]["recall"] >= 0


def test_agent_tools_and_verify():
    if not _has_corpus():
        print("[skip] 缺语料")
        return
    from kgc import agent_tools

    v = agent_tools.view(TOPIC)
    st = v.stats()
    assert st["node_count"] > 0

    if TOPIC == "t2-cve-attack":
        from kgc import agent_t2 as agent
        assert v.search("CVE-2021-44228")["count"] >= 1
        nb = v.neighbors("T1059.001", depth=1, relation="belongs_to_tactic")
        assert nb["count"] >= 1 and any(t.get("evidence") for t in nb["triples"])
        p = v.path("G0096", "TA0002")
        assert p.get("found") and "doc" not in " ".join(p.get("nodes", []))
        ret = agent.retrieve(v, "CVE-2021-44228 的弱点是什么？")
        rows = ret[0]
        weak = [r for r in rows if r["relation"] == "has_weakness"][:1]
        assert weak, "检索结果缺少 has_weakness"
        # 正确句可溯源；编造的编号必须被抓出来
        res = agent.verify(
            f"CVE-2021-44228 的弱点是 {weak[0]['to_label']}[1]。"
            "它也影响 CVE-1999-0001[1]。",
            weak, agent.I.IdResolver.from_cfg(agent.S.load_topic(TOPIC)), v, {})
        assert res["unsupported_count"] >= 1, "验证器未能检出幻觉句"
        assert res["supported_count"] >= 1, "验证器误杀正确句"
        return

    from kgc import agent_app
    assert v.search("TCP")["count"] >= 1
    nb = v.neighbors("TCP", depth=1, relation="has_field")
    assert nb["count"] >= 1 and any(t.get("evidence") for t in nb["triples"])
    # 路径查询必须排除文档枢纽，否则会得到 a -> doc -> b 的伪路径
    p = v.path("RFC 9293", "Transport Layer")
    assert p.get("found") is None or "doc" not in " ".join(p.get("nodes", []))

    ret = agent_app.retrieve(TOPIC, "IPv6 首部包含哪些字段？")
    assert ret["triple_count"] >= 1
    # 验证器必须能识别出图谱未支撑的断言
    res = agent_app.verify("IPv6 首部包含 Hop Limit 字段。IPv6 由 ISO 在 1985 年发布。",
                           ret["triples"])
    assert res["unsupported"] >= 1, "验证器未能检出幻觉句"
    assert res["supported"] >= 1, "验证器误杀正确句"


def test_mcp_tool_dispatch():
    if not _has_corpus():
        print("[skip] 缺语料")
        return
    import kgc.mcp_server as M

    M.TOPIC = TOPIC
    st = M._dispatch("kg_stats", {})
    st = json.loads(st) if isinstance(st, (str, bytes)) else st
    assert st["node_count"] > 0
    names = {t["name"] for t in M.TOOLS}
    assert names == {"kg_stats", "kg_search", "kg_neighbors", "kg_path"}
    for t in M.TOOLS:
        assert t["description"] and t["inputSchema"]["type"] == "object"


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn()
            print(f"PASS  {fn.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"FAIL  {fn.__name__}: {e}")
        except Exception as e:  # noqa: BLE001
            failed += 1
            print(f"ERROR {fn.__name__}: {type(e).__name__}: {e}")
    print(f"\n{len(fns) - failed}/{len(fns)} 通过")
    sys.exit(1 if failed else 0)
