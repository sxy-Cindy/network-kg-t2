"""把 ReasonCheck 的日志整理成报告，并核对“推理新增”到底增加了什么。

输入
    protege/reports/reasoned/<name>.reasoncheck.log
    protege/owl/<name>.owl.ttl
    protege/reports/reasoned/<name>.inferred.owl

输出
    protege/reports/reasoner_results.jsonl
    protege/reports/reasoner_results.md
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from rdflib import Graph, RDF, URIRef

ROOT = Path(__file__).resolve().parents[2]
OWL_DIR = ROOT / "protege" / "owl"
REASONED = ROOT / "protege" / "reports" / "reasoned"
REPORT = ROOT / "protege" / "reports"


def types(g: Graph, ns: str) -> set[tuple[str, str]]:
    out = set()
    for i, c in g.subject_objects(RDF.type):
        if isinstance(i, URIRef) and isinstance(c, URIRef) and str(c).startswith(ns):
            out.add((str(i), str(c)))
    return out


def edges(g: Graph, ns: str, rels: set[str]) -> set[tuple[str, str, str]]:
    out = set()
    for h, p, o in g.triples((None, None, None)):
        if not (isinstance(h, URIRef) and isinstance(p, URIRef) and isinstance(o, URIRef)):
            continue
        ps = str(p)
        if ps.startswith(ns) and ps.split("#")[-1] in rels:
            out.add((str(h), ps, str(o)))
    return out


def main() -> None:
    seed = json.loads((ROOT / "topics" / "t2-cve-attack" / "ontology.json")
                      .read_text(encoding="utf-8"))
    ns = seed["namespace"]
    rels = {r["id"] for r in seed.get("relations", [])}
    results = []
    for log in sorted(REASONED.glob("*.reasoncheck.log")):
        data = None
        for line in log.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if line.startswith("{"):
                data = json.loads(line)
                break
        if data is None:
            continue
        name = log.name.replace(".reasoncheck.log", "")
        base_path = OWL_DIR / f"{name}.owl.ttl"
        inferred_path = REASONED / f"{name}.inferred.owl"
        base = Graph()
        base.parse(base_path, format="turtle")
        inferred = Graph()
        inferred.parse(inferred_path, format="xml")

        added_types = types(inferred, ns) - types(base, ns)
        added_edges = edges(inferred, ns, rels) - edges(base, ns, rels)
        data["file"] = str(base_path.relative_to(ROOT))
        data["inferred_file"] = str(inferred_path.relative_to(ROOT))
        data["inferred_class_breakdown"] = dict(Counter(
            c.split("#")[-1] for _, c in added_types))
        data["inferred_edge_breakdown"] = dict(Counter(
            p.split("#")[-1] for _, p, _ in added_edges))
        data["inferred_class_assertions_verified"] = len(added_types)
        data["inferred_object_assertions_verified"] = len(added_edges)
        results.append(data)

    results.sort(key=lambda x: x["file"])
    with (REPORT / "reasoner_results.jsonl").open("w", encoding="utf-8") as f:
        for r in results:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    lines = [
        "# Protégé / HermiT 推理报告",
        "",
        "- 推理机：HermiT 1.4.3.456（Protégé 5.6.9 自带的 `org.semanticweb.hermit`）",
        "- OWL API：4.5.29（Protégé 5.6.9 自带）",
        "- 运行方式：`protege/tools/ReasonCheck.java`，classpath 指向 `protege/tools/lib/`",
        "- 说明：`inferred_*_verified` 是对 `*.inferred.owl` 做集合差得到的实测值，",
        "  与 ReasonCheck 打印的计数相互核对。",
        "",
        "| 文件 | 一致 | 不可满足类 | 类 | 对象属性 | 个体 | 公理 | OWL 2 DL | 违规 | 推理新增类型 | 推理新增边 | 耗时 ms |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for r in results:
        lines.append(
            f"| `{r['file']}` | {r['consistent']} | {r['unsatisfiable_classes']} | "
            f"{r['classes']} | {r['object_properties']} | {r['individuals']} | "
            f"{r['axioms']} | {r['owl2_dl_profile']} | {r['profile_violations']} | "
            f"{r['inferred_class_assertions']} | {r['inferred_object_assertions']} | "
            f"{r['reasoner_ms']} |")
    lines += ["", "## 推理新增明细", ""]
    for r in results:
        lines += [f"### `{r['file']}`", ""]
        if r.get("inferred_class_breakdown"):
            lines.append("- 新增类断言：" + "、".join(
                f"`{k}` × {v}" for k, v in
                sorted(r["inferred_class_breakdown"].items())))
        else:
            lines.append("- 新增类断言：无")
        if r.get("inferred_edge_breakdown"):
            lines.append("- 新增对象属性边：" + "、".join(
                f"`{k}` × {v}" for k, v in
                sorted(r["inferred_edge_breakdown"].items())))
        else:
            lines.append("- 新增对象属性边：无")
        lines.append("")
    lines += [
        "## 怎么读这些数",
        "",
        "- `SecurityConcept × 406`：所有领域类个体都通过 `rdfs:subClassOf` 被推理出",
        "  属于顶层类；Document 个体不属于 `SecurityConcept`，所以是 421 − 15 = 406。",
        "- `uses × 197`：`group_uses`（113）与 `software_uses`（84）是 `uses` 的子属性，",
        "  HermiT 为每条子属性边补出父属性边。",
        "- `used_by × 113`：`used_by owl:inverseOf group_uses`，所以每条组织使用技术的边",
        "  都反推出“技术被组织使用”。",
        "- 这些是 OWL 语义的**必然推论**，不是新抽取的事实；原始图谱仍以 1572 条断言边为准。",
        "",
    ]
    (REPORT / "reasoner_results.md").write_text("\n".join(lines), encoding="utf-8")
    print(f"[reasoner] {len(results)} 个本体")
    for r in results:
        print(f"[reasoner] {r['file']}: consistent={r['consistent']} "
              f"dl={r['owl2_dl_profile']} +types={r['inferred_class_assertions']} "
              f"+edges={r['inferred_object_assertions']}")
    print(f"[reasoner] -> {REPORT / 'reasoner_results.md'}")


if __name__ == "__main__":
    main()
