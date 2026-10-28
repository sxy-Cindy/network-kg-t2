"""在 Protégé 同款 OWL 上执行一组可复核的 SPARQL 能力题。

这些查询对应题目二的 Agent 应用：
  * 暴露面：PAN-OS 10.2 受哪些 CVE 影响、是否在 KEV；
  * 检测覆盖：T1059.001 由哪些 Sigma 规则覆盖；
  * 多跳：CVE -> CWE -> CAPEC -> Technique -> Tactic；
  * 组织画像：G0096 -> T1059.001 -> TA0002；
  * 数据属性：KEV 日期 / 勒索软件标记；
  * 拒答：不存在的 CVE 返回 0 行。

输出 protege/reports/query_results.json / .md。
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from rdflib import Graph
from rdflib.term import Literal, URIRef

ROOT = Path(__file__).resolve().parents[2]
OWL = ROOT / "protege" / "owl" / "t2-threat-intel.owl.ttl"
QUERY_DIR = ROOT / "protege" / "queries"
REPORT = ROOT / "protege" / "reports"


def jsonable(v: Any) -> Any:
    if v is None:
        return None
    if isinstance(v, (URIRef, Literal)):
        return str(v)
    return v


def run_one(g: Graph, path: Path) -> dict:
    q = path.read_text(encoding="utf-8")
    res = g.query(q)
    rows = [{str(k): jsonable(v) for k, v in row.asdict().items()} for row in res]
    return {
        "query": path.name,
        "title": next((line.lstrip("# ").strip()
                       for line in q.splitlines() if line.strip().startswith("#")), ""),
        "vars": [str(v) for v in res.vars] if res.vars else [],
        "row_count": len(rows),
        "rows": rows,
    }


def main() -> None:
    g = Graph()
    g.parse(OWL, format="turtle")
    results = [run_one(g, p) for p in sorted(QUERY_DIR.glob("*.rq"))]
    payload = {
        "owl": str(OWL.relative_to(ROOT)),
        "triples": len(g),
        "queries": results,
    }
    REPORT.mkdir(parents=True, exist_ok=True)
    (REPORT / "query_results.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    lines = [
        "# Protégé/SPARQL 能力题执行结果",
        "",
        f"- OWL：`{OWL.relative_to(ROOT)}`（{len(g)} 三元组）",
        f"- 查询目录：`protege/queries/`",
        "",
        "| 查询 | 结果行数 | 说明 |",
        "|---|---:|---|",
    ]
    for r in results:
        lines.append(f"| `{r['query']}` | {r['row_count']} | {r['title']} |")
    lines += ["", "## 明细", ""]
    for r in results:
        lines += [f"### {r['query']}", "", r["title"], "",
                  f"返回 **{r['row_count']}** 行。", ""]
        if not r["rows"]:
            lines += ["（0 行：这正是拒答探针的预期结果。）", ""]
            continue
        cols = r["vars"] or list(r["rows"][0].keys())
        lines.append("| " + " | ".join(cols) + " |")
        lines.append("|" + "|".join(["---"] * len(cols)) + "|")
        for row in r["rows"][:12]:
            lines.append("| " + " | ".join(
                str(row.get(c, "")).replace("|", "\\|") for c in cols) + " |")
        if len(r["rows"]) > 12:
            lines.append(f"| … | 共 {len(r['rows'])} 行，见 JSON |" +
                         " |" * (len(cols) - 2))
        lines.append("")
    (REPORT / "query_results.md").write_text("\n".join(lines), encoding="utf-8")

    print(f"[query] {len(results)} 条查询 · OWL {len(g)} triples")
    for r in results:
        print(f"[query] {r['query']:32} {r['row_count']:>3} 行  {r['title']}")
    print(f"[query] -> {REPORT / 'query_results.json'}")


if __name__ == "__main__":
    main()
