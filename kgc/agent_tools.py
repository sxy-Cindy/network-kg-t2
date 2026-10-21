"""阶段三的查询底座：知识图谱查询函数（无外部依赖，供 skill / MCP / 教学演示复用）。

设计原则（对应阶段三的验收点）：**Agent 只能通过本模块访问图谱**，
不允许让 LLM 凭记忆回答领域问题。所有返回值都带三元组原文与来源文档，
以便答案可溯源（"图谱里没有 → 回答'图谱中无此知识'"，而不是编一个）。

命令行（也是 skill 里给 Agent 用的调用方式）：
    python -m kgc.agent_tools --topic t5-protocol-rfc stats
    python -m kgc.agent_tools --topic t5-protocol-rfc search --keyword TCP
    python -m kgc.agent_tools --topic t5-protocol-rfc neighbors --node RFC8200 --depth 2
    python -m kgc.agent_tools --topic t5-protocol-rfc path --a RFC8200 --b Protocol
    python -m kgc.agent_tools --topic t5-protocol-rfc triples --relation operatesAt
"""

from __future__ import annotations

import json
from collections import deque
from pathlib import Path
from typing import Dict, List, Optional

from . import schema as S


# --------------------------------------------------------------------------- #
# 数据装载与索引
# --------------------------------------------------------------------------- #
class KGView:
    def __init__(self, kg: dict):
        self.kg = kg
        self.nodes: Dict[str, dict] = {n["id"]: n for n in kg["nodes"]}
        self.out: Dict[str, List[dict]] = {}
        self.inc: Dict[str, List[dict]] = {}
        for e in kg["edges"]:
            self.out.setdefault(e["source"], []).append(e)
            self.inc.setdefault(e["target"], []).append(e)
        # 标签与别名都参与解析：规范标签是官方编号（G0096），但用户会问 "APT41"
        self.label2ids: Dict[str, List[str]] = {}
        self.aliases: Dict[str, List[str]] = {}
        for nid, n in self.nodes.items():
            self.label2ids.setdefault(S.norm_label(n["label"]).lower(), []).append(nid)
            for a in (n.get("properties") or {}).get("aliases") or []:
                self.aliases.setdefault(S.norm_label(a).lower(), []).append(nid)
                self.label2ids.setdefault(S.norm_label(a).lower(), []).append(nid)

    # -- 解析：允许用 ID 或标签（大小写、空白不敏感）指定节点 --
    def resolve(self, ref: str) -> Optional[str]:
        if ref in self.nodes:
            return ref
        cands = self.label2ids.get(S.norm_label(ref).lower(), [])
        if len(cands) == 1:
            return cands[0]
        if len(cands) > 1:
            return cands[0]  # 歧义时取第一个并在结果里标注 ambiguous
        # 退化：子串匹配
        for nid, n in self.nodes.items():
            if ref.lower() in n["label"].lower():
                return nid
        return None

    def stats(self) -> dict:
        return {
            "topic": self.kg.get("topic"),
            "source_method": self.kg.get("source_method"),
            "node_count": self.kg["node_count"], "edge_count": self.kg["edge_count"],
            "node_types": self.kg["node_type_counts"],
            "relations": self.kg["edge_relation_counts"],
        }

    def search(self, keyword: str = "", node_type: str = "", limit: int = 20) -> dict:
        hits = []
        kw = S.norm_label(keyword).lower()
        for nid, n in self.nodes.items():
            if node_type and n["type"] != node_type:
                continue
            aliases = (n.get("properties") or {}).get("aliases") or []
            if kw and kw not in n["label"].lower() and kw not in nid.lower() \
                    and not any(kw in a.lower() for a in aliases):
                continue
            hits.append({"id": nid, "label": n["label"], "type": n["type"]})
            if len(hits) >= limit:
                break
        return {"keyword": keyword, "type": node_type, "hits": hits, "count": len(hits)}

    def neighbors(self, ref: str, depth: int = 1, relation: str = "",
                  direction: str = "both", limit: int = 40) -> dict:
        start = self.resolve(ref)
        if not start:
            return {"error": "node_not_found", "query": ref, "hint": "先用 search 确认节点存在"}
        seen = {start: 0}
        q = deque([(start, 0)])
        rows: List[dict] = []
        while q:
            cur, d = q.popleft()
            if d >= depth:
                continue
            edges = []
            if direction in ("out", "both"):
                edges += self.out.get(cur, [])
            if direction in ("in", "both"):
                edges += self.inc.get(cur, [])
            for e in edges:
                if relation and e["relation"] != relation:
                    continue
                other = e["target"] if e["source"] == cur else e["source"]
                rows.append({
                    "from": self.nodes.get(e["source"], {}).get("label", e["source"]),
                    "relation": e["relation"],
                    "to": self.nodes.get(e["target"], {}).get("label", e["target"]),
                    "doc": e.get("doc", ""), "evidence": e.get("evidence", "")[:160],
                    "confidence": e.get("confidence"),
                })
                if other not in seen:
                    seen[other] = d + 1
                    q.append((other, d + 1))
                if len(rows) >= limit:
                    q.clear()
                    break
        return {"node": self.nodes.get(start, {}).get("label", start),
                "depth": depth, "triples": rows, "count": len(rows)}

    def path(self, a: str, b: str, max_len: int = 4,
             exclude_types: tuple = ("Document",)) -> dict:
        """两实体间最短路径。

        ⚠ 教学要点（实测踩坑）：结构关系 `mentioned_in` 会让每个"文档节点"与它内部
        全部实体相连，于是文档节点成为图的**超级枢纽**——任何两个实体都能在 2 跳内
        连通（a → doc → b），最短路径失去意义。实测中 `RFC 9293 → Transport Layer`
        就是这样被"抄近路"的。解决办法：路径搜索默认排除 Document 类节点，
        只在"实体—实体"的语义边上找路径。这一点必须在实验报告里写清楚。
        """
        sa, sb = self.resolve(a), self.resolve(b)
        if not sa or not sb:
            return {"found": False, "reason": "node_not_found", "a": a, "b": b,
                    "message": "图谱中不存在该实体（可作为'无此知识'的判据）"}
        # BFS 最短路径（无向），排除枢纽型节点
        prev: Dict[str, tuple] = {sa: (None, None)}
        q = deque([sa])
        while q:
            cur = q.popleft()
            if cur == sb:
                break
            nbrs = [(e["target"], e["relation"]) for e in self.out.get(cur, [])]
            nbrs += [(e["source"], e["relation"]) for e in self.inc.get(cur, [])]
            for nxt, rel in nbrs:
                if nxt in prev:
                    continue
                if self.nodes.get(nxt, {}).get("type") in exclude_types:
                    continue
                prev[nxt] = (cur, rel)
                q.append(nxt)
        if sb not in prev:
            return {"found": False,
                    "message": "图谱中不存在连通路径（可作为'无此知识'的判据）",
                    "excluded_types": list(exclude_types)}
        nodes_path, rels_path = [], []
        cur = sb
        while cur is not None:
            nodes_path.append(self.nodes.get(cur, {}).get("label", cur))
            p, rel = prev[cur]
            if rel:
                rels_path.append(rel)
            cur = p
        nodes_path.reverse()
        rels_path.reverse()
        if len(rels_path) > max_len:
            return {"found": True, "hops": len(rels_path), "nodes": nodes_path,
                    "relations": rels_path, "note": f"路径长度超过 max_len={max_len}"}
        return {"found": True, "hops": len(rels_path), "nodes": nodes_path,
                "relations": rels_path}

    def triples(self, relation: str = "", head: str = "", tail: str = "",
                min_confidence: float = 0.0, limit: int = 50) -> dict:
        rows = []
        for e in self.kg["edges"]:
            if relation and e["relation"] != relation:
                continue
            if head and S.norm_label(head).lower() not in \
                    S.norm_label(self.nodes.get(e["source"], {}).get("label", "")).lower():
                continue
            if tail and S.norm_label(tail).lower() not in \
                    S.norm_label(self.nodes.get(e["target"], {}).get("label", "")).lower():
                continue
            if (e.get("confidence") or 1.0) < min_confidence:
                continue
            rows.append({
                "head": self.nodes.get(e["source"], {}).get("label", e["source"]),
                "head_type": self.nodes.get(e["source"], {}).get("type", ""),
                "relation": e["relation"],
                "tail": self.nodes.get(e["target"], {}).get("label", e["target"]),
                "tail_type": self.nodes.get(e["target"], {}).get("type", ""),
                "doc": e.get("doc", ""), "confidence": e.get("confidence"),
                "methods": e.get("methods", []),
            })
            if len(rows) >= limit:
                break
        return {"filters": {"relation": relation, "head": head, "tail": tail,
                            "min_confidence": min_confidence},
                "triples": rows, "count": len(rows)}


_CACHE: Dict[str, KGView] = {}


def view(topic: str, method: str = "ensemble", kg_file: str | None = None) -> KGView:
    """kg_file 指向旁路图谱（如 LLM 单方法对照图）；默认读 <topic>_kg.json。"""
    p = Path(kg_file) if kg_file else S.out_dir("kg", topic) / f"{topic}_kg.json"
    if not p.is_absolute():
        p = S.repo_root() / p
    key = f"{topic}:{method}:{p}"
    if key not in _CACHE:
        if not p.exists():
            raise SystemExit(f"[agent_tools] 缺少 {p}，先运行 kgc.kg --topic {topic}")
        _CACHE[key] = KGView(S.read_json(p))
    return _CACHE[key]


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def main() -> None:
    import argparse

    ap = argparse.ArgumentParser(description="KG 查询工具（Agent/教学/脚本共用）")
    ap.add_argument("--topic", required=True)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("stats")
    p = sub.add_parser("search"); p.add_argument("--keyword", default=""); p.add_argument("--type", default=""); p.add_argument("--limit", type=int, default=20)
    p = sub.add_parser("neighbors"); p.add_argument("--node", required=True); p.add_argument("--depth", type=int, default=1); p.add_argument("--relation", default=""); p.add_argument("--direction", default="both")
    p = sub.add_parser("path"); p.add_argument("--a", required=True); p.add_argument("--b", required=True)
    p = sub.add_parser("triples"); p.add_argument("--relation", default=""); p.add_argument("--head", default=""); p.add_argument("--tail", default=""); p.add_argument("--min-confidence", type=float, default=0.0); p.add_argument("--limit", type=int, default=50)
    a = ap.parse_args()
    v = view(a.topic)
    if a.cmd == "stats":
        out = v.stats()
    elif a.cmd == "search":
        out = v.search(a.keyword, a.type, a.limit)
    elif a.cmd == "neighbors":
        out = v.neighbors(a.node, a.depth, a.relation, a.direction)
    elif a.cmd == "path":
        out = v.path(a.a, a.b)
    else:
        out = v.triples(a.relation, a.head, a.tail, a.min_confidence, a.limit)
    print(json.dumps(out, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
