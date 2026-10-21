#!/usr/bin/env python3
"""MCP 冒烟测试客户端：真实通过 stdio 连接 kgc.mcp_server，调用工具并打印结果。

    python scripts/mcp_smoke_client.py --topic t2-cve-attack

作用：验证"阶段三·Agent 访问 KG"的链路真的通了（而不是"应该能通"）。
校验三件事：
  1. 服务器能 initialize，并声明 tools 能力；
  2. tools/list 返回的 4 个工具 schema 完整（Agent 靠它决定何时调用）；
  3. tools/call 真能查到三元组、且返回值带原文证据（Agent 靠它做溯源）。

跨平台：用 `sys.executable` 启动同解释器，继承当前环境变量。原脚手架写死
`.venv/bin/python` 和 Linux PATH，在 Windows 上会直接起不来。
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# 每个选题用真实存在于图里的实体做探针，避免"通了但查不到"被误判为失败。
PROBES = {
    "t2-cve-attack": {
        "neighbor": "T1059.001", "relation": "belongs_to_tactic",
        "path": ("G0096", "TA0002"), "search": "CVE-2021-44228",
        "absent": "RFC 9293",
    },
    "t5-protocol-rfc": {
        "neighbor": "TCP", "relation": "has_field",
        "path": ("TCP", "Transport Layer"), "search": "RFC 9293",
        "absent": "GraphDB",
    },
}


async def run(topic: str) -> int:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    probe = PROBES.get(topic, PROBES["t5-protocol-rfc"])
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONPATH"] = str(ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "kgc.mcp_server", "--topic", topic],
        cwd=str(ROOT),
        env=env,
    )
    failures = 0
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            init = await session.initialize()
            info = getattr(init, "server_info", None) or getattr(init, "serverInfo", None)
            proto = getattr(init, "protocol_version", None) or getattr(init, "protocolVersion", "?")
            print(f"① initialize  ok · server={info.name if info else '?'} protocol={proto}")
            tools = await session.list_tools()
            names = [t.name for t in tools.tools]
            print(f"② tools/list  ok · {len(names)} 个工具：{names}")
            expect = {"kg_stats", "kg_search", "kg_neighbors", "kg_path"}
            missing = expect - set(names)
            if missing:
                print(f"   ✗ 缺少工具：{missing}")
                failures += 1
            for t in tools.tools:
                schema = getattr(t, "input_schema", None) or getattr(t, "inputSchema", None) or {}
                if not t.description or schema.get("properties") is None:
                    print(f"   ✗ {t.name} schema 不完整")
                    failures += 1

            r = await session.call_tool("kg_stats", {})
            stats = json.loads(r.content[0].text)
            print(f"③ kg_stats    ok · 节点 {stats['node_count']} · 边 {stats['edge_count']}")
            print(f"   节点类型：{stats['node_types']}")

            r = await session.call_tool("kg_search", {"keyword": probe["search"]})
            found = json.loads(r.content[0].text)
            print(f"④ kg_search   ok · 关键词 {probe['search']} 命中 {found['count']} 个节点")
            if not found["count"]:
                print("   ✗ 关键词检索为空")
                failures += 1

            r = await session.call_tool("kg_neighbors",
                                        {"node": probe["neighbor"], "depth": 1,
                                         "relation": probe["relation"]})
            nb = json.loads(r.content[0].text)
            print(f"⑤ kg_neighbors ok · {probe['neighbor']} 的 {probe['relation']} "
                  f"三元组 {nb['count']} 条")
            for row in nb["triples"][:3]:
                ev = (row.get("evidence") or "")[:60]
                print(f"    {row['from']} --{row['relation']}--> {row['to']}  | 证据: {ev}")
            if not any(row.get("evidence") for row in nb["triples"]):
                print("   ✗ 三元组未携带证据，Agent 无法溯源")
                failures += 1

            a, b = probe["path"]
            r = await session.call_tool("kg_path", {"a": a, "b": b})
            p = json.loads(r.content[0].text)
            print(f"⑥ kg_path     ok · 路径 {p.get('nodes')} 关系 {p.get('relations')}")
            if not p.get("found"):
                print("   ✗ 期望存在的最短路径未找到")
                failures += 1

            r = await session.call_tool("kg_path", {"a": a, "b": probe["absent"]})
            p = json.loads(r.content[0].text)
            print(f"⑦ 不存在路径时返回 found={p.get('found')} → Agent 应答「图谱中无此知识」")
            if p.get("found"):
                print("   ✗ 不存在的路径被判为存在")
                failures += 1

    print("\n结果：" + ("全部通过 ✅" if not failures else f"{failures} 项失败 ❌"))
    return failures


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--topic", default="t2-cve-attack")
    a = ap.parse_args()
    sys.exit(asyncio.run(run(a.topic)))
