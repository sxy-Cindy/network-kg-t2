"""阶段三：把 KG 查询能力以 **MCP server** 形式暴露给 Intellect Agent（agent loop）。

为什么用 MCP：Agent 需要的不是"一个脚本"，而是**可发现、可调用、带 schema 的工具**。
本模块把 kgc.agent_tools 的四个查询封装成 MCP tools，Intellect 启动时自动发现并注册为
`mcp_kg_*`，Agent 在对话中即可直接调用（无需把图谱内容塞进 prompt）。

接入方式（学生按此操作，两个命令足够）：

    # 1) 安装 MCP 依赖（Intellect 侧需要 mcp 包：pip install mcp）
    # 2) 注册（写入 ~/.intellect/config.yaml 的 mcp_servers）
    #    Windows 用 <repo>/.venv/Scripts/python.exe，Linux/macOS 用 <repo>/.venv/bin/python
    intellect mcp add kg --command <repo>/.venv/Scripts/python.exe \
        --args -m,kgc.mcp_server,--topic,t2-cve-attack
    intellect mcp list        # 确认已注册
    intellect mcp test kg     # 冒烟测试

等价的 config.yaml 片段：

    mcp_servers:
      kg:
        command: "/abs/path/kgcase/network/.venv/Scripts/python.exe"
        args: ["-m", "kgc.mcp_server", "--topic", "t2-cve-attack"]
        cwd: "/abs/path/kgcase/network"
        timeout: 60

启动后 Agent 获得的工具：
    mcp_kg_kg_stats()                       图谱规模统计
    mcp_kg_kg_search(keyword, type)         实体检索
    mcp_kg_kg_neighbors(node, depth, ...)   邻域三元组（带证据）
    mcp_kg_kg_path(a, b)                    两实体最短路径（多跳推理）

兼容性：优先使用官方 `mcp` 包的 FastMCP；若未安装，则退化为本文件内置的
**最小 JSON-RPC 2.0 stdio 服务器**（实现 initialize / tools/list / tools/call），
保证在没有网络/依赖的教学机上也能跑通——这段退化实现本身也是很好的协议教学材料。
"""

from __future__ import annotations

import json
import sys
from typing import Any, Dict, List

from . import agent_tools as KT

TOPIC = "t5-protocol-rfc"

TOOLS: List[Dict[str, Any]] = [
    {
        "name": "kg_stats",
        "description": "返回知识图谱规模统计：节点数、边数、节点类型分布、关系类型分布。",
        "inputSchema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "kg_search",
        "description": "按关键词/类型检索图谱实体。当你不确定实体在图谱中的确切名称时先调用它。",
        "inputSchema": {"type": "object", "properties": {
            "keyword": {"type": "string", "description": "关键词（大小写不敏感）"},
            "type": {"type": "string",
                     "description": "限定本体类，如 Vulnerability/Weakness/Product/Technique"},
            "limit": {"type": "integer", "default": 20},
        }, "required": ["keyword"]},
    },
    {
        "name": "kg_neighbors",
        "description": ("查询某实体的邻域三元组（可指定深度/关系/方向），"
                        "每条结果带原文证据与来源文档 —— 回答问题时必须引用这些证据。"),
        "inputSchema": {"type": "object", "properties": {
            "node": {"type": "string", "description": "实体 ID 或标签"},
            "depth": {"type": "integer", "default": 1, "maximum": 3},
            "relation": {"type": "string", "description": "限定关系（留空为全部）"},
            "direction": {"type": "string", "enum": ["out", "in", "both"], "default": "both"},
        }, "required": ["node"]},
    },
    {
        "name": "kg_path",
        "description": ("查询两个实体之间的最短路径（多跳推理）。"
                        "若返回 found=false，应回答'图谱中无此知识'，不得自行推断。"),
        "inputSchema": {"type": "object", "properties": {
            "a": {"type": "string"}, "b": {"type": "string"},
        }, "required": ["a", "b"]},
    },
]


def _dispatch(name: str, args: Dict[str, Any]) -> dict:
    v = KT.view(TOPIC)
    if name == "kg_stats":
        return v.stats()
    if name == "kg_search":
        return v.search(args.get("keyword", ""), args.get("type", ""), int(args.get("limit", 20)))
    if name == "kg_neighbors":
        return v.neighbors(args["node"], int(args.get("depth", 1)),
                           args.get("relation", ""), args.get("direction", "both"))
    if name == "kg_path":
        return v.path(args["a"], args["b"])
    raise ValueError(f"unknown tool: {name}")


# --------------------------------------------------------------------------- #
# 路线 1：官方 mcp 包（推荐）
# --------------------------------------------------------------------------- #
def serve_fastmcp(topic: str) -> bool:
    try:
        try:
            from mcp.server.fastmcp import FastMCP  # mcp < 2
        except Exception:
            from mcp.server.mcpserver import MCPServer as FastMCP  # mcp >= 2
    except Exception:
        return False

    app = FastMCP(f"kg-{topic}")

    @app.tool(name="kg_stats", description=TOOLS[0]["description"])
    def kg_stats() -> str:
        return json.dumps(_dispatch("kg_stats", {}), ensure_ascii=False)

    @app.tool(name="kg_search", description=TOOLS[1]["description"])
    def kg_search(keyword: str, type: str = "", limit: int = 20) -> str:
        return json.dumps(_dispatch("kg_search", {"keyword": keyword, "type": type, "limit": limit}),
                          ensure_ascii=False)

    @app.tool(name="kg_neighbors", description=TOOLS[2]["description"])
    def kg_neighbors(node: str, depth: int = 1, relation: str = "", direction: str = "both") -> str:
        return json.dumps(_dispatch("kg_neighbors", {"node": node, "depth": depth,
                                                     "relation": relation, "direction": direction}),
                          ensure_ascii=False)

    @app.tool(name="kg_path", description=TOOLS[3]["description"])
    def kg_path(a: str, b: str) -> str:
        return json.dumps(_dispatch("kg_path", {"a": a, "b": b}), ensure_ascii=False)

    app.run()  # stdio transport
    return True


# --------------------------------------------------------------------------- #
# 路线 2：内置最小 JSON-RPC stdio 实现（无依赖兜底）
# --------------------------------------------------------------------------- #
def _send(msg: dict) -> None:
    sys.stdout.write(json.dumps(msg, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def serve_minimal() -> None:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except Exception:
            continue
        method, rid = req.get("method"), req.get("id")
        params = req.get("params") or {}
        if method == "initialize":
            result = {"protocolVersion": "2024-11-05",
                      "capabilities": {"tools": {}},
                      "serverInfo": {"name": f"kg-{TOPIC}", "version": "0.1.0"}}
        elif method == "notifications/initialized":
            continue
        elif method == "tools/list":
            result = {"tools": TOOLS}
        elif method == "tools/call":
            name = params.get("name", "")
            try:
                out = _dispatch(name, params.get("arguments") or {})
                result = {"content": [{"type": "text",
                                       "text": json.dumps(out, ensure_ascii=False)}],
                          "isError": False}
            except Exception as exc:
                result = {"content": [{"type": "text", "text": f"error: {exc}"}], "isError": True}
        else:
            result = {}
        if rid is not None:
            _send({"jsonrpc": "2.0", "id": rid, "result": result})


def main() -> None:
    global TOPIC
    import argparse

    ap = argparse.ArgumentParser(description="KG 查询 MCP server（stdio）")
    ap.add_argument("--topic", default=TOPIC)
    ap.add_argument("--minimal", action="store_true", help="强制使用内置最小实现")
    a = ap.parse_args()
    TOPIC = a.topic
    if not a.minimal and serve_fastmcp(a.topic):
        return
    serve_minimal()


if __name__ == "__main__":
    main()
