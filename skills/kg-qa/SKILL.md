---
name: kg-qa
description: "基于知识图谱作答：先用 kgc 查询图谱，再回答并标注三元组序号，图谱未覆盖时说不知道。"
version: 1.1.0
author: ONTOWEB / kgcourse-starter
license: MIT
platforms: [linux, macos, windows]
metadata:
  intellect:
    tags: [KnowledgeGraph, RAG, Teaching]
    related_skills: [native-mcp]
---

# 基于知识图谱的问答（KG-grounded QA）

## 何时使用

用户问的是**某个已建好的知识图谱里的事实**（协议规范、网络资产、漏洞情报、
日志根因、路由事件、等保条款……），且本机存在该图谱的构建产物
（`data/kg/<topic>_kg.json`）。此时**不要凭模型记忆作答**，必须走图谱检索。

## 前置确认（先做这一步）

```bash
python -m kgc.agent_tools --topic <topic> stats
```

- 有输出 → 图谱可用，继续第 1 步；
- 报错 `缺少 .../<topic>_kg.json` → 告诉用户尚未建图，提示运行
  `python -m kgc.kg --topic <topic>`，不要继续猜测答案。

## 步骤

1. **确认实体名**（不要凭猜测写实体名）
   ```bash
   python -m kgc.agent_tools --topic <topic> search --keyword "<用户问题中的术语>"
   ```
2. **取子图（带证据）**
   ```bash
   python -m kgc.agent_tools --topic <topic> neighbors --node "<实体>" --depth 2
   ```
   需要多跳关系时用 `path --a "<实体A>" --b "<实体B>"`。
3. **只用检索到的三元组作答**，每条结论后标注三元组序号与来源文档；
   图谱里没有的部分明确写「图谱中无此知识」。
4. **自检（必做）**：把答案写进临时文件后跑验证器，把未支撑句改写或删除：
   ```bash
   # 题目二（CVE × ATT&CK）
   python -m kgc.agent_t2 --topic t2-cve-attack verify "<原问题>" --answer-file <答案文件>
   # 其他选题
   python -m kgc.agent_app --topic <topic> verify \
       --question "<原问题>" --answer-file <答案文件>
   ```
   要求：`unsupported_count = 0`。若无法消除，必须在回答中显式标注该句为推测。
   验证器只认"官方编号是检索三元组端点 + 引用 [n] 与句子相关"，
   `mentioned_in` 等结构边不能作为依据。

## 题目二示例（CVE × CWE × CPE × ATT&CK）

```bash
python -m kgc.agent_tools --topic t2-cve-attack search --keyword "CVE-2021-44228"
python -m kgc.agent_tools --topic t2-cve-attack neighbors --node "CVE-2021-44228" --depth 1
python -m kgc.agent_tools --topic t2-cve-attack path --a "G0096" --b "TA0002"
python -m kgc.agent_t2 --topic t2-cve-attack ask "CVE-2021-44228 的弱点是什么？"
```

`ask` 会打印检索子图、答案、逐句核验和三级溯源；`verify` 只核验已有答案、不调用 LLM。

## 通过 MCP 调用（若已注册 `intellect mcp add kg ...`）

图谱查询也可以直接作为工具调用，无需自己跑命令行：

- `mcp_kg_kg_search(keyword, type)` — 找实体
- `mcp_kg_kg_neighbors(node, depth, relation, direction)` — 取邻域三元组（含证据）
- `mcp_kg_kg_path(a, b)` — 两实体最短路径（已自动排除文档枢纽节点）
- `mcp_kg_kg_stats()` — 图谱规模

## 坑（实测踩过）

1. **文档节点是超级枢纽**：结构关系 `mentioned_in` 让 `doc:xxx` 与全部实体相连，
   任何两实体 2 跳可达。做路径查询时必须排除 Document 类型（本仓库已默认排除）。
2. **置信度截断会丢关键事实**：实测 `TCP operates_at Transport Layer` 置信度 0.4，
   在按置信度取 Top-12 时被截掉，导致问答失败。取子图时优先按"与问题实体直接相邻"
   过滤，而不是单纯按置信度截断。
3. **不要合并不同题目的图谱**：每个选题的命名空间与本体不同，跨题查询会得到错误关系。
4. **结构关系不是知识**：`mentioned_in` 只表示"出现在同一文档"，不能作为事实依据引用。
