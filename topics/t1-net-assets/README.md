# 选题 `t1-net-assets` — 网络设备、接口与链路资产知识图谱

把设备/接口/链路/IP 段/厂商/角色串成资产拓扑图，支撑影响面分析与故障定位问答。

## 语料

- 真实数据集/标准：见主文档《知识图谱技术与应用·网络工程实践作业方案》该选题小节
  （source_url: https://github.com/netbox-community/netbox）
- 脚手架自带 `fixtures/`：**小型示意语料**，只用于把三阶段流水线跑通；
  正式提交必须换成真实数据，并在报告中写明数据来源、版本、下载日期。

## 命令

```bash
python -m kgc.ontology --topic t1-net-assets          # 阶段一：本体 → TTL/JSON
python -m kgc.ontology --topic t1-net-assets --check  # 本体自检
python -m kgc.rule    --topic t1-net-assets           # 阶段二·方法A（规则）
python -m kgc.model   --topic t1-net-assets           # 阶段二·方法B（模型）
python -m kgc.llm     --topic t1-net-assets --from-file <llm输出.json>   # 阶段二·方法C（LLM）
python -m kgc.fuse    --topic t1-net-assets           # 三方法融合 + 消歧
python -m kgc.kg      --topic t1-net-assets           # 建图 → JSON/TTL/GraphML/Cytoscape
python -m kgc.evaluate --topic t1-net-assets          # 对金标准评测
python -m kgc.agent_tools --topic t1-net-assets stats # 阶段三：图谱查询
python -m kgc.mcp_server --topic t1-net-assets        # 阶段三：暴露为 MCP 工具给 Intellect
```

## 需要学生补全的部分

1. `patterns.yaml`：本选题的规则/模板（当前为示例，需按真实语料补全并给出命中率）。
2. `lexicons.yaml`：领域词典（建议 ≥80 条术语，注明来源）。
3. `gold.jsonl`：金标准 30–60 条（关系 ≥20），两人独立标注 + 交叉核对。
4. `ontology.json`：按真实数据扩展类/关系（≥10 类 / ≥10 关系），并说明设计依据。
