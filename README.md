<h1>《知识图谱技术与应用》网络工程专业实践作业脚手架（kgcourse-starter）</h1>

> **本次提交（题目二）**：网络安全威胁情报知识图谱（CVE × CWE × CPE × ATT&CK）。
> 仓库：https://github.com/sxy-Cindy/network-kg-t2
> 一条命令：`scripts\run_t2.cmd`（Windows）／见
> [`topics/t2-cve-attack/README.md`](topics/t2-cve-attack/README.md)。
> 报告：[`report/题目二-威胁情报知识图谱实验报告.md`](report/题目二-威胁情报知识图谱实验报告.md)；
> **Protégé 实现与跑通详解**：[`题目二-Protégé实现与跑通详解.md`](题目二-Protégé实现与跑通详解.md)
> （OWL 导出 17,966 三元组、HermiT 一致、0 不可满足类、10 条 SPARQL、桌面 Protégé 截图）；
> 合规声明：[`docs/题目二-数据来源与合规声明.md`](docs/题目二-数据来源与合规声明.md)。
> 数据快照 2026-10，提交前已通过 `tools/check_restricted_data.py`。
>
> **T5 公共热身（5 分）**：一条命令 `scripts\run_t5.cmd`；日志
> [`report/T5公共热身-运行日志.txt`](report/T5公共热身-运行日志.txt)；≤3 页报告
> [`report/T5公共热身-三方法对比初探.pdf`](report/T5公共热身-三方法对比初探.pdf)。

> 本目录是 [kgcase 仓库](../README.md) 的 `network/` 子项目（2026-10 并入），
> 与 `power/` 子项目（电力合规案例）**互相独立**，共用同一套"本体 → 多路线抽取 → 图谱 → 应用"方法学。

配套文档（`docs/`）：

| 文档 | 读者 | 内容 |
|---|---|---|
| [`学生作业说明.md`](docs/学生作业说明.md) | **学生** | 一页纸：三阶段任务、选题与分层规则、4 周时间线、评分与答辩、数据红线、快速开始 |
| [`选题介绍.html`](docs/选题介绍.html) | **学生** | **图文版 8 选题详解**（内联 SVG 图示 + 实测指标图表，离线可看可打印） |
| [`学生作业说明.pdf`](docs/学生作业说明.pdf) / [`选题介绍.pdf`](docs/选题介绍.pdf) | **学生（打印分发）** | 上面两份的 PDF 版：一页纸 A4 单页、图文版 A4 15 页；`python tools/build_pdf.py` 一键重生成 |
| [`作业方案.md`](docs/作业方案.md) | 教师/教务 | 完整方案：验收标准、数据集核验、实测基线、评分量规、进度与范围调整 |
| [`数据分发与合规.md`](docs/数据分发与合规.md) | 教师/学生 | 受限材料分发边界、逐类评估矩阵、门禁用法、学生合规声明模板 |
| [`评审报告-2026-10-14.md`](docs/评审报告-2026-10-14.md) | 教师 | 方案评审：一致性/合理性/工程质量发现与修复记录 |
| [`评审报告-学生材料-2026-10-17.md`](docs/评审报告-学生材料-2026-10-17.md) | 教师 | **学生材料评审**：8 卡缺参考文献、PDF 未重导、分页留白等问题与修复实测 |

本脚手架把三阶段流水线固化成一键可跑的命令，学生只需改**题目配置**（本体种子、规则、
词典、金标准）与**数据集**，不需要从零写工程代码。参考案例：`~/workspace/kgcase/power`
（电力合规知识图谱，同一套"本体 → 三方法抽取 → KG → RAG/Agent"结构）。

## 快速开始

```bash
cd ~/workspace/kgcase/network
python3.11 -m venv .venv && .venv/bin/pip install -r requirements.txt   # 或见下"离线安装"

# 1) 取语料：t5 用真实 RFC 全文；其余题目先跑离线示意语料做冒烟
.venv/bin/python scripts/fetch_corpus.py --topic t5-protocol-rfc
.venv/bin/python scripts/fetch_corpus.py --all --fixture

# 2) 三阶段流水线（以 t5-protocol-rfc 为例）
.venv/bin/python -m kgc.ontology --topic t5-protocol-rfc          # 阶段一：本体 → TTL + JSON
.venv/bin/python -m kgc.rule     --topic t5-protocol-rfc          # 阶段二·方法A 规则/词典
.venv/bin/python -m kgc.model    --topic t5-protocol-rfc --min-prob 0.6   # 阶段二·方法B 模型
.venv/bin/python scripts/make_llm_prompt.py --topic t5-protocol-rfc       # 方法C：生成可粘贴的提示词包
.venv/bin/python -m kgc.llm --topic t5-protocol-rfc \
    --from-file data/llm_output/t5_agent_llm.json                 # 阶段二·方法C LLM（离线产物）
.venv/bin/python -m kgc.fuse     --topic t5-protocol-rfc          # 融合 + 消歧 + 置信度
.venv/bin/python -m kgc.kg       --topic t5-protocol-rfc          # 建图（JSON/TTL/GraphML/Cytoscape）
.venv/bin/python scripts/check_gold.py --topic t5-protocol-rfc    # 金标准自检
.venv/bin/python -m kgc.evaluate --topic t5-protocol-rfc          # 评测（P/R/F1 + 分档）

# 3) 阶段三：KG 增强应用
.venv/bin/python -m kgc.agent_app --topic t5-protocol-rfc retrieve \
    --question "IPv6 首部包含哪些字段？"                            # 检索 + 组上下文
.venv/bin/python -m kgc.agent_app --topic t5-protocol-rfc bench    # 题库：可回答率 + 幻觉检出
.venv/bin/python scripts/mcp_smoke_client.py --topic t5-protocol-rfc   # MCP 链路冒烟测试
.venv/bin/python tests/test_pipeline.py                            # 全链路自检
```

离线安装（无外网时）：

```bash
.venv/bin/pip install -i https://mirrors.aliyun.com/pypi/simple/ --trusted-host mirrors.aliyun.com \
    rdflib networkx scikit-learn pyyaml requests neo4j mcp
```

## 8 个选题

| ID | 选题 | 语料来源 |
|---|---|---|
| t1-net-assets | 网络设备、接口与链路资产知识图谱 | NetBox 导出 / 设备配置 / 运维台账 |
| t2-cve-attack | 网络安全威胁情报图谱（CVE×CWE×CPE×ATT&CK） | NVD·CVE API·ATT&CK STIX·security-kg 三元组 |
| t3-log-rca | 日志驱动的故障根因图谱 | Loghub（19 数据集 / 4.95 亿行） |
| t4-bgp-routing | BGP 路由事件与 AS 关系图谱 | RouteViews / RIPE RIS / BGPStream 归档 |
| t5-protocol-rfc | TCP/IP 协议与 RFC 规范图谱（**完整示例**） | rfc-editor.org 真实 RFC 全文 |
| t6-ai-dcn | AI 数据中心高性能网络图谱 | OCP MRC / UEC 规范 / arXiv 论文 |
| t7-mlps-compliance | 网络安全等级保护合规图谱 | GB/T 22239-2019 等公开标准 |
| t8-netconfig | 网络配置知识图谱与配置校验（进阶） | Batfish 快照 / Cisco·华为配置 |

## 实测基线（t5-protocol-rfc，5 篇真实 RFC，金标准 23 实体 / 18 三元组）

| 方法 | 实体 F1 | 三元组 P | 三元组 R | 三元组 F1 |
|---|---|---|---|---|
| A 规则/词典 | 0.142 | 0.125 | 0.333 | 0.182 |
| B 模型（弱监督 LogReg-BIO） | 0.128 | 0.024 | 0.278 | 0.044 |
| C LLM（本体约束 + 证据回填） | **0.759** | **0.516** | **0.889** | **0.653** |
| 融合（三路投票） | 0.105 | 0.079 | **0.944** | 0.146 |

> 金标准是抽样，precision 为**下界**。阈值：模型 `min_prob=0.6`，规则邻近窗口 `max_gap=40`。
> 融合层含**质量门槛**：标签合法性（纯数字/单字符丢弃）+ 受控词表（`fusion.controlled_classes`）+ 类继承感知的域值域校验（违规边降权 0.5×），丢弃与降权清单全部记录在 `data/extraction/<topic>_ensemble.json`。

阶段三实测：题库 8 题，图谱可回答率 **0.75**，平均期望三元组覆盖率 **0.667**；
答案验证器对含幻觉句的答案能逐句标出未支撑断言（示例见 `data/reports/*_qa_bench.json`）。

## 目录结构

```
kgc/                 共享引擎（学生一般不改）
  ontology.py        阶段一：本体种子 → TTL(OWL) + JSON，含本体自检
  rule.py            方法A：正则/词典/模板抽取（含邻近窗口约束）
  model.py           方法B：sklearn 词特征 + BIO 序列标注（可换 BERT/BiLSTM-CRF）
  llm.py             方法C：本体约束提示 + JSON 清洗 + 本体校验 + 离线导入
  fuse.py            融合：实体对齐、投票、置信度、一致性分布
  kg.py              建图：JSON / TTL / GraphML / Cytoscape
  evaluate.py        评测：实体级·三元组级 P/R/F1、越界率、证据覆盖率、票数分档
  neo4j_import.py    Neo4j Cypher 生成与直连导入（关系名白名单，防注入）
  agent_tools.py     图谱查询函数（stats/search/neighbors/path/triples）
  agent_app.py       阶段三：检索 → 组上下文 → 生成 → **答案验证**（幻觉检出）
  mcp_server.py      MCP server：把图谱查询暴露为 4 个工具给 Intellect Agent
skills/kg-qa/        Intellect 技能：教导 Agent 先查图再作答、并自检
topics/<id>/         题目配置：ontology.json / patterns.yaml / lexicons.yaml / gold.jsonl / README
scripts/             run_all.sh（一键全流程）/ fetch_corpus.py（真实数据抓取）/ check_gold.py /
                     make_llm_prompt.py（生成可粘贴的 LLM 提示词包）/ mcp_smoke_client.py
data/                语料、本体、抽取、图谱、报告、题库（运行产物）
tools/gen_topics.py  生成 8 个选题的骨架（本体种子集中维护，便于教师批量调整）
```

## 与 Intellect Agent（`~/workspace/intellect-agent`）的接入

两条路，任选一条即可满足作业要求（建议都做）：

1. **Skill 路线**（最简单）：把 `skills/kg-qa/` 拷到 `~/.intellect/skills/`，Agent 在对话中
   自动加载技能，然后按技能里的命令调用 `python -m kgc.agent_tools ...` 查图作答。
2. **MCP 路线**（工程化）：把图谱查询注册为 MCP 工具，Agent 直接调用 `mcp_kg_*`：

   ```bash
   intellect mcp add kg --command /abs/path/kgcase/network/.venv/bin/python \
       --args -m,kgc.mcp_server,--topic,t5-protocol-rfc
   intellect mcp list && intellect mcp test kg
   ```

   等价的 `~/.intellect/config.yaml` 片段见 `kgc/mcp_server.py` 文件头注释。

## 学生必须自己补的部分

- `topics/<id>/patterns.yaml`：按真实语料写规则/模板，并报告命中率；
- `topics/<id>/lexicons.yaml`：领域词典 ≥80 条术语，注明来源；
- `topics/<id>/gold.jsonl`：金标准 30–60 条（关系 ≥20），两人独立标注 + 交叉核对；
- `topics/<id>/ontology.json`：≥10 类 / ≥10 关系，写清设计依据（标准条款号 / 上位本体）；
- 阶段三的题目问答集（`data/qa/<topic>_qa.jsonl`）与幻觉率统计。
