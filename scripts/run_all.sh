#!/usr/bin/env bash
# 一键跑通某选题的三阶段流水线（教学用；每一步都可单独跑，见 README）
#
#   bash scripts/run_all.sh t5-protocol-rfc
#   bash scripts/run_all.sh t1-net-assets --fixture      # 用离线示意语料
#
# 失败即停（set -e），任何一步报错都能在日志里看到是哪一步——不要吞错。
set -euo pipefail

TOPIC="${1:-t5-protocol-rfc}"
MODE="${2:-}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="$ROOT/.venv/bin/python"

if [ ! -x "$PY" ]; then
  echo "找不到 $PY：请先创建 venv 并安装依赖（见 README）" >&2
  exit 1
fi

cd "$ROOT"
step() { printf '\n=== %s ===\n' "$*"; }

step "0. 语料"
if [ "$MODE" = "--fixture" ]; then
  "$PY" scripts/fetch_corpus.py --topic "$TOPIC" --fixture
elif [ ! -d "data/corpus/$TOPIC" ] || [ -z "$(ls -A "data/corpus/$TOPIC" 2>/dev/null)" ]; then
  "$PY" scripts/fetch_corpus.py --topic "$TOPIC"
else
  echo "data/corpus/$TOPIC 已有语料，跳过下载"
fi

step "1. 本体（阶段一）"
"$PY" -m kgc.ontology --topic "$TOPIC"
"$PY" -m kgc.ontology --topic "$TOPIC" --check

step "2. 方法A 规则/词典"
"$PY" -m kgc.rule --topic "$TOPIC"

step "3. 方法B 模型"
"$PY" -m kgc.model --topic "$TOPIC" --min-prob 0.6

step "4. 方法C LLM（--from-file 离线产物；有 API 时可去掉）"
LLM_FILE="data/llm_output/${TOPIC}_agent_llm.json"
if [ -f "$LLM_FILE" ]; then
  "$PY" -m kgc.llm --topic "$TOPIC" --from-file "$LLM_FILE"
else
  echo "缺少 ${LLM_FILE}：本选题尚未提供离线 LLM 产物，先跳过（报告中说明即可）"
fi

step "5. 融合（阶段二）"
"$PY" -m kgc.fuse --topic "$TOPIC"

step "6. 建图"
"$PY" -m kgc.kg --topic "$TOPIC"

step "7. 金标准自检 + 评测"
"$PY" scripts/check_gold.py --topic "$TOPIC" || echo "⚠ 金标准自检未通过：先修正 gold.jsonl 再看评测结论"
"$PY" -m kgc.evaluate --topic "$TOPIC"

step "8. 阶段三：KG 增强问答"
"$PY" -m kgc.agent_app --topic "$TOPIC" bench

step "9. Neo4j Cypher 生成（可选导入）"
"$PY" -m kgc.neo4j_import --topic "$TOPIC"

printf '\n全部完成。产物：\n'
printf '  本体   data/ontology/%s_ontology.{ttl,json}\n' "$TOPIC"
printf '  抽取   data/extraction/%s_{rule,model,llm,ensemble}.json\n' "$TOPIC"
printf '  图谱   data/kg/%s_kg.{json,ttl,graphml}\n' "$TOPIC"
printf '  报告   data/reports/%s_{eval.json,eval.md,qa_bench.json}\n' "$TOPIC"
printf '\n提示：用 --fixture 可跳过真实数据下载；MCP 冒烟测试见 scripts/mcp_smoke_client.py\n'
