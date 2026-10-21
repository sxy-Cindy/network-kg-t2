@echo off
REM ===================================================================
REM  T5 public warm-up: one-command pipeline (Windows / cmd)
REM
REM    scripts\run_t5.cmd
REM
REM  Runs the scaffold on the bundled RFC fixtures: ontology -> three
REM  extraction methods -> fusion -> graph -> evaluation -> KG QA ->
REM  MCP smoke test. Method C reads a saved LLM output file, so this
REM  command needs no API key and no network.
REM
REM  This file is ASCII-only on purpose: cmd.exe parses .cmd bytes with
REM  the OEM codepage, so UTF-8 Chinese text breaks under GBK console.
REM ===================================================================
chcp 65001 >nul
setlocal
cd /d "%~dp0.."
set "PYTHONIOENCODING=utf-8"

if exist ".venv\Scripts\python.exe" (
  set "PY=.venv\Scripts\python.exe"
) else (
  set "PY=python"
)

"%PY%" -c "import sys;print('[run] Python',sys.version.split()[0])" || goto :fail

echo.
echo === 1. Ontology (stage 1) ===
"%PY%" -m kgc.ontology --topic t5-protocol-rfc || goto :fail
"%PY%" -m kgc.ontology --topic t5-protocol-rfc --check || goto :fail

echo.
echo === 2. Method A: rules + lexicon ===
"%PY%" -m kgc.rule --topic t5-protocol-rfc || goto :fail

echo.
echo === 3. Method B: sequence labeling + relation classifier ===
"%PY%" -m kgc.model --topic t5-protocol-rfc --min-prob 0.6 || goto :fail

echo.
echo === 4. Method C: LLM output (saved, no API key needed) ===
"%PY%" -m kgc.llm --topic t5-protocol-rfc --from-file data/llm_output/t5_agent_llm.json || goto :fail

echo.
echo === 5. Fusion / disambiguation / quality gates ===
"%PY%" -m kgc.fuse --topic t5-protocol-rfc || goto :fail

echo.
echo === 6. Build graph ===
"%PY%" -m kgc.kg --topic t5-protocol-rfc || goto :fail

echo.
echo === 7. Gold check + evaluation ===
"%PY%" scripts\check_gold.py --topic t5-protocol-rfc || goto :fail
"%PY%" -m kgc.evaluate --topic t5-protocol-rfc || goto :fail

echo.
echo === 8. Stage 3: KG-enhanced QA bench ===
"%PY%" -m kgc.agent_app --topic t5-protocol-rfc bench || goto :fail

echo.
echo === 9. MCP smoke test ===
"%PY%" scripts\mcp_smoke_client.py --topic t5-protocol-rfc || goto :fail

echo.
echo All done.
echo   ontology  data\ontology\t5-protocol-rfc_ontology.{ttl,json}
echo   extract   data\extraction\t5-protocol-rfc_{rule,model,llm,ensemble}.json
echo   graph     data\kg\t5-protocol-rfc_kg.{json,ttl,graphml}
echo   reports   data\reports\t5-protocol-rfc_eval.md
echo   qa bench  data\reports\t5-protocol-rfc_qa_bench.json
exit /b 0

:fail
echo.
echo [run] FAILED: previous step returned non-zero, stopped.
exit /b 1
