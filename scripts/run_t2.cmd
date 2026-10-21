@echo off
REM ===================================================================
REM  Topic 2: one-command pipeline (Windows / cmd)
REM
REM    scripts\run_t2.cmd
REM
REM  Prereq: .venv created and requirements.txt installed. First run
REM  downloads CVE/NVD/KEV/ATT&CK/CWE/CAPEC/Sigma/EPSS. Method C needs
REM  KGC_LLM_API_KEY (or ANTHROPIC_AUTH_TOKEN); with data\llm_cache
REM  present it can run offline from cache.
REM  Stops immediately on any non-zero exit.
REM
REM  This file is ASCII-only on purpose: cmd.exe parses .cmd bytes with
REM  the OEM codepage, so UTF-8 Chinese text breaks under GBK console.
REM ===================================================================
chcp 65001 >nul
setlocal
cd /d "%~dp0.."
set "PYTHONIOENCODING=utf-8"
set "KGC_TOPIC=t2-cve-attack"

if exist ".venv\Scripts\python.exe" (
  set "PY=.venv\Scripts\python.exe"
) else (
  set "PY=python"
)

echo [run] interpreter: %PY%
"%PY%" -c "import sys;print('[run] Python',sys.version.split()[0])" || goto :fail

if not exist "data\raw\known_exploited_vulnerabilities.json" (
  echo.
  echo === 0. Fetch raw data ^(first run, may be slow^) ===
  "%PY%" scripts\fetch_t2_data.py || goto :fail
) else (
  echo.
  echo === 0. Raw data present, skip download ^(use fetch_t2_data.py --force to refresh^) ===
)

echo.
echo === 1. Lexicons ===
"%PY%" scripts\lexicon_build.py || goto :fail

echo.
echo === 2. Corpus ===
"%PY%" scripts\corpus_build.py || goto :fail

echo.
echo === 3. Ontology ^(stage 1^) ===
"%PY%" -m kgc.ontology --topic t2-cve-attack || goto :fail
"%PY%" -m kgc.ontology --topic t2-cve-attack --check || goto :fail

echo.
echo === 4. Method A: rules/lexicon + structured mapping ===
"%PY%" -m kgc.rule_a --topic t2-cve-attack || goto :fail

echo.
echo === 5. Method B: sequence labeling + relation classifier ===
"%PY%" -m kgc.model_t2 --topic t2-cve-attack || goto :fail

echo.
echo === 6. Method C: ontology-constrained LLM extraction ===
"%PY%" -m kgc.llm_t2 --topic t2-cve-attack || goto :fail

echo.
echo === 7. Gold standard ^(from official structured fields^) ===
"%PY%" scripts\build_gold.py || goto :fail
"%PY%" scripts\check_gold.py --topic t2-cve-attack || goto :fail

echo.
echo === 8. Fusion / disambiguation / confidence ===
"%PY%" -m kgc.fuse --topic t2-cve-attack || goto :fail

echo.
echo === 9. Build graph ===
"%PY%" -m kgc.kg --topic t2-cve-attack || goto :fail

echo.
echo === 10. Extraction quality evaluation ===
"%PY%" -m kgc.evaluate --topic t2-cve-attack || goto :fail

echo.
echo === 11. Cross-source ID mapping verification ===
"%PY%" scripts\cross_source_report.py || goto :fail

echo.
echo === 12. Stage 3: KG-enhanced QA + hallucination rate ===
"%PY%" -m kgc.agent_t2 --topic t2-cve-attack bench || goto :fail

echo.
echo === 13. Hallucination: LLM-only graph vs fused graph ===
"%PY%" scripts\compare_single_vs_fusion.py --topic t2-cve-attack || goto :fail

echo.
echo === 14. MCP smoke test ===
"%PY%" scripts\mcp_smoke_client.py --topic t2-cve-attack || goto :fail

echo.
echo === 15. Scaffold self-test ===
"%PY%" tests\test_pipeline.py || goto :fail

echo.
echo All done.
echo   ontology  data\ontology\t2-cve-attack_ontology.{ttl,json}
echo   extract   data\extraction\t2-cve-attack_{rule,model,llm,ensemble}.json
echo   graph     data\kg\t2-cve-attack_kg.{json,ttl,graphml}
echo   reports   data\reports\t2-cve-attack_{eval,cross_source,qa_bench}.md
echo   compare   data\reports\t2-cve-attack_single_vs_fusion.md
exit /b 0

:fail
echo.
echo [run] FAILED: previous step returned non-zero, stopped.
exit /b 1
