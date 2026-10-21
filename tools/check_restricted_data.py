#!/usr/bin/env python3
"""受限数据提交前门禁：扫描仓库中"不应公开/应脱敏"的内容。

    .venv/bin/python tools/check_restricted_data.py                 # 扫全仓（排除 .venv/.git）
    .venv/bin/python tools/check_restricted_data.py --staged        # 只扫 git 暂存区（更适合做 pre-commit）

为什么需要它：本仓库**对学生公开**（参考答案开放），而课程语料里混有不可公开的材料：
推荐性国家标准全文（GB/T 系列，无再分发授权）、实验室设备配置（含管理地址/口令散列）、
自采日志（含内网 IP/主机名）。靠"记得别提交"是靠不住的，必须机器化门禁。

检查项与判定依据（分级：高 = 必须移除；中 = 需确认/脱敏；低 = 提示）：
  高 · 标准全文       文件含 `GB/T 22239`/`GB/T 28448` 且章节编号行 ≥20 且体量 > 30 KB
                      ——判据刻意保守：只在正文里引用条款号不应被误判
  高 · 设备配置       含 ≥5 行厂商配置特征（`enable secret`/`username ... password`/
                      `snmp-server community`/`ip route`/`switchport`/`interface <if>`）
  高 · 凭据           匹配 `(password|passwd|secret|api_key|token) = <非占位符>`
  高 · 二进制/归档    `.pcap/.pcapng/.parquet/.zip/.tar*/,.db/.xlsx/.pem/.key`
  低 · 真实日志       .txt/.log/.csv 中含 ≥6 行 syslog 时间戳（`Mon DD HH:MM:SS`）
  中 · 大数据文件     > 5 MB 的文本/CSV/JSON（大概率是原始数据集，应改为下载脚本）
  低 · 配置里的地址   配置类文件中紧邻 `ip/address/gateway/neighbor/peer` 或带 `/掩码` 的
                      非文档用网段地址（避免把条款编号 `8.1.3.1` 误判为 IP）

白名单（明确允许公开，附理由）：
  data/corpus/t5-protocol-rfc/rfc*.txt   RFC 文本可完整再分发（IETF Trust 法律条款，文件内含版权声明）
  topics/*/fixtures/*.txt 及其**内容相同**的 data/corpus 副本  自写示意语料（RFC 5737 文档用网段、
                                        虚构主机名），本仓库自己的产物，允许公开（按 sha256 内容指纹判定）
  *.md 中的示例代码块                    允许出现 `password: ***` 等占位符

退出码：0 = 无高风险项；1 = 存在高风险项（不得提交）。
"""

from __future__ import annotations

import argparse
import hashlib
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

SKIP_DIRS = {".git", ".venv", "venv", "__pycache__", "node_modules", ".mypy_cache", "build", "dist",
             # 原始下载与 LLM 缓存已在 .gitignore 中排除，可由脚本重建，不属于提交内容。
             # 提交前请用 --staged 检查真正会进入仓库的文件。
             "raw", "llm_cache"}
TEXT_EXT = {".md", ".txt", ".py", ".json", ".jsonl", ".yaml", ".yml", ".csv", ".cypher", ".sh",
            ".cfg", ".conf", ".log"}
BINARY_BAD = {".pcap", ".pcapng", ".parquet", ".zip", ".tar", ".gz", ".tgz", ".db", ".sqlite",
              ".xlsx", ".xls", ".pem", ".key", ".p12", ".jks", ".ovpn"}
WHITELIST = [
    re.compile(r"^data/corpus/t5-protocol-rfc/rfc\d+\.txt$"),   # RFC 可再分发
    re.compile(r"^topics/[^/]+/fixtures/[^/]+\.txt$"),           # 自写示意语料
    re.compile(r"^(power|network)/data/corpus/t5-protocol-rfc/rfc\d+\.txt$"),
]

CRED_RX = re.compile(r"(?i)\b(password|passwd|secret|api[_-]?key|access[_-]?token)\b\s*[:=]\s*(\S{6,})")
CRED_PLACEHOLDER = re.compile(r"(?i)^(\*{3,}|<[^>]+>|\$\{?[A-Z_]+\}?|xxx+|changeme|example|placeholder|"
                              r"redacted|your[_-]?\w+|not-needed|todo)")
CONFIG_RX = re.compile(r"(?im)^\s*(enable secret|username \S+ (password|secret)|snmp-server community|"
                       r"ip route |switchport |interface (Gi|Te|Fa|Eth|GE|XGE|Vlanif|Loopback)\S*|"
                       r"hostname \S+)")
SYSLOG_RX = re.compile(r"(?m)^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}")
GB_RX = re.compile(r"GB/T\s?(22239|28448|25058|35770|35746)")
GB_CLAUSE_RX = re.compile(r"(?m)^\s*\d{1,2}\.\d{1,2}(\.\d{1,2}){0,2}\s+\S+")
# 负向先行断言里必须用非捕获组，否则 group(1) 会被内层组占掉（实测踩过）
PUBLIC_IP_RX = re.compile(r"\b(?!10\.|127\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|192\.0\.2\.|"
                          r"198\.51\.100\.|203\.0\.113\.|0\.|255\.)"
                          r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")
# 只有"看得像网络配置"的地址才算线索，否则会把条款编号（8.1.3.1）当成 IP
IP_CONTEXT_RX = re.compile(r"(?i)(ip|address|gateway|neighbor|peer|prefix|route)[^\n]{0,20}$|/\d{1,2}\b")

findings: list[tuple[str, str, str]] = []      # (severity, path, message)
scanned = 0


def iter_files(staged_only: bool):
    if staged_only:
        out = subprocess.run(["git", "-C", str(ROOT), "diff", "--cached", "--name-only"],
                             capture_output=True, text=True).stdout.split()
        for name in out:
            p = ROOT / name
            if p.is_file():
                yield p
        return
    for p in ROOT.rglob("*"):
        if any(part in SKIP_DIRS for part in p.parts) or not p.is_file():
            continue
        yield p


def is_whitelisted(rel: str) -> bool:
    return any(rx.match(rel) for rx in WHITELIST)


def fixture_hashes() -> set[str]:
    """topics/*/fixtures/*.txt 的内容指纹：这些是我们自己写的示意语料，
    复制到 data/corpus/<topic>/ 后仍允许公开（按内容判定，避免路径白名单被绕过）。"""
    out: set[str] = set()
    for p in ROOT.glob("topics/*/fixtures/*.txt"):
        out.add(hashlib.sha256(p.read_bytes()).hexdigest())
    return out


FIXTURE_SHA = None


def check(p: Path) -> None:
    global scanned
    rel = p.relative_to(ROOT).as_posix()
    if is_whitelisted(rel):
        return
    global FIXTURE_SHA
    if FIXTURE_SHA is None:
        FIXTURE_SHA = fixture_hashes()
    if p.suffix.lower() == ".txt" and hashlib.sha256(p.read_bytes()).hexdigest() in FIXTURE_SHA:
        return
    size = p.stat().st_size
    if p.suffix.lower() in BINARY_BAD:
        findings.append(("高", rel, f"二进制/归档文件（{p.suffix}，{size/1024:.0f} KB）不应入库"))
        return
    if p.suffix.lower() not in TEXT_EXT and size > 200_000:
        return
    if size > 5 * 1024 * 1024:
        findings.append(("中", rel, f"大文本文件 {size/1024/1024:.1f} MB：原始数据集应改为下载脚本"))
        return
    try:
        text = p.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return
    scanned += 1

    n_cfg = len(CONFIG_RX.findall(text)) if p.suffix.lower() != ".py" else 0
    if n_cfg >= 5:
        findings.append(("高", rel, f"疑似设备配置（命中 {n_cfg} 行厂商配置特征）"))
    if GB_RX.search(text):
        n_clause = len(GB_CLAUSE_RX.findall(text))
        if n_clause >= 20 and size > 30_000:
            findings.append(("高", rel, f"疑似推荐性国家标准全文（{size//1024} KB，"
                                        f"{n_clause} 处章节编号）——无再分发授权，禁止入公网仓库"))
    for m in CRED_RX.finditer(text):
        val = m.group(2)
        if CRED_PLACEHOLDER.match(val):
            continue
        findings.append(("高", rel, f"疑似真实凭据：`{m.group(1)} = {val[:12]}…`（第 "
                                    f"{text[:m.start()].count(chr(10)) + 1} 行）"))
        break
    if p.suffix.lower() in (".txt", ".log", ".csv"):
        n_syslog = len(SYSLOG_RX.findall(text))
        if n_syslog >= 6:
            findings.append(("低", rel, f"疑似日志文本（{n_syslog} 行 syslog 时间戳）"
                                        f"——须脱敏或标注为示意语料"))
    # 只检查配置类文件，且要求地址处于"像网络配置"的上下文里
    if p.suffix.lower() in (".txt", ".cfg", ".conf", ".cypher", ".sh"):
        ips = {m.group(1) for m in PUBLIC_IP_RX.finditer(text)
               if IP_CONTEXT_RX.search(text[max(0, m.start() - 24):m.end() + 4])}
        if ips:
            findings.append(("低", rel, f"配置类文件中出现非文档用网段地址 {sorted(ips)[:3]}"
                                        f"——确认非真实环境地址"))


def main() -> None:
    ap = argparse.ArgumentParser(description="受限数据提交前门禁")
    ap.add_argument("--staged", action="store_true", help="只检查 git 暂存区（pre-commit 用）")
    ap.add_argument("--quiet", action="store_true")
    a = ap.parse_args()

    for p in iter_files(a.staged):
        check(p)

    order = {"高": 0, "中": 1, "低": 2}
    findings.sort(key=lambda x: (order[x[0]], x[1]))
    high = [f for f in findings if f[0] == "高"]

    if not a.quiet:
        print(f"== 受限数据检查（{'暂存区' if a.staged else '全仓'}）：扫描 {scanned} 个文本文件 ==")
        for sev, path, msg in findings:
            print(f"  [{sev}] {path}: {msg}")
        if not findings:
            print("  未发现受限内容 ✅")
    print(f"\n高风险 {len(high)} 项 · 中/低 {len(findings) - len(high)} 项"
          + ("——存在高风险项，禁止提交" if high else "——通过"))
    sys.exit(1 if high else 0)


if __name__ == "__main__":
    main()
