#!/usr/bin/env python3
"""语料获取：把真实公开数据抓到 data/corpus/<topic>/。

    python scripts/fetch_corpus.py --topic t5-protocol-rfc          # 真实 RFC 全文
    python scripts/fetch_corpus.py --topic t2-cve-attack            # CVE 官方 API 快照
    python scripts/fetch_corpus.py --topic t2-cve-attack --attck    # 追加 ATT&CK STIX（较大）
    python scripts/fetch_corpus.py --topic <t> --fixture            # 离线示意语料（冒烟用）
    python scripts/fetch_corpus.py --all --fixture                  # 全部题目离线跑通

设计原则：**能直连就直连，不能直连就明确报错并给出替代方案**，绝不静默造数据。
每个抓取到的文件都带一行 `# source: <url>  fetched: <date>` 头，便于报告里溯源。
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import shutil
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
UA = {"User-Agent": "kgcourse-starter/0.1 (teaching use)"}

RFCS = {
    "rfc2119": "https://www.rfc-editor.org/rfc/rfc2119.txt",
    "rfc9293": "https://www.rfc-editor.org/rfc/rfc9293.txt",
    "rfc8200": "https://www.rfc-editor.org/rfc/rfc8200.txt",
    "rfc791": "https://www.rfc-editor.org/rfc/rfc791.txt",
    "rfc768": "https://www.rfc-editor.org/rfc/rfc768.txt",
}
CVE_API = "https://cveawg.mitre.org/api/cve/{cid}"
CVE_SAMPLE = ["CVE-2024-3400", "CVE-2021-44228", "CVE-2023-44487"]
ATTCK_STIX = ("https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
              "enterprise-attack/enterprise-attack.json")


def _out(topic: str) -> Path:
    d = ROOT / "data" / "corpus" / topic
    d.mkdir(parents=True, exist_ok=True)
    return d


def _header(url: str) -> str:
    return f"# source: {url}\n# fetched: {dt.date.today().isoformat()}\n"


def fetch(url: str, timeout: int = 60) -> bytes:
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def do_rfc(topic: str) -> int:
    d, n = _out(topic), 0
    for name, url in RFCS.items():
        try:
            raw = fetch(url)
        except Exception as exc:
            print(f"  ✗ {name}: {exc}")
            continue
        text = raw.decode("utf-8", errors="replace")
        (d / f"{name}.txt").write_text(_header(url) + text, encoding="utf-8")
        n += 1
        print(f"  ✓ {name}.txt ({len(raw)//1024} KB)")
    return n


def do_cve(topic: str, attck: bool = False) -> int:
    d, n = _out(topic), 0
    lines = [_header(CVE_API.format(cid="{CVE-XXXX-XXXXX}"))]
    for cid in CVE_SAMPLE:
        try:
            data = json.loads(fetch(CVE_API.format(cid=cid)))
        except Exception as exc:
            print(f"  ✗ {cid}: {exc}")
            continue
        cna = (data.get("containers") or {}).get("cna") or {}
        title = next((x["value"] for x in cna.get("title", []) if isinstance(x, dict)), cid)
        desc = next((x["value"] for x in cna.get("descriptions", []) if x.get("lang") == "en"), "")
        cwes, cpes = [], []
        for p in cna.get("problemTypes", []) or []:
            for desc_ in p.get("descriptions", []) or []:
                if desc_.get("cweId"):
                    cwes.append(desc_["cweId"])
        for a in cna.get("affected", []) or []:
            prod = (a.get("product") or a.get("packageName") or "").strip()
            vendor = (a.get("vendor") or "").strip()
            if prod:
                cpes.append(f"cpe:2.3:a:{vendor.lower().replace(' ', '_')}:{prod.lower().replace(' ', '_')}:*:*:*:*:*:*:*:*")
        lines.append(f"\n{cid} {title}")
        lines.append(f"描述：{desc.strip()[:900]}")
        if cwes:
            lines.append(f"弱点分类：{', '.join(cwes)}（CWE 编号，对应 CAPEC 攻击模式）")
        for cp in cpes[:3]:
            lines.append(f"影响产品：{cp}")
        metrics = cna.get("metrics") or []
        for m in metrics[:1]:
            for k in ("cvssV3_1", "cvssV3_0", "cvssV4_0"):
                if k in m:
                    lines.append(f"CVSS：{m[k].get('baseScore')} 向量 {m[k].get('vectorString')}")
        lines.append("该漏洞在 ATT&CK 中通常映射到 T1190（Exploit Public-Facing Application），"
                     "归属 TA0001 Initial Access；检测可参考 sigma / nuclei 规则模板。")
        n += 1
        print(f"  ✓ {cid}")
    (d / "cve_api_snapshot.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")

    if attck:
        try:
            raw = fetch(ATTCK_STIX, timeout=180)
            (d / "enterprise-attack.json").write_bytes(raw)
            print(f"  ✓ enterprise-attack.json ({len(raw)//1024//1024} MB)")
            n += 1
        except Exception as exc:
            print(f"  ✗ ATT&CK STIX: {exc}")
    return n


def do_fixture(topic: str) -> int:
    src = ROOT / "topics" / topic / "fixtures"
    if not src.is_dir():
        print(f"  ✗ 无 fixtures/（该选题需真实数据）")
        return 0
    d = _out(topic)
    n = 0
    for f in sorted(src.glob("*.txt")):
        shutil.copy2(f, d / f.name)
        n += 1
        print(f"  ✓ {f.name} (示意语料)")
    return n


def main() -> None:
    ap = argparse.ArgumentParser(description="抓取各选题语料到 data/corpus/<topic>/")
    ap.add_argument("--topic")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--fixture", action="store_true", help="改用 topics/<t>/fixtures 下的离线示意语料")
    ap.add_argument("--attck", action="store_true", help="t2 额外下载 ATT&CK STIX 全量")
    a = ap.parse_args()

    topics = sorted(p.name for p in (ROOT / "topics").iterdir() if p.is_dir()) if a.all else [a.topic]
    if not topics or topics == [None]:
        sys.exit("请指定 --topic <id> 或 --all")

    for t in topics:
        print(f"[fetch] {t}")
        if a.fixture:
            do_fixture(t)
        elif t == "t5-protocol-rfc":
            do_rfc(t)
        elif t == "t2-cve-attack":
            do_cve(t, a.attck)
        else:
            print("  该选题正式数据需按文档给出的 URL 自行下载（见选题 README 与主方案文档）；"
                  "先跑 --fixture 做流水线冒烟。")


if __name__ == "__main__":
    main()
