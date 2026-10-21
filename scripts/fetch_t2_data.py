#!/usr/bin/env python3
"""T2 真实数据获取（可复现、幂等、带来源与许可记录）。

数据源（全部为公开可下载、许可明确的数据）：
  1. CVE Services API 2.1  https://cveawg.mitre.org/api/cve/<CVE-ID>
  2. CISA KEV             https://www.cisa.gov/known-exploited-vulnerabilities-catalog
  3. MITRE ATT&CK STIX    https://github.com/mitre-attack/attack-stix-data
  4. MITRE CWE XML        https://cwe.mitre.org/data/xml/cwec_latest.xml.zip
  5. MITRE CAPEC XML      https://capec.mitre.org/data/xml/capec_latest.xml
  6. FIRST EPSS           https://api.first.org/data/v1/epss

只取 40 条 CVE 的切片（课程要求：不要全量导入 3137 万条三元组）。
所有原始文件放在 data/raw/（已 gitignore），派生语料放在 data/corpus/<topic>/。
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOPIC = "t2-cve-attack"

# Windows 控制台默认 GBK，脚本输出含中文/符号；统一改成 UTF-8，避免 UnicodeEncodeError
try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except Exception:  # noqa: BLE001
    pass
RAW = ROOT / "data" / "raw"
UA = {"User-Agent": "kgcourse-t2/1.0 (course assignment; contact: student)"}

CVE_IDS = """CVE-2024-3400 CVE-2023-20198 CVE-2023-20273 CVE-2024-20353 CVE-2024-20359
CVE-2022-42475 CVE-2018-13379 CVE-2023-27997 CVE-2023-36845 CVE-2023-36844
CVE-2023-4966 CVE-2023-3519 CVE-2019-19781 CVE-2020-5902 CVE-2021-22986
CVE-2022-1388 CVE-2019-11510 CVE-2021-22893 CVE-2023-46805 CVE-2024-21887
CVE-2024-21893 CVE-2022-47966 CVE-2021-44228 CVE-2021-45046 CVE-2022-22965
CVE-2022-26134 CVE-2021-26084 CVE-2023-34362 CVE-2023-0669 CVE-2020-14882
CVE-2022-21587 CVE-2023-44487 CVE-2021-34527 CVE-2020-1472 CVE-2019-0708
CVE-2017-0144 CVE-2021-26855 CVE-2021-27065 CVE-2022-30190 CVE-2023-23397""".split()

SOURCES = {
    "kev": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "attack_stix": ("https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
                    "master/enterprise-attack/enterprise-attack.json"),
    "cwe_xml": "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip",
    "capec_xml": "https://capec.mitre.org/data/xml/capec_latest.xml",
}
LICENSES = {
    "cve": "CVE Program Terms of Use (public; attribution required)",
    "kev": "U.S. Government Works (public domain)",
    "attack_stix": "MITRE ATT&CK Terms of Use (free use with attribution)",
    "cwe_xml": "MITRE CWE Terms of Use (free use with attribution)",
    "capec_xml": "MITRE CAPEC Terms of Use (free use with attribution)",
    "epss": "FIRST EPSS data (CC BY 4.0 attribution)",
}


def _get(url: str, timeout: int = 120) -> bytes:
    last = None
    for attempt in range(4):
        try:
            req = urllib.request.Request(url, headers=UA)
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.read()
        except Exception as exc:  # noqa: BLE001
            last = exc
            time.sleep(1.5 * (attempt + 1))
    raise RuntimeError(f"下载失败 {url}: {last}")


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def fetch_cve(cid: str, out_dir: Path) -> tuple[str, str]:
    out = out_dir / f"{cid}.json"
    if out.exists() and out.stat().st_size > 1000:
        return cid, "cached"
    raw = _get(f"https://cveawg.mitre.org/api/cve/{cid}", timeout=45)
    if not raw.lstrip().startswith(b"{"):
        raise RuntimeError(f"{cid}: 返回非 JSON")
    out.write_bytes(raw)
    return cid, f"{len(raw)//1024} KB"


def fetch_nvd(cid: str, out_dir: Path) -> tuple[str, str]:
    """NVD 2.0 补充 CPE / CWE（CVE 官方记录常常没有 CPE）。无 API key 时限速 5 次/30s。"""
    out = out_dir / f"{cid}.json"
    if out.exists() and out.stat().st_size > 1000:
        return cid, "cached"
    raw = _get(f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cid}", timeout=60)
    data = json.loads(raw)
    if not data.get("vulnerabilities"):
        raise RuntimeError(f"{cid}: NVD 无结果")
    out.write_bytes(raw)
    time.sleep(6.2)  # NVD 公共限速：无 key 5 requests / 30 seconds
    return cid, f"{len(raw)//1024} KB"


def fetch_sources(force: bool = False) -> dict:
    RAW.mkdir(parents=True, exist_ok=True)
    cve_dir = RAW / "cve"
    cve_dir.mkdir(exist_ok=True)
    report = {"topic": TOPIC, "fetched_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
              "sources": {}}

    files = {
        "kev": RAW / "known_exploited_vulnerabilities.json",
        "attack_stix": RAW / "enterprise-attack.json",
        "cwe_xml": RAW / "cwec_latest.xml.zip",
        "capec_xml": RAW / "capec_latest.xml",
    }
    for key, path in files.items():
        if force or not path.exists() or path.stat().st_size < 10000:
            print(f"[fetch] {key} ...", flush=True)
            path.write_bytes(_get(SOURCES[key], timeout=600))
        report["sources"][key] = {"url": SOURCES[key], "path": str(path.relative_to(ROOT)),
                                  "bytes": path.stat().st_size, "sha256": sha256(path),
                                  "license": LICENSES[key]}

    # CVE 40 条并发抓取（官方 API 比较宽容，限 6 并发）
    results = {}
    with ThreadPoolExecutor(max_workers=6) as pool:
        futs = {pool.submit(fetch_cve, cid, cve_dir): cid for cid in CVE_IDS}
        for fut in as_completed(futs):
            cid = futs[fut]
            try:
                _, status = fut.result()
                results[cid] = status
                print(f"  ✓ {cid} {status}", flush=True)
            except Exception as exc:  # noqa: BLE001
                results[cid] = f"ERROR: {exc}"
                print(f"  ✗ {cid}: {exc}", flush=True)
    report["sources"]["cve_api"] = {
        "url": "https://cveawg.mitre.org/api/cve/{cveId}",
        "cve_count": len(CVE_IDS),
        "ok": sum(1 for v in results.values() if not str(v).startswith("ERROR")),
        "license": LICENSES["cve"], "detail": results,
    }

    # NVD 2.0：补 CPE/CWE（CVE 官方记录对老漏洞常缺 CPE）
    nvd_dir = RAW / "nvd"
    nvd_dir.mkdir(exist_ok=True)
    nvd_ok = 0
    for cid in CVE_IDS:
        try:
            _, st = fetch_nvd(cid, nvd_dir)
            nvd_ok += 1
            print(f"  ✓ NVD {cid} {st}", flush=True)
        except Exception as exc:  # noqa: BLE001
            print(f"  ✗ NVD {cid}: {exc}", flush=True)
    report["sources"]["nvd_api"] = {
        "url": "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cveId}",
        "cve_count": len(CVE_IDS), "ok": nvd_ok,
        "license": "NVD / U.S. Government Works (public domain)",
    }

    # EPSS 批量（一个请求）
    epss_path = RAW / "epss_scores.json"
    if force or not epss_path.exists():
        q = ",".join(CVE_IDS)  # FIRST EPSS 用逗号分隔，重复 cve= 参数会被截断
        try:
            epss_path.write_bytes(_get(f"https://api.first.org/data/v1/epss?cve={q}", timeout=90))
        except Exception as exc:  # noqa: BLE001
            print(f"[fetch] EPSS 失败（非阻塞）：{exc}")
    if epss_path.exists():
        report["sources"]["epss"] = {
            "url": "https://api.first.org/data/v1/epss", "path": str(epss_path.relative_to(ROOT)),
            "bytes": epss_path.stat().st_size, "sha256": sha256(epss_path),
            "license": LICENSES["epss"],
        }

    out = ROOT / "data" / "reports" / f"{TOPIC}_data_channel.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    # 人类可读的数据通道验证日志（第 1 周检查点）
    lines = ["# T2 数据通道验证（Data Channel Verification）", "",
             f"- 时间（UTC）：{report['fetched_at']}",
             f"- 选题：{TOPIC}",
             f"- 规划 CVE 数：{len(CVE_IDS)}；成功：{report['sources']['cve_api']['ok']}", "",
             "| 源 | URL | 本地文件 | 大小 | SHA-256（前 16） | 许可 |",
             "|---|---|---|---|---|---|"]
    for key, info in report["sources"].items():
        if key == "cve_api":
            continue
        lines.append(f"| {key} | {info['url']} | `{info['path']}` | {info['bytes']//1024} KB "
                     f"| `{info['sha256'][:16]}` | {info['license']} |")
    lines += ["", "## 校验命令", "", "```bash",
              "python scripts/fetch_t2_data.py            # 幂等重跑，已有文件跳过",
              "python -c \"import json;d=json.load(open('data/reports/t2-cve-attack_data_channel.json'));print(d['sources']['cve_api']['ok'])\"",
              "```", ""]
    (ROOT / "data" / "reports" / f"{TOPIC}_data_channel.md").write_text("\n".join(lines), encoding="utf-8")
    print(f"[fetch] 报告 -> {out}")
    return report


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--force", action="store_true", help="重新下载所有原始文件")
    a = ap.parse_args()
    rep = fetch_sources(a.force)
    ok = rep["sources"]["cve_api"]["ok"]
    sys.exit(0 if ok == len(CVE_IDS) else 1)
