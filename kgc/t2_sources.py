"""T2 数据源装载与归一化（CVE / KEV / ATT&CK / CWE / CAPEC / Sigma / EPSS）。

这一层把各源的**原始格式**统一成"可直接映射为本体实例"的字典，供
  * scripts/build_t2_corpus.py   生成真实语料文本
  * scripts/extract_structured.py 方法A 的结构化源直接映射
  * scripts/build_gold.py        金标准（跨源对齐）
复用。

设计原则：
  * 只做格式归一，不做事实推断；每条记录保留 source / license / fetched 元数据。
  * 所有 ID 以 MITRE 官方 ID 为主键（CVE-… / CWE-… / CAPEC-… / T… / TA… / G… / S… / M…），
    人类可读名称只作为 label/properties，避免名称变更导致主键漂移。
"""
from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, Iterable, List, Optional

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "data" / "raw"
TOPIC = "t2-cve-attack"

# 选题的 CVE 切片（与 scripts/fetch_t2_data.py 保持一致）
CVE_IDS = """CVE-2024-3400 CVE-2023-20198 CVE-2023-20273 CVE-2024-20353 CVE-2024-20359
CVE-2022-42475 CVE-2018-13379 CVE-2023-27997 CVE-2023-36845 CVE-2023-36844
CVE-2023-4966 CVE-2023-3519 CVE-2019-19781 CVE-2020-5902 CVE-2021-22986
CVE-2022-1388 CVE-2019-11510 CVE-2021-22893 CVE-2023-46805 CVE-2024-21887
CVE-2024-21893 CVE-2022-47966 CVE-2021-44228 CVE-2021-45046 CVE-2022-22965
CVE-2022-26134 CVE-2021-26084 CVE-2023-34362 CVE-2023-0669 CVE-2020-14882
CVE-2022-21587 CVE-2023-44487 CVE-2021-34527 CVE-2020-1472 CVE-2019-0708
CVE-2017-0144 CVE-2021-26855 CVE-2021-27065 CVE-2022-30190 CVE-2023-23397""".split()

# 与 40 条 CVE 的攻击链相关的 ATT&CK 技术（父技术会自动展开子技术）
SELECTED_TECHNIQUES = [
    "T1190", "T1059", "T1505", "T1133", "T1078", "T1203", "T1210", "T1068",
    "T1548", "T1003", "T1021", "T1105", "T1071", "T1486", "T1490", "T1562",
    "T1110", "T1566", "T1195", "T1047", "T1055", "T1090",
]
# 只保留与这批 CVE 攻击链最相关的子技术，避免语料/图谱被 100+ 子技术淹没
SELECTED_SUBTECHNIQUES = [
    "T1059.001", "T1059.003", "T1059.004", "T1505.003",
    "T1021.001", "T1021.002", "T1548.002", "T1562.001", "T1078.004",
]

CPE_23 = re.compile(r"^cpe:2\.3:([aho]):([^:]+):([^:]+):([^:]+)")


# --------------------------------------------------------------------------- #
# CVE
# --------------------------------------------------------------------------- #
def _cna_blocks(cve: dict) -> List[dict]:
    c = cve.get("containers") or {}
    return [c.get("cna") or {}] + list(c.get("adp") or [])


def _first_lang(items: Iterable[dict], lang: str = "en") -> str:
    for it in items or []:
        if it.get("lang") == lang and it.get("value"):
            return str(it["value"])
    for it in items or []:
        if it.get("value"):
            return str(it["value"])
    return ""


def parse_cpe(cpe: str) -> Optional[dict]:
    m = CPE_23.match(cpe.strip())
    if not m:
        return None
    part, vendor, product, version = m.groups()
    version = "" if version in ("*", "-", "") else version
    vendor = vendor.replace("\\", "")
    product = product.replace("\\", "")
    pretty = f"{vendor} {product}".replace("_", " ").strip()
    if version:
        pretty += f" {version}"
    return {"cpe": cpe.strip(), "part": part, "vendor": vendor, "product": product,
            "version": version, "label": pretty}


def _dedupe_cpes(cpes: List[str], limit: int = 4) -> List[dict]:
    out, seen = [], set()
    for raw in cpes:
        p = parse_cpe(raw)
        if not p:
            continue
        # 以 vendor/product/版本主次号去重，避免同一产品的补丁版本刷屏
        key = (p["vendor"], p["product"], ".".join(p["version"].split(".")[:2]))
        if key in seen:
            continue
        seen.add(key)
        out.append(p)
    # 版本号具体的排前面（"10.2.0" 比 "*" 更有信息量）
    out.sort(key=lambda x: (x["version"] == "", x["cpe"]))
    return out[:limit]


_CWE_RE = re.compile(r"^CWE-\d{1,5}$")


def valid_cwes(items: Iterable[str]) -> List[str]:
    """NVD 里会出现 NVD-CWE-noinfo / NVD-CWE-Other 这类占位值，不是本体里的弱点类。"""
    out: List[str] = []
    for x in items:
        x = (x or "").strip()
        if _CWE_RE.match(x) and x not in out:
            out.append(x)
    return out


def load_cves(raw: Path = RAW) -> List[dict]:
    rows: List[dict] = []
    for cid in CVE_IDS:
        p = raw / "cve" / f"{cid}.json"
        if not p.exists():
            continue
        d = json.loads(p.read_text(encoding="utf-8"))
        meta = d.get("cveMetadata") or {}
        cna = (d.get("containers") or {}).get("cna") or {}
        adp = (d.get("containers") or {}).get("adp") or []
        blocks = [cna] + adp

        cwes: List[str] = []
        cpes: List[str] = []
        for b in blocks:
            for pt in b.get("problemTypes") or []:
                for desc in pt.get("descriptions") or []:
                    cwe = desc.get("cweId")
                    if cwe and cwe not in cwes:
                        cwes.append(cwe)
            for aff in b.get("affected") or []:
                for cpe in aff.get("cpes") or []:
                    if cpe not in cpes:
                        cpes.append(cpe)
            # NVD 风格 configurations
            for cfg in b.get("configurations") or []:
                for node in cfg.get("nodes") or []:
                    for m in node.get("cpeMatch") or []:
                        cpe = m.get("criteria")
                        if cpe and cpe not in cpes:
                            cpes.append(cpe)

        # NVD 2.0 补充（CVE 官方记录常缺 CPE；老 CVE 的 CWE 也可能只在 NVD）
        nvd_path = raw / "nvd" / f"{cid}.json"
        if nvd_path.exists():
            try:
                nvd = json.loads(nvd_path.read_text(encoding="utf-8"))
                nv = (nvd.get("vulnerabilities") or [{}])[0].get("cve") or {}
                for cfg in nv.get("configurations") or []:
                    for node in cfg.get("nodes") or []:
                        for m in node.get("cpeMatch") or []:
                            cpe = m.get("criteria")
                            if cpe and cpe not in cpes:
                                cpes.append(cpe)
                for w in nv.get("weaknesses") or []:
                    for d_ in w.get("description") or []:
                        if d_.get("value") and d_["value"] not in cwes:
                            cwes.append(d_["value"])
            except Exception:  # noqa: BLE001
                pass

        cvss = {}
        for b in blocks:
            for m in b.get("metrics") or []:
                for k in ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"):
                    if k in m:
                        v = m[k]
                        cvss = {"score": v.get("baseScore"), "severity": v.get("baseSeverity", ""),
                                "vector": v.get("vectorString", ""), "version": v.get("version", k)}
                        break
                if cvss:
                    break
            if cvss:
                break

        refs = []
        for b in blocks:
            for r in b.get("references") or []:
                if r.get("url") and r["url"] not in [x["url"] for x in refs]:
                    refs.append({"url": r["url"], "tags": r.get("tags") or []})

        if not cvss and nvd_path.exists():
            try:
                nvd = json.loads(nvd_path.read_text(encoding="utf-8"))
                nv = (nvd.get("vulnerabilities") or [{}])[0].get("cve") or {}
                metrics = nv.get("metrics") or {}
                for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"):
                    vals = metrics.get(key) or []
                    if vals:
                        v = vals[0].get("cvssData") or {}
                        cvss = {"score": v.get("baseScore"),
                                "severity": vals[0].get("baseSeverity", v.get("baseSeverity", "")),
                                "vector": v.get("vectorString", ""), "version": v.get("version", "")}
                        break
            except Exception:  # noqa: BLE001
                pass

        rows.append({
            "id": cid,
            "title": (cna.get("title") or "").strip() or cid,
            "description": _first_lang(cna.get("descriptions")),
            "state": meta.get("state", ""),
            "published": (meta.get("datePublished") or "")[:10],
            "updated": (meta.get("dateUpdated") or "")[:10],
            "cwes": valid_cwes(cwes),
            "cpes": _dedupe_cpes(cpes),
            "cvss": cvss,
            "references": refs[:6],
            "source": f"https://cveawg.mitre.org/api/cve/{cid}",
            "license": "CVE Program Terms of Use",
        })

    # KEV 兜底：没有 CPE 的 CVE 至少保留"厂商 + 产品"这一级产品节点
    kev_vulns = load_kev(raw)["vulnerabilities"]
    for r in rows:
        k = kev_vulns.get(r["id"])
        r["kev"] = k
        if not r["cpes"] and k:
            r["product_fallback"] = {
                "vendor": k.get("vendorProject", ""),
                "product": k.get("product", ""),
                "label": f"{k.get('vendorProject','')} {k.get('product','')}".strip(),
                "source": "CISA KEV vendorProject/product",
            }
    return sorted(rows, key=lambda r: r["id"])


# --------------------------------------------------------------------------- #
# KEV / EPSS
# --------------------------------------------------------------------------- #
def load_kev(raw: Path = RAW) -> dict:
    p = raw / "known_exploited_vulnerabilities.json"
    if not p.exists():
        return {"catalogVersion": "", "vulnerabilities": {}}
    d = json.loads(p.read_text(encoding="utf-8"))
    return {"catalogVersion": d.get("catalogVersion", ""), "dateReleased": d.get("dateReleased", ""),
            "source": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            "license": "U.S. Government Works (public domain)",
            "vulnerabilities": {v["cveID"]: v for v in d.get("vulnerabilities", [])}}


def load_epss(raw: Path = RAW) -> dict:
    p = raw / "epss_scores.json"
    if not p.exists():
        return {}
    d = json.loads(p.read_text(encoding="utf-8"))
    return {r["cve"]: r for r in d.get("data", [])}


# --------------------------------------------------------------------------- #
# MITRE ATT&CK STIX
# --------------------------------------------------------------------------- #
def _ext_id(obj: dict) -> str:
    for r in obj.get("external_references") or []:
        if r.get("external_id") and r.get("source_name") in ("mitre-attack", "mitre-mobile-attack",
                                                             "mitre-ics-attack"):
            return r["external_id"]
    return ""


def load_attack(raw: Path = RAW) -> dict:
    p = raw / "enterprise-attack.json"
    if not p.exists():
        return {"objects": [], "by_ext": {}, "by_stix": {}, "relationships": [],
                "tactic_short": {}, "source": "", "license": ""}
    bundle = json.loads(p.read_text(encoding="utf-8"))
    objs = bundle.get("objects") or []
    by_stix = {o["id"]: o for o in objs if o.get("id")}
    by_ext: Dict[str, dict] = {}
    tactic_short: Dict[str, str] = {}
    for o in objs:
        eid = _ext_id(o)
        if eid:
            by_ext[eid] = o
        if o.get("type") == "x-mitre-tactic":
            short = o.get("x_mitre_shortname")
            if short and eid:
                tactic_short[short] = eid
    rels = [o for o in objs if o.get("type") == "relationship"]
    return {"objects": objs, "by_ext": by_ext, "by_stix": by_stix, "relationships": rels,
            "tactic_short": tactic_short,
            "source": "https://github.com/mitre-attack/attack-stix-data",
            "license": "MITRE ATT&CK Terms of Use",
            "collection": bundle.get("id", "")}


def technique_ids_for(attack: dict) -> List[str]:
    """选定父技术 + 白名单子技术（子技术必须显式列出，避免语料爆炸）。"""
    ids = {t for t in SELECTED_TECHNIQUES if t in attack["by_ext"]}
    ids |= {t for t in SELECTED_SUBTECHNIQUES if t in attack["by_ext"]}
    return sorted(ids)


def technique_tactics(attack: dict, tech: dict) -> List[str]:
    out = []
    for ph in tech.get("kill_chain_phases") or []:
        if ph.get("kill_chain_name") != "mitre-attack":
            continue
        ta = attack["tactic_short"].get(ph.get("phase_name", ""))
        if ta and ta not in out:
            out.append(ta)
    return out


def attack_uses_edges(attack: dict, src_types: Iterable[str], target_ids: Iterable[str]) -> List[dict]:
    """返回 (source_ext, target_ext) 的 uses 边。"""
    want = set(target_ids)
    out = []
    for r in attack["relationships"]:
        if r.get("relationship_type") != "uses":
            continue
        s = attack["by_stix"].get(r.get("source_ref"))
        t = attack["by_stix"].get(r.get("target_ref"))
        if not s or not t or s.get("type") not in src_types:
            continue
        se, te = _ext_id(s), _ext_id(t)
        if se and te in want:
            out.append({"source": se, "target": te, "source_name": s.get("name", ""),
                        "target_name": t.get("name", "")})
    return out


def attack_mitigates_edges(attack: dict, target_ids: Iterable[str]) -> List[dict]:
    want = set(target_ids)
    out = []
    for r in attack["relationships"]:
        if r.get("relationship_type") != "mitigates":
            continue
        s = attack["by_stix"].get(r.get("source_ref"))
        t = attack["by_stix"].get(r.get("target_ref"))
        if not s or not t:
            continue
        se, te = _ext_id(s), _ext_id(t)
        if se and te in want and s.get("type") == "course-of-action":
            out.append({"source": se, "target": te, "source_name": s.get("name", ""),
                        "target_name": t.get("name", ""),
                        "description": (s.get("description") or "").strip()})
    return out


# --------------------------------------------------------------------------- #
# CWE / CAPEC
# --------------------------------------------------------------------------- #
def _strip_ns(elem: ET.Element) -> ET.Element:
    elem.tag = elem.tag.split("}")[-1]
    for child in elem:
        _strip_ns(child)
    return elem


def _xml_text(elem: Optional[ET.Element]) -> str:
    if elem is None:
        return ""
    return re.sub(r"\s+", " ", "".join(elem.itertext())).strip()


def load_cwe(raw: Path = RAW) -> dict:
    cands = sorted((raw / "cwe").glob("cwec_*.xml"))
    if not cands:
        return {"by_id": {}, "version": "", "source": "", "license": ""}
    root = _strip_ns(ET.parse(cands[0]).getroot())
    by_id = {}
    for w in root.find("Weaknesses").findall("Weakness"):
        cid = f"CWE-{w.get('ID')}"
        rel_ap = [f"CAPEC-{x.get('CAPEC_ID')}" for x in
                  (w.find("Related_Attack_Patterns").findall("Related_Attack_Pattern")
                   if w.find("Related_Attack_Patterns") is not None else [])]
        parents = []
        rw = w.find("Related_Weaknesses")
        if rw is not None:
            for x in rw.findall("Related_Weakness"):
                if x.get("Nature") == "ChildOf" and x.get("Ordinal") == "Primary":
                    parents.append(f"CWE-{x.get('CWE_ID')}")
        by_id[cid] = {
            "id": cid, "name": w.get("Name", ""), "description": _xml_text(w.find("Description")),
            "related_attack_patterns": rel_ap, "parents": parents,
            "abstraction": w.get("Abstraction", ""),
        }
    return {"by_id": by_id, "version": root.get("Version", ""), "date": root.get("Date", ""),
            "source": "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip",
            "license": "MITRE CWE Terms of Use"}


def load_capec(raw: Path = RAW) -> dict:
    p = raw / "capec_latest.xml"
    if not p.exists():
        return {"by_id": {}, "version": "", "source": "", "license": ""}
    root = _strip_ns(ET.parse(p).getroot())
    by_id = {}
    for a in root.find("Attack_Patterns").findall("Attack_Pattern"):
        cid = f"CAPEC-{a.get('ID')}"
        rw = a.find("Related_Weaknesses")
        weaks = [f"CWE-{x.get('CWE_ID')}" for x in (rw.findall("Related_Weakness") if rw is not None else [])]
        by_id[cid] = {
            "id": cid, "name": a.get("Name", ""),
            "description": _xml_text(a.find("Description")),
            "related_weaknesses": weaks,
            "severity": _xml_text(a.find("Typical_Severity")),
            "likelihood": _xml_text(a.find("Likelihood_Of_Attack")),
            "abstraction": a.get("Abstraction", ""),
        }
    return {"by_id": by_id, "version": root.get("Version", ""), "date": root.get("Date", ""),
            "source": "https://capec.mitre.org/data/xml/capec_latest.xml",
            "license": "MITRE CAPEC Terms of Use"}


# --------------------------------------------------------------------------- #
# Sigma
# --------------------------------------------------------------------------- #
def load_sigma(raw: Path = RAW, technique_ids: Optional[Iterable[str]] = None,
               per_technique: int = 2) -> List[dict]:
    """只取规则的元数据（id/title/tags/description/level/logsource），不复制检测逻辑。

    这样既能构建 `detects` 关系，又符合 SigmaHQ 的 DRL 1.1（不再分发规则正文）。
    """
    import yaml

    root = raw / "sigma" / "sigma-master" / "rules"
    if not root.is_dir():
        return []
    want = set(technique_ids or [])
    picked: Dict[str, List[dict]] = {}
    for p in sorted(root.rglob("*.yml")):
        try:
            d = yaml.safe_load(p.read_text(encoding="utf-8", errors="replace"))
        except Exception:  # noqa: BLE001
            continue
        if not isinstance(d, dict) or not d.get("id") or not d.get("title"):
            continue
        tags = [str(t) for t in (d.get("tags") or [])]
        techs = []
        for t in tags:
            m = re.fullmatch(r"attack\.(t\d{4}(?:\.\d{3})?)", t.lower())
            if m:
                tid = "T" + m.group(1)[1:].upper()
                if tid in want:
                    techs.append(tid)
        if not techs:
            continue
        for tid in techs:
            bucket = picked.setdefault(tid, [])
            if len(bucket) >= per_technique:
                continue
            if any(x["id"] == d["id"] for x in bucket):
                continue
            # 优先 stable + high/critical
            score = (1 if d.get("status") == "stable" else 0) + \
                    (2 if str(d.get("level", "")).lower() in ("high", "critical") else 0)
            bucket.append({
                "id": d["id"], "title": d["title"], "techniques": techs,
                "level": d.get("level", ""), "status": d.get("status", ""),
                "description": re.sub(r"\s+", " ", str(d.get("description") or ""))[:400],
                "logsource": d.get("logsource") or {},
                "path": str(p.relative_to(raw)),
                "_score": score,
            })
    out = []
    for tid, rows in picked.items():
        rows.sort(key=lambda x: -x["_score"])
        for r in rows:
            r = dict(r)
            r.pop("_score", None)
            out.append(r)
    out.sort(key=lambda x: (x["techniques"][0], x["id"]))
    return out


# --------------------------------------------------------------------------- #
# 便捷：选定的 CWE / CAPEC 集合
# --------------------------------------------------------------------------- #
def selected_cwes(cves: List[dict], kev: dict) -> List[str]:
    ids: List[str] = []
    for c in cves:
        for x in valid_cwes(c["cwes"]):
            if x not in ids:
                ids.append(x)
        k = kev["vulnerabilities"].get(c["id"])
        for x in valid_cwes((k or {}).get("cwes") or []):
            if x not in ids:
                ids.append(x)
    return sorted(ids, key=lambda s: int(s.split("-")[1]))


def selected_capecs(cwes: List[str], cwe: dict, capec: dict, limit: int = 24) -> List[str]:
    """从 CWE→CAPEC 关系里挑出与这批 CVE 最相关的攻击模式（按出现频次排序）。"""
    freq: Dict[str, int] = {}
    for cid in cwes:
        for ap in (cwe["by_id"].get(cid) or {}).get("related_attack_patterns", []):
            freq[ap] = freq.get(ap, 0) + 1
    ranked = sorted(freq, key=lambda x: (-freq[x], int(x.split("-")[1])))
    return [x for x in ranked if x in capec["by_id"]][:limit]
