#!/usr/bin/env python3
"""把 data/raw/ 下的公开原始数据切片，渲染成方法 A/B/C 共用的语料文档。

设计约束（写进报告的“语料构建”一节）：
  * 同一份语料、同一套本体、同一评测协议 —— 三种方法只共享文本，不共享标注。
  * 每条文档头部保留 source / fetched / license / slice 四行，便于三级溯源与合规审计。
  * 只做“渲染”不做“标注”：实体与关系必须由三种方法自己从文本里抽，脚本不写答案。
  * 实体识别模式只在 topics/<topic>/patterns.yaml 里定义一次，本脚本不重复维护正则。
  * ATT&CK 描述截断到前 N 字符，截断落在句号处，避免单条文档过大导致 LLM 分块过碎。
  * Sigma 只渲染元数据（id/title/tags/level/description），不复制规则正文（DRL 1.1）。

用法：
    python scripts/corpus_build.py            # 重新生成全部语料
    python scripts/corpus_build.py --dry-run  # 只打印统计，不写文件
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from kgc import t2_sources as T  # noqa: E402

try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except Exception:  # noqa: BLE001
    pass

TOPIC = "t2-cve-attack"
OUT = ROOT / "data" / "corpus" / TOPIC
FETCHED = dt.date.today().isoformat()


def header(source: str, license_: str, slice_: str) -> str:
    return (f"# source: {source}\n"
            f"# fetched: {FETCHED}\n"
            f"# license: {license_}\n"
            f"# slice: {slice_}\n\n")


_MD_LINK = re.compile(r"\[([^\]]+)\]\((?:https?:)?//[^)]+\)")


def clean_prose(text: str) -> str:
    """去掉 ATT&CK 描述里的站内 Markdown 链接，只保留锚文本。

    本图是**闭包切片**：语料里的每个编号都应在图谱中有节点与来源文档。ATT&CK 描述大量
    用 `[T1059](https://attack.mitre.org/techniques/T1059)` 指向切片外的条目，保留链接会
    让规则抽取把“参见”误当成实体提及，且无法溯源到本文档。
    """
    return _MD_LINK.sub(r"\1", text or "")


def clip(text: str, limit: int) -> str:
    """按句号截断到 limit 字符以内（找不到句号就硬截断）。"""
    text = re.sub(r"\s+", " ", text or "").strip()
    if len(text) <= limit:
        return text
    cut = text[:limit]
    pos = max(cut.rfind(". "), cut.rfind("。"))
    return (cut[: pos + 1] if pos > limit * 0.5 else cut).strip()


def cpe_short(spec: str) -> str:
    p = T.parse_cpe(spec)
    if not p:
        return spec
    ver = p["version"] if p["version"] not in ("*", "-", "") else "all versions"
    return f"{p['vendor']} {p['product']} ({ver})"


# --------------------------------------------------------------------------- #
# 1) 漏洞记录（4 批 × 10 条）
# --------------------------------------------------------------------------- #
def render_records(cves, epss) -> dict:
    out = {}
    for i in range(0, len(cves), 10):
        batch = cves[i:i + 10]
        n = i // 10 + 1
        parts = [header("CVE Services API 2.1 + NVD API 2.0 + CISA KEV + FIRST EPSS",
                        "CVE Program Terms of Use / NVD public domain / KEV public domain / EPSS CC BY 4.0",
                        f"漏洞记录 第 {n}/{(len(cves) + 9) // 10} 批（{len(batch)} 条）")]
        for c in batch:
            lines = [f"{c['id']} {c['title']}" if c["title"] != c["id"] else c["id"]]
            desc = clip(clean_prose(c["description"]), 420)
            if desc:
                lines.append(desc)
            lines.append(f"{c['id']} was published on {c['published'] or 'unknown date'}.")
            if c["cwes"]:
                lines.append(f"The root cause of {c['id']} is " + ", ".join(c["cwes"]) +
                             " according to the CVE record and NVD weakness mapping.")
            if c["cpes"]:
                lines.append(f"{c['id']} affects " +
                             ", ".join(cpe_short(x["cpe"]) for x in c["cpes"]) + ".")
                # 同时给出一条完整标识串，供规则/词典方法识别。
                # 行尾不留句号：CPE 的最后一段是通配符，句号会被正则一起吃进去。
                lines.append(f"The product identifiers of {c['id']} are " +
                             ", ".join(x["cpe"] for x in c["cpes"]))
            elif c.get("product_fallback"):
                fb = c["product_fallback"]
                lines.append(f"{c['id']} affects {fb['vendor']} {fb['product']} "
                             f"according to the CISA KEV vendor and product fields.")
            cv = c.get("cvss") or {}
            if cv.get("score") is not None:
                lines.append(f"CVSS {cv.get('version') or 'base'} base score is {cv['score']} "
                             f"({cv.get('severity') or 'n/a'}), vector {cv.get('vector') or 'n/a'}.")
            k = c.get("kev")
            if k:
                lines.append(f"The KEV entry for {c['id']} was added on {k.get('dateAdded')} "
                             f"with remediation due {k.get('dueDate')}; known ransomware campaign use: "
                             f"{k.get('knownRansomwareCampaignUse')}.")
                if k.get("requiredAction"):
                    lines.append(f"CISA requires: {clip(k['requiredAction'], 160)}")
            e = epss.get(c["id"])
            if e:
                lines.append(f"FIRST EPSS score for {c['id']} is {float(e.get('epss', 0)):.5f} "
                             f"at percentile {float(e.get('percentile', 0)):.5f}.")
            out.setdefault(f"cve_records_{n:02d}", []).append("\n".join(lines))
    return {k: "\n\n".join(v) + "\n" for k, v in out.items()}


# --------------------------------------------------------------------------- #
# 2) KEV 切片
# --------------------------------------------------------------------------- #
def render_kev(kev, ids) -> str:
    parts = [header("CISA Known Exploited Vulnerabilities Catalog",
                    "U.S. Government Works (public domain)",
                    f"catalogVersion {kev.get('catalogVersion')} / {len(ids)} 条（本项目切片）")]
    for cid in ids:
        k = kev["vulnerabilities"].get(cid)
        if not k:
            continue
        parts.append("\n".join([
            f"{cid} {k.get('vulnerabilityName', '')}",
            clip(clean_prose(k.get("shortDescription", "")), 300),
            f"Vendor project: {k.get('vendorProject')}; product: {k.get('product')}.",
            f"The KEV entry for {cid} was added on {k.get('dateAdded')} with remediation due {k.get('dueDate')}.",
            f"Known ransomware campaign use: {k.get('knownRansomwareCampaignUse')}.",
            f"Required action: {clip(k.get('requiredAction', ''), 160)}",
        ]))
    return "\n\n".join(parts) + "\n"


# --------------------------------------------------------------------------- #
# 3) ATT&CK：技术 / 战术 / 组织 / 软件 / 缓解
# --------------------------------------------------------------------------- #
def _name(attack, tid):
    o = attack["by_ext"].get(tid) or {}
    return o.get("name", "")


def render_techniques(attack, tids) -> str:
    parts = [header("MITRE ATT&CK Enterprise STIX 2.1",
                    "MITRE ATT&CK Terms of Use (attribution required)",
                    f"{len(tids)} 个技术（父技术 + 显式子技术，非全量 600+）")]
    for tid in tids:
        o = attack["by_ext"][tid]
        lines = [f"{tid} {o.get('name', '')}"]
        desc = clip(clean_prose(o.get("description", "")), 700)
        if desc:
            lines.append(desc)
        tactics = T.technique_tactics(attack, o)
        if tactics:
            lines.append(f"{tid} belongs to tactic " +
                         ", ".join(f"{ta} {_name(attack, ta)}" for ta in tactics) + ".")
        parent = next((r for r in attack["relationships"]
                       if r.get("relationship_type") == "subtechnique-of"
                       and r.get("source_ref") == o.get("id")), None)
        if parent:
            p = attack["by_stix"].get(parent.get("target_ref")) or {}
            pe = T._ext_id(p)
            if pe:
                lines.append(f"{tid} is a subtechnique of {pe} {p.get('name', '')}.")
        parts.append("\n".join(lines))
    return "\n\n".join(parts) + "\n"


def render_tactics(attack, tids) -> str:
    used = sorted({ta for tid in tids for ta in T.technique_tactics(attack, attack["by_ext"][tid])})
    parts = [header("MITRE ATT&CK Enterprise STIX 2.1",
                    "MITRE ATT&CK Terms of Use (attribution required)",
                    f"{len(used)} 个战术（仅覆盖本次所选技术）")]
    for ta in used:
        o = attack["by_ext"][ta]
        lines = [f"{ta} {o.get('name', '')}"]
        d = clip(clean_prose(o.get("description", "")), 300)
        if d:
            lines.append(d)
        lines.append(f"Short name: {o.get('x_mitre_shortname', '')}.")
        parts.append("\n".join(lines))
    return "\n\n".join(parts) + "\n"


def _software_edges(attack, tids, src_types, limit):
    edges = T.attack_uses_edges(attack, src_types, tids)
    by_src = {}
    for e in edges:
        by_src.setdefault(e["source"], []).append(e)
    ranked = sorted(by_src.items(), key=lambda kv: (-len(kv[1]), kv[0]))[:limit]
    return ranked


def render_groups(attack, tids, limit=14) -> str:
    ranked = _software_edges(attack, tids, ("intrusion-set",), limit)
    parts = [header("MITRE ATT&CK Enterprise STIX 2.1",
                    "MITRE ATT&CK Terms of Use (attribution required)",
                    f"{len(ranked)} 个攻击组织（按命中技术数排序）")]
    for gid, edges in ranked:
        o = attack["by_ext"].get(gid) or {}
        targets = "; ".join(f"{e['target']} {e['target_name']}" for e in edges[:8])
        lines = [f"{gid} {o.get('name', '')}"]
        d = clip(clean_prose(o.get("description", "")), 380)
        if d:
            lines.append(d)
        lines.append(f"{gid} {o.get('name', '')} uses {targets}.")
        aliases = o.get("aliases") or []
        if aliases:
            lines.append("Also known as: " + ", ".join(aliases[:5]) + ".")
        parts.append("\n".join(lines))
    return "\n\n".join(parts) + "\n"


def render_software(attack, tids, limit=14) -> str:
    ranked = _software_edges(attack, tids, ("malware", "tool"), limit)
    parts = [header("MITRE ATT&CK Enterprise STIX 2.1",
                    "MITRE ATT&CK Terms of Use (attribution required)",
                    f"{len(ranked)} 个恶意软件/工具（按命中技术数排序）")]
    for sid, edges in ranked:
        o = attack["by_ext"].get(sid) or {}
        kind = o.get("type")
        targets = "; ".join(f"{e['target']} {e['target_name']}" for e in edges[:6])
        lines = [f"{sid} {o.get('name', '')} ({kind})"]
        d = clip(clean_prose(o.get("description", "")), 320)
        if d:
            lines.append(d)
        lines.append(f"{sid} {o.get('name', '')} uses {targets}.")
        parts.append("\n".join(lines))
    return "\n\n".join(parts) + "\n"


def render_mitigations(attack, tids, limit=20) -> str:
    edges = T.attack_mitigates_edges(attack, tids)
    by_m = {}
    for e in edges:
        by_m.setdefault(e["source"], []).append(e)
    ranked = sorted(by_m.items(), key=lambda kv: (-len(kv[1]), kv[0]))[:limit]
    parts = [header("MITRE ATT&CK Enterprise STIX 2.1",
                    "MITRE ATT&CK Terms of Use (attribution required)",
                    f"{len(ranked)} 条缓解措施（覆盖所选技术）")]
    for mid, es in ranked:
        o = attack["by_ext"].get(mid) or {}
        lines = [f"{mid} {o.get('name', '')}"]
        d = clip(clean_prose(es[0].get("description") or o.get("description", "")), 380)
        if d:
            lines.append(d)
        lines.append(f"{mid} {o.get('name', '')} mitigates " +
                     "; ".join(f"{e['target']} {e['target_name']}" for e in es[:6]) + ".")
        parts.append("\n".join(lines))
    return "\n\n".join(parts) + "\n"


# --------------------------------------------------------------------------- #
# 4) CWE / CAPEC（交叉引用只保留切片内目标，保证闭包）
# --------------------------------------------------------------------------- #
def render_cwe(cwe, ids, capec_ids) -> str:
    parts = [header("MITRE CWE XML",
                    "MITRE CWE Terms of Use (attribution required)",
                    f"CWE {cwe.get('version')} / {len(ids)} 个弱点（由所选记录与 KEV 反查）")]
    for cid in ids:
        w = cwe["by_id"].get(cid)
        if not w:
            continue
        lines = [f"{cid} {w['name']}"]
        d = clip(w["description"], 420)
        if d:
            lines.append(d)
        aps = [x for x in w["related_attack_patterns"] if x in capec_ids]
        if aps:
            lines.append(f"{cid} relates to attack pattern " + ", ".join(aps[:6]) + ".")
        parents = [x for x in w["parents"] if x in ids]
        if parents:
            lines.append(f"Parent weakness: {parents[0]}.")
        parts.append("\n".join(lines))
    return "\n\n".join(parts) + "\n"


def render_capec(capec, ids, cwe_ids) -> str:
    parts = [header("MITRE CAPEC XML",
                    "MITRE CAPEC Terms of Use (attribution required)",
                    f"CAPEC {capec.get('version')} / {len(ids)} 个攻击模式（由 CWE 反查）")]
    for cid in ids:
        a = capec["by_id"].get(cid)
        if not a:
            continue
        lines = [f"{cid} {a['name']}"]
        d = clip(a["description"], 420)
        if d:
            lines.append(d)
        lines.append(f"Typical severity: {a['severity'] or 'n/a'}; likelihood of attack: "
                     f"{a['likelihood'] or 'n/a'}; abstraction: {a['abstraction'] or 'n/a'}.")
        weaks = [x for x in a["related_weaknesses"] if x in cwe_ids]
        if weaks:
            lines.append(f"{cid} exploits weakness " + ", ".join(weaks[:6]) + ".")
        parts.append("\n".join(lines))
    return "\n\n".join(parts) + "\n"


# --------------------------------------------------------------------------- #
# 4b) CAPEC → ATT&CK 分析师映射表
# --------------------------------------------------------------------------- #
def render_crosswalk(capec, attack) -> str:
    import csv

    path = ROOT / "topics" / TOPIC / "capec_attck_crosswalk.csv"
    if not path.exists():
        return ""
    parts = [header("analyst crosswalk (topics/t2-cve-attack/capec_attck_crosswalk.csv)",
                    "本项目作者编写，CC BY 4.0；MITRE 未发布官方 CAPEC→ATT&CK 映射",
                    "24 条人工映射，confidence 字段标注把握程度")]
    with path.open(encoding="utf-8", newline="") as fh:
        for row in csv.DictReader(fh):
            cid, tid = row["capec_id"], row["technique_id"]
            cname = (capec["by_id"].get(cid) or {}).get("name", "")
            tname = (attack["by_ext"].get(tid) or {}).get("name", "")
            parts.append(f"{cid} {cname} is implemented by {tid} {tname}. "
                         f"Crosswalk confidence: {row['confidence']}. {row['rationale']}")
    return "\n\n".join(parts) + "\n"


# --------------------------------------------------------------------------- #
# 5) Sigma（元数据）
# --------------------------------------------------------------------------- #
_TECH_NAMES: dict = {}


def _short_tech(tid: str) -> str:
    return _TECH_NAMES.get(tid, "")


def render_sigma(rules) -> str:
    parts = [header("SigmaHQ/sigma",
                    "Detection Rule License 1.1 (metadata only; rule bodies not redistributed)",
                    f"{len(rules)} 条检测规则元数据")]
    for r in rules:
        lines = [f"Sigma rule {r['id']} {r['title']}"]
        if r.get("description"):
            lines.append(clip(clean_prose(r["description"]), 240))
        lines.append(f"Sigma rule {r['id']} detects " +
                     ", ".join(f"{t} {_short_tech(t)}" for t in r["techniques"]) +
                     f" (level: {r['level'] or 'n/a'}, status: {r['status'] or 'n/a'}).")
        ls = r.get("logsource") or {}
        if ls:
            lines.append("Log source: " + ", ".join(f"{k}={v}" for k, v in ls.items() if v) + ".")
        parts.append("\n".join(lines))
    return "\n\n".join(parts) + "\n"


# --------------------------------------------------------------------------- #
# 6) EPSS
# --------------------------------------------------------------------------- #
def render_epss(epss, ids) -> str:
    parts = [header("FIRST EPSS API v1",
                    "FIRST EPSS data (CC BY 4.0)",
                    f"{len([i for i in ids if i in epss])} 条评分")]
    parts.append("The EPSS model estimates the probability that a published vulnerability "
                 "is exploited in the wild within the next 30 days.")
    for cid in ids:
        e = epss.get(cid)
        if not e:
            continue
        parts.append(f"{cid} has EPSS score {float(e.get('epss', 0)):.5f} at percentile "
                     f"{float(e.get('percentile', 0)):.5f} "
                     f"(model {e.get('model', 'n/a')}, date {e.get('date', 'n/a')}).")
    return "\n\n".join(parts) + "\n"


# --------------------------------------------------------------------------- #
def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()

    cves = T.load_cves()
    kev = T.load_kev()
    epss = T.load_epss()
    attack = T.load_attack()
    cwe = T.load_cwe()
    capec = T.load_capec()

    tids = T.technique_ids_for(attack)
    _TECH_NAMES.update({t: (attack["by_ext"].get(t) or {}).get("name", "") for t in tids})
    cwes = T.selected_cwes(cves, kev)
    capecs = T.selected_capecs(cwes, cwe, capec)
    sigma = T.load_sigma(technique_ids=tids, per_technique=2)

    docs = {}
    docs.update(render_records(cves, epss))
    docs["kev_slice"] = render_kev(kev, [c["id"] for c in cves])
    docs["attack_techniques"] = render_techniques(attack, tids)
    docs["attack_tactics"] = render_tactics(attack, tids)
    docs["attack_groups"] = render_groups(attack, tids)
    docs["attack_software"] = render_software(attack, tids)
    docs["attack_mitigations"] = render_mitigations(attack, tids)
    docs["cwe_weaknesses"] = render_cwe(cwe, cwes, set(capecs))
    docs["capec_patterns"] = render_capec(capec, capecs, set(cwes))
    docs["capec_crosswalk"] = render_crosswalk(capec, attack)
    docs["sigma_rules"] = render_sigma(sigma)
    docs["epss_scores"] = render_epss(epss, [c["id"] for c in cves])

    docs = {k: v for k, v in docs.items() if v}
    total = sum(len(v) for v in docs.values())
    print(f"[corpus] 文档 {len(docs)} 篇 / {total/1024:.1f} KB")
    for name, text in sorted(docs.items()):
        print(f"  {name:22s} {len(text)/1024:6.1f} KB")
    print(f"[corpus] 记录 {len(cves)} · 有产品标识 {sum(1 for c in cves if c['cpes'])} · "
          f"KEV {sum(1 for c in cves if c['kev'])} · CWE {len(cwes)} · CAPEC {len(capecs)} · "
          f"技术 {len(tids)} · Sigma {len(sigma)}")
    if a.dry_run:
        return 0

    OUT.mkdir(parents=True, exist_ok=True)
    for old in OUT.glob("*.txt"):
        old.unlink()
    for name, text in docs.items():
        (OUT / f"{name}.txt").write_text(text, encoding="utf-8")

    stats = {
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "documents": {k: {"chars": len(v), "bytes": len(v.encode("utf-8"))} for k, v in docs.items()},
        "total_chars": total,
        "counts": {"records": len(cves), "records_with_product": sum(1 for c in cves if c["cpes"]),
                   "records_in_kev": sum(1 for c in cves if c["kev"]),
                   "product_nodes": sum(len(c["cpes"]) for c in cves),
                   "cwe": len(cwes), "capec": len(capecs), "techniques": len(tids),
                   "sigma": len(sigma)},
    }
    (ROOT / "data" / "reports").mkdir(parents=True, exist_ok=True)
    (ROOT / "data" / "reports" / f"{TOPIC}_corpus_stats.json").write_text(
        json.dumps(stats, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"[corpus] -> {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
