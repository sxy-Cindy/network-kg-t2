#!/usr/bin/env python3
"""生成方法 A 的词典（gazetteer）：把**人类可读名称**归一到**官方编号**。

为什么需要词典：
  * 官方编号是主键，但正文里经常只写名称（“Initial Access”“Exploit Public-Facing
    Application”）。纯正则只能抓编号，会漏掉名称级提及。
  * 词典项 `{surface, id, label}` 让规则方法在命中名称时直接产出官方 ID，
    这样它与模型/LLM 的产物能在融合阶段按 (type, id) 对齐，而不是各写各的。

词典只从**本次数据切片**生成，不引入外部人工术语表，避免“答案泄漏”：
  ATT&CK 技术/战术/缓解名称、CWE/CAPEC 名称、CPE 厂商名 —— 都是数据的自然语言面。

用法：
    python scripts/lexicon_build.py
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from kgc import t2_sources as T  # noqa: E402

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:  # noqa: BLE001
    pass

TOPIC = "t2-cve-attack"
OUT = ROOT / "topics" / TOPIC / "lexicons.yaml"


def q(s: str) -> str:
    return '"' + str(s).replace("\\", "\\\\").replace('"', '\\"') + '"'


def entry(surface: str, eid: str, label: str) -> str:
    return f"- {{surface: {q(surface)}, id: {q(eid)}, label: {q(label)}}}"


def main() -> int:
    cves = T.load_cves()
    kev = T.load_kev()
    attack = T.load_attack()
    cwe = T.load_cwe()
    capec = T.load_capec()

    tids = T.technique_ids_for(attack)
    cwes = T.selected_cwes(cves, kev)
    capecs = T.selected_capecs(cwes, cwe, capec)

    blocks: dict[str, list[str]] = {}
    seen: dict[str, set] = {}

    def add(etype: str, surface: str, eid: str, label: str):
        surface = (surface or "").strip()
        if len(surface) < 6 or surface.lower() in {"unknown", "other"}:
            return
        bucket = seen.setdefault(etype, set())
        key = surface.lower()
        if key in bucket:
            return
        bucket.add(key)
        blocks.setdefault(etype, []).append(entry(surface, eid, label))

    for tid in tids:
        o = attack["by_ext"].get(tid) or {}
        add("Technique", o.get("name", ""), f"attck:{tid}", tid)

    used_tactics = sorted({ta for tid in tids
                           for ta in T.technique_tactics(attack, attack["by_ext"][tid])})
    for ta in used_tactics:
        o = attack["by_ext"].get(ta) or {}
        add("Tactic", o.get("name", ""), f"tactic:{ta}", ta)

    for e in T.attack_mitigates_edges(attack, tids):
        o = attack["by_ext"].get(e["source"]) or {}
        add("Mitigation", o.get("name", ""), f"attck:{e['source']}", e["source"])

    for cid in cwes:
        w = cwe["by_id"].get(cid)
        if w:
            add("Weakness", w["name"], f"cwe:{cid}", cid)

    for cid in capecs:
        a = capec["by_id"].get(cid)
        if a:
            add("AttackPattern", a["name"], f"capec:{cid}", cid)

    # 厂商：CPE vendor 串（正文里就是小写 slug）+ KEV vendorProject（正文原样）
    vendors: dict[str, str] = {}
    for c in cves:
        for x in c["cpes"]:
            p = T.parse_cpe(x["cpe"])
            if p and p["vendor"] not in ("*", "-", ""):
                vendors.setdefault(p["vendor"], p["vendor"])
    for c in cves:
        k = c.get("kev")
        if k and k.get("vendorProject"):
            slug = k["vendorProject"].lower().replace(" ", "")
            vendors.setdefault(k["vendorProject"], slug)
    for surface, slug in vendors.items():
        add("Vendor", surface, f"vendor:{slug}", surface)

    lines = [
        "# 由 scripts/lexicon_build.py 自动生成，请勿手改（改数据后重跑即可）。",
        "# 每个条目 = {surface, id, label}：surface 是正文中的名称，id 是官方主键。",
        "# 词典只覆盖本次切片，不引入外部术语表。",
        "",
    ]
    for etype in ("Technique", "Tactic", "Mitigation", "Weakness", "AttackPattern", "Vendor"):
        items = blocks.get(etype) or []
        if not items:
            continue
        lines.append(f"{etype}:  # {len(items)} 条")
        lines.extend(items)
        lines.append("")

    OUT.write_text("\n".join(lines), encoding="utf-8")
    counts = {k: len(v) for k, v in blocks.items()}
    print(f"[lexicon] -> {OUT}")
    print(f"[lexicon] {counts}  总计 {sum(counts.values())} 条")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
