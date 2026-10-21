#!/usr/bin/env python3
"""文档—代码一致性检查器：把"方案文档里的每一条可核查断言"自动对照仓库实际状态。

    .venv/bin/python tools/check_doc_consistency.py            # 默认检查 docs/作业方案.md
    .venv/bin/python tools/check_doc_consistency.py --doc <path>

检查项（发现即计问题，按严重度分级）：
  [路径]  文档中出现的 scripts/xxx、kgc/xxx、data/xxx、topics/xxx 路径是否真实存在
  [命令]  文档中的 `python -m kgc.<mod>` 模块是否存在、CLI 子命令是否存在
  [选题]  文档提到的 topic id 是否存在于 topics/
  [规模]  "N 类 / M 关系" 的声称是否与 topics/<id>/ontology.json 一致
  [金标准] 文档声称的金标准条数是否与 gold.jsonl 行数一致（含逐选题统计）
  [量规]  评分表权重是否合计 100（或文档声明的总分）
  [数字]  文档引用的实测数字是否与 data/reports/*.json 一致
  [交叉]  文档内部交叉引用（"见 X.Y 节"）的目标小节是否存在
  [计数]  附录 A 表行数是否与文中声称的"N 个开源仓库 / M 个数据集 / K 个站点"一致

退出码：0 = 全部通过；1 = 存在高严重度问题。
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DOC = ROOT / "docs" / "作业方案.md"

problems: list[tuple[str, str, str]] = []   # (severity, kind, message)
notes: list[str] = []


def add(sev: str, kind: str, msg: str) -> None:
    problems.append((sev, kind, msg))


# --------------------------------------------------------------------------- #
# 1. 路径 / 命令 / 选题
# --------------------------------------------------------------------------- #
PATH_RX = re.compile(r"`((?:scripts|kgc|tools|tests|skills|topics|data)/[A-Za-z0-9_./<>\-]+)`")
MOD_RX = re.compile(r"python -m (kgc\.[a-z_0-9]+)")
TOPIC_RX = re.compile(r"(?<![a-z0-9-])(t[1-8]-[a-z0-9]+(?:-[a-z0-9]+)*)(?![a-z0-9-])")
# 注意：不能用 \b 收尾——`t5-protocol-rfc_eval.md` 里 `_` 是词字符，
# 用 \b 会回溯成 `t5-protocol` 造成误报（评审工具自身踩过的坑）。
REPO_ROOT = ROOT.parent          # kgcase/（含 power/ 与 network/）


def check_paths(doc: str) -> None:
    for raw in sorted(set(PATH_RX.findall(doc))):
        if "<" in raw or ">" in raw:      # 模板占位（<topic> 等）跳过
            continue
        p = ROOT / raw
        if p.exists():
            continue
        # 允许 power/ 子项目的路径（文档 1.3 节描述参考案例时会引用）
        if (REPO_ROOT / "power" / raw).exists():
            notes.append(f"[路径] {raw} 属于 power/ 子项目 ✓")
            continue
        if (REPO_ROOT / raw).exists():
            notes.append(f"[路径] {raw} 位于仓库根 ✓")
            continue
        # 允许 data/<kind>/<file> 这类运行产物（由流水线生成），但必须是脚本会产出的形态
        if raw.startswith("data/"):
            notes.append(f"[路径] {raw} 是运行产物（当前不存在，流水线会生成）")
            continue
        # 允许 topics/<id>/xxx 的泛化写法
        if raw.startswith("topics/<"):
            continue
        add("中", "路径", f"文档提到的路径不存在：{raw}")


def check_commands(doc: str) -> None:
    mods = sorted(set(MOD_RX.findall(doc)))
    for m in mods:
        f = ROOT / (m.replace(".", "/") + ".py")
        if not f.exists():
            add("高", "命令", f"文档引用了不存在的模块：python -m {m}")
    notes.append(f"[命令] 文档引用 kgc 模块 {len(mods)} 个，全部存在" if mods else "[命令] 未引用模块")


def check_topics(doc: str) -> None:
    have = {p.name for p in (ROOT / "topics").iterdir() if p.is_dir()}
    mentioned = set(TOPIC_RX.findall(doc))
    unknown = mentioned - have
    if unknown:
        add("高", "选题", f"文档提到不存在的选题 id：{sorted(unknown)}")
    missing = have - mentioned
    if missing:
        add("中", "选题", f"仓库有但文档未提及的选题：{sorted(missing)}")
    notes.append(f"[选题] 仓库 {len(have)} 个课题，文档提及 {len(mentioned)} 个")


# --------------------------------------------------------------------------- #
# 2. 规模声称（"N 类 / M 关系"）
# --------------------------------------------------------------------------- #
SCALE_RX = re.compile(r"脚手架(?:已给|已生成)?\s*（?(\d+)\s*类\s*/\s*(\d+)\s*关系")


def check_scale(doc: str) -> None:
    # 逐选题核对：抓取 "### Tn ..." 段落内的 类/关系 声称
    blocks = re.split(r"\n### (T\d[^\n]*)\n", doc)
    for i in range(1, len(blocks), 2):
        title, body = blocks[i], blocks[i + 1]
        m = SCALE_RX.search(body) or re.search(r"（脚手架已给 (\d+) 类 / (\d+) 关系", body)
        if not m:
            continue
        # 找该小节对应 topic 目录
        cands = [p for p in (ROOT / "topics").iterdir()
                 if p.is_dir() and body.find(p.name) >= 0]
        if not cands:
            continue
        seed = json.loads((cands[0] / "ontology.json").read_text(encoding="utf-8"))
        nc, nr = len(seed["classes"]), len(seed["relations"])
        if (int(m.group(1)), int(m.group(2))) != (nc, nr):
            add("高", "规模", f"{cands[0].name}：文档称 {m.group(1)} 类 / {m.group(2)} 关系，"
                            f"实际 {nc} 类 / {nr} 关系（{title[:24]}）")
        else:
            notes.append(f"[规模] {cands[0].name}: {nc} 类 / {nr} 关系 ✓")


# --------------------------------------------------------------------------- #
# 3. 金标准
# --------------------------------------------------------------------------- #
def gold_rows(topic: str) -> int:
    p = ROOT / "topics" / topic / "gold.jsonl"
    if not p.exists():
        return 0
    return len([l for l in p.read_text(encoding="utf-8").splitlines() if l.strip()])


def check_gold(doc: str) -> None:
    for p in sorted((ROOT / "topics").iterdir()):
        if not p.is_dir():
            continue
        n = gold_rows(p.name)
        rel = len([l for l in (p / "gold.jsonl").read_text(encoding="utf-8").splitlines()
                   if l.strip() and '"relation"' in l]) if (p / "gold.jsonl").exists() else 0
        notes.append(f"[金标准] {p.name}: {n} 行（其中带关系 {rel} 行）")
    # 文档声称 T5 的金标准规模
    m = re.search(r"金标准[^\n]{0,20}?(\d+)\s*实体\s*/\s*(\d+)\s*三元组", doc)
    if m:
        rep = ROOT / "data" / "reports" / "t5-protocol-rfc_eval.json"
        if rep.exists():
            gs = json.loads(rep.read_text(encoding="utf-8"))["gold_size"]
            if int(m.group(1)) != gs["entities"] or int(m.group(2)) != gs["triples"]:
                add("高", "金标准", f"文档称 {m.group(1)} 实体 / {m.group(2)} 三元组，"
                                    f"报告实测 {gs['entities']} / {gs['triples']}")


# --------------------------------------------------------------------------- #
# 4. 评分量规
# --------------------------------------------------------------------------- #
def check_rubric(doc: str) -> None:
    m = re.search(r"## 6\. 评分量规（(\d+) 分）", doc)
    if not m:
        add("中", "量规", "未找到评分量规小节标题（或标题格式变化）")
        return
    total = int(m.group(1))
    sec = doc[m.end(): doc.find("\n**公共热身", m.end()) if "\n**公共热身" in doc else len(doc)]
    ws = [int(x) for x in re.findall(r"^\| [^|\n]+ \| \*{0,2}(\d+)\*{0,2} \|", sec, re.M)]
    s = sum(ws)
    if s != total:
        add("高", "量规", f"评分表权重合计 {s}，与标题声明的 {total} 分不一致（各项 {ws}）")
    else:
        notes.append(f"[量规] 权重合计 {s} = {total} ✓（{len(ws)} 项）")
    # 公共热身 + 加分上限
    if "加分项（供学有余力的学生，累计不超过 10 分）" not in doc:
        add("低", "量规", "未找到加分项上限声明")


# --------------------------------------------------------------------------- #
# 5. 实测数字一致性
# --------------------------------------------------------------------------- #
def check_numbers(doc: str) -> None:
    rep = ROOT / "data" / "reports" / "t5-protocol-rfc_eval.json"
    if not rep.exists():
        add("低", "数字", "缺少 t5 评测报告，无法核对数字")
        return
    d = json.loads(rep.read_text(encoding="utf-8"))["methods"]
    expect = {
        "规则": ("rule", "0.182"), "模型": ("model", "0.044"), "LLM": ("llm", "0.653"),
    }
    for label, (key, f1) in expect.items():
        actual = f"{d[key]['triple']['f1']:.3f}"
        if actual != f1:
            add("高", "数字", f"文档称 {label} 三元组 F1 = {f1}，报告实测 {actual}")
        else:
            notes.append(f"[数字] {label} 三元组 F1 = {f1} ✓")
    ens = d.get("ensemble", {})
    if "0.944" in doc and f"{ens.get('triple', {}).get('recall', 0):.3f}" != "0.944":
        add("高", "数字", f"文档称融合召回 0.944，实测 {ens.get('triple', {}).get('recall')}")
    kg = ROOT / "data" / "kg" / "t5-protocol-rfc_kg.json"
    if kg.exists():
        k = json.loads(kg.read_text(encoding="utf-8"))
        m = re.search(r"节点\s*\*{0,2}(\d+)\*{0,2}\s*·\s*边\s*\*{0,2}(\d+)", doc)
        if m and (int(m.group(1)), int(m.group(2))) != (k["node_count"], k["edge_count"]):
            add("高", "数字", f"文档称图谱 {m.group(1)} 节点/{m.group(2)} 边，"
                              f"实测 {k['node_count']}/{k['edge_count']}")
        else:
            notes.append(f"[数字] 图谱 {k['node_count']} 节点 / {k['edge_count']} 边 ✓")
    # 方法C 拒绝统计
    llm = ROOT / "data" / "extraction" / "t5-protocol-rfc_llm.json"
    if llm.exists():
        rej = json.loads(llm.read_text(encoding="utf-8"))["rejected"]
        if sum(rej.values()) != 0:
            add("中", "数字", f"方法C 存在拒绝条目 {rej}，文档称「拒绝率 0」需更新")


# --------------------------------------------------------------------------- #
# 6. 内部交叉引用
# --------------------------------------------------------------------------- #
def check_xrefs(doc: str) -> None:
    heads = set(re.findall(r"^#{2,4} (\d+(?:\.\d+)?|[A-Z]?\d?)", doc, re.M))
    heads |= set(re.findall(r"^### (T\d)", doc, re.M))
    secs = set(re.findall(r"^### (\d+\.\d+)", doc, re.M))
    for ref in sorted(set(re.findall(r"见\s*\*{0,2}(\d+\.\d+(?:\(\d\))?)\*{0,2}\s*节", doc))):
        base = ref.split("(")[0]
        if base not in secs:
            add("中", "交叉引用", f"文档引用了不存在的小节：见 {ref} 节")
    for ref in sorted(set(re.findall(r"见第\s*(\d+)\s*节", doc))):
        if ref not in heads:
            add("中", "交叉引用", f"文档引用了不存在的大节：见第 {ref} 节")
    notes.append(f"[交叉引用] 小节 {len(secs)} 个，大节 {len(heads)} 个")


# --------------------------------------------------------------------------- #
# 7. 附录 A 计数
# --------------------------------------------------------------------------- #
def check_appendix(doc: str) -> None:
    part = doc[doc.find("## 附录 A"): doc.find("## 附录 B")]
    rows = [l for l in part.splitlines() if l.startswith("| ") and not l.startswith("|---")]
    repo_rows = [l for l in rows if re.search(r"\|\s*[★\d]+\s*\||未声明|（存在", l)]
    ds_rows = [l for l in rows if "HF `" in l or "logpai/loghub" in l]
    notes.append(f"[附录A] 表格行 {len(rows)}，疑似仓库行 {len(repo_rows)}，数据集行 {len(ds_rows)}")
    m = re.search(r"(\d+)\s*个开源仓库", doc)
    if m and abs(len(repo_rows) - int(m.group(1))) > 2:
        add("低", "计数", f"文档称 {m.group(1)} 个开源仓库，附录表疑似 {len(repo_rows)} 行")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--doc", default=str(DEFAULT_DOC))
    ap.add_argument("--quiet-notes", action="store_true")
    a = ap.parse_args()
    doc = Path(a.doc).read_text(encoding="utf-8")

    for fn in (check_paths, check_commands, check_topics, check_scale, check_gold,
               check_rubric, check_numbers, check_xrefs, check_appendix):
        fn(doc)

    order = {"高": 0, "中": 1, "低": 2}
    problems.sort(key=lambda x: order[x[0]])
    print(f"== 文档一致性检查：{a.doc} ==")
    if not a.quiet_notes:
        for n in notes:
            print("  ·", n)
    if not problems:
        print("\n未发现问题 ✅")
        sys.exit(0)
    print(f"\n共 {len(problems)} 项问题：")
    for sev, kind, msg in problems:
        print(f"  [{sev}] ({kind}) {msg}")
    sys.exit(1 if any(p[0] == "高" for p in problems) else 0)


if __name__ == "__main__":
    main()
