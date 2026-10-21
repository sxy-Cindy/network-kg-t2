"""实体 ID 归一：把任意方法抽到的**标签**映射回**官方主键**。

为什么单独一层：模型法只认识 token，它解码出的标签是原文片段；LLM 法可能返回
`T1059`、`T1059.001` 或 `Command and Scripting Interpreter` 三种写法。如果各方法
自己生成 ID（`technique:t1059`、`attck:T1059`、`tactic:...`），融合阶段就无法对齐，
下游 Agent 也没法用官方 ID 去查 MITRE。

本模块只做一件事：给定 (本体类, 标签)，返回该类的规范 ID；识别不了就退回
`<type>:<slug>`。规则/模型/LLM/融合四条路径都必须走这里。

⚠ 本文件**不写任何编号正则**：正则与 ID 模板统一放在 topics/<topic>/patterns.yaml 的
`entity_patterns[].id_template` 与 `id_patterns` 里（数据与代码分离）。
"""
from __future__ import annotations

import re
from typing import Iterable, List, Optional, Tuple

from . import schema as S


def _format(template: str, m: re.Match) -> str:
    # 模板里的 {1} 指第一个捕获组；格式化参数因此是 [整段匹配, 组1, 组2, ...]
    args = [m.group(0)] + [g or "" for g in m.groups()]
    try:
        return template.format(*args)
    except (IndexError, KeyError):
        return template


def _match(rx: re.Pattern, lab: str) -> Optional[re.Match]:
    """整串匹配；对带结尾 lookahead 的 CPE 模式，补一个空格再试（匹配仍需止于 lab）。"""
    m = rx.fullmatch(lab)
    if m:
        return m
    m = rx.match(lab + " ")
    if m and m.end() == len(lab):
        return m
    return None


class IdResolver:
    """(类 -> [(正则, ID 模板)]) 的解析器，按配置文件构造。"""

    def __init__(self, rules: Iterable[dict], lexicons: dict | None = None):
        self.rules: dict[str, List[Tuple[re.Pattern, str]]] = {}
        for r in rules:
            try:
                rx = re.compile(r["regex"])
            except (KeyError, re.error):
                continue
            tmpl = r.get("template") or r.get("id_template") or "{1}"
            self.rules.setdefault(r["type"], []).append((rx, tmpl))
        # surface 名称 -> (官方 ID, 规范标签)：LLM 常把 "T1059.001 PowerShell" 里的
        # 名称抄下来却不抄编号，这一步把名称映射回官方主键。
        self.lex: dict[Tuple[str, str], Tuple[str, str]] = {}
        for etype, entries in (lexicons or {}).items():
            for entry in entries:
                if isinstance(entry, dict):
                    surface = entry.get("surface", "")
                    eid = entry.get("id") or ""
                    label = entry.get("label", surface)
                else:
                    surface, eid, label = entry, "", entry
                if surface:
                    self.lex[(etype, S.norm_label(surface).lower())] = (
                        eid or self.canonical(etype, surface), S.norm_label(label))

    @classmethod
    def from_cfg(cls, cfg: dict) -> "IdResolver":
        pats = cfg.get("patterns") or {}
        rules: List[dict] = list(pats.get("id_patterns") or [])
        for p in pats.get("entity_patterns") or []:
            if p.get("id_template"):
                rules.append({"type": p["type"], "regex": p["regex"],
                              "template": p["id_template"]})
        return cls(rules, cfg.get("lexicons"))

    def lookup(self, etype: str, label: str) -> Optional[Tuple[str, str]]:
        """正文名称 -> (官方 ID, 规范标签)；不在词典里返回 None。"""
        return self.lex.get((etype, S.norm_label(label or "").lower()))

    def types(self) -> List[str]:
        return sorted(self.rules)

    def official(self, etype: str, label: str) -> Optional[str]:
        """标签本身就是该类官方编号时返回它，否则 None。"""
        lab = S.norm_label(label or "")
        for rx, _ in self.rules.get(etype, []):
            if _match(rx, lab):
                return lab
        return None

    def find_id(self, etype: str, label: str) -> Optional[str]:
        """在标签里**搜索**该类官方编号（不要求整串就是编号）。

        用途：LLM 会把 KEV 记录写成 "The KEV entry for CVE-2021-44228"、把产品写成
        "FortiProxy 2.0.0"；这类标签的主键仍应落到官方编号上，否则同一实体因措辞
        不同会被拆成多个节点（实测：KEV 记录被拆成 `kev:CVE-x` 与
        `ExploitationRecord:the-kev-entry-for-cve-x` 两份）。
        """
        lab = S.norm_label(label or "")
        for rx, _ in self.rules.get(etype, []):
            m = _match(rx, lab) or rx.search(lab)
            if m:
                return m.group(1) if m.groups() else m.group(0)
        return None

    def find_all(self, text: str) -> List[Tuple[str, str, int, int]]:
        """在自由文本中定位所有官方编号：[(类型, 原文编号, 起, 止)]。

        用途是**核验模型答案**：答案里出现的每个编号都要能落到一条检索到的三元组上，
        否则就是编造（即使它格式合法、甚至指向一个真实但图谱里没有的编号）。
        正则仍全部来自 patterns.yaml，本模块不内置任何选题词表。
        """
        found: List[Tuple[str, str, int, int]] = []
        for etype, rules in self.rules.items():
            for rx, _ in rules:
                for m in rx.finditer(text or ""):
                    if m.groups():
                        s, e = m.span(1)
                        surface = m.group(1)
                    else:
                        s, e = m.span(0)
                        surface = m.group(0)
                    found.append((etype, surface, s, e))
        found.sort(key=lambda x: (x[2], -(x[3] - x[2])))
        kept: List[Tuple[str, str, int, int]] = []
        seen_span = set()
        for item in found:
            span = (item[2], item[3])
            if span in seen_span:      # 同一个编号被多条规则命中（如 CVE 与 KEV 派生规则）
                continue
            if kept and item[2] < kept[-1][3]:
                continue               # 与更长的匹配重叠（T1059 落在 T1059.001 内）
            kept.append(item)
            seen_span.add(span)
        return kept

    def canonical(self, etype: str, label: str) -> str:
        lab = S.norm_label(label or "")
        for rx, tmpl in self.rules.get(etype, []):
            m = _match(rx, lab) or rx.search(lab)
            if m:
                # 模板里若带固定前缀（如 kev:），格式化后直接作为主键
                cand = _format(tmpl, m)
                return cand if ":" in cand else f"{etype.lower()}:{cand}"
        if etype == "Vendor":
            return f"vendor:{S.slug(lab)}"
        return S.make_id(etype, lab)
