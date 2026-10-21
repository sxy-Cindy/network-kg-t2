"""kgcourse-starter — 《知识图谱技术与应用》网络工程专业实践作业共享脚手架。

统一数据模型与工具函数。所有阶段的中间产物都用这里的 `Entity` / `Relation`
结构承载，便于三种抽取方法横向对比与融合。

产物约定（与参考案例 kgcase 对齐）：
    本体   : ontology.json（工程友好） + ontology.ttl（OWL/RDFS，可导入 GraphDB）
    抽取   : extraction/<topic>_<method>.json
    知识图谱: kg/<topic>_kg.json + .ttl + .graphml + _cytoscape.json
    评估   : reports/<topic>_eval_<method>.json
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

__version__ = "0.1.0"

# 方法标识：三种构建 KG 的路线 + 融合
METHODS = ("rule", "model", "llm", "ensemble")


# --------------------------------------------------------------------------- #
# 统一数据模型
# --------------------------------------------------------------------------- #
@dataclass
class Entity:
    """一个实体提及（mention）。同一实体在不同文档中会出现多次，融合阶段再归并。"""

    id: str                      # 规范主键，如 rfc:2119 / proto:TCP
    label: str                   # 人类可读名称
    type: str                    # 本体类名，必须存在于 ontology.json 的 classes 中
    doc: str = ""                # 来源文档 ID
    evidence: str = ""           # 原文证据（一句话或片段的上下文）
    method: str = ""             # rule / model / llm
    aliases: List[str] = field(default_factory=list)
    properties: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Relation:
    """一条三元组（s, r, o）的实例。"""

    source: str                  # Entity.id
    relation: str                # 本体中的关系 ID，必须存在于 ontology.json 的 relations 中
    target: str                  # Entity.id
    doc: str = ""
    evidence: str = ""
    method: str = ""
    properties: Dict[str, Any] = field(default_factory=dict)

    def key(self) -> tuple:
        return (self.source, self.relation, self.target)


# --------------------------------------------------------------------------- #
# 读写
# --------------------------------------------------------------------------- #
def read_json(path: Path | str) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write_json(path: Path | str, obj: Any) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")
    return p


def read_jsonl(path: Path | str) -> List[dict]:
    rows: List[dict] = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        rows.append(json.loads(line))
    return rows


def write_jsonl(path: Path | str, rows: Iterable[dict]) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")
    return p


def dumps_compact(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))


def entities_to_json(entities: Iterable[Entity]) -> List[dict]:
    return [asdict(e) for e in entities]


def relations_to_json(relations: Iterable[Relation]) -> List[dict]:
    return [asdict(r) for r in relations]


# --------------------------------------------------------------------------- #
# 归一化 / 消歧辅助
# --------------------------------------------------------------------------- #
_WS = re.compile(r"\s+")


def norm_label(text: str) -> str:
    """标签归一：去首尾空白、压缩内部空白、全角转半角、统一小写用于比较。"""
    text = unicodedata_normalize(text)
    text = _WS.sub(" ", text).strip()
    return text


def unicodedata_normalize(text: str) -> str:
    import unicodedata

    return unicodedata.normalize("NFKC", text)


def slug(text: str, prefix: str = "") -> str:
    """把标签转成稳定 ID 后缀（保留 ASCII 字母数字，其余折叠为 `-`）。"""
    s = unicodedata_normalize(text).strip().lower()
    s = re.sub(r"[^0-9a-z\u4e00-\u9fff]+", "-", s).strip("-")
    return f"{prefix}{s}" if prefix else s


def make_id(prefix: str, label: str) -> str:
    return f"{prefix}:{slug(label)}"


# --------------------------------------------------------------------------- #
# 项目路径
# --------------------------------------------------------------------------- #
def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def topic_dir(topic: str) -> Path:
    d = repo_root() / "topics" / topic
    if not d.is_dir():
        raise FileNotFoundError(
            f"topic {topic!r} 不存在；可选：{', '.join(sorted(p.name for p in (repo_root() / 'topics').iterdir() if p.is_dir()))}"
        )
    return d


def load_topic(topic: str) -> dict:
    """读取题目配置（topic.yaml）+ 本体种子 + 规则 + 词典 + 金标准。"""
    import yaml

    td = topic_dir(topic)
    cfg = yaml.safe_load((td / "topic.yaml").read_text(encoding="utf-8")) or {}
    cfg["topic"] = topic
    cfg["dir"] = str(td)
    cfg["ontology_seed"] = read_json(td / "ontology.json")
    pat = td / "patterns.yaml"
    cfg["patterns"] = (yaml.safe_load(pat.read_text(encoding="utf-8")) or {}) if pat.exists() else {}
    lex = td / "lexicons.yaml"
    cfg["lexicons"] = (yaml.safe_load(lex.read_text(encoding="utf-8")) or {}) if lex.exists() else {}
    gold = td / "gold.jsonl"
    cfg["gold"] = read_jsonl(gold) if gold.exists() else []
    return cfg


def out_dir(kind: str, topic: str) -> Path:
    """kind ∈ {ontology, extraction, kg, reports, corpus}"""
    d = repo_root() / "data" / kind
    d.mkdir(parents=True, exist_ok=True)
    return d


def load_corpus(cfg: dict) -> List[dict]:
    """读取题目语料：data/corpus/<topic>/*.txt，返回 [{doc_id, title, text}]。"""
    root = repo_root() / "data" / "corpus" / cfg["topic"]
    docs: List[dict] = []
    for f in sorted(root.glob("*.txt")):
        text = f.read_text(encoding="utf-8", errors="replace")
        title = ""
        for line in text.splitlines()[:40]:
            if line.strip():
                title = line.strip()
                break
        docs.append({"doc_id": f.stem, "title": title, "text": text, "path": str(f)})
    return docs


def require_known_types(cfg: dict, entities: List[Entity]) -> List[str]:
    """校验抽取结果里出现的类是否都在本体中定义（教学用：本体约束抽取）。

    返回违规的类名列表，不抛异常，便于学生在报告里统计"越界实体"。
    """
    known = {c["id"] for c in cfg["ontology_seed"].get("classes", [])}
    return sorted({e.type for e in entities if e.type not in known})


def require_known_relations(cfg: dict, relations: List[Relation]) -> List[str]:
    known = {r["id"] for r in cfg["ontology_seed"].get("relations", [])}
    return sorted({r.relation for r in relations if r.relation not in known})


_BLANK = re.compile(r"\n[ \t]*\n")


def snippet(text: str, start: int, end: int, width: int = 60) -> str:
    """截取证据片段（匹配处前后各 width 字符，压平空白）。

    证据必须落在**同一条记录**内：语料以空行分块，若只按 ±width 截取，片段会越过
    空行把上一条记录的描述带进来（实测 CAPEC-10 的证据里出现了 CAPEC-9 的中文说明，
    看起来像关系抽错了）。因此先把窗口裁到最近的空行边界。
    """
    lo = max(0, start - width)
    hi = min(len(text), end + width)
    head = list(_BLANK.finditer(text, 0, start))
    if head:
        lo = max(lo, head[-1].end())
    tail = _BLANK.search(text, end)
    if tail:
        hi = min(hi, tail.start())
    return _WS.sub(" ", text[lo:hi]).strip()


_PURE_DIGITS = re.compile(r"^\d+$")


def is_valid_label(label: str, min_len: int = 2) -> bool:
    """实体标签的**最小**质量门槛（融合阶段使用）。

    实测背景：模型法会把通用词与纯数字标成实体（`6`、`x`、`layer`），进入融合后形成
    技术上是错的边（`6 operates_at layer`、`TCP operates_at Application Layer`）。
    本体只约束"类/关系的名字"，管不住"标签内容"，因此融合层需要内容门槛。

    刻意保守（只抓明显垃圾，宁可漏放不可误杀）：
      * 长度 < min_len（默认 2）→ 丢弃，如 `6`、`x`；
      * 纯数字 → 丢弃，如 `6`；
      * 其余一律保留 —— 因为"合法但语义可疑"的标签（`1.1` 章节号、`10.10.20.0/24`
        CIDR、`AS12345`）都是**正常领域标签**，通用词法规则分不清，误杀代价远大于漏放。

    更细的语义把关交给两个**类别感知**的机制，而不是通用词法规则：
      1. `fusion.controlled_classes` + lexicons.yaml 受控词表（例：Layer 只能是五个分层名，
         这条能拦住 `layer`，且不会影响 CIDR/IP 这类无词表的类）；
      2. `check_domain_range()` 类继承感知的域值域校验（拦住类型错误的关系）。
    """
    if not label:
        return False
    lbl = norm_label(label)
    if len(lbl) < min_len:
        return False
    return not _PURE_DIGITS.match(lbl)


def check_domain_range(cfg: dict, entities: Dict[str, "Entity"],
                       relations: Iterable["Relation"]) -> list[dict]:
    """按本体声明的 domain/range 校验关系的两端类型，返回违规记录。

    这是本体的第二次用法：第一次用来约束抽取（越界类/关系），第二次用来**校验图的合法性**
    （`operates_at` 的两端必须真的是 Protocol → Layer）。实现上不做硬删除，
    只产出违规清单，供融合阶段降权或学生做抽检。
    """
    seed = cfg["ontology_seed"]
    spec = {}
    for r in seed.get("relations", []):
        if r.get("domain") and r.get("range"):
            spec[r["id"]] = (r["domain"], r["range"])
    parents = {c["id"]: c.get("parent") for c in seed.get("classes", [])}
    parents.setdefault("Document", None)

    def is_a(cls: str, want: str) -> bool:
        """类继承判定（`cites` 的域值域是 Document→Document，而两端实体常是 RFC ⊑ Document，
        不做继承展开会把全部合法边误判为违规——实测踩过）。"""
        seen = set()
        cur = cls
        while cur and cur not in seen:
            if cur == want:
                return True
            seen.add(cur)
            cur = parents.get(cur)
        return False
    out: list[dict] = []
    for rel in relations:
        want = spec.get(rel.relation)
        if not want:
            continue
        s, t = entities.get(rel.source), entities.get(rel.target)
        if s is None or t is None:
            continue
        if not (is_a(s.type, want[0]) and is_a(t.type, want[1])):
            out.append({"relation": rel.relation, "expected": f"{want[0]}->{want[1]}",
                        "actual": f"{s.type}->{t.type}",
                        "head": s.label, "tail": t.label, "doc": rel.doc})
    return out
