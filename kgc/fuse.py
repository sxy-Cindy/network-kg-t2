"""阶段二 · 融合（ensemble）：三路结果的合并、消歧与置信度。

为什么需要融合：规则法召回高但精度受模板限制；模型法在标注覆盖的类上精度高、
未见类全丢；LLM 法召回与泛化最好但会幻觉，且不稳定。融合的目标是 **取并集后
按证据投票**，把"三方法各自能发现什么"变成一条可信度排序的三元组清单。

算法（可复现，无隐藏随机性）：
  1. **实体对齐**：以 (type, 归一化 label) 为键归并不同方法给出的实体 ID，
     取权重最高方法提供的 ID 作为规范 ID；别名表 topics/<topic>/aliases.yaml
     可把同义表面形式显式合并（例如 "IPv6" / "Internet Protocol version 6"）。
  2. **三元组投票**：把 (规范头, 关系, 规范尾) 作为键收集命中方法集合。
  3. **置信度**：confidence = Σ权重(命中方法) / Σ权重(全部方法)，
     权重在 topic.yaml `fusion.weights` 中配置，默认 rule=1.0, model=0.8, llm=1.2。
  4. **证据合并**：保留各方法给出的 evidence，按方法顺序拼接（截断到 300 字），
     便于人工抽检时对照原文。
  5. **一致性报告**：单方法独有/两法共有/三法共有 的数量分布，用于讨论
     "哪类知识只有 LLM 能抽到、哪类只有规则能保证"。

  6. **质量门槛（实测新增）**：本体只约束"类/关系的名字"，管不住"标签内容"。
     实测中模型法产出的 `6` / `layer` 等标签会形成技术错误的边
     （`6 operates_at layer`、`TCP operates_at Application Layer`），因此融合层增加：
       * `is_valid_label()` 标签质量门槛（纯数字/单字符/纯标点一律丢弃）；
       * `fusion.controlled_classes`（可选）受控词表校验：该类实体的标签必须出现在
         `lexicons.yaml` 的同名词表中（例如 Layer 只能是五个分层名之一）；
       * `check_domain_range()` 域值域校验，违规边记入报告并（可选）降权。
     被丢弃的实体与边全部记录在报告中，不允许静默删除。
  """

from __future__ import annotations

from typing import Dict, List, Tuple

from . import ids as I
from . import schema as S

DEFAULT_WEIGHTS = {"rule": 1.0, "model": 0.8, "llm": 1.2}


def _load_method(cfg: dict, method: str) -> dict | None:
    p = S.out_dir("extraction", cfg["topic"]) / f"{cfg['topic']}_{method}.json"
    if not p.exists():
        return None
    return S.read_json(p)


def _aliases(cfg: dict) -> Dict[str, str]:
    import yaml

    p = S.repo_root() / "topics" / cfg["topic"] / "aliases.yaml"
    if not p.exists():
        return {}
    data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    out: Dict[str, str] = {}
    for canonical, variants in data.items():
        out[S.norm_label(canonical).lower()] = S.norm_label(canonical)
        for v in variants or []:
            out[S.norm_label(v).lower()] = S.norm_label(canonical)
    return out


def run(topic: str, verbose: bool = True) -> dict:
    cfg = S.load_topic(topic)
    weights = {**DEFAULT_WEIGHTS, **(cfg.get("fusion", {}).get("weights") or {})}
    alias_map = _aliases(cfg)
    controlled = set((cfg.get("fusion") or {}).get("controlled_classes") or [])
    lexicons = cfg.get("lexicons") or {}
    drop_controlled = bool((cfg.get("fusion") or {}).get("enforce_controlled", True))
    official_classes = set((cfg.get("fusion") or {}).get("official_id_classes") or [])
    label_templates = (cfg.get("fusion") or {}).get("label_templates") or {}
    resolver = I.IdResolver.from_cfg(cfg)

    available = {m: _load_method(cfg, m) for m in ("rule", "model", "llm")}
    available = {m: v for m, v in available.items() if v}
    if not available:
        raise SystemExit("[fuse] 没有找到任何抽取结果，先跑 rule / model / llm")

    # 0) **ID 归一优先于标签对齐**：同一个实体在不同方法里可能写成
    #    "CVE-2021-44228" / "The KEV entry for CVE-2021-44228" / "KEV entry for CVE-…"。
    #    先按该类官方编号把标签收敛到统一形式，再做 (type,label) 对齐，
    #    否则 KEV 记录会被拆成两个节点（实测出现过）。关系端点同步重映射。
    def _normalize_entity(e: dict) -> dict:
        etype = e["type"]
        oid = resolver.find_id(etype, e.get("label", ""))
        if not oid:
            return e
        e = dict(e)
        e["id"] = resolver.canonical(etype, oid)
        tmpl = label_templates.get(etype)
        e["label"] = tmpl.format(id=oid) if tmpl else oid
        return e

    def _normalize_payload(payload: dict) -> dict:
        remap: Dict[str, str] = {}
        ents: List[dict] = []
        seen: set = set()
        for e in payload.get("entities") or []:
            ne = _normalize_entity(e)
            remap[e["id"]] = ne["id"]
            if ne["id"] in seen:
                continue
            seen.add(ne["id"])
            ents.append(ne)
        rels = []
        for r in payload.get("relations") or []:
            r = dict(r)
            r["source"] = remap.get(r["source"], r["source"])
            r["target"] = remap.get(r["target"], r["target"])
            rels.append(r)
        out = dict(payload)
        out["entities"], out["relations"] = ents, rels
        return out

    available = {m: _normalize_payload(v) for m, v in available.items()}

    # 0b) 标签质量门槛 + 受控词表门槛（丢弃清单随报告一起给出，便于人工复核）
    dropped: Dict[str, list] = {"invalid_label": [], "out_of_controlled": [],
                                "non_official_id": []}

    def _keep(e: dict) -> bool:
        if not S.is_valid_label(e["label"]):
            dropped["invalid_label"].append({"type": e["type"], "label": e["label"],
                                             "id": e["id"]})
            return False
        if e["type"] in official_classes and not resolver.find_id(e["type"], e["label"]):
            # 有官方编号的类不接受自由文本（"command injection" 不是 CWE 节点）
            dropped["non_official_id"].append({"type": e["type"], "label": e["label"],
                                               "id": e["id"]})
            return False
        if drop_controlled and e["type"] in controlled:
            allowed = {S.norm_label(x).lower() for x in (lexicons.get(e["type"]) or [])}
            if allowed and S.norm_label(e["label"]).lower() not in allowed:
                dropped["out_of_controlled"].append({"type": e["type"], "label": e["label"],
                                                     "id": e["id"]})
                return False
        return True

    kept: Dict[str, dict] = {}
    for method, payload in available.items():
        ents = [e for e in payload["entities"] if _keep(e)]
        rels = {e["id"] for e in ents}
        payload = dict(payload)
        payload["entities"] = ents
        # 结构关系 mentioned_in 的尾端是合成的文档节点 id（doc:xxx），不在实体表里，
        # 必须放行 —— 否则会被这里误删（实测踩过：错误过滤后 mentioned_in 全丢）。
        def _ok_endpoint(x: str) -> bool:
            return x in rels or x.startswith("doc:")

        payload["relations"] = [r for r in payload["relations"]
                                if _ok_endpoint(r["source"]) and _ok_endpoint(r["target"])]
        kept[method] = payload
    available = kept

    # 1) 实体对齐
    ent_index: Dict[Tuple[str, str], dict] = {}
    for method, payload in available.items():
        for e in payload["entities"]:
            label = alias_map.get(S.norm_label(e["label"]).lower(), S.norm_label(e["label"]))
            key = (e["type"], label.lower())
            slot = ent_index.setdefault(key, {"label": label, "type": e["type"],
                                              "ids": {}, "methods": set(),
                                              "aliases": set()})
            slot["ids"].setdefault(method, e["id"])
            slot["methods"].add(method)
            # 名称别名：A 的结构化实体带 name（"APT41"），C 带 surface；
            # 规范标签用官方编号后名称不能丢，否则 Agent 用 "APT41" 查不到 G0096。
            for prop in ("name", "surface"):
                v = (e.get("properties") or {}).get(prop)
                if v and S.norm_label(v) and S.norm_label(v) != label:
                    slot["aliases"].add(S.norm_label(v))

    canonical: Dict[Tuple[str, str, str], str] = {}
    used_ids: Dict[str, int] = {}
    for key, slot in ent_index.items():
        best_method = max(slot["ids"], key=lambda m: weights.get(m, 0))
        cid = slot["ids"][best_method]
        if cid in used_ids and used_ids[cid] != hash(key):
            cid = S.make_id(slot["type"], slot["label"])
        used_ids[cid] = hash(key)
        canonical[(slot["type"], slot["label"].lower(), "")] = cid
        canonical[(slot["type"], slot["label"].lower(), best_method)] = cid
        slot["canonical_id"] = cid

    id_map: Dict[str, str] = {}
    for method, payload in available.items():
        for e in payload["entities"]:
            label = alias_map.get(S.norm_label(e["label"]).lower(), S.norm_label(e["label"]))
            id_map[e["id"]] = ent_index[(e["type"], label.lower())]["canonical_id"]

    # 2) 三元组投票
    votes: Dict[Tuple[str, str, str], dict] = {}
    for method, payload in available.items():
        for r in payload["relations"]:
            s_id = id_map.get(r["source"], r["source"])
            t_id = id_map.get(r["target"], r["target"])
            if s_id == t_id:
                continue
            k = (s_id, r["relation"], t_id)
            slot = votes.setdefault(k, {"methods": [], "evidence": {}, "docs": set()})
            if method not in slot["methods"]:
                slot["methods"].append(method)
            slot["evidence"][method] = r.get("evidence", "")
            slot["docs"].add(r.get("doc", ""))

    total_w = sum(weights.get(m, 1.0) for m in available)
    relations: List[S.Relation] = []
    for (s_id, rel, t_id), slot in votes.items():
        conf = round(sum(weights.get(m, 1.0) for m in slot["methods"]) / total_w, 4)
        ev = " || ".join(f"[{m}] {slot['evidence'][m]}" for m in slot["methods"] if slot["evidence"][m])[:300]
        relations.append(S.Relation(
            source=s_id, relation=rel, target=t_id, doc=",".join(sorted(d for d in slot["docs"] if d)),
            evidence=ev, method="ensemble",
            properties={"methods": sorted(slot["methods"]), "confidence": conf,
                        "votes": len(slot["methods"])},
        ))
    relations.sort(key=lambda r: (-r.properties["confidence"], r.source, r.relation, r.target))

    entities = [
        S.Entity(id=slot["canonical_id"], label=slot["label"], type=slot["type"],
                 method="ensemble",
                 properties={"methods": sorted(slot["methods"]),
                             "aliases": sorted(slot["aliases"])})
        for slot in ent_index.values()
    ]

    # 6) 域值域校验（本体第二次用法）：违规边记录 + 降权，不静默删除
    ent_by_id = {e.id: e for e in entities}
    violations = S.check_domain_range(cfg, ent_by_id, relations)
    vkeys = {(v["head"], v["relation"], v["tail"]) for v in violations}
    for r in relations:
        head = ent_by_id[r.source].label if r.source in ent_by_id else r.source
        tail = ent_by_id[r.target].label if r.target in ent_by_id else r.target
        if (head, r.relation, tail) in vkeys:
            r.properties["domain_range_violation"] = True
            r.properties["confidence"] = round(r.properties.get("confidence", 1.0) * 0.5, 4)

    dist: Dict[str, int] = {}
    for r in relations:
        dist[str(r.properties["votes"])] = dist.get(str(r.properties["votes"]), 0) + 1

    payload = {
        "topic": topic, "method": "ensemble",
        "methods_available": sorted(available), "weights": weights,
        "entity_count": len(entities), "relation_count": len(relations),
        "triple_vote_distribution": dict(sorted(dist.items())),
        "dropped": {k: v[:50] for k, v in dropped.items()},
        "dropped_counts": {k: len(v) for k, v in dropped.items()},
        "domain_range_violations": violations[:50],
        "domain_range_violation_count": len(violations),
        "entities": S.entities_to_json(entities),
        "relations": S.relations_to_json(relations),
    }
    path = S.write_json(S.out_dir("extraction", topic) / f"{topic}_ensemble.json", payload)
    if verbose:
        print(f"[fuse] 方法={payload['methods_available']} 权重={weights}")
        print(f"[fuse] 质量门槛丢弃：标签不合法 {payload['dropped_counts']['invalid_label']} · "
              f"受控词表外 {payload['dropped_counts']['out_of_controlled']} · "
              f"非官方编号 {payload['dropped_counts'].get('non_official_id', 0)}")
        print(f"[fuse] 域值域违规边 {payload['domain_range_violation_count']}（已降权 0.5×，未删除）")
        print(f"[fuse] 对齐后实体 {len(entities)} · 融合三元组 {len(relations)}")
        print(f"[fuse] 投票分布（命中方法数 -> 三元组数）：{payload['triple_vote_distribution']}")
        print(f"[fuse] -> {path}")
    return payload


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="阶段二·融合：三方法合并 + 消歧 + 置信度")
    ap.add_argument("--topic", required=True)
    run(ap.parse_args().topic)
