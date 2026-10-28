# Protégé / HermiT 推理报告

- 推理机：HermiT 1.4.3.456（Protégé 5.6.9 自带的 `org.semanticweb.hermit`）
- OWL API：4.5.29（Protégé 5.6.9 自带）
- 运行方式：`protege/tools/ReasonCheck.java`，classpath 指向 `protege/tools/lib/`
- 说明：`inferred_*_verified` 是对 `*.inferred.owl` 做集合差得到的实测值，
  与 ReasonCheck 打印的计数相互核对。

| 文件 | 一致 | 不可满足类 | 类 | 对象属性 | 个体 | 公理 | OWL 2 DL | 违规 | 推理新增类型 | 推理新增边 | 耗时 ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `protege\owl\t2-threat-intel-tbox.owl.ttl` | True | 0 | 19 | 17 | 0 | 400 | True | 0 | 0 | 0 | 734 |
| `protege\owl\t2-threat-intel.owl.ttl` | True | 0 | 19 | 17 | 421 | 5379 | True | 0 | 406 | 310 | 1503 |

## 推理新增明细

### `protege\owl\t2-threat-intel-tbox.owl.ttl`

- 新增类断言：无
- 新增对象属性边：无

### `protege\owl\t2-threat-intel.owl.ttl`

- 新增类断言：`SecurityConcept` × 406
- 新增对象属性边：`used_by` × 113、`uses` × 197

## 怎么读这些数

- `SecurityConcept × 406`：所有领域类个体都通过 `rdfs:subClassOf` 被推理出
  属于顶层类；Document 个体不属于 `SecurityConcept`，所以是 421 − 15 = 406。
- `uses × 197`：`group_uses`（113）与 `software_uses`（84）是 `uses` 的子属性，
  HermiT 为每条子属性边补出父属性边。
- `used_by × 113`：`used_by owl:inverseOf group_uses`，所以每条组织使用技术的边
  都反推出“技术被组织使用”。
- 这些是 OWL 语义的**必然推论**，不是新抽取的事实；原始图谱仍以 1572 条断言边为准。
