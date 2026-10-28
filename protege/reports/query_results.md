# Protégé/SPARQL 能力题执行结果

- OWL：`protege\owl\t2-threat-intel.owl.ttl`（17966 三元组）
- 查询目录：`protege/queries/`

| 查询 | 结果行数 | 说明 |
|---|---:|---|
| `q01_panos_exposure.rq` | 1 | 暴露面：哪些漏洞影响 PAN-OS 10.2？是否进入 KEV？ |
| `q02_t1059_rules.rq` | 2 | 检测覆盖：哪些 Sigma 规则声明检测 T1059.001？ |
| `q03_ta0002_techniques.rq` | 7 | 战术汇总：TA0002（Execution）下有哪些技术？ |
| `q04_cve_multihop.rq` | 26 | 多跳：CVE-2024-3400 -> CWE -> CAPEC -> ATT&CK 技术 -> 战术 |
| `q05_kev_coverage.rq` | 1 | KEV 覆盖：切片内漏洞数与 KEV 记录数 |
| `q06_group_path.rq` | 1 | 多跳：APT41（G0096）使用 T1059.001，后者属于 TA0002 |
| `q07_panos_detection.rq` | 14 | 跨源检测覆盖：CVE-2024-3400 的弱点/攻击模式/技术对应哪些 Sigma 规则？ |
| `q08_kev_ransomware.rq` | 12 | 数据属性：被标记为 Known 勒索软件利用的 KEV 条目（按收录日期倒序） |
| `q09_refusal_probe.rq` | 0 | 拒答探针：图谱中不存在的 CVE 应返回 0 行 |
| `q10_t1190_coverage.rq` | 15 | 检测/缓解覆盖：T1190（Exploit Public-Facing Application）的 Sigma 规则与 ATT&CK 缓解 |

## 明细

### q01_panos_exposure.rq

暴露面：哪些漏洞影响 PAN-OS 10.2？是否进入 KEV？

返回 **1** 行。

| cve | product | kev_date |
|---|---|---|
| CVE-2024-3400 | cpe:2.3:o:paloaltonetworks:pan-os:10.2.0:*:*:*:*:*:*:* | 2024-04-12 |

### q02_t1059_rules.rq

检测覆盖：哪些 Sigma 规则声明检测 T1059.001？

返回 **2** 行。

| rule_id | title |
|---|---|
| 1ab3c5ed-5baf-417b-bb6b-78ca33f6c3df | AWS EC2 Startup Shell Script Change |
| 401e5d00-b944-11ea-8f9a-00163ecd60ae | AppLocker Prevented Application or Script from Running |

### q03_ta0002_techniques.rq

战术汇总：TA0002（Execution）下有哪些技术？

返回 **7** 行。

| technique | name |
|---|---|
| T1021 | Remote Services |
| T1047 | Windows Management Instrumentation |
| T1059 | Command and Scripting Interpreter |
| T1059.001 | PowerShell |
| T1059.003 | Windows Command Shell |
| T1059.004 | Unix Shell |
| T1203 | Exploitation for Client Execution |

### q04_cve_multihop.rq

多跳：CVE-2024-3400 -> CWE -> CAPEC -> ATT&CK 技术 -> 战术

返回 **26** 行。

| weakness | pattern | technique | tactic |
|---|---|---|---|
| CWE-20 | CAPEC-10 | T1068 | TA0004 |
| CWE-20 | CAPEC-108 | T1190 | TA0001 |
| CWE-20 | CAPEC-109 | T1190 | TA0001 |
| CWE-20 | CAPEC-110 | T1190 | TA0001 |
| CWE-20 | CAPEC-136 | T1190 | TA0001 |
| CWE-20 | CAPEC-14 | T1203 | TA0002 |
| CWE-20 | CAPEC-22 | T1078 | TA0001 |
| CWE-20 | CAPEC-22 | T1078 | TA0003 |
| CWE-20 | CAPEC-22 | T1078 | TA0004 |
| CWE-20 | CAPEC-22 | T1078 | TA0005 |
| CWE-20 | CAPEC-24 | T1190 | TA0001 |
| CWE-20 | CAPEC-43 | T1059 | TA0002 |
| … | 共 26 行，见 JSON | | |

### q05_kev_coverage.rq

KEV 覆盖：切片内漏洞数与 KEV 记录数

返回 **1** 行。

| vulnerabilities | kev_records |
|---|---|
| 45 | 40 |

### q06_group_path.rq

多跳：APT41（G0096）使用 T1059.001，后者属于 TA0002

返回 **1** 行。

| group_id | technique | tactic |
|---|---|---|
| G0096 | T1059.001 | TA0002 |

### q07_panos_detection.rq

跨源检测覆盖：CVE-2024-3400 的弱点/攻击模式/技术对应哪些 Sigma 规则？

返回 **14** 行。

| cve | rule_id | title |
|---|---|---|
| CVE-2024-3400 | 071d5e5a-9cef-47ec-bc4e-a42e34d8d0ed | Possible Coin Miner CPU Priority Param |
| CVE-2024-3400 | 101a1877-2cf4-474d-abfd-7f6ac4788d1a | Antivirus - APT Malware Signature |
| CVE-2024-3400 | 18b042f0-2ecd-4b6e-9f8d-aa7a7e7de781 | Buffer Overflow Attempts |
| CVE-2024-3400 | 238527ad-3c2c-4e4f-a1f6-92fd63adb864 | Antivirus - Exploitation Framework Signature |
| CVE-2024-3400 | 48d91a3a-2363-43ba-a456-ca71ac3da5c2 | Audit CVE Event |
| CVE-2024-3400 | 6991bc2b-ae2e-447f-bc55-3a1ba04c14e5 | OpenCanary - FTP Login Attempt |
| CVE-2024-3400 | 72af37e2-ec32-47dc-992b-bc288a2708cb | Azure New CloudShell Created |
| CVE-2024-3400 | 808146b2-9332-4d78-9416-d7e47012d83d | BPFDoor Abnormal Process ID or Lock File Accessed |
| CVE-2024-3400 | bb0e9cec-d4da-46f5-997f-22efc59f3dca | Potential JNDI Injection Exploitation In JVM Based Application |
| CVE-2024-3400 | e0cfaecd-602d-41af-988d-f6ccebb2af26 | Suspicious Installer Package Child Process |
| CVE-2024-3400 | e9a2b582-3f6a-48ac-b4a1-6849cdc50b3c | Apache Threading Error |
| CVE-2024-3400 | eed82177-38f5-4299-8a76-098d50d225ab | Kubernetes Admission Controller Modification |
| … | 共 14 行，见 JSON | |

### q08_kev_ransomware.rq

数据属性：被标记为 Known 勒索软件利用的 KEV 条目（按收录日期倒序）

返回 **12** 行。

| cve | kev_date | ransomware |
|---|---|---|
| CVE-2024-3400 | 2024-04-12 | Known |
| CVE-2024-21893 | 2024-01-31 | Known |
| CVE-2023-46805 | 2024-01-10 | Known |
| CVE-2024-21887 | 2024-01-10 | Known |
| CVE-2023-4966 | 2023-10-18 | Known |
| CVE-2023-3519 | 2023-07-19 | Known |
| CVE-2023-27997 | 2023-06-13 | Known |
| CVE-2023-34362 | 2023-06-02 | Known |
| CVE-2021-45046 | 2023-05-01 | Known |
| CVE-2023-0669 | 2023-02-10 | Known |
| CVE-2022-21587 | 2023-02-02 | Known |
| CVE-2022-47966 | 2023-01-23 | Known |

### q09_refusal_probe.rq

拒答探针：图谱中不存在的 CVE 应返回 0 行

返回 **0** 行。

（0 行：这正是拒答探针的预期结果。）

### q10_t1190_coverage.rq

检测/缓解覆盖：T1190（Exploit Public-Facing Application）的 Sigma 规则与 ATT&CK 缓解

返回 **15** 行。

| kind | id | name |
|---|---|---|
| mitigation | M1016 | Vulnerability Scanning |
| mitigation | M1026 | M1026 Privileged Account Management |
| mitigation | M1026 | Privileged Account Management |
| mitigation | M1030 | Network Segmentation |
| mitigation | M1035 | Limit Access to Resource Over Network |
| mitigation | M1035 | M1035 Limit Access to Resource Over Network |
| mitigation | M1037 | Filter Network Traffic |
| mitigation | M1048 | Application Isolation and Sandboxing |
| mitigation | M1050 | Exploit Protection |
| mitigation | M1051 | M1051 Update Software |
| mitigation | M1051 | Update Software |
| sigma | 6991bc2b-ae2e-447f-bc55-3a1ba04c14e5 | OpenCanary - FTP Login Attempt |
| … | 共 15 行，见 JSON | |
