# ReverseHelper Public CTF Benchmark v0.3

## Phase 4 performance protocol

The runner accepts `--deep`; Quick and Deep use the same evaluator and frozen ground truth. Phase 4 records five complete Quick runs and one Deep run in separate result directories, preserving every per-challenge result and environment snapshot. Pending slots remain excluded. Analyzer time is never reported as human TTCF; the separate [TTCF protocol](ttcf_protocol.md) and empty CSV template require real participant observations.

Final Phase 4 Quick median-of-medians is 285.11 ms with P90 range 1378.31–1506.12 ms. Deep median/P90/max is 302.29/6090.92/9754.87 ms. Deep leaves Top-1/3/5 unchanged at 56.67/60/60%, increases function-start recall from 83.64% to 85.45%, and adds one Validation FP (8/4/14 versus Quick 8/3/14). See the [Phase 4 report](../docs/phase4-competition-grade-integration.md).

## Phase 3A algorithm scoring

Ground truth may now contain `algorithm_ground_truth`, but only when an official solution, trusted writeup or manual confirmation establishes both the algorithm and its location. Missing algorithm labels are unadjudicated, not negatives. The runner reports TP/FP/FN, absolute per-algorithm counts and on-slice precision. The first scored sample is `xorkey-crackme`: 2 TP / 0 FP / 0 FN overall (XOR 1/0/0, CRC32 1/0/0) and 1/1 on-slice precision. This denominator is intentionally reported as too small for broad accuracy claims.

## Phase 3B control-flow scoring

`control_flow_ground_truth` requires an official/trusted writeup or manual CFG confirmation with a structure and function location. Explicit negative annotations, when available, use `control_flow_negative_ground_truth`; predictions outside adjudicated positive/negative locations are unadjudicated rather than false positives. The runner reports TP/FP/FN, per-kind absolute counts, on-slice precision, dispatcher localization and state-variable exact/same-base/wrong/unknown counts.

The first scored record is Flare-On 2016 challenge 5, whose official solution identifies RVA `0x1540` as its VM function-table dispatcher and global RVA `0xDF1E` as the program counter. Current result is 1 TP / 0 FP / 0 FN, dispatcher 1/1 exact and state 1 exact. No public on-slice control-flow prediction is currently adjudicated, so that metric remains unavailable rather than being reported as 100%.

## Phase 3C semantic scoring

`decompiler_ground_truth` compares semantic roles rather than exact suggested spelling. Explicit negative annotations can identify known-wrong roles; all other unmatched suggestions remain unadjudicated. Type hints are scored as EXACT, COMPATIBLE, WRONG or UNKNOWN.

Two source-backed samples currently provide three role labels: xorkey's validation function and smokestack's dispatcher function/program-counter global. Results are 3 TP / 0 FP / 0 FN for roles, 2 TP / 0 FP for function rename roles, and one EXACT type with no wrong type. These small denominators are reported explicitly and are not a claim of general decompiler accuracy.

这个基准衡量默认 Quick 分析能否把人工确认的关键函数排到前列。它不执行样本，不保存 Flag，也不把分析器耗时冒充人工 TTCF。

## 当前数据集

`manifest.json` 定义 40 个固定槽位，Tier A/B/C 分别为 15/10/15。当前 31 个公开样本已取得并冻结，9 个 `pending-user-sample` 槽位尚未取得；pending 不进入任何得分或性能分母。

可用样本分布：

- 20 个 Flare-On 2015–2018、7 个 Reverse_Engineering_CTFs、2 个作者公开 challenge、2 个 REplay 关卡；
- 26 个 x86、5 个 x86-64；25 个 PE32、5 个 PE32+、1 个故意损坏 DOS signature 的 PE-like parser 负例；
- 8 个 Tier A、10 个 Tier B、13 个 Tier C；
- 6 个标注 packed、6 个标注 obfuscated 或 packed+obfuscated；
- 27 条 `SINGLE_REVIEW`、4 条 `OFFICIAL_WP_CONFIRMED`，没有双人复核标签。

每条记录明确保存 challenge、source、event、year、tier、format、architecture、compiler、packed、obfuscated、ground_truth_source、review_status、SHA-256、ground-truth 路径和 availability。Ground truth 建立时不查看 ReverseHelper 排名。

公开来源：

- [Flare-On archive](https://www.flare-on.com/)
- [Reverse_Engineering_CTFs](https://github.com/InfectedCapstone/Reverse_Engineering_CTFs)
- [ReverseEngineering-challenge-1](https://github.com/AvivShabtay/ReverseEngineering-challenge-1)
- [xorkey-crackme](https://github.com/Alon-Alush/xorkey-crackme)
- [REplay](https://github.com/SkyPenguinLabs/REplay) 与 [REplay writeups](https://github.com/SkyPenguinLabs/REplay-Writeups)

## 目录

```text
benchmarks/
├── README.md
├── manifest.json
├── ground_truth/
├── results/
│   ├── p0-before-phase2/
│   ├── phase2-after/
│   ├── phase25-a-diversity/
│   ├── phase25-b-function-boundary/
│   ├── phase25-c-validation-decision-final/
│   ├── phase25-d-dataflow/
│   ├── phase25-e-packed/
│   ├── phase25-final-v5/
│   ├── phase26-baseline/
│   ├── phase26-value-identity/
│   ├── phase26-alias/
│   ├── phase26-indirect/
│   ├── phase26-function-chunk/
│   ├── phase26-partial-flow/
│   └── phase26-final/
├── analysis/
│   ├── slice_failures.json
│   └── phase26_stage_comparison.json
└── run_benchmark.py
```

二进制位于本地忽略目录 `benchmarks/samples/`，不会提交到仓库。Runner 在分析前逐个验证文件大小与 SHA-256，只把路径交给静态 `ReverseHelperAnalyzer.analyze()`，并对单题错误做隔离。

## 可复现运行

```powershell
python benchmarks\run_benchmark.py --output benchmarks\results\phase26-final
```

只跑一个样本：

```powershell
python benchmarks\run_benchmark.py --id flareon2017-02 --output benchmarks\results\one
```

缺少样本、哈希不符或 parser 错误会写入单题记录，其他题继续运行。`summary.json` 保存工具版本、源码快照哈希、Python/系统信息、配置、manifest coverage、总计和按 Tier 聚合指标。

## Phase 2.6 结果

Final 的 31 个可用样本中，30 个完成分析，1 个故意损坏 DOS signature 的 parser 负例产生预期隔离错误。排名指标的分母为 30。所有样本只做哈希校验和静态读取，从未执行。

| 指标 | Phase 2.6 Final |
|---|---:|
| Top-1 / Top-3 / Top-5 | 46.67% / 56.67% / 56.67% |
| START HERE coverage hit rate | 36.67%（11/30） |
| START HERE emitted precision | 84.62%（11/13） |
| Validation P/R/F1 | 57.14% / 18.18% / 27.59%（4 TP / 3 FP / 18 FN） |
| Complete Slice P/R | 100% / 9.09%（2 TP / 0 FP / 20 FN） |
| Actionable Slice P/R | 100% / 13.64%（3 TP / 0 FP / 19 FN） |
| Static-visible Complete / Actionable recall | 9.52% / 14.29% |
| Function Boundary start recall | 83.64%（46/55） |
| Packed visibility accuracy / recall | 86.67% / 33.33% |
| Median / P90 / max Quick | 212.70 / 1145.96 / 2080.94 ms |

`static_visibility` 分布为 FULLY_VISIBLE 20、PARTIALLY_VISIBLE 4、PACKED_OR_TRANSFORMED 6、UNKNOWN 1。Packed Accuracy 统计 TP/TN/FP/FN=2/24/0/4；packed 样本无法看到验证代码时按正确降级处理，但当前 packed 检出 recall 仍低。

逐阶段结果：

| 阶段 | Top-1 | Top-3/5 | START hit / emitted precision | Validation P/R | Complete / Actionable Slice recall | Static-visible Complete / Actionable | Median / P90 ms |
|---|---:|---:|---:|---:|---:|---:|---:|
| Baseline | 46.67% | 53.33% | 36.67% / 91.67% | 57.14% / 18.18% | 4.55% / 4.55% | 4.76% / 4.76% | 203.47 / 1252.11 |
| Value Identity | 46.67% | 53.33% | 36.67% / 91.67% | 57.14% / 18.18% | 9.09% / 9.09% | 9.52% / 9.52% | 162.44 / 1144.18 |
| Alias | 46.67% | 53.33% | 36.67% / 91.67% | 57.14% / 18.18% | 9.09% / 9.09% | 9.52% / 9.52% | 190.69 / 1266.56 |
| Indirect / wrapper | 46.67% | 53.33% | 36.67% / 91.67% | 57.14% / 18.18% | 9.09% / 9.09% | 9.52% / 9.52% | 226.81 / 1186.92 |
| Function chunk | 46.67% | 56.67% | 36.67% / 91.67% | 57.14% / 18.18% | 9.09% / 9.09% | 9.52% / 9.52% | 194.45 / 1159.99 |
| Partial / Flow Break | 46.67% | 56.67% | 36.67% / 84.62% | 57.14% / 18.18% | 9.09% / 13.64% | 9.52% / 14.29% | 167.88 / 1322.31 |
| Final | 46.67% | 56.67% | 36.67% / 84.62% | 57.14% / 18.18% | 9.09% / 13.64% | 9.52% / 14.29% | 212.70 / 1145.96 |

Value Identity 阶段新增的完整 Slice 命中来自 Phase 2.6 基线前加入的 `xorkey-crackme`；它不是原 20 个 Slice FN 中的修复。原始 FN 中真正新增的命中只有 `flareon2017-03` 的 checksum RVA `0x11E6`，由 CODE-but-non-executable `.text` 恢复、`recv` 输入、寄存器变换链和合法 StaticFlowBreak 共同形成 Actionable Partial。该题 `0x1000` 仍未命中。Function chunk 阶段使该题三个已裁决函数起点可见并把关键函数提升到 Top-3，但不能单独证明 chunk 语义修复了 Slice。

按 Tier：

| Tier | 完成/可用 | Top-1 | Top-3/5 | START | Validation P/R | Complete / Actionable Slice | Quick median/p90/max ms |
|---|---:|---:|---:|---:|---:|---:|---:|
| A | 7/8 | 85.71% | 85.71% | 71.43% | 100% / 40% | 40% / 40% | 145.76 / 252.58 / 726.51 |
| B | 10/10 | 50% | 70% | 20% | 100% / 14.29% | 0% / 7.14% | 386.43 / 1145.96 / 2080.94 |
| C | 13/13 | 23.08% | 30.77% | 30.77% | 0% / 0% | 0% / 0% | 495.11 / 1130.25 / 1940.62 |

阶段计时有正常运行波动，不能把单次下降解释为确定的性能优化。Final 仍在普通 CTF 低秒级预算内；最大成本来自重复的有界函数内传播、跨函数 fixed point、ValueIdentity/alias 状态和间接目标回溯。完整设计、原始 20 个 FN 分类与 Phase 3 gate 结论见 [Phase 2.6 报告](../docs/phase2.6-static-flow-recovery.md)。

## Phase 2.7A Static Slice Failure Audit

Phase 2.7A 没有修改生产规则或基准参数。它以 validation sink 为单位重审 Phase 2.6 Final 的 19 个 unresolved actionable Slice FN；共涉及 14 道题，已命中的 `flareon2017-03:0x11E6` 不进入分母。

| 审计指标 | 结果 |
|---|---:|
| Fully / Partially / Packed-or-transformed | 15 / 3 / 1 |
| 现实可修复 static-visible FN | 15 / 19 |
| Low-repairability static-visible | 3 / 19 |
| Packed / OUT_OF_SCOPE | 1 / 19 |
| 同时属于 Validation FN | 17 / 19 |
| START HERE 仍落在真实关键区域 | 7 / 19 |
| StaticFlowBreak Exact / Near / Wrong / None | 0 / 1 / 1 / 17 |
| 仅被 publication threshold 阻塞 | 0 / 19 |

Primary failure frequency：`INPUT_SOURCE_MISSED` 9、`STATIC_LINKED_COMPARE` 3、`FUNCTION_BOUNDARY` 2、`OPTIMIZED_COMPARE` 2、`STATIC_NOT_VISIBLE` 1、`GLOBAL_FLOW` 1、`INPUT_WRAPPER_MISSED` 1。按现实可修复集合计算，前三类覆盖 14/15（93.33%）。

重要纠正：`flareon2018-10` 的四个 checker 边界和 direct-call relationship 均已正确恢复；ReverseHelper 只在四次 checker 调用之后的 `0x1E15` 识别出 `argv[1]`。因此四个 first broken edge 都是 early input source 漏识别，而不是旧分类中的 `FUNCTION_CHUNK`。`replay-level-01` 也先缺真实 GUI input wrapper，`INDIRECT_CALL` 只是 secondary。

逐题 first broken edge、Failure Funnel、Compare→Decision→Validation funnel、Function Boundary funnel、Flow Break 人工准确性、Priority Matrix 和 Phase 2.7B 三项建议见 [Phase 2.7A 报告](../docs/phase2.7a-slice-failure-audit.md)；机器可读记录见 [`analysis/phase27_slice_failure_audit.json`](analysis/phase27_slice_failure_audit.json)。Phase 3 继续冻结；本轮没有开始任何 failure 修复。

## Phase 2.5 结果（保留基线）

Final 的 30 个可用样本中，29 个完成分析，1 个故意损坏 DOS signature 的 parser 负例产生预期隔离错误。排名指标的分母为 29。

| 指标 | Final |
|---|---:|
| Top-1 Critical Function | 44.83% |
| Top-3 Critical Function | 51.72% |
| Top-5 Critical Function | 51.72% |
| START HERE coverage hit rate | 34.48%（10/29） |
| START HERE emitted precision | 90.91%（10/11） |
| Validation precision | 50.00%（3 TP / 3 FP） |
| Validation recall | 14.29%（3 TP / 18 FN） |
| Validation F1 | 22.22% |
| Interesting String adjudicated precision | 100%（已知 noise promotion 为 0） |
| Interesting String relevant recall | 60%（15/25） |
| Function Boundary start recall | 77.78%（42/54） |
| Static Slice precision / recall | 100% / 4.76%（1 TP / 0 FP / 20 FN） |
| Packed visibility recall | 33.33%（2/6） |
| Median / P90 / max Quick | 172.32 / 1150.29 / 1973.61 ms |

字符串 precision 只对人工列出的 relevant/noise 项裁决；414 个未裁决提升项不被自动算成正确或误报。Function Boundary 目前只测 start recall，因为多数 ground truth 没有可信的函数结尾。边界置信度分布为 CONFIRMED 1581、LIKELY 2340、HEURISTIC 577。Static Slice 的状态分布为 Confirmed 0、Likely 1、Partial 0、Unresolved 142；100% precision 只有一个 Likely TP，不能视为成熟能力。没有真人 TTCF 实验，因此 TTCF 与 TTCF reduction 仍未测量。

阶段对比：

| 阶段 | Top-1 | Top-3 | Top-5 | START | Validation P/R | Median / P90 |
|---|---:|---:|---:|---:|---:|---:|
| A Diversity baseline | 24.14% | 31.03% | 34.48% | 20.69% | 2.60% / 9.52% | 129.59 / 1021.82 ms |
| B Function Boundary 2.0 | 24.14% | 31.03% | 34.48% | 20.69% | 2.60% / 9.52% | 163.35 / 1057.18 ms |
| C Validation/Decision | 31.03% | 37.93% | 37.93% | 27.59% | 50.00% / 14.29% | 171.57 / 1101.98 ms |
| D Data Flow | 31.03% | 37.93% | 37.93% | 27.59% | 50.00% / 14.29% | 145.67 / 1047.08 ms |
| E Packed | 31.03% | 37.93% | 37.93% | 34.48% | 50.00% / 14.29% | 157.94 / 1072.74 ms |
| Final Ranking 2.2 + safe start | 44.83% | 51.72% | 51.72% | 34.48% | 50.00% / 14.29% | 172.32 / 1150.29 ms |

按当前可用样本分层：

| Tier | 完成/可用 | Top-1 | Top-3/5 | START | Validation P/R | Slice recall | Boundary recall | Quick median/p90/max ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| A | 6/7 | 83.33% | 83.33% | 66.67% | 100% / 25% | 25% | 100% | 142.00 / 172.32 / 727.41 |
| B | 10/10 | 50.00% | 60.00% | 20.00% | 100% / 14.29% | 0% | 78.26% | 398.25 / 1098.91 / 1742.90 |
| C | 13/13 | 23.08% | 30.77% | 30.77% | 0% / 0% | 0% | 68.18% | 461.84 / 1150.29 / 1973.61 |

Final 相对 A 的 Top-1/3/5 和 START HERE 覆盖命中率分别增加 20.69、20.69、17.24、13.79 个百分点。START HERE 变得更严格：只有置信度与分差足够时才单选，其余输出 START WITH THESE，所以覆盖率下降但已输出项 precision 达到 90.91%。主要收益来自把 comparison observation 与 actionable Validation 分开、运行库降噪、输入流/Static Slice 优先、packed entry strategy 和 Ranking 2.2 的证据上限。Function Boundary 2.0 增加了边界质量与可解释性，但在当前已标注 start 集合上没有单独提高阶段 B 的 aggregate ranking。

## 指标口径

- Top-1/3/5：有序、按函数去重的候选与 `critical_functions` 相交；数据地址不算函数命中。
- START HERE coverage hit rate：在全部可排名样本中，单一 start 是否被输出且命中；emitted precision 只在实际输出单一 start 的样本中计算。低置信度或分数接近时输出 START WITH THESE。
- Validation：只统计 `context_only=false` 的 actionable function prediction，并与冻结正例按函数去重；没有臆造 TN。
- Interesting Strings：关键字符串是否进入 HIGH/MEDIUM；人工列出的无关字符串提升单独计数，其他提升为 unadjudicated。
- Function Boundary：人工标注函数起点是否被 FunctionIndex 恢复；不把未知结尾算作正确。
- Static Slice：source-to-validation sink 是否命中人工确认的 validation function。
- Packed visibility：标注 packed 样本是否被静态 packed strategy 识别。
- Performance：记录 Quick 分析耗时、runner wall time、文件大小和指令数；P90 使用 runner 固定实现。

失败题按 `NO_STRING_SIGNAL`、`FUNCTION_BOUNDARY_FAILURE`、`INDIRECT_CALL`、`INPUT_FLOW_MISSING`、`OPTIMIZED_COMPARE`、`STATIC_LINK_NOISE`、`CRT_NOISE`、`PACKED`、`OBFUSCATED`、`RANKING_WEIGHT_ERROR`、`PARSER_FAILURE` 或 `OTHER` 分类。Final Top-5 失败以 packed 为主；3 个 Validation FP 全部出现在 Tier C。

## Ground Truth 维护规则

1. 先依据公开题解与独立静态分析确认地址，再冻结 ground truth，之后才运行 ReverseHelper。
2. 地址不确定时保留限制说明，不用 ReverseHelper 输出反推答案。
3. 每条记录必须写 review_status；单人复核、作者/官方题解确认和双人复核不能混写。
4. 调权只看 development split；evaluation split 保持冻结并报告 before/after。
5. 样本、标注、规则或预算改变时创建新的结果目录，不能覆盖旧基线。
6. 新增来源必须公开且允许研究/学习；无法取得时登记 pending，不伪造样本或结果。
7. 二进制永不进入仓库，分析期间永不执行。

完整实现审计、Ranking 2.2 权重和失败说明见 [Phase 2.5 报告](../docs/phase2.5-hardening.md)。

## Phase 2.7B Targeted Static Slice Recovery

Phase 2.7B 只加入审计选出的 argv/DLL export InputSource、static-linked comparator/thunk 和两种 entry/body 关系。最终完整基准保存在 `results/phase27b-final-regression-v10`。

| 指标 | Phase 2.6 Final | Phase 2.7B Final |
|---|---:|---:|
| Top-1 / Top-3 / Top-5 | 46.67% / 56.67% / 56.67% | 53.33% / 60.00% / 60.00% |
| START coverage / precision | 36.67% / 84.62% | 43.33% / 100.00% |
| Validation P/R/F1 | 57.14% / 18.18% / 27.59% | 57.14% / 18.18% / 27.59% |
| Actionable Slice TP/FP/FN | 3 / 0 / 19 | 4 / 0 / 18 |
| Complete Slice TP/FP/FN | 2 / 0 / 20 | 2 / 0 / 20 |
| Static-visible actionable recall | 14.29% | 19.05% |
| Quick median / P90 / max | 212.70 / 1145.96 / 2080.94 ms | 306.81 / 1517.66 / 2321.60 ms |

15 个现实可修复 static-visible FN 中实际闭合 1 个：`flareon2015-02:0x1084`。新增 argv/export 与 CompareSite 中间证据没有在证据不足时直接提升为 Validation。完整设计、阶段指标、15 项清单与 Phase 3 gate 见 [Phase 2.7B 报告](../docs/phase2.7b-targeted-static-slice-recovery.md)。Phase 3 继续冻结。

最终等价代码多次运行的 median/P90 范围为 200.70–306.81 / 1211.28–1517.66 ms；另有一次可单题复现排除的 437 秒系统异常。最新运行如表所示，因此 Quick 保护线结论为不确定，不宣称性能改善。

## Phase 2.8 Final Static Flow Recovery

Phase 2.8 baseline 保存于 `results/phase28-baseline`，集成检查保存于 `results/phase28-integrated-candidate`，五次同源码哈希的等价最终运行保存于 `results/phase28-final-v2-run1` 至 `phase28-final-v2-run5`。Ground truth、预算与分母未改变。

| 指标 | Phase 2.7B | Phase 2.8 Final |
|---|---:|---:|
| Top-1 / Top-3 / Top-5 | 53.33 / 60.00 / 60.00% | 56.67 / 60.00 / 60.00% |
| START coverage / precision | 43.33 / 100.00% | 46.67 / 100.00% |
| Validation TP/FP/FN | 4 / 3 / 18 | 8 / 3 / 14 |
| Validation precision / recall | 57.14 / 18.18% | 72.73 / 36.36% |
| Complete Slice TP/FP/FN | 2 / 0 / 20 | 6 / 0 / 16 |
| Actionable Slice TP/FP/FN | 4 / 0 / 18 | 8 / 0 / 14 |
| Static-visible actionable recall | 19.05% | 38.10% |

真实收益归因：Parameter provenance 0 FN、普通 Return provenance 0 FN、In-place/output 0 FN、Golf return-semantics 4 FN。新增 Validation/Slice FP 均为 0。五次 Quick median 为 187.72、191.58、192.55、188.95、195.14 ms；median-of-medians 191.58 ms，P90 范围 1162.69–1184.53 ms。

完整根因、14 项审计、测试和最终 Gate 见 [Phase 2.8 报告](../docs/phase2.8-final-static-flow-recovery.md)。**Phase 2.x CLOSED**；下一轮允许进入 Phase 3，但本轮未启动 Phase 3，也不创建 Phase 2.9。
