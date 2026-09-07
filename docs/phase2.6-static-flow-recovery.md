# Phase 2.6 Development Report

日期：2026-09-05  
范围：Static Flow Recovery；没有进入 Phase 3、Deep Mode、完整 SSA、Algorithm Recognition 扩展、Decompiler、Solver、ELF、动态调试、AI 或 TraceInfer。所有公开样本均先校验 SHA-256，再交给静态分析器读取；没有执行样本。

## 1–8. Benchmark、review 与 Slice Failure Taxonomy

当前 manifest 有 40 个固定槽位，31 个可用、9 个 pending。Tier A/B/C 可用数量为 8/10/13；正常完成分析 7/10/13，Tier A 中另有 1 个故意损坏 DOS signature 的 parser 负例，它按预期隔离失败。Ground Truth review 状态为 27 `SINGLE_REVIEW`、4 `OFFICIAL_WP_CONFIRMED`、0 `DOUBLE_REVIEW`。这仍是单维护者数据集，不能把标签数量解释为独立多人复核。

`static_visibility` 分布：

| 可见性 | 数量 |
|---|---:|
| FULLY_VISIBLE | 20 |
| PARTIALLY_VISIBLE | 4 |
| PACKED_OR_TRANSFORMED | 6 |
| UNKNOWN | 1（parser 负例） |

在任何 Phase 2.6 production 改动前，对 Phase 2.5 的 1 TP / 0 FP / 20 FN 逐条复核，并冻结在 `benchmarks/analysis/slice_failures.json`。原始 20 个 FN 的主失败分类为：

| Failure | 数量 |
|---|---:|
| INPUT_SOURCE_NOT_FOUND | 5 |
| FUNCTION_CHUNK | 4 |
| STATIC_LINKED_COMPARE | 3 |
| OPTIMIZED_COMPARE | 2 |
| INDIRECT_INPUT_CALL | 2 |
| FUNCTION_BOUNDARY | 1 |
| GLOBAL_FLOW | 1 |
| INDIRECT_CALL | 1 |
| PACKED_NOT_STATIC_VISIBLE | 1 |

本轮按频率选择 INPUT_SOURCE_NOT_FOUND、FUNCTION_CHUNK、STATIC_LINKED_COMPARE、OPTIMIZED_COMPARE、INDIRECT_INPUT_CALL，并围绕其共同底层缺口实施 Value Identity/Alias、唯一间接目标、wrapper、function chunks、global/return provenance 和 Partial Flow。结果显示底层能力成立，但 static-linked/optimized comparator 与多数真实输入源仍没有被恢复；不能因为测试机制通过就把对应 FN 宣称已修复。

## 9–17. Static Flow 设计

### Value Identity 与 Alias

`ValueIdentity` 保存：

```text
id / origin / base_object / offset / index / scale
confidence / provenance / alias_confidence
version / merged_origins
```

同一输入对象经过寄存器复制、stack spill/restore、直接参数、global store/load 和派生返回值时保留稳定 `id` 与 `origin`。`EXACT_ALIAS` 表示同一对象与精确位置，`BASE_ALIAS` 表示同一 base object 的常量偏移或符号索引，`POSSIBLE_ALIAS` 只用于保守 merge。明显覆盖会 kill 旧 identity；不把不相关来源合并为确定别名。路径 merge 记录双方 origin 并降为 POSSIBLE。

这是有界、路径不敏感的局部模型。它不区分所有 scalar arithmetic 与 pointer arithmetic，也不做 heap points-to、通用 alias set 求解或 Memory SSA。当前预算为 max values 256、aliases 1024、versions 64、flow states 512；超限写入 `BUDGET_LIMIT` 并允许生成 Partial/Flow Break。

### Object Versioning 与 Transform

原地 XOR/ADD/SUB/ROL/ROR、byte swap 和已支持的 table lookup 保留 base object，并推进轻量版本：`Input#id:v0 → v1`。COPY/IDENTITY 不推进版本；派生 offset 记录 `DERIVED_BUFFER` 语义；未知但 source-reachable 的变换保留 provenance 并降低 confidence。它表达“仍来自同一输入、状态已经改变”，不声称恢复算法。

CompareSite 的 flow 记录每个 tainted operand 的完整 `value_identity`。静态只读 target 的通用角色推断仍不完整，因此 comparator A/B/length 的角色在复杂调用中仍可能未知。

### Function Chunk

`Function` 增加 `chunks`、`primary_range` 和 `secondary_chunks`。FunctionIndex 从同一 bounded CFG membership 中标注 PRIMARY、TAIL、COLD、SHARED_EPILOGUE；共享尾部保留歧义，不强行独占。数据流按逻辑函数的记录集合传播，可跨 jump-connected secondary chunk。

本轮还修正一个可见性边界：PE section 带 CODE 但缺 EXECUTE 时，仅当节名为 `.text` 或包含入口点才保守反汇编，并输出 `NonExecutableCodeSection` warning。它使 `flareon2017-03` 从 0 条指令恢复到 409 条指令及 3/3 个已裁决函数起点。这个收益来自透明的 section 可见性规则，不能全部归功于 chunk 推断。

### Indirect-but-resolvable Call

只解析唯一、静态、低歧义目标：IAT slot load → register/copy/一次 spill → call、单一常量函数指针，以及 FunctionIndex 已能确认的简单 thunk。遇到控制流分叉、覆盖、多个候选或预算停止时输出 unresolved，不猜 target。常量 vtable slot 的一般形式尚未覆盖。

专项 fixture 证明 IAT register chain 和唯一函数指针可传播，也证明有分支的双赋值函数指针保持 unresolved。该阶段没有新增公开题 Slice TP，因此没有据此增加 Ranking 权重。

### Input Wrapper、Global Flow 与 Return Identity

简单 wrapper 只有在已知 input API 明确写入 wrapper 参数，且直接 caller 的对应参数可恢复时，才将 side effect 映射回 caller。wrapper 使用本地 buffer 或复杂函数里偶然调用 input API，不会泛化为 caller input。无 import 名称的 static-linked wrapper 目前只保留低置信候选边界，没有足够真实证据发布通用推断。

Global flow 保留 `GlobalObject` identity、常量 offset 和符号 index。消费者范围限定为当前 source trace、其 sibling helper 和已在 trace 上函数的直接 callee，避免扫描全程序后把任意 global read 接到 input。Return flow 把 source-reachable callee return 映射回精确 callsite；`input + constant offset` 的 derived pointer 保留 origin、offset 与 version。

### Partial Slice 与 StaticFlowBreak

`StaticFlowBreak` 不是动态断点。它描述静态 provenance 在哪里失去可靠追踪，并包含 input source、真实 edge 子链、最后确认节点、break RVA/function、下一未解析 target、原因、confidence 和 evidence。

发布条件没有放宽为“存在 input + validation”。普通 alias 中断至少需要 3 条真实边且含 transform；unresolved indirect 或预算中断也必须先有 source-reachable 子链。Quick Summary 显示：

```text
FLOW BREAK
Input flow is confirmed through FUN_A.
Provenance becomes unresolved before FUN_B.

START HERE
FUN_A
Reason: inspect the last confirmed write/return and FUN_B arguments.
```

完整 Slice 的 confidence 使用关键边中最弱 confidence；Partial 不会因为边数多而升级成 Confirmed。若已有可靠完整 Slice，原 START HERE 策略保持优先；只有无决定性 start 且 Flow Break 有明确 next target 和足够真实边时，才从 break point 开始。

## 18–19. Packed 行为与 Ranking 决策

`PACKED_OR_TRANSFORMED` 不要求在未脱壳表面恢复 Slice。Quick 会报告静态可靠性下降和 unpacking 前不可见原因，而不是构造 input-to-validation 路径。本轮 Packed Visibility TP/TN/FP/FN 为 2/24/0/4，accuracy 86.67%、packed recall 33.33%。Accuracy 较高主要来自 24 个非 packed TN，不能掩盖 4 个 packed FN。

Ranking 保持 2.2，没有发布 2.3。Value Identity 的新增完整命中来自基线前加入的单一新题；Indirect/Alias 没有新增真实 TP；Function chunk 的 Top-3 提升来自恢复原本完全不可见的 `.text`；Partial 只修复一个原始 sink，同时 Flow Break START 使 emitted precision 从 91.67% 降为 84.62%。这些证据不足以校准 confirmed/likely slice 或 flow-break 权重，继续调权会掩盖候选识别缺口。

## 20–23. 文件与测试

Phase 2.6 主要修改文件：

- `reversehelper/dataflow_model.py`
- `reversehelper/intra_dataflow.py`
- `reversehelper/interproc_dataflow.py`
- `reversehelper/function_index.py`
- `reversehelper/instruction_context.py`
- `reversehelper/input_sources.py`
- `reversehelper/findings.py`
- `reversehelper/static_slice.py`
- `reversehelper/quick_analysis.py`
- `reversehelper/challenge_summary.py`
- `benchmarks/manifest.json`
- `benchmarks/run_benchmark.py`
- `README.md`、`CHANGELOG.md`、`docs/roadmap.md`、`benchmarks/README.md`

新增文件：

- `reversehelper/value_identity.py`
- `reversehelper/indirect_resolver.py`
- `benchmarks/analyze_slice_failures.py`
- `benchmarks/annotate_phase26_metadata.py`
- `benchmarks/analysis/slice_diagnostics.json`
- `benchmarks/analysis/slice_failures.json`
- `benchmarks/analysis/phase26_stage_comparison.json`
- `benchmarks/ground_truth/xorkey-crackme.json`
- `tests/test_static_flow_recovery_v26.py`
- `tests/fixtures/phase26_optimized_flow.c`
- `tests/test_compiled_optimized_fixtures_v26.py`
- 本报告及各 `benchmarks/results/phase26-*` 冻结结果

测试覆盖 register spill/restore、identity chain、base+offset、symbolic index、kill、merge、function chunk、shared epilogue、IAT indirect、唯一/歧义函数指针、wrapper/false positive、global version、in-place version、derived return、合法 flow break 和 packed visibility。自有 C fixture 使用 MinGW GCC 分别以 `-O1`、`-O2` 真实编译成临时 PE 后仅做静态分析；生成文件不会执行，也不会提交。最终为 **256 passed，源码覆盖率 87%**。

## 24–32. Baseline → Stages → Final

| 阶段 | Top-1 | Top-3/5 | START hit | START precision | Validation P/R | Complete Slice | Actionable Slice | Static-visible Complete/Actionable | Median/P90/max ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Baseline | 46.67% | 53.33% | 36.67% | 91.67% | 57.14% / 18.18% | 4.55% | 4.55% | 4.76% / 4.76% | 203.47 / 1252.11 / 2200.98 |
| Value Identity | 46.67% | 53.33% | 36.67% | 91.67% | 57.14% / 18.18% | 9.09% | 9.09% | 9.52% / 9.52% | 162.44 / 1144.18 / 1844.41 |
| Alias | 46.67% | 53.33% | 36.67% | 91.67% | 57.14% / 18.18% | 9.09% | 9.09% | 9.52% / 9.52% | 190.69 / 1266.56 / 2106.83 |
| Indirect / wrapper | 46.67% | 53.33% | 36.67% | 91.67% | 57.14% / 18.18% | 9.09% | 9.09% | 9.52% / 9.52% | 226.81 / 1186.92 / 2237.66 |
| Function chunk | 46.67% | 56.67% | 36.67% | 91.67% | 57.14% / 18.18% | 9.09% | 9.09% | 9.52% / 9.52% | 194.45 / 1159.99 / 1902.92 |
| Partial / Flow Break | 46.67% | 56.67% | 36.67% | 84.62% | 57.14% / 18.18% | 9.09% | 13.64% | 9.52% / 14.29% | 167.88 / 1322.31 / 1893.29 |
| Final | **46.67%** | **56.67%** | **36.67%** | **84.62%** | **57.14% / 18.18%** | **9.09%** | **13.64%** | **9.52% / 14.29%** | **212.70 / 1145.96 / 2080.94** |

Final Validation 为 4 TP / 3 FP / 18 FN，F1 27.59%。Complete Slice 为 2 TP / 0 FP / 20 FN；Actionable 为 3 TP / 0 FP / 19 FN。Slice 状态输出为 Confirmed 1、Likely 2、Partial Flow Break 3、Unresolved 142。3 个 Partial 中只有 1 个 next target 命中裁决 sink，另外 2 个是无可评分 target 的 unresolved indirect break，因此 Slice FP 仍为 0。

Tier A/B/C 的 median Quick 分别为 145.76/386.43/495.11 ms，P90 为 252.58/1145.96/1130.25 ms，max 为 726.51/2080.94/1940.62 ms。单次阶段计时受缓存与系统调度影响；应看最终低秒级边界，不把阶段间的小幅下降视为确定优化。

## 33–39. 真正修复、误差与 Phase 3 Gate

原始 20 个 Slice FN 中，真正修复 **1 个**：`flareon2017-03` checksum function RVA `0x11E6`。恢复链是 `recv → stack/register → XOR/ADD → store → alias break → direct checksum call`，作为 Actionable Partial 命中。该题另一个 sink `0x1000` 仍 unresolved。Value Identity 阶段新增的完整 TP 是 Phase 2.6 baseline 前才加入的 `xorkey-crackme`，不能计作原 20 FN 修复；它同时验证了新模型在公开作者源码题上的真实作用。已有 `flareon2017-02` Slice 从 Likely 升为 Confirmed，但它本来就是 TP。

剩余 19 个原始 FN：INPUT_SOURCE_NOT_FOUND 5、FUNCTION_CHUNK 4、STATIC_LINKED_COMPARE 3、OPTIMIZED_COMPARE 2，以及 FUNCTION_BOUNDARY、PACKED_NOT_STATIC_VISIBLE、INDIRECT_INPUT_CALL、GLOBAL_FLOW、INDIRECT_CALL 各 1。尤其 `flareon2018-10` 的四个 checker chunk、静态链接 comparator、export/argv/date 输入和大型 REplay 间接路径仍没有形成可评分 Slice。

主要性能成本是每个输入源的有界重复函数内分析、跨函数 fixed-point、ValueIdentity/alias/version 状态、间接 call backward scan 和 flow-break 子链整理。预算和 visited/cache 限制防止状态爆炸；Final max 2.081 秒，仍符合 Quick 的低秒级目标。

主要误报：3 个 actionable Validation FP 全在 Tier C；字符串仍有 1 个已知 noise promotion 与 423 个未裁决提升项；13 个 START HERE 中有 2 个未命中，其中 `flareon2017-03` 的 `FUN_401008` 是有真实 flow break 的有用位置，但不在冻结 exact critical-function starts 中。Flow Break 能提高可操作性，也降低了 emitted precision。

主要漏报：静态链接/custom comparator、优化后的 argv/export/date 输入、复杂 global/heap alias、跨多层 wrapper、控制流相关多目标函数指针、vtable、复杂 return/decision、packed 后代码和大型程序预算边界。Packed 分类自身仍漏 4/6；Tier C Top-5 30.77%、Validation P/R 0%/0%。

**不建议进入 Phase 3。** Tier A Top-5 为 85.71%，Validation precision 保持 57.14%，Quick 仍低秒级，但 Static-visible Actionable Slice recall 只有 14.29%，整个 benchmark 只有 3 个 actionable TP，仍接近用户设定的否决区间。下一轮应继续 Phase 2.6 hardening：先补齐 9 个 pending 与独立 review，再按剩余 taxonomy 优先实现 module-boundary argv/export/date InputSource、静态链接 comparator/optimized compare 的 operand provenance、真实 direct-call global/return flow 和 `flareon2018-10` chunk/call linkage。达到多题稳定的真实 Complete/Partial Slice 后，再重新评估 Ranking 2.3 和 Phase 3。
