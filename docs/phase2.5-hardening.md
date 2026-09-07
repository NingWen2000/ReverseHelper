# Phase 2.5 — Public Benchmark Expansion + Core Hardening

日期：2026-09-04

本阶段按固定顺序完成 Benchmark Diversity、Function Boundary 2.0、Compare/Decision/Validation、有限 Data Flow Hardening、Packed Handling 和 Ranking 2.2。所有样本只做静态读取，从未执行。范围没有进入完整 CFG、完整跨函数 Data Flow、Algorithm Recognition 扩展、Solver、ELF、动态调试、AI、TraceInfer 或 Deep Mode。

## 审计结论

Phase 1.5 的 20 题 Flare-On 集合能复现，但来源单一、编译器分布窄，函数边界只有起点集合且缺乏证据质量，Validation 把很多运行库比较当成可操作候选，Phase 2 静态切片没有在公开题上连成一条。Ranking 2.1 能解释分数，但输入、比较和字符串只要在同一函数附近出现，仍可能被弱关联抬高。

因此 Phase 2.5 先扩数据，再修底层事实和候选质量，最后调整权重。没有针对单个 challenge ID 写规则。

## Benchmark v0.2

`manifest.json` 现在定义 40 个槽位，Tier A/B/C 分别为 15/10/15。当前可取得并冻结 30 个样本，另有 10 个 `pending-user-sample` 槽位；pending 不进入任何准确率、召回率或性能分母。

30 个可用样本来自四组公开来源：20 个 Flare-On、7 个 Reverse_Engineering_CTFs、1 个作者公开 challenge、2 个 REplay 关卡。架构为 25 个 x86、5 个 x86-64；24 个 PE32、5 个 PE32+，另有 1 个故意损坏 DOS 签名的 PE-like 负例。人工标签包含 6 个 packed、6 个 obfuscated 或 packed+obfuscated 样本。

每条 manifest 记录都包含 challenge、source、event、year、tier、format、architecture、compiler、packed、obfuscated、ground_truth_source 和 review_status。27 条为 `SINGLE_REVIEW`，3 条为 `OFFICIAL_WP_CONFIRMED`；没有把任何记录写成双人复核。

公开来源：

- [Flare-On archive](https://www.flare-on.com/)
- [Reverse_Engineering_CTFs](https://github.com/InfectedCapstone/Reverse_Engineering_CTFs)
- [ReverseEngineering-challenge-1](https://github.com/AvivShabtay/ReverseEngineering-challenge-1)
- [REplay](https://github.com/SkyPenguinLabs/REplay) 与 [作者题解](https://github.com/SkyPenguinLabs/REplay-Writeups)

Runner 在读取前核验 SHA-256，逐题隔离错误，输出总计与按 Tier 指标，并记录源码快照、系统、耗时、warning 和失败分类。

## 核心改进

### Function Boundary 2.0

- 优先采用 x64 exception directory 的 runtime ranges 和有范围的 COFF function symbols。
- 使用 entry、exports、direct call targets、frame prologues、post-return prologues 与 thunk leads 补充候选。
- 为每个 Function 记录半开区间结尾、来源、理由、置信度、thunk target、tail calls 和 shared tails。
- 对强 COFF preamble 内部的 frame-like bytes 保守处理，避免把同一函数拆开。
- `boundary_confidence` 正式使用 CONFIRMED/LIKELY/HEURISTIC，冲突尾部标为 ambiguous；`runtime_likelihood` 使用 USER_CODE/RUNTIME_LIKELY/THUNK/UNKNOWN。RUNTIME_LIKELY 和 THUNK 进入 Ranking 惩罚，heuristic-only 边界不能生成 HIGH Validation。

当前 benchmark 只标注了足够可信的函数起点，所以 Boundary 指标是 start recall，不是完整边界准确率。

### Compare / Decision / Validation

- Quick JSON Schema 1.5 正式拆出 `compare_sites`、`decision_sites` 和 `validation_candidates`。CompareSite 只陈述 compare type、operands、length、confidence 与 evidence，不作验证结论；DecisionSite 只在 live result 被 Jcc/setcc/cmov 或 caller branch 消费时建立。
- 识别 imported comparator、静态/内联 byte compare、byte-vs-byte loop、comparison cluster 与有限 hash context。
- 跟踪比较结果被 Jcc、setcc、cmov 消费，以及被调用者返回值在 caller 中控制分支。
- 输出 decision type、branch polarity、success/failure 分支、runtime noise、unknown fields 和 context-only。
- 只有满足上下文门槛的候选才进入 actionable Validation 指标；普通 memcmp、单 buffer 通用循环和 CRT/PE structure 比较保留为 context-only 或显著降权。

### 有限 Data Flow Hardening

- 支持 indexed stack alias、indexed absolute globals 和原地内存 transform。
- 支持 global writer 经过 controller 到 sibling checker 的有限传播，以及 wrapper side effect。
- x86 参数恢复支持常见 push arguments 和写入 `[esp+offset]` 的调用前参数准备；寄存器/栈 alias 保留 base object 与固定或 indexed offset，从而让 `buffer+1`、`buffer+4` 和 `buffer[index]` 维持同源关系。
- Static-linked byte loop 先进入 CompareSite，只有 live decision 与输入/outcome 等上下文达到门槛才升级 Validation。
- Slice 状态为 CONFIRMED_SLICE、LIKELY_SLICE 或 PARTIAL_SLICE；预算截断或 POSSIBLE 链路显示 `Partial Input Flow`，未连通候选计入 unresolved，不能伪装为完整链。
- 继续服从函数数、边数、深度和指令预算；复杂 alias、间接调用、路径条件和未证明的 buffer identity 会停止或降级。

### Packed Handling

- 输出 `static_visibility`、`analysis_reliability` 和 `recommended_steps`。
- likely-packed/suspicious 时降低字符串和 Validation 置信度，非 PACKING target 最高 20 分，入口桩成为 START HERE。
- Quick 明确提示优先确认 OEP、重建 imports、在隔离调试器中 dump，再对 unpacked dump 重跑 ReverseHelper。
- 不自动脱壳，不把壳表面的 compare/string 当作已验证 flag checker。

### START HERE safety

只有 PACKING entry，或置信度、分数与 top-2 分差达到门槛的候选才输出单一 START HERE。其余情况输出 `START WITH THESE` 三个起点，并明确说明单一选择的证据不足。Benchmark 同时报告全题 coverage hit rate 与实际输出时的 precision。

### Ranking 2.2

主要正向权重：confirmed/likely/possible static slice 为 +40/+30/+12；confirmed/likely/possible input flow 为 +38/+28/+12；outcome pair +22；input call +18；comparison +16；outcome branch +16；CTF string +14；return controls branch +10；transform +8；conditional branch +8；loop/length/algorithm constant 各 +6；sensitive API/call relationship 各 +4。

主要惩罚：未连通的同函数 input+comparison -15；context-only -12；PE structure -20；runtime noise -25。独立证据族达到 2/3/4 个时 corroboration bonus 为 +8/+18/+24。单一证据最多 30 分，两个独立证据最多 65 分，三个及以上才允许达到 100；无函数归属、无字符串/输入/算法支撑、context-only、runtime noise 和 packed surface 还有更严格上限。所有加减分与 cap 均进入 `score_breakdown`。

## 阶段结果

| 阶段 | Top-1 | Top-3 | Top-5 | START HERE | Validation P/R | Median / P90 |
|---|---:|---:|---:|---:|---:|---:|
| A Diversity baseline | 24.14% | 31.03% | 34.48% | 20.69% | 2.60% / 9.52% | 129.59 / 1021.82 ms |
| B Function Boundary 2.0 | 24.14% | 31.03% | 34.48% | 20.69% | 2.60% / 9.52% | 163.35 / 1057.18 ms |
| C Validation/Decision | 31.03% | 37.93% | 37.93% | 27.59% | 50.00% / 14.29% | 171.57 / 1101.98 ms |
| D Data Flow | 31.03% | 37.93% | 37.93% | 27.59% | 50.00% / 14.29% | 145.67 / 1047.08 ms |
| E Packed | 31.03% | 37.93% | 37.93% | 34.48% | 50.00% / 14.29% | 157.94 / 1072.74 ms |
| Final Ranking 2.2 + safe start | 44.83% | 51.72% | 51.72% | 34.48% | 50.00% / 14.29% | 172.32 / 1150.29 ms |

这些排名分母是 29 个成功完成且可排名的样本。第 30 个可用样本是故意损坏 DOS 签名的 parser 负例，按预期产生隔离错误。相对 A，Final 的 Top-1、Top-3、Top-5 和 START HERE 覆盖命中率分别提高 20.69、20.69、17.24 和 13.79 个百分点。严格 START HERE 只输出 11 次，命中 10 次，precision 为 90.91%；其余低置信度或分数接近的样本输出三个 START WITH THESE。

Final 的 Validation 为 3 TP、3 FP、18 FN，precision 50.00%、recall 14.29%、F1 22.22%。Interesting String 的人工已标注集合为 precision 100%、recall 60%，但另有 414 个未裁决提升项，不能把该 precision 外推到全部输出。Boundary start recall 为 42/54，即 77.78%；全体恢复函数边界置信度分布为 CONFIRMED 1581、LIKELY 2340、HEURISTIC 577。Static Slice 为 1 TP、0 FP、20 FN，precision 100%、recall 4.76%，状态分布为 Confirmed 0、Likely 1、Partial 0、Unresolved 142。Packed visibility 在 6 个标注 packed 样本中识别 2 个，recall 33.33%。Quick max 为 1973.61 ms。

按当前可用样本分层：

| Tier | 完成/可用 | Top-1 | Top-3/5 | START | Validation P/R | Slice recall | Boundary recall | Quick median/p90/max ms |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| A | 6/7 | 83.33% | 83.33% | 66.67% | 100% / 25% | 25% | 100% | 142.00 / 172.32 / 727.41 |
| B | 10/10 | 50.00% | 60.00% | 20.00% | 100% / 14.29% | 0% | 78.26% | 398.25 / 1098.91 / 1742.90 |
| C | 13/13 | 23.08% | 30.77% | 30.77% | 0% / 0% | 0% | 68.18% | 461.84 / 1150.29 / 1973.61 |

## 失败与限制

- Top-5 失败主要是 5 个 packed、2 个 input-flow missing，以及 function boundary、optimized compare、obfuscation、ranking weight 和大型 REplay 各类失败。
- 3 个 Validation FP 全部在 Tier C：`flareon2017-06` 两个、`flareon2018-07` 一个。它们说明复杂/packed 表面仍可能把比较模式抬成 actionable。
- Static Slice 只在一个公开样本上建立；100% precision 的样本数太小，不能视为成熟能力。
- Tier C 的排名、Validation、函数起点与 packed 检出都明显偏弱；大型 x64 MSVC 样本还会触发 Quick 预算警告。
- 10 个 pending 槽位尚未取得可复核样本；当前结果是 30 个可用样本的结果，不是 40 个实际样本的结果。
- 没有真人 TTCF 实验，因此只报告 Quick 分析耗时，不能宣称 TTCF reduction。

最终自动测试为 237 项全部通过，源码覆盖率 87%。专项测试覆盖 Function Boundary 2.0、Jcc/setcc/cmov 与 caller-return decision、x86 push/ESP argument、indexed stack/global flow、wrapper side effect、packed visibility/cap、START WITH THESE、Ranking 2.2 以及 Phase 2 集成 slice。

## 结论

Phase 2.5 应保留为一个完成的 hardening milestone：它显著改善了候选精度、Top-K 和 START HERE，也建立了可追溯的分层 benchmark。它还没有达到 Top-5 85% 的长期门槛。下一轮应先补齐 10 个 pending 样本并完成独立复核，再以 Tier C 的 packed、optimized compare、函数边界和间接输入流失败为驱动继续修正；不应仅通过继续调权掩盖缺失候选。
