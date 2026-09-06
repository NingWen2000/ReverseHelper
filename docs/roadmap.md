# ReverseHelper 开发路线图

2026-09-03 起，以[产品目标](product-goals.md)为准：**Offline-First CTF Reverse Engineering Workbench**。北极星指标为 TTCF；所有阶段遵守 FAST、ACCURATE、OFFLINE、ACTIONABLE。

这份路线图区分现有基础与待实现能力，不代表功能已经发布，也不承诺未经测量的速度或准确率。

## 当前基线（Phase 2.8 完成，Phase 2.x CLOSED，2026-09-06）

当前源码已有 PE x86/x64 解析、字符串/导入/异常线索、有预算的 Capstone 反汇编、Function Boundary 2.0 + logical chunks、直接字符串 XREF、输入与验证候选、ReverseTarget 2.2，以及 Ghidra Comment 导入基础。

ReverseTarget 2.2 按函数归并可确认的证据，优先受限 static slice 和 input flow，输出 0–100 分、每项贡献、证据来源、corroboration bonus、运行库惩罚和证据上限。无法确认函数归属时保留为 code location/data/import，并限制最高分；packed surface 的非入口结论也被限制。所有结果仍是候选，不是已确认关键函数。

默认命令和 `--quick` 均运行有严格预算的 Quick Analysis，并优先显示 Challenge Summary、Input Flow、Static Slice / FLOW BREAK / Possible Static Path 与 START HERE。旧完整分析仅保留为 Python API `analyze_full()`；没有 `--deep`。Phase 2.6 通过 ValueIdentity 保留寄存器、栈、全局、参数和派生返回值的来源，用轻量版本表达原地修改；跨函数只传播直接调用、唯一可解析间接调用、简单 wrapper 与受限 global consumer，不是完整 data flow。

Public CTF Benchmark v0.3 定义 40 个槽位，其中 31 个公开样本已取得并冻结，9 个为明确 pending。Final 完成 30 个，Top-1/3/5 为 56.67%/60.00%/60.00%；严格 START HERE 输出 14 次并全部命中，覆盖命中率 46.67%。Validation precision/recall 为 72.73%/36.36%，Complete/Actionable Slice recall 为 27.27%/36.36%，static-visible actionable recall 为 38.10%。五次最终运行的 median-of-medians 为 191.58 ms，P90 范围 1162.69–1184.53 ms。当前 ground truth 为 27 条单人复核和 4 条作者题解确认，没有真人 TTCF 数据。

Phase 2.8 用受限的调用约定参数、return/in-place/output summary 和 Golf `RETURN_SEMANTICS` 闭合 4 个 sink，没有新增 Validation 或 Slice FP。Final Top-1/3/5 为 56.67%/60.00%/60.00%，START coverage/precision 为 46.67%/100%，Validation 为 8/3/14，Complete/Actionable Slice 为 6/0/16 与 8/0/14。详见 [Phase 2.8 报告](phase2.8-final-static-flow-recovery.md)。Ranking 保持 2.2。

**Phase 2.x CLOSED.** Gate 为 Outcome A：`Phase 2 complete enough. Proceed to Phase 3.` Phase 3 只在下一轮用户指令后开始；本轮没有开始 Phase 3，也不会创建 Phase 2.9。

## P0：先找到关键逻辑

| 能力 | 第一阶段状态 | 下一步验收 |
|---|---|---|
| Reverse Target Ranking | 已交付 Ranking 2.2：0–100 分、函数级聚合、评分明细、static slice/input flow 优先、corroboration、CRT/packed 限分；支持九类目标 | 用扩充且独立复核的公开 ground truth 继续报告 Top-1/3/5；重点修复 Tier C 缺候选，不以单纯调权代替底层识别 |
| Input → Validation Static Slice | 已交付结构化 InputSource/Location/Edge、indexed stack/global alias、覆盖 kill、有限跨函数参数/返回/全局 side effect、简单 transform 和 StaticSlice；有严格预算 | 提高公开集 slice recall；扩展优化代码与间接调用时保持边界，不升级为完整符号执行 |
| Validation Discovery | 已覆盖 comparator、byte/custom loop、length、checksum/hash context、outcome text、Jcc/setcc/cmov 与 caller return decision；actionable 和 context-only 分离 | 修复 Tier C packed/optimized compare 误报漏报；没有证据时继续保留未知 branch polarity 和 buffer identity |
| Interesting String Intelligence | 已交付 13 类字符串、直接 XREF、函数归属、附近分支、优先级和理由；文本单独命中不能得到 HIGH | 扩展公开题目的字符串编码与引用形式，并测量对 Top-K 的实际收益 |

### P0 的交付入口与顺序

1. **已完成：**字符串、输入、比较与分支证据到函数级排序的最小链路；默认 Quick、Challenge Summary、START HERE 与 Suggested Static Path。
2. **已完成：**x86/x64 自动化 fixture，以及 strcmp、memcmp、byte-loop、普通 memcmp 的本地验收样本。
3. **已完成：**20 道公开题的 manifest、ground truth、冻结评估集与 before/after runner；如实保留低准确率和失败分类。
4. **已完成：**Phase 2 受限 input-to-validation slice、Ranking 2.1 与 Quick Summary flow path。
5. **已完成：**Phase 2.5 扩展为 40 槽位/30 可用样本，交付 Function Boundary 2.0、Validation Decision、Data Flow hardening、Packed strategy 与 Ranking 2.2。
6. **已完成：**Phase 2.6 建立 Slice FN taxonomy、static_visibility、ValueIdentity/版本、有限 alias/indirect/wrapper/global/return flow、logical chunks 与 StaticFlowBreak；Ranking 2.2 因校准证据不足保持不变。
7. **已完成：**Phase 2.7A 将 19 个 unresolved sink 重建为 first-broken-edge 故障图；纠正 `flareon2018-10` 的旧 `FUNCTION_CHUNK` 分类为早期 argv source 漏识别，并确认 threshold-only block 为 0。
8. **已完成：**Phase 2.7B 恢复 argv/DLL export seed、2/3 个审计 comparator CompareSite 与 2/2 个 entry/body 关系；闭合 `flareon2015-02:0x1084`，保持 Validation、Slice 和 START precision。
9. **已完成：**Phase 2.8 恢复受限 parameter/return/in-place/output provenance，并以 Golf 的真实 local-indirect scalar return → caller decision 闭合四个 checker；Phase 2.x 正式关闭。
10. **下一阶段：**等待用户指令后进入 Phase 3；不得回开 Phase 2.9。

当前 Quick 包含 Binary Triage、Interesting Strings、Imports、Input Sources、Validation Candidates、已有的常量指纹、Reverse Target Ranking 与 Suggested Static Path。扫描预算写入 `analysis_limits`，未运行模块写入 `skipped_modules`，失败或截断写入 `analysis_warnings`。

目标 Deep 必须主动请求，增加跨函数数据流、CFG、table usage、结构匹配、validation tracing、call graph；不得阻塞 Quick 首批结果。迁移 CLI 时同步处理默认模式、显式 Quick/Deep、报告的部分分析标记和旧参数兼容，不能只把完整分析重命名为 Quick。

对普通小于 10 MB 的题目记录冷启动、首次有用结果、Quick 总耗时与 Deep 耗时。性能预算从真实基线得出，不先承诺未经验证的秒数。

## P1：让候选更可靠，并接入 Ghidra

- **Algorithm Recognition**：优先 XOR、Rolling XOR、TEA、XTEA、XXTEA、RC4、AES、Base64、CRC、LCG、S-box、Feistel-like、lookup transform、ROL/ROR。按证据质量与 CTF 收益安排，不以数量验收；常量、结构、真实确认分别标注。
- **Key / Table Discovery**：candidate key、target bytes、S-box、lookup table、encoded blob、constant table；必须关联使用位置和函数，解释候选身份，不能只扫描高熵块。
- **Ghidra Deep Integration**：RH_INPUT、RH_VALIDATION、RH_TRANSFORM、RH_CRYPTO、RH_KEY_TABLE、RH_TOP_TARGET 的 Bookmark / Comment / Label；保留证据与来源、哈希身份和 RVA 重定位，避免覆盖用户命名。已有 Findings 导入只是基础，需验证重复导入和实际 CodeBrowser 行为。

## P2 / P3：核心之外

Control Flow Assistant、Decompiler Cleanup、Solver Skeleton、ELF support、plugin framework、advanced packing、advanced deobfuscation 降为 P2/P3。P0 切片所必需的局部 CFG/调用关系不等于优先建设完整 Control Flow Assistant。

保留现有 x64dbg/x32dbg 建议断点导出和兼容性验证事项；动态执行、观测与反馈闭环属于 TraceInfer。新增 Hex Editor 等不能明确减少 TTCF 的功能暂缓。

## 比赛环境与发布门槛

- 赛前安装依赖后，在断网、无账号、无 API Key 的环境完整运行核心分析与报告。便携包可行性、依赖离线准备和无需强制安装器纳入交付验证。
- 默认不进行远程请求、上传或必需遥测；核心不能被可选 AI 扩展绑定。
- 模块独立容错：记录失败模块及原因，保留其他结果；不支持的格式或架构给出清晰边界。
- 同一版本、样本与预算的排序和证据可复现；计时与生成时间单独记录。
- 首屏优先回答从哪里开始，Sections、Imports 明细、Entropy、Resources 进入详情。

## Benchmark 与成功标准

[Benchmark 规范](../benchmarks/README.md)定义公开题目的来源、ground truth、Top-K、误报、算法/验证识别和人工 TTCF。目标是 **20 → 50 → 100 道已核验题目**，包含开发集与冻结评估集；40 槽位中有 31 个可用样本，30 个正常完成静态分析，另有 1 个预期 parser 负例。

报告 Top-1/3/5 Critical Function Accuracy、Median TTCF、Validation Detection Accuracy、Algorithm Detection Accuracy，并同时给出样本数、失败/超时、不支持范围和测量条件。

Top-5 >85%、Median TTCF reduction >50% 是希望达到的目标。当前 Top-5 为 56.67%，TTCF 未测量，不得在 README、Release 或界面宣称已达到。
# Phase 3

- **3A Algorithm Recognition: complete.** Conservative static recognition, typed evidence, slice/key-table integration and benchmark support are implemented. See [Phase 3A report](phase3a-algorithm-recognition.md).
- **3B Control Flow Understanding: complete.** Bounded switch, dispatcher, indirect structure and flattening-like explanations are integrated. See [Phase 3B report](phase3b-control-flow-understanding.md).
- **3C Decompiler Assistance: complete.** Evidence from input flow, validation, algorithms and control flow now produces bounded semantic suggestions. See [Phase 3C report](phase3c-decompiler-assistance.md).

**Phase 3 CLOSED.** Phase 3 is complete enough; Phase 4 is next and has not started.

# Phase 4

**Phase 4 CLOSED (Outcome B).** 默认 Quick、显式 Deep、统一预算与 JSON annotations、Ghidra 交接、Windows x64 便携构建、离线回归、发布文档和 TTCF 记录框架已交付。Ranking 保持 2.2。公开样本仍为 31 available / 9 pending，不以低质量样本补数。

当前建议版本为 `0.2.0b1`，不是 1.0。真实干净 Windows 机器、实际 Ghidra UI 导入和真人 TTCF 仍需外部验证；Phase 5 不在本轮开始。
