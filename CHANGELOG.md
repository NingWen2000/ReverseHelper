# ReverseHelper 更新日志

ReverseHelper 仍处于早期开发期。版本号用于区分可下载、可复现的功能快照；默认分析仍然只读取目标 PE，不会执行它。

## 0.2.0b2 — Post-release localization（2026-09-08，Beta 预发布）

- Added Simplified Chinese localization：新增 Quick/Deep 摘要、帮助、报告和 Ghidra 注释的简体中文展示。
- Added `--lang en / zh-CN`：默认英文，不随系统语言自动切换。
- Added Chinese documentation：README、QUICKSTART、workflow、limitations 和统一术语表。
- No analysis/ranking behavior changes：分析器、Ranking 2.2、Schema 1.5、JSON 字段和枚举均保持兼容；仅 Ghidra 导出的 annotation 标题及注释跟随语言。
- 新增英文 golden 回归、跨语言事实等价及 Windows Unicode 输出测试；portable 使用独立 b2 文件名，不覆盖 b1 发布包。

## 0.2.0b1 — Phase 4 Competition-Grade Integration（2026-09-06）

- 默认单命令 Quick 工作流完成产品化；摘要增加目标名、静态可见度、直接 validation、截断说明和按需 Deep 提示。
- 新增 `--deep`，通过统一 `AnalysisBudget` 放大同一套 decode/function/data-flow/algorithm/CFG/semantic 分析器，不复用旧 full pipeline。
- JSON 保持 Schema 1.5 兼容并新增统一 annotations、result status、截断模块和通用耗时；Ranking 保持 2.2。
- 新增 `--ghidra`，导入脚本优先使用 `RH:START`、`RH:INPUT`、`RH:SLICE`、`RH:VALIDATION`、algorithm/control-flow/FLOW_BREAK/semantic 统一注释。
- 新增 Windows x64 PyInstaller 单文件构建脚本、Quick Start、workflow/limitations、TTCF 实验协议及空白记录模板。
- IDA 深度集成与 solver skeleton 延后：当前证据不足以证明其 TTCF 收益或避免误导。

## Unreleased — Phase 2.8 Final Static Flow Recovery（2026-09-06）

### 新增

- 在现有 ValueIdentity 引擎中加入 x64 entry-RSP 栈槽规范化、调用约定参数 identity、轻量 ReturnSummary、in-place mutation 与直接 output-parameter relation；summary 有缓存和独立 edge cap。
- 同一 `argv[n]` 的后续重载保持一个 canonical ValueIdentity，避免较早寄存器定义被字符串指令或调用 kill 后链路永久断开。
- 针对 Golf 的真实 `argument -> local indirect checker -> scalar return -> caller movzx/test/jcc` 形态加入受限 `RETURN_SEMANTICS` CompareSite；不解析或猜测运行时生成代码。
- 加入 14 个 Phase 2.8 正负测试，并保存目标审计与 5 次最终完整基准。

### 实测结果与 Gate

- Validation 从 4/3/18 提升到 8/3/14，precision/recall 为 72.73%/36.36%；Actionable Slice 从 4/0/18 提升到 8/0/14，Complete Slice 从 2/0/20 提升到 6/0/16。新增 FP 为 0。
- Top-1/3/5 为 56.67%/60.00%/60.00%；START coverage/precision 为 46.67%/100%。Ranking 保持 2.2。
- Parameter、普通 Return、In-place/output 各修复 0 个冻结 FN；Golf 修复 4 个。14 个目标 FN 最终为 fixed 4、still fixable 10、out-of-scope after re-audit 0。
- 5 次 Quick 的 median-of-medians 为 191.58 ms，P90 范围 1162.69–1184.53 ms。285 项测试通过，语句覆盖率 86%。
- Gate 为 Outcome A：`Phase 2 complete enough. Proceed to Phase 3.` Phase 2.x 已关闭，不创建 Phase 2.9；本轮未开始 Phase 3。详见 [Phase 2.8 报告](docs/phase2.8-final-static-flow-recovery.md)。

## Unreleased — Phase 2.7B Targeted Static Slice Recovery（2026-09-05）

### 新增

- 恢复 x86/x64 argv 固定与动态下标，为 `ArgvObject#n` 建立 ValueIdentity；x64 支持 CRT/user-main 常见的 ABI 参数保存、RSP 调整和重载。
- 对 DLL export 中实际进入 validation/transform 使用的参数建立保守 `EXPORTED_ARGUMENT`；handle/flags-only 参数不提升。
- 识别有双内存流、推进、回边、退出形态和 caller return decision 的 static-linked comparator，并记录 comparator origin/function/thunk chain。
- 将两种已审计 entry/body 形态表示为现有 Function 下的 `ENTRY_STUB`/`BODY` chunks，保持 LIKELY confidence。
- 加入本轮机制的正负 fixture，以及 `-O1`/`-O2` 真实 MinGW PE 编译回归。

### 实测结果与边界

- 271 项测试通过。最终完整基准 Top-1/3/5 为 53.33%/60.00%/60.00%；START coverage/precision 为 43.33%/100%。
- Validation 保持 4 TP / 3 FP / 18 FN（P/R/F1 57.14%/18.18%/27.59%）。Actionable Slice 从 3/0/19 改善到 4/0/18；static-visible actionable recall 从 14.29% 提升到 19.05%。Complete Slice 保持 2/0/20。
- 15 个现实可修复 FN 中实际闭合 1 个：`flareon2015-02:0x1084`。另恢复 7 个 sink 的输入来源证据、2/3 个审计 comparator CompareSite 和 2/2 个 entry/body 关系，但证据不足的路径没有提升为 Validation。
- 最新 Quick median/P90/max 为 306.81/1517.66/2321.60 ms；等价最终运行存在明显环境波动，完整范围和异常复核见报告。271 项测试通过，语句覆盖率 86%。Ranking 保持 2.2；Phase 3 继续冻结。详见 [Phase 2.7B 报告](docs/phase2.7b-targeted-static-slice-recovery.md)。

## Unreleased — Phase 2.6 Static Flow Recovery（2026-09-05）

### 新增

- 对原始 20 个 Static Slice FN 建立冻结 taxonomy 与逐题证据：INPUT_SOURCE_NOT_FOUND 5、FUNCTION_CHUNK 4、STATIC_LINKED_COMPARE 3、OPTIMIZED_COMPARE 2、INDIRECT_INPUT_CALL 2，其余 FUNCTION_BOUNDARY、GLOBAL_FLOW、INDIRECT_CALL、PACKED_NOT_STATIC_VISIBLE 各 1。
- Benchmark schema v3 增加 `static_visibility`、Complete/Actionable Slice、Static-visible 聚合、Packed Visibility TP/TN/FP/FN 与 review coverage；加入作者源码确认的 `xorkey-crackme`，当前 31 个可用、9 个 pending。
- `ValueIdentity` 保留 origin/base object/offset/index/scale/provenance/alias confidence/version；支持寄存器复制、spill/restore、stack/global base+offset、符号索引、保守 merge/kill 与原地变换版本。
- 受限跨函数流保留参数、派生返回值和直接调用消费者中的全局对象 identity；简单 wrapper 只在明确参数写回关系成立时映射调用者。
- 唯一目标间接解析支持 IAT load → register/copy/spill → call、常量函数指针和已有简单 thunk；控制流歧义或多目标保持 unresolved。
- Function 模型增加 PRIMARY/COLD/TAIL/SHARED_EPILOGUE logical chunks；对名称为 `.text` 或包含入口点的 PE CODE-but-non-executable section 做透明警告下的保守解码。
- `StaticFlowBreak` 只从真实 source-reachable 子链构造，输出最后确认节点、中断 RVA、下一未解析目标、原因和证据。Quick Summary 增加 FLOW BREAK，并可把可靠中断点作为 START HERE。
- 为 Value Identity、alias kill/merge、版本、function chunk/shared epilogue、IAT/函数指针、wrapper、global flow、derived return、Partial Slice 和 packed visibility 增加专项测试。

### 实测结果与边界

- 31 个可用样本中 30 个完成，1 个预期 parser 负例隔离失败。Top-1/3/5 为 46.67%/56.67%/56.67%；START HERE 覆盖命中率 36.67%，已输出项 precision 84.62%。
- Validation 为 4 TP / 3 FP / 18 FN，P/R/F1 57.14%/18.18%/27.59%。Complete Slice 为 2 TP / 0 FP / 20 FN，recall 9.09%；Actionable Slice 为 3 TP / 0 FP / 19 FN，recall 13.64%。Static-visible Complete/Actionable recall 为 9.52%/14.29%。
- Function start recall 为 83.64%，Packed Visibility accuracy 为 86.67%（recall 33.33%）。Median/P90/max Quick 为 212.70/1145.96/2080.94 ms。
- 原始 20 个 Slice FN 中只有 `flareon2017-03` checksum `0x11E6` 被合法 Partial 修复；19 个仍 unresolved。新增完整 Slice 命中来自 Phase 2.6 基线前加入的 `xorkey-crackme`。
- Ranking 保持 2.2：真实 Slice 增益不足以校准 2.3，且 Flow Break START 使 emitted precision 从 91.67% 降到 84.62%。当前不建议进入 Phase 3。
- 254 项测试全部通过，源码覆盖率 87%。完整阶段数据与限制见 [Phase 2.6 报告](docs/phase2.6-static-flow-recovery.md) 与 [Benchmark](benchmarks/README.md)。

## Unreleased — Phase 2.5 Public Benchmark Expansion + Core Hardening（2026-09-04）

### 新增

- 将公开基准扩展为 40 个固定槽位：30 个已取得并冻结的 PE/PE-like 样本与 10 个明确的 `pending-user-sample`；覆盖四组公开来源、25 个 x86、5 个 x86-64，以及 Tier A/B/C 分层。
- Benchmark schema v2 为每条记录增加 challenge/source/event/year/tier/format/architecture/compiler/packed/obfuscated/ground_truth_source/review_status；runner 增加按 Tier 指标、Validation F1、人工裁决字符串 precision/recall、function start recall、slice precision/recall、P90、packed visibility 和 manifest coverage。
- Function Boundary 2.0：综合 x64 runtime ranges、COFF symbols、entry、exports、direct calls、prologues 和 thunk leads，并输出范围、来源、置信度、tail-call/shared-tail 证据。
- Validation/Decision 2.0：识别 Jcc、setcc、cmov、caller return consumer、inline byte comparison、byte-vs-byte loop、comparison cluster 和有限 hash context；区分 actionable、context-only、runtime noise 与 unknown fields。
- 有预算的数据流增加 indexed stack/global alias、原地 memory transform、global writer → controller → sibling checker 和 wrapper side effect。
- Packed strategy 输出 static visibility、analysis reliability 与下一步建议；壳表面非 PACKING target 限分，START HERE 优先入口桩，不自动脱壳。
- Ranking 2.2 强化 static slice/input flow 权重、运行库降噪、corroboration 与证据上限，并让所有权重、惩罚和 cap 保持可解释。
- Quick JSON Schema 升至 1.5，正式输出 CompareSite、DecisionSite、runtime_likelihood、slice status/distribution，并在低置信度或分数接近时使用 `START WITH THESE`。

### 实测结果与边界

- Final 在 30 个可用样本中完成 29 个；另一个是故意损坏 DOS 签名的 parser 负例。Top-1/3/5 为 44.83%/51.72%/51.72%。严格 START HERE 输出 11 次、命中 10 次，precision 90.91%，按全部题计算的覆盖命中率 34.48%。
- Validation 为 3 TP / 3 FP / 18 FN，precision 50.00%、recall 14.29%、F1 22.22%；3 个 FP 均来自 Tier C。
- 已人工裁决的 Interesting String precision/recall 为 100%/60%，但另有 414 个 unadjudicated promotions；Function Boundary start recall 77.78%，Static Slice precision/recall 100%/4.76%，packed visibility recall 33.33%。
- Median/P90/max Quick 为 172.32/1150.29/1973.61 ms。没有真人 TTCF 数据，不宣称 TTCF reduction。
- 237 项测试全部通过，最终源码覆盖率 87%；新增 Function Boundary、Validation Decision、x86 push/ESP argument、data-flow hardening、packed strategy、START WITH THESE 和 Ranking 2.2 专项测试。
- Ground truth 为 27 条 SINGLE_REVIEW 与 3 条 OFFICIAL_WP_CONFIRMED，没有双人复核标签。10 个 pending 槽位不进入结果分母。
- 完整阶段结果、权重和失败分类见 [Phase 2.5 报告](docs/phase2.5-hardening.md) 与 [Benchmark](benchmarks/README.md)。

## Unreleased — Phase 1.5 Benchmark + Phase 2 Static Slice（2026-09-04）

### 新增

- 冻结 `Public CTF Benchmark v0.1`：20 道 Flare-On 2015–2018 PE 题、逐题 SHA-256、公开来源、独立 ground truth、14/6 development/evaluation 划分，以及可复现 runner 与逐题结果。
- 结构化 `InputSource` 与 Register/Stack/Memory/Argument/Return/Global location 模型；支持 argv、scanf-family、fgets/gets、ReadFile/ReadConsole、GetDlgItemText、GetWindowText 和 GetCommandLine 常见入口。
- 有预算的 intra-function COPY/ADDRESS/LOAD/STORE/TRANSFORM/COMPARE 流，处理明显寄存器与栈覆盖；复杂 alias 停止或降为 POSSIBLE。
- 有深度、函数数、边数和指令数上限的 direct-call 参数、返回值及保守 x86 输出参数回传。
- `StaticSlice` 将输入、简单 XOR/ADD/SUB/ROL/ROR/byte-swap/table lookup、ValidationCandidate 与 outcome branch 关联；候选输出 `input_flow_to_validation`。
- Ranking 2.1 增加 confirmed/likely/possible input-flow、slice transform、return-to-branch 证据，并对同函数但未连通的 input+comparison 组合降权；原证据上限和 corroboration 保护保留。
- Quick Summary 增加 Input Flow、Static Slice / Possible Static Path，并按 flow position 生成建议查看顺序。
- Quick JSON Schema 升至 1.4，新增 `input_sources`、`data_flow`、`static_slices` 与 Validation flow 字段；旧字段继续保留。

### 校准与边界

- P0 frozen baseline：Top-1/3/5 30%/40%/40%，START HERE 30%，Validation precision/recall 4.76%/10.53%，字符串相关召回 50%，median Quick 401 ms。
- Phase 2 after 使用同一 20 题冻结集：排名与 Validation 指标未改变，median Quick 434.38 ms；共识别 33 个输入源，但没有建立通过保守门槛的公开题 StaticSlice。该结果作为未改善基线保留。
- Ground truth 当前为单人复核，20 道题来自同一比赛系列；没有真人 TTCF 数据，也没有宣称 TTCF 改善。
- Phase 2 仍是 Quick 中受预算约束的静态切片，不包含完整 alias、SSA、符号执行、路径约束、动态跟踪、ELF、Solver、AI 或 Deep Mode。

## Unreleased — P0 第一阶段（2026-09-04）

### 新增

- Interesting String Intelligence：SUCCESS、FAILURE、FLAG、PASSWORD、INPUT、KEY、ERROR、FORMAT、FILE、NETWORK、CRYPTO、DEBUG、GENERIC 分类，以及 String → direct XREF → bounded Function → nearby branch 关联。
- 保留同值字符串的不同地址，输出稳定 ID、地址、编码、分类、优先级、置信度、XREF 数、引用函数和评分理由。
- 保守 FunctionIndex：优先使用 PE x64 exception directory，并结合 EntryPoint、Export、direct CALL target 与 frame prologue；控制流成员遍历有 4096 条指令上限。
- ValidationCandidate：覆盖 strcmp/strncmp/memcmp、逐字节或自定义比较循环、length + comparison、直接 checksum 返回值比较、hash-output + comparator 上下文，以及候选 success/failure 分支。
- Reverse Target Ranking 2.0：统一 0–100 分、评分明细、证据来源和 corroboration bonus；按函数聚合，未知函数边界时按位置保守限分。
- 默认命令运行有明确字节、指令、字符串与函数预算的 P0 Quick Analysis。首屏改为 Challenge Summary，依次展示 START HERE、Interesting Strings、Validation Candidates、Top Reverse Targets 与 Suggested Static Path。
- Quick Markdown、HTML 和 JSON 报告；单个分析或报告模块失败会记录 warning，并继续保留其他分析结果或报告格式。
- 自行编写的 strcmp、memcmp、byte-loop 和普通数据 memcmp 验收样本源文件，以及 x86/x64 可复现单元 PE fixture。

### 验证与边界

- 191 项测试通过，覆盖率 85%；P0 专项包含字符串、strcmp、memcmp、逐字节循环、普通 memcmp 误报、多个候选排序、Quick Summary、预算与故障隔离。
- 本地编译的三个 crackme 均将 `main` 排为 Top-1（92/98/92）；普通数据 memcmp 最高 30/100，并保持 COMPARE/LOW。这是功能验收结果，不是公开 CTF Benchmark 准确率。
- Quick 不运行 Deep、符号执行或跨函数数据流。`input_source`、success/failure 分支与 hash 上下文会明确标记未证明的数据/语义关系。
- JSON Schema 升至 1.3；旧完整分析保留为 Python API `analyze_full()`，没有作为 Deep Mode 发布。

## Unreleased — 产品目标修订（2026-09-03）

- 正式定位为 Offline-First CTF Reverse Engineering Workbench，以 TTCF 为北极星指标。
- 同步 README、包描述、贡献规范、设计约束与 P0/P1/P2/P3 路线图。
- 建立 CTF Benchmark 来源入口、标注模板和测量规范；尚无公开题目的实测准确率或 TTCF 结论。
- 此条目记录当日的产品方向与开发验收约束；后续实现状态见上方 P0 第一阶段条目。

## v0.1.0 — 2026-08-28

v0.1.0 将 PE 结构初筛扩展为“证据 → Finding → ReverseTarget → 动态问题”的静态逆向工作流。当前条目描述本地 v0.1.0 成品；尚未创建标签或 GitHub Release。

### 新增

- Capstone x86/x64 反汇编，严格限制在 PE section 的实际 raw bytes 范围内。
- direct/indirect CALL、JMP、Jcc、RET 分类，以及 x64 RIP-relative pointer slot 记录。
- Anti-Debug Analyzer：组合 API、PEB/BeingDebugged/NtGlobalFlag、INT3/ICEBP/RDTSC 和条件分支上下文。
- Crypto Analyzer 2.0：保留旧常量结果，为 TEA-family 与 RC4 候选增加指令证据。
- Validation/Input Analyzer：定位 comparator/input 调用点，并保守关联返回值、TEST/CMP 和 Jcc。
- 统一 Finding、ReverseTarget、分析路径和未决问题；`finding_ids` 保留排序原因。
- `--only antidebug/validation/crypto/targets` 与 `--x64dbg-script`。
- `ImportReverseHelperFindings.py`，默认将 Findings/Targets 作为 Ghidra Comment 导入。

### 兼容性

- 默认命令、`--quick`、旧 `--only` 模块、报告参数和退出码保持兼容。
- JSON Schema 从 1.1 增至 1.2；旧字段不删除，只追加指令级结果字段。
- quick 模式不进入 Capstone 指令分析，仍用于快速结构初筛。
- Risk Score 与 ReverseTarget Priority 保持独立。

### 质量与边界

- 单个可选分析模块失败会写入 `analysis_warnings`，不会使其他模块丢失结果。
- Anti-Debug、Validation 和 Input 共用一次 Capstone detail 与导入调用解析。
- 启发式结果使用 Candidate/Possible 等保守措辞；间接目标、运行时参数和 buffer 不会被猜测。
- 完整验证记录见 [v0.1.0 Phase 6 validation](docs/phase6-validation.md)，发布说明草案见 [v0.1.0 release notes](docs/releases/v0.1.0.md)。

## v0.0.2 — 2026-08-26

### 相较 v0.0.1 的变化

| 项目 | v0.0.1 | v0.0.2 |
|---|---|---|
| 默认完整分析 | 支持 | 保持原行为和分析结果 |
| 快速结构初筛 | 不支持 | 新增 `--quick` |
| 单模块分析 | 不支持 | 新增 `--only anomaly/strings/imports` |
| 帮助页 | 基础参数 | 增加模式说明、含空格路径和完整示例 |
| 输入错误 | 部分情况共用同一提示 | 区分不存在、目录、不可读、非普通文件和非 PE |
| CLI 测试 | 无专项覆盖 | 增加参数调度、互斥、错误和真实 PE 集成测试 |
| 版本下载 | 无 GitHub Release | 提供 v0.0.1、v0.0.2 独立下载页 |

### 安装与确认版本

在源码目录中安装：

```powershell
python -m pip install -e .
reversehelper --version
reversehelper --help
```

`reversehelper --version` 应显示 `ReverseHelper 0.0.2`。使用虚拟环境时，请先激活虚拟环境，或者用该环境中的 Python 执行安装。

### 默认完整分析

```powershell
reversehelper sample.exe
```

这是兼容 v0.0.1 的默认行为，会执行完整静态分析：

- PE Header、架构、ImageBase、EntryPoint、哈希和子系统；
- 节区地址、权限、Entropy 与 RWX 信号；
- Import、Export 和规则匹配的敏感 API；
- ASCII、UTF-16LE 字符串及文件偏移、RVA、VA、所属节区；
- EntryPoint 字节和少量明确入口桩；
- 可执行节中的 `00`/`CC` 连续填充候选；
- Overlay、已知壳节名、高熵与入口点异常；
- AES、TEA、MD5、CRC 等内置密码学常量；
- 可解释风险分数。

路径中有空格时要保留引号：

```powershell
reversehelper "C:\Lab Files\sample.exe"
```

### 快速模式：`--quick`

```powershell
reversehelper sample.exe --quick
```

快速模式适合刚拿到样本时先判断架构、入口点和节区是否值得优先检查。它会运行：

- PE 基础信息和哈希；
- Sections、Imports、Exports；
- EntryPoint 基础检查；
- 已知壳节名、高熵、RWX、异常入口点、少量导入与大 Overlay 规则；
- 不含字符串信号的结构风险分数。

它会跳过完整字符串提取、密码学常量和代码洞扫描。由于信号范围不同，快速模式中的 `Structural risk` 不应与默认完整分析的风险分数直接比较。

### 异常模块：`--only anomaly`

```powershell
reversehelper sample.exe --only anomaly
```

只输出加壳和 PE 结构异常相关结果，包括：

- 可能的壳名称；
- `likely-packed`、`suspicious`、`weak-indicators` 或 `no-obvious-indicators` verdict；
- 规则置信分；
- 每条异常的类型、严重度和证据。

这些结果是静态启发式线索，不是恶意判定。没有命中只表示内置规则没有发现明显异常。

### 字符串模块：`--only strings`

```powershell
reversehelper sample.exe --only strings
```

提取 ASCII 和 UTF-16LE 字符串，并显示编码、文件偏移、RVA、所属节区和分类。终端最多展示前 100 条保留结果；分析器仍受最大保留数量控制。

可以调整最小长度和最大保留数量：

```powershell
reversehelper sample.exe --only strings --min-string-length 6 --max-strings 5000
```

最小长度不能小于 3，最大数量必须为正数。提高最小长度可以减少噪声，提高最大数量会增加内存占用和输出规模。

### 导入表模块：`--only imports`

```powershell
reversehelper sample.exe --only imports
```

按 DLL 列出导入 API、IAT 地址和规则分类。`Rule match` 只表示函数名命中了内置规则，例如内存操作、进程操作、注入、反调试、动态加载或网络能力；是否真正执行仍需在 Ghidra/x64dbg 中检查调用方。

### 报告输出

完整分析可以继续生成 Markdown、JSON 和独立 HTML：

```powershell
reversehelper sample.exe --report
reversehelper sample.exe --report .\reports
reversehelper sample.exe --json .\reports\sample.json
reversehelper sample.exe --markdown .\reports\sample.md
reversehelper sample.exe --html .\reports\sample.html
```

`--quick` 和 `--only` 暂时不能与报告参数组合。原因是完整报告模板要求所有模块字段齐全；把未运行的字段写成空值，会让读者误以为模块已经运行但没有发现结果。

### 参数组合与错误处理

`--quick` 和 `--only` 互斥，下面的命令会直接显示参数错误：

```powershell
reversehelper sample.exe --quick --only strings
```

以下预期错误会显示简洁说明并返回非零状态，不会向普通用户输出 traceback：

- 必填 PE 路径缺失；
- 路径不存在；
- 输入路径是目录或不是普通文件；
- 文件无法读取；
- 缺少 `MZ` 签名或 PE 结构无效；
- 字符串参数超出允许范围；
- 部分分析模式与完整报告参数混用。

### 开发接口

默认 API 保持不变：

```python
from reversehelper import ReverseHelperAnalyzer

analyzer = ReverseHelperAnalyzer()
full_result = analyzer.analyze("sample.exe")
quick_result = analyzer.analyze_quick("sample.exe")
strings_result = analyzer.analyze_module("sample.exe", "strings")
```

新增的部分分析结果包含 `analysis_mode` 和 `analysis_modules`，用于明确区分“模块没有运行”和“模块运行后没有发现”。默认 `analyze()` 的原始结果结构保持不变。

### 验证

- Windows Python 3.13 环境下 38 项测试全部通过；
- `--quick` 和三个 `--only` 命令均使用合法 PE 完成只读实测；
- 含空格路径验证通过；
- editable install、源码包和 wheel 构建通过；
- 测试不会执行被分析的 PE。

## v0.0.1 — 基线版本

v0.0.1 保留为本轮模式扩展之前的可下载基线，包含：

- 完整 PE 静态分析流程；
- 基础 `reversehelper sample.exe` 命令；
- PE Header、Sections、Import/Export、Strings、Entropy、Overlay、Crypto Constants；
- EntryPoint、代码洞、加壳/异常和风险提示；
- Markdown、JSON、HTML 报告；
- Ghidra 辅助脚本和项目案例文档。

v0.0.1 不包含 `--quick`、`--only`、新的输入错误分类和 CLI 专项测试。该版本不会因发布 v0.0.2 而删除或覆盖。
# Phase 3C

- Added bounded, evidence-linked decompiler suggestions for function/object roles, conservative types, arrays, struct-like objects and local temporary-expression groups.
- Added trusted-symbol preservation, runtime filtering, role deduplication, suggestion budgets and comment-only Ghidra `RH:SUGGEST_*` annotations.
- Added semantic role/type benchmark scoring and optimized Phase 3C fixtures without changing Ranking 2.2.

# Phase 3B

- Added bounded control-flow findings for validated switch/jump tables, state-machine dispatchers, indirect call structures, flattening-like CFGs and LOW-only opaque-like hints.
- Added dispatcher/state-update explanations, StaticSlice relations, a capped Control Flow summary and Ghidra bookmarks/comments without changing Ranking 2.2.
- Added x86/x64 deterministic fixtures, optimized `-O1`/`-O2` source fixtures and official-solution-backed control-flow benchmark scoring.

# Phase 3A

- Added bounded, machine-readable CTF algorithm candidates for XOR variants, TEA family, RC4, Base64, CRC32, table transforms, LCG and conservative custom transforms.
- Linked algorithm evidence to StaticSlice, Challenge Summary and Ranking 2.2 without allowing LOW/off-slice detections to promote targets.
- Added algorithm benchmark scoring and independently sourced algorithm ground truth for `xorkey-crackme`.
