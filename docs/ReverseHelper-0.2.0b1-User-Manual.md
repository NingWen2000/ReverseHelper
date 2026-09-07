# ReverseHelper v0.2.0b1 用户使用说明书

文档版本：1.0  
适用软件版本：ReverseHelper `0.2.0b1`  
适用平台：Windows x64 便携包；目标文件为 Windows PE x86/x64  
版本状态：Beta 可用版，Phase 1–4 已全部完成并关闭

## 1. ReverseHelper 是什么

ReverseHelper 是面向 CTF Reverse 场景的离线静态预分析工具。它在你刚拿到未知 Windows PE 文件时，帮助回答几个最先需要解决的问题：

- 这个文件是什么架构，是否存在明显加壳或混淆迹象？
- 输入可能从哪里进入？
- 输入可能经过哪些变换，又在哪里被比较或验证？
- 哪些函数、数据、算法或控制流结构最值得先看？
- 打开 Ghidra 后，第一站应该跳到哪里？

ReverseHelper 只读取目标文件，不执行目标、不上传样本、不依赖网络、账号、API Key、云服务或 LLM。它适合在赛时网络受限、时间紧张，需要快速完成机械式初筛的环境中使用。

ReverseHelper **不是自动解题器**。它不会自动得到 Flag，不会自动脱壳、执行、模拟、符号求解或重写控制流，也不能替代 DIE、PE-bear、Ghidra、IDA 或 x64dbg。它的作用是缩短从“拿到文件”到“开始阅读关键代码”的距离。

## 2. 当前版本状态

当前版本是 **`0.2.0b1`**：

- Phase 1–4 已全部完成并关闭；
- 默认 Quick、按需 Deep、报告、Ghidra 注释交接和 Windows x64 便携构建均已实现；
- 当前属于可实际使用的 Beta 版本，不是 1.0；
- Phase 5 不属于当前使用流程，也不是使用本版本的前置条件。

当前便携包已在构建机器上完成 Quick、Deep、真实公开 PE 和异常输入测试。独立干净 Windows 机器与真实 Ghidra CodeBrowser UI 导入仍属于外部验证项，因此首次用于正式比赛前，建议在自己的比赛电脑上用一个已知 PE 完成一次演练。

## 3. 下载、解压与第一次启动

### 3.1 便携包内容

将 `ReverseHelper-0.2.0b1-win-x64.zip` 解压后，目录应包含：

```text
ReverseHelper-0.2.0b1-win-x64/
├── ReverseHelper.exe
├── ImportReverseHelperFindings.py
├── QUICKSTART.md
└── LICENSE
```

便携包设计为直接运行，不要求安装 Python。最终验证包的 ZIP SHA-256 为：

```text
FE3995C92A49926BD5DE8204ECE3B3B9BF8404B093A7D02B09A11D7668C2DD9F
```

如果文件来自其他构建或后续重新发布版本，应以对应发布页提供的哈希为准。不要为了运行未知来源的文件而关闭 Windows 安全功能。

### 3.2 在 PowerShell 中启动

不要依赖双击 EXE 查看结果，因为窗口可能在分析结束后立即关闭。推荐在解压目录打开 PowerShell：

```powershell
cd C:\Tools\ReverseHelper-0.2.0b1-win-x64
.\ReverseHelper.exe --version
```

预期输出：

```text
ReverseHelper 0.2.0b1
```

查看完整参数：

```powershell
.\ReverseHelper.exe --help
```

## 4. 最常用的命令

| 目的 | 命令 |
|---|---|
| 默认 Quick 分析 | `.\ReverseHelper.exe .\challenge.exe` |
| 显式 Quick 分析 | `.\ReverseHelper.exe .\challenge.exe --quick` |
| 扩大静态分析范围 | `.\ReverseHelper.exe .\challenge.exe --deep` |
| 输出 Markdown、HTML、JSON | `.\ReverseHelper.exe .\challenge.exe --report .\reports` |
| 输出 Ghidra 注释 JSON | `.\ReverseHelper.exe .\challenge.exe --ghidra` |
| 指定 Ghidra JSON 路径 | `.\ReverseHelper.exe .\challenge.exe --ghidra .\reports\challenge.reversehelper.json` |
| 只输出 JSON | `.\ReverseHelper.exe .\challenge.exe --json .\reports\challenge.json` |
| 显示预算和截断详情 | `.\ReverseHelper.exe .\challenge.exe --verbose` |
| 生成 x64dbg 建议断点脚本 | `.\ReverseHelper.exe .\challenge.exe --x64dbg-script .\reports\challenge.x64dbg` |

文件路径含空格时必须加引号：

```powershell
.\ReverseHelper.exe "C:\CTF Challenges\rev 01\challenge.exe"
```

默认命令与 `--quick` 完全等价。普通用户一般不需要显式写 `--quick`。

## 5. Quick 模式

### 5.1 最简单的真实可执行示例

假设便携包和题目文件位于：

```text
C:\CTF\Tools\ReverseHelper\ReverseHelper.exe
C:\CTF\Challenges\warmup\warmup.exe
```

执行：

```powershell
cd C:\CTF\Tools\ReverseHelper
.\ReverseHelper.exe "C:\CTF\Challenges\warmup\warmup.exe"
```

这会运行默认 Quick Analysis，并在终端显示 Challenge Summary。没有指定报告参数时，不会自动生成 Markdown、HTML 或 JSON 文件。

### 5.2 Quick 适合什么时候使用

Quick 是所有新题的推荐第一步。它采用固定的字节、指令、函数、数据流、算法和 CFG 上限，优先尽快给出可操作结果。典型用途是：

1. 在 DIE/PE-bear 初步看完格式和壳信息后，对 PE 做统一静态初筛；
2. 找到 `START HERE`、输入源、Validation 或关键字符串；
3. 把候选位置带进 Ghidra；
4. 判断是否真的值得投入 Deep 或动态调试时间。

Quick 的输出是有界的。出现截断并不代表分析失败，只表示预算之外的代码尚未检查。

## 6. 如何阅读输出结果

终端摘要按照“先行动、后证据”的顺序排列。不同样本可能缺少某些部分；缺少候选表示当前静态证据不足，不表示对应逻辑不存在。

### 6.1 Target、Binary、Packing 与 Static visibility

- `Target`：实际分析的文件名。
- `Binary`：PE32/PE64 和 x86/x86-64 架构。
- `Packing`：是否存在明显壳或混淆迹象。这是启发式判断，不是权威壳鉴定。
- `Static visibility`：当前静态视野是否正常、有限或未知。

如果显示静态可见度有限，应优先阅读 `Post-Unpack Guidance`。此时字符串、Validation 和 Ranking 可能只反映壳表面，不应直接当作原始程序逻辑。

### 6.2 START HERE 与 START WITH THESE

`START HERE` 是 ReverseHelper 在当前证据下选出的单一优先检查位置，通常包含：

- 函数或位置名称；
- 0–100 的 Ranking 分数；
- confidence；
- `Reason`：为什么排在这里；
- `Next`：建议进入 Ghidra 后做什么。

只有分数、置信度和候选间差距满足保守条件时，工具才输出单一 `START HERE`。如果证据不足或多个候选接近，会输出 `START WITH THESE`；如果连候选也不足，则建议从入口点和已保留字符串引用开始。

不要把 `START HERE` 理解为“这里一定是 Flag 检查函数”。它表示“这里最值得先人工确认”。

### 6.3 Ranking / Top Reverse Targets

Ranking 2.2 将独立证据按函数或位置聚合，并考虑输入流、Static Slice、Validation、关键字符串、算法、控制流、运行库噪声和 packed surface 限分。

分数是**人工审查优先级**，不是成功概率或正确率：

- 高分：有多类证据支持，值得先看；
- 中等分：可能有价值，但需要结合 XREF、调用者和分支判断；
- 低分：弱线索或上下文候选，不应据此下结论。

报告或 JSON 中的 `score_breakdown`、`reason`、`recommended_action` 和 `finding_ids` 可用于追溯分数来源。Ranking 当前固定为 2.2，Quick 与 Deep 使用同一排名规则。

### 6.4 Input Flow

`Input Flow` 显示工具识别到的输入来源以及输入进入的寄存器、栈位置或其他目标，例如 `argv[1]`、输入 API 的缓冲区等。

`CONFIRMED`、`LIKELY`、`POSSIBLE` 表示来源关系的证据强度。即使输入源成立，也不意味着它已经被追踪到最终验证位置。

### 6.5 Static Slice、Likely Static Path 与 Partial Input Flow

Slice 是从输入来源出发，沿受限静态数据流连接到变换或 Validation 的路径。常见状态包括：

- `CONFIRMED_SLICE`：当前模型下有较完整、较强的静态连接；
- `LIKELY_SLICE`：主要关系成立，但存在需要人工确认的环节；
- `PARTIAL_SLICE`：只恢复了部分路径；
- 无 Slice：预算、间接调用、别名、优化或运行时行为使路径无法建立。

摘要中的 `->` 表示较强连接，`-?->` 表示路径包含不确定关系。Slice 是有界、路径不敏感的静态结果，不等价于完整污点分析或符号执行。

### 6.6 FLOW BREAK

`FLOW BREAK` 表示工具已把输入追踪到某个位置，但在这里失去可靠的静态关系。输出会给出：

- 中断原因；
- 最后可确认的位置；
- 可能的下一个未解析函数或调用点；
- 支撑这一判断的证据。

这不是错误信息，而是很实用的人工接力点：在 Ghidra 中跳到该 RVA，查看间接调用目标、参数传递、全局对象或返回值使用。

### 6.7 Likely Validation 与 Validation Candidates

Validation 是可能决定输入正确与否的比较或决策位置，例如 comparator、逐字节比较、长度检查、checksum/hash 结果消费，以及比较结果到条件分支的关系。

- `Likely Validation`：摘要中最直接的中高置信、非 context-only 候选；
- `Validation Candidates`：保留更多候选及其类型、RVA 和置信度；
- `context_only=true`：只观察到比较上下文，证据不足以当作可操作的验证点；
- `input_flow_to_validation`：输入是否被静态连接到该候选。

人工确认时应同时检查比较两侧、长度、调用者、成功/失败分支和相关字符串。看到 `memcmp`、`strcmp` 或 `JNE` 本身并不能证明它是 Flag 验证。

### 6.8 Algorithms

算法候选来自常量、操作结构、数据对象和 Slice 关系等证据，可涉及 XOR/rolling transform、CRC、TEA 家族、RC4、AES、Base64 和 lookup/table 类模式。

候选名称表示“证据与该算法相符”，不是完整确认。进入 Ghidra 后仍需核对轮数、常量、数据宽度、key/table 使用位置和输入输出对象。

### 6.9 Control Flow

Control Flow 部分可能提示 switch/jump table、间接调用簇、dispatcher、state machine 或 flattening-like 结构，并给出 dispatcher、case target、state 位置或建议查看动作。

`FLATTENING_LIKE` 和 opaque-like 等描述只是结构提示，不证明控制流一定经过混淆，也不会自动重写 CFG。

### 6.10 Semantic Suggestions

Suggestions 根据已有输入、Slice、Validation、算法和控制流证据，给出便于阅读反编译结果的候选语义，例如：

- 某函数可能承担输入处理、变换、验证或 dispatcher 角色；
- 某对象可能是 `input_buf`、state、lookup table 或 possible key；
- 某内存访问可能具有数组、结构体字段或临时表达式含义。

Suggestions 是**审阅建议**，不是事实。ReverseHelper 不会因为 Suggestion 自动修改 Ghidra 名称。摘要只突出高价值建议，JSON 中可能保留更多中等置信记录。

### 6.11 Interesting Strings

这里列出被分类为较有逆向价值的字符串，并关联 XREF、所属函数、类别和优先级。应优先检查成功/失败文本、输入提示、格式串、路径、命令、编码或算法相关文本的引用函数。

字符串可以帮助定位，但文本单独出现不能证明函数角色。没有字符串也不代表题目不可分析，尤其是 packed、宽字符、运行时解密或无文本题目。

### 6.12 Suggested Static Path

该部分给出最多几个建议步骤，帮助把“先看哪里”转换为检查顺序。它是导航建议，不是程序真实执行路径的证明。

### 6.13 Analysis Warnings 与 Coverage

- `Analysis Warnings`：模块失败、边界不确定、非标准节属性、软预算超时或其他降级信息；
- `Coverage / Truncated`：哪些模块受预算限制；
- Quick 出现截断时，摘要会提示可考虑 `--deep`。

警告应和候选一起阅读。`unknown`、`unavailable` 或 `truncated` 都不能解释为“没有风险”或“没有该逻辑”。

## 7. Deep 模式

### 7.1 使用方法

```powershell
.\ReverseHelper.exe .\challenge.exe --deep
```

Deep 和 Quick 使用同一套分析器、同一 Schema 1.5、同一 Ranking 2.2。Deep 不是另一套旧分析流程；它扩大代码字节、指令、函数、跨函数数据流、算法、CFG、间接目标和语义建议预算。

也可以直接生成 Deep 报告或 Ghidra JSON：

```powershell
.\ReverseHelper.exe .\challenge.exe --deep --report .\reports\deep
.\ReverseHelper.exe .\challenge.exe --deep --ghidra .\reports\challenge-deep.reversehelper.json
```

### 7.2 什么时候值得使用

建议在以下情况使用 Deep：

- Quick 明确列出关键模块截断；
- Quick 没有找到可用起点，但文件规模和静态可见度允许继续扩大扫描；
- 你需要覆盖更多函数、table、CFG 或间接目标；
- 已经在 Ghidra 中看到 Quick 预算之外的可疑区域，希望重新生成更广的注释。

以下情况通常不应立即使用 Deep：

- Quick 已给出清晰、可验证的 `START HERE`；
- 文件明显 packed，真正代码尚未解包；
- 关键逻辑由运行时生成、复杂虚拟机或动态环境决定；
- 你只是想让同一个候选“变得更可信”。Deep 增加覆盖范围，不自动提高准确性。

当前公开基准中，Deep 没有改善 Top-K 或 Slice 命中，反而新增一个 Validation FP，P90 也明显高于 Quick。因此默认应先用 Quick，再根据证据决定是否 Deep。

### 7.3 Quick 与 Deep 对比

| 项目 | Quick | Deep |
|---|---|---|
| 启动方式 | 默认或 `--quick` | `--deep` |
| 分析器与 Schema | 当前统一分析器 / 1.5 | 相同 |
| Ranking | 2.2 | 2.2 |
| 预算 | 较小，优先快速首批结果 | 更大，优先扩大静态覆盖 |
| 适合场景 | 每道新题的第一遍 | Quick 截断或证据不足后的主动复查 |
| 结论可靠性 | 由证据决定 | 不因模式自动提高 |
| 当前实测 P90 | 约 1.38–1.51 秒 | 约 6.09 秒 |

以上时间来自当前公开基准和特定构建环境，不是对任意电脑或样本的性能保证。

## 8. 生成和使用报告

### 8.1 报告组合

```powershell
.\ReverseHelper.exe .\challenge.exe --report
```

未指定目录时写入当前工作目录下的 `reports`。假设目标是 `challenge.exe`，生成：

```text
reports/
├── challenge_report.md
├── challenge_report.html
└── challenge_report.json
```

指定目录：

```powershell
.\ReverseHelper.exe .\challenge.exe --report .\analysis-output
```

也可以只生成一种格式：

```powershell
.\ReverseHelper.exe .\challenge.exe --markdown .\reports\challenge.md
.\ReverseHelper.exe .\challenge.exe --html .\reports\challenge.html
.\ReverseHelper.exe .\challenge.exe --json .\reports\challenge.json
```

- Markdown：适合个人笔记、Writeup 草稿和版本管理；
- HTML：适合浏览器查看；
- JSON：保留最完整的结构化结果，适合 Ghidra 导入、脚本处理和复核证据。

### 8.2 重要 JSON 字段

| 字段 | 含义 |
|---|---|
| `schema_version` | 当前 Quick/Deep Schema，`0.2.0b1` 为 `1.5` |
| `basic`、`hashes` | 目标身份、架构、入口点和哈希 |
| `packing` | 壳迹象、静态可见度和建议 |
| `challenge_summary` | 终端摘要使用的结构化结果 |
| `input_sources` | 输入来源候选 |
| `static_slices` | 输入到变换/验证的静态 Slice |
| `static_flow_breaks` | 静态追踪中断及人工接力位置 |
| `validation_candidates` | Validation 候选及决策关系 |
| `algorithm_candidates` | 算法和 key/table 关系候选 |
| `control_flow_findings` | switch、dispatcher、state-machine 等结构候选 |
| `decompiler_suggestions` | 审阅式语义建议 |
| `reverse_targets` | Ranking 2.2 排序结果 |
| `annotations` | 供 Ghidra 等工具使用的统一注释 |
| `result_status` | facts、candidates、suggestions、unavailable、truncated 的解释与状态 |
| `analysis_warnings` | 模块失败、降级或预算信息 |
| `truncated_modules` | 明确受限的模块列表 |
| `analysis_limits` | 本次 Quick/Deep 使用的预算 |
| `module_timings_ms` | 部分昂贵阶段的耗时 |
| `analysis_elapsed_ms` | 本次分析总耗时 |

JSON 消费脚本应忽略不认识的新字段，不应依赖字段顺序。

## 9. Ghidra 集成

### 9.1 生成 Ghidra JSON

默认 Quick + Ghidra 导出：

```powershell
.\ReverseHelper.exe "C:\CTF\Challenges\warmup\warmup.exe" --ghidra
```

如果当前 PowerShell 目录是便携包目录，会生成：

```text
.\reports\warmup.reversehelper.json
```

`--ghidra` 的默认目录取决于**当前工作目录**，不一定是目标 PE 所在目录。为避免找不到文件，推荐在比赛中显式指定路径：

```powershell
.\ReverseHelper.exe "C:\CTF\Challenges\warmup\warmup.exe" `
  --ghidra "C:\CTF\Challenges\warmup\warmup.reversehelper.json"
```

### 9.2 在 Ghidra 中导入

1. 在 Ghidra 中导入与 JSON 对应的同一个 PE。
2. 打开 CodeBrowser，并先完成基础 Auto Analyze。
3. 打开 **Window → Script Manager**。
4. 点击 **Manage Script Directories**，添加便携包解压目录；也可以把 `ImportReverseHelperFindings.py` 复制到已有 Ghidra script 目录。
5. 刷新脚本列表，在 `ReverseHelper` 分类运行 `ImportReverseHelperFindings.py`。
6. 在文件选择窗口中选择 `.reversehelper.json`。
7. 导入完成后，通过 Bookmarks 或 Listing 中的 Plate Comments 查看 ReverseHelper 标记。

导入器优先比较 JSON 中的 SHA-256 与当前 Ghidra 程序哈希；如果当前环境无法提供哈希，才退回文件名比较。身份不匹配时会拒绝导入。每个 RVA 都按当前 Ghidra ImageBase 重定位，未映射地址会跳过。

当前统一 annotations 路径默认只添加 **Bookmark 和 Plate Comment**，不会自动重命名函数，也不会覆盖用户已有名称。已有 Plate Comment 会被保留；ReverseHelper 内容会追加在后面。由于真实 Ghidra UI 的重复导入尚未完成外部验证，正式题目中建议先保存工程快照。

### 9.3 `RH:*` annotations 含义

| 标记 | 含义 | 推荐人工动作 |
|---|---|---|
| `RH:START` | 当前最优先的起点 | 先看调用者、参数、XREF 和后继分支 |
| `RH:INPUT` | 输入来源或输入写入位置 | 确认 API 参数、缓冲区和长度 |
| `RH:SLICE` | 输入可达的变换位置 | 顺着 def-use 检查变换前后对象 |
| `RH:VALIDATION` | 可能的验证/比较位置 | 检查比较两侧及成功/失败分支 |
| `RH:ALGORITHM` | 中高置信算法候选 | 核对常量、轮数、宽度、key/table 和调用关系 |
| `RH:FLOW_BREAK` | 静态跟踪失去可靠关系的位置 | 手工解析间接目标、别名、全局对象或返回值 |
| `RH:DISPATCHER` | 可能的 dispatcher | 先标记 state 写入，再划分 case/handler |
| `RH:SWITCH`、`RH:JUMP_TABLE` 等 | 具体控制流结构候选 | 核对 selector 范围和目标表 |
| `RH:SUGGEST_*` | 反编译阅读建议 | 人工确认后再决定是否命名或改类型 |

`RH:SUGGEST_*` 的后缀可能对应函数角色、对象角色、变量/global rename 建议、数组提示或临时表达式分组。它们始终是建议，不应批量无审查地应用。

每条 annotation 在 JSON 中包含：

- `rva`：相对虚拟地址；
- `category`：`RH:*` 标记；
- `title` 和 `comment`：标题与建议动作；
- `confidence`：证据强度；
- `evidence`：证据摘要；
- `fact_status`：当前为需要复核的 candidate。

## 10. 完整 CTF Reverse 实战工作流

推荐流程是：

### 第一步：DIE / PE-bear 做格式与壳初筛

用 DIE 判断文件类型、编译器/壳线索，用 PE-bear 查看 PE Header、节区、入口点、导入表和异常布局。记录：

- x86 还是 x64；
- 是否疑似 packed；
- Entry Point 是否位于异常节；
- 导入是否过少或明显在运行时解析。

这一步不被 ReverseHelper 替代。DIE 的签名和 PE-bear 的结构视图通常比通用启发式更适合确认文件外观。

### 第二步：先跑 ReverseHelper Quick

```powershell
.\ReverseHelper.exe .\challenge.exe --report .\reports --ghidra .\reports\challenge.reversehelper.json
```

先读终端顶部，不要立刻浏览全部报告：

1. Packing / Static visibility；
2. `START HERE` 或 `START WITH THESE`；
3. Input Flow、Slice 或 `FLOW BREAK`；
4. Likely Validation；
5. Suggested Static Path；
6. Warnings / Truncated。

### 第三步：在 Ghidra 中验证候选

导入同一目标，完成 Auto Analyze，再导入 ReverseHelper JSON。按以下顺序检查：

1. `RH:START` 的调用者和被调用者；
2. `RH:INPUT` 到 `RH:SLICE`/`RH:VALIDATION` 的对象是否真是同一份输入；
3. Validation 两侧数据、长度和分支含义；
4. `RH:ALGORITHM` 的常量和循环结构；
5. `RH:FLOW_BREAK` 或 `RH:DISPATCHER` 的间接目标与 state 更新；
6. 确认后再手工重命名、改类型和添加自己的注释。

如果 Quick 已给出可验证路径，继续人工逆向即可。只有在覆盖明显不足时才跑 Deep，并可用独立文件名保存 Deep JSON，避免混淆两轮证据。

### 第四步：必要时使用 x64dbg

当静态分析无法确认运行时值、解包后代码、间接调用目标或分支条件时，再进入隔离的调试环境。可以生成建议断点：

```powershell
.\ReverseHelper.exe .\challenge.exe `
  --x64dbg-script .\reports\challenge.x64dbg
```

脚本只导出带 RVA 的 HIGH/MEDIUM ReverseTarget，并使用 `module:$RVA` 形式适配 ASLR。加载前必须确认：

- x64dbg/x32dbg 中加载的是同一文件；
- 模块名与脚本一致；
- 断点只是建议位置，不保证一定命中关键逻辑；
- 对未知或恶意样本使用隔离虚拟机，ReverseHelper 的“静态不执行”边界不延伸到调试器。

如果目标文件名含空格或其他不安全字符，ReverseHelper 可以正常分析，但 x64dbg 脚本导出会拒绝不安全的模块表达式。需要脚本时，可先制作一个合法授权的工作副本并使用只含字母、数字、下划线、点或连字符的文件名重新分析。

## 11. 完整可执行示例

### 示例 A：最简单 Quick 分析

```powershell
cd C:\CTF\Tools\ReverseHelper-0.2.0b1-win-x64
.\ReverseHelper.exe "C:\CTF\Challenges\baby-re\baby-re.exe"
```

操作目标：先得到 `START HERE`、Validation 和 Ghidra 中应优先检查的 RVA。若有明确起点，直接进入 Ghidra，不必为了“更多输出”先跑 Deep。

### 示例 B：Quick → Ghidra → 按需 Deep

```powershell
cd C:\CTF\Tools\ReverseHelper-0.2.0b1-win-x64

.\ReverseHelper.exe "C:\CTF\Challenges\level2\level2.exe" `
  --report "C:\CTF\Challenges\level2\reports\quick" `
  --ghidra "C:\CTF\Challenges\level2\reports\level2-quick.reversehelper.json"
```

然后：

1. 在 Ghidra 导入 `level2.exe` 并完成 Auto Analyze；
2. 运行 `ImportReverseHelperFindings.py`；
3. 选择 `level2-quick.reversehelper.json`；
4. 从 `RH:START` 开始验证 Input → Slice → Validation；
5. 如果 Quick 显示关键模块截断，或 Ghidra 中发现大量预算外代码，再执行：

```powershell
.\ReverseHelper.exe "C:\CTF\Challenges\level2\level2.exe" --deep `
  --report "C:\CTF\Challenges\level2\reports\deep" `
  --ghidra "C:\CTF\Challenges\level2\reports\level2-deep.reversehelper.json"
```

把 Quick 与 Deep 结果分目录保存。若 Deep 只是增加低置信候选，应保留 Quick 的原始判断顺序并继续人工复核。

## 12. 其他参数

### 12.1 输出控制

- `--quiet`：不显示分析摘要表格，适合只生成文件；报告写入提示仍可能显示。
- `--verbose`：在普通摘要后显示分析 profile、完整预算字典和截断模块。
- `--min-string-length N`：最短字符串长度，`N` 不得小于 3，默认 4。
- `--max-strings N`：最多保留的字符串数，必须为正数，默认 2000。

### 12.2 单模块诊断

以下是保留的高级诊断模式：

```powershell
.\ReverseHelper.exe .\challenge.exe --only anomaly
.\ReverseHelper.exe .\challenge.exe --only strings
.\ReverseHelper.exe .\challenge.exe --only imports
.\ReverseHelper.exe .\challenge.exe --only antidebug
.\ReverseHelper.exe .\challenge.exe --only validation
.\ReverseHelper.exe .\challenge.exe --only crypto
.\ReverseHelper.exe .\challenge.exe --only targets
```

`--quick`、`--deep` 和 `--only` 互斥。`--only` 不能与 `--report`、`--json`、`--html`、`--markdown` 或 `--ghidra` 组合；它不是首次使用者的正常入口。

## 13. 已知限制和不适用场景

### 13.1 支持范围

当前重点支持 Windows PE x86/x64。以下目标不属于本版本支持范围：

- ELF、Mach-O；
- .NET/其他 managed assembly 的高级语义；
- 任意固件和裸二进制；
- 需要专用 VM 语义、运行时 JIT 或自修改代码才能看见的逻辑。

### 13.2 静态分析边界

ReverseHelper 是有界、路径不敏感的静态工具：

- 不执行或模拟样本；
- 不自动脱壳；
- 不做完整 SSA、通用污点或完整符号执行；
- 不恢复运行时生成代码；
- 不保证函数边界、输入流、算法、控制流或类型建议完全正确；
- 不因“没有发现”而证明某种逻辑不存在。

### 13.3 Packed / obfuscated 样本

壳检测是启发式的，当前公开样本上的 packed recall 仍较低。DIE 判定和人工节区/入口检查仍然重要。若当前代码不可见，Quick 和 Deep 都不能代替解包；应在合法、隔离环境中取得 unpacked dump 后重新分析。

### 13.4 工具集成边界

- Ghidra：统一 JSON importer 已通过自动化逻辑测试，但真实 CodeBrowser UI 仍需用户环境验证；
- IDA：当前没有等价的深度 importer；可根据报告中的 RVA 手动跳转；
- x64dbg：只生成建议断点脚本，不控制调试器、不执行目标；
- DIE/PE-bear：与 ReverseHelper 配合使用，没有自动联动。

### 13.5 不应做出的结论

不要从输出直接得出以下结论：

- “分数 90 表示 90% 正确”；
- “没有 START HERE 就没有验证函数”；
- “出现 AES/TEA 常量就一定用了该算法”；
- “出现 FLOW BREAK 表示工具崩溃”；
- “Deep 的结果一定比 Quick 正确”；
- “ReverseHelper 没有执行样本，所以随后在 x64dbg 执行也天然安全”。

## 14. 常见错误与排查

### 14.1 `Input file does not exist`

目标路径错误。使用绝对路径，或先运行：

```powershell
Test-Path "C:\完整路径\challenge.exe"
```

路径含空格时加引号。

### 14.2 `Input path is a directory, not a PE file`

传入了目录而不是文件。命令最后一个位置参数必须是具体 EXE、DLL、SYS 或其他 PE 文件。

### 14.3 `Input is not a PE file: missing MZ signature`

文件不是标准 PE、已经损坏，或题目故意修改了 DOS signature。ReverseHelper 会以退出码 2 安全结束。可先用十六进制工具、DIE 或 PE-bear 确认格式；不要为了绕过检查直接修改原始题目文件。

### 14.4 `Could not read input file`

检查文件权限、文件是否被其他程序独占、压缩包是否完整解压，以及安全软件是否隔离了文件。不要直接关闭安全软件；优先在隔离的 CTF/恶意样本实验环境中处理。

### 14.5 报告没有生成或退出码为 3

退出码 3 表示报告或 x64dbg 脚本写入失败。检查：

- 输出目录是否可写；
- 路径是否合法；
- 文件是否正被编辑器占用；
- x64dbg 输出扩展名是否为 `.txt` 或 `.x64dbg`；
- 目标模块名是否只含安全字符。

分析结果可能仍已在终端显示，其他成功格式也可能已经写出。

### 14.6 Quick 显示 `Truncated`

先看被截断的是哪个模块。如果已有明确 `START HERE`，通常先去 Ghidra 验证更划算；如果关键路径缺失，再运行 `--deep`。不要把截断理解为文件损坏。

### 14.7 Deep 仍然没有找到关键函数

可能原因包括 packed、运行时生成代码、复杂间接调用、优化比较、未支持输入方式、managed code 或静态模型之外的别名关系。回到 DIE/PE-bear 和 Ghidra，检查入口、导入、字符串 XREF、调用图及动态需求。Deep 不是自动兜底求解器。

### 14.8 Ghidra 提示 SHA-256 或文件名不匹配

不要强行导入。确认 Ghidra 中打开的文件与 ReverseHelper 分析的文件完全一致。常见原因是：

- 分析了原文件，但 Ghidra 打开的是 unpacked/patched 副本；
- Quick 和 Deep JSON 来自另一道题；
- 文件被重命名，且当前 Ghidra 环境无法提供 SHA-256，只能退回文件名校验。

应对正确副本重新运行 ReverseHelper 并生成新 JSON。

### 14.9 Ghidra 中看不到 `RH:*`

检查：

1. 是否运行了 `ImportReverseHelperFindings.py` 而不是其他脚本；
2. 是否选择了 `.reversehelper.json`；
3. Ghidra 是否已完成 Auto Analyze；
4. Bookmarks 窗口是否显示对应分类；
5. JSON 顶层 `annotations` 是否为空；
6. 相关 RVA 是否落在 Ghidra 已映射内存中。

旧 JSON 没有 `annotations` 时，导入器会退回 findings/targets 兼容路径。

## 15. FAQ

### ReverseHelper 会运行题目吗？

不会。核心分析只读取 PE。只有你后来主动在 x64dbg 等调试器中运行目标时，才进入动态执行阶段。

### 需要联网或登录吗？

不需要。便携核心没有账号、API Key、云端或 LLM 前置条件。

### 每道题都应该先跑 Deep 吗？

不应该。先跑 Quick；只有截断或覆盖不足确实影响下一步时再 Deep。

### 为什么没有 `START HERE`？

工具拒绝在证据不足时制造确定性。查看 `START WITH THESE`、入口点、Interesting Strings、Validation Candidates 和 warnings。

### Ranking 分数能直接比较不同题目吗？

不建议。分数主要用于同一次分析内安排检查顺序，不是跨题难度或成功概率。

### Suggestion 可以直接批量应用吗？

不建议。当前 Ghidra annotation 路径只导入 Comment/Bookmark；函数名、变量名和类型应由逆向者确认后手工应用。

### 可以分析 DLL 或 SYS 吗？

CLI 接受 EXE、DLL、SYS 和其他 PE 文件，但核心目标仍是 x86/x64 Windows PE 静态初筛。入口和输入模型对非常规驱动、内核环境或特殊加载流程可能覆盖不足。

### 能分析恶意软件吗？

技术上可以读取 PE，但本项目定位是 CTF Reverse。对真实恶意样本应使用专业隔离环境、组织流程和对应工具，不应因为 ReverseHelper 本身不执行样本而降低操作安全标准。

### 能自动生成 Solver 或 Flag 吗？

不能。`0.2.0b1` 不提供自动 Solver，算法和数据对象只作为人工逆向证据。

### Phase 5 是否必须安装或启用？

不是。当前 `0.2.0b1` 的用户流程完整建立在已完成并关闭的 Phase 1–4 上；Phase 5 不属于当前版本或使用前置条件。

## 16. 退出码

| 退出码 | 含义 |
|---:|---|
| `0` | 分析及所请求输出成功 |
| `2` | 输入、PE 解析或分析失败；命令参数错误也由参数解析器以 2 结束 |
| `3` | 报告或 x64dbg 脚本写入失败 |

可在 PowerShell 中查看最近一次退出码：

```powershell
$LASTEXITCODE
```

## 17. 从源码运行（可选）

普通用户优先使用便携包。需要从源码运行时，要求 Python 3.10+：

```powershell
cd C:\path\to\ReverseHelper
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\reversehelper.exe C:\path\to\challenge.exe
```

这与便携 EXE 使用相同 CLI。依赖安装需要在赛前准备；核心分析本身不需要网络。

## 18. 当前文档一致性说明

本说明书以 `0.2.0b1` 当前代码行为为准。核对时发现以下旧文档需要后续同步，但不影响本说明书中的命令执行：

1. `scripts/README.md` 末尾仍写成 `v0.1.0`，应更新为当前 Beta 状态。
2. `scripts/README.md` 和 `docs/usage.md` 仍笼统描述显式 high-confidence Rename；对当前带顶层 `annotations` 的 `0.2.0b1` JSON，导入器优先走统一 annotation 路径，实际不会自动 Rename。当前用户应按 Comment/Bookmark-only 理解。
3. `docs/design.md` 和 `docs/phase6-validation.md` 保存了旧 `v0.1.0` 架构/验证记录，其中“尚无当前 Deep/Schema”的表述属于历史内容，不应作为 `0.2.0b1` 用户说明。
4. Windows x64 单文件包已完成本机打包和运行验证，但独立干净 Windows、真实 Ghidra UI 导入仍未完成外部验证。首次比赛使用前应在目标机器演练一次。

这些差异没有导致 Quick、Deep、报告或 Ghidra JSON 命令无法执行，因此本次只记录，不修改程序功能。
