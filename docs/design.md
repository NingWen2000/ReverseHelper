# ReverseHelper 设计说明

## 目标与边界

ReverseHelper 负责 PE 文件的静态初筛，目的是把人工逆向前最常查的一组信息统一提取出来，并明确展示规则为什么触发。工具不会加载或执行目标，不尝试自动脱壳，也不把启发式结果包装成确定结论。

## 数据流

```text
目标文件
  ├─ 文件校验与哈希
  ├─ pefile 解析 PE 结构
  │    ├─ Headers
  │    ├─ Sections + RVA/RAW + Entropy
  │    ├─ Imports + 可疑 API 规则
  │    └─ Exports
  ├─ 原始字节扫描
  │    ├─ EntryPoint 字节与简单入口桩
  │    ├─ ASCII / UTF-16LE + RAW/RVA/VA 映射
  │    ├─ 可执行节 00/CC 填充区
  │    └─ Crypto constants
  ├─ Capstone 指令分析（仅可执行节的 raw bytes）
  │    ├─ x86/x64 指令与控制转移
  │    ├─ Anti-Debug / Crypto / Validation / Input Findings
  │    ├─ ReverseTarget 排序、局部合并和 finding_ids 追溯
  │    └─ Analysis Path / Unresolved Questions
  ├─ 加壳与结构异常启发式
  ├─ 可解释风险评分
  └─ Rich 终端 / Markdown / JSON / HTML / x64dbg script
```

`reversehelper.analyzer.ReverseHelperAnalyzer` 是高层入口，负责汇总分析结果，并把 `Finding` 和 `ReverseTarget` 转成 JSON 可序列化的字典。报告层只读取汇总结果，不接触 `pefile.PE` 对象。

## 模块职责

- `pe_parser.py`：文件校验、PE Header、哈希、导入导出与节区的统一解析。
- `section_analyzer.py`：RVA 到 RAW 转换、节区权限和 Shannon Entropy。
- `addressing.py`：把文件偏移映射为节区、RVA 和 VA。
- `entry_analyzer.py`：读取入口字节，识别少量明确的相对跳转/紧凑解密桩。
- `code_cave_analyzer.py`：列出可执行节的长填充区，交给人工确认是否能用于补丁。
- `import_analyzer.py`：IAT/EAT 解析及 Windows API 分类规则。
- `string_analyzer.py`：ASCII/UTF-16LE 提取和可疑内容分类。
- `disassembler.py` / `control_flow_analyzer.py`：受 raw section 边界约束的 x86/x64 解码和基础控制转移分类。
- `instruction_context.py`：共享连续性、寄存器/EFLAGS 覆盖检查和保守的导入调用解析。
- `anti_debug_analyzer.py`：组合 API、PEB/特殊指令和分支上下文。
- `crypto_analyzer.py`：保留常量检测，并组合 TEA-family/RC4 指令证据。
- `validation_analyzer.py`：定位 comparator/input 调用点，验证返回值到条件分支的局部语义链。
- `target_ranker.py` / `dynamic_advisor.py`：把 Findings 组织为可追溯目标、分析路径和未决问题。
- `x64dbg_exporter.py`：以 module-relative RVA 输出 HIGH/MEDIUM 建议断点。
- `packer_detector.py`：相互独立、带证据的加壳/异常信号。
- `risk.py`：把信号压缩为 0–10 分，同时保留每项得分理由。
- `reporting.py`：生成 Markdown、JSON 和不依赖外部资源的 HTML，旧字段继续保留。
- `console.py` / `cli.py`：终端显示、参数、退出码和文件写入。

## 风险评分

评分不是机器学习模型，也不是恶意性概率。当前权重：

- 可疑导入 API：按 low/medium/high 累加，最多 3 分。
- 加壳与节区异常：按启发式证据累加后折算，最多 5 分。
- 高信号字符串：命令、凭据、调试、网络类别，最多 1.5 分。
- PE 结构警告：最多 0.5 分。

分级阈值为 `LOW < 3`、`MEDIUM < 6`、`HIGH < 8`、其余为 `CRITICAL`。这些阈值服务于演示和分析排序，不能用于生产阻断策略。

Target Priority 与风险分数分开计算。`target_ranker.py` 还会读取 Finding 的标题、理由和证据中的关键词，因此修改这些输出文案也可能改变目标评分和排序，不能按纯展示文字处理。

## 地址与容错

RVA 是静态位置的核心标识。Preferred VA 只用于静态显示，不能当作 ASLR 后的运行时地址；x64 RIP-relative 间接转移解析到的是 pointer slot，不等于最终函数地址。反汇编长度始终受 Section `RawSize` 和文件长度约束，`VirtualSize > RawSize` 的虚拟尾部不会被当作文件字节。

PE 结构解析失败属于整体失败。字符串、入口、反汇编、控制流和各 Finding 分析器属于可隔离模块：某个模块异常时记录 `analysis_warnings` 并继续运行其他模块。共享的 Capstone detail 和导入调用解析只计算一次，避免 Anti-Debug、Validation 和 Input 重复解码。

## 安全考虑

- 输入始终以普通二进制数据读取，不调用目标文件。
- 生成报告时对 HTML 和 Markdown 中的样本字符串进行转义。
- `.gitignore` 默认排除 PE、转储、生成报告和本地环境文件。
- 仓库不附带 CrackMe、CTF 题目或恶意样本。
- 对恶意构造 PE 的解析风险主要来自第三方解析库；分析未知样本时仍建议在隔离环境运行工具。

## 扩展方式

新增检测规则时，优先返回规则标识和可复查证据。v0.1.0 不计划引入完整 CFG、SSA、污点或符号执行；需要跨函数语义时，把问题留在 `unresolved_questions`，交给 Ghidra/x64dbg 人工验证。
