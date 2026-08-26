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
  │    ├─ ASCII / UTF-16LE
  │    └─ Crypto constants
  ├─ 加壳与结构异常启发式
  ├─ 可解释风险评分
  └─ Rich 终端 / Markdown / JSON / HTML
```

`reversehelper.analyzer.ReverseHelperAnalyzer` 是唯一的高层入口。各分析模块返回只包含 JSON 可序列化类型的字典，报告层不接触 `pefile.PE` 对象，因此后续可以比较容易地增加 Web/TUI 前端。

## 模块职责

- `pe_parser.py`：文件校验、PE Header、哈希、导入导出与节区的统一解析。
- `section_analyzer.py`：RVA 到 RAW 转换、节区权限和 Shannon Entropy。
- `import_analyzer.py`：IAT/EAT 解析及 Windows API 分类规则。
- `string_analyzer.py`：ASCII/UTF-16LE 提取和可疑内容分类。
- `crypto_analyzer.py`：已知常量的精确字节匹配。
- `packer_detector.py`：相互独立、带证据的加壳/异常信号。
- `risk.py`：把信号压缩为 0–10 分，同时保留每项得分理由。
- `reporting.py`：生成 Markdown、JSON 和不依赖外部资源的 HTML。
- `console.py` / `cli.py`：终端显示、参数、退出码和文件写入。

## 风险评分

评分不是机器学习模型，也不是恶意性概率。当前权重：

- 可疑导入 API：按 low/medium/high 累加，最多 3 分。
- 加壳与节区异常：按启发式证据累加后折算，最多 5 分。
- 高信号字符串：命令、凭据、调试、网络类别，最多 1.5 分。
- PE 结构警告：最多 0.5 分。

分级阈值为 `LOW < 3`、`MEDIUM < 6`、`HIGH < 8`、其余为 `CRITICAL`。这些阈值服务于演示和分析排序，不能用于生产阻断策略。

## 安全考虑

- 输入始终以普通二进制数据读取，不调用目标文件。
- 生成报告时对 HTML 和 Markdown 中的样本字符串进行转义。
- `.gitignore` 默认排除 PE、转储、生成报告和本地环境文件。
- 仓库不附带 CrackMe、CTF 题目或恶意样本。
- 对恶意构造 PE 的解析风险主要来自第三方解析库；分析未知样本时仍建议在隔离环境运行工具。

## 扩展方式

新增检测规则时，优先返回：规则标识、严重度、具体证据和权重。新增输出端只应消费分析结果字典，不应重复解析 PE。若未来引入 YARA、Capstone 或图分析，应作为可选依赖，避免让基础安装变重。
