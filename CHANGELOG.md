# ReverseHelper 更新日志

ReverseHelper 在 `0.0.x` 阶段仍处于早期开发期。版本号用于区分可下载、可复现的功能快照；默认分析仍然只读取目标 PE，不会执行它。

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
