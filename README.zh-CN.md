# ReverseHelper

[简体中文](README.zh-CN.md) | [English](README.md)

面向 CTF 逆向选手的离线静态分析工具。它把未知 Windows PE 整理成一份可操作的初步分析地图：输入从哪里进入、可能在哪里变换与验证、有哪些算法和控制流证据、建议从哪里开始阅读。工具只读取目标，不执行或上传样本。

当前源码版本：**0.2.0b2 Beta**，属于发布后的简体中文本地化。主路线 Phase 1–4 保持完成并关闭。本版本使用同一分析引擎、Ranking 2.2 和 Schema 1.5；语言只影响人类可读展示。已发布的 b1 包保持原样。

## 一条命令开始

```powershell
reversehelper .\challenge.exe --lang zh-CN
```

默认使用 Quick（快速分析）模式，首先显示目标、架构、加壳情况和静态可见性，然后给出“建议从这里开始”或多个保守的候选起点。输入数据流、静态数据流切片（Static Slice）、静态追踪中断点、验证逻辑、算法、控制流和语义建议帮助你决定下一步检查什么。

未指定 `--lang` 时始终保持英文，不根据系统语言自动切换。可用值为 `en` 和 `zh-CN`；其他值明确报错。帮助也支持中文：

```powershell
reversehelper --lang zh-CN --help
reversehelper .\challenge.exe --lang en
```

## Quick / Deep

Quick 使用有限预算，适合首次阅读。若提示截断或静态证据不足，可以使用 Deep（深入静态分析）模式提高预算：

```powershell
reversehelper .\challenge.exe --lang zh-CN --deep
```

Deep 使用同一分析器和数据格式，增加解码、函数、数据流、算法、控制流和语义分析的预算。它扩大覆盖范围，不保证推断更加确定，也不执行目标。

## 输出与 Ghidra 工作流

```powershell
reversehelper .\challenge.exe --lang zh-CN --report .\reports
reversehelper .\challenge.exe --lang zh-CN --json .\reports\challenge.json
reversehelper .\challenge.exe --lang zh-CN --ghidra
```

`--report` 生成 `<目标名>_report.md`、`.html` 和 `.json`。Markdown/HTML 跟随语言；JSON 的结构、分析事实、枚举及原有说明保持不变，便于脚本比较。文件名规则不随语言变化。

`--ghidra` 默认生成 `reports\challenge.reversehelper.json`。在 Ghidra 打开同一文件，运行随附的 `ImportReverseHelperFindings.py` 并选择此 JSON。导入前检查 SHA-256 或文件名，默认只添加注释和书签，不自动重命名。中文导出仅改变 `annotations[].title/comment`，`RH:START`、`RH:VALIDATION`、`RH:SLICE`、`RH:SUGGEST_*` 等分类不变。`--json` 与 `--ghidra` 可以同时指定各自输出路径。

参阅 [快速开始](QUICKSTART.zh-CN.md)、[比赛工作流](docs/workflow.zh-CN.md)、[限制](docs/limitations.zh-CN.md)和[术语表](docs/terminology.zh-CN.md)。

## 核心能力

- 读取 PE32/PE32+ 的身份、节区、导入导出和入口点。
- 分类值得关注的字符串，将交叉引用关联到函数。
- 在预算内恢复函数边界、逻辑块、输入来源、比较与决策位置。
- 构建保守的输入到验证逻辑切片；无法继续追踪时报告最后已证实的位置。
- 根据独立证据类别、分数上限以及运行库/加壳惩罚排列阅读优先级。
- 识别 XOR、滚动变换、CRC、TEA 系列、RC4、AES、Base64 与数据表证据。
- 解释部分 switch、跳转表、分发器、状态机和间接控制流结构。
- 提供需要人工复查的反编译器语义建议。
- 导出 Markdown、HTML、稳定 JSON、Ghidra 注释和支持 ASLR 的 x64dbg 建议脚本。

这些结果是静态候选，不是已解出的题目。没有输出不代表相关行为不存在。

## Windows x64 便携包

本地构建产物为 `ReverseHelper-0.2.0b2-win-x64.zip`。解压到可写目录后，无需安装 Python：

```powershell
.\ReverseHelper.exe --version
.\ReverseHelper.exe "C:\CTF\题目\challenge.exe" --lang zh-CN
```

从 [v0.2.0b2 发布页](https://github.com/NingWen2000/ReverseHelper/releases/tag/v0.2.0b2) 下载便携包及 SHA-256 校验文件。该 Beta 预发布保留所有旧版下载文件。包内附带中英文快速开始、文档和 Ghidra 导入脚本；其中本地化报告保留发布前的验证记录。详见[本版发布说明](docs/releases/v0.2.0b2.md)。

## 从源码安装

需要 Python 3.10 或更新版本：

```powershell
git clone https://github.com/NingWen2000/ReverseHelper.git
cd ReverseHelper
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\reversehelper.exe .\challenge.exe --lang zh-CN
```

构建便携包：

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[release]"
.\scripts\build-portable.ps1
```

运行无需账号、API key、网络或 LLM，也没有新增国际化运行时依赖。

## 已测量的能力与当前限制

公开基准共有 40 个固定位置，31 个可用/冻结，9 个仍待补充。既有 Phase 3 基线包含 30 个可分析样本及 1 个预期解析失败的畸形样本。本轮没有修改基准定义或重新宣称能力提升。

| 指标 | 既有基线 |
|---|---|
| 关键函数 Top-1 / Top-3 / Top-5 | 56.67% / 60.00% / 60.00% |
| 发出 START HERE 时的精确率 | 100% |
| 验证逻辑 TP / FP / FN | 8 / 3 / 14 |
| 可操作切片 TP / FP / FN | 8 / 0 / 14 |
| 算法 TP / FP / FN | 2 / 0 / 0 |
| 控制流 TP / FP / FN | 1 / 0 / 0 |
| 语义角色 TP / FP / FN | 3 / 0 / 0 |

算法、控制流及语义样本分母很小，不能据此宣称普遍准确率。尚无真人 TTCF 测量结果，不宣称缩短了解题时间。完整定义见[基准文档](benchmarks/README.md)。

支持重点为 Windows PE x86/x64。加壳、混淆、运行时生成代码、堆别名、托管程序集及非 PE 输入可能超出模型。分析有界且不区分路径；“未知”不能理解为“安全”或“不存在”。独立干净 Windows 和真实 Ghidra UI 重复导入的验证限制见[本地化报告](docs/simplified-chinese-localization-report.md)。

开发者/debug 诊断、原始证据详情、旧 `--only` 单模块诊断和 x64dbg 脚本注释保留英文；默认 Quick/Deep 的主要界面为中文。样本字符串、API、函数名、地址和代码类型原样保留。

工具不脱壳、不模拟、不符号执行、不自动求解或打补丁。IDA 深度集成及 solver 生成继续延后，动态观察属于 TraceInfer；本轮不增加相关功能。

## 开发

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -m pytest
```

参阅 [CONTRIBUTING](CONTRIBUTING.md)、[路线图](docs/roadmap.md)和[更新日志](CHANGELOG.md)。采用 [MIT](LICENSE) 许可证。
