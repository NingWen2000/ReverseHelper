# ReverseHelper 使用说明

这份说明面向第一次使用 ReverseHelper 的同学。整个流程只做静态读取，不会运行待分析的 EXE/DLL，但未知样本仍建议放在隔离虚拟机中处理。

## 1. 准备环境

需要：

- Python 3.10 或更高版本
- Windows PowerShell
- 一个合法获得、允许分析的 Windows PE 文件
- 可选：Ghidra，用于继续检查反编译结果和交叉引用

打开 PowerShell，进入项目目录：

```powershell
cd C:\Users\你的用户名\Desktop\ReverseHelper
```

项目已经有 `.venv` 时，可以直接激活：

```powershell
.\.venv\Scripts\Activate.ps1
```

第一次从 GitHub 下载时，执行：

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e .
```

如果 PowerShell 不允许执行激活脚本，不必修改系统策略，直接使用虚拟环境中的 Python：

```powershell
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\python.exe main.py --help
```

## 2. 第一次分析

假设待分析文件位于：

```text
samples\hello.exe
```

使用安装后的命令：

```powershell
reversehelper .\samples\hello.exe
```

或者使用源码入口：

```powershell
python main.py .\samples\hello.exe
```

正常情况下会依次显示：

1. 文件名、大小、架构、ImageBase、EntryPoint 和 SHA-256；
2. 节区 RVA、RAW 大小、权限和 Entropy；
3. Import/Export 数量与规则匹配的 API；
4. URL、命令、凭据、调试、网络、CTF 等字符串；
5. 加壳或结构异常信号；
6. 密码学常量；
7. `0–10` 的可解释风险分数。

## 3. 选择分析模式

默认命令运行完整分析：

```powershell
reversehelper .\samples\hello.exe
```

需要先快速查看 PE 结构、入口点、导入/导出和加壳异常时，使用：

```powershell
reversehelper .\samples\hello.exe --quick
```

快速模式不会运行完整字符串、密码学常量和代码洞扫描，因此其中的结构风险分数不能与完整分析分数直接比较。

只检查一个模块时，使用：

```powershell
reversehelper .\samples\hello.exe --only anomaly
reversehelper .\samples\hello.exe --only strings
reversehelper .\samples\hello.exe --only imports
```

`--quick` 和 `--only` 不能同时使用。部分分析模式不生成完整报告；需要报告时使用默认完整分析命令配合报告参数，避免把未运行的模块误写成“未发现”。

## 4. 生成报告

一次生成 Markdown、JSON、HTML 三种报告：

```powershell
reversehelper .\samples\hello.exe --report
```

默认输出到 `reports`：

```text
reports/
├── hello_report.md
├── hello_report.json
└── hello_report.html
```

- Markdown：适合放进分析笔记或 Writeup。
- JSON：适合后续脚本处理、批量比较和前端开发。
- HTML：浏览器直接打开，适合演示和截图。

指定输出目录：

```powershell
reversehelper .\samples\hello.exe --report .\my-reports
```

只生成一种报告：

```powershell
reversehelper .\samples\hello.exe --json .\reports\hello.json
reversehelper .\samples\hello.exe --markdown .\reports\hello.md
reversehelper .\samples\hello.exe --html .\reports\hello.html
```

生成报告但不显示终端表格：

```powershell
reversehelper .\samples\hello.exe --report --quiet
```

## 5. 字符串参数

默认提取长度至少为 4 的 ASCII 和 UTF-16LE 字符串，并最多保留 2000 条。

```powershell
reversehelper .\samples\hello.exe --min-string-length 6 --max-strings 5000
```

提高最小长度可以减少噪声；提高最大数量适合体积较大的 PE，但会增加报告体积。完整参数可用以下命令查看：

```powershell
reversehelper --help
```

## 6. 如何阅读结果

### ImageBase、RVA、VA 与 RAW

- ImageBase：PE 希望加载到内存中的基址。
- RVA：相对 ImageBase 的地址。
- VA：进程内虚拟地址，通常为 `ImageBase + RVA`。
- RAW：对应文件中的字节偏移。

ReverseHelper 同时输出 EntryPoint RVA、VA 和文件偏移，方便在 PE 编辑器、Ghidra 与调试器之间定位。

### Entropy

Entropy 越接近 8，字节分布越随机。压缩、加密或加壳数据常出现高熵，但资源文件和正常压缩数据也可能高熵。工具默认在节区至少 512 字节且 Entropy 不低于 7.2 时标记 `HIGH-ENTROPY`。

### RWX

`RWX` 表示节区同时可读、可写、可执行。这值得人工检查，但不是恶意证据。需要继续查看节区内容、交叉引用和运行时行为。

### Suspicious API

工具会把 `WriteProcessMemory`、`CreateRemoteThread`、`VirtualProtect`、`IsDebuggerPresent` 等导入函数分类。导入只代表程序具备这种能力，不代表相关路径一定执行，更不能单凭 API 判恶意。

### Packing verdict

- `no-obvious-indicators`：内置规则没有发现明显信号，不代表一定未加壳。
- `weak-indicators`：存在较弱或可能正常的异常。
- `suspicious`：多个异常组合出现，建议优先检查入口点和节区。
- `likely-packed`：匹配已知壳节名，例如 UPX；仍需人工确认。

### Risk score

风险分用于安排分析优先级，不是杀毒判定：

- `LOW`：低于 3；
- `MEDIUM`：3 到 5.9；
- `HIGH`：6 到 7.9；
- `CRITICAL`：8 到 10。

报告中的 `Risk explanation` 会列出每一项加分原因。正常程序也可能因为调试、网络或动态加载能力得到分数。

## 7. 配合 Ghidra 使用

建议先用 ReverseHelper 初筛，再导入 Ghidra：

```text
ReverseHelper 找入口点、异常节区、API、字符串
        ↓
Ghidra 查看交叉引用、反编译代码和调用关系
        ↓
必要时在隔离环境使用 x64dbg/x32dbg 动态验证
```

安装仓库脚本：

1. 在 Ghidra 打开目标并完成 Auto Analyze。
2. 进入 **Window → Script Manager**。
3. 点击 **Manage Script Directories**。
4. 添加本项目的 `scripts` 目录。
5. 刷新，在 `ReverseHelper` 分类中运行脚本。

推荐顺序：

1. `FindSuspiciousStrings.py`：给可疑字符串添加 Plate Comment；
2. `FindCryptoConstants.py`：查找常见密码学常量；
3. `AutoRename.py`：根据高信号 API 重命名默认函数名；
4. `ExportAnalysisReport.py`：导出当前 Ghidra 分析摘要。

`AutoRename.py` 会修改 Ghidra 工程。第一次运行前建议先保存工程快照，所有自动生成的函数名都应人工检查。

## 8. 推荐练习流程

第一次练习可以准备三个自己有权分析的文件：

1. 普通 HelloWorld：观察正常 PE Header、节区和低风险结果；
2. 自己编写的 CrackMe：观察字符串、比较函数和输入验证相关导入；
3. 自己使用 UPX 压缩的程序：比较压缩前后的节名、Entropy、导入数量与入口点。

每个文件保留以下记录：

```text
ReverseHelper 报告
静态分析假设
Ghidra 交叉引用证据
动态调试结果
假设被证实或修正的原因
```

## 9. 常见错误

### `missing MZ signature`

输入不是 Windows PE，或者文件已损坏。确认路径没有指向 Markdown、压缩包或快捷方式。

### `Input file does not exist`

路径不存在。路径包含空格时加引号：

```powershell
reversehelper "C:\Lab Files\hello.exe"
```

### `No module named pefile` 或 `No module named rich`

当前 Python 环境没有安装依赖：

```powershell
python -m pip install -r requirements.txt
```

如果使用 `.venv`，先确认命令中的 Python 来自 `.venv\Scripts\python.exe`。

### 安装成功后 PowerShell 仍无法识别 `reversehelper`

如果 `pip` 显示 `Successfully installed reversehelper`，但同时警告 `reversehelper.exe` 所在的 `Scripts` 目录不在 `PATH`，说明程序已经安装，PowerShell 只是找不到命令入口。

先查看当前 Python 的用户脚本目录：

```powershell
python -c "import sysconfig; print(sysconfig.get_path('scripts', scheme='nt_user'))"
```

将输出的目录永久加入当前用户的 `PATH`：

1. 按 `Win + R`，输入 `sysdm.cpl`。
2. 选择“高级 → 环境变量”。
3. 在“用户变量”中编辑 `Path`，新建一项并粘贴上一步的输出。
4. 关闭并重新打开 PowerShell，然后验证：

```powershell
reversehelper --help
```

如果按本文档推荐的 `.venv` 方式安装，每次使用前激活 `.venv` 即可，不需要手动修改 `PATH`。

### 报告目录无法写入

换到当前用户有权限的目录，例如项目内的 `reports`，不要写入 Windows 系统目录。

### 没有发现字符串或密码学常量

程序可能在运行时解密字符串、使用不同编码、内联算法，或者根本不包含内置签名。此时应在 Ghidra 中查看数据引用、解密循环和调用方，不能把“未命中”理解为“不存在”。

## 10. 安全与隐私

- 不要运行来源未知的 EXE；ReverseHelper 自身不需要运行分析目标。
- 对疑似恶意文件使用隔离虚拟机，并保持快照。
- 不要把 Flag、比赛私有附件、真实恶意样本、Cookie、Token、密码或个人目录报告上传到公开仓库。
- `samples` 和 `reports` 中的本地内容默认被 `.gitignore` 排除，但提交前仍应检查 `git status`。

遇到误报时，先记录触发规则和人工验证证据，再考虑调整阈值。工具的价值不在于给出一个绝对答案，而在于让下一步逆向分析更快、更有方向。
