# ReverseHelper

[![Tests](https://github.com/NingWen2000/ReverseHelper/actions/workflows/tests.yml/badge.svg)](https://github.com/NingWen2000/ReverseHelper/actions/workflows/tests.yml)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

ReverseHelper 是我在学习 Windows PE、Ghidra 和 x32dbg 时写的静态初筛工具。它不替代反汇编器，主要解决进入 Ghidra 前反复手查 PE Header、节区权限、导入表、字符串地址和入口点字节的问题。

项目只读取目标文件，不会执行它。

## 版本下载

| 版本 | 下载 | 说明 |
|---|---|---|
| **[v0.0.2](https://github.com/NingWen2000/ReverseHelper/archive/refs/tags/v0.0.2.zip)** | [Release 说明](https://github.com/NingWen2000/ReverseHelper/releases/tag/v0.0.2) | 快速模式、单模块分析、清晰错误与 CLI 测试 |
| **[v0.0.1](https://github.com/NingWen2000/ReverseHelper/archive/refs/tags/v0.0.1.zip)** | [Release](https://github.com/NingWen2000/ReverseHelper/releases/tag/v0.0.1) | 本轮 CLI 模式扩展之前的保留基线 |

点击版本号会直接下载对应源码 ZIP。详细差异和每个命令的用法见 [更新日志](CHANGELOG.md)。

## 目前能做什么

- 解析 PE 基础信息、节区、IAT/EAT 和 Overlay
- 同时给出 EntryPoint 的 RVA、VA、文件偏移及入口字节
- 识别简单入口桩，并计算首个相对 CALL/JMP 的目标地址
- 为字符串标注文件偏移、RVA、VA 和所属节区
- 列出可执行节中的连续 `00`/`CC` 填充区，辅助人工寻找代码洞
- 检查 RWX、高熵、异常入口点、少量导入和常见壳节名
- 匹配 AES、TEA、MD5、CRC 常量
- 输出终端摘要以及 Markdown、JSON、HTML 报告
- 提供四个可独立运行的 Ghidra 脚本

这些检测都是分析线索。`LOW` 不代表文件安全，RWX 或某个 API 也不能单独证明加壳或恶意。

## 安装与运行

需要 Python 3.10 或更高版本：

```powershell
git clone https://github.com/NingWen2000/ReverseHelper.git
cd ReverseHelper
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e .
```

直接分析一个 PE：

```powershell
reversehelper .\sample.exe
```

快速结构初筛（跳过字符串、密码学常量和代码洞扫描）：

```powershell
reversehelper .\sample.exe --quick
```

只运行并显示一个模块：

```powershell
reversehelper .\sample.exe --only anomaly
reversehelper .\sample.exe --only strings
reversehelper .\sample.exe --only imports
```

生成 Markdown、JSON 和 HTML 报告：

```powershell
reversehelper .\sample.exe --report .\reports
```

不安装命令行入口也可以：

```powershell
python main.py .\sample.exe --report .\reports
```

完整参数和常见报错见 [使用说明](docs/usage.md)。

## 一次真实分析

《逆向工程核心原理》第 20 章的 `unpackme#1.aC.exe` 给出了下面的入口信息：

```text
Architecture  x86
ImageBase     0x400000
EntryPoint    RVA 0x1000 / VA 0x401000 / RAW 0x400

Entry-point review
Bytes          60 E8 E3 00 00 00 C3 EC 20 44 75 44 27 68 61 27
Pattern        pushad-call-ret
First transfer RVA 0x10E9 / VA 0x4010E9
```

`.text` 同时可写、可执行，而入口是一个很短的 `PUSHAD → CALL → RET` 桩。两条线索结合后，下一步不再是盲目浏览全部函数，而是直接检查 `0x4010E9` 是否写回代码节。

同一份报告还定位到 `.text` 尾部从 RAW `0x680`、VA `0x401280` 开始的连续零填充区。官方 patched 版本正是把 Inline Patch 放在这里；工具只把它列为候选，不会自动认定该空间可安全覆盖。

完整推理、地址换算、解密循环和仍待动态验证的补丁候选记录在 [PatchMe 第 20 章案例](docs/cases/patchme-ch20.md)。仓库不重新分发该样本，案例末尾列出了作者的官方来源。

## 报告怎么接到 Ghidra

假设报告里某个字符串显示：

```text
File offset 0x408 / RVA 0x1008 / VA 0x401008 / .text
```

在 Ghidra 中按 `G` 后输入 `00401008`。如果 ASLR 或重定位改变了运行时基址，优先使用 RVA，并加上调试器里实际模块基址。

仓库的 [Ghidra 脚本说明](scripts/README.md) 包含安装和行为边界。`AutoRename.py` 会改动当前工程，运行前建议保存快照。

## 项目布局

```text
reversehelper/   Python 分析器
scripts/         Ghidra 脚本
tests/           单元测试与 PE 集成测试
docs/cases/      真实样本分析记录，不存放二进制
notes/           开发和验证笔记
samples/         样本管理说明
```

运行测试：

```powershell
python -m pip install -r requirements-dev.txt
python -m pytest
```

当前自动测试不会下载或执行样本。Windows 集成测试只读取正在运行的 Python 解释器；PatchMe 案例使用本地样本人工复核，不会进入 CI。

## 已知限制

- 不反汇编任意指令；入口桩识别只是少量明确字节模式
- 不自动脱壳，也不修复 dump 后的导入表
- 可疑 API、字符串规则和风险分数只用于安排人工分析顺序
- Ghidra 脚本仍需要继续积累不同版本下的实机验证

欢迎提交带样本哈希、复现步骤和预期结果的 Issue。请不要上传无权公开的二进制、比赛 Flag、凭据或个人数据。

## License

[MIT License](LICENSE)
