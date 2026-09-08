# ReverseHelper 快速开始

[简体中文](QUICKSTART.zh-CN.md) | [English](QUICKSTART.md)

ReverseHelper 是 Windows PE CTF 题目的离线静态分析工具。它读取目标，不运行或上传目标。

## Windows 便携版

1. 解压 `ReverseHelper-0.2.0b2-win-x64.zip`。
2. 在解压目录打开 PowerShell。
3. 将路径替换为自己的题目文件，执行：

```powershell
.\ReverseHelper.exe "C:\CTF\题目\challenge.exe" --lang zh-CN
```

首先看静态可见性和“建议从这里开始”。在 Ghidra/IDA 找到对应函数，按原因和下一步建议检查。没有唯一可靠起点时会显示多个候选。静态追踪中断表示只能证实到该位置，不表示后续没有行为。

Quick 被截断或证据不足时，再扩大预算：

```powershell
.\ReverseHelper.exe "C:\CTF\题目\challenge.exe" --lang zh-CN --deep
```

## 保存报告和导入 Ghidra

```powershell
.\ReverseHelper.exe "C:\CTF\题目\challenge.exe" --lang zh-CN --report reports
.\ReverseHelper.exe "C:\CTF\题目\challenge.exe" --lang zh-CN --ghidra
```

报告位于 `reports`，Markdown/HTML 为中文，分析 JSON 保持原有英文机器字段和分析事实。

将 `ImportReverseHelperFindings.py` 放入 Ghidra 脚本目录；打开同一题目，运行脚本，选择 `reports\challenge.reversehelper.json`。导入会核对身份，只添加注释/书签，不自动重命名。中文注释不改变 `RH:*` 分类。

## 源码安装

在源码目录执行：

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\reversehelper.exe "C:\CTF\题目\challenge.exe" --lang zh-CN
```

`--lang en` 切换英文；省略 `--lang` 也始终为英文。中文帮助：`ReverseHelper.exe --lang zh-CN --help`。

请只分析获授权的文件。加壳、运行时生成、托管、非 PE 及严重优化的代码可能超出静态模型；警告和缺失结果都不能作为“行为不存在”的证明。详情见[限制](docs/limitations.zh-CN.md)。
