# ReverseHelper Ghidra Scripts

## 安装

1. 打开 Ghidra CodeBrowser。
2. 选择 **Window → Script Manager**。
3. 点击 **Manage Script Directories** 图标。
4. 添加本仓库的 `scripts` 目录并刷新。
5. 在 `ReverseHelper` 分类中运行所需脚本。

脚本基于 GhidraScript API，设计为可由 Script Manager 直接执行。对于不可信程序，先让 Ghidra 完成基础分析，再运行字符串、常量和报告脚本。

## 脚本说明

- `FindSuspiciousStrings.py`：扫描 Ghidra 已定义字符串，给 URL、命令、凭据、反调试和 CTF 相关内容添加 Plate Comment。
- `FindCryptoConstants.py`：扫描内存块中的 TEA、MD5、CRC32 常量并添加 Plate Comment。短签名必须人工检查交叉引用。
- `AutoRename.py`：对仍为 `FUN_*` 的函数，根据其引用的高信号外部 API 生成 `rh_*` 名称。该脚本会修改工程，运行前建议保存快照。
- `ExportAnalysisReport.py`：导出程序基本信息、内存块和函数列表为 Markdown 文件。

不同 Ghidra 版本的 Python 运行环境可能不同；项目中的脚本避免使用 Python 3 专属语法，以兼容常见的 Jython/PyGhidra 脚本环境。
