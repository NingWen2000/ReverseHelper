# ReverseHelper Ghidra Scripts

For the product workflow, run `reversehelper challenge.exe --ghidra`, then use `ImportReverseHelperFindings.py` and select `reports\challenge.reversehelper.json`. New reports expose one tool-independent `annotations` array with `RH:START`, input/slice/validation/algorithm/control-flow/FLOW_BREAK and review-only semantic markers. The importer still accepts older findings/targets JSON.

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
- `ImportReverseHelperFindings.py`：校验目标身份后，以 RVA 映射 Findings/ReverseTargets 并添加 Plate Comment；默认不重命名函数。
- `ExportAnalysisReport.py`：导出程序基本信息、内存块和函数列表为 Markdown 文件。

不同 Ghidra 版本的 Python 运行环境可能不同；项目中的脚本避免使用 Python 3 专属语法，以兼容常见的 Jython/PyGhidra 脚本环境。

## 导入 ReverseHelper JSON

先生成完整报告：

```powershell
reversehelper sample.exe --json reports\sample.json
```

在已经完成 Auto Analyze 的同一目标程序中运行 `ImportReverseHelperFindings.py`，选择该 JSON。脚本会先比较 SHA-256；当前 Ghidra 环境无法提供哈希时退回文件名校验。每个 RVA 都会按当前 Ghidra ImageBase 重新定位并检查内存范围，越界记录不会导入。

默认行为是添加包含 category、confidence、evidence 和 recommended action 的 Plate Comment。高置信 Rename 需要显式启用，且只处理脚本能够保守确认的函数入口；不要把自动名称当作已验证结论。

脚本逻辑已有自动化测试覆盖身份拒绝、地址范围、RVA 重定位和默认 Comment 行为。v0.1.0 发布准备环境未安装 Ghidra，因此尚未完成实际 CodeBrowser 运行验证。
