# 已验证分析示例

本示例使用项目虚拟环境中的 Python 3.13 启动器 `python.exe`。它是一个正常 Windows PE 文件，分析过程只读取文件，没有执行这个目标副本。

## 观察结果

- 架构：x86-64
- 类型：EXE / Windows Console
- 节区数：8
- EntryPoint RVA：`0x22CC`
- 导入：92 个函数，来自 2 个库
- 节区：未发现高熵或 RWX 信号
- 加壳判断：`no-obvious-indicators`
- 风险分：`2.5 / 10 (LOW)`

规则匹配到 `IsDebuggerPresent`、`GetProcAddress`、`VirtualProtect` 等 API。这是一个很好的反例：这些 API 出现在导入表中并不意味着文件恶意，Python 启动器的正常功能也会需要动态解析、内存保护或调试检测相关能力。

静态假设：文件具备动态加载和少量反调试相关能力。

动态验证：本次没有进行，因为验证目标只是确认 ReverseHelper 能稳定解析真实 PE 并生成报告，不能据此声称这些 API 在某条执行路径上实际被调用。

## 复现

```powershell
python main.py .\.venv\Scripts\python.exe --report reports
```

会在本地 `reports` 目录生成同名的 Markdown、JSON 与 HTML 文件。报告默认被 Git 忽略，避免意外公开分析目标中的路径、字符串或其他信息。

另一个更贴近手工逆向流程的记录见 [PatchMe 第 20 章案例](cases/patchme-ch20.md)。该案例展示了入口字节和地址映射如何缩短 Ghidra 定位过程，同时保留尚未完成动态验证的部分。
