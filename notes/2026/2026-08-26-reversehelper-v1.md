# ReverseHelper v1.0 MVP

## 问题与目标

希望把正在学习的 PE、IAT/EAT、UPX、Ghidra 和 Python 串成一个能公开展示的安全工具，而不是停留在零散的 CTF Writeup。第一版需要能够读取 Windows PE，整理结构和可疑信号，并输出适合继续人工分析的报告。

范围刻意限制为静态分析：不执行目标、不自动脱壳、不做“AI 判恶意”，也不把简单规则包装成确定结论。

## 分析路径

先建立统一数据流：

```text
MZ/PE 校验 → Header → Sections → IAT/EAT
          ↘ 原始字节 → Strings / Crypto constants
所有信号 → Packing heuristics → Explainable risk → Reports
```

地址处理保留 RVA、VA 和 RAW 三种视角。RVA 转换优先调用解析库，失败时再按节区区间计算：

```text
RAW = RVA - Section.VirtualAddress + Section.PointerToRawData
```

节区 Entropy、RWX、入口点位置和壳节名都只作为独立证据保存。这样报告能够回答“为什么触发”，而不是只给一个无法复查的分数。

## 静态假设与已验证事实

静态假设：高熵节区、RWX、入口点异常、少量导入与已知壳节名组合出现时，样本更值得优先检查；单个信号不足以证明加壳或恶意。

已验证事实：使用本地 Python 3.13 Windows 启动器作为正常 PE 进行只读集成测试，解析到 x86-64、8 个节区、92 个导入函数，未触发明显加壳信号，风险结果为 `2.5/10 LOW`。测试没有执行被分析的目标副本。

另一个有用观察是，正常 Python 启动器也会导入 `IsDebuggerPresent`、`GetProcAddress` 和 `VirtualProtect`。因此“可疑 API”必须解释成能力线索，不能直接解释成恶意行为。

## 修正过的问题

第一次终端验证在中文 Windows 控制台输出 Unicode 圆点时失败。报告已经成功生成，失败发生在最后的路径显示阶段。将终端装饰符改为 ASCII 后，GBK 控制台可以稳定输出。

UTF-16LE 提取的第一版在 ASCII 字符串紧邻宽字符串时，会把前一个 ASCII 字符误当成宽字符开头。为 UTF-16LE 匹配增加左边界条件后，单元测试确认结果恢复为预期字符串。

系统 Python 的用户级依赖目录不可写，因此项目改用本地 `.venv`。这也让安装和验证环境更容易复现。

## 当前验证

- 13 项自动测试全部通过。
- Windows PE 集成分析通过。
- Markdown、JSON、独立 HTML 三种报告均成功生成并读取。
- 可编辑安装入口 `reversehelper` 与源码入口 `python main.py` 均可用。
- Python wheel 构建成功，依赖检查无冲突。
- 生成报告、虚拟环境、PE 样本和构建产物均被 Git 忽略。

Ghidra 脚本尚未在具体 Ghidra 工程中动态运行，因此只能记录为待用户环境验证，不能声称已经完成 Ghidra 内部执行验证。
