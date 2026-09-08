# Simplified Chinese Localization Report

项目：ReverseHelper。源码/本地便携版本：**0.2.0b2 Beta**。日期：2026-09-08。工作类别：Post-release localization。没有新建 Phase，没有修改已关闭的主路线，也没有发布或覆盖 b1 artifact。

## 1. Localization architecture

保留一个分析引擎和一份分析结果。`localization.py` 提供 `Language`、消息资源、枚举显示和旧分析器说明文本的展示映射；`localization_cli.py` 处理帮助、用户错误与进程内输出编码；`localized_annotations.py` 只在导出副本上翻译注释。语言参数不进入 detector、预算、Schema、Ranking 或 Benchmark。

Quick/Deep 继续共用 `summary_lines`，终端、Markdown 和 HTML 共同消费这一展示层；没有复制中文分析逻辑。没有新增运行时依赖、网络访问或国际化框架。

## 2. Supported languages

支持 `en` 和 `zh-CN`，通过 `Language.EN` / `Language.ZH_CN` 表示。没有启用系统语言检测或 `auto`。

## 3. `--lang` behavior

省略参数始终为英文。`--lang zh-CN`、`--lang=zh-CN` 以及 argparse 支持的无歧义缩写均正确选择语言；语言选项放在 `--help` 前后都可显示中文帮助。非法语言退出码为 2，列出 `en, zh-CN`。未增加新的输出文件命名规则。

## 4. Translation key strategy

64 个主消息 key 覆盖 `summary.*`、`error.*`、`warning.*`、`output.*` 和帮助语言选项；帮助资源按稳定的 argparse destination 组织。59 个枚举显示项不修改内部值。

为避免触碰旧分析器，68 个既有说明文本及 19 个有界模板由展示层映射。模板只匹配明确的分析器说明字段，不对整个输出做字符串替换；只有标记为置信度或关系的捕获组按枚举翻译。未知开发者诊断原样回退为英文。测试检查中英文资源占位符一致。

样本字符串、路径、函数名、API、算法名和类型名不经过全文翻译。名称碰巧为 `INPUT` 或 `KEY` 时也保持原样；语义角色字段才使用中文映射。

## 5. Schema compatibility

Schema 保持 **1.5**，Ranking 保持 **2.2**。实际静态可见性仍为 `normal/limited/unknown`，没有替换成说明示例中的新枚举；仅显示为“完全可见 / 已加壳或运行时变换 / 未知”。映射也支持大写展示术语，但不宣称 `normal` 证明了所有代码均可恢复。

JSON key、内部 enum、置信度、切片状态、算法、控制流类型、建议种类、证据 ID、排序分数和分析模块状态均未改动。

## 6. JSON behavior

普通 `--json FILE` 和报告包中的 JSON 完全不做本地化，连原有说明文本也保持英文。这比允许个别人类文本变化的最低要求更严格。

`--ghidra` 使用深拷贝，只改变 `annotations[].title/comment`。测试逐项比较其余 annotation 字段和所有其他顶层字段。不会污染随后生成的普通 JSON。

## 7. Quick Summary translation

中文覆盖目标、加壳、静态可见性、首选或多个起点、原因与下一步、输入数据流、静态数据流切片、中断点、验证逻辑、语义建议、控制流、算法候选、字符串、排序目标、警告及预算截断提示。技术符号和样本原文保持不变。

固定 fixture 的中英文摘要保存在 `tests/golden/localization`。另一个富内容 fixture 覆盖 START WITH THESE、切片、XTEA、状态机、角色/类型建议和截断。

## 8. Deep output translation

Deep 使用同一消息和摘要渲染函数，显示“Deep 模式分析”。终端、Markdown 和 HTML 跟随语言，HTML 使用 UTF-8 和正确的 `lang` 属性，仍对样本 HTML/Markdown 标记进行转义。详细报告保留部分原始诊断与证据内容，未将其伪装成完整中文证据库。

## 9. Ghidra category/comment strategy

保留所有 `RH:*` category、RVA、confidence、evidence 和 fact_status。中文导出在 comment 中形成带 `[ReverseHelper]` 前缀的完整中文注释；导入器识别这一已格式化注释，避免再套英文标签。旧英文注释和无 annotations 的兼容路径不变。

测试覆盖 START、INPUT、VALIDATION、SLICE、FLOW_BREAK、ALGORITHM、CONTROL_FLOW、STATE_MACHINE 和 SUGGEST 分类，以及身份校验后的导入计划；默认 rename 始终为空。未运行实际 Ghidra UI，因此不宣称已完成界面内重复导入检查。

## 10. README.zh-CN

[中文版 README](../README.zh-CN.md) 包含项目定位、快速使用、Quick/Deep、输出/Ghidra、核心能力、便携版、源码安装、既有测量、限制和开发入口。英文 README 新增相对语言导航及 b2 本地化说明；原有修改和旧版下载链接保留。

## 11. QUICKSTART.zh-CN

[中文快速开始](../QUICKSTART.zh-CN.md) 提供解压后的一条中文命令、Deep、报告、Ghidra 和源码安装路径，并解释缺失结果的可信边界。

## 12. workflow.zh-CN

[中文工作流](workflow.zh-CN.md) 对应比赛入口、START HERE/START WITH THESE、Static Slice、Flow Break、Deep、Ghidra、IDA 延后及 solver 延后的原有决策。

## 13. limitations.zh-CN

[中文限制](limitations.zh-CN.md) 保留英文限制的全部九项，并明确混淆、运行时生成代码、堆别名、基准规模小、PE 支持重点和验证环境的边界。[术语表](terminology.zh-CN.md) 统一关键用语。

## 14. Unicode console/path handling

所有新增中文文件、资源和报告采用 UTF-8。中文模式下，重定向 stdout/stderr 使用 UTF-8；原生控制台保留能表示中文的编码，无法表示的其他字符采用转义回退，避免 `UnicodeEncodeError`。不修改系统区域设置、注册表或控制台代码页。

专项测试覆盖 ASCII、cp1252、GBK 和 UTF-8 的管道环境。英文路径保留既有编码策略：冻结 Python 可能忽略 `PYTHONIOENCODING`，本机英文便携输出使用 OEM/GBK，因此验证器按实际编码读取，不借本地化改变英文默认行为。

源码与便携矩阵均使用包含“用户 测试 / Desktop / 题目”和“逆向32.exe / 逆向64.exe”的路径。cmd.exe、PowerShell 7、Windows PowerShell 的中文帮助输出均通过。没有实际打开 Windows Terminal 窗口做视觉验收。

## 15. Tests

完整回归：**368 passed**，24.94 秒。最后增加语言选项缩写覆盖并修正预解析一致性后，最终 CLI + 本地化专项：**65 passed**，其中本地化 **45 项**。全量测试与最终专项之间仅有该参数预解析调整及对应测试，不涉及分析代码。

测试覆盖默认英文、中文语言、非法语言、帮助顺序、跨语言事实一致、JSON 不变、摘要、错误、警告、Ghidra 注释/分类、中文路径/输出、样本转义、名称与角色区分、资源占位符，以及报告写入失败的隔离。

首次运行的默认 pytest 临时目录因本机 ACL 无法访问，改用项目 `build` 下独立临时目录后通过；未修改系统权限。初始 fixture 已有的可选 data-flow `NoneType` 诊断保留在英文 golden 中，本轮没有修复或隐藏这个既有分析问题。

## 16. Coverage

全量测试记录的项目语句覆盖率为 **87.97%（四舍五入 88%）**。这是可执行语句覆盖率，不是翻译词条覆盖率，也不代表每种真实样本或每个 Windows 终端都已验证。最终参数缩写调整由上述专项补充覆盖。

## 17. English regression

在修改前保存真实固定 PE 的英文摘要；英文 Markdown/HTML golden 从当前任务修改前的 Git 版本渲染器生成。当前默认英文输出与这些 golden 逐字一致，动态路径/时间不进入摘要快照。富内容英文 golden 也逐字一致。

有意可见变化仅为新增 `--lang` 帮助和版本号 b2。旧 CLI、报告错误隔离和 Ghidra 兼容测试通过。

## 18. Cross-language analysis equivalence

源码 Quick/Deep 分别在 en/zh-CN 下运行并比较整个 JSON；便携矩阵再比较各语言与源码结果。只排除 `analyzed_at_utc`、`*_elapsed_ms` 和 `module_timings_ms`，因为独立运行的测量时间自然不同。没有排除 Ranking、START、Validation、StaticSlice、Algorithm、Control Flow、Suggestions、Module status 或 Truncation。

未修改任何分析器、分析规则、Ranking 权重、预算或 Benchmark 定义；主路线继续关闭。

## 19. Portable validation

独立产物：`dist/ReverseHelper-0.2.0b2-win-x64.zip`。使用本机已有 PyInstaller 6.22.2 构建，不覆盖 b1。

| PE 架构 | 模式 | 英文 | 中文 |
|---|---|---|---|
| x86 | Quick | 通过 | 通过 |
| x86 | Deep | 通过 | 通过 |
| x64 | Quick | 通过 | 通过 |
| x64 | Deep | 通过 | 通过 |

每格同时验证终端、Markdown/HTML/JSON、Ghidra 导出、中文路径以及源码/便携分析事实等价。验证使用静态生成的 PE fixture，从未运行被分析目标。便携程序本身在复制到中文路径后执行。

完整矩阵和测量见 [localization-validation.json](localization-validation.json)。可复现命令：

```powershell
.\.venv\Scripts\python.exe scripts\validate-localization.py dist\ReverseHelper-0.2.0b2-win-x64\ReverseHelper.exe
```

这是当前 Windows 主机的验证，不是无 Python 的独立干净 Windows 环境认证。

## 20. Performance impact

对富内容固定摘要，每种语言运行 7 批、每批 300 次，取每次渲染的批次中位数：

| 语言 | 每次渲染 |
|---|---|
| en | 0.0483 ms |
| zh-CN | 0.1141 ms |

中文增加约 **0.0658 ms** 的纯文本渲染成本。该数字是本机微基准，不包括终端 I/O 或分析耗时；绝对成本很小，没有重跑或修改复杂分析 Benchmark。

## 21. Version recommendation

采用 **0.2.0b2**：新增 `--lang` 是发布后的用户可见功能，即使分析逻辑不变也应有新版本。已同步 pyproject、运行时版本、CLI 版本测试和便携包文件名。CHANGELOG 标记为未发布，不建立虚假的 b2 远程发布链接。

## 22. Known untranslated developer/debug areas

原始证据、异常技术详情、未知开发者诊断、`--verbose` 预算字典、旧 `--only` 单模块诊断、旧完整分析 API 报告及 x64dbg 脚本注释保留英文。普通 JSON 有意保持全部原始文本。样本字符串及代码标识符也原样保留，但它们不是遗漏翻译。

默认 Quick/Deep 的主要标题、固定说明、排序理由和下一步建议已提供中文；遇到新的分析器说明文本时，由统一展示资源补充，不在分析器中加入语言分支。

## 23. Release readiness

源码测试、英文 golden、跨语言等价、中文文档、本机便携矩阵及三种 shell 自动化验证已通过，可交付 **b2 本地候选包**。未执行远程发布，也未覆盖任何已发布 artifact。

剩余未验证项明确为：独立干净 Windows、实际 Windows Terminal 窗口显示，以及真实 Ghidra UI 重复导入。不能把现有自动化结果表述为这些环境已通过。真人 TTCF 仍无数据，本轮不宣称分析能力或解题效率提升。
