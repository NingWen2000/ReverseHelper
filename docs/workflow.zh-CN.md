# 比赛工作流

[简体中文](workflow.zh-CN.md) | [English](workflow.md)

## 推荐流程

`题目 PE → reversehelper challenge.exe --lang zh-CN → 题目摘要 → Ghidra/IDA → 人工逆向`

默认 Quick 显示目标身份、架构、加壳和静态可见性、“建议从这里开始”（START HERE）或保守的多个起点、输入数据流、静态数据流切片（Static Slice）或静态追踪中断点（StaticFlowBreak / FLOW BREAK）、很可能的验证逻辑、算法与控制流候选，以及下一步动作。

先确认静态可见性。如果样本已加壳或存在运行时变换，在脱壳或获取展开后的代码之前，不要完全信任当前验证逻辑、排序和切片。按照脱壳后建议获取映像，再重新分析。

查看首选函数的原因和下一步建议。分数只表示阅读优先级，不是概率。“建议优先查看这些位置”（START WITH THESE）表示没有证据足够突出的单一起点；不要把第一名当作已经确定的关键函数。

遇到 FLOW BREAK 时，先检查最后已证实的数据来源关系和中断原因，再手动检查未解析调用、函数返回值及调用方如何使用它。可能的数据流片段不等于已证实的事实。

仅当 Quick 被截断或静态证据不足时使用 `--deep`。Deep 增加解码、函数、数据流、算法、CFG 和语义预算，仍使用同一分析器及 Schema，不切换到旧的完整分析流程。更高预算不意味着可以恢复运行时生成代码。

使用 `--report` 输出 Markdown/HTML/JSON，使用 `--json FILE` 做自动化，使用 `--ghidra` 生成带统一注释的 JSON。`--verbose` 显示预算与开发者诊断；旧 `--only` 单模块诊断保留英文，主要产品入口仍为 Quick/Deep。

## Ghidra 交接

顶层 `annotations` 数组与具体工具无关。随附脚本添加 `RH:START`、`RH:INPUT`、`RH:SLICE`、`RH:VALIDATION`、`RH:ALGORITHM`、`RH:FLOW_BREAK`、分发器/控制流标记和 `RH:SUGGEST_*` 注释与书签。

```powershell
reversehelper challenge.exe --lang zh-CN --ghidra
```

`--lang zh-CN` 只改变该导出中 `annotations[].title/comment` 的人类文本，分类、RVA、置信度、证据和事实状态保持不变。导入脚本核对程序身份，不默认重命名；不带 `annotations` 的旧 JSON 继续使用 findings/targets 兼容路径。导入后仍需判断地址处的语义是否正确。

IDA 专用深度集成继续延后。没有实际端到端验证就维护第二套导入器，可能增加维护成本而无法证明 TTCF 收益。通用 annotation schema 仍是未来集成边界。

## Solver 决策

继续延后自动 solver 骨架生成。当前公开算法真值样本太少，静态切片召回仍有限，直接生成 solver 可能把假设误呈现为可执行事实。ReverseHelper 提供证据和下一步建议，由选手验证。

术语统一见[术语表](terminology.zh-CN.md)，能力边界见[限制](limitations.zh-CN.md)。
