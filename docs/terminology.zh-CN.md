# 简体中文术语表

面向逆向选手，保留 API、函数名、算法名、RVA、VA、PE、switch、Ghidra、IDA 和代码类型。内部枚举与 JSON 字段始终使用原值。

| 英文 | 中文展示 |
|---|---|
| Challenge Summary | 题目摘要 |
| START HERE | 建议从这里开始 |
| START WITH THESE | 建议优先查看这些位置 |
| Validation | 验证逻辑 |
| Static Slice | 静态数据流切片 |
| StaticFlowBreak / FLOW BREAK | 静态追踪中断点 |
| Static tracking lost here | 静态追踪在此中断 |
| Control Flow | 控制流 |
| Dispatcher | 分发器 |
| State Machine | 状态机 |
| Jump Table | 跳转表 |
| Flattening-like | 类控制流平坦化结构 |
| Provenance | 来源追踪 / 数据来源关系 |
| Ranking | 排序 |
| Candidate | 候选 |
| Semantic Suggestions | 语义建议 |
| Suggested type | 建议类型 |
| Quick | Quick（快速分析）模式 |
| Deep | Deep（深入静态分析）模式 |
| Analysis truncated | 分析因预算限制被截断 |

| 内部值 | 中文展示 |
|---|---|
| FULLY_VISIBLE / normal | 完全可见 |
| PARTIALLY_VISIBLE | 部分可见 |
| PACKED_OR_TRANSFORMED / limited | 已加壳或运行时变换 |
| UNKNOWN | 未知 |
| HIGH / MEDIUM / LOW | 高 / 中 / 低 |
| CONFIRMED / LIKELY / POSSIBLE | 已确认 / 很可能 / 可能 |
| COMPLETE / TRUNCATED / SKIPPED / UNAVAILABLE / ERROR | 完成 / 已截断 / 已跳过 / 不可用 / 错误 |
| INPUT / TRANSFORMED_INPUT | 输入 / 已变换输入 |
| KEY / POSSIBLE_KEY | 密钥 / 可能的密钥 |
| TARGET / LOOKUP_TABLE / STATE / VALIDATION_RESULT | 目标数据 / 查找表 / 状态变量 / 验证结果 |
| CRYPTO / ENCODING / CHECKSUM / TRANSFORM | 加密/密码变换 / 编码 / 校验和 / 数据变换 |

当前 Schema 的静态可见性实际使用 `normal/limited/unknown`。显示层同时提供上述大写术语映射，不改写 Schema，也不将 `normal` 解释为已证明所有代码完全可分析。
