修订日期：2026-09-03。本文保存用户提供的完整产品目标，作为后续开发依据。实现状态见 [路线图](roadmap.md)，现有命令见 [使用说明](usage.md)。文中的地址、得分、置信百分比与耗时案例均为设计示例；85% 和 50% 为目标，不是实测结果。

# ReverseHelper 产品目标修订

从现在开始，ReverseHelper 的核心定位正式调整为：

> **Offline-First CTF Reverse Engineering Workbench**

ReverseHelper 的目标不是成为功能最多的逆向软件，也不是替代 Ghidra、IDA、x64dbg、DIE 或 PE-bear。

它的目标是：

> **成为 CTF Reverse 选手在无法使用 AI、无法联网、比赛限时环境下，拿到未知二进制后第一个打开的工具。**

ReverseHelper 必须尽可能快速地帮助选手回答：

```text
这个程序是什么？
有没有壳或明显异常？
输入从哪里进入？
哪个函数最值得先看？
验证逻辑可能在哪里？
输入经过了哪些关键变换？
有没有已知算法？
哪里可能是 key / table / target bytes？
哪条成功/失败分支最关键？
我打开 Ghidra 后第一步应该看哪里？
```

---

# 一、核心设计原则

所有功能必须围绕：

```text
FAST
ACCURATE
OFFLINE
ACTIONABLE
```

展开。

即：

### FAST

必须适合比赛场景。

用户拖入二进制后，应尽快产生第一批有价值结果。

不要默认执行成本极高的全程序分析。

---

### ACCURATE

结果必须：

```text
有证据
有置信度
可解释
可追踪
```

宁可输出：

```text
Possible Validation Candidate
Confidence: Medium
```

也不要错误地输出：

```text
This is the flag checker.
```

---

### OFFLINE

ReverseHelper 的全部核心功能必须：

```text
No Internet
No Cloud
No API Key
No Login
No Upload
No LLM
```

断网状态下功能完整。

不得把任何核心功能建立在：

```text
OpenAI
Claude
Gemini
Qwen API
remote inference
cloud service
```

之上。

如果未来增加 AI 插件，也只能作为可选扩展，不属于 ReverseHelper 核心。

---

### ACTIONABLE

不能只告诉用户：

```text
发现了某个东西
```

而必须告诉用户：

```text
这个东西为什么重要？
下一步应该去哪里看？
```

例如不要只输出：

```text
String:
"Wrong flag"
```

而应该输出：

```text
Interesting String

"Wrong flag"

XREF:
FUN_401830

Related:
conditional branch @ RVA 0x18A2

Reverse Priority:
HIGH

Suggested:
Inspect FUN_401830 first.
```

---

# 二、ReverseHelper 的核心竞争指标

以后不要用：

```text
支持多少功能
支持多少算法
有多少检测规则
```

作为最重要指标。

ReverseHelper 的北极星指标定义为：

# Time To First Critical Function

即：

> 用户从拿到未知 CTF Reverse 二进制，到定位第一个关键验证、变换或输入处理函数所需的时间。

简称：

```text
TTCF
```

ReverseHelper 的首要目标：

> 显著降低 TTCF。

例如：

```text
Ghidra only:
12.4 min

ReverseHelper + Ghidra:
4.1 min
```

这类指标比“100种检测功能”更重要。

---

# 三、最高优先级能力

## P0 — Reverse Target Ranking

这是 ReverseHelper 第一核心。

给出：

```text
Top Reverse Targets
```

例如：

```text
#1 FUN_401830
96/100
VALIDATION

#2 FUN_401970
91/100
TRANSFORM

#3 DAT_405020
84/100
KEY_TABLE
```

评分必须可解释。

---

## P0 — Input → Validation Static Slice

这是 ReverseHelper 第二核心。

目标：

> 尽可能自动恢复 CTF Reverse 最常见的静态主链。

即：

```text
INPUT
 ↓
LENGTH CHECK
 ↓
TRANSFORM
 ↓
CRYPTO / TABLE / XOR
 ↓
COMPARE
 ↓
SUCCESS / FAILURE
```

例如：

```text
argv[1]
 ↓
FUN_401210
 ↓
FUN_401480
 ↓
XOR with DAT_405020
 ↓
FUN_401790
 ↓
memcmp
 ↓
success branch
```

第一版不需要实现完整符号执行。

重点是：

```text
可靠的跨函数简化静态切片
```

---

## P0 — Validation Discovery

自动重点识别：

```text
strcmp
strncmp
memcmp
byte compare loop
hash comparison
checksum comparison
custom validation loop
success/failure branch
```

输出：

```text
Input
Target
Compare Length
Transform Function
Success Branch
Failure Branch
```

---

## P0 — Interesting String Intelligence

重点围绕：

```text
flag
correct
wrong
success
failed
password
input
key
invalid
congratulations
```

进行：

```text
String
→ XREF
→ Function
→ Branch
→ Reverse Target
```

而不是普通字符串列表。

---

# 四、第二优先级能力

## P1 — Algorithm Recognition

优先识别 CTF 高频模式：

```text
XOR
Rolling XOR
TEA
XTEA
XXTEA
RC4
AES
Base64
CRC
LCG
S-box
Feistel-like
lookup transform
ROL/ROR based transform
```

不要为了算法数量而牺牲准确率。

---

## P1 — Key / Table Discovery

识别：

```text
candidate key
target bytes
S-box
lookup table
encoded blob
constant table
```

并自动关联使用它们的函数。

---

## P1 — Ghidra Deep Integration

ReverseHelper 不替代 Ghidra。

它应该帮助用户：

```text
ReverseHelper
 ↓
快速确定目标
 ↓
Ghidra
 ↓
深度人工分析
```

Ghidra 中自动加入：

```text
RH_INPUT
RH_VALIDATION
RH_TRANSFORM
RH_CRYPTO
RH_KEY_TABLE
RH_TOP_TARGET
```

Bookmark / Comment / Label。

目标是：

> 用户打开 Ghidra 时，不再面对几百个完全陌生的 FUN_xxxxx。

---

# 五、第三优先级能力

以下功能仍然有价值，但不能影响核心开发：

```text
Control Flow Assistant
Decompiler Cleanup
Solver Skeleton
ELF support
plugin framework
advanced packing
advanced deobfuscation
```

这些属于：

```text
P2 / P3
```

而不是第一阶段核心。

---

# 六、Quick Mode 与 Deep Mode

比赛环境必须支持两级分析。

## Quick Mode

默认模式。

目标：

> 尽快给出“从哪里开始”。

分析：

```text
Binary Triage
Interesting Strings
Imports
Input Sources
Validation Candidates
Basic Algorithm Fingerprints
Reverse Target Ranking
Suggested Static Path
```

Quick Mode 必须优先考虑速度。

---

## Deep Mode

用户主动请求后运行。

增加：

```text
cross-function data flow
CFG analysis
table usage analysis
algorithm structural matching
validation tracing
call graph analysis
```

不要让 Deep Mode 阻塞 Quick Mode 的首屏结果。

---

# 七、首屏设计

ReverseHelper 打开一个 challenge 后，第一屏不要优先显示：

```text
Sections
Imports
Entropy
Resources
...
```

这些属于详细信息。

首屏必须叫：

# Challenge Summary

示例：

```text
ReverseHelper
================================

Binary
PE64 / x86-64 / MSVC

Packing
No strong packing evidence

Input
argv[1]

Likely Goal
Flag / password validation

Top Reverse Targets

96  FUN_401830   VALIDATION
91  FUN_401970   TRANSFORM
84  DAT_405020   KEY TABLE

Possible Algorithm
XTEA-like
Confidence: 91%

Static Flow

argv[1]
 ↓
FUN_401830
 ↓
FUN_401970
 ↓
memcmp
 ↓
success

START HERE

FUN_401830
Reason:
Input reaches this function and its return path controls the
success/failure decision.
```

首屏必须直接告诉选手：

> START HERE

---

# 八、Suggested Static Path

必须生成明确的静态分析顺序。

例如：

```text
Recommended Static Analysis Path

1. FUN_401830
   Validation candidate

2. FUN_401970
   Transforms user input

3. DAT_405020
   Candidate key table

4. Branch RVA 0x1A90
   Controls success output
```

不要只是列 Finding。

---

# 九、比赛环境要求

ReverseHelper 必须针对比赛环境设计。

要求：

```text
100% offline core
fast startup
portable if feasible
no mandatory installer
no account
no telemetry required
no remote dependency
predictable output
graceful failure
```

一个模块分析失败：

```text
Algorithm Recognition failed
```

不能导致：

```text
整个 ReverseHelper 崩溃
```

每个模块必须独立容错。

---

# 十、性能要求

对普通：

```text
< 10 MB
```

CTF 二进制：

Quick Mode 应尽可能快速产生：

```text
Top Targets
Input
Validation
Interesting Strings
Suggested Start
```

不要为了完全分析程序而让用户等待很久。

Deep Mode 可以更慢。

---

# 十一、Benchmark

必须开始建立：

```text
ReverseHelper CTF Benchmark
```

使用公开 CTF Reverse 题。

建议至少：

```text
20 → 50 → 100
```

道题逐步扩大。

记录：

```text
Challenge
Architecture
Difficulty
True critical function
ReverseHelper Top 1 rank
ReverseHelper Top 3 rank
ReverseHelper Top 5 rank
TTCF
False positives
Algorithm detection
Validation detection
```

重点指标：

```text
Top-1 Critical Function Accuracy
Top-3 Critical Function Accuracy
Top-5 Critical Function Accuracy
Median TTCF
Validation Detection Accuracy
Algorithm Detection Accuracy
```

例如目标：

```text
Critical function appears in Top 5:
> 85%

Median TTCF reduction:
> 50%
```

这些数字必须来自真实测试，不能编造。

---

# 十二、产品开发决策原则

每增加一个功能，必须问：

> 这个功能能否明显减少 CTF Reverse 选手找到关键逻辑所需要的时间？

如果答案是：

```text
不能
```

则降低开发优先级。

例如：

```text
新增一个 Hex Editor
```

通常不是核心。

而：

```text
识别 Input → Transform → Compare
```

是核心。

---

# 十三、ReverseHelper 与其他工具关系

不要试图替代：

```text
Ghidra
IDA
Binary Ninja
x64dbg
DIE
PE-bear
```

ReverseHelper 应处于：

```text
              ReverseHelper
                   ↓
        Reverse Analysis Triage
                   ↓
       ┌───────────┴───────────┐
       ↓                       ↓
    Ghidra                    IDA
       ↓                       ↓
 Deep Static Analysis     Deep Static Analysis
```

未来也可以输出：

```text
x64dbg Suggested Breakpoints
```

但动态闭环属于 TraceInfer。

---

# 十四、最终用户习惯目标

ReverseHelper 的长期成功标准不是：

> “别人知道有这个软件。”

而是让 CTF Reverse 选手形成：

```text
拿到题
 ↓
先丢 ReverseHelper
 ↓
看 Start Here
 ↓
打开 Ghidra / IDA
```

这样的肌肉记忆。

理想用户评价：

> “比赛不能用 AI 的时候，我拿到 Reverse 题第一件事就是跑 ReverseHelper。”

---

# 十五、最终产品口号

README 和产品定位统一为：

> ReverseHelper — Offline-first static reverse engineering workbench for CTF competitors.

或者：

> ReverseHelper helps CTF reversers find where to start.

核心原则：

> **Do not replace the reverser. Eliminate the mechanical work before the real reversing begins.**

