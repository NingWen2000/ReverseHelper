# very simple keycheck：从输入变量追到 ECX

> 来源：Crackmes.one / kcgaming
>
> 分类：Windows x64 Reverse
>
> 网站难度：1.0
>
> 完成日期：2026-09-03
>
> 验证状态：静态汇编核对 + 原程序运行验证

这道题的校验很短，实际卡住的地方是 C++ 输入输出函数的长名称，以及 Ghidra 没有正确关联的函数参数。解题时需要回答的不只是“比较常量是多少”，还有“凭什么知道参与比较的就是输入”。

本次用 PowerShell 做黑盒测试和最终验证，用 DIE 初筛文件，在 Ghidra 中查看反编译与交叉引用，并用反汇编输出复核关键地址。没有记录 x64dbg 断点命中或寄存器现场；下文的寄存器传递结论来自静态指令。

## 样本信息

题目页面：[kcgaming's very simple keycheck](https://crackmes.one/crackme/6a503f2ab1e3022155040e63)。

| 项目 | 记录 |
| --- | --- |
| 文件名 | `password.exe` |
| 文件大小 | 80309 bytes，约 78.43 KiB |
| SHA-256 | `0281DD6F6D72F610A6C9A2B260D325E34AC760BB6DF3AA241008573C3302D6BA` |
| 格式与架构 | PE32+ / AMD64 / Windows 控制台程序 |
| ImageBase | `0x140000000` |
| PE 入口 RVA | `0x1046` |
| `main` | VA `0x140001726` / RVA `0x1726` |
| `checkPassword` | VA `0x140001710` / RVA `0x1710` |

本文地址基于上述静态 ImageBase；调试时若模块重定位，应使用实际模块基址加 RVA。PE 入口与 C++ 的 `main` 不是同一个位置。

仓库只保存分析记录，不重新分发 EXE、压缩包或带个人路径的原始截图。附件的统一解压密码见 [Crackmes.one FAQ](https://crackmes.one/faq)，它与程序要求的口令是两回事。

## 黑盒：相同报错能说明多少

最初尝试：

```powershell
'aa' | .\password.exe
'aaaa' | .\password.exe
```

另一次输入了更长的连续字母，三次都显示：

```text
Enter number: Access Denied
```

当时只改变了字母串长度，却忽略了 `Enter number:` 这个提示。以上结果只能说明这些输入被拒绝，不能据此认定程序有固定长度检查，也不能判断失败发生在数字读取阶段还是后续校验阶段。

随后改用整数 `41`，分别做字符串管道、数字管道与交互输入：

```powershell
'41' | .\password.exe
41 | .\password.exe
.\password.exe
```

交互输入的实际结果：

```text
Enter number: 41
Access Denied
```

三种方式都得到拒绝，没有观察到输入方式改变可见结果。继续随机猜数字带来的信息有限，于是转入文件初筛和静态分析。

## DIE 初筛

DIE 3.2.0 的界面显示：

- 文件类型 `PE64`，模式 `64 位`，架构 `AMD64`，字节序 `LE`；
- 类型为控制台程序；
- `Compiler: MinGW`；
- `(Heur) Language: C++`；
- 检测到 `.debug_aranges` 调试信息节；
- Overlay 偏移为 `0xB200`，大小为 `0x87B5`。

编译器与语言识别作为工具线索保留，尤其 `Heur` 表示启发式判断。当前扫描没有列出明确壳名；Overlay 和调试节本身都不能证明加壳或无壳。

后续可以直接读到 `main` 和 `checkPassword` 的静态代码，因此这次没有进行脱壳。

## 先缩小 main 的阅读范围

Ghidra 中可以看到 `Enter number:`、`Access Denied`、`Access Granted`，以及保留的 `main`、`checkPassword` 函数名称。沿提示字符串的引用和函数调用关系，能把阅读范围缩小到主函数与校验函数。

主函数里有很多 `std::` 开头的长名称。结合导入与实参，其主要行为是：

1. 用 `cout` 输出输入提示；
2. 用 `cin` 把整数读入 `pass`；
3. 调用 `checkPassword`；
4. 返回值为零时输出拒绝，非零时输出成功；
5. 最后调用 `ignore()`、`get()` 处理输入流；它们位于成功/失败分支之后。

下面是按实际数据流整理的主流程节选，不是提取出的原始源码：

```cpp
int pass;
std::cout << "Enter number: ";
std::cin >> pass;

if (checkPassword(pass) != 0) {
    std::cout << "Access Granted\n";
} else {
    std::cout << "Access Denied\n";
}
```

原来的反编译结果却把调用参数显示成 `in_stack_...`，并提示：

```text
WARNING: Unknown calling convention
```

这时不应该仅按伪代码变量名理解输入。需要回到调用点，确认参数实际从哪里来。

## 为什么 in_ECX 就是这次的输入

### 输入先落在 main 的栈变量中

`main` 中输入调用附近的指令为：

```asm
140001749  LEA  RDX, [RBP-0x4]
14000174D  MOV  RAX, QWORD PTR [RIP+0x3C4C] ; cin 对象地址
140001754  MOV  RCX, RAX
140001757  CALL 0x1400017E8                ; _ZNSirsERi，读取 int&
```

这里 `LEA` 取的是 `[RBP-0x4]` 对应位置的地址。它与反编译中的 `&pass` 一致：输入函数获得存储位置，把解析出的整数写进去。

此时 `RCX` 用于传递输入流对象，`RDX` 传递目标变量地址。寄存器的用途要结合当前调用，不能把 `RCX` 永远理解成用户输入。

### 调用校验函数之前，输入被搬到 ECX

输入调用返回后，紧接着是：

```asm
14000175C  MOV  EAX, DWORD PTR [RBP-0x4]
14000175F  MOV  ECX, EAX
140001761  CALL 0x140001710                ; checkPassword
```

第一条从刚才的输入位置读取四字节整数；第二条把它复制到 `ECX`；第三条立即调用校验函数。因此在这个调用点，`ECX` 中保存的是输入变量的值。

Windows x64 默认调用约定使用 `RCX` 传递第一个整数参数；本题参数是 32 位的 `int`，使用其低 32 位 `ECX`。这与指令中的传递方式相符，参见 [微软 x64 调用约定](https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention?view=msvc-170)。

### 被调函数确实使用了入口 ECX

`checkPassword` 的完整汇编只有 22 字节、8 条指令：

```asm
140001710  PUSH  RBP
140001711  MOV   RBP, RSP
140001714  MOV   DWORD PTR [RBP+0x10], ECX
140001717  CMP   DWORD PTR [RBP+0x10], 0x4D2
14000171E  SETZ  AL
140001721  MOVZX EAX, AL
140001724  POP   RBP
140001725  RET
```

函数建立自己的栈帧后，把入口 `ECX` 保存到 `[RBP+0x10]`，然后比较保存的值。这里的 `RBP` 与 `main` 中的 `RBP` 已不同；两个栈位置通过寄存器传值，并不是同一块内存。

数据流可以连成：

```text
输入文本被解析成整数
  → main 的 pass（[RBP-0x4]）
  → EAX
  → ECX
  → checkPassword 保存参数
  → 与 0x4D2 比较
```

Ghidra 当时显示：

```cpp
int checkPassword(int x)
{
    int in_ECX;
    return (int)(in_ECX == 0x4d2);
}
```

这里 `in_ECX` 表示函数入口时的 ECX 值，不表示读取标准输入。反编译器没有正确把这个值关联到形参 `x`；也不能把伪代码里的局部声明当成源码中“未初始化变量”的证据。具体参数恢复问题的成因，本次没有进一步定位。

认定它是用户输入，依据是调用方与被调函数的指令衔接，而不是 `in_` 这个名字。

## 还原比较条件

`CMP` 比较两个值并设置标志，不会把比较结果写回操作数。相等时 ZF 为 1；紧跟的 `SETZ AL` 将相等结果写成 `1`，不相等则写成 `0`。随后 `MOVZX EAX, AL` 把它零扩展为整数返回值。

因此函数可以整理成：

```cpp
int checkPassword(int x)
{
    return x == 0x4D2;
}
```

主函数在调用之后检查这个返回值：

```asm
140001766  TEST  EAX, EAX
140001768  SETNE AL
14000176B  TEST  AL, AL
14000176D  JE    0x140001787  ; 返回值为零时进入拒绝分支
```

十六进制常量换算为：

```text
0x4D2 = 4 × 16² + 13 × 16 + 2 = 1234
```

所以应提交十进制整数 `1234`。不需要写求解脚本，也不需要修改校验分支。

## 原程序运行验证

在 PowerShell 中直接启动原程序并输入候选值：

```powershell
.\password.exe
```

实际终端记录：

```text
Enter number: 1234
Access Granted
```

这一步验证了还原出的输入能够通过原程序。此前的 `41` 是拒绝样本，`1234` 是接受样本。

这里记录的是直接运行的输入与输出，没有声称在 x64dbg 中观察过 `ECX`、ZF 或 `EAX` 的现场，也没有用修改程序后的成功提示替代真实输入验证。

## 这次值得保留的教训

最初看到长长的 C++ 名称和奇怪的 `in_stack_...`，容易把“反编译结果不清爽”理解成“校验算法复杂”。实际跟到 `checkPassword` 后，关键逻辑只有一次比较。

另一个容易误判的地方是：几组不同长度的字母都失败，并不能推出长度限制。应先读懂输入提示，再通过代码确认解析方式和失败分支。

这题更可复用的收获是追踪传参：遇到 `in_ECX` 这样的入口寄存器值，回到调用点找最后一次赋值，再追它的来源；不要仅凭变量名下结论。静态数据流解释了程序为什么接受该输入，原程序运行结果则验证了这个结论。
