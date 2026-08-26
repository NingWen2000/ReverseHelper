# PatchMe 第 20 章：从初筛到补丁候选

这是 ReverseHelper 的第一个真实小样本记录。目标不是把输出包装成自动化结论，而是看看初筛结果能否减少进入 Ghidra 后的无效查找。

## 样本身份

- 文件名：`unpackme#1.aC.exe`
- 文件大小：5120 bytes
- SHA-256：`E23B7B4F5772DB3E0AE0FC3FCE409F9B2318802383F1845FD892E83D94084A92`
- 架构：x86
- ImageBase：`0x400000`
- EntryPoint：RVA `0x1000` / VA `0x401000` / file offset `0x400`

仓库不附带 EXE。使用文末来源下载后，应先核对哈希，再在隔离环境中操作。

## ReverseHelper 给出的切入点

`.text` 的权限是 RWX，熵为 `4.750`。熵不高，因此不能按“高熵壳”处理；更值得注意的是代码节可写。入口附近的原始字节为：

```text
60 E8 E3 00 00 00 C3 EC 20 44 75 44 27 68 61 27
```

新版入口检查会把前七个字节识别为：

```asm
PUSHAD
CALL 0x4010E9
RET
```

CALL 目标由相对位移计算得到，不需要先在 Ghidra 中手动追踪。RWX 与紧凑入口桩同时出现，只能说明它值得优先检查运行时写入，不能单凭这两项断言已加壳。

导入表只有 `user32.dll` 和 `kernel32.dll` 的 9 个函数。`DialogBoxParamA`、`SetDlgItemTextA`、`MessageBoxA`、`EndDialog` 表明主体很可能是对话框程序。文件偏移 `0x408` 开始出现乱码；地址映射为 RVA `0x1008`、VA `0x401008`，位于 `.text`。

## Ghidra 中确认的解密路径

入口调用的 `0x4010E9` 把 `0x4010F5` 传给 `0x40109B`。两轮处理如下：

```text
0x4010F5 .. 0x401248  XOR 0x44
0x401007 .. 0x401085  XOR 0x07
0x4010F5 .. 0x401248  XOR 0x11
```

第一块最终等效于 XOR `0x55`。第二块解密后包含校验逻辑：从 `0x4010F5` 开始进行 `0x154` 次重叠 DWORD 加和，与 `0x31EB8DB0` 比较。校验通过后，程序解密导入跳板并跳转到 `0x40121E`；这个地址是当前的 OEP 候选。

这里的“候选”很重要：以上由静态字节还原和 Ghidra Listing 得到，尚未在 x32dbg 中通过执行断点确认。

## 从直接绕过到 Inline Patch

最初根据静态解密得到的方案，是修改校验分支并跳过 `0x4011B4` 的 NAG 弹窗。它改动少，但本质是绕过保护，不能体现本章的 Inline Patch 思路。

官方仓库同时提供了 patched 版本。只读比较两份 5120-byte 文件后发现，共有 49 个字节不同：一个字节用于重定向控制流，其余非零字节位于原文件的零填充区。ReverseHelper 的代码洞检查把这段空间定位为：

```text
Section .text / RAW 0x680 / RVA 0x1280 / VA 0x401280
```

文件偏移 `0x484` 从 `91` 改成 `FF`。这处字节经过入口的 XOR `0x07` 后，使 `0x401083` 的跳转由：

```asm
JMP 0x40121E
```

变为：

```asm
JMP 0x401280
```

`0x401280` 的代码洞中加入：

```asm
MOV ECX, 0x0C
MOV ESI, 0x4012A8       ; "ReverseCore\0"
MOV EDI, 0x401123       ; 原 NAG 文本
REP MOVSB

MOV ECX, 0x09
MOV ESI, 0x4012B4       ; "Unpacked\0"
MOV EDI, 0x40110A       ; 原状态文本
REP MOVSB

JMP 0x40121E
```

受校验区域在计算校验和时没有被修改，所以原比较仍然成立。补丁代码在校验通过后才覆盖两段提示文本，随后回到原程序入口候选。这就是本例 Inline Patch 的关键：把新增逻辑放进代码洞，通过一处控制流修改接入，再回到原执行路径。

官方 patched 文件的字节差异已静态核对；本地仍未执行它。若要完成动态验证，应在 x32dbg 中确认 `0x401280` 被执行、两次 `REP MOVSB` 的目标内存发生变化，以及最后确实到达 `0x40121E`。

## 样本来源

样本来自《逆向工程核心原理》第 20 章配套文件，作者维护的公开仓库：

- <https://github.com/reversecore/book>
- [第 20 章原版与 patched 样本目录](https://github.com/reversecore/book/tree/master/实습예제/02_PE_File_Format/20_인라인_패치_실습/bin)

该仓库没有声明可识别的开源许可证，因此 ReverseHelper 只记录样本身份、分析过程和来源链接，不重新分发原始或修改后的二进制。
