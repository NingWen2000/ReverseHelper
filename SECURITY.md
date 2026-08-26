# Security Policy

## Reporting a vulnerability

请不要在公开 Issue 中发布能够直接利用的未修复漏洞、恶意样本、Flag、凭据或个人数据。请通过 GitHub Security Advisories 的私密报告功能联系维护者，并提供可复现的最小测试数据。

## Analyzing untrusted files

ReverseHelper 不会主动执行目标文件，但 PE 解析仍会处理攻击者控制的数据。分析未知或恶意样本时，请在隔离虚拟机中运行，并保持 Python、`pefile` 与 Ghidra 为受支持版本。
