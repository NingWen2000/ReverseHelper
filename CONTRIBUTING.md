# Contributing

ReverseHelper 的定位是 **Offline-First CTF Reverse Engineering Workbench**。贡献前请阅读[产品目标](docs/product-goals.md)、[路线图](docs/roadmap.md)和 [Benchmark 规范](benchmarks/README.md)。

每项功能或规则改动应说明：它如何缩短选手找到关键逻辑的 TTCF？优先完善目标排序、输入到验证的静态切片、验证发现和高价值字符串关联。算法数量、规则数量和界面功能数量不作为主要成功指标。

1. 不要提交未获授权的二进制、Flag、恶意样本、凭据或个人数据。
2. 新规则应说明检测证据、可能误报和适用范围。
3. 修改 Python 代码后运行 `python -m pytest --cov=reversehelper`。
4. PR 请保持范围清晰，并同步更新相关文档或测试。
5. 核心功能必须离线可用，不引入云端推理、登录、API Key、上传或必需遥测；可选扩展不能成为核心依赖。
6. 候选必须有证据、置信度、可追溯地址和下一步静态操作；未知字段保留未知，不把控制流可达性写成输入数据流。
7. Quick 的首次有用结果不能等待 Deep 完成；模块失败应局部降级，说明失败或截断范围。
8. 对性能或准确率的声明附上真实测量条件、样本数量和结果；合成测试、设计目标与公开 CTF 实测分开报告。
