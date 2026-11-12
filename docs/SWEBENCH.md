# 官方实例接入边界

当前固定实例为 `sympy__sympy-20590`，来自 [SWE-bench Lite 固定版本](https://huggingface.co/datasets/princeton-nlp/SWE-bench_Lite/tree/6ec7bb89b9342f664a54a6e0a6ea6501d3437cc2)。完整官方 row 和来源摘要位于 `evals/swebench/sympy__sympy-20590.json`；没有把自定义算法任务改称 SWE-bench。

`admit_swebench_instance` 接收调用方固定的 row 摘要、编辑路径和 oracle 路径。它核验实例身份、准确 F2P/P2P 名单和有限文本补丁语法，输出既有 TaskWorkspace 使用的最小任务映射。返回 `valid=True` 仍有 `execution_admitted=False`：没有执行 Git、检查目标对象或证明补丁适用性，也没有批准运行仓库代码。JSON 字节加载方必须先拒绝重复字段；该接口接收的是已解码 mapping。

`grade_swebench_instance` 只对外部可信证据做严格状态判定：全部 F2P 必须 FAIL→PASS，全部 P2P 必须 PASS→PASS。报告身份和完整名单必须一致；缺失、重复、额外 case、SKIP/ERROR、模糊前缀匹配均不能通过。空 P2P 返回 N/A。准确 ID 映射由调用方提供，评分器不推测 pytest/JUnit 名称。

两个模块只处理数据，不创建模型或执行器，不改变旧 S5a 合同和生产 verification 的 pytest JUnit 契约。

固定控制中，编辑范围可按 gold 文件审查；给模型同样的范围会泄漏答案位置，不能据此报告无提示官方成绩。模型只应接收问题及独立预登记的上下文，不接收 gold、test patch 或 hints。官方文件提供 1 个 F2P 和 21 个 P2P；完整测试文件应用 test patch 后有 23 个测试函数，评分名单与实际收集数必须分别记录。

Git 工作区现已隔离继承配置、hooks、模板、filters、fsmonitor 和 replace refs，拒绝借用对象和非普通 tree mode。该保护仍假定可信 Git 和无并发恶意写入者；不是任意对象库的 OS 沙箱、clone 过程硬配额或 blob 字节精确物化。30 秒父 Git timeout 也不是通用进程树截止。

真实模型评测仍需独立完成可信执行/报告准入、多文件与依赖环境控制、预登记预算和重复运行。只读测试与候选处于同一 Python 进程时仍可能被 monkeypatch 或伪造 stdout；固定原始/gold/wrong 控制不能消除这项限制。旧 Windows profile 保持撤回。本轮不新增模型费用。

本地数据合同检查：

```text
uv run --locked python -m unittest -v tests.evaluation.test_swebench_instance
```

项目全量支持检查仍采用 CONTRIBUTING.md 的两个正式 suite。固定控制日志属于对应输入、环境和版本，不能替代新候选的执行证据，也不是整体 SWE-bench resolved rate。
