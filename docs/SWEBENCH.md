# 官方实例接入边界

当前固定实例为 `sympy__sympy-20590`，来自 [SWE-bench Lite 固定版本](https://huggingface.co/datasets/princeton-nlp/SWE-bench_Lite/tree/6ec7bb89b9342f664a54a6e0a6ea6501d3437cc2)。完整官方 row 和来源摘要位于 `evals/swebench/sympy__sympy-20590.json`；没有把自定义算法任务改称 SWE-bench。

`admit_swebench_instance` 接收调用方固定的 row 摘要、编辑路径和 oracle 路径。它核验实例身份、准确 F2P/P2P 名单和有限文本补丁语法，输出既有 TaskWorkspace 使用的最小任务映射。返回 `valid=True` 仍有 `execution_admitted=False`：没有执行 Git、检查目标对象或证明补丁适用性，也没有批准运行仓库代码。JSON 字节加载方必须先拒绝重复字段；该接口接收的是已解码 mapping。

`grade_swebench_instance` 只对外部可信证据做严格状态判定：全部 F2P 必须 FAIL→PASS，全部 P2P 必须 PASS→PASS。报告身份和完整名单必须一致；缺失、重复、额外 case、SKIP/ERROR、模糊前缀匹配均不能通过。空 P2P 返回 N/A。准确 ID 映射由调用方提供，评分器不推测 pytest/JUnit 名称。

两个模块只处理数据，不创建模型或执行器，不改变旧 S5a 合同和生产 verification 的 pytest JUnit 契约。

固定控制中，编辑范围可按 gold 文件审查；给模型同样的范围会泄漏答案位置，不能据此报告无提示官方成绩。模型只应接收问题及独立预登记的上下文，不接收 gold、test patch 或 hints。官方文件提供 1 个 F2P 和 21 个 P2P；完整测试文件应用 test patch 后有 23 个测试函数，评分名单与实际收集数必须分别记录。

Git 工作区现已隔离继承配置、hooks、模板、filters、fsmonitor 和 replace refs，拒绝借用对象和非普通 tree mode。该保护仍假定可信 Git 和无并发恶意写入者；不是任意对象库的 OS 沙箱、clone 过程硬配额或 blob 字节精确物化。30 秒父 Git timeout 也不是通用进程树截止。

已新增独立的协作式研究入口 `scripts/swebench_pilot.py`：真实官方源码/依赖与 G/O 分离、固定 host pytest observer、受限Docker、原 Architect→Developer/S1/SQLite/轨迹与HTTP人民币guard。固定源码从官方archive准备，不伪造Git提交，也不声称已取得base Git对象。源码、测试、依赖与observer身份分别检查，候选只可改变一个有界普通UTF-8文件。

研究结果恒标记 `COOPERATIVE_SWEBENCH_*`、`hinted_scope=true`、`adversarial_proof=false`。只读测试与候选处于同一Python进程仍可能被monkeypatch或伪造stdout；严格F2P/P2P只核验结构和状态，不提供反作弊证明。该通道由用户明确选择，不改变默认生产宿主准入或恢复旧Windows profile。

CLI 的 `--prepare` 不联网、不读取凭据或调用Docker；`--check` 消费一次检查记录且不发模型请求；`--run` 必须显式提供新的预算，先通过官方输入、clean源码、当日价格和模型配置门槛。缺条件返回 `NOT_STARTED`。旧3元批次不自动续用；单次八请求峰值总预留0.917504元，上限1元，无HTTP重试或整trial自动恢复。S2有限regression repair保留，总请求上限不变。源码入口需要项目数据和锁环境，不是wheel console命令。

```text
uv run --locked python scripts/swebench_pilot.py --help
uv run --locked python scripts/swebench_pilot.py --prepare --output .research-cache/cooperative-check --artifacts-root .research-cache/swebench-official-research
uv run --locked python scripts/swebench_pilot.py --check --output .research-cache/cooperative-check --env-file .env.local
```

检查后的目录不能重用。真实运行须另建fresh目录、完成当版无模型控制并获得新预算，再显式传 `--new-batch-budget-cny` 和 `--max-trial-cny`；不要把密钥写在命令行或发送到聊天。输入需预先在artifact目录准备 `sympy-base.tar.gz`、`mpmath-1.3.0-py3-none-any.whl` 与规范化官方row；实现中的PINS逐字节校验，拒绝自动替换或网络fallback。

本地数据合同检查：

```text
uv run --locked python -m unittest -v tests.evaluation.test_swebench_instance
```

项目全量支持检查仍采用 CONTRIBUTING.md 的两个正式 suite。实际控制及模型成绩需按准确源码版本单独记录；固定控制不能替代新候选的执行证据，也不是整体SWE-bench resolved rate。多文件/新依赖/无提示holdout仍不在此固定一文件研究通道的支持范围。
