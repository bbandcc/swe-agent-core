# 多文件、依赖与无提示评测准备

新数据接口与既有生产执行准入分开；不恢复已撤回的Windows profile，不改变单文件hinted试点的原始结果。

- `freeze_candidate(B,G,CandidatePolicy,destination)`：捕获完整允许树，支持多个UTF-8文件EDIT/CREATE，返回准确文件/tree/patch摘要；保护路径、删除、链接、超限和源漂移拒绝。scope由可信预注册策略提供，不从gold答案生成。它是字节快照，不是多文件原子写事务或OS沙箱。
- `prepare_dependency_bundle(cache,pins,destination)`：只接受受审hash/名称/版本的纯Python wheel，拒绝危险ZIP布局并复制校验过的同一bytes。没有host import/build/install；完整依赖解析、native/sdist构建不在该接口内，execution_admitted=false。
- `build_benchmark_manifest`／`scripts/prepare_benchmark.py`：固定Lite revision、20题分层确定性采样、排除已见实例/base。推理视图只有问题、repo和base；gold/hints/oracle保留评测侧。Lite过滤多文件修复，不能据其成绩声称多文件覆盖。
- `SettledTrialTransport`：独立新合同，每题0.2元，20题分配总4元。每请求仍通过旧协议/usage guard并先保留最坏费用，仅在已知结算审计落盘后释放差额；未知/失败不释放、停止后续请求。最多20次尝试，余额不足则本地拒绝；旧不可退款账本不改写。它不是已经接通的批次执行器，启动仍需任务环境/价格/源码/预算准入。
- `scripts/windows_guest_preflight.ps1`：PowerShell7只读环境报告；Home、缺失或未知能力保持拒绝。即使HOST_READY也不授权执行，必须另有固定guest与真实正负/生命周期验收。

这些能力通过公开接口测试；多文件/固定wheel还通过作者编写的真实Docker控制。作者控制、元数据准备和模型评测不是同类证据。20题真实运行需要逐题环境控制与无提示有界上下文/具体runner接线；缺条件保留NOT_STARTED，不调用模型凑数量。

已提供全repo有界工具和durable runtime seam，以及固定JSON-case RepositoryObserverRunner/具体RepositoryAdmission/repository_graph_factory。host只加载项目静态observer，外来oracle只入Docker。完整作者Mock→两文件→Docker→SQLite控制通过；其证据仍是cooperative，并非防伪oracle或官方12repo harness适配。BenchmarkBatchAllowance只负责20×0.2一次性串行财务槽，不赋予执行安全或评分准入。
