# 原生候选研究边界

新增具体Requests原生执行器及`native_graph_factory`，复用原Architect→Developer、S1事务、S2有限repair和SQLite。仅支持审定的Requests3362历史配方，不接受任意repo/argv/trusted开关。Windows AppContainer撤销状态保持。

调用方先持有`native_requests.ownership.lease_owner`，再进入`tls.fixed_tls_materials`；同一所有者锁覆盖材料创建、图执行及最终清理。NativeRequestsRunner只接收固定来源树、16个固定wheel、可信测试patch和材料数据。候选挂载没有gold patch；原生日志是非可信数据，宿主固定pytest逐项断言产生真实JUnit。

每次执行绑定原图已armed的VerificationAttempt；32位receipt UUID与64位attempt SHA分别保留。数据审计核对case、image/environment、原图结果、RunRecord、修复路径及最终源码。只有regression能进入下一repair；未知创建或清理不能接受。

已有本地真实Mock SDK→S1→原生Docker→JUnit→SQLite/receipt控制，以及父进程硬退出后的独立精确清理控制。Mock控制不是模型效果；中断恢复只清理资源，不把SQLite STARTED恢复成成功，也不自动重跑。

20题、各一次、总4元评测仍须独立满足环境、源码、精确CI和财务门。账本只在明确RELEASED且无active/UNKNOWN时手工续接，close终结；不能新建目录绕过原授权。两种受审wire ID为deepseek-flash、deepseek-v4-flash，保留原ID。旧ID的当前服务版本和价格需按[官方说明](https://api-docs.deepseek.com/zh-cn/quick_start/pricing/)记录，不能当固定旧权重。

环境摘要用于本次baseline/post同材料核对，包含本机路径的实现摘要不保证跨机器同值。Docker协作式结果不能防候选伪造日志，不等于官方harness或Windows隔离安全恢复。
