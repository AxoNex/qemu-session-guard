# ADR-0007：审计同时记录模型意图与实际执行（含拒绝）

- 状态：已接受
- 日期：2026-10-25
- 相关安全不变量：**不变量 7**（审计双层、拒绝也留痕）

## 背景

仅有"执行了什么"的日志无法回答"模型想干什么"；仅有"模型请求了什么"又无法
证明"实际执行的是同一件事"。安全审计需要把**模型意图**与**实际执行**都
落库，且**被拒绝的尝试同样留痕**（用于探测行为分析与合规取证）。

## 决策

每条 `AuditEntry` 包含：

- `model_params`：模型 tool 调用时的**原始参数**（注入尝试时的
  `rejected_fields` 也记录）——意图层；
- `executed`：实际发生的底层动作列表，例如
  - `vm_start.exec` 记录的**完整 QEMU 命令行**（含基线参数、QMP 地址、
    卷路径），
  - `qmp` 记录的**实际 QMP 命令**（`stop` / `cont` / `quit` /
    `system_powerdown`）——执行层；
- `result`：`allowed / denied / pending_approval`；
- `deny_reason`：内部真实原因（脱敏前的），存在性信息只进这里；
- `approval_id`：关联的审批单（若有）；
- `actor`：`model / webui / system`。

要求：

1. **拒绝也入库**（`denied`），包括注入尝试、越权、配额不足；
2. 审计写入是同步的（`AuditLog.record` 先写 SQLite 再广播 WS），避免丢；
3. `GET /api/audits` 支持按 `session_id / vm_id / result / 时间窗` 过滤，
   并可 `format=csv` 导出。

## 后果

- 任意一次 VM 变更都能从"模型意图 → 权限决定 → 实际执行"完整还原；
- 探测 / 注入行为有独立 `denied` 记录可统计；
- 代价：审计表增长快（每次调用一行），需定期归档（README 路线图）。
