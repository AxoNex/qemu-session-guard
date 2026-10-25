# ADR-0004：vm_force_off 默认需一次性审批，审批可过期、一次性

- 状态：已接受
- 日期：2026-10-25
- 相关安全不变量：**不变量 6**（破坏性操作显式审批）

## 背景

`vm_force_off`（QMP `quit`）相当于直接拔电源：guest 无机会落盘，可能损坏
镜像或丢失数据。其余电源操作（`vm_shutdown` = ACPI 关机、`vm_stop`/`vm_resume`
= 暂停/继续）可恢复，唯独 `quit` 不可逆。让模型自主执行不可逆操作风险过高。

## 决策

1. `SessionPerms.approval_actions` 默认包含 `vm_force_off`（管理员可按会话
   覆盖为空列表以放开，或加入其他 action 收紧）；
2. 命中审批的调用**不立即执行**：PermissionEngine 创建一条 `Approval`
   （含 `params` 原样、绑定的 `session_generation`、5 分钟过期），tool 调用
   挂起在 `wait_for_approval`；
3. WebUI 审批后 `decide_approval(approve=True)`，挂起的调用继续执行；
   拒绝则返回"操作未获批准"；超时未决自动 `EXPIRED`，返回"审批超时"；
4. 审批**一次性**：每条 `Approval` 只授权**这一次**调用及其**当时绑定的
   params**（`{"vm_id": "lc-vm"}`），模型不能事后替换参数或复用批准；
5. 审批全生命周期进审计：`pending_approval`（模型意图）→
   `approval.approved / approval.rejected / approval.expired`（管理员决定）。

## 后果

- 不可逆操作始终有人工在环；
- params 原样绑定杜绝"批 A 执行 B"；
- 过期机制防止"批了放着以后用"；
- 代价：实时性依赖管理员在线（WebUI 实时状态页有 approval 提醒与 toast）。
