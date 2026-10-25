# ADR-0006：QMP 客户端默认用内置极简实现而非 qemu.qmp

- 状态：已接受
- 日期：2026-10-25
- 相关安全不变量：不变量 4（QMP 通道由插件实现、可审计）

## 背景

最初设计优先使用 QEMU 官方 Python 库 `qemu.qmp`（`qemu.qmp.QMPClient`）。
在 Python 3.14 上实测发现：`qemu.qmp` 0.0.6 在 capabilities 协商阶段
`Negotiation failed: CancelledError`——QMP 服务端确实收到了
`qmp_capabilities` 并已回 `{"return": {}}`，但客户端 `_recv` 挂起直到
`wait_for` 超时。多份 `debug_qmp*.py` 复现确认是 `qemu.qmp` 0.0.6 与
Python 3.14 的兼容性问题（服务端收发正常，卡在客户端 `_negotiate` 内
`_readline`）。

## 决策

1. **默认使用内置 `_MiniQMP`**（`qmp_client.py`）：约 120 行 asyncio
   streams 实现，只做三件事——读 greeting、发 `qmp_capabilities` 完成协商、
   按递增 id 分发命令响应并把无 id 的 `{"event": ...}` 交给事件回调；
2. 环境变量 `QSG_QMP_BACKEND=official` 可切回官方库（未来该库修复
   Python 3.14 兼容后）；
3. 两种后端暴露相同接口（`QmpSession.connect / execute / disconnect /
   connected`），上层 QmpBroker 不感知差异。

## 理由

- 内置实现协议面足够小、完全可审计（安全不变量 4 要求 QMP 通道由插件
  独占且可控）；
- 避免被上游库的版本兼容性阻塞交付；
- 官方库并未提供我们需要的额外能力（异步事件流、超时控制内置实现都有）。

## 后果

- 默认路径在 Python 3.14 + MSYS2 QEMU 上可用；
- 保留官方库作为可选后端，便于未来回归；
- 代价：内置实现需自行维护（协议面极小，风险低）。
