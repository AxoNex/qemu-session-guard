# qemu-session-guard

面向 **LLM Agent 会话** 的、**会话作用域 + 权限受控** 的 QEMU 虚拟机管理插件。
模型从不接触原始 QEMU 命令行，只能通过一组**结构化工具**操作被授权的 VM；
所有 QMP socket 由插件独占管理。兼容 **MSYS2（UCRT64 / MINGW64）** 上的
QEMU，也支持单独的 QEMU for Windows 安装。

```
模型（LLM）                管理员（WebUI）
    │                          │
    │ 结构化 tool 调用          │ 注册 VM / 卷 / 会话 / 审批 / 审计
    ▼                          ▼
┌──────────────────────────────────────────────────┐
│                 Controller（FastAPI）             │
│  SessionGuard ── PermissionEngine ── AuditLog    │
│         │              │                          │
│         │        QmpBroker（spawn + QMP 独占）     │
│         │              │                          │
│         └─── 不可变会话权限快照（不变量 3）          │
└──────────────────────────────────────────────────┘
                     │ 受控 argv（不变量 1、5）
                     ▼
        QEMU 进程池（QMP over loopback/unix，插件独占）
```

---

## 目录

- [安全不变量](#安全不变量)
- [威胁模型](#威胁模型)
- [安装](#安装)
- [快速开始](#快速开始)
- [配置](#配置)
- [模型工具（tools）](#模型工具tools)
- [管理 REST API](#管理-rest-api)
- [WebSocket 实时事件](#websocket-实时事件)
- [审计](#审计)
- [MSYS2 / QEMU 发现](#msys2--qemu-发现)
- [安全基线与禁止参数](#安全基线与禁止参数)
- [测试](#测试)
- [架构决策记录（ADR）](#架构决策记录adr)
- [项目结构](#项目结构)
- [路线图](#路线图)

---

## 安全不变量

以下不变量是本系统的**安全契约**；触及它们的代码路径都用 `不变量 N` 注释标注。

| # | 不变量 | 关键实现 |
|---|--------|----------|
| 1 | **模型永不接触原始 QEMU CLI**——只暴露语义化工具 | `tools.ModelTools` |
| 2 | **存在性不泄露**——不可见 VM 与不存在 VM 报文完全一致 | `VMNotVisibleError` / `PermissionDeniedError` 同 `public` |
| 3 | **会话权限快照不可变**——权限变更只影响**后续**调用 | `SessionGuard.snapshot()` 深拷贝 + `perms_generation` |
| 4 | **QMP socket 插件独占**——模型得不到地址、不可自建通道 | `QmpBroker._alloc_qmp_address` + 禁 `-qmp/-monitor/-chardev` |
| 5 | **启动基线强制** + **禁用危险参数** | `baseline_args()` + `validate_extra_args()` |
| 6 | **破坏性操作显式审批**——一次性、可过期、绑定参数 | `PermissionEngine` + `Approval` |
| 7 | **审计双层**——模型意图 + 实际执行（含拒绝） | `AuditEntry.model_params / executed` |
| 8 | **不硬编码 MSYS2 路径** | `qemu_discovery.discover` 优先级搜索 |

## 威胁模型

**保护什么**：宿主机文件系统、网络、其他会话的 VM、以及"哪些 VM 存在"这一
元信息。

**防谁**：被提示注入 / 越权诱导的模型输出，以及把模型输出直接转成命令的
宿主框架。假设模型可能尝试：

- 传 `-kernel/-initrd/-append` 加载任意内核 → **被禁**（不变量 5）；
- 传 `-drive file=/etc/passwd` 或 `-fsdev/-virtfs` 挂宿主目录 → **被禁**；
- 传 `-netdev ...,hostfwd=...` 做端口转发 → **被禁**；
- 自建 `-qmp`/`-monitor`/`-chardev` 拿特权通道 → **被禁**；
- 在 tool 参数里塞 `qemu_args`/`cmdline` 等字段注入命令行 → **被 strict
  schema + 禁用参数名拒绝并审计**；
- 用 `session_id` 覆盖会话作用域 → **被剥除**；
- 枚举 VM id 探测拓扑 → **报文不可区分 + 探测限流告警**；
- 直接 `vm_force_off` 毁数据 → **默认需人工审批**。

**不在范围**：QEMU 自身漏洞、宿主机 OS 加固、WebUI 的认证鉴权（默认监听
loopback，面向本机受信管理员）。

## 安装

需要 **Python 3.10+**（开发使用 3.14）。

```bash
cd backend
python -m pip install -r requirements.txt
```

依赖：`fastapi`、`uvicorn`、`pydantic`、`PyYAML`、`qemu.qmp`（可选后端）、
`psutil`（资源指标，可选）、`pytest` + `pytest-asyncio` + `httpx`（测试）。

## 快速开始

```bash
# 1) 指向你的 MSYS2（默认 C:\msys64，可用环境变量覆盖）
set MSYS2_ROOT=C:\msys64          # 或 export MSYS2_ROOT=...
::  也可以直接指定 QEMU 目录，优先级最高
set QEMU_BINARY_DIR=C:\msys64\ucrt64\bin

# 2) 启动（默认 127.0.0.1:8787）
cd backend
python -m qemu_session_guard.server
# 或： python -m qemu_session_guard   （等价入口）

# 3) 打开 WebUI
::  http://127.0.0.1:8787/
```

WebUI 五个视图：**VM 注册 / 会话管理 / 权限矩阵 / 审计日志 / 实时状态**。

典型流程（也可全在 WebUI 完成）：

```bash
# 发现可用 QEMU
curl http://127.0.0.1:8787/api/qemu/discover

# 预注册一个磁盘卷（模型只能引用卷 id，不能写宿主路径）
curl -X POST http://127.0.0.1:8787/api/volumes \
  -H "Content-Type: application/json" \
  -d '{"id":"disk0","path":"D:\\img\\alpine.qcow2","read_only":false}'

# 注册 VM（qemu_binary 用发现接口返回的路径）
curl -X POST http://127.0.0.1:8787/api/vms \
  -H "Content-Type: application/json" \
  -d '{"id":"alpine","qemu_binary":"C:\\msys64\\ucrt64\\bin\\qemu-system-x86_64.exe",
       "machine":"q35","vcpus":2,"mem_mb":1024,"disk_volume_ids":["disk0"]}'

# 创建会话：可见 alpine，read+power，vm_force_off 需审批（默认）
curl -X POST http://127.0.0.1:8787/api/sessions \
  -H "Content-Type: application/json" \
  -d '{"label":"agent-1","granted_vm_ids":["alpine"],
       "permission_map":{"alpine":["read","power"]}}'
# → 返回 {"id": "<session_id>", ...}
```

模型侧通过宿主框架拿到的 tool 调用（下表）都以 `session_id` 作用域执行。
WebUI 的「会话管理」页提供了**模拟模型调用**入口便于调试。

## 配置

配置来源（后者覆盖前者）：内置默认值 → YAML 配置文件 → 环境变量。

| 环境变量 | 默认 | 说明 |
|----------|------|------|
| `QSG_CONFIG` | — | YAML 配置文件路径 |
| `QSG_DATA_DIR` | `./data` | 数据目录（SQLite、QMP socket） |
| `QEMU_BINARY_DIR` | — | 显式 QEMU 目录（**最高优先**） |
| `MSYS2_ROOT` | `C:\msys64` | MSYS2 安装根（用于推导 ucrt64/mingw64 bin） |
| `QSG_HOST` | `127.0.0.1` | 监听地址 |
| `QSG_PORT` | `8787` | 监听端口 |
| `QSG_TOKEN_SECRET` | 随机（仅内存） | 预留的会话签名密钥 |
| `QSG_QMP_BACKEND` | `mini` | QMP 客户端后端：`mini`（默认，ADR-0006）或 `official` |

## 模型工具（tools）

宿主框架把下列 tool 注册给模型。所有 tool 都以 `session_id` 作用域执行，
返回 JSON 字符串。**schema 是 strict（`additionalProperties: false`）**。

| tool | 参数 | 所需权限 | 说明 |
|------|------|----------|------|
| `vm_list` | — | read | 列出**本会话可见**的 VM（含状态） |
| `vm_status` | `vm_id` | read | 单 VM 状态（不泄露 QMP 地址/宿主路径） |
| `vm_start` | `vm_id` | power | 启动（幂等；受配额约束） |
| `vm_shutdown` | `vm_id` | power | ACPI 优雅关机（QMP `system_powerdown`） |
| `vm_stop` | `vm_id` | power | 暂停（QMP `stop`） |
| `vm_resume` | `vm_id` | power | 继续（QMP `cont`） |
| `vm_force_off` | `vm_id` | power + **审批** | 强制断电（QMP `quit`），默认需审批 |

错误（模型可见、脱敏）：

- `VM 不存在或无权限` —— 不可见 / 不存在 / 无对应权限（三者同报文，不变量 2）
- `超出会话资源配额`
- `参数不被允许`
- `操作未获批准` / `审批超时`
- `请求过于频繁`

## 管理 REST API

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/qemu/discover` | 发现可用 QEMU 二进制 |
| GET/POST/DELETE | `/api/volumes[/{id}]` | 预注册卷 |
| GET/POST/DELETE | `/api/vms[/{id}]` | 注册/删除 VM（运行中删除返回 409） |
| POST | `/api/vms/{id}/power/{start\|shutdown\|force_off\|stop\|resume}` | 管理员直接操作 |
| GET/POST | `/api/sessions` | 列出 / 创建会话 |
| GET | `/api/sessions/{id}` | 会话详情（含 `perms_generation`） |
| PUT | `/api/sessions/{id}/perms` | 改权限（返回"仅对后续调用生效"提示） |
| POST | `/api/sessions/{id}/deactivate` | 停用会话 |
| POST | `/api/sessions/{id}/tool` | **模拟模型调用**（调试） |
| GET | `/api/approvals?status=` | 审批列表 |
| POST | `/api/approvals/{id}/decide` | 批准 / 拒绝 |
| GET | `/api/audits?session_id&vm_id&result&since&until&limit&offset&format=csv` | 审计查询 / 导出 |
| GET | `/api/status` | 全部 VM 实时状态 |

错误统一 `{ "detail": "<脱敏消息>" }`，拒绝返回 403。

## WebSocket 实时事件

`GET /ws`（WebSocket）。连接后**首帧**为全量快照，随后推送增量事件：

```json
{"type": "snapshot", "statuses": {"alpine": "running"}}
{"type": "vm.status", "vm_id": "alpine", "status": "paused"}
{"type": "vm.exited", "vm_id": "alpine", "returncode": 0}
{"type": "approval.requested", "approval": {"id": "...", "action": "vm_force_off"}}
{"type": "security.probe_alert", "session_id": "...", "count": 5}
{"type": "vm.qmp_lost", "vm_id": "alpine"}
```

前端据此做实时状态刷新、审批提醒与探测告警 toast。

## 审计

每次 tool 调用写一条 `AuditEntry`（含**拒绝**），双层记录：

- `model_params`：模型意图（原始参数）；
- `executed`：实际执行（`vm_start.exec` 记完整 QEMU 命令行；`qmp` 记实际
  QMP 命令）。

示例（`vm_start` 后）：

```
vm_start        allowed   model_params={"vm_id":"alpine"}
vm_start.exec   allowed   executed=["C:\msys64\ucrt64\bin\qemu-system-x86_64.exe -nodefaults
                          -no-user-config -nodefconfig -qmp tcp:127.0.0.1:PORT,server=on,wait=off
                          -sandbox on -name qsg-alpine -machine q35 -smp 2 -m 1024
                          -display none -vga none -drive file=D:\img\alpine.qcow2,if=virtio,..."]
```

支持 CSV 导出：`GET /api/audits?format=csv`。

## MSYS2 / QEMU 发现

`qemu_discovery.discover` 按优先级查找（不变量 8）：

1. `QEMU_BINARY_DIR`
2. `%MSYS2_ROOT%\ucrt64\bin`（UCRT64，推荐）
3. `%MSYS2_ROOT%\mingw64\bin`（MINGW64）
4. `PATH` 中的 `qemu-system-*`

每个候选执行 `--version` 校验并解析版本，记录 `QemuVariant`（UCRT64 /
MINGW64 / OTHER）。

## 安全基线与禁止参数

**强制基线**（`baseline_args`，模型不可移除/覆盖）：

```
-nodefaults -no-user-config -nodefconfig -qmp <插件分配> -sandbox on
```

**注册时一律拒绝**的参数前缀（`FORBIDDEN_ARG_PREFIXES`）：

```
-kernel -initrd -append -pidfile -fsdev -virtfs -chardev
-qmp -monitor -serial -sandbox -nodefaults -no-user-config -nodefconfig
-S -daemonize -incoming
```

`-drive` 与 `-netdev` 不整体禁止（管理员可能需要 CD-ROM 等），但其值
**不得包含** `file=` / `hostfwd=` / `guestfwd=` 子项（`FORBIDDEN_SUBARG_RE`）——
磁盘必须走预注册 Volume，端口转发按会话预授权（本版未开放，见路线图）。

## 测试

```bash
cd backend
python -m pytest tests -q
```

52 个测试覆盖六大安全场景 + 协议级用例（`tests/`）：

1. **可见性混淆**：不可见 vs 不存在同报文；探测限流告警（`test_permission.py`）
2. **快照隔离**：进行中操作持旧快照；权限变更只影响后续；代次 +1（`test_permission.py`）
3. **配额**：`max_running_vms` / vCPU / 内存（`test_permission.py`）
4. **注入**：`extra_args` / 禁用参数名 / strict schema / `session_id` 覆盖 /
   `vm_id` 路径字符（`test_tools.py`）
5. **基线参数**：强制注入、卷 readonly、QMP 地址 loopback（`test_qmp_broker.py`）
6. **审批 + 审计双层**：`vm_force_off` 审批流；意图 + 执行双层（`test_tools.py` /
   `test_qmp_broker.py`）

测试用 `conftest.FakeQMPProcess`（asyncio TCP 服务端）模拟 QMP 端，配合
`python` 替身子进程完整走 `QmpBroker.start → _connect_qmp → query-status`
路径，无需真实 QEMU。

## 架构决策记录（ADR）

见 [`docs/`](docs)：

- [ADR-0001 QMP socket 插件独占](docs/ADR-0001-qmp-socket-exclusive.md)
- [ADR-0002 会话权限快照不可变](docs/ADR-0002-session-permission-snapshot.md)
- [ADR-0003 可见性不可区分](docs/ADR-0003-visibility-indistinguishable.md)
- [ADR-0004 vm_force_off 一次性审批](docs/ADR-0004-force-off-approval.md)
- [ADR-0005 MSYS2/QEMU 发现策略](docs/ADR-0005-msys2-discovery.md)
- [ADR-0006 QMP 客户端默认内置实现](docs/ADR-0006-qmp-client-backend.md)
- [ADR-0007 审计双层记录](docs/ADR-0007-dual-layer-audit.md)

## 项目结构

```
qemu-session-guard/
├── README.md
├── .gitignore
├── examples/
│   └── model_tools_integration.py  # 宿主框架接入示例
├── docs/                          # ADR
│   ├── ADR-0001-qmp-socket-exclusive.md
│   ├── ADR-0002-session-permission-snapshot.md
│   ├── ADR-0003-visibility-indistinguishable.md
│   ├── ADR-0004-force-off-approval.md
│   ├── ADR-0005-msys2-discovery.md
│   ├── ADR-0006-qmp-client-backend.md
│   └── ADR-0007-dual-layer-audit.md
└── backend/
    ├── requirements.txt
    ├── pytest.ini
    ├── qemu_session_guard/
    │   ├── __init__.py            # APP_ID / __version__
    │   ├── __main__.py            # python -m qemu_session_guard
    │   ├── server.py              # uvicorn 入口
    │   ├── app.py                 # FastAPI 装配 + REST/WS
    │   ├── config.py              # 配置（env > YAML > 默认）
    │   ├── models.py              # 数据模型（SessionPerms 等）
    │   ├── errors.py              # GuardError 体系（public 脱敏）
    │   ├── store.py               # SQLite 持久化
    │   ├── audit.py               # 审计
    │   ├── session_guard.py       # 会话生命周期（不变量 2、3）
    │   ├── permission.py          # 权限引擎 + 审批
    │   ├── qmp_client.py          # QMP 客户端（_MiniQMP / 官方库）
    │   ├── qmp_broker.py          # spawn + QMP 独占（不变量 1、4、5）
    │   ├── qemu_discovery.py      # MSYS2 发现 + 基线/禁用参数
    │   └── tools.py               # 模型 tools（strict schema）
    ├── frontend/
    │   ├── index.html             # 无构建 SPA 外壳
    │   └── app.js                 # 五视图 + WS 实时
    └── tests/
        ├── conftest.py            # FakeQMPProcess + fixtures
        ├── test_permission.py     # 场景 1/2/3
        ├── test_tools.py          # 场景 4/6
        ├── test_qmp_broker.py     # 场景 5/6 + 协议级
        └── test_discovery.py      # 发现层
```

## 路线图

- [ ] 控制台（`-serial` over unix socket + console 服务，`vm_console_read/write` 已在权限模型预留）
- [ ] 按会话预授权的网络转发（受控 `hostfwd`）
- [ ] 审计表归档 / 轮转
- [ ] WebUI 认证（当前仅 loopback，面向受信管理员）
- [ ] 快照（snapshot）与镜像模板
- [ ] 多宿主 / 远程 QmpBroker

---

> 本系统默认监听 `127.0.0.1`，不应对外暴露；WebUI 暂无认证，请仅在受信
> 环境使用，或置于反向代理 + 认证之后。
