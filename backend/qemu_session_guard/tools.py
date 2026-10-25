"""模型侧 tool 接口（不变量 1、2、5）。

设计要点：
- 语义化、strict schema（extra="forbid"），拒绝未知参数字段与任何字符串形式的
  「额外 QEMU 参数」（不变量 5）；
- `vm_id` 必须是会话可见列表中的字符串标识，不做模糊匹配；
- 所有错误对模型统一脱敏：不可见 / 不存在 / 无权限 → 同一句
  「VM 不存在或无权限」（不变量 2）；
- 每次调用先取会话权限快照（SessionGuard.snapshot），整个调用期间持有——
  进行中的操作不受中途权限变更影响（不变量 3）；
- 需要审批的操作挂起等待 WebUI 人工决定，超时或被拒即失败（不变量 6）；
- 执行结果与 QMP 命令全部进审计日志（不变量 7）。
"""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .errors import ArgumentViolationError, GuardError
from .models import ApprovalStatus, AuditResult, ToolAction, VMStatus
from .permission import PermissionEngine
from .qmp_broker import QmpBroker
from .session_guard import SessionGuard

log = logging.getLogger(__name__)

# 对模型的通用错误文案（存在性不泄露，不变量 2）
GENERIC_VM_ERROR = "VM 不存在或无权限"


# ---------------------------------------------------------------------------
# 参数 schema（strict：拒绝未知字段）
# ---------------------------------------------------------------------------


class VmIdParams(BaseModel):
    model_config = ConfigDict(extra="forbid")

    vm_id: str = Field(min_length=1, max_length=128)

    @field_validator("vm_id")
    @classmethod
    def _no_path_chars(cls, v: str) -> str:
        # vm_id 是纯标识符，不得含路径/命令分隔符（防止任何形式的注入式混淆）
        if any(c in v for c in ("/", "\\", "\x00", " ", "\t", "\n")):
            raise ValueError("vm_id 含有非法字符")
        return v


class EmptyParams(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ConsoleWriteParams(VmIdParams):
    data: str = Field(max_length=4096)


class ConsoleReadParams(VmIdParams):
    max_bytes: int = Field(default=4096, ge=1, le=65536)


#: 模型永远看不到的参数名——出现即拒绝并审计（不变量 5）
_FORBIDDEN_PARAM_NAMES = {
    "qemu_args",
    "extra_args",
    "args",
    "argv",
    "command",
    "cmdline",
    "session_id_override",
}


# ---------------------------------------------------------------------------
# Tool 接口
# ---------------------------------------------------------------------------


class ModelTools:
    """暴露给模型会话的 tool 集合。每个方法对应一个 tool。"""

    def __init__(
        self,
        sessions: SessionGuard,
        perms: PermissionEngine,
        broker: QmpBroker,
        approval_timeout: float = 300,
    ):
        self._sessions = sessions
        self._perms = perms
        self._broker = broker
        self._approval_timeout = approval_timeout

    # ------------------------------------------------------------ tool 描述

    @staticmethod
    def tool_schemas() -> list[dict[str, Any]]:
        """供宿主 Agent 框架注册的 tool 描述（名称、说明、JSON Schema）。"""
        vm_id_schema = VmIdParams.model_json_schema()
        return [
            {
                "name": "vm_list",
                "description": "列出当前会话可见的虚拟机（id、架构、状态）。不可见的 VM 不会出现在结果中。",
                "parameters": EmptyParams.model_json_schema(),
            },
            {
                "name": "vm_status",
                "description": "查询一台可见虚拟机的状态与资源摘要。",
                "parameters": vm_id_schema,
            },
            {
                "name": "vm_start",
                "description": "启动一台已停止的虚拟机（幂等：已运行则返回当前状态）。受会话配额限制。",
                "parameters": vm_id_schema,
            },
            {
                "name": "vm_shutdown",
                "description": "优雅关机（向 guest 发送 ACPI 关机信号）。",
                "parameters": vm_id_schema,
            },
            {
                "name": "vm_stop",
                "description": "暂停虚拟机（vCPU 停止调度，可随时恢复）。",
                "parameters": vm_id_schema,
            },
            {
                "name": "vm_resume",
                "description": "恢复一台已暂停的虚拟机。",
                "parameters": vm_id_schema,
            },
            {
                "name": "vm_force_off",
                "description": "强制断电（立即终止 QEMU 进程）。高危操作，可能需要管理员批准后才会执行。",
                "parameters": vm_id_schema,
            },
        ]

    # -------------------------------------------------------------- 公共入口

    async def call(self, session_id: str, tool: str, raw_params: dict | None) -> str:
        """宿主框架的统一入口：按 tool 名分发，返回 JSON 字符串。

        任何 GuardError 都以脱敏消息返回；未知参数 / 注入尝试被拒绝并审计。
        """
        raw_params = dict(raw_params or {})
        # 模型不可覆盖会话作用域（不变量 3）
        raw_params.pop("session_id", None)
        injected = _FORBIDDEN_PARAM_NAMES & set(raw_params)
        if injected:
            # 记录意图但不执行；对模型只说「参数不被允许」（不变量 5、7）
            try:
                sess = self._sessions.snapshot(session_id)
                self._perms._audit.record(  # noqa: SLF001 - 同包内部复用审计通道
                    session_id=sess.id,
                    session_label=sess.label,
                    action=tool,
                    model_params={"rejected_fields": sorted(injected)},
                    result=AuditResult.DENIED,
                    deny_reason=f"forbidden param names: {sorted(injected)}",
                    actor="model",
                )
            except GuardError:
                pass
            raise ArgumentViolationError(f"forbidden params: {sorted(injected)}")

        handlers = {
            "vm_list": self.vm_list,
            "vm_status": self.vm_status,
            "vm_start": self.vm_start,
            "vm_shutdown": self.vm_shutdown,
            "vm_stop": self.vm_stop,
            "vm_resume": self.vm_resume,
            "vm_force_off": self.vm_force_off,
        }
        handler = handlers.get(tool)
        if handler is None:
            raise ArgumentViolationError(f"unknown tool {tool!r}")
        result = await handler(session_id, raw_params)
        return json.dumps(result, ensure_ascii=False)

    # --------------------------------------------------------------- helpers

    def _snapshot(self, session_id: str):
        return self._sessions.snapshot(session_id)

    async def _authorize(self, sess, action: ToolAction, vm_id: str, params: dict):
        """权限校验 + 审批挂起。返回 True 表示可执行。"""
        decision = await self._perms.check(sess, action, vm_id, params)
        if decision.allowed:
            return True
        appr = decision.approval
        assert appr is not None
        final = await self._perms.wait_for_approval(appr.id, self._approval_timeout)
        if final.status is not ApprovalStatus.APPROVED:
            raise GuardError(
                "操作未获批准" if final.status is ApprovalStatus.REJECTED else "审批超时",
                f"approval {appr.id} -> {final.status.value}",
            )
        return True

    def _visible_or_raise(self, sess, vm_id: str) -> None:
        if not sess.perms.is_visible(vm_id):
            from .errors import VMNotVisibleError

            raise VMNotVisibleError()

    # ----------------------------------------------------------------- tools

    async def vm_list(self, session_id: str, params: dict) -> dict:
        EmptyParams.model_validate(params)
        sess = self._snapshot(session_id)
        await self._perms.check(sess, ToolAction.VM_LIST, None, params)
        statuses = self._broker.statuses()
        vms = []
        for vm_id in sess.perms.granted_vm_ids:
            reg = self._broker_reg(vm_id)
            if reg is None:
                continue  # 已注销的 VM 对模型同样不可见
            vms.append(
                {
                    "vm_id": vm_id,
                    "arch": reg.arch,
                    "status": statuses.get(vm_id, VMStatus.STOPPED).value,
                }
            )
        return {"vms": vms}

    async def vm_status(self, session_id: str, params: dict) -> dict:
        p = VmIdParams.model_validate(params)
        sess = self._snapshot(session_id)
        await self._perms.check(sess, ToolAction.VM_STATUS, p.vm_id, params)
        info = await self._broker.query_status(p.vm_id)
        # 不泄露 QMP 地址、宿主机路径等元数据（不变量 4）
        info.pop("qmp_address", None)
        return info

    async def vm_start(self, session_id: str, params: dict) -> dict:
        p = VmIdParams.model_validate(params)
        sess = self._snapshot(session_id)
        await self._authorize(sess, ToolAction.VM_START, p.vm_id, params)
        return await self._broker.start(p.vm_id, actor="model", session_id=sess.id)

    async def vm_shutdown(self, session_id: str, params: dict) -> dict:
        p = VmIdParams.model_validate(params)
        sess = self._snapshot(session_id)
        await self._authorize(sess, ToolAction.VM_SHUTDOWN, p.vm_id, params)
        return await self._broker.shutdown(p.vm_id, actor="model", session_id=sess.id)

    async def vm_stop(self, session_id: str, params: dict) -> dict:
        p = VmIdParams.model_validate(params)
        sess = self._snapshot(session_id)
        await self._authorize(sess, ToolAction.VM_STOP, p.vm_id, params)
        return await self._broker.stop(p.vm_id, actor="model", session_id=sess.id)

    async def vm_resume(self, session_id: str, params: dict) -> dict:
        p = VmIdParams.model_validate(params)
        sess = self._snapshot(session_id)
        await self._authorize(sess, ToolAction.VM_RESUME, p.vm_id, params)
        return await self._broker.resume(p.vm_id, actor="model", session_id=sess.id)

    async def vm_force_off(self, session_id: str, params: dict) -> dict:
        p = VmIdParams.model_validate(params)
        sess = self._snapshot(session_id)
        await self._authorize(sess, ToolAction.VM_FORCE_OFF, p.vm_id, params)
        return await self._broker.force_off(p.vm_id, actor="model", session_id=sess.id)

    # --------------------------------------------------------------- 内部

    def _broker_reg(self, vm_id: str):
        return self._broker._store.get_vm(vm_id)  # noqa: SLF001 - 同包内部共享 store
