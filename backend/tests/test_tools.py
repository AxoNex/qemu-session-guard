"""安全场景测试 4–5：QEMU 参数注入、QMP 命令注入 / 审批流。

覆盖：不变量 1（模型不可触 QEMU CLI）、5（禁止参数）、6（审批一次性、
可过期、绑定具体调用）、7（审计双层记录）。
"""
from __future__ import annotations

import asyncio
import json

import pytest
from pydantic import ValidationError

from qemu_session_guard.errors import ArgumentViolationError, GuardError
from qemu_session_guard.models import (
    ApprovalStatus,
    ToolAction,
    VMRegistration,
    VMResources,
)
from qemu_session_guard.qemu_discovery import validate_extra_args


def _reg(store, vm_id: str) -> VMRegistration:
    vm = VMRegistration(
        id=vm_id,
        qemu_binary=r"C:\fake\qemu-system-x86_64.exe",
        qemu_version="9.0.0",
        resources=VMResources(vcpus=2, mem_mb=1024),
    )
    store.save_vm(vm)
    return vm


def _sess(sessions, label="agent-x", approval_actions=None):
    return sessions.create_session(
        label=label,
        granted_vm_ids=["vm-a"],
        permission_map={"vm-a": ["read", "power"]},
        approval_actions=approval_actions if approval_actions is not None else ["vm_force_off"],
    )


class TestQemuArgInjection:
    """场景 4：模型试图通过 tool 参数注入任意 QEMU CLI 参数 → 拒绝 + 审计。"""

    @pytest.mark.asyncio
    async def test_extra_args_param_rejected(self, tools, sessions, store):
        _reg(store, "vm-a")
        sess = _sess(sessions)
        with pytest.raises(ArgumentViolationError):
            await tools.call(
                sess.id, "vm_start",
                {"vm_id": "vm-a", "extra_args": ["-kernel", "/evil"]},
            )
        entries = store.query_audits(session_id=sess.id, result="denied")
        assert any("forbidden param" in e.deny_reason for e in entries)

    @pytest.mark.asyncio
    async def test_unknown_fields_rejected_by_strict_schema(self, tools, sessions, store):
        _reg(store, "vm-a")
        sess = _sess(sessions)
        # strict schema：未知字段直接 ValidationError
        with pytest.raises(ValidationError):
            await tools.call(sess.id, "vm_start", {"vm_id": "vm-a", "evil": 1})

    @pytest.mark.asyncio
    async def test_session_override_impossible(self, tools, sessions, store):
        _reg(store, "vm-a")
        sess_a = _sess(sessions, "agent-x1")
        sess_b = _sess(sessions, "agent-x2")
        # 模型在参数里塞 session_id 也不会改变作用域（被 pop 掉）
        with pytest.raises(GuardError):  # vm-b 不存在 → 通用错误
            await tools.call(
                sess_a.id, "vm_status",
                {"vm_id": "vm-b", "session_id": sess_b.id},
            )

    @pytest.mark.asyncio
    async def test_vm_id_path_chars_rejected(self, tools, sessions, store):
        _reg(store, "vm-a")
        sess = _sess(sessions)
        with pytest.raises(ValidationError):
            await tools.call(sess.id, "vm_status", {"vm_id": "../../etc/passwd"})
        with pytest.raises(ValidationError):
            await tools.call(sess.id, "vm_status", {"vm_id": "vm-a; rm -rf /"})


class TestForbiddenArgList:
    """forbidden-list 单元测试（注册层，管理员 extra_args）。"""

    @pytest.mark.parametrize(
        "bad",
        [
            "-kernel", "-initrd", "-append", "-pidfile", "-fsdev", "-virtfs",
            "-chardev", "-qmp", "-monitor", "-serial", "-sandbox", "-nodefaults",
            "-S", "-daemonize", "-incoming",
            "-drive file=/etc/passwd,if=virtio",
            "-netdev user,id=n0,hostfwd=tcp::2222-:22",
        ],
    )
    def test_forbidden_args_detected(self, bad):
        assert validate_extra_args([bad]) == [bad]

    @pytest.mark.parametrize(
        "good",
        [
            "-cpu", "-device", "-rtc", "-boot", "-nic",
            "-drive media=cdrom,if=ide",
        ],
    )
    def test_allowed_args_pass(self, good):
        assert validate_extra_args([good]) == []


class TestApprovalFlow:
    """场景 6（补充不变量 6）：vm_force_off 默认需要审批；审批一次性、可过期。"""

    @pytest.mark.asyncio
    async def test_force_off_pending_then_rejected(self, tools, sessions, store, perms):
        _reg(store, "vm-a")
        sess = _sess(sessions)
        # vm-a 未运行，broker 会报「VM 未在运行」——但应先走到审批，被拒绝后
        # 根本不会触达 broker。超时=1s（fixture）。
        task = asyncio.create_task(
            tools.call(sess.id, "vm_force_off", {"vm_id": "vm-a"})
        )
        await asyncio.sleep(0.1)
        pendings = store.list_approvals(ApprovalStatus.PENDING)
        assert len(pendings) == 1
        appr = pendings[0]
        assert appr.action is ToolAction.VM_FORCE_OFF
        assert appr.session_id == sess.id
        # 审计已有 pending_approval 记录（不变量 7）
        pending_entries = store.query_audits(session_id=sess.id, result="pending_approval")
        assert len(pending_entries) == 1
        # 拒绝 → tool 调用失败
        await perms.decide_approval(appr.id, approve=False, decided_by="admin")
        with pytest.raises(GuardError) as exc_info:
            await task
        assert exc_info.value.public == "操作未获批准"
        # 审批一次性：不能再次决定
        again = await perms.decide_approval(appr.id, approve=True, decided_by="admin")
        assert again.status is ApprovalStatus.REJECTED

    @pytest.mark.asyncio
    async def test_approval_expires(self, tools, sessions, store, perms):
        _reg(store, "vm-a")
        sess = _sess(sessions)
        task = asyncio.create_task(
            tools.call(sess.id, "vm_force_off", {"vm_id": "vm-a"})
        )
        await asyncio.sleep(0.1)
        # 不做决定，等待 approval_timeout（fixture=1s）后超时
        with pytest.raises(GuardError) as exc_info:
            await task
        assert exc_info.value.public == "审批超时"
        appr = store.list_approvals()[0]
        assert appr.status is ApprovalStatus.EXPIRED
        # 过期后决定无效
        decided = await perms.decide_approval(appr.id, approve=True, decided_by="admin")
        assert decided.status is ApprovalStatus.EXPIRED

    @pytest.mark.asyncio
    async def test_non_approval_action_no_approval(self, tools, sessions, store):
        _reg(store, "vm-a")
        sess = _sess(sessions)
        out = json.loads(await tools.call(sess.id, "vm_list", {}))
        assert out["vms"][0]["vm_id"] == "vm-a"
        assert store.list_approvals(ApprovalStatus.PENDING) == []

    @pytest.mark.asyncio
    async def test_approval_bound_to_call_params(self, tools, sessions, store, perms):
        """审批绑定具体调用：params 原样入库（脱敏后），不可被模型事后替换。"""
        _reg(store, "vm-a")
        sess = _sess(sessions)
        task = asyncio.create_task(
            tools.call(sess.id, "vm_force_off", {"vm_id": "vm-a"})
        )
        await asyncio.sleep(0.1)
        appr = store.list_approvals(ApprovalStatus.PENDING)[0]
        assert appr.params == {"vm_id": "vm-a"}
        assert appr.session_generation == 1
        await perms.decide_approval(appr.id, approve=False, decided_by="admin")
        with pytest.raises(GuardError):
            await task


class TestToolSchemas:
    """tool 描述完整性：宿主注册用 schema 必须 strict。"""

    def test_schemas_are_strict(self, tools):
        from qemu_session_guard.tools import ModelTools

        for schema in ModelTools.tool_schemas():
            params = schema["parameters"]
            assert params.get("additionalProperties") is False, schema["name"]
