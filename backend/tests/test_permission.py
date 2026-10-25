"""安全场景测试 1–3：可见性混淆、权限快照隔离、配额边界。

对照 README §安全不变量 2 / 3 / 配额，以及用户指定的六条必测场景。
"""
from __future__ import annotations

import json

import pytest

from qemu_session_guard.errors import (
    GuardError,
    PermissionDeniedError,
    QuotaExceededError,
    RateLimitedError,
)
from qemu_session_guard.models import (
    AuditResult,
    Quota,
    ToolAction,
    VMRegistration,
    VMResources,
)


def _reg(store, vm_id: str) -> VMRegistration:
    vm = VMRegistration(
        id=vm_id,
        qemu_binary=r"C:\fake\qemu-system-x86_64.exe",
        qemu_version="9.0.0",
        resources=VMResources(vcpus=2, mem_mb=1024),
    )
    store.save_vm(vm)
    return vm


async def _denied_message(tools, session_id: str, tool: str, params: dict) -> str:
    with pytest.raises(GuardError) as exc_info:
        await tools.call(session_id, tool, params)
    return exc_info.value.public


class TestVisibilityConfusion:
    """场景 1：模型探测不可见 VM —— 报文与「不存在」完全一致（不变量 2）。"""

    @pytest.mark.asyncio
    async def test_invisible_vm_same_message_as_nonexistent(
        self, tools, sessions, store, perms
    ):
        _reg(store, "vm-secret")
        _reg(store, "vm-public")
        sess = sessions.create_session(
            label="agent-a",
            granted_vm_ids=["vm-public"],
            permission_map={"vm-public": ["read", "power"]},
        )
        msg_secret = await _denied_message(tools, sess.id, "vm_status", {"vm_id": "vm-secret"})
        msg_ghost = await _denied_message(tools, sess.id, "vm_status", {"vm_id": "vm-ghost"})
        assert msg_secret == msg_ghost == "VM 不存在或无权限"

    @pytest.mark.asyncio
    async def test_vm_list_hides_invisible(self, tools, sessions, store):
        _reg(store, "vm-a")
        _reg(store, "vm-b")
        sess = sessions.create_session(
            label="agent-a",
            granted_vm_ids=["vm-a"],
            permission_map={"vm-a": ["read"]},
        )
        out = json.loads(await tools.call(sess.id, "vm_list", {}))
        ids = [v["vm_id"] for v in out["vms"]]
        assert ids == ["vm-a"]

    @pytest.mark.asyncio
    async def test_denials_audited_and_probe_alert(
        self, tools, sessions, store, audit
    ):
        _reg(store, "vm-secret")
        sess = sessions.create_session(
            label="agent-a",
            granted_vm_ids=["vm-a"],
            permission_map={"vm-a": ["read"]},
        )
        for _ in range(5):
            with pytest.raises(GuardError):
                await tools.call(sess.id, "vm_status", {"vm_id": "vm-secret"})
        entries = store.query_audits(session_id=sess.id, result="denied")
        assert len(entries) == 5
        assert all(e.deny_reason for e in entries)
        # 继续大量试探触发限流
        for _ in range(10):
            with pytest.raises(GuardError):
                await tools.call(sess.id, "vm_status", {"vm_id": "vm-secret"})
        with pytest.raises(RateLimitedError):
            await tools.call(sess.id, "vm_status", {"vm_id": "vm-secret"})

    @pytest.mark.asyncio
    async def test_permission_level_enforced(self, tools, sessions, store):
        """read-only 会话执行 power 操作 → 与「不存在」同一报文（不变量 2）。"""
        _reg(store, "vm-a")
        sess = sessions.create_session(
            label="agent-ro",
            granted_vm_ids=["vm-a"],
            permission_map={"vm-a": ["read"]},
        )
        msg = await _denied_message(tools, sess.id, "vm_stop", {"vm_id": "vm-a"})
        assert msg == "VM 不存在或无权限"


class TestSnapshotIsolation:
    """场景 2：会话 A 运行期间被撤销权限，进行中的操作继续，新调用被拒（不变量 3）。"""

    @pytest.mark.asyncio
    async def test_mid_operation_snapshot_isolated(self, tools, sessions, store, perms):
        _reg(store, "vm-a")
        sess = sessions.create_session(
            label="agent-b",
            granted_vm_ids=["vm-a"],
            permission_map={"vm-a": ["read", "power"]},
        )
        # 快照在操作开始时取得（模拟进行中的操作）
        snap_before = sessions.snapshot(sess.id)
        assert snap_before.perms.allows("vm-a", ToolAction.VM_STOP)

        # 管理员撤销 power 权限
        sessions.update_perms(
            sess.id,
            permission_map={"vm-a": ["read"]},
        )

        # 进行中的操作（持有旧快照）仍然被允许
        decision = await perms.check(snap_before, ToolAction.VM_STOP, "vm-a", {})
        assert decision.allowed is True

        # 新调用使用新快照 → 拒绝
        with pytest.raises(GuardError):
            await tools.call(sess.id, "vm_stop", {"vm_id": "vm-a"})

        # 代次已递增
        updated = sessions.get(sess.id)
        assert updated.perms_generation == 2

    @pytest.mark.asyncio
    async def test_revoke_visibility_mid_operation(self, tools, sessions, store, perms):
        _reg(store, "vm-a")
        sess = sessions.create_session(
            label="agent-c",
            granted_vm_ids=["vm-a"],
            permission_map={"vm-a": ["read", "power"]},
        )
        snap_before = sessions.snapshot(sess.id)
        sessions.update_perms(sess.id, granted_vm_ids=[])
        # 旧快照仍可见
        assert snap_before.perms.is_visible("vm-a")
        decision = await perms.check(snap_before, ToolAction.VM_STATUS, "vm-a", {})
        assert decision.allowed is True
        # 新调用连 read 都被拒
        with pytest.raises(GuardError):
            await tools.call(sess.id, "vm_status", {"vm_id": "vm-a"})
        # 权限矩阵中的孤儿授权被裁剪
        assert sessions.get(sess.id).perms.permission_map == {}

    @pytest.mark.asyncio
    async def test_deactivated_session_rejected(self, tools, sessions, store):
        _reg(store, "vm-a")
        sess = sessions.create_session(
            label="agent-d",
            granted_vm_ids=["vm-a"],
            permission_map={"vm-a": ["read"]},
        )
        sessions.deactivate(sess.id)
        with pytest.raises(GuardError):
            await tools.call(sess.id, "vm_list", {})


class TestQuotaBoundary:
    """场景 3：配额为 0 时 vm_start 被拒；配额计数按运行中 VM 数。"""

    @pytest.mark.asyncio
    async def test_zero_running_quota_denies_start(self, tools, sessions, store, broker):
        _reg(store, "vm-a")
        sess = sessions.create_session(
            label="agent-q",
            granted_vm_ids=["vm-a"],
            permission_map={"vm-a": ["read", "power"]},
            quota=Quota(max_running_vms=0, max_vcpus_per_vm=4, max_mem_mb_per_vm=4096),
        )
        with pytest.raises(QuotaExceededError) as exc_info:
            await tools.call(sess.id, "vm_start", {"vm_id": "vm-a"})
        assert exc_info.value.public == "超出会话资源配额"

    @pytest.mark.asyncio
    async def test_quota_counts_running_vms(self, sessions, store, broker, perms):
        _reg(store, "vm-a")
        _reg(store, "vm-b")
        sess = sessions.create_session(
            label="agent-q2",
            granted_vm_ids=["vm-a", "vm-b"],
            permission_map={"vm-a": ["read", "power"], "vm-b": ["read", "power"]},
            quota=Quota(max_running_vms=1, max_vcpus_per_vm=4, max_mem_mb_per_vm=4096),
        )
        # 模拟 vm-a 已在运行
        rt = broker.runtime("vm-a")
        from qemu_session_guard.models import VMStatus

        rt.status = VMStatus.RUNNING
        snap = sessions.snapshot(sess.id)
        with pytest.raises(QuotaExceededError):
            await perms.check(snap, ToolAction.VM_START, "vm-b", {})
        # 幂等 start（对已在运行的同一台）不占新配额
        decision = await perms.check(snap, ToolAction.VM_START, "vm-a", {})
        assert decision.allowed is True
        # 审计：一次 denied（配额）一次 allowed
        denied = store.query_audits(session_id=sess.id, result=AuditResult.DENIED.value)
        assert any("quota" in e.deny_reason for e in denied)
