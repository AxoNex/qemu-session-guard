"""PermissionEngine：每次 tool 调用的运行时中介与校验（不变量 2、6）。

对每次调用依次检查：
1. 限流（同一 session 对同一 VM 的相同试探性拒绝在窗口内只放大告警一次）；
2. 可见性 —— 不可见 VM 统一报「VM 不存在或无权限」（不变量 2）；
3. 权限级别（read / power / console / config）；
4. 配额（仅 vm_start 消耗 running 配额）；
5. 审批策略（needs_approval 时挂起，等待 WebUI 人工批准，不变量 6）。

每一步失败都会写审计日志并触发实时事件。
"""
from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable, Coroutine
from typing import Any, NamedTuple

from .audit import AuditLog
from .errors import (
    PermissionDeniedError,
    QuotaExceededError,
    RateLimitedError,
    VMNotVisibleError,
)
from .models import (
    ACTION_PERM,
    Approval,
    ApprovalStatus,
    AuditResult,
    Session,
    ToolAction,
    VMStatus,
)
from .store import Store

log = logging.getLogger(__name__)

EventCb = Callable[[dict], Coroutine[Any, Any, None]]


class Decision(NamedTuple):
    """一次校验的结果。allowed=True 时可直接执行；否则 approval 非空表示挂起。"""

    allowed: bool
    approval: Approval | None = None


class PermissionEngine:
    # 同一 (session, vm, action) 的拒绝在多少秒内视为「试探风暴」
    PROBE_WINDOW_SEC = 60
    PROBE_THRESHOLD = 5

    def __init__(
        self,
        store: Store,
        audit: AuditLog,
        running_count: Callable[[], dict[str, VMStatus]],
    ):
        self._store = store
        self._audit = audit
        self._running_count = running_count  # 返回 vm_id -> status
        self._events: list[EventCb] = []
        self._deny_log: dict[tuple[str, str, str], list[float]] = {}
        self._approval_waiters: dict[str, asyncio.Event] = {}
        self._lock = asyncio.Lock()

    # ---------------------------------------------------------------- events

    def subscribe(self, cb: EventCb) -> Callable[[], None]:
        self._events.append(cb)

        def _unsub() -> None:
            try:
                self._events.remove(cb)
            except ValueError:
                pass

        return _unsub

    async def _emit(self, kind: str, payload: dict) -> None:
        msg = {"type": kind, **payload}
        for cb in list(self._events):
            try:
                await cb(msg)
            except Exception:  # noqa: BLE001
                log.exception("event subscriber failed")

    # ---------------------------------------------------------------- checks

    async def check(
        self,
        sess: Session,
        action: ToolAction,
        vm_id: str | None,
        params: dict | None = None,
    ) -> Decision:
        """对一次 tool 调用做完整权限校验。

        - 通过 → Decision(allowed=True)，审计 result=allowed；
        - 需要审批 → Decision(allowed=False, approval=...)，审计 pending_approval；
        - 拒绝 → 抛 GuardError 子类，审计 denied（调用方负责把脱敏消息返回模型）。
        """
        params = params or {}
        vm_arg = vm_id if vm_id is not None else (params.get("vm_id") or "")

        try:
            self._check_rate_limit(sess, action, vm_arg)
            if action is ToolAction.VM_LIST:
                # vm_list 不需要具体 vm 的权限；会话有效即可（snapshot() 已校验）
                self._record(sess, action, None, params, AuditResult.ALLOWED)
                return Decision(True)

            assert vm_arg, "vm action requires vm_id"
            perms = sess.perms
            if not perms.is_visible(vm_arg):
                # 不变量 2：存在性不泄露。无论 VM 是否存在，报文一致。
                raise VMNotVisibleError(f"vm {vm_arg!r} not in session grants")
            if not perms.allows(vm_arg, action):
                need = ACTION_PERM[action].value
                raise PermissionDeniedError(
                    f"session lacks {need} on {vm_arg!r}"
                )
            if action is ToolAction.VM_START:
                self._check_quota(sess, vm_arg)

            if perms.needs_approval(action):
                approval = await self._create_approval(sess, action, vm_arg, params)
                self._record(
                    sess,
                    action,
                    vm_arg,
                    params,
                    AuditResult.PENDING_APPROVAL,
                    approval_id=approval.id,
                )
                await self._emit(
                    "approval.requested",
                    {"approval": approval.model_dump(mode="json")},
                )
                return Decision(False, approval)

            self._record(sess, action, vm_arg, params, AuditResult.ALLOWED)
            return Decision(True)
        except (VMNotVisibleError, PermissionDeniedError, QuotaExceededError, RateLimitedError) as exc:
            self._record(
                sess,
                action,
                vm_arg or None,
                params,
                AuditResult.DENIED,
                deny_reason=exc.detail,
            )
            self.note_denied(sess, action, vm_arg)
            await self._maybe_emit_probe_alert(sess, action, vm_arg)
            raise

    # --------------------------------------------------------------- helpers

    def _check_quota(self, sess: Session, vm_id: str) -> None:
        statuses = self._running_count()
        running = sum(
            1 for s in statuses.values() if s in (VMStatus.RUNNING, VMStatus.PAUSED, VMStatus.STARTING)
        )
        if statuses.get(vm_id) in (VMStatus.RUNNING, VMStatus.PAUSED):
            return  # 幂等 start，不占新配额
        if running >= sess.perms.quota.max_running_vms:
            raise QuotaExceededError(
                f"quota max_running_vms={sess.perms.quota.max_running_vms} reached"
            )

    def _check_rate_limit(self, sess: Session, action: ToolAction, vm_id: str) -> None:
        key = (sess.id, vm_id, action.value)
        now_ts = time.time()
        window = self._deny_log.setdefault(key, [])
        # 只统计最近窗口内的拒绝次数；达到阈值后限制继续试探
        recent = [t for t in window if now_ts - t < self.PROBE_WINDOW_SEC]
        self._deny_log[key] = recent
        if len(recent) >= self.PROBE_THRESHOLD * 3:
            raise RateLimitedError(f"probe storm on {vm_id!r}")

    async def _maybe_emit_probe_alert(
        self, sess: Session, action: ToolAction, vm_id: str
    ) -> None:
        key = (sess.id, vm_id, action.value)
        hits = len(self._deny_log.get(key, []))
        if hits == self.PROBE_THRESHOLD:
            await self._emit(
                "security.probe_alert",
                {
                    "session_id": sess.id,
                    "vm_id": vm_id,
                    "action": action.value,
                    "count": hits,
                    "message": "同一会话对同一目标的拒绝已达阈值，疑似边界试探",
                },
            )

    def note_denied(self, sess: Session, action: ToolAction, vm_id: str) -> None:
        key = (sess.id, vm_id, action.value)
        self._deny_log.setdefault(key, []).append(time.time())

    async def _create_approval(
        self, sess: Session, action: ToolAction, vm_id: str, params: dict
    ) -> Approval:
        appr = Approval(
            session_id=sess.id,
            session_generation=sess.perms_generation,
            action=action,
            vm_id=vm_id,
            params=params,
        )
        self._store.save_approval(appr)
        return appr

    # ------------------------------------------------------------- approvals

    async def wait_for_approval(self, approval_id: str, timeout: float) -> Approval:
        """挂起等待审批决定（不变量 6：审批绑定具体调用，一次性、可过期）。"""
        event = self._approval_waiters.setdefault(approval_id, asyncio.Event())
        try:
            await asyncio.wait_for(event.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            pass
        finally:
            self._approval_waiters.pop(approval_id, None)
        appr = self._store.get_approval(approval_id)
        assert appr is not None
        if appr.status is ApprovalStatus.PENDING:
            appr.status = ApprovalStatus.EXPIRED
            self._store.save_approval(appr)
        return appr

    async def decide_approval(
        self, approval_id: str, approve: bool, decided_by: str
    ) -> Approval | None:
        async with self._lock:
            appr = self._store.get_approval(approval_id)
            if appr is None:
                return None
            if appr.status is not ApprovalStatus.PENDING or appr.expired():
                return appr  # 已决定或已过期：不可复用（不变量 6）
            appr.status = ApprovalStatus.APPROVED if approve else ApprovalStatus.REJECTED
            appr.decided_by = decided_by
            appr.decided_at = time.time()
            self._store.save_approval(appr)
        event = self._approval_waiters.get(approval_id)
        if event:
            event.set()
        await self._emit(
            "approval.decided", {"approval": appr.model_dump(mode="json")}
        )
        return appr

    def _record(
        self,
        sess: Session,
        action: ToolAction,
        vm_id: str | None,
        params: dict,
        result: AuditResult,
        deny_reason: str = "",
        approval_id: str | None = None,
    ) -> None:
        self._audit.record(
            session_id=sess.id,
            session_label=sess.label,
            action=action.value,
            vm_id=vm_id,
            model_params=params,
            result=result,
            deny_reason=deny_reason,
            approval_id=approval_id,
            actor="model",
        )
