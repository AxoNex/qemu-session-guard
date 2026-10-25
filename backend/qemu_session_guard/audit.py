"""审计日志（不变量 7）。

同时记录两个层面：
- 模型意图：tool 名 + 脱敏后的结构化参数（model_params）；
- 实际执行：真实发出的 QMP 命令 / QEMU 启动参数（executed）。

被拒绝的请求同样记录，并带拒绝原因，以便发现行为边界试探。
"""
from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable, Coroutine
from typing import Any

from .models import AuditEntry, AuditResult
from .store import Store

log = logging.getLogger(__name__)

# 订阅者：新审计条目产生时回调（用于 WebSocket 推送）。
Subscriber = Callable[[AuditEntry], Coroutine[Any, Any, None]]


class AuditLog:
    def __init__(self, store: Store):
        self._store = store
        self._subs: list[Subscriber] = []

    def subscribe(self, cb: Subscriber) -> Callable[[], None]:
        self._subs.append(cb)

        def _unsub() -> None:
            try:
                self._subs.remove(cb)
            except ValueError:
                pass

        return _unsub

    def record(
        self,
        *,
        session_id: str = "",
        session_label: str = "",
        action: str,
        vm_id: str | None = None,
        model_params: dict | None = None,
        executed: list[str] | None = None,
        result: AuditResult = AuditResult.ALLOWED,
        deny_reason: str = "",
        approval_id: str | None = None,
        error: str = "",
        actor: str = "model",
    ) -> AuditEntry:
        entry = AuditEntry(
            session_id=session_id,
            session_label=session_label,
            action=action,
            vm_id=vm_id,
            model_params=model_params or {},
            executed=executed or [],
            result=result,
            deny_reason=deny_reason,
            approval_id=approval_id,
            error=error,
            actor=actor,
        )
        self._store.save_audit(entry)
        for cb in list(self._subs):
            try:
                asyncio.get_running_loop().create_task(cb(entry))
            except RuntimeError:
                pass  # 无事件循环（同步上下文，如单元测试）
            except Exception:  # noqa: BLE001 - 订阅者故障不得影响审计写入
                log.exception("audit subscriber failed")
        return entry
