"""SessionGuard：会话生命周期管理（不变量 2、3）。

- 创建会话时把管理员给定的权限固化为 SessionPerms 快照；
- 权限修改生成新快照并 bump perms_generation，仅对**后续** tool 调用生效；
  进行中的操作持有旧快照副本，不受影响（不变量 3）；
- 会话过期 / 停用后所有调用被拒绝。
"""
from __future__ import annotations

import logging

from .errors import PermissionDeniedError
from .models import PermLevel, Quota, Session, SessionPerms, now


def _normalize_levels(levels: list) -> list[PermLevel]:
    """把权限级别统一规整为 PermLevel 枚举（接受枚举或其字符串值）。

    update_perms 的调用方可能传字符串（'read'）或枚举（PermLevel.READ）；
    快照持久化前必须统一，否则 pydantic 序列化到 SQLite 时会对 str 值告警。
    """
    out: list[PermLevel] = []
    for v in levels:
        if isinstance(v, PermLevel):
            out.append(v)
        else:
            out.append(PermLevel(str(v)))
    return out


from .store import Store

log = logging.getLogger(__name__)


class SessionGuard:
    def __init__(self, store: Store, session_ttl_hours: float = 0):
        self._store = store
        self._ttl_hours = session_ttl_hours

    # ------------------------------------------------------------------ CRUD

    def create_session(
        self,
        *,
        label: str = "",
        owner: str = "admin",
        granted_vm_ids: list[str],
        permission_map: dict[str, list[str]],
        quota: Quota | None = None,
        approval_actions: list[str] | None = None,
    ) -> Session:
        perms_kwargs: dict = {
            "granted_vm_ids": [v for v in granted_vm_ids],
            "permission_map": {
                k: _normalize_levels(list(v))
                for k, v in permission_map.items()
                if k in set(granted_vm_ids)
            },
            "quota": quota or Quota(),
        }
        if approval_actions is not None:
            perms_kwargs["approval_actions"] = list(approval_actions)
        sess = Session(label=label, owner=owner, perms=SessionPerms(**perms_kwargs))
        if self._ttl_hours > 0:
            sess.expires_at = now() + self._ttl_hours * 3600
        self._store.save_session(sess)
        log.info("会话 %s 创建（label=%r，可见 VM=%s）", sess.id, label, granted_vm_ids)
        return sess

    def get(self, session_id: str) -> Session | None:
        return self._store.get_session(session_id)

    def list(self) -> list[Session]:
        return self._store.list_sessions()

    def deactivate(self, session_id: str) -> Session | None:
        sess = self._store.get_session(session_id)
        if sess is None:
            return None
        sess.active = False
        self._store.save_session(sess)
        return sess

    def snapshot(self, session_id: str) -> Session:
        """取会话的当前权限快照副本。

        工具调用在**开始时**调用一次并持有返回值直到操作结束——这就是
        「进行中的操作不受权限变更影响」的实现方式（不变量 3）。
        """
        sess = self._store.get_session(session_id)
        if sess is None:
            raise PermissionDeniedError(f"未知会话 {session_id}")
        if not sess.active or sess.expired():
            raise PermissionDeniedError(f"会话 {session_id} 已停用或过期")
        sess.last_activity_at = now()
        self._store.save_session(sess)
        # model_copy(deep=True) 保证后续 update_perms 不会改写本次快照
        return sess.model_copy(deep=True)

    def update_perms(
        self,
        session_id: str,
        *,
        granted_vm_ids: list[str] | None = None,
        permission_map: dict[str, list[str]] | None = None,
        quota: Quota | None = None,
        approval_actions: list[str] | None = None,
    ) -> Session | None:
        """修改会话权限：生成新快照、代次 +1。仅对后续 tool 调用生效（不变量 3）。"""
        sess = self._store.get_session(session_id)
        if sess is None:
            return None
        new_perms = sess.perms.model_copy(deep=True)
        if granted_vm_ids is not None:
            new_perms.granted_vm_ids = list(dict.fromkeys(granted_vm_ids))
        if permission_map is not None:
            visible = set(new_perms.granted_vm_ids)
            new_perms.permission_map = {
                k: _normalize_levels(list(v))
                for k, v in permission_map.items()
                if k in visible
            }
        else:
            # 可见列表收窄时同步裁剪权限矩阵，避免留下“孤儿”授权
            visible = set(new_perms.granted_vm_ids)
            new_perms.permission_map = {
                k: v for k, v in new_perms.permission_map.items() if k in visible
            }
        if quota is not None:
            new_perms.quota = quota
        if approval_actions is not None:
            new_perms.approval_actions = list(approval_actions)
        sess.perms = new_perms
        sess.perms_generation += 1
        self._store.save_session(sess)
        log.info(
            "会话 %s 权限更新为代次 %d（仅对新调用生效）",
            sess.id,
            sess.perms_generation,
        )
        return sess
