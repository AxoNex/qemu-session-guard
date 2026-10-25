"""SQLite 持久化层。

四张表：vms / volumes / sessions / audits / approvals。
所有写操作走单连接（check_same_thread=False + 互斥锁），WAL 模式。
"""
from __future__ import annotations

import json
import logging
import sqlite3
import threading
from pathlib import Path

from .models import (
    Approval,
    ApprovalStatus,
    AuditEntry,
    Session,
    VMRegistration,
    Volume,
)

log = logging.getLogger(__name__)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS vms (
    id TEXT PRIMARY KEY,
    doc TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS volumes (
    id TEXT PRIMARY KEY,
    doc TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    doc TEXT NOT NULL,
    last_activity REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS audits (
    id TEXT PRIMARY KEY,
    ts REAL NOT NULL,
    session_id TEXT NOT NULL,
    vm_id TEXT,
    action TEXT NOT NULL,
    result TEXT NOT NULL,
    doc TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audits_ts ON audits(ts);
CREATE INDEX IF NOT EXISTS idx_audits_session ON audits(session_id);
CREATE INDEX IF NOT EXISTS idx_audits_vm ON audits(vm_id);
CREATE TABLE IF NOT EXISTS approvals (
    id TEXT PRIMARY KEY,
    status TEXT NOT NULL,
    session_id TEXT NOT NULL,
    doc TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_approvals_status ON approvals(status);
"""


class Store:
    def __init__(self, db_path: Path):
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._lock = threading.Lock()
        with self._lock:
            self._conn.executescript(_SCHEMA)
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # -- 通用 ---------------------------------------------------------------

    def _put(self, table: str, row_id: str, doc: str, extra: dict | None = None) -> None:
        cols = ["id", "doc"]
        vals: list = [row_id, doc]
        if extra:
            for k, v in extra.items():
                cols.append(k)
                vals.append(v)
        sql = f"INSERT OR REPLACE INTO {table} ({','.join(cols)}) VALUES ({','.join('?' * len(cols))})"
        with self._lock:
            self._conn.execute(sql, vals)
            self._conn.commit()

    def _get(self, table: str, row_id: str) -> str | None:
        with self._lock:
            row = self._conn.execute(
                f"SELECT doc FROM {table} WHERE id=?", (row_id,)
            ).fetchone()
        return row["doc"] if row else None

    def _all(self, table: str) -> list[str]:
        with self._lock:
            rows = self._conn.execute(f"SELECT doc FROM {table}").fetchall()
        return [r["doc"] for r in rows]

    def _del(self, table: str, row_id: str) -> None:
        with self._lock:
            self._conn.execute(f"DELETE FROM {table} WHERE id=?", (row_id,))
            self._conn.commit()

    # -- VM / Volume ---------------------------------------------------------

    def save_vm(self, vm: VMRegistration) -> None:
        self._put("vms", vm.id, vm.model_dump_json())

    def get_vm(self, vm_id: str) -> VMRegistration | None:
        doc = self._get("vms", vm_id)
        return VMRegistration.model_validate_json(doc) if doc else None

    def list_vms(self) -> list[VMRegistration]:
        return [VMRegistration.model_validate_json(d) for d in self._all("vms")]

    def delete_vm(self, vm_id: str) -> None:
        self._del("vms", vm_id)

    def save_volume(self, vol: Volume) -> None:
        self._put("volumes", vol.id, vol.model_dump_json())

    def get_volume(self, vol_id: str) -> Volume | None:
        doc = self._get("volumes", vol_id)
        return Volume.model_validate_json(doc) if doc else None

    def list_volumes(self) -> list[Volume]:
        return [Volume.model_validate_json(d) for d in self._all("volumes")]

    def delete_volume(self, vol_id: str) -> None:
        self._del("volumes", vol_id)

    # -- Session -------------------------------------------------------------

    def save_session(self, sess: Session) -> None:
        self._put(
            "sessions",
            sess.id,
            sess.model_dump_json(),
            {"last_activity": sess.last_activity_at},
        )

    def get_session(self, session_id: str) -> Session | None:
        doc = self._get("sessions", session_id)
        return Session.model_validate_json(doc) if doc else None

    def list_sessions(self) -> list[Session]:
        return [Session.model_validate_json(d) for d in self._all("sessions")]

    # -- Audit ---------------------------------------------------------------

    def save_audit(self, entry: AuditEntry) -> None:
        self._put(
            "audits",
            entry.id,
            entry.model_dump_json(),
            {
                "ts": entry.ts,
                "session_id": entry.session_id,
                "vm_id": entry.vm_id,
                "action": entry.action,
                "result": entry.result.value,
            },
        )

    def query_audits(
        self,
        session_id: str | None = None,
        vm_id: str | None = None,
        result: str | None = None,
        since: float | None = None,
        until: float | None = None,
        limit: int = 500,
        offset: int = 0,
    ) -> list[AuditEntry]:
        sql = "SELECT doc FROM audits WHERE 1=1"
        params: list = []
        if session_id:
            sql += " AND session_id=?"
            params.append(session_id)
        if vm_id:
            sql += " AND vm_id=?"
            params.append(vm_id)
        if result:
            sql += " AND result=?"
            params.append(result)
        if since is not None:
            sql += " AND ts>=?"
            params.append(since)
        if until is not None:
            sql += " AND ts<=?"
            params.append(until)
        sql += " ORDER BY ts DESC LIMIT ? OFFSET ?"
        params += [limit, offset]
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
        return [AuditEntry.model_validate_json(r["doc"]) for r in rows]

    # -- Approval ------------------------------------------------------------

    def save_approval(self, appr: Approval) -> None:
        self._put(
            "approvals",
            appr.id,
            appr.model_dump_json(),
            {"status": appr.status.value, "session_id": appr.session_id},
        )

    def get_approval(self, appr_id: str) -> Approval | None:
        doc = self._get("approvals", appr_id)
        return Approval.model_validate_json(doc) if doc else None

    def list_approvals(self, status: ApprovalStatus | None = None) -> list[Approval]:
        if status is None:
            return [Approval.model_validate_json(d) for d in self._all("approvals")]
        with self._lock:
            rows = self._conn.execute(
                "SELECT doc FROM approvals WHERE status=?", (status.value,)
            ).fetchall()
        return [Approval.model_validate_json(r["doc"]) for r in rows]

    # -- JSON 导出辅助 --------------------------------------------------------

    @staticmethod
    def audits_to_json(entries: list[AuditEntry]) -> str:
        return json.dumps(
            [e.model_dump(mode="json") for e in entries],
            ensure_ascii=False,
            indent=2,
        )
