"""FastAPI 应用：WebUI REST API + WebSocket 实时推送 + 静态前端。

WebUI 自身的所有 VM 操作同样走 PermissionEngine 与 AuditLog（§4.1），
使用一个内置的「管理员会话」语义：actor="webui"，权限不受会话限制，
但审计一样完整。
"""
from __future__ import annotations

import asyncio
import csv
import io
import json
import logging
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field

from .audit import AuditLog
from .config import Config
from .errors import ArgumentViolationError, GuardError
from .models import (
    ApprovalStatus,
    AuditResult,
    PermLevel,
    Quota,
    SessionPerms,
    ToolAction,
    VMRegistration,
    VMResources,
    VMStatus,
    Volume,
)
from .permission import PermissionEngine
from .qmp_broker import QmpBroker
from .qemu_discovery import discover, validate_extra_args
from .session_guard import SessionGuard
from .store import Store
from .tools import ModelTools

log = logging.getLogger(__name__)

FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"


# ---------------------------------------------------------------------------
# 请求模型（strict）
# ---------------------------------------------------------------------------


class VolumeIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1, max_length=128)
    path: str = Field(min_length=1)
    read_only: bool = True
    description: str = ""


class VMIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1, max_length=128)
    arch: str = "x86_64"
    machine: str = ""
    qemu_binary: str = Field(min_length=1)
    vcpus: int = Field(default=2, ge=1, le=64)
    mem_mb: int = Field(default=2048, ge=128, le=262144)
    disk_volume_ids: list[str] = Field(default_factory=list)
    extra_args: list[str] = Field(default_factory=list)


class SessionIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    label: str = ""
    owner: str = "admin"
    granted_vm_ids: list[str] = Field(default_factory=list)
    permission_map: dict[str, list[str]] = Field(default_factory=dict)
    quota: Quota = Field(default_factory=Quota)
    approval_actions: list[str] | None = None


class PermsUpdateIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    granted_vm_ids: list[str] | None = None
    permission_map: dict[str, list[str]] | None = None
    quota: Quota | None = None
    approval_actions: list[str] | None = None


class ApprovalDecisionIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    approve: bool
    decided_by: str = "admin"


class ToolCallIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tool: str = Field(min_length=1)
    params: dict = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# 应用装配
# ---------------------------------------------------------------------------


class Service:
    """后端核心容器：把所有组件装配在一起。"""

    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.store = Store(Path(cfg.data_dir) / "qsg.db")
        self.audit = AuditLog(self.store)
        self.sessions = SessionGuard(self.store, cfg.session_ttl_hours)
        self.broker = QmpBroker(cfg, self.store, self.audit)
        self.perms = PermissionEngine(self.store, self.audit, self.broker.statuses)
        self.tools = ModelTools(self.sessions, self.perms, self.broker, cfg.approval_timeout_sec)

    async def close(self) -> None:
        await self.broker.shutdown_all()
        self.store.close()


class WSHub:
    """WebSocket 连接集线器：广播 broker / perms / audit 事件。"""

    def __init__(self):
        self._clients: set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def add(self, ws: WebSocket) -> None:
        async with self._lock:
            self._clients.add(ws)

    async def remove(self, ws: WebSocket) -> None:
        async with self._lock:
            self._clients.discard(ws)

    async def broadcast(self, msg: dict) -> None:
        data = json.dumps(msg, ensure_ascii=False)
        async with self._lock:
            clients = list(self._clients)
        for ws in clients:
            try:
                await ws.send_text(data)
            except Exception:  # noqa: BLE001
                await self.remove(ws)


def create_app(cfg: Config | None = None) -> FastAPI:
    cfg = cfg or Config()
    svc = Service(cfg)
    hub = WSHub()
    app = FastAPI(title="qemu-session-guard", version="0.1.0")
    app.state.svc = svc

    # 事件汇流：broker / perms / audit -> WebSocket
    svc.broker.subscribe(hub.broadcast)
    svc.perms.subscribe(hub.broadcast)

    async def _audit_event(entry):
        await hub.broadcast({"type": "audit", "entry": entry.model_dump(mode="json")})

    svc.audit.subscribe(_audit_event)

    @app.exception_handler(GuardError)
    async def _guard_exc(_req: Request, exc: GuardError) -> JSONResponse:
        return JSONResponse({"error": exc.public}, status_code=403)

    # ------------------------------------------------------------- 发现层

    @app.get("/api/qemu/discover")
    async def api_discover():
        found = await discover(cfg.msys2_root, cfg.qemu_binary_dir, verify=True)
        return {"candidates": [b.as_dict() for b in found]}

    # ------------------------------------------------------------- 卷管理

    @app.get("/api/volumes")
    async def list_volumes():
        return {"volumes": [v.model_dump(mode="json") for v in svc.store.list_volumes()]}

    @app.post("/api/volumes")
    async def create_volume(body: VolumeIn):
        if svc.store.get_volume(body.id):
            raise HTTPException(409, "卷 ID 已存在")
        vol = Volume(**body.model_dump())
        svc.store.save_volume(vol)
        return vol.model_dump(mode="json")

    @app.delete("/api/volumes/{vol_id}")
    async def delete_volume(vol_id: str):
        svc.store.delete_volume(vol_id)
        return {"ok": True}

    # ------------------------------------------------------------- VM 注册

    @app.get("/api/vms")
    async def list_vms():
        statuses = svc.broker.statuses()
        out = []
        for vm in svc.store.list_vms():
            doc = vm.model_dump(mode="json")
            doc["status"] = statuses.get(vm.id, VMStatus.STOPPED).value
            out.append(doc)
        return {"vms": out}

    @app.post("/api/vms")
    async def register_vm(body: VMIn):
        if svc.store.get_vm(body.id):
            raise HTTPException(409, "VM ID 已存在")
        violations = validate_extra_args(body.extra_args)
        if violations:
            svc.audit.record(
                action="vm.register",
                vm_id=body.id,
                model_params={"extra_args": body.extra_args},
                result=AuditResult.DENIED,
                deny_reason=f"forbidden qemu args: {violations}",
                actor="webui",
            )
            raise ArgumentViolationError(f"被拒绝的 QEMU 参数: {violations}")
        # 校验 binary 可执行并记录版本
        from .qemu_discovery import probe_version, _variant_of  # noqa: PLC0415

        binary = Path(body.qemu_binary)
        if not binary.is_file():
            raise HTTPException(400, "QEMU binary 不存在")
        try:
            version = await probe_version(binary)
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(400, f"QEMU binary 不可执行: {exc}") from exc
        # 卷必须已注册
        for vol_id in body.disk_volume_ids:
            if svc.store.get_volume(vol_id) is None:
                raise HTTPException(400, f"卷 {vol_id!r} 未注册")
        vm = VMRegistration(
            id=body.id,
            arch=body.arch,
            machine=body.machine,
            qemu_binary=str(binary),
            qemu_version=version,
            qemu_variant=_variant_of(binary),
            resources=VMResources(vcpus=body.vcpus, mem_mb=body.mem_mb),
            disk_volume_ids=list(body.disk_volume_ids),
            extra_args=list(body.extra_args),
        )
        svc.store.save_vm(vm)
        return vm.model_dump(mode="json")

    @app.delete("/api/vms/{vm_id}")
    async def delete_vm(vm_id: str):
        status = svc.broker.statuses().get(vm_id, VMStatus.STOPPED)
        if status in (VMStatus.RUNNING, VMStatus.PAUSED, VMStatus.STARTING):
            raise HTTPException(409, "VM 正在运行，无法删除")
        svc.store.delete_vm(vm_id)
        return {"ok": True}

    # ------------------------------------------------------- VM 电源（WebUI）

    async def _webui_power(vm_id: str, action: str):
        """WebUI 的电源操作同样走 broker + 审计（§4.1）。"""
        if svc.store.get_vm(vm_id) is None:
            raise HTTPException(404, "VM 不存在")
        handlers = {
            "start": svc.broker.start,
            "shutdown": svc.broker.shutdown,
            "force_off": svc.broker.force_off,
            "stop": svc.broker.stop,
            "resume": svc.broker.resume,
        }
        try:
            return await handlers[action](vm_id, actor="webui")
        except GuardError as exc:
            raise HTTPException(409, exc.public) from exc

    @app.post("/api/vms/{vm_id}/power/{action}")
    async def vm_power(vm_id: str, action: str):
        if action not in {"start", "shutdown", "force_off", "stop", "resume"}:
            raise HTTPException(400, "未知操作")
        return await _webui_power(vm_id, action)

    # ------------------------------------------------------------- 会话管理

    @app.get("/api/sessions")
    async def list_sessions():
        statuses = svc.broker.statuses()
        running = sum(
            1 for s in statuses.values()
            if s in (VMStatus.RUNNING, VMStatus.PAUSED, VMStatus.STARTING)
        )
        out = []
        for sess in svc.sessions.list():
            doc = sess.model_dump(mode="json")
            doc["running_vms_total"] = running
            doc["expired"] = sess.expired()
            out.append(doc)
        return {"sessions": out}

    @app.post("/api/sessions")
    async def create_session(body: SessionIn):
        # 可见列表与权限矩阵中的 VM 必须已注册（防止悬空授权）
        for vm_id in set(body.granted_vm_ids) | set(body.permission_map):
            if svc.store.get_vm(vm_id) is None:
                raise HTTPException(400, f"VM {vm_id!r} 未注册")
        try:
            perms_map = {
                k: [PermLevel(x) for x in v] for k, v in body.permission_map.items()
            }
            _ = SessionPerms(
                granted_vm_ids=body.granted_vm_ids,
                permission_map=perms_map,
                quota=body.quota,
                approval_actions=(
                    [ToolAction(a) for a in body.approval_actions]
                    if body.approval_actions is not None
                    else [ToolAction.VM_FORCE_OFF]
                ),
            )
        except ValueError as exc:
            raise HTTPException(400, f"权限参数无效: {exc}") from exc
        sess = svc.sessions.create_session(
            label=body.label,
            owner=body.owner,
            granted_vm_ids=body.granted_vm_ids,
            permission_map=body.permission_map,
            quota=body.quota,
            approval_actions=body.approval_actions,
        )
        return sess.model_dump(mode="json")

    @app.get("/api/sessions/{session_id}")
    async def get_session(session_id: str):
        sess = svc.sessions.get(session_id)
        if sess is None:
            raise HTTPException(404, "会话不存在")
        return sess.model_dump(mode="json")

    @app.put("/api/sessions/{session_id}/perms")
    async def update_perms(session_id: str, body: PermsUpdateIn):
        sess = svc.sessions.update_perms(
            session_id,
            granted_vm_ids=body.granted_vm_ids,
            permission_map=body.permission_map,
            quota=body.quota,
            approval_actions=body.approval_actions,
        )
        if sess is None:
            raise HTTPException(404, "会话不存在")
        svc.audit.record(
            session_id=session_id,
            action="session.update_perms",
            model_params=body.model_dump(mode="json"),
            result=AuditResult.ALLOWED,
            actor="webui",
            deny_reason="",
        )
        return {
            "session": sess.model_dump(mode="json"),
            "note": "权限变更仅对后续 tool 调用生效；进行中的操作不受影响。",
        }

    @app.post("/api/sessions/{session_id}/deactivate")
    async def deactivate_session(session_id: str):
        sess = svc.sessions.deactivate(session_id)
        if sess is None:
            raise HTTPException(404, "会话不存在")
        return {"ok": True}

    # ------------------------------------------------------- 模型 tool 调用

    @app.post("/api/sessions/{session_id}/tool")
    async def call_tool(session_id: str, body: ToolCallIn):
        """模拟模型侧 tool 调用（供测试与 WebUI 调试）。

        拒绝已在 PermissionEngine / tools 层审计，此处不再重复记录。
        """
        try:
            result = await svc.tools.call(session_id, body.tool, body.params)
            return json.loads(result)
        except GuardError as exc:
            raise HTTPException(403, exc.public) from exc

    # ------------------------------------------------------------- 审批

    @app.get("/api/approvals")
    async def list_approvals(status: str | None = None):
        st = ApprovalStatus(status) if status else None
        apprs = svc.store.list_approvals(st)
        return {"approvals": [a.model_dump(mode="json") for a in apprs]}

    @app.post("/api/approvals/{approval_id}/decide")
    async def decide_approval(approval_id: str, body: ApprovalDecisionIn):
        appr = await svc.perms.decide_approval(approval_id, body.approve, body.decided_by)
        if appr is None:
            raise HTTPException(404, "审批不存在")
        svc.audit.record(
            session_id=appr.session_id,
            action=f"approval.{'approved' if body.approve else 'rejected'}",
            vm_id=appr.vm_id,
            model_params={"approval_id": approval_id, "action": appr.action.value},
            result=AuditResult.ALLOWED,
            actor="webui",
        )
        return appr.model_dump(mode="json")

    # ------------------------------------------------------------- 审计

    @app.get("/api/audits")
    async def query_audits(
        session_id: str | None = None,
        vm_id: str | None = None,
        result: str | None = None,
        since: float | None = None,
        until: float | None = None,
        limit: int = 200,
        offset: int = 0,
        format: str = "json",
    ):
        entries = svc.store.query_audits(
            session_id=session_id, vm_id=vm_id, result=result,
            since=since, until=until, limit=min(limit, 2000), offset=offset,
        )
        if format == "csv":
            buf = io.StringIO()
            writer = csv.writer(buf)
            writer.writerow(
                ["ts", "session_id", "session_label", "action", "vm_id", "result", "deny_reason", "executed", "model_params", "actor"]
            )
            for e in entries:
                writer.writerow([
                    e.ts, e.session_id, e.session_label, e.action, e.vm_id or "",
                    e.result.value, e.deny_reason, " | ".join(e.executed),
                    json.dumps(e.model_params, ensure_ascii=False), e.actor,
                ])
            return PlainTextResponse(
                buf.getvalue(),
                media_type="text/csv",
                headers={"Content-Disposition": "attachment; filename=audits.csv"},
            )
        return {"audits": [e.model_dump(mode="json") for e in entries]}

    # ------------------------------------------------------------- 监控

    @app.get("/api/status")
    async def all_status():
        return {"statuses": {k: v.value for k, v in svc.broker.statuses().items()}}

    @app.websocket("/ws")
    async def websocket(ws: WebSocket):
        await ws.accept()
        await hub.add(ws)
        try:
            # 首帧推送当前全量状态
            await ws.send_text(json.dumps({
                "type": "snapshot",
                "statuses": {k: v.value for k, v in svc.broker.statuses().items()},
            }, ensure_ascii=False))
            while True:
                await ws.receive_text()  # 目前不接收客户端指令，仅保持连接
        except WebSocketDisconnect:
            pass
        finally:
            await hub.remove(ws)

    # ------------------------------------------------------------- 前端

    if FRONTEND_DIR.is_dir():
        app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")

        @app.get("/", include_in_schema=False)
        async def index():
            return FileResponse(FRONTEND_DIR / "index.html")

    @app.on_event("shutdown")
    async def _shutdown():
        await svc.close()

    return app
