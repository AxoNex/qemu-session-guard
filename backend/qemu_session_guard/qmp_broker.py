"""QMP Broker：受控 QEMU 进程池（数据面）+ QMP 控制面。

职责：
- 以安全基线参数 spawn QEMU（不变量 1、5）；QMP socket 由插件独占管理（不变量 4）；
- 通过 QMP 完成 query-status / system_powerdown / quit / stop / cont；
- 监听 QEMU 进程退出与 QMP 事件，维护 VMStatus；
- QMP 连接异常断开时**不重连未授权 socket**，标记 UNKNOWN 并告警（§2.3）；
- Windows 下 QMP 只能走 TCP loopback，端口从空闲池分配并记录；
  类 Unix 系统优先 unix socket，socket 文件放插件私有目录。
"""
from __future__ import annotations

import asyncio
import logging
import platform
import socket
import subprocess
import uuid
from collections.abc import Callable, Coroutine
from pathlib import Path
from typing import Any

from .audit import AuditLog
from .config import Config
from .errors import ConflictError, GuardError, NotFoundError
from .models import AuditResult, VMRegistration, VMStatus
from .qmp_client import QMPError, QmpSession
from .qemu_discovery import baseline_args
from .store import Store

log = logging.getLogger(__name__)

IS_WINDOWS = platform.system() == "Windows"

# QMP 事件 -> 内部状态
_EVENT_STATUS = {
    "STOP": VMStatus.PAUSED,
    "RESUME": VMStatus.RUNNING,
    "SHUTDOWN": VMStatus.SHUTDOWN,
    "RESET": VMStatus.RUNNING,
    "POWERDOWN": None,  # guest 正在关机，等待 SHUTDOWN
}


class _VMRuntime:
    """单个 VM 的运行时状态（不持久化）。"""

    def __init__(self, vm_id: str):
        self.vm_id = vm_id
        self.proc: subprocess.Popen | None = None
        self.qmp: QmpSession | None = None
        self.status: VMStatus = VMStatus.STOPPED
        self.qmp_address: tuple[str, Any] | None = None
        self.monitor_task: asyncio.Task | None = None
        self.last_error: str = ""


class QmpBroker:
    def __init__(self, cfg: Config, store: Store, audit: AuditLog):
        self._cfg = cfg
        self._store = store
        self._audit = audit
        self._runtimes: dict[str, _VMRuntime] = {}
        self._lock = asyncio.Lock()
        self._events: list[Callable[[dict], Coroutine[Any, Any, None]]] = []
        self._qmp_dir = Path(cfg.data_dir) / "qmp"

    # ---------------------------------------------------------------- events

    def subscribe(self, cb) -> Callable[[], None]:
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
                log.exception("broker event subscriber failed")

    # --------------------------------------------------------------- runtime

    def runtime(self, vm_id: str) -> _VMRuntime:
        rt = self._runtimes.get(vm_id)
        if rt is None:
            rt = _VMRuntime(vm_id)
            self._runtimes[vm_id] = rt
        return rt

    def statuses(self) -> dict[str, VMStatus]:
        return {vm_id: rt.status for vm_id, rt in self._runtimes.items()}

    async def _set_status(self, rt: _VMRuntime, status: VMStatus) -> None:
        if rt.status is status:
            return
        rt.status = status
        await self._emit("vm.status", {"vm_id": rt.vm_id, "status": status.value})

    # ------------------------------------------------------------ QMP 地址

    def _alloc_qmp_address(self, vm_id: str) -> tuple[str, Any]:
        """分配插件独占的 QMP 端点（不变量 4）。地址不返回给模型。"""
        if IS_WINDOWS or not self._cfg.prefer_unix_qmp:
            # Windows 的 QEMU 只支持 TCP QMP；绑定 127.0.0.1 + 随机空闲端口
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(("127.0.0.1", 0))
                port = s.getsockname()[1]
            return ("tcp", "127.0.0.1", port)
        path = self._qmp_dir / f"{vm_id}-{uuid.uuid4().hex[:8]}.sock"
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass
        return ("unix", str(path))

    @staticmethod
    def _qmp_spec(address: tuple[str, Any]) -> str:
        if address[0] == "tcp":
            return f"tcp:{address[1]}:{address[2]},server=on,wait=off"
        return f"unix:{address[1]},server=on,wait=off"

    # ------------------------------------------------------------- 启动参数

    def build_command(
        self, vm: VMRegistration, volumes: dict[str, tuple[str, bool]]
    ) -> tuple[list[str], tuple[str, Any]]:
        """组装受控的 QEMU 命令行（不变量 1、5）。

        volumes: volume_id -> (宿主机路径, 是否只读)（仅预注册卷）。
        返回 (argv, qmp_address)。
        """
        address = self._alloc_qmp_address(vm.id)
        argv = [vm.qemu_binary]
        argv += baseline_args(self._qmp_spec(address))
        machine = vm.machine or ("q35" if vm.arch in ("x86_64", "i386") else "virt")
        argv += [
            "-name",
            f"qsg-{vm.id}",
            "-machine",
            machine,
        ]
        argv += ["-smp", str(vm.resources.vcpus), "-m", str(vm.resources.mem_mb)]
        argv += ["-display", "none", "-vga", "none"]
        # 预注册卷（不变量 5：模型不可指定任意宿主机路径）
        for vol_id in vm.disk_volume_ids:
            entry = volumes.get(vol_id)
            if not entry:
                raise GuardError("卷未注册", f"volume {vol_id!r} not registered")
            path, read_only = entry
            ro = ",readonly=on" if read_only else ""
            argv += [
                "-drive",
                f"file={path},if=virtio,media=disk,format=raw{ro}",
            ]
        # 管理员级 extra_args（注册时已通过 forbidden-list 校验，此处原样附加）
        argv += list(vm.extra_args)
        return argv, address

    # ----------------------------------------------------------------- 操作

    async def start(self, vm_id: str, actor: str = "model", session_id: str = "") -> dict:
        """spawn QEMU 并建立 QMP 连接。幂等：已运行则直接返回。"""
        async with self._lock:
            rt = self.runtime(vm_id)
            if rt.status in (VMStatus.RUNNING, VMStatus.PAUSED, VMStatus.STARTING) and rt.proc and rt.proc.poll() is None:
                return {"vm_id": vm_id, "status": rt.status.value, "idempotent": True}
            vm = self._store.get_vm(vm_id)
            if vm is None:
                raise NotFoundError("VM 不存在或无权限", f"vm {vm_id!r} not registered")
            volumes = {v.id: (v.path, v.read_only) for v in self._store.list_volumes()}
            argv, address = self.build_command(vm, volumes)
            await self._set_status(rt, VMStatus.STARTING)
            self._audit.record(
                session_id=session_id,
                action="vm_start.exec",
                vm_id=vm_id,
                executed=[subprocess.list2cmdline(argv)],
                result=AuditResult.ALLOWED,
                actor=actor,
            )
            creationflags = 0
            if IS_WINDOWS:
                # 防止 QEMU 弹出控制台窗口；不继承父进程控制台
                creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
            try:
                rt.proc = subprocess.Popen(  # noqa: S603 - argv 完全由插件构造
                    argv,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    creationflags=creationflags,
                )
            except OSError as exc:
                await self._set_status(rt, VMStatus.STOPPED)
                raise GuardError("QEMU 启动失败", str(exc)) from exc
            rt.qmp_address = address
            rt.monitor_task = asyncio.create_task(self._monitor(vm_id, rt))
            try:
                await self._connect_qmp(rt, timeout=15)
            except GuardError:
                # 启动失败：清掉进程，避免留下无控制面的 QEMU
                self._kill_proc(rt)
                await self._set_status(rt, VMStatus.STOPPED)
                raise
            await self._refresh_status(rt)
            return {"vm_id": vm_id, "status": rt.status.value, "idempotent": False}

    async def _connect_qmp(self, rt: _VMRuntime, timeout: float = 15) -> None:
        """等待 QEMU 打开 QMP 端点并完成 capabilities 协商。"""
        deadline = asyncio.get_running_loop().time() + timeout
        last_exc: Exception | None = None
        while asyncio.get_running_loop().time() < deadline:
            if rt.proc and rt.proc.poll() is not None:
                raise GuardError(
                    "QEMU 进程已退出", f"exit code {rt.proc.returncode}"
                )
            sess = QmpSession(rt.qmp_address, event_handler=lambda e: self._on_qmp_event(rt, e))
            try:
                await sess.connect(timeout=5)
                rt.qmp = sess
                return
            except (OSError, ConnectionError, asyncio.TimeoutError) as exc:
                last_exc = exc
                await asyncio.sleep(0.3)
            except Exception as exc:  # noqa: BLE001
                last_exc = exc
                await asyncio.sleep(0.3)
        raise GuardError("QMP 连接超时", str(last_exc))

    async def _on_qmp_event(self, rt: _VMRuntime, event: dict) -> None:
        name = event.get("event", "")
        new_status = _EVENT_STATUS.get(name)
        if name == "SHUTDOWN":
            # guest 关机完成：QEMU 进程即将退出，由 _monitor 收尾
            await self._set_status(rt, VMStatus.SHUTDOWN)
        elif new_status is not None:
            await self._set_status(rt, new_status)
        await self._emit("vm.qmp_event", {"vm_id": rt.vm_id, "event": event})

    async def _refresh_status(self, rt: _VMRuntime) -> VMStatus:
        """query-status → 内部状态映射（§2.3）。"""
        if rt.qmp is None or not rt.qmp.connected:
            await self._set_status(rt, VMStatus.UNKNOWN)
            return VMStatus.UNKNOWN
        ret = await rt.qmp.execute("query-status")
        running = bool(ret.get("running"))
        qmp_status = str(ret.get("status", ""))
        if qmp_status in ("shutdown",) :
            status = VMStatus.SHUTDOWN
        elif qmp_status in ("paused", "suspended", "prelaunch"):
            status = VMStatus.PAUSED if qmp_status != "prelaunch" else VMStatus.STARTING
        elif running:
            status = VMStatus.RUNNING
        else:
            status = VMStatus.PAUSED
        await self._set_status(rt, status)
        return status

    async def _monitor(self, vm_id: str, rt: _VMRuntime) -> None:
        """等待 QEMU 进程退出；退出后清理 QMP、标记状态。"""
        proc = rt.proc
        assert proc is not None
        loop = asyncio.get_running_loop()
        rc = await loop.run_in_executor(None, proc.wait)
        log.info("VM %s 的 QEMU 进程退出，rc=%s", vm_id, rc)
        if rt.qmp:
            await rt.qmp.disconnect()
            rt.qmp = None
        # 清理 unix socket 文件
        if rt.qmp_address and rt.qmp_address[0] == "unix":
            try:
                Path(rt.qmp_address[1]).unlink(missing_ok=True)
            except OSError:
                pass
        if rt.status not in (VMStatus.SHUTDOWN,):
            await self._set_status(rt, VMStatus.SHUTDOWN if rc == 0 else VMStatus.STOPPED)
        await self._emit(
            "vm.exited", {"vm_id": vm_id, "returncode": rc}
        )

    # ------------------------------------------------------------- QMP 命令

    async def _require_qmp(self, vm_id: str) -> _VMRuntime:
        rt = self.runtime(vm_id)
        if rt.qmp is None or not rt.qmp.connected or rt.proc is None or rt.proc.poll() is not None:
            raise ConflictError("VM 未在运行", f"vm {vm_id!r} has no live QMP")
        return rt

    async def query_status(self, vm_id: str) -> dict:
        rt = self.runtime(vm_id)
        if rt.qmp and rt.qmp.connected and rt.proc and rt.proc.poll() is None:
            try:
                status = await self._refresh_status(rt)
            except QMPError:
                # 连接在我们检查后、命令执行前断开 → 标 UNKNOWN（§2.3 不重连）
                await self._set_status(rt, VMStatus.UNKNOWN)
                status = VMStatus.UNKNOWN
        else:
            status = rt.status
        info: dict[str, Any] = {
            "vm_id": vm_id,
            "status": status.value,
            "qemu_pid": rt.proc.pid if rt.proc and rt.proc.poll() is None else None,
        }
        if rt.proc and rt.proc.poll() is None:
            try:
                import psutil  # 可选依赖

                p = psutil.Process(rt.proc.pid)
                with p.oneshot():
                    info["cpu_percent"] = p.cpu_percent(interval=None)
                    info["mem_rss_mb"] = round(p.memory_info().rss / 1024 / 1024, 1)
            except Exception:  # noqa: BLE001 - psutil 缺失时仅省略资源字段
                pass
        return info

    async def shutdown(self, vm_id: str, actor: str = "model", session_id: str = "") -> dict:
        """优雅关机：QMP system_powerdown。"""
        rt = await self._require_qmp(vm_id)
        await rt.qmp.execute("system_powerdown")
        self._audit.record(
            session_id=session_id, action="qmp", vm_id=vm_id,
            executed=["system_powerdown"], result=AuditResult.ALLOWED, actor=actor,
        )
        return {"vm_id": vm_id, "sent": "system_powerdown"}

    async def force_off(self, vm_id: str, actor: str = "model", session_id: str = "") -> dict:
        """强制退出：QMP quit（高危操作，默认需要审批——审批逻辑在 PermissionEngine）。"""
        rt = await self._require_qmp(vm_id)
        try:
            await rt.qmp.execute("quit")
        except Exception:  # noqa: BLE001 - quit 常导致连接立即断开
            pass
        self._audit.record(
            session_id=session_id, action="qmp", vm_id=vm_id,
            executed=["quit"], result=AuditResult.ALLOWED, actor=actor,
        )
        # quit 后 QEMU 进程退出由 _monitor 收尾；兜底直接 kill
        await asyncio.sleep(0.5)
        if rt.proc and rt.proc.poll() is None:
            self._kill_proc(rt)
        await self._set_status(rt, VMStatus.STOPPED)
        return {"vm_id": vm_id, "sent": "quit"}

    async def stop(self, vm_id: str, actor: str = "model", session_id: str = "") -> dict:
        rt = await self._require_qmp(vm_id)
        await rt.qmp.execute("stop")
        self._audit.record(
            session_id=session_id, action="qmp", vm_id=vm_id,
            executed=["stop"], result=AuditResult.ALLOWED, actor=actor,
        )
        await self._set_status(rt, VMStatus.PAUSED)
        return {"vm_id": vm_id, "sent": "stop"}

    async def resume(self, vm_id: str, actor: str = "model", session_id: str = "") -> dict:
        rt = await self._require_qmp(vm_id)
        await rt.qmp.execute("cont")
        self._audit.record(
            session_id=session_id, action="qmp", vm_id=vm_id,
            executed=["cont"], result=AuditResult.ALLOWED, actor=actor,
        )
        await self._set_status(rt, VMStatus.RUNNING)
        return {"vm_id": vm_id, "sent": "cont"}

    # ----------------------------------------------------------------- 清理

    @staticmethod
    def _kill_proc(rt: _VMRuntime) -> None:
        if rt.proc and rt.proc.poll() is None:
            try:
                rt.proc.kill()
            except OSError:
                pass

    async def mark_unknown(self, vm_id: str, reason: str) -> None:
        """QMP 连接异常断开：不重连未授权 socket，标记 unknown 并告警（§2.3）。"""
        rt = self.runtime(vm_id)
        rt.last_error = reason
        await self._set_status(rt, VMStatus.UNKNOWN)
        await self._emit(
            "vm.qmp_lost",
            {"vm_id": vm_id, "reason": reason, "message": "QMP 连接断开，状态不可信"},
        )

    async def shutdown_all(self) -> None:
        """服务关闭时清理所有受管 QEMU 进程。"""
        for rt in list(self._runtimes.values()):
            if rt.qmp and rt.qmp.connected:
                try:
                    await rt.qmp.execute("quit")
                except Exception:  # noqa: BLE001
                    pass
            self._kill_proc(rt)
        # 清理 socket 目录
        if self._qmp_dir.exists():
            for f in self._qmp_dir.glob("*.sock"):
                try:
                    f.unlink()
                except OSError:
                    pass
