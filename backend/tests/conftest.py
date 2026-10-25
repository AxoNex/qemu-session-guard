"""pytest 公共 fixtures。

FakeQMPProcess 模拟一个 QEMU 进程的 QMP 端：监听 127.0.0.1:0，完成
greeting / qmp_capabilities 握手，并按脚本响应 query-status / stop /
cont / system_powerdown / quit。这让 spawn 路径可以在没有真实 QEMU 的
环境下被完整测试（包括 -qmp tcp:...,server=on,wait=off 的基线参数解析）。
"""
from __future__ import annotations

import asyncio
import json
import os
import stat
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from qemu_session_guard.audit import AuditLog  # noqa: E402
from qemu_session_guard.config import Config  # noqa: E402
from qemu_session_guard.models import Quota, ToolAction  # noqa: E402
from qemu_session_guard.permission import PermissionEngine  # noqa: E402
from qemu_session_guard.qmp_broker import QmpBroker  # noqa: E402
from qemu_session_guard.session_guard import SessionGuard  # noqa: E402
from qemu_session_guard.store import Store  # noqa: E402
from qemu_session_guard.tools import ModelTools  # noqa: E402

# 每个测试函数一个子事件循环策略
pytest_plugins = ()


class FakeQMPProcess:
    """模拟 QEMU 的 QMP 服务端（asyncio TCP server）。"""

    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.server: asyncio.base_events.Server | None = None
        self.running = True  # 模拟 guest 运行状态
        self.received: list[str] = []
        self._writers: set[asyncio.StreamWriter] = set()

    async def start(self) -> None:
        self.server = await asyncio.start_server(self._handle, self.host, self.port)

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self._writers.add(writer)
        writer.write(b'{"QMP": {"version": {"qemu": {"major": 9, "minor": 0, "micro": 0}, "package": "fake"}, "capabilities": []}}\r\n')
        await writer.drain()
        try:
            while True:
                line = await reader.readline()
                if not line:
                    break
                try:
                    msg = json.loads(line.decode())
                except json.JSONDecodeError:
                    continue
                cmd = msg.get("execute")
                mid = msg.get("id")
                if cmd is None:
                    continue
                self.received.append(cmd)
                if cmd == "qmp_capabilities":
                    writer.write(json.dumps({"return": {}, "id": mid}).encode() + b"\r\n")
                elif cmd == "query-status":
                    status = "running" if self.running else "paused"
                    writer.write(json.dumps({"return": {"running": self.running, "singlestep": False, "status": status}, "id": mid}).encode() + b"\r\n")
                elif cmd == "stop":
                    self.running = False
                    writer.write(json.dumps({"return": {}, "id": mid}).encode() + b"\r\n")
                    await writer.drain()
                    writer.write(b'{"event": "STOP", "timestamp": {"seconds": 0, "microseconds": 0}}\r\n')
                elif cmd == "cont":
                    self.running = True
                    writer.write(json.dumps({"return": {}, "id": mid}).encode() + b"\r\n")
                    await writer.drain()
                    writer.write(b'{"event": "RESUME", "timestamp": {"seconds": 0, "microseconds": 0}}\r\n')
                elif cmd == "system_powerdown":
                    writer.write(json.dumps({"return": {}, "id": mid}).encode() + b"\r\n")
                elif cmd == "quit":
                    writer.write(json.dumps({"return": {}, "id": mid}).encode() + b"\r\n")
                    await writer.drain()
                    break
                else:
                    writer.write(json.dumps({"error": {"class": "CommandNotFound", "desc": cmd}, "id": mid}).encode() + b"\r\n")
                await writer.drain()
        except (ConnectionResetError, asyncio.IncompleteReadError):
            pass
        finally:
            self._writers.discard(writer)
            try:
                writer.close()
            except Exception:  # noqa: BLE001
                pass

    async def stop(self) -> None:
        if self.server:
            self.server.close()
            # 先断开所有活动连接：asyncio.Server.wait_closed() 在有活动连接
            # 时不会返回，必须先 close() 各 writer 再等待。
            writers = list(self._writers)
            for w in writers:
                try:
                    w.close()
                except Exception:  # noqa: BLE001
                    pass
            if writers:
                await asyncio.gather(
                    *(w.wait_closed() for w in writers),
                    return_exceptions=True,
                )
            await self.server.wait_closed()


@pytest.fixture
def anyio_backend():  # 兼容 pytest-anyio（若安装）
    return "asyncio"


@pytest.fixture
def cfg(tmp_path) -> Config:
    c = Config(data_dir=tmp_path / "data", prefer_unix_qmp=False)
    (c.data_dir / "qmp").mkdir(parents=True, exist_ok=True)
    return c


@pytest.fixture
def store(cfg) -> Store:
    s = Store(cfg.data_dir / "test.db")
    yield s
    s.close()


@pytest.fixture
def audit(store) -> AuditLog:
    return AuditLog(store)


@pytest.fixture
def sessions(store) -> SessionGuard:
    return SessionGuard(store)


@pytest.fixture
def broker(cfg, store, audit) -> QmpBroker:
    return QmpBroker(cfg, store, audit)


@pytest.fixture
def perms(store, audit, broker) -> PermissionEngine:
    return PermissionEngine(store, audit, broker.statuses)


@pytest.fixture
def tools(sessions, perms, broker) -> ModelTools:
    return ModelTools(sessions, perms, broker, approval_timeout=1.0)


@pytest.fixture
def fake_qemu_binary(tmp_path) -> str:
    """生成一个假的 qemu-system-x86_64 可执行文件（用于注册校验之外的路径）。"""
    p = tmp_path / "qemu-system-x86_64.exe"
    p.write_text("@echo off\r\necho QEMU emulator version 9.0.0 (fake)\r\n", encoding="utf-8")
    if os.name != "nt":
        p.chmod(p.stat().st_mode | stat.S_IEXEC)
    return str(p)


DEFAULT_QUOTA = Quota(max_running_vms=2, max_vcpus_per_vm=4, max_mem_mb_per_vm=4096)
