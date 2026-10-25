"""QMP 客户端封装。

后端选择（ADR-0006）：默认使用内置极简 asyncio 实现 `_MiniQMP`（完成
capabilities 协商、命令执行、事件监听）；设置环境变量
`QSG_QMP_BACKEND=official` 可改用 QEMU 官方 `qemu.qmp` 库。
默认内置实现的原因：qemu.qmp 0.0.6 在 Python 3.14 上协商阶段存在
兼容性问题（响应已到达但 `_recv` 挂起），且内置实现协议面足够小、
完全可审计。两种后端暴露相同接口，上层不感知差异。

内置实现与 qemu.qmp 一样只做一件事：把 JSON QMP 协议跑在 stream 上——
它不构成模型直连通道，socket 地址由插件独占管理（不变量 4）。
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
from collections.abc import Callable, Coroutine
from typing import Any

log = logging.getLogger(__name__)

try:  # pragma: no cover - 取决于环境
    from qemu.qmp import QMPClient as _OfficialQMPClient  # type: ignore

    _HAVE_QEMU_QMP = True
except Exception:  # noqa: BLE001
    _OfficialQMPClient = None
    _HAVE_QEMU_QMP = False


def use_official_lib() -> bool:
    """是否使用官方 qemu.qmp 后端（默认否，见 ADR-0006）。"""
    return _HAVE_QEMU_QMP and os.environ.get("QSG_QMP_BACKEND", "mini").lower() == "official"


EventHandler = Callable[[dict], Coroutine[Any, Any, None]]


class QMPError(Exception):
    pass


class _MiniQMP:
    """极简 QMP 协议客户端（asyncio streams）。

    握手：读取 greeting → 发送 qmp_capabilities → 等待返回。
    之后每条命令分配递增 id，后台 reader 按 id 分发响应；QMP 事件
    （无 id 的 {"event": ...}）交给事件回调。
    """

    def __init__(self) -> None:
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._pending: dict[int, asyncio.Future] = {}
        self._next_id = 1
        self._reader_task: asyncio.Task | None = None
        self._event_handler: EventHandler | None = None
        self.connected = False

    def set_event_handler(self, cb: EventHandler | None) -> None:
        self._event_handler = cb

    async def connect(self, address: tuple[str, int] | str, timeout: float = 10.0) -> None:
        if isinstance(address, tuple):
            host, port = address
            conn = asyncio.open_connection(host, port)
        else:
            conn = asyncio.open_unix_connection(address)
        self._reader, self._writer = await asyncio.wait_for(conn, timeout=timeout)
        greeting = await self._read_json(timeout)
        if "QMP" not in greeting:
            raise QMPError(f"非预期的 QMP greeting: {greeting!r}")
        await self._execute("qmp_capabilities", negotiate=True)
        self.connected = True
        self._reader_task = asyncio.create_task(self._reader_loop())

    async def _read_json(self, timeout: float = 10.0) -> dict:
        assert self._reader is not None
        line = await asyncio.wait_for(self._reader.readline(), timeout=timeout)
        if not line:
            raise QMPError("QMP 连接被对端关闭")
        return json.loads(line.decode("utf-8", errors="replace"))

    async def _reader_loop(self) -> None:
        try:
            while True:
                msg = await self._read_json(timeout=3600)
                if "event" in msg:
                    if self._event_handler:
                        try:
                            await self._event_handler(msg)
                        except Exception:  # noqa: BLE001
                            log.exception("QMP 事件回调失败")
                    continue
                msg_id = msg.get("id")
                fut = self._pending.pop(msg_id, None)
                if fut and not fut.done():
                    if "error" in msg:
                        fut.set_exception(QMPError(str(msg["error"])))
                    else:
                        fut.set_result(msg.get("return"))
        except (QMPError, asyncio.IncompleteReadError, ConnectionResetError, OSError) as exc:
            log.info("QMP reader 结束: %s", exc)
        except asyncio.CancelledError:
            pass
        except Exception:  # noqa: BLE001 - 任何异常都必须终止循环并唤醒等待者
            log.exception("QMP reader 意外失败")
        finally:
            self.connected = False
            for fut in self._pending.values():
                if not fut.done():
                    fut.set_exception(QMPError("QMP 连接已断开"))
            self._pending.clear()

    async def _execute(self, cmd: str, negotiate: bool = False, **kwargs: Any) -> Any:
        assert self._writer is not None
        msg_id = self._next_id
        self._next_id += 1
        fut: asyncio.Future = asyncio.get_running_loop().create_future()
        self._pending[msg_id] = fut
        payload: dict[str, Any] = {"execute": cmd, "id": msg_id}
        if kwargs:
            payload["arguments"] = kwargs
        self._writer.write(json.dumps(payload).encode() + b"\r\n")
        await self._writer.drain()
        if negotiate:
            # 协商阶段 reader loop 尚未启动，直接同步等待响应行
            while True:
                resp = await self._read_json(timeout=10)
                if resp.get("id") == msg_id:
                    self._pending.pop(msg_id, None)
                    if "error" in resp:
                        raise QMPError(str(resp["error"]))
                    return resp.get("return")
                # 握手期间可能夹带事件，忽略
        return await fut

    async def execute(self, cmd: str, **kwargs: Any) -> Any:
        if not self.connected:
            raise QMPError("QMP 未连接")
        return await self._execute(cmd, **kwargs)

    async def disconnect(self) -> None:
        self.connected = False
        task = self._reader_task
        self._reader_task = None
        if task:
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
        if self._writer:
            try:
                self._writer.close()
                await asyncio.wait_for(self._writer.wait_closed(), timeout=2)
            except Exception:  # noqa: BLE001
                pass


class QmpSession:
    """对一个 VM 的 QMP 连接。address: ('tcp', host, port) 或 ('unix', path)。"""

    def __init__(self, address: tuple[str, Any], event_handler: EventHandler | None = None):
        self.address = address
        self._event_handler = event_handler
        self._backend: Any = None
        self._listener_task: asyncio.Task | None = None
        self.connected = False

    async def connect(self, timeout: float = 10.0) -> None:
        kind = self.address[0]
        if use_official_lib():
            client = _OfficialQMPClient()
            if kind == "tcp":
                await asyncio.wait_for(
                    client.connect((self.address[1], self.address[2])), timeout
                )
            else:
                await asyncio.wait_for(client.connect(self.address[1]), timeout)
            self._backend = client
            if self._event_handler:
                self._listener_task = asyncio.create_task(self._official_events())
        else:
            mini = _MiniQMP()
            if self._event_handler:
                mini.set_event_handler(self._event_handler)
            if kind == "tcp":
                await mini.connect((self.address[1], self.address[2]), timeout=timeout)
            else:
                await mini.connect(self.address[1], timeout=timeout)
            self._backend = mini
        self.connected = True

    async def _official_events(self) -> None:  # pragma: no cover - 依赖官方库
        try:
            async for event in self._backend.events:
                if self._event_handler:
                    await self._event_handler(event)
        except asyncio.CancelledError:
            pass
        except Exception as exc:  # noqa: BLE001
            log.info("QMP 事件流结束: %s", exc)
        finally:
            self.connected = False

    async def execute(self, cmd: str, **kwargs: Any) -> Any:
        backend = self._backend
        if isinstance(backend, _MiniQMP):
            if not backend.connected:
                self.connected = False
                raise QMPError("QMP 未连接")
            return await backend.execute(cmd, **kwargs)
        if kwargs:
            return await backend.execute(cmd, kwargs)
        return await backend.execute(cmd)

    async def disconnect(self) -> None:
        if self._listener_task:
            task = self._listener_task
            self._listener_task = None
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
        try:
            if self._backend is not None:
                await self._backend.disconnect()
        except Exception:  # noqa: BLE001
            pass
        self.connected = False
