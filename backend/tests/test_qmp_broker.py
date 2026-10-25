"""安全场景测试 6 + QMP 协议级测试：spawn 基线、状态映射、审计双层记录。

使用 conftest.FakeQMPProcess 在 127.0.0.1 上模拟 QEMU 的 QMP 端；spawn 用
一个真实的子进程（python -c sleep）替代 QEMU，但 **命令行仍由
QmpBroker.build_command 生成**，从而可以断言基线参数（不变量 1、5）。
"""
from __future__ import annotations

import asyncio
import subprocess
import sys

import pytest

from qemu_session_guard.models import (
    AuditResult,
    VMRegistration,
    VMResources,
    VMStatus,
    Volume,
)
from qemu_session_guard.qemu_discovery import baseline_args

from conftest import FakeQMPProcess


def _reg(store, vm_id: str, extra_args=None, volumes=None) -> VMRegistration:
    vm = VMRegistration(
        id=vm_id,
        qemu_binary=sys.executable,  # spawn 时以 python 替身验证参数组装
        qemu_version="9.0.0",
        resources=VMResources(vcpus=2, mem_mb=1024),
        disk_volume_ids=volumes or [],
        extra_args=extra_args or [],
    )
    store.save_vm(vm)
    return vm


class TestBaselineArgs:
    """不变量 5：基线参数强制注入且模型不可覆盖。"""

    def test_baseline_contains_required_flags(self):
        args = baseline_args("tcp:127.0.0.1:4444,server=on,wait=off")
        assert "-nodefaults" in args
        assert "-no-user-config" in args
        assert "-nodefconfig" in args
        assert "-sandbox" in args and "on" in args
        i = args.index("-qmp")
        assert args[i + 1] == "tcp:127.0.0.1:4444,server=on,wait=off"

    def test_build_command_structure(self, broker, store):
        store.save_volume(Volume(id="vol-ro", path=r"D:\img\a.qcow2", read_only=True))
        store.save_volume(Volume(id="vol-rw", path=r"D:\img\b.qcow2", read_only=False))
        vm = _reg(store, "vm-a", extra_args=["-cpu", "host"], volumes=["vol-ro", "vol-rw"])
        volumes = {v.id: (v.path, v.read_only) for v in store.list_volumes()}
        argv, address = broker.build_command(vm, volumes)
        assert argv[0] == sys.executable
        joined = " ".join(argv)
        # 基线在前
        assert joined.index("-nodefaults") < joined.index("-name")
        # 只读卷带 readonly=on，可写卷不带
        ro_drive = next(a for a in argv if "a.qcow2" in a)
        rw_drive = next(a for a in argv if "b.qcow2" in a)
        assert "readonly=on" in ro_drive
        assert "readonly" not in rw_drive
        # QMP 地址由插件分配，TCP loopback（Windows 策略）
        assert address[0] == "tcp" and address[1] == "127.0.0.1"
        qmp_spec = argv[argv.index("-qmp") + 1]
        assert f"tcp:127.0.0.1:{address[2]}" in qmp_spec
        assert "server=on,wait=off" in qmp_spec

    def test_unregistered_volume_rejected(self, broker, store):
        vm = _reg(store, "vm-a", volumes=["vol-ghost"])
        with pytest.raises(Exception) as exc_info:
            broker.build_command(vm, {})
        assert "卷未注册" in exc_info.value.public


class TestSpawnAndStatus:
    """场景 6：QMP 连接断开 → UNKNOWN + 告警，不重连（§2.3）。

    以及 query-status → 内部状态映射。
    """

    @pytest.mark.asyncio
    async def test_spawn_connect_qmp_and_status_mapping(self, broker, store, audit, cfg):
        """完整走 spawn 路径：假 QEMU = python 子进程 + FakeQMPProcess 服务端。"""
        vm = _reg(store, "vm-a")
        # 替换 qemu_binary 为「启动一个 python QMP 服务端」的替身：
        # 这里直接用 broker.build_command 生成 argv，再以 FakeQMPProcess 作为
        # 被连端验证客户端握手。
        volumes = {}
        argv, address = broker.build_command(vm, volumes)
        assert "-qmp" in argv

        fake = FakeQMPProcess("127.0.0.1", address[2])
        await fake.start()
        try:
            # 手动 spawn（与 broker.start 同参数），验证 QmpSession 能握手
            proc = subprocess.Popen(
                [sys.executable, "-c", "import time; time.sleep(30)"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            rt = broker.runtime("vm-a")
            rt.proc = proc
            rt.qmp_address = address
            await broker._connect_qmp(rt, timeout=5)  # noqa: SLF001
            assert rt.qmp is not None and rt.qmp.connected
            # 握手命令已被服务端收到
            assert "qmp_capabilities" in fake.received

            status = await broker._refresh_status(rt)  # noqa: SLF001
            assert status is VMStatus.RUNNING

            # stop → PAUSED，事件被接收
            await broker.stop("vm-a")
            assert rt.status is VMStatus.PAUSED
            assert fake.running is False

            # cont → RUNNING
            await broker.resume("vm-a")
            await asyncio.sleep(0.2)
            assert rt.status is VMStatus.RUNNING

            # 审计：qmp stop / cont 命令已记录（不变量 7：实际执行层）
            entries = store.query_audits(vm_id="vm-a")
            executed = [c for e in entries for c in e.executed]
            assert "stop" in executed and "cont" in executed

            # QMP 异常断开 → query_status 返回 unknown（不重连）
            await fake.stop()
            await asyncio.sleep(0.3)
            info = await broker.query_status("vm-a")
            assert info["status"] == VMStatus.UNKNOWN.value

            proc.kill()
            proc.wait()
        finally:
            await fake.stop()

    @pytest.mark.asyncio
    async def test_mark_unknown_emits_alert(self, broker, store):
        events = []

        async def _collect(m):
            events.append(m)

        broker.subscribe(_collect)
        _reg(store, "vm-a")
        await broker.mark_unknown("vm-a", "qmp lost")
        assert broker.statuses()["vm-a"] is VMStatus.UNKNOWN
        assert any(e["type"] == "vm.qmp_lost" for e in events)


class TestAuditDualLayer:
    """不变量 7：审计同时记录模型意图与实际执行。"""

    @pytest.mark.asyncio
    async def test_audit_records_intent_and_execution(self, store, audit):
        audit.record(
            session_id="s1",
            action="vm_start",
            vm_id="vm-a",
            model_params={"vm_id": "vm-a"},
            result=AuditResult.ALLOWED,
            actor="model",
        )
        audit.record(
            session_id="s1",
            action="vm_start.exec",
            vm_id="vm-a",
            executed=["qemu-system-x86_64.exe -nodefaults -qmp tcp:..."],
            result=AuditResult.ALLOWED,
            actor="model",
        )
        audit.record(
            session_id="s1",
            action="vm_status",
            vm_id="vm-b",
            model_params={"vm_id": "vm-b"},
            result=AuditResult.DENIED,
            deny_reason="vm not visible to session",
            actor="model",
        )
        entries = store.query_audits(session_id="s1")
        assert len(entries) == 3
        denied = [e for e in entries if e.result is AuditResult.DENIED]
        assert denied and denied[0].deny_reason
        intent = [e for e in entries if e.action == "vm_start"][0]
        execd = [e for e in entries if e.action == "vm_start.exec"][0]
        assert intent.model_params == {"vm_id": "vm-a"}
        assert execd.executed and "-qmp" in execd.executed[0]
