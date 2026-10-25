"""MSYS2 发现层测试（不变量 8）：多前缀支持、优先级、无硬编码。"""
from __future__ import annotations

import pytest

from qemu_session_guard.models import QemuVariant
from qemu_session_guard.qemu_discovery import _scan_dir, _variant_of, discover


def _mk_qemu(bin_dir, name="qemu-system-x86_64.exe"):
    bin_dir.mkdir(parents=True, exist_ok=True)
    exe = bin_dir / name
    exe.write_bytes(b"MZ fake")
    return exe


class TestDiscovery:
    @pytest.mark.asyncio
    async def test_ucrt64_preferred_over_mingw64(self, tmp_path):
        root = tmp_path / "msys64"
        ucrt = _mk_qemu(root / "ucrt64" / "bin")
        mingw = _mk_qemu(root / "mingw64" / "bin")
        found = await discover(str(root), verify=False)
        paths = [str(b.path) for b in found]
        # 两者都发现，UCRT64 在前（优先级）
        assert paths.index(str(ucrt)) < paths.index(str(mingw))
        variants = {str(b.path): b.variant for b in found}
        assert variants[str(ucrt)] is QemuVariant.UCRT64
        assert variants[str(mingw)] is QemuVariant.MINGW64

    @pytest.mark.asyncio
    async def test_qemu_binary_dir_highest_priority(self, tmp_path):
        root = tmp_path / "msys64"
        _mk_qemu(root / "ucrt64" / "bin")
        custom = tmp_path / "custom"
        cexe = _mk_qemu(custom, "qemu-system-aarch64.exe")
        found = await discover(str(root), qemu_binary_dir=str(custom), verify=False)
        assert str(found[0].path) == str(cexe)
        assert found[0].variant is QemuVariant.OTHER

    @pytest.mark.asyncio
    async def test_no_msys2_returns_empty_or_path_only(self, tmp_path):
        found = await discover(str(tmp_path / "nonexistent"), verify=False)
        # 不依赖硬编码路径：不存在的 MSYS2 根目录不报错
        assert all(b.path.is_file() for b in found)

    def test_scan_dir_ignores_non_qemu(self, tmp_path):
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        (bin_dir / "qemu-img.exe").write_bytes(b"MZ")
        (bin_dir / "notepad.exe").write_bytes(b"MZ")
        _mk_qemu(bin_dir)
        found = _scan_dir(bin_dir)
        assert len(found) == 1
        assert found[0][1] == "x86_64"

    def test_variant_of(self):
        from pathlib import Path

        assert _variant_of(Path(r"C:\msys64\ucrt64\bin\qemu-system-x86_64.exe")) is QemuVariant.UCRT64
        assert _variant_of(Path(r"C:\msys64\mingw64\bin\qemu-system-x86_64.exe")) is QemuVariant.MINGW64
        assert _variant_of(Path(r"D:\qemu\qemu-system-x86_64.exe")) is QemuVariant.OTHER
