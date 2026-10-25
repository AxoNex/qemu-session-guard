"""MSYS2 / QEMU 环境适配层（不变量 8）。

发现策略（优先级从高到低）：
1. 环境变量 / 配置 `QEMU_BINARY_DIR`；
2. `%MSYS2_ROOT%\\ucrt64\\bin`（UCRT64，推荐）；
3. `%MSYS2_ROOT%\\mingw64\\bin`（MINGW64）；
4. 从 `PATH` 查找 `qemu-system-*`。

发现后对每个候选执行 `qemu-system-* --version` 校验可执行性并记录版本。
支持 UCRT64 与 MINGW64 两种前缀，不硬编码单一路径。
"""
from __future__ import annotations

import asyncio
import logging
import os
import re
import shutil
from pathlib import Path

from .models import QemuVariant

log = logging.getLogger(__name__)

# 支持的 QEMU target 架构后缀
ARCH_SUFFIXES = [
    "x86_64",
    "i386",
    "aarch64",
    "arm",
    "riscv64",
    "riscv32",
    "ppc64",
    "ppc",
    "s390x",
    "mips64",
    "mips",
    "sparc64",
    "alpha",
    "avr",
    "hppa",
    "loongarch64",
    "m68k",
    "microblaze",
    "microblazeel",
    "mipsel",
    "mips64el",
    "nios2",
    "or1k",
    "ppc64le",
    "rx",
    "sh4",
    "sh4eb",
    "sparc",
    "tricore",
    "xtensa",
    "xtensaeb",
]

_VERSION_RE = re.compile(r"QEMU emulator version (\S+)", re.IGNORECASE)


class QemuBinary:
    """一个已验证的 QEMU 可执行文件。"""

    def __init__(self, path: Path, arch: str, version: str, variant: QemuVariant):
        self.path = path
        self.arch = arch
        self.version = version
        self.variant = variant

    def __repr__(self) -> str:  # pragma: no cover - 调试辅助
        return f"<QemuBinary {self.path.name} {self.version} {self.variant.value}>"

    def as_dict(self) -> dict:
        return {
            "path": str(self.path),
            "arch": self.arch,
            "version": self.version,
            "variant": self.variant.value,
        }


def _variant_of(path: Path) -> QemuVariant:
    parts = {p.lower() for p in path.parts}
    if "ucrt64" in parts:
        return QemuVariant.UCRT64
    if "mingw64" in parts:
        return QemuVariant.MINGW64
    return QemuVariant.OTHER


def _candidate_dirs(msys2_root: str, qemu_binary_dir: str = "") -> list[Path]:
    dirs: list[Path] = []
    if qemu_binary_dir:
        dirs.append(Path(qemu_binary_dir))
    root = Path(msys2_root)
    dirs.append(root / "ucrt64" / "bin")
    dirs.append(root / "mingw64" / "bin")
    return dirs


def _scan_dir(bin_dir: Path) -> list[tuple[Path, str]]:
    """在目录中找 qemu-system-<arch>(.exe)。"""
    found: list[tuple[Path, str]] = []
    if not bin_dir.is_dir():
        return found
    for entry in bin_dir.iterdir():
        name = entry.name.lower()
        if not name.startswith("qemu-system-"):
            continue
        stem = name[len("qemu-system-"):]
        if stem.endswith(".exe"):
            stem = stem[: -len(".exe")]
        if stem in ARCH_SUFFIXES and entry.is_file():
            found.append((entry, stem))
    return found


def _scan_path() -> list[tuple[Path, str]]:
    found: list[tuple[Path, str]] = []
    for arch in ARCH_SUFFIXES:
        exe = shutil.which(f"qemu-system-{arch}")
        if exe:
            found.append((Path(exe), arch))
    return found


async def probe_version(binary: Path) -> str:
    """执行 `<binary> --version` 并解析版本号；失败抛异常。"""
    proc = await asyncio.create_subprocess_exec(
        str(binary),
        "--version",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=15)
    except asyncio.TimeoutError:
        proc.kill()
        raise RuntimeError(f"{binary} --version 超时") from None
    if proc.returncode != 0:
        raise RuntimeError(f"{binary} --version 退出码 {proc.returncode}: {err[:200]!r}")
    m = _VERSION_RE.search(out.decode(errors="replace"))
    return m.group(1) if m else "unknown"


async def discover(
    msys2_root: str, qemu_binary_dir: str = "", verify: bool = True
) -> list[QemuBinary]:
    """发现所有可用的 QEMU binary；verify=False 时跳过版本探测（测试用）。"""
    candidates: list[tuple[Path, str]] = []
    seen: set[str] = set()

    for bin_dir in _candidate_dirs(msys2_root, qemu_binary_dir):
        for path, arch in _scan_dir(bin_dir):
            key = str(path).lower()
            if key not in seen:
                seen.add(key)
                candidates.append((path, arch))
    for path, arch in _scan_path():
        key = str(path).lower()
        if key not in seen:
            seen.add(key)
            candidates.append((path, arch))

    results: list[QemuBinary] = []
    for path, arch in candidates:
        version = "unknown"
        if verify:
            try:
                version = await probe_version(path)
            except Exception as exc:  # noqa: BLE001 - 损坏的候选直接跳过
                log.warning("跳过不可执行的 QEMU 候选 %s: %s", path, exc)
                continue
        results.append(QemuBinary(path, arch, version, _variant_of(path)))
    return results


def discover_sync(
    msys2_root: str, qemu_binary_dir: str = "", verify: bool = True
) -> list[QemuBinary]:
    """同步包装（供 WebUI 注册接口在请求线程内使用）。"""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None
    if loop and loop.is_running():
        # 已在事件循环内：由调用方使用 await discover(...)
        raise RuntimeError("请使用异步 discover()")
    return asyncio.run(discover(msys2_root, qemu_binary_dir, verify))


# ---------------------------------------------------------------------------
# 启动参数安全基线与禁止项（不变量 5）
# ---------------------------------------------------------------------------

#: 插件强制注入的基线参数。模型侧任何途径都无法移除或覆盖它们。
def baseline_args(qmp_spec: str) -> list[str]:
    """返回安全基线参数。qmp_spec 形如 'unix:/path/sock' 或 'tcp:127.0.0.1:4444,server=on,wait=off'。"""
    return [
        "-nodefaults",
        "-no-user-config",
        "-nodefconfig",
        "-qmp",
        qmp_spec,
        "-sandbox",
        "on",
    ]


#: 即使管理员在注册 VM 时提供 extra_args，也一律拒绝的选项前缀。
FORBIDDEN_ARG_PREFIXES: tuple[str, ...] = (
    "-kernel",
    "-initrd",
    "-append",
    "-pidfile",
    "-fsdev",
    "-virtfs",
    "-chardev",
    "-qmp",  # QMP 由插件独占管理
    "-monitor",
    "-serial",  # 控制台 socket 由插件 console 服务管理，模型不得自建
    "-sandbox",
    "-nodefaults",
    "-no-user-config",
    "-nodefconfig",
    "-S",  # 启动即暂停由 spawn 逻辑统一管理
    "-daemonize",
    "-incoming",
)

#: 以 key= 形式出现的危险 -drive / -netdev 子项。key 前面必须是参数值起始
#: （选项名后的第一个字符）、逗号或空白——例如 "-drive file=...,if=virtio"
#: 与 "-netdev user,id=n0,hostfwd=tcp::2222-:22" 均命中。
FORBIDDEN_SUBARG_RE = re.compile(
    r"(?:^|[,\s])(?:hostfwd|guestfwd|file)=", re.IGNORECASE
)


def validate_extra_args(args: list[str]) -> list[str]:
    """校验管理员提供的额外 QEMU 参数。返回违规项列表（空 = 通过）。

    -drive 与 -netdev 不是整体禁止（管理员可能需要配置 CD-ROM 等），但其值
    不得包含 file=/hostfwd= 等子项——磁盘文件必须走预注册 Volume，端口转发
    必须按会话预授权（本版本未开放网络转发，见 README 路线图）。
    """
    violations: list[str] = []
    for raw in args:
        low = raw.strip().lower()
        for prefix in FORBIDDEN_ARG_PREFIXES:
            if low == prefix.lower() or low.startswith(prefix.lower() + "=") or low.startswith(
                prefix.lower() + ":"
            ):
                violations.append(raw)
                break
        else:
            if FORBIDDEN_SUBARG_RE.search(raw):
                violations.append(raw)
    return violations
