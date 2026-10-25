"""核心数据模型。

所有需要持久化 / 跨层传递的结构集中在此。会话权限快照（SessionPerms）
是不可变值对象：任何权限修改都生成新快照，旧快照继续被进行中的操作
引用（安全不变量 3）。
"""
from __future__ import annotations

import time
import uuid
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, field_validator

# ---------------------------------------------------------------------------
# 枚举
# ---------------------------------------------------------------------------


class VMStatus(str, Enum):
    """插件内部 VM 状态。"""

    STOPPED = "stopped"
    STARTING = "starting"  # 已 spawn，等待 QMP 握手完成
    RUNNING = "running"
    PAUSED = "paused"
    SHUTDOWN = "shutdown"  # QEMU 报告 shutdown（guest 关机或 quit）
    UNKNOWN = "unknown"  # QMP 连接异常断开，进程状态不可信（不变量 7）


class ToolAction(str, Enum):
    """模型侧 tool 的动作集合。"""

    VM_LIST = "vm_list"
    VM_STATUS = "vm_status"
    VM_START = "vm_start"
    VM_SHUTDOWN = "vm_shutdown"
    VM_STOP = "vm_stop"
    VM_RESUME = "vm_resume"
    VM_FORCE_OFF = "vm_force_off"
    VM_CONSOLE_READ = "vm_console_read"
    VM_CONSOLE_WRITE = "vm_console_write"


class PermLevel(str, Enum):
    """操作权限粒度。"""

    READ = "read"
    POWER = "power"
    CONSOLE = "console"
    CONFIG = "config"


class AuditResult(str, Enum):
    ALLOWED = "allowed"
    DENIED = "denied"
    PENDING_APPROVAL = "pending_approval"
    ERROR = "error"


class ApprovalStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"


class QemuVariant(str, Enum):
    UCRT64 = "ucrt64"
    MINGW64 = "mingw64"
    OTHER = "other"


# 动作 -> 所需权限级别（session 级权限矩阵的判定依据，不变量 2）
ACTION_PERM: dict[ToolAction, PermLevel] = {
    ToolAction.VM_LIST: PermLevel.READ,
    ToolAction.VM_STATUS: PermLevel.READ,
    ToolAction.VM_START: PermLevel.POWER,
    ToolAction.VM_SHUTDOWN: PermLevel.POWER,
    ToolAction.VM_STOP: PermLevel.POWER,
    ToolAction.VM_RESUME: PermLevel.POWER,
    ToolAction.VM_FORCE_OFF: PermLevel.POWER,
    ToolAction.VM_CONSOLE_READ: PermLevel.CONSOLE,
    ToolAction.VM_CONSOLE_WRITE: PermLevel.CONSOLE,
}


# ---------------------------------------------------------------------------
# 值对象
# ---------------------------------------------------------------------------


def new_id() -> str:
    return uuid.uuid4().hex


def now() -> float:
    return time.time()


class Volume(BaseModel):
    """预注册的可挂载卷（模型不得任意指定宿主机磁盘路径，见 §2.2 禁用项）。"""

    model_config = ConfigDict(extra="forbid")

    id: str
    path: str  # 宿主机绝对路径，仅管理员在 WebUI 中登记
    read_only: bool = True
    description: str = ""


class VMResources(BaseModel):
    model_config = ConfigDict(extra="forbid")

    vcpus: int = Field(ge=1, le=64, default=2)
    mem_mb: int = Field(ge=128, le=262144, default=2048)


class VMRegistration(BaseModel):
    """已注册 VM。disk_volume_ids 只能引用预注册 Volume。"""

    model_config = ConfigDict(extra="forbid")

    id: str
    arch: str = "x86_64"
    machine: str = ""  # 留空 = 按 arch 选默认（q35 / virt），见 QmpBroker.build_command
    qemu_binary: str = ""  # 注册时由发现层校验并记录版本
    qemu_version: str = ""
    qemu_variant: QemuVariant = QemuVariant.OTHER
    resources: VMResources = Field(default_factory=VMResources)
    disk_volume_ids: list[str] = Field(default_factory=list)
    boot_from_cdrom: bool = False
    extra_args: list[str] = Field(default_factory=list)  # 仅管理员，且过 forbidden-list 校验
    created_at: float = Field(default_factory=now)


class Quota(BaseModel):
    model_config = ConfigDict(extra="forbid")

    max_running_vms: int = Field(ge=0, le=64, default=2)
    max_vcpus_per_vm: int = Field(ge=1, le=64, default=4)
    max_mem_mb_per_vm: int = Field(ge=128, le=262144, default=4096)


class SessionPerms(BaseModel):
    """会话权限快照（不可变值对象）。

    权限在会话创建时固化；中途修改生成新快照，仅对**后续** tool 调用生效，
    进行中的操作继续引用旧快照（安全不变量 3）。
    """

    model_config = ConfigDict(extra="forbid")

    granted_vm_ids: list[str] = Field(default_factory=list)
    # vm_id -> 允许的权限级别集合；不在 granted_vm_ids 中的 vm 一律视为不存在
    permission_map: dict[str, list[PermLevel]] = Field(default_factory=dict)
    quota: Quota = Field(default_factory=Quota)
    # 需要人工审批的动作集合
    approval_actions: list[ToolAction] = Field(
        default_factory=lambda: [ToolAction.VM_FORCE_OFF]
    )

    def is_visible(self, vm_id: str) -> bool:
        return vm_id in set(self.granted_vm_ids)

    def allows(self, vm_id: str, action: ToolAction) -> bool:
        need = ACTION_PERM[action]
        granted = set(self.permission_map.get(vm_id, []))
        return self.is_visible(vm_id) and need in granted

    def needs_approval(self, action: ToolAction) -> bool:
        return action in set(self.approval_actions)

    # 输入规整 -------------------------------------------------------------

    @field_validator("granted_vm_ids", mode="before")
    @classmethod
    def _dedup(cls, v):
        if isinstance(v, (list, tuple, set, frozenset)):
            return list(dict.fromkeys(v))
        return v


class Session(BaseModel):
    """一个模型会话。perms 为当前生效快照；旧快照由进行中的操作自行持有。"""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(default_factory=new_id)
    label: str = ""  # 绑定的 Agent/模型标识（管理员在 WebUI 填写）
    owner: str = "admin"  # 用户/角色标识
    perms: SessionPerms = Field(default_factory=SessionPerms)
    created_at: float = Field(default_factory=now)
    expires_at: float | None = None
    last_activity_at: float = Field(default_factory=now)
    active: bool = True
    # 单调递增的快照代次，权限变更时 +1（WebUI 展示“变更仅对新调用生效”）
    perms_generation: int = 1

    def expired(self) -> bool:
        return self.expires_at is not None and now() >= self.expires_at


class Approval(BaseModel):
    """一次高危操作审批请求。绑定到具体会话 + 具体调用，一次性、可过期（不变量 6）。"""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(default_factory=new_id)
    session_id: str
    session_generation: int  # 提出请求时的权限快照代次
    action: ToolAction
    vm_id: str
    params: dict = Field(default_factory=dict)  # 脱敏后的调用参数
    status: ApprovalStatus = ApprovalStatus.PENDING
    created_at: float = Field(default_factory=now)
    expires_at: float = Field(default_factory=lambda: now() + 300)  # 5 分钟过期
    decided_by: str | None = None
    decided_at: float | None = None

    def expired(self) -> bool:
        return now() >= self.expires_at


class AuditEntry(BaseModel):
    """审计日志：同时记录“模型意图”与“实际执行”两个层面（不变量 7）。"""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(default_factory=new_id)
    ts: float = Field(default_factory=now)
    session_id: str = ""
    session_label: str = ""
    action: str = ""  # tool 名或 WebUI 操作名
    vm_id: str | None = None
    model_params: dict = Field(default_factory=dict)  # 模型侧结构化参数（脱敏）
    executed: list[str] = Field(default_factory=list)  # 实际 QMP 命令 / QEMU 启动参数
    result: AuditResult = AuditResult.ALLOWED
    deny_reason: str = ""  # 拒绝原因：权限缺失 / 配额不足 / 参数违规 / ...
    approval_id: str | None = None
    error: str = ""
    actor: str = "model"  # model | webui
