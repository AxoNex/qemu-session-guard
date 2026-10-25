"""错误类型与脱敏策略（不变量 2）。

对模型侧返回的错误分两类：
- DeniedError：权限 / 可见性 / 配额 / 参数违规。对模型统一表现为
  「VM 不存在或无权限」或通用配额/参数提示，绝不泄露被隐藏 VM 的存在性。
- 其他内部错误：对模型只返回通用错误码 + 详情进审计日志。
"""
from __future__ import annotations


class GuardError(Exception):
    """插件内部错误基类。`public` 为可展示给模型的脱敏消息。"""

    def __init__(self, public: str, detail: str = ""):
        super().__init__(detail or public)
        self.public = public
        self.detail = detail or public


class VMNotVisibleError(GuardError):
    """VM 不在会话可见列表中（无论它是否真实存在，报文完全一致）。

    注意：消息文案必须与「VM 确实不存在」时完全相同，防止存在性探测。
    """

    def __init__(self, detail: str = ""):
        super().__init__("VM 不存在或无权限", detail or "vm not visible to session")


class PermissionDeniedError(GuardError):
    def __init__(self, detail: str = ""):
        super().__init__("VM 不存在或无权限", detail or "permission denied")


class QuotaExceededError(GuardError):
    def __init__(self, detail: str = ""):
        super().__init__("超出会话资源配额", detail)


class ArgumentViolationError(GuardError):
    def __init__(self, detail: str = ""):
        super().__init__("参数不被允许", detail)


class ConflictError(GuardError):
    def __init__(self, public: str, detail: str = ""):
        super().__init__(public, detail)


class NotFoundError(GuardError):
    def __init__(self, public: str, detail: str = ""):
        super().__init__(public, detail)


class RateLimitedError(GuardError):
    def __init__(self, detail: str = ""):
        super().__init__("请求过于频繁", detail or "rate limited")
