"""qemu-session-guard — 会话级 QEMU 虚拟机安全管控插件后端。

模型（LLM Agent）只能通过本包暴露的结构化 tool 间接管理 QEMU 虚拟机；
所有 QEMU 进程由本包以受控参数 spawn，QMP socket 由本包独占管理。
"""

__version__ = "0.1.0"

APP_ID = "qemu-session-guard"
