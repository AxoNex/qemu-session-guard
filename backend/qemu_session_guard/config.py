"""插件配置：环境变量 + YAML。

- QSG_CONFIG          YAML 配置文件路径（可选）
- QSG_DATA_DIR        数据目录（SQLite、QMP socket、快照等），默认 <cwd>/data
- QEMU_BINARY_DIR     直接指定 QEMU bin 目录（发现层最高优先级，不变量 8）
- MSYS2_ROOT          MSYS2 安装根目录，默认 C:\\msys64
- QSG_HOST / QSG_PORT WebUI 监听地址，默认 127.0.0.1:8787
- QSG_TOKEN_SECRET    审批/管理接口的签名密钥（不入库明文；未设置时随机生成
                      并仅存在于进程内存，重启后旧审批全部失效——这是特性）

YAML 文件可覆盖一切同名小写键，环境变量优先于 YAML。
"""
from __future__ import annotations

import os
import secrets
from pathlib import Path

import yaml
from pydantic import BaseModel


class Config(BaseModel):
    data_dir: Path = Path("data")
    msys2_root: str = r"C:\msys64"
    qemu_binary_dir: str = ""  # 对应 QEMU_BINARY_DIR
    host: str = "127.0.0.1"
    port: int = 8787
    token_secret: str = ""
    # 在 Windows 上 QMP 只能用 TCP loopback；类 Unix 系统默认 unix socket
    prefer_unix_qmp: bool = True
    # 会话过期（小时），0 = 永不过期
    session_ttl_hours: float = 0
    # 审批等待超时（秒）
    approval_timeout_sec: int = 300


def load_config() -> Config:
    raw: dict = {}
    cfg_path = os.environ.get("QSG_CONFIG", "")
    if cfg_path and Path(cfg_path).is_file():
        with open(cfg_path, "r", encoding="utf-8") as fh:
            raw = yaml.safe_load(fh) or {}

    env_map = {
        "data_dir": "QSG_DATA_DIR",
        "msys2_root": "MSYS2_ROOT",
        "qemu_binary_dir": "QEMU_BINARY_DIR",
        "host": "QSG_HOST",
        "port": "QSG_PORT",
        "token_secret": "QSG_TOKEN_SECRET",
        "session_ttl_hours": "QSG_SESSION_TTL_HOURS",
    }
    for key, env in env_map.items():
        val = os.environ.get(env)
        if val not in (None, ""):
            raw[key] = val

    if "port" in raw:
        raw["port"] = int(raw["port"])
    if "session_ttl_hours" in raw:
        raw["session_ttl_hours"] = float(raw["session_ttl_hours"])

    cfg = Config(**raw)
    if not cfg.token_secret:
        # 仅存在于进程内存的随机密钥：重启后所有签名上下文失效（不持久化明文）
        cfg.token_secret = secrets.token_hex(32)
    cfg.data_dir = Path(cfg.data_dir).resolve()
    (cfg.data_dir / "qmp").mkdir(parents=True, exist_ok=True)
    return cfg
