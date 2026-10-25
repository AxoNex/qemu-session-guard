"""服务入口：python -m qemu_session_guard.server"""
from __future__ import annotations

import logging

import uvicorn

from .app import create_app
from .config import load_config


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    )
    cfg = load_config()
    app = create_app(cfg)
    uvicorn.run(app, host=cfg.host, port=cfg.port, log_level="info")


if __name__ == "__main__":
    main()
