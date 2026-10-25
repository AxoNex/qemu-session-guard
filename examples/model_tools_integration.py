"""把 qemu-session-guard 的 tools 注册给 LLM 宿主框架的最小示例。

运行前提：后端已启动（默认 127.0.0.1:8787），并已创建好一个会话
（拿到 session_id）。本示例演示宿主框架侧如何把 tool 定义暴露给模型，
以及把模型的 tool_call 转发给后端。

真实接入时：
  - tools 的 JSON Schema 来自 GET /api/tools/schemas（或后端 tools.tool_schemas()）；
  - 模型只产生 tool_call 名称 + 参数 JSON；
  - 宿主把它 POST 到 /api/sessions/{session_id}/tool，拿回 JSON 字符串结果喂回模型；
  - 绝不要让模型拼接 shell / QEMU 命令行。
"""
from __future__ import annotations

import json
import urllib.request

BASE = "http://127.0.0.1:8787"
SESSION_ID = "替换为你的 session_id"  # 创建会话时返回的 id


def _post(path: str, payload: dict) -> dict:
    req = urllib.request.Request(
        BASE + path,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:  # 拒绝 / 错误：detail 已是脱敏消息
        body = json.loads(e.read().decode("utf-8"))
        return {"error": body.get("detail", f"HTTP {e.code}")}


def call_tool(tool: str, params: dict) -> str:
    """把一次模型 tool_call 转发给后端，返回喂回模型的 JSON 字符串。"""
    resp = _post(f"/api/sessions/{SESSION_ID}/tool", {"tool": tool, "params": params})
    return json.dumps(resp, ensure_ascii=False)


if __name__ == "__main__":
    # 模拟模型依次发起的 tool_call（宿主框架实际从模型输出里解析得到）
    print(call_tool("vm_list", {}))                       # 只列本会话可见 VM
    print(call_tool("vm_status", {"vm_id": "alpine"}))
    print(call_tool("vm_start", {"vm_id": "alpine"}))
    # 破坏性操作：默认需要人工审批，结果会是「操作未获批准」或挂起等待
    print(call_tool("vm_force_off", {"vm_id": "alpine"}))
    # 注入尝试：以下会被拒绝并审计
    print(call_tool("vm_start", {"vm_id": "alpine", "extra_args": ["-kernel", "/x"]}))
