#!/usr/bin/env python3
"""范围闸的 Python 集成层：把 OPA/Rego 策略接进编排器。

## 为什么不直接在 Python 里 if

事故背景：比赛时为绕开自己的范围闸，把 `allowedHosts` / `deniedTools` 全清空了。
在 CTF 靶机上那是权宜，在真实渗透里等于拆掉授权边界。根子不在"清空"这个动作，
而在闸的口径散落在 Python 的 if 里——改起来太容易、也没法证明它现在拦得住什么。

策略挪到 `policy/scope.rego` 之后：默认拒绝、可单测（15 条断言）、可审计。
Python 这层只负责三件事：组装 input、调 OPA、把结论翻译成人话。

## 两条硬规矩

1. **fail-closed**：OPA 不存在、崩溃、超时、返回看不懂的东西——一律判拒绝。
   一个"闸坏了所以全放行"的实现，比没有闸更危险，因为它给人虚假的安全感。
2. **不抛异常**：`check()` 永远返回一个 Decision。调用方不需要 try/except，
   也就不可能"忘了处理异常导致动作漏过闸"。
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

POLICY_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "policy")
OPA_BIN = "opa"


class Decision(BaseModel):
    """一次越界判定的结果。"""

    model_config = ConfigDict(frozen=True, extra="allow")

    allow: bool = False
    rule: str = ""
    reason: str = ""
    policy_version: str = ""
    # 判定本身是否可信。False 表示 OPA 不可用或输出异常——此时 allow 恒为 False。
    trusted: bool = True

    def describe(self) -> str:
        if self.allow:
            return f"放行（{self.rule}）"
        return f"拒绝（{self.reason}）"


class Scope(BaseModel):
    """一次 engagement 的授权范围。"""

    model_config = ConfigDict(extra="forbid")

    cidrs: list[str] = Field(default_factory=list)
    hosts: list[str] = Field(default_factory=list)
    tools: list[str] = Field(default_factory=list)

    @classmethod
    def load(cls, path: str) -> "Scope":
        with open(path, encoding="utf-8") as fh:
            raw = json.load(fh)
        # 允许两种写法：{"cidrs":...} 或 {"scope": {...}}
        return cls.model_validate(raw.get("scope", raw))


Action = Literal["connect", "http_request", "run_tool"]


class ScopeGate:
    """范围闸。构造一次，反复判定。"""

    def __init__(self, scope: Scope, policy_dir: str = POLICY_DIR):
        self.scope = scope
        self.policy_dir = policy_dir
        self._opa = shutil.which(OPA_BIN)

    @classmethod
    def from_file(cls, path: str, policy_dir: str = POLICY_DIR) -> "ScopeGate":
        return cls(Scope.load(path), policy_dir)

    # ---------- 判定 ----------

    def check(self, action: Action, **fields: Any) -> Decision:
        """对一个动作做越界判定。永远返回 Decision，不抛异常。"""
        if not self._opa:
            return Decision(
                allow=False, trusted=False,
                reason="OPA 不可用（找不到 opa 可执行文件），按 fail-closed 拒绝",
            )

        payload = {"action": action, "scope": self.scope.model_dump(), **fields}
        try:
            proc = subprocess.run(
                [self._opa, "eval", "-d", self.policy_dir, "--format", "json",
                 "--input", "/dev/stdin", "data.nai.scope.decision"],
                input=json.dumps(payload).encode(),
                capture_output=True, timeout=15,
            )
        except (subprocess.TimeoutExpired, OSError) as exc:
            return Decision(allow=False, trusted=False,
                            reason=f"OPA 调用失败（{type(exc).__name__}），按 fail-closed 拒绝")

        if proc.returncode != 0:
            err = proc.stderr.decode("utf-8", "replace").strip()[:200]
            return Decision(allow=False, trusted=False,
                            reason=f"OPA 返回非零（{proc.returncode}）：{err}")

        try:
            body = json.loads(proc.stdout.decode("utf-8", "replace"))
            value = body["result"][0]["expressions"][0]["value"]
        except (ValueError, KeyError, IndexError):
            return Decision(allow=False, trusted=False,
                            reason="OPA 输出无法解析，按 fail-closed 拒绝")

        if not isinstance(value, dict) or "allow" not in value:
            return Decision(allow=False, trusted=False,
                            reason=f"OPA 输出缺少 allow 字段：{str(value)[:120]}")

        return Decision(
            allow=bool(value.get("allow")),
            rule=str(value.get("rule") or ""),
            reason=str(value.get("reason") or ""),
            policy_version=str(value.get("policy_version") or ""),
            trusted=True,
        )

    # ---------- 便捷封装 ----------

    def allow_connect(self, target: str) -> Decision:
        return self.check("connect", target=target)

    def allow_http(self, host: str) -> Decision:
        return self.check("http_request", host=host)

    def allow_tool(self, tool: str) -> Decision:
        return self.check("run_tool", tool=tool)
