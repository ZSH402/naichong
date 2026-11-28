#!/usr/bin/env python3
"""凭据池 —— 多身份测试的前置条件。

## 为什么它决定整套工具的成败

这套东西最值钱的能力是"差分"：换一个身份看响应变不变。
但实测下来，**匿名面本来就没有东西可测**（95 个目标里只有 3 个匿名可访问且有内容，
其余是认证墙 / 401 / 空壳）。

也就是说：**没有身份，最强的能力用不上。**

而早先的身份是命令行里手拼的字符串：
    --ids "a=cookie:sid=abc,role=user"
这有三个问题：cookie 会过期、无法验证是否真的登录成功、多租户场景要手工复制粘贴 N 份。

## 这里解决三件事

  1. **验证** —— 加进池子时先发一个请求，确认这个凭据真的能过认证。
     没验证过的凭据比没有更糟：它会让所有差分结果都是"两个匿名用户的对比"，
     而那种对比永远显示"无差异"，看起来像"没有越权"。
  2. **区分身份维度** —— 除了 name/role，还要记 tenant。
     越权测试里真正的问题是"跨租户"，而 tenant 是那个维度的标签。
  3. **失效检测** —— 每次使用后如果拿到 401，标记为 stale 并从后续测试里排除，
     避免用过期凭据跑出一堆假的"无差异"。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .core import Identity, Response, SessionPool


@dataclass
class Credential:
    """一个可验证的身份。"""
    name: str
    role: str = "user"              # anonymous / user / admin / service
    tenant: str = ""                # 租户/组织标识。跨租户越权测试的维度
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    # 有效性探针：一个只有登录后才能访问的路径。
    # 不给的话无法验证，池子会标记为 unverified。
    verify_path: str = "/"
    # 验证通过时应该看到的特征（状态码或正文片段）。空表示"只要不是 401/302 到登录页"
    expect_status: int | None = None
    expect_contains: str = ""
    # 运行时状态
    verified: bool = False
    stale: bool = False
    last_status: int = 0
    note: str = ""

    def to_identity(self) -> Identity:
        return Identity(name=self.name, role=self.role,
                        headers=dict(self.headers), cookies=dict(self.cookies))

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "role": self.role,
            "tenant": self.tenant,
            "verified": self.verified,
            "stale": self.stale,
            "last_status": self.last_status,
            **({"note": self.note} if self.note else {}),
        }


class CredentialPool:
    """身份池。所有差分/越权测试都从这里取身份。"""

    def __init__(self, base_url: str, pool: SessionPool) -> None:
        self.base = base_url
        self.pool = pool
        self.creds: dict[str, Credential] = {}

    def add(self, cred: Credential) -> Credential:
        self.pool.add(cred.to_identity())
        self.creds[cred.name] = cred
        return cred

    def get(self, name: str) -> Credential | None:
        return self.creds.get(name)

    # ── 验证

    def verify(self, name: str, path: str | None = None) -> Credential | None:
        """确认这个凭据真的能过认证。

        判据优先级：
          1. 显式给了 expect_status / expect_contains → 按它判
          2. 否则：**不是 401、也不是跳到登录页** 就算通过
             （这是"能用"的最低标准，比"看起来登录了"可靠）

        为什么要显式探针：cookie 过期后接口往往返回 200 + 一个空 JSON，
        不报 401。没有探针的话，一个过期凭据会让所有差分测试变成
        "两个匿名用户的对比"，结论是"无越权"——假阴性。
        """
        c = self.creds.get(name)
        if c is None:
            return None
        probe = path or c.verify_path
        r: Response = self.pool.send(name, "GET", probe)
        c.last_status = r.status

        if r.error:
            c.verified, c.stale, c.note = False, True, f"probe failed: {r.error[:60]}"
            return c

        if c.expect_status is not None:
            ok = r.status == c.expect_status
            if c.expect_contains:
                ok = ok and c.expect_contains in (r.body or "")
            c.verified = ok
            c.note = "" if ok else f"expected {c.expect_status}, got {r.status}"
            c.stale = not ok
            return c

        loc = (r.headers.get("location") or "").lower()
        bounced = r.status in (301, 302, 303, 307, 308) and any(
            k in loc for k in ("login", "signin", "sso", "oauth", "auth"))
        c.verified = r.status not in (401,) and not bounced
        c.stale = not c.verified
        c.note = "" if c.verified else f"probe status {r.status}{' (bounced to login)' if bounced else ''}"
        return c

    def verify_all(self, path: str | None = None) -> dict[str, Any]:
        out = {}
        for name in list(self.creds):
            c = self.verify(name, path)
            if c is not None:
                out[name] = c.as_dict()
        return out

    # ── 使用约束

    def usable(self) -> list[Credential]:
        """可用于差分的身份：验证通过且没过期。"""
        return [c for c in self.creds.values() if c.verified and not c.stale]

    def by_tenant(self) -> dict[str, list[str]]:
        """按租户分组。跨租户越权测试要的是"不同 tenant 的同一 role"。"""
        out: dict[str, list[str]] = {}
        for c in self.usable():
            out.setdefault(c.tenant or "__no_tenant__", []).append(c.name)
        return out

    def mark_stale(self, name: str) -> None:
        c = self.creds.get(name)
        if c is not None:
            c.stale = True
            c.verified = False
            if c.note == "":
                c.note = "marked stale after a 401 during testing"

    def pairs_for_bola(self) -> list[tuple[str, str]]:
        """给出所有适合做 BOLA 测试的身份对。

        BOLA（对象级越权）要的是"同权不同人"：两个同 role 但不同 tenant/用户。
        拿 admin 和 user 对比没有意义——它们本来就该看到不同东西，
        那种差异是设计，不是漏洞。
        """
        out: list[tuple[str, str]] = []
        groups: dict[str, list[str]] = {}
        for c in self.usable():
            groups.setdefault(c.role, []).append(c.name)
        for role, names in groups.items():
            if role == "anonymous" or len(names) < 2:
                continue
            for i, a in enumerate(names):
                for b in names[i + 1:]:
                    out.append((a, b))
        return out

    def summary(self) -> dict[str, Any]:
        return {
            "total": len(self.creds),
            "usable": len(self.usable()),
            "stale": [c.name for c in self.creds.values() if c.stale],
            "by_tenant": self.by_tenant(),
            "bola_pairs": len(self.pairs_for_bola()),
            "warning": (
                "no verified credential — every differential test below compares two anonymous "
                "sessions and will report 'no difference' no matter what the target does"
                if not self.usable() else ""
            ).strip() or None,
        }
