#!/usr/bin/env python3
"""响应分类 —— 判断"这个响应到底意味着什么"。

## 为什么单看状态码不够

实测 95 个目标的状态码分布：200 有 20 个、302 有 9 个、401/403 有 14 个、
404 有 30 多个。但同样一个 200，可能是：
  - 一个真实页面（有内容、有可测的面）
  - 一个空壳（SPA index，所有内容靠 JS）
  - 一个假的 200（WAF 的挑战页，浏览器里会跳验证）

同样一个 302，可能是：
  - 认证墙（跳到统一登录）
  - 挑战页（跳到验证/风控）
  - 正常业务跳转

**把这三类混在一起，就是"报告里全是没用的东西"的根源。**

## 分类规则从哪来

全部来自本次实战的观测，不是凭空想的：
  - `login.dingtalk.com/oauth2/auth` → 认证墙（9 个目标共用同一个入口）
  - `login.dingtalk.com/oauth2/challenge.htm` → 挑战页（12 个变体全被导到这里）
  - 302 + 空 body → 不是"没有内容"，是"内容在你进不去的地方"
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

# 认证墙特征：跳转目标里出现这些词，基本就是"先登录再说"
AUTH_WALL_HINTS = re.compile(
    r"(login|signin|sign-in|sso|oauth|auth|passport|cas/|saml)", re.I)

# 挑战页特征：人机验证、风控、WAF 拦截
CHALLENGE_HINTS = re.compile(
    r"(challenge|captcha|verify|验证|人机|risk|punish|security-check|"
    r"waf|blocked|denied|slider|nc_|_cf_chl|__jsluid)", re.I)

# 挑战页的正文特征（有些挑战页直接返回 200 + HTML）
CHALLENGE_BODY = re.compile(
    r"(请完成验证|人机验证|captcha|滑动验证|正在验证您的浏览器|"
    r"Just a moment|Checking your browser|Attention Required|"
    r"Access denied|Request blocked)", re.I)

# 空壳特征：SPA 的 index 通常只有一个挂载点 + 几个 script
SPA_SHELL = re.compile(r"(<div id=\"(app|root)\"[^>]*>\s*</div>|<app-root)", re.I)


@dataclass
class Verdict:
    """一次响应的分类结论。"""
    kind: str                      # page / spa / api / auth-wall / challenge / forbidden / empty / dead
    score: int                     # 可测性 0-100
    reasons: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "score": self.score, "reasons": self.reasons, **self.details}


def classify(*, status: int, headers: dict[str, str], body: str,
             content_type: str = "", endpoints: int = 0, js_fetched: int = 0,
             leaks: int = 0) -> Verdict:
    """把一次响应归到某个类，并给出可测性评分。

    评分不是"这个目标不安全"，是**"还有多少东西可测"**——一个全是墙的目标
    不代表安全，只代表从这个入口推不动。
    """
    h = {k.lower(): v for k, v in (headers or {}).items()}
    loc = h.get("location", "")
    ctype = (content_type or h.get("content-type", "")).split(";")[0].strip().lower()
    body = body or ""
    reasons: list[str] = []

    # 1. 挑战页优先判：它可能伪装成 200、302 或 403
    if CHALLENGE_HINTS.search(loc) or CHALLENGE_BODY.search(body[:4000]):
        return Verdict("challenge", 0,
                       ["intercepted by a bot/risk challenge — everything after this point "
                        "measures the challenge page, not the application"],
                       {"location": loc[:100]})

    # 2. 认证墙
    if status in (301, 302, 303, 307, 308) and AUTH_WALL_HINTS.search(loc) and len(body) < 2000:
        return Verdict("auth-wall", 0,
                       ["redirects to a shared authentication entry — anonymous surface ends here",
                        "to test this you need an authenticated identity"],
                       {"location": loc[:100]})

    # 3. 连着不上/死
    if status == 0:
        return Verdict("dead", 0, ["no HTTP response at all"])

    # 4. 权限拒绝：**这两个比 404 有价值得多**
    if status in (401, 403):
        sc = 70 if status == 401 else 55
        reasons = [
            "401: the endpoint exists and authenticates — it is a real API, not a 404",
            "an authenticated identity could test authorization here",
        ] if status == 401 else [
            "403: the endpoint exists but refuses this caller — worth retrying with another identity",
        ]
        return Verdict("forbidden", sc, reasons, {"status": status})

    # 5. JSON API
    if "json" in ctype:
        sc = 60 + min(20, endpoints * 2)
        return Verdict("api", sc,
                       ["returns JSON — every key is a lead about the data model"],
                       {"content_type": ctype})

    # 6. 空壳 SPA
    if SPA_SHELL.search(body):
        sc = 40 + min(40, js_fetched * 8 + endpoints * 3)
        reasons = ["SPA shell — routes live in the JS bundles"]
        if js_fetched == 0:
            reasons.append("no same-origin JS was fetched, so the route table is still unknown")
        return Verdict("spa", sc, reasons, {"js_fetched": js_fetched, "endpoints": endpoints})

    # 7. 真实页面
    if status == 200 and len(body) > 500:
        sc = 30 + min(50, endpoints * 4 + js_fetched * 6 + leaks * 5)
        reasons = [f"{len(body)} bytes of HTML with {endpoints} discovered endpoint(s)"]
        if js_fetched:
            reasons.append(f"{js_fetched} same-origin bundle(s) parsed")
        if leaks:
            reasons.append(f"{leaks} framework/version/path disclosure(s)")
        return Verdict("page", sc, reasons, {"len": len(body), "endpoints": endpoints})

    # 8. 短 200 / 404 等
    if status == 200:
        return Verdict("empty", 15, [f"200 but only {len(body)} bytes — nothing to work with"])
    if status == 404:
        return Verdict("empty", 0, ["404 — no handler at this path"])
    if status >= 500:
        return Verdict("error", 35, [f"{status} — server-side error, sometimes leaks more than a 200"],
                       {"status": status})

    return Verdict("unknown", 10, [f"status {status}, {len(body)} bytes"])


def extract_redirect_chain_targets(location: str) -> list[str]:
    """从跳转目标里挖出所有值得记录的域名/路径。

    302 的 Location 本身就是情报：它暴露了认证体系的入口、
    参数名（redirect_uri / continue / client_id）、以及**内部域名**。
    """
    if not location:
        return []
    out: list[str] = []
    try:
        u = urlparse(location)
        if u.netloc:
            out.append(f"{u.scheme}://{u.netloc}{u.path}"[:160])
    except Exception:
        pass
    return out
