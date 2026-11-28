#!/usr/bin/env python3
"""JS 深度分析 —— 从 bundle 里提取的不该只有路径。

## 缺口的由来

实测 `demo-appserver-livepaas` 的 `app.js` 有 145KB，之前只从里面抠出 5 个
字符串路径。而真正有价值的东西全在里面：

  - **API 调用表**：`fetch("/api/ai-config", {method:"POST", headers:{...}})`
    → 知道了方法、参数位置、自定义头
  - **鉴权方式**：`Authorization: Bearer ${token}` / `X-Csrf-Token` / cookie 名
  - **baseURL**：`axios.create({baseURL:"https://api.example.com/v2"})`
  - **功能开关**：`features:{aiAssist:true, ...}` → 知道哪些接口是灰度的
  - **内嵌常量**：版本号、渠道标识、有时甚至是 key（要报警但**不落盘值**）

**这些信息决定"怎么测"，而路径只决定"测哪里"。**

## 一条纪律

提取到的疑似凭据**只记位置和类型，不记值**。原因是这个工具的输出会进报告，
而报告会被转发。写进去等于二次泄露。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

# fetch / axios / $.ajax 的调用点。JS 打包后代码高度压缩，
# 所以用宽松模式匹配"方法 + 路径"的相邻出现，而不是解析 AST。
_CALL_PATTERNS = [
    # fetch("/path", {...})  /  fetch(`/path/${id}`)
    (re.compile(r"""fetch\s*\(\s*["'`]([^"'`]{2,200})["'`]"""), "fetch"),
    # axios.get("/path") / axios.post(`/path`)
    (re.compile(r"""axios\s*\.\s*(get|post|put|patch|delete)\s*\(\s*["'`]([^"'`]{2,200})["'`]""", re.I), "axios"),
    # $.ajax({url:"/path", method:"POST"})
    (re.compile(r"""\$\.(?:ajax|get|post)\s*\(\s*[{"'][^}]*?url\s*:\s*["'`]([^"'`]{2,200})["'`]""", re.I), "jquery"),
    # request("/path", {method:"PUT"})
    (re.compile(r"""\.request\s*\(\s*["'`]([^"'`]{2,200})["'`]"""), "request"),
    # url: "/path"（配置对象里）
    (re.compile(r"""\burl\s*:\s*["'`]([^"'`]{2,200})["'`]"""), "config"),
    # 原生表单：el('form', {action:'/api/x', method:'post'}) 或 <form action="/api/x">
    # 服务端渲染的应用（不是 SPA）把接口全写成 form action，
    # 实测 demo-appserver 的 /api/ai-config 就是这样，纯 fetch 正则完全匹配不到。
    (re.compile(r"""action\s*:\s*["'`]([^"'`]{2,200})["'`]"""), "form"),
    (re.compile(r"""<form[^>]+action=["']([^"']{2,200})["']""", re.I), "form"),
]

# 第三方服务的标准路径。出现在前端代码里是**配置提示**，不是本站端点。
# 实测 demo-appserver 的 app.js 里有一张 provider→path 映射表：
#   {openai: '/v1/chat/completions', anthropic: '/v1/messages', ollama: '/api/chat', ...}
# 早先这些被当成本站接口去打，全部 404——白白消耗配额还污染端点清单。
_THIRD_PARTY_PATHS = re.compile(
    r"^/(?:" + "|".join([
        r"v1/chat/completions", r"v1/completions", r"v1/embeddings", r"v1/models",
        r"v1/messages", r"v1/responses", r"v1beta/models", r"v1beta/",
        r"api/chat", r"api/generate", r"api/tags", r"api/embeddings",
        r"v1/audio", r"v1/images", r"openai/", r"anthropic/",
    ]) + r")",
    re.I)

_BASEURL = re.compile(r"""baseURL\s*:\s*["'`]([^"'`]{4,200})["'`]""")
_AUTH_HDR = re.compile(
    r"""(?:Authorization|X-Csrf-Token|X-XSRF-TOKEN|X-Auth-Token|X-Api-Key)["']?\s*[:=]\s*["'`]?([^"'`,\n}]{0,80})""",
    re.I)
_HEARDER_NAME = re.compile(r"""headers\s*:\s*\{([^}]{0,300})\}""", re.I)
_TOKEN_KEY = re.compile(r"""["']([a-z0-9_]*(?:token|key|secret|password|passwd)["']?\s*:\s*)["'`]([^"'`]{0,120})["'`]""", re.I)
_FEATURE_FLAG = re.compile(r"""["']?(?:features?|flags?)["']?\s*:\s*\{([^}]{0,300})\}""", re.I)

# 疑似凭据的前缀特征。命中只记**类型和位置**，不记值。
_SECRET_PREFIX = re.compile(
    r"""\b(sk-[A-Za-z0-9]{16,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{20,}|"""
    r"""eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.|xox[baprs]-[A-Za-z0-9-]{10,})""")


@dataclass
class JsIntel:
    """从一个 JS bundle 里提取到的情报。"""
    source: str
    size: int = 0
    calls: list[dict[str, Any]] = field(default_factory=list)      # {method, path, via}
    base_urls: list[str] = field(default_factory=list)
    auth_headers: list[str] = field(default_factory=list)          # 头名或 scheme，不含值
    feature_flags: list[str] = field(default_factory=list)
    secret_slots: list[dict[str, str]] = field(default_factory=list)  # {kind, location} 不含值

    def as_dict(self) -> dict[str, Any]:
        return {
            "source": self.source[-60:],
            "size": self.size,
            "calls": self.calls[:25],
            "base_urls": self.base_urls[:5],
            "auth": self.auth_headers[:8],
            "features": self.feature_flags[:8],
            **({"secret_slots": self.secret_slots[:5]} if self.secret_slots else {}),
        }


def analyze(source: str, text: str) -> JsIntel:
    """分析一段 JS。

    `source` 只用于标记出处（日志里显示末 60 字符）。
    """
    intel = JsIntel(source=source, size=len(text or ""))
    if not text:
        return intel

    # ── 调用点
    seen: set[tuple[str, str]] = set()
    for rx, via in _CALL_PATTERNS:
        for m in rx.finditer(text):
            groups = m.groups()
            if via == "axios":
                method = (groups[0] or "GET").upper()
                path = groups[1] if len(groups) > 1 else ""
            else:
                method = "GET"
                path = groups[-1]
            path = (path or "").strip()
            if len(path) < 2 or len(path) > 160:
                continue
            if path.startswith(("data:", "blob:", "#", "http://", "https://")) and "api" not in path:
                continue
            head = path.split("?")[0]
            if _THIRD_PARTY_PATHS.match(head):
                continue          # 这是让你填的第三方服务路径，不是本站的
            key = (method, head)
            if key in seen:
                continue
            seen.add(key)
            if via == "form":
                # 表单的 method 写在别处（同一对象的 method: 'post'）
                near = text[max(0, m.start() - 200):m.end() + 200]
                mm = re.search(r"""method\s*:\s*["'`](get|post|put|patch|delete)["'`]""", near, re.I)
                method = mm.group(1).upper() if mm else "POST"
            intel.calls.append({"method": method, "path": path[:120], "via": via})
            if len(intel.calls) >= 40:
                break

    # ── baseURL
    for m in _BASEURL.finditer(text):
        v = m.group(1).strip()
        if v and v not in intel.base_urls:
            intel.base_urls.append(v[:160])

    # ── 鉴权头：只留头名与 scheme，值一律丢弃
    for m in _HEARDER_NAME.finditer(text):
        blob = m.group(1)
        for h in _AUTH_HDR.finditer(blob):
            head = h.group(0).split(":")[0].split("=")[0].strip().strip('"\'')
            if head and head not in intel.auth_headers:
                intel.auth_headers.append(head[:40])
    for m in re.finditer(r"""["'](Authorization|X-Csrf-Token|X-Api-Key|X-Auth-Token)["']""", text):
        h = m.group(1)
        if h not in intel.auth_headers:
            intel.auth_headers.append(h)

    # ── 功能开关
    for m in _FEATURE_FLAG.finditer(text):
        for kv in re.finditer(r"""([A-Za-z_][A-Za-z0-9_]{2,30})\s*:\s*(true|false|1|0)""", m.group(1)):
            flag = f"{kv.group(1)}={kv.group(2)}"
            if flag not in intel.feature_flags:
                intel.feature_flags.append(flag)

    # ── 疑似凭据：**只记类型与位置，不记值**
    for m in _SECRET_PREFIX.finditer(text):
        kind = ("jwt" if m.group(0).startswith("eyJ") else
                "aws-key" if m.group(0).startswith("AKIA") else
                "openai-key" if m.group(0).startswith("sk-") else
                "github-token" if m.group(0).startswith("ghp_") else
                "slack-token")
        intel.secret_slots.append({"kind": kind, "location": f"{source[-40:]}:offset {m.start()}"})
    for m in _TOKEN_KEY.finditer(text):
        name = m.group(1).strip().strip('"\' :')
        val = m.group(2)
        # 空串或占位符不算；出现了实际长度才报"这里有一个凭据槽位"
        if len(val) >= 8:
            intel.secret_slots.append({"kind": f"field:{name}"[:40],
                                       "location": f"{source[-40:]}:offset {m.start()}"})

    return intel


def merge_endpoints_from_intel(intel: JsIntel) -> list[tuple[str, str]]:
    """把调用点转成 (method, path) 列表，供上层登记成端点。

    这一步很关键：调用点比字符串路径可靠得多——它带**方法**。
    `POST /api/ai-config` 和 `GET /api/ai-config` 可能是完全不同的权限模型。
    """
    out: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for c in intel.calls:
        p = c["path"]
        if not p.startswith("/"):
            continue
        p = p.split("?")[0].split("#")[0]
        # 带模板变量的保留占位符形式，但不要把 `${...}` 当真实路径去打
        key = (c["method"], p)
        if key in seen:
            continue
        seen.add(key)
        out.append((c["method"], p))
    return out
