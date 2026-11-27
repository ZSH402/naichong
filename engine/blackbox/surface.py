#!/usr/bin/env python3
"""端点测绘 —— 黑盒的感知层。

## 没有源码时"知道有什么"靠三样

1. **爬**：把页面里的链接、表单、JS 里的路径挖出来（katana 做这件事更全，
   但很多目标只需要解析响应就够了，所以这里自带一个轻量版）
2. **猜**：目录/参数枚举（ffuf 的活，这里只做参数，因为目录爆破噪音太大）
3. **漏**：错误响应会主动告诉你内部结构——栈帧里的文件路径、报错里的
   框架名、404 页面上的版本号

第三样最值钱。真实项目里"从报错反推内部结构"往往比爬虫有效一个量级，
因为爬虫只能看到被链接的东西，而报错会暴露没被链接的实现细节。

## 为什么不做目录爆破

`ffuf` 已经做得很好了，而自建的字典永远打不过 SecLists。这里的定位是
**把已经拿到的响应嚼碎**，产出结构化的端点-参数-角色矩阵，而不是再写一个爆破器。
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .core import Response

# 路径提取。刻意宽松——宁多勿漏，因为下游还有一步"这个端点通不通"的验证。
_PATH_RE = re.compile(r"""["'`](/[^"'`\s<>]{2,160})["'`]""")
_URL_RE = re.compile(r"""["'`](https?://[^\s"'`<>]{4,200})["'`]""")
_ACTION_RE = re.compile(r"""<form[^>]*action=["']([^"']+)["']""", re.I)
_FETCH_RE = re.compile(r"""\b(?:fetch|axios\.\w+|\.open)\s*\(\s*["'`]([^"'`]{2,200})["'`]""")
_PARAM_IN_URL = re.compile(r"[?&]([A-Za-z_][A-Za-z0-9_]{0,30})=")
_PARAM_JSON = re.compile(r"""["']([A-Za-z_][A-Za-z0-9_]{1,30})["']\s*:""")

# 错误/报错里会出现、但正常响应里不该有的东西
_LEAK_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("framework", re.compile(r"(X-Powered-By:\s*([^\s]+))|(Server:\s*([^\s]+))", re.I)),
    ("version", re.compile(r"\b((?:nginx|Apache|Tomcat|Express|Flask|Django|Spring|PHP|ASP\.NET)[/\s]?[\d.]+)", re.I)),
    ("path", re.compile(r"(?:^|[\s\"'])(/(?:home|root|usr|var|opt|srv|app|sites|www|tmp|Users)/[\w./\-\u4e00-\u9fff]{3,90})")),
    ("sql", re.compile(r"(SQL syntax|mysql_fetch|ORA-\d{5}|SQLSTATE\[|You have an error in your SQL)", re.I)),
    ("debug", re.compile(r"(debug\s*=\s*true|DJANGO_SETTINGS_MODULE|X-Debug-Token|Whoops\\Exception)", re.I)),
]


@dataclass
class Endpoint:
    """一个端点及其已知信息。"""
    method: str
    path: str
    params: list[str] = field(default_factory=list)
    source: str = ""                       # crawl / js / form / error / guess
    statuses: dict[str, int] = field(default_factory=dict)   # identity -> status
    notes: list[str] = field(default_factory=list)

    @property
    def key(self) -> str:
        return f"{self.method} {self.path}"

    def as_dict(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "path": self.path,
            "params": self.params[:20],
            "source": self.source,
            "statuses": self.statuses,
            "notes": self.notes[:5],
        }


@dataclass
class Surface:
    """一次测绘的结果。"""
    base: str
    endpoints: dict[str, Endpoint] = field(default_factory=dict)
    leaks: list[dict[str, str]] = field(default_factory=list)
    roles: dict[str, list[str]] = field(default_factory=dict)  # identity -> 可见端点

    def add(self, ep: Endpoint) -> None:
        cur = self.endpoints.get(ep.key)
        if cur is None:
            self.endpoints[ep.key] = ep
            return
        for p in ep.params:
            if p not in cur.params:
                cur.params.append(p)
        if ep.source and ep.source not in cur.notes:
            cur.notes.append(ep.source)

    def as_dict(self) -> dict[str, Any]:
        return {
            "base": self.base,
            "endpoint_count": len(self.endpoints),
            "endpoints": [e.as_dict() for e in self.endpoints.values()][:200],
            "leaks": self.leaks[:30],
            "roles": {k: v[:40] for k, v in self.roles.items()},
        }

    def save(self, path: str | Path) -> int:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        with p.open("w", encoding="utf-8") as f:
            for ep in self.endpoints.values():
                f.write(json.dumps(ep.as_dict(), ensure_ascii=False) + "\n")
        return len(self.endpoints)


def harvest(response: Response, surface: Surface, *, method: str = "GET") -> int:
    """从一个响应里榨出所有能榨的东西。

    返回新增/更新的端点数。同一个响应可以被反复喂进来（不同身份访问同一页面
    得到的内容不同），端点会合并。
    """
    before = len(surface.endpoints)
    body = response.body or ""

    paths: set[str] = set()
    for m in _PATH_RE.finditer(body):
        # 去掉查询串与锚点：端点本身才是要登记的东西，参数单独提。
        # 之前这里没剥，遇到 `/api/search?id=1` 会整体匹配失败，
        # 于是带参数的端点一个都收不进来。
        p = m.group(1).split("?")[0].split("#")[0]
        if _looks_like_path(p):
            paths.add(p)
    for m in _ACTION_RE.finditer(body):
        paths.add(m.group(1))
    for m in _FETCH_RE.finditer(body):
        v = m.group(1)
        if v.startswith("/"):
            paths.add(v)
        elif v.startswith("http"):
            paths.add(_as_path(v, surface.base))

    for p in paths:
        surface.add(Endpoint(method=method, path=p, params=sorted(set(_PARAM_IN_URL.findall(p))), source="crawl"))

    # 参数：URL 查询串 + JSON 键
    params = sorted(set(_PARAM_IN_URL.findall(response.url)) | set(_PARAM_JSON.findall(body)))
    if params and response.url:
        surface.add(Endpoint(method=method, path=_as_path(response.url, surface.base),
                             params=params, source="error" if response.status >= 400 else "crawl"))

    # 泄露
    for kind, rx in _LEAK_PATTERNS:
        for m in rx.finditer(body + "\n" + "\n".join(f"{k}: {v}" for k, v in response.headers.items())):
            matched = (m.group(0) or "").strip()[:160]
            if matched and not any(x["match"] == matched for x in surface.leaks):
                surface.leaks.append({"kind": kind, "match": matched, "url": response.url})

    # 按身份记录可见性
    surface.roles.setdefault(response.identity, [])
    for ep in surface.endpoints.values():
        if response.status < 400 and ep.key not in surface.roles[response.identity]:
            # 只知道这个身份在这个响应里看到了相关路径，不代表能访问；标记为"可见"
            if ep.path in body:
                surface.roles[response.identity].append(ep.key)

    return len(surface.endpoints) - before


def _looks_like_path(p: str) -> bool:
    if len(p) < 3 or len(p) > 120:
        return False
    if p.count("/") < 1:
        return False
    # 排除明显的资源与噪声
    if re.search(r"\.(png|jpe?g|gif|svg|woff2?|ttf|ico|css|map)$", p, re.I):
        return False
    if re.search(r"(^|/)\.(well-known|git)/", p):
        return False
    # 排除重复斜杠、纯数字路径（分页噪声）
    if "//" in p or re.fullmatch(r"/\d+", p):
        return False
    return True


def _as_path(url: str, base: str) -> str:
    """把绝对 URL 压成路径。跨域的要保留全 URL，因为那是第三方依赖的线索。"""
    if url.startswith(base):
        rest = url[len(base):]
        return rest if rest else "/"
    m = re.match(r"https?://[^/]+(/.*)?$", url)
    if m and url.startswith(base):
        return m.group(1) or "/"
    return url


def probe_surface(pool, surface: Surface, *, identities: list[str],
                  per_identity_limit: int = 40) -> dict[str, Any]:
    """对测绘出的端点做一轮身份可见性探测。

    只做 GET，只记录状态码——目的是**建立端点-角色矩阵**，
    不是测试。哪些端点对不同身份呈现不同状态，就是后续差分的目标。
    """
    tested = 0
    for ep in list(surface.endpoints.values())[:per_identity_limit]:
        if "{" in ep.path or ":" in ep.path.split("/")[-1]:
            # 带占位符的路径先跳过：没有真实 id 打过去只会得到 404，噪音
            continue
        for ident in identities:
            r = pool.send(ident, "GET", ep.path)
            if r.error:
                continue
            ep.statuses[ident] = r.status
            tested += 1
    return {
        "tested_requests": tested,
        "endpoints": len(surface.endpoints),
        "matrix": [
            {"endpoint": e.key, "statuses": e.statuses}
            for e in surface.endpoints.values() if e.statuses
        ][:80],
    }
