#!/usr/bin/env python3
"""黑盒探测原语 —— 确定性层，零 LLM。

## 这一层的定位

纯黑盒下，"模型想测什么"是最不可靠的一环。能确定下来的事情应该由代码做：
发请求、记响应、算差异。模型只在**差异出现之后**才被叫醒，去解释这个差异
意味着什么。

这不是分工偏好，是信息论上的必然：一次黑盒交互产生的信息量（状态码、头部、
字段集合、时序）远超过模型读一遍能提取的部分，让模型逐条看是浪费且不可复现。

## 四维差分

同一份请求，在四个维度上各变一次，看响应是否跟着变：

    identity  换身份（A/B/低权/管理员/匿名）—— 抓 BOLA / 越权
    protocol  换 HTTP 版本或编码变体      —— 抓代理与源站的解析歧义
    syntax    换参数形态（重复键/大小写/类型）—— 抓参数污染与类型混淆
    time      同请求并发重放               —— 抓非原子子状态

四个维度都是**纯机械操作**，不需要任何语义判断。差异本身才是信号，
解释留给上层。

## 为什么用 requests 而不是 httpx

requests 的会话对象能原样保留 cookie jar 与连接池，这对"多身份"场景是刚需：
每个身份一个 Session，互不串味。httpx 也能做，但 requests 的行为更可预测，
而黑盒探测最怕的就是"客户端自己引入的不确定性"。
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass, field
from typing import Any, Iterable

import requests
from requests.adapters import HTTPAdapter

# 一套默认的"看起来像正常浏览器"的头。不带 UA 会被大量 WAF 直接拦截，
# 那种 403 会被误读成"目标拒绝"，其实是客户端自己的问题。
DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/126.0 Safari/537.36",
    "Accept": "*/*",
    "Accept-Language": "en-US,en;q=0.9",
    "Connection": "keep-alive",
}


@dataclass
class Identity:
    """一个可复用的身份。

    黑盒里"身份"不是用户名密码，而是**一组能让响应产生差异的凭据集合**。
    可以是 cookie、bearer token、basic auth，或者什么都没有（匿名）。
    """
    name: str
    role: str                     # anonymous / user / admin / other
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    session: requests.Session | None = None


@dataclass
class Response:
    """一次探测的完整记录。字段刻意保持扁平，便于直接进证据链。"""
    identity: str
    method: str
    url: str
    status: int
    headers: dict[str, str]
    body: str
    elapsed_ms: float
    error: str = ""

    @property
    def fingerprint(self) -> str:
        """结构指纹：状态码 + 字段集合 + 长度量级。

        不含具体值——因为值会随会话变，而**结构**才是区分"两个不同响应"的依据。
        长度取量级（百/千/万）而不是精确值，避免把噪声当信号。
        """
        length_bucket = 0
        n = len(self.body)
        for bound in (100, 1_000, 10_000, 100_000):
            if n >= bound:
                length_bucket += 1
        keys = sorted(self.json_keys())[:40]
        raw = f"{self.status}|{length_bucket}|{';'.join(keys)}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def json_keys(self) -> list[str]:
        """从 JSON 响应里提取字段名（递归两层的点路径）。非 JSON 返回空。"""
        try:
            data = json.loads(self.body)
        except Exception:
            return []
        out: list[str] = []

        def walk(obj: Any, prefix: str, depth: int) -> None:
            if depth > 2:
                return
            if isinstance(obj, dict):
                for k, v in obj.items():
                    path = f"{prefix}.{k}" if prefix else str(k)
                    out.append(path)
                    walk(v, path, depth + 1)
            elif isinstance(obj, list) and obj:
                walk(obj[0], f"{prefix}[]", depth + 1)

        walk(data, "", 0)
        return out

    def sensitive_hits(self, needles: Iterable[str]) -> list[str]:
        """响应正文里出现了哪些不该出现的标记（别的用户的 id、canary 等）。"""
        return [n for n in needles if n and n in self.body]

    def as_dict(self) -> dict[str, Any]:
        return {
            "identity": self.identity,
            "method": self.method,
            "url": self.url,
            "status": self.status,
            "elapsed_ms": round(self.elapsed_ms, 1),
            "fingerprint": self.fingerprint,
            "json_keys": self.json_keys()[:40],
            "body_len": len(self.body),
            "error": self.error,
        }


class SessionPool:
    """多身份会话池。

    每个身份一个独立 Session（独立 cookie jar、独立连接池），这是"不串味"的
    前提——共用 Session 会让 A 的 cookie 被 B 的请求带上，出来的差异全是假的。
    """

    def __init__(self, base_url: str, timeout: float = 15.0, verify_tls: bool = False,
                 headers: dict[str, str] | None = None) -> None:
        self.base_url = base_url.rstrip("/")
        # 黑盒探测几乎总会遇到自签证书，默认不校验；要校验时显式打开
        self.verify_tls = verify_tls
        self.timeout = timeout
        self.base_headers = {**DEFAULT_HEADERS, **(headers or {})}
        self.identities: dict[str, Identity] = {}
        self._warned_insecure = False

    def add(self, identity: Identity) -> Identity:
        s = requests.Session()
        s.headers.update(self.base_headers)
        s.headers.update(identity.headers)
        for k, v in identity.cookies.items():
            s.cookies.set(k, v)
        # 连接池开大：并发探测时默认 10 个很快就不够
        adapter = HTTPAdapter(pool_connections=32, pool_maxsize=32)
        s.mount("http://", adapter)
        s.mount("https://", adapter)
        identity.session = s
        self.identities[identity.name] = identity
        return identity

    def get(self, name: str) -> Identity | None:
        return self.identities.get(name)

    def names(self) -> list[str]:
        return list(self.identities.keys())

    def close(self) -> None:
        for ident in self.identities.values():
            if ident.session is not None:
                ident.session.close()

    # ── 发送

    def send(self, identity: str, method: str, path: str, *,
             params: dict[str, Any] | None = None,
             data: Any = None,
             json_body: Any = None,
             headers: dict[str, str] | None = None,
             allow_redirects: bool = False) -> Response:
        """发一个请求并记录。

        默认**不跟随重定向**——因为 302 本身常常就是信号（登录态判定、
        授权跳转），跟随之后看到的只是终点，中间的语义全丢了。
        """
        ident = self.identities.get(identity)
        if ident is None or ident.session is None:
            return Response(identity, method, path, 0, {}, "", 0.0, error=f"unknown identity: {identity}")
        url = path if path.startswith("http") else f"{self.base_url}{path}"
        if not self.verify_tls and not self._warned_insecure and url.startswith("https"):
            self._warned_insecure = True
        started = time.perf_counter()
        try:
            r = ident.session.request(
                method.upper(), url, params=params, data=data, json=json_body,
                headers={**self.base_headers, **(headers or {})},
                timeout=self.timeout, allow_redirects=allow_redirects,
                verify=self.verify_tls,
            )
            elapsed = (time.perf_counter() - started) * 1000
            # 头部名统一小写：不同服务端的头部大小写不一致，直接比会假阳性
            hdrs = {k.lower(): v for k, v in r.headers.items()}
            return Response(identity, method.upper(), r.url, r.status_code, hdrs, r.text, elapsed)
        except Exception as exc:
            elapsed = (time.perf_counter() - started) * 1000
            return Response(identity, method.upper(), url, 0, {}, "", elapsed, error=str(exc)[:200])


# ── 差分

@dataclass
class Difference:
    """两个响应之间的差异。只报"变了什么"，不解释"为什么"。"""
    dimension: str
    left: Response
    right: Response
    status_changed: bool
    keys_added: list[str]
    keys_removed: list[str]
    length_delta: int
    sensitive: list[str]

    @property
    def significant(self) -> bool:
        """是否值得叫醒模型。

        判据刻意保守：只有**结构性**差异才算数（状态码变了、字段集合变了、
        或者泄出了不该出现的标记）。长度抖动不算——每个服务端都有动态内容，
        把那当信号等于天天报假警。
        """
        return (
            self.status_changed
            or bool(self.keys_added)
            or bool(self.keys_removed)
            or bool(self.sensitive)
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "dimension": self.dimension,
            "from": self.left.identity,
            "to": self.right.identity,
            "status": f"{self.left.status} -> {self.right.status}",
            "keys_added": self.keys_added[:15],
            "keys_removed": self.keys_removed[:15],
            "length_delta": self.length_delta,
            "sensitive": self.sensitive[:10],
            "significant": self.significant,
            "url": self.right.url,
        }


def compare(dimension: str, left: Response, right: Response,
            sensitive_markers: Iterable[str] = ()) -> Difference:
    """比对两个响应。sensitive_markers 是"只有某个身份才该看到的标记"，
    比如 A 的资源 id——它出现在 B 的响应里就是硬证据。"""
    lk, rk = set(left.json_keys()), set(right.json_keys())
    return Difference(
        dimension=dimension,
        left=left,
        right=right,
        status_changed=left.status != right.status,
        keys_added=sorted(rk - lk),
        keys_removed=sorted(lk - rk),
        length_delta=len(right.body) - len(left.body),
        sensitive=right.sensitive_hits(sensitive_markers),
    )


# ── 四维差分矩阵

def identity_matrix(pool: SessionPool, method: str, path: str, *,
                    params: dict[str, Any] | None = None,
                    data: Any = None,
                    json_body: Any = None,
                    sensitive_markers: Iterable[str] = ()) -> dict[str, Any]:
    """身份维：同一请求换身份各发一次，两两比对。

    黑盒里 BOLA/IDOR 的表现就是"换身份后响应结构变了"或者"看到了别人的标记"。
    不需要知道代码长什么样。
    """
    names = pool.names()
    responses = {n: pool.send(n, method, path, params=params, data=data, json_body=json_body) for n in names}
    diffs: list[Difference] = []
    for i in range(len(names)):
        for j in range(i + 1, len(names)):
            a, b = names[i], names[j]
            diffs.append(compare(f"identity:{a}vs{b}", responses[a], responses[b], sensitive_markers))
    return {
        "dimension": "identity",
        "url": path,
        "responses": {n: r.as_dict() for n, r in responses.items()},
        "differences": [d.as_dict() for d in diffs if d.significant],
        "tested": len(diffs),
    }


def behavior_matrix(pool: SessionPool, method: str, path: str, *,
                    params: dict[str, Any] | None = None,
                    body: Any = None,
                    probe_headers: dict[str, str] | None = None,
                    sensitive_markers: Iterable[str] = ()) -> dict[str, Any]:
    """一次请求 × 全部身份的完整行为矩阵 —— 「探索」而不是「验证」。

    与 `identity_matrix` 的区别不是代码，是**用途**：
      identity_matrix 回答"哪个身份和哪个身份不一样"（用于验证某条越权假设）
      behavior_matrix  回答"这个端点对身份敏感吗，敏感在哪一层"（用于发现假设）

    后者的输出刻意做成模型能直接读的表：每一行是一个身份，
    列是这个身份看到的状态码、字段数、长度量级、是否看到了别人的标记。
    **模型不需要自己发请求再比对——那是它最容易出错的地方**（我实测里
    两次把"参数被携带"读成"参数被接受"，都是手工比对造成的）。
    """
    names = pool.names()
    rows = []
    for n in names:
        r = pool.send(n, method, path, params=params, data=body, headers=probe_headers)
        rows.append({
            "identity": n,
            "status": r.status,
            "keys": len(r.json_keys()),
            "key_names": r.json_keys()[:10],
            "length": len(r.body or ""),
            "leaked": r.sensitive_hits(sensitive_markers),
            "error": r.error[:60] if r.error else "",
        })

    # 归纳：哪些维度对身份敏感
    statuses = {row["status"] for row in rows if not row["error"]}
    keycounts = {row["keys"] for row in rows if not row["error"]}
    leaks = [row for row in rows if row["leaked"]]

    signals = []
    if len(statuses) > 1:
        signals.append(f"状态码随身份变化：{sorted(statuses)} → 存在身份相关分支")
    if len(keycounts) > 1:
        signals.append(f"返回字段数随身份变化：{sorted(keycounts)} → 数据可见性按身份裁剪")
    if leaks:
        signals.append(f"跨身份标记泄露：{[(r['identity'], r['leaked']) for r in leaks]}")

    return {
        "endpoint": f"{method} {path}",
        "identities": len(names),
        "rows": rows,
        "sensitive_to_identity": bool(signals),
        "signals": signals,
        "how_to_read": (
            "每一行是一个身份对同一请求的观测。若 `sensitive_to_identity` 为真，"
            "说明这个端点的行为依赖身份——**但依赖身份本身不是漏洞**，"
            "关键看差异是否合理（管理员看到更多字段是设计，普通用户看到别人的数据才是问题）。"
            "下一步：用同一对象在多个身份下分别请求，看谁的数据被谁看到了。"
        ),
    }


# 语法维的变异器。全部是"同一个语义、不同的书写"，用来撞解析歧义。
SYNTAX_VARIANTS: list[tuple[str, dict[str, Any] | list[tuple[str, Any]]]] = [
    ("duplicate-key", [("id", "1"), ("id", "2")]),
    ("case-variant", [("ID", "1")]),
    ("type-string", [("id", "1")]),
    ("type-array", [("id[]", "1")]),
    ("null-byte", [("id", "1\x00")]),
    ("negative", [("id", "-1")]),
    ("large", [("id", "99999999999999999999")]),
]


def syntax_matrix(pool: SessionPool, identity: str, method: str, path: str, *,
                  base_params: dict[str, Any], key: str) -> dict[str, Any]:
    """语法维：同一个参数换不同书写形式，看服务端怎么解释。

    `id=1&id=2` 这种重复键，代理和源站取的值可能不同——这就是参数污染和
    代理/源站歧义的来源，不需要读代码就能测。
    """
    baseline = pool.send(identity, method, path, params=base_params)
    out = []
    for label, pairs in SYNTAX_VARIANTS:
        # 用原始查询串拼接，避免 requests 把重复键合并
        qs = "&".join(f"{k}={v}" for k, v in pairs)
        url = f"{path}?{qs}" if "?" not in path else f"{path}&{qs}"
        r = pool.send(identity, method, url)
        d = compare(f"syntax:{label}", baseline, r)
        out.append({
            "variant": label,
            "status": r.status,
            "fingerprint": r.fingerprint,
            "differs_from_baseline": d.significant,
            "keys_added": d.keys_added[:8],
            "body_len": len(r.body),
            # 参数污染的证据在**值**上不在结构上（服务端取了哪个 id），
            # 只比结构会漏掉它。这里带上正文摘要供上层判断。
            "body_excerpt": r.body[:200],
        })
    return {
        "dimension": "syntax",
        "url": path,
        "key": key,
        "variants": out,
        "divergent": [v["variant"] for v in out if v["differs_from_baseline"]],
    }


_PROTO_VARIANTS = [
    ("http10", {"Connection": "close"}),
    ("no-host", {}),
    ("x-forwarded", {"X-Forwarded-Host": "canary.invalid", "X-Forwarded-For": "127.0.0.1"}),
    ("chunked", {"Transfer-Encoding": "chunked"}),
    ("te-cl", {"Transfer-Encoding": "chunked", "Content-Length": "0"}),
]


def protocol_matrix(pool: SessionPool, identity: str, method: str, path: str, *,
                    headers: dict[str, str] | None = None) -> dict[str, Any]:
    """协议维：调头部让代理和源站的解释产生分歧。

    真正的请求走私需要 socket 级控制（见 race.py），这里做的是**低成本筛选**：
    哪些头部组合会让响应结构发生变化。变了说明链路里有人在意这些头，
    值得用单包攻击深入验证。
    """
    base = pool.send(identity, method, path, headers=headers)
    out = []
    for label, extra in _PROTO_VARIANTS:
        r = pool.send(identity, method, path, headers={**(headers or {}), **extra})
        d = compare(f"protocol:{label}", base, r)
        out.append({
            "variant": label,
            "status": r.status,
            "fingerprint": r.fingerprint,
            "differs_from_baseline": d.significant,
        })
    return {
        "dimension": "protocol",
        "url": path,
        "variants": out,
        "divergent": [v["variant"] for v in out if v["differs_from_baseline"]],
    }
