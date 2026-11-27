#!/usr/bin/env python3
"""异常检测 —— 黑盒的"发现"入口。

## 和白盒预言机的根本区别

白盒：有明确期望（"打这个请求应该返回别人的数据"）→ hit / miss / unknown。

黑盒：**没有期望**。你不知道正常长什么样，直到你量出来。

所以这里的范式是：**先采基线，再找偏离**。同一端点重复请求若干次，
把"稳定长什么样"记下来；之后任何一次与基线不符的响应都是候选异常。

## 为什么必须采基线而不是直接看响应

真实服务端的响应本来就在抖：时间戳、请求 id、A/B 分桶、动态广告位。
不采基线就直接判异常，等于把噪声当信号——这是黑盒扫描器误报率高的头号原因。

PortSwigger 的 HTTP Terminator 给的三条判据（一个请求回两个响应、响应体里
混进内联 HTTP 头、Range 请求回 200 而非 206）之所以硬，是因为**它们不是
"看起来不对"，而是结构上不可能**。这里的 baseline 判定走的是同一条路：
只认结构性偏离。
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any

from .core import Response, SessionPool, compare


@dataclass
class Baseline:
    """一个端点的"正常长什么样"。"""
    identity: str
    method: str
    path: str
    samples: int
    statuses: set[int] = field(default_factory=set)
    stable_keys: set[str] = field(default_factory=set)     # 每次都出现
    optional_keys: set[str] = field(default_factory=set)   # 时有时无
    min_len: int = 0
    max_len: int = 0
    fingerprints: set[str] = field(default_factory=set)
    errors: int = 0

    @property
    def settled(self) -> bool:
        """样本够不够判"稳定"。

        全成功或全失败都不算 settled——前者可能是缓存，后者说明根本没通。
        """
        return self.samples >= 3 and self.errors < self.samples

    def as_dict(self) -> dict[str, Any]:
        return {
            "identity": self.identity,
            "endpoint": f"{self.method} {self.path}",
            "samples": self.samples,
            "errors": self.errors,
            "statuses": sorted(self.statuses),
            "stable_keys": sorted(self.stable_keys)[:30],
            "optional_keys": sorted(self.optional_keys)[:30],
            "len_range": [self.min_len, self.max_len],
            "distinct_fingerprints": len(self.fingerprints),
            "settled": self.settled,
        }


def collect(pool: SessionPool, identity: str, method: str, path: str, *,
            samples: int = 5, gap_ms: int = 30,
            params: dict[str, Any] | None = None) -> Baseline:
    """采样建立基线。

    间隔发而不是并发发：并发会让"服务器忙"混进样本，把负载特征当成正常形态。
    """
    import time

    b = Baseline(identity=identity, method=method, path=path, samples=0)
    key_counts: dict[str, int] = {}
    lengths: list[int] = []
    for i in range(samples):
        r = pool.send(identity, method, path, params=params)
        b.samples += 1
        if r.error:
            b.errors += 1
            continue
        b.statuses.add(r.status)
        b.fingerprints.add(r.fingerprint)
        lengths.append(len(r.body))
        for k in r.json_keys():
            key_counts[k] = key_counts.get(k, 0) + 1
        if i < samples - 1:
            time.sleep(gap_ms / 1000)

    ok = b.samples - b.errors
    b.stable_keys = {k for k, c in key_counts.items() if c == ok and ok > 0}
    b.optional_keys = {k for k, c in key_counts.items() if 0 < c < ok}
    if lengths:
        b.min_len = min(lengths)
        b.max_len = max(lengths)
    return b


@dataclass
class Anomaly:
    """一次异常。带判据，不带解释。"""
    kind: str
    endpoint: str
    identity: str
    detail: str
    evidence: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "endpoint": self.endpoint,
            "identity": self.identity,
            "detail": self.detail,
            "evidence": self.evidence,
        }


def detect(baseline: Baseline, response: Response) -> Anomaly | None:
    """把一次响应和基线比。只报结构性偏离。"""
    if response.error:
        # 网络错误不是异常，是没测成。两类必须分开，否则断网会被读成"目标行为变了"
        return None
    if not baseline.settled:
        return None

    endpoint = f"{baseline.method} {baseline.path}"

    if baseline.statuses and response.status not in baseline.statuses:
        return Anomaly(
            kind="status-divergence",
            endpoint=endpoint,
            identity=response.identity,
            detail=f"status {response.status} never seen in {baseline.samples} baseline samples "
                   f"(known: {sorted(baseline.statuses)})",
            evidence={"status": response.status, "known": sorted(baseline.statuses)},
        )

    new_keys = set(response.json_keys()) - baseline.stable_keys - baseline.optional_keys
    if new_keys:
        return Anomaly(
            kind="field-appearance",
            endpoint=endpoint,
            identity=response.identity,
            detail=f"response gained {len(new_keys)} field(s) not present in baseline: {sorted(new_keys)[:8]}",
            evidence={"new_keys": sorted(new_keys)[:20]},
        )

    # 长度：只认"超出历史区间一个量级"的偏离。小幅抖动不算。
    if baseline.max_len > 0 and len(response.body) > baseline.max_len * 3:
        return Anomaly(
            kind="length-blowup",
            endpoint=endpoint,
            identity=response.identity,
            detail=f"body {len(response.body)} bytes, baseline max {baseline.max_len}",
            evidence={"len": len(response.body), "baseline_max": baseline.max_len},
        )

    return None


# ── 结构性异常的硬判据（不依赖基线）

_INLINE_HEADER = re.compile(
    r"(?:\r?\n|^)(?:HTTP/\d\.\d\s+\d{3}|Content-Length:\s*\d+|Transfer-Encoding:\s*\w+|"
    r"Location:\s*https?://|Set-Cookie:\s*\w+=)", re.M)
_DOUBLE_RESPONSE = re.compile(r"HTTP/\d\.\d\s+\d{3}[^\n]*\n(?:[^\n]*\n)*?HTTP/\d\.\d\s+\d{3}")
_STACK_TRACE = re.compile(
    r"(Traceback \(most recent call last\)|at [\w.$]+\([\w.]+\.java:\d+\)|"
    r"#0\s+0x[0-9a-f]+\s+in\s+\w+|System\.NullReferenceException|"
    r"<b>Fatal error</b>:|Stack trace:|goroutine \d+ \[)", re.I)
_PATH_LEAK = re.compile(r"(/(?:home|root|usr|var|opt|srv|app|sites|www|tmp|Users)/[\w./\-\u4e00-\u9fff]{3,90})")


def structural_checks(response: Response) -> list[Anomaly]:
    """不依赖基线的硬判据。

    这几条之所以可靠，是因为它们描述的是**结构上不可能**的情况：
    一个 HTTP 响应里再套一个 HTTP 响应、正文里出现服务端栈帧。
    正常业务代码不会产生这种输出。
    """
    out: list[Anomaly] = []
    endpoint = f"{response.method} {response.url}"
    body = response.body or ""

    if _DOUBLE_RESPONSE.search(body):
        out.append(Anomaly(
            kind="double-response",
            endpoint=endpoint,
            identity=response.identity,
            detail="response body contains a second complete HTTP response line",
            evidence={"sample": body[:200]},
        ))
    elif _INLINE_HEADER.search(body):
        out.append(Anomaly(
            kind="inline-http-header",
            endpoint=endpoint,
            identity=response.identity,
            detail="response body contains inline HTTP header lines (parser boundary suspect)",
            evidence={"sample": body[:200]},
        ))

    m = _STACK_TRACE.search(body)
    if m is not None:
        out.append(Anomaly(
            kind="stack-trace",
            endpoint=endpoint,
            identity=response.identity,
            detail=f"server-side stack frame leaked: {m.group(0)[:80]}",
            evidence={"match": m.group(0)[:200]},
        ))

    p = _PATH_LEAK.search(body)
    if p is not None:
        out.append(Anomaly(
            kind="path-leak",
            endpoint=endpoint,
            identity=response.identity,
            detail="absolute server path leaked in response",
            evidence={"path": p.group(1)},
        ))

    return out


def identity_anomalies(pool: SessionPool, method: str, path: str, *,
                       sensitive_markers: list[str] | None = None,
                       params: dict[str, Any] | None = None) -> list[Anomaly]:
    """跨身份的结构差异，直接当异常报。

    这是黑盒里对越权最敏感的一条：不需要知道谁是"受害者"，只要
    A 和 B 看到的**结构不同**（一个多字段、一个少字段、一个 200 一个 403），
    就说明这条端点的行为依赖身份，值得追。
    """
    from .core import identity_matrix

    m = identity_matrix(pool, method, path, params=params,
                        sensitive_markers=sensitive_markers or ())
    out: list[Anomaly] = []
    for d in m["differences"]:
        if d["sensitive"]:
            out.append(Anomaly(
                kind="cross-identity-leak",
                endpoint=f"{method} {path}",
                identity=d["to"],
                detail=f"{d['to']} saw markers that belong to another identity: {d['sensitive']}",
                evidence=d,
            ))
        elif d["keys_added"] or d["status"] .split(" -> ")[0] != d["status"].split(" -> ")[-1]:
            out.append(Anomaly(
                kind="cross-identity-divergence",
                endpoint=f"{method} {path}",
                identity=d["to"],
                detail=f"structural divergence {d['from']} vs {d['to']}: {d['status']}",
                evidence=d,
            ))
    return out
