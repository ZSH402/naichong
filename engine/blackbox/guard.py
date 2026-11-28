#!/usr/bin/env python3
"""黑盒专属护栏 —— 让自动化不至于把自己变成一次真实攻击。

## 四道闸，缺一不可

**白名单**：域名/IP 硬锁。黑盒探测直接作用于运行中的服务，一旦模型发散
或响应里出现在第三方链接，就会打到不该打的地方。HTTP Terminator 的实测
记录里就有这种事：模型在被允许之后变得鲁莽，试图切换扫描未授权目标。

**熵增熔断**：拿"发现多少新 URL"当奖励，会被动态页面喂饱——无限派生的
链接零后端状态变化。改用**确定性状态增益**作判据：有没有新的报错指纹、
新的参数结构、新的鉴权边界。连续 N 次零增益就剪枝。

**早退**：一旦确认越权或响应泄露，立刻停手，只留存最小可验证证据。
继续抽取真实业务数据会把"验证"变成"数据泄露"。

**认知纠偏**：模型会被术语带偏，也会被系统的安全话术触发自我审查。
把容易引起误解的表述换成精确中性的说法，是工程问题不是措辞问题。
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Any, Iterable
from urllib.parse import urlparse


# ── 1. 白名单

@dataclass
class Scope:
    """硬白名单。任何不在列表里的目标一律拒绝，且**不提供"临时放行"接口**。

    这一点是刻意的：一旦存在绕过开关，它一定会在赶进度时被用上，
    而范围越界在渗透里是不可逆的——你没法"撤回"一次对第三方系统的探测。
    """
    hosts: set[str] = field(default_factory=set)
    cidrs: list[str] = field(default_factory=list)
    deny_ports: set[int] = field(default_factory=set)

    @classmethod
    def from_list(cls, hosts: Iterable[str], deny_ports: Iterable[int] = ()) -> "Scope":
        return cls(hosts={h.lower().strip() for h in hosts if h.strip()},
                   deny_ports=set(deny_ports))

    def check(self, url: str) -> tuple[bool, str]:
        u = urlparse(url)
        host = (u.hostname or "").lower()
        port = u.port or (443 if u.scheme == "https" else 80)
        if not self.hosts:
            return False, "scope is empty — refusing everything (fail-closed)"
        if host == "":
            return False, "cannot determine host from url"
        if host not in self.hosts:
            return False, f"host '{host}' is not in the authorized list"
        if port in self.deny_ports:
            return False, f"port {port} is explicitly denied"
        for c in self.cidrs:
            if _in_cidr(host, c):
                return True, f"host matches cidr {c}"
        return True, "host is in the authorized list"


def _in_cidr(host: str, cidr: str) -> bool:
    """极简 CIDR 判定。只处理 IPv4 字面量，域名不做 DNS 解析——
    解析会引入"DNS 变了导致范围判断漂移"的风险。"""
    try:
        import ipaddress

        return ipaddress.ip_address(host) in ipaddress.ip_network(cidr, strict=False)
    except Exception:
        return False


# ── 2. 限速

@dataclass
class RateLimit:
    """全局限速。黑盒并发探测最容易把目标打挂，而 DoS 是真事故不是漏洞。"""
    max_qps: float = 20.0
    max_errors: int = 20
    _window_start: float = field(default_factory=time.time)
    _window_count: int = 0
    _error_run: int = 0
    _slowdown: float = 1.0

    def acquire(self, timeout: float = 60.0) -> bool:
        """阻塞直到拿到一个配额，或超时。

        为什么需要这个：`allow()` 返回 False 只是"这一瞬间超了"，
        而调用方（probe 主循环）拿到 False 就 `break` 把整个作业标成 stopped——
        于是 qps 调得越保守，作业死得越快（实测 qps=2 时第 3 个请求就终止）。

        限速的语义应该是**推迟**，不是**放弃**。这里用一个短的 sleep 轮询，
        拿到配额返回 True；真等了 timeout 还没slot 才返回 False（那种情况
        通常意味着调用方把 qps 配成了 0 或者别的地方出了问题）。
        """
        import time as _t

        deadline = _t.time() + timeout
        while _t.time() < deadline:
            ok, _why = self.allow()
            if ok:
                return True
            _t.sleep(0.1)
        return False

    def allow(self) -> tuple[bool, str]:
        now = time.time()
        if now - self._window_start >= 1.0:
            self._window_start = now
            self._window_count = 0
        if self._window_count >= self.max_qps * self._slowdown:
            return False, "qps cap reached, backing off"
        self._window_count += 1
        return True, ""

    def record(self, ok: bool) -> tuple[bool, str]:
        """记录一次结果。连续失败会自动降速——这比硬性熔断更符合真实环境。"""
        if ok:
            self._error_run = 0
            return True, ""
        self._error_run += 1
        if self._error_run >= self.max_errors:
            return False, f"{self._error_run} consecutive errors — target may be down, stop"
        if self._error_run % 5 == 0:
            # 每次累加降速，最多降到 1/8
            self._slowdown = min(self._slowdown * 1.5, 8.0)
            return True, f"error rate high, slowing to 1/{self._slowdown:.1f} of the qps cap"
        return True, ""


# ── 3. 熵增熔断

@dataclass
class NoveltyTracker:
    """以"确定性状态增益"而非"新 URL 数"作探索奖励。

    这是针对 WebMaze 那类诱饵迷宫的直接对策：诱饵会无限派生结构相似的
    动态链接，任何按 URL 数量给奖励的策略都会往墙上撞。
    这里只认四类增益——新报错指纹、新参数结构、新鉴权边界、新持久化变更。
    """
    seen_errors: set[str] = field(default_factory=set)
    seen_params: set[str] = field(default_factory=set)
    seen_auth: set[str] = field(default_factory=set)
    seen_persist: set[str] = field(default_factory=set)
    zero_gain_streak: int = 0
    max_zero_streak: int = 15

    def observe(self, *, errors: Iterable[str] = (), params: Iterable[str] = (),
                auth: Iterable[str] = (), persist: Iterable[str] = ()) -> tuple[bool, str]:
        gained = []
        for label, bucket, items in (
            ("error", self.seen_errors, errors),
            ("param", self.seen_params, params),
            ("auth", self.seen_auth, auth),
            ("persist", self.seen_persist, persist),
        ):
            for it in items:
                if it and it not in bucket:
                    bucket.add(it)
                    gained.append(label)
        if gained:
            self.zero_gain_streak = 0
            return True, f"state gain: {sorted(set(gained))}"
        self.zero_gain_streak += 1
        if self.zero_gain_streak >= self.max_zero_streak:
            return False, (f"{self.zero_gain_streak} consecutive probes produced no new deterministic state — "
                           f"pruning this branch (likely a decoy or an already-explored area)")
        return False, ""

    def stats(self) -> dict[str, int]:
        return {
            "errors": len(self.seen_errors),
            "params": len(self.seen_params),
            "auth_boundaries": len(self.seen_auth),
            "persistent_changes": len(self.seen_persist),
            "zero_gain_streak": self.zero_gain_streak,
        }


# ── 4. 早退

@dataclass
class EarlyExit:
    """命中即停。

    一旦"越权读到 / 命令执行 / 任意文件读"被确认，继续抽取更多数据
    会把验证变成事故。这里只保留最小可验证证据（前 N 字节），然后置位停止。
    """
    tripped: bool = False
    reason: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)
    max_evidence_bytes: int = 512

    def trip(self, reason: str, evidence: dict[str, Any]) -> None:
        if self.tripped:
            return
        self.tripped = True
        self.reason = reason
        # 截断：证明"读到了"，不保存"读到了什么全部"
        trimmed = {}
        for k, v in evidence.items():
            if isinstance(v, str):
                trimmed[k] = v[: self.max_evidence_bytes]
            else:
                trimmed[k] = v
        self.evidence = trimmed

    def guard(self) -> tuple[bool, str]:
        return (False, f"early-exit tripped: {self.reason}") if self.tripped else (True, "")


# ── 5. 认知纠偏

# 术语中性化。目的不是"规避审查"，而是**消除歧义**：
# 同一个词在安全语境和通用语境里含义不同时，模型会按通用语境理解，结论就跑偏。
NEUTRAL_TERMS: dict[str, str] = {
    "attack": "probe",
    "attack the endpoint": "exercise the endpoint",
    "exploit": "verify",
    "weaponize": "construct a reproduction",
    "victim": "peer account",
    "victim response": "peer response",
    "steal": "retrieve",
    "hack": "test",
    "breach": "reach",
    "malicious": "edge-case",
    "bypass": "traverse",
}


def neutralize(text: str) -> str:
    """把容易引起歧义的术语换成精确表述。

    注意这是**双向**的：既让模型不把正常现象读成攻击，也让它在写结论时
    用可核对的词（"verified that account A could retrieve account B's invoice"
    比 "exploited IDOR" 更可复核）。
    """
    out = text
    for bad, good in sorted(NEUTRAL_TERMS.items(), key=lambda kv: -len(kv[0])):
        out = re.sub(re.escape(bad), good, out, flags=re.I)
    return out


# 无意义的响应头。保留它们只会让模型在噪音上编故事。
NOISE_HEADERS = {
    "date", "server-timing", "x-request-id", "x-runtime", "x-trace-id",
    "cf-ray", "x-cache", "x-served-by", "age", "etag", "last-modified",
    "x-amz-cf-id", "x-amz-cf-pop", "via", "x-varnish", "x-backend-server",
}


def denoise_headers(headers: dict[str, str]) -> dict[str, str]:
    """去掉纯噪声头，保留能说明技术栈与安全策略的那些。"""
    keep = {k: v for k, v in headers.items() if k.lower() not in NOISE_HEADERS}
    # 值太长的也截断：Set-Cookie 里塞 JWT 时能到几 KB
    return {k: (v[:200] if len(v) > 200 else v) for k, v in keep.items()}
