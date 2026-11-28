#!/usr/bin/env python3
"""编排层 —— 四层脚手架 + 双层反思。

## 四层解耦的意义

黑盒面对的每个目标都有独特的 WAF 策略、自定义加密、框架回显风格。
脚手架写死一套，模型很快会被困在重复试错里。

把外围拆成四层，每层可以**独立**被诊断和调整：

    L_S  策略层   纪律、早退条件、剪枝阈值、探索/利用的切换判据
    L_I  接口层   发包封装、重试、超时、编码规则（防转义问题）
    L_P  感知层   观察过滤：噪声头剥离、长响应截断、术语中性化
    L_D  技能层   领域战术手册，按目标类型挂载（REST / GraphQL / 表单流）

关键在"独立"：一次失败能归因到**具体哪一层**，只改那一层。
全部混在一个 prompt 里时，任何调整都会牵连全部行为，调完不知道是哪个改动起的作用。

## 双层反思

**微观**（Intra）：盯单次响应——状态码、重定向、令牌缺失、WAF 特征。
判据是确定的（正则 + 状态码），不需要模型。

**宏观**（Inter）：某条攻击链连续消耗步数而无状态增益时剪枝换路。
判据用 NoveltyTracker 的零增益连击，不用模型自评"我是不是卡住了"。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from .guard import NoveltyTracker, denoise_headers, neutralize


# ── 四层

@dataclass
class Layer:
    """一个可热替换的配置层。"""
    name: str
    config: dict[str, Any] = field(default_factory=dict)
    revisions: int = 0
    history: list[dict[str, Any]] = field(default_factory=list)

    def patch(self, changes: dict[str, Any], reason: str) -> dict[str, Any]:
        """原地调整。记录修订历史，便于事后回答"为什么这一轮行为和上一轮不一样"。"""
        before = {k: self.config.get(k) for k in changes}
        self.config.update(changes)
        self.revisions += 1
        entry = {"revision": self.revisions, "reason": reason, "from": before, "to": changes}
        self.history.append(entry)
        return entry


DEFAULT_LAYERS: dict[str, dict[str, Any]] = {
    "L_S": {
        "max_steps_without_gain": 15,
        "early_exit_on_leak": True,
        "explore_ratio": 0.4,          # 探索/利用比例
        "stop_on_error_run": 20,
    },
    "L_I": {
        "timeout_sec": 15,
        "retries": 1,
        "follow_redirects": False,
        "http2": True,
        "encode_params": True,
    },
    "L_P": {
        "strip_noise_headers": True,
        "max_body_chars": 4000,
        "neutralize_terms": True,
        "summarize_html": True,
    },
    "L_D": {
        "handbook": "generic",          # generic / rest / graphql / form-flow
        "auth_scheme": "unknown",       # cookie / bearer / basic
    },
}


class Scaffold:
    """整套脚手架。四层可独立读改，失败能归因到层。"""

    def __init__(self, layers: dict[str, dict[str, Any]] | None = None) -> None:
        cfg = layers or DEFAULT_LAYERS
        self.layers: dict[str, Layer] = {k: Layer(k, dict(v)) for k, v in cfg.items()}
        self.novelty = NoveltyTracker(max_zero_streak=self.layers["L_S"].config["max_steps_without_gain"])

    def layer(self, name: str) -> Layer:
        return self.layers[name]

    # ── 感知层：把响应变成模型能看的东西

    def observe(self, status: int, headers: dict[str, str], body: str) -> dict[str, Any]:
        cfg = self.layers["L_P"].config
        h = denoise_headers(headers) if cfg["strip_noise_headers"] else dict(headers)

        # **先清洗再截断**，顺序不能反。
        #
        # 早先是先按 max_body_chars 截原始 HTML、再 _summarize_html。
        # 如果页面前 4KB 全是 <head><style>…</style><script>…</script>，
        # 截断点落在 <script> 中间：闭合标签没了，_summarize_html 的
        # 非贪婪 `</script>` 匹配不上，整段"脚本"会被当成正文留下——
        # 或者相反，清洗后返回空串，正文里的 API 线索全丢。
        b = body
        if cfg["summarize_html"]:
            b = _summarize_html(b)
        if cfg["max_body_chars"] and len(b) > cfg["max_body_chars"]:
            b = b[: cfg["max_body_chars"]] + f"\n…[truncated, total {len(body)} chars]"
        if cfg["neutralize_terms"]:
            b = neutralize(b)
        return {"status": status, "headers": h, "body": b}

    # ── 微观反思：单次响应是否该重试/换载荷

    WAF_HINTS = re.compile(
        r"(cloudflare|akamai|imperva|sucuri|mod_security|wallarm|f5 big-ip|"
        r"request blocked|access denied|not acceptable|rate limit|too many requests)", re.I)

    def intra_reflect(self, obs: dict[str, Any]) -> dict[str, Any]:
        """根据一次响应给出可执行的调整建议。

        不调模型：这些判断都是模式匹配，模型来做只会引入不确定性。
        """
        status = int(obs.get("status", 0))
        headers = {k.lower(): v for k, v in (obs.get("headers") or {}).items()}
        body = str(obs.get("body") or "")
        advice: dict[str, Any] = {"action": "continue", "reasons": []}

        if status == 429 or "retry-after" in headers:
            advice["action"] = "backoff"
            advice["reasons"].append(f"rate limited (status {status})")
            advice["patch_hint"] = {"L_I": {"retries": 0, "timeout_sec": 30}}
        elif status in (401, 403) and self.WAF_HINTS.search(body + str(headers)):
            advice["action"] = "backoff"
            advice["reasons"].append("WAF fingerprint in a 401/403 response")
            advice["patch_hint"] = {"L_I": {"encode_params": False}}
        elif status == 302 and "location" in headers:
            loc = headers["location"]
            advice["reasons"].append(f"redirect to {loc[:80]} — treat the redirect itself as the signal")
        elif status >= 500:
            advice["action"] = "keep"
            advice["reasons"].append(f"server error {status} — often the most informative response")
        return advice

    # ── 宏观反思：是否该剪枝

    def inter_reflect(self, *, gained: bool) -> dict[str, Any]:
        if not gained and self.novelty.zero_gain_streak >= self.novelty.max_zero_streak:
            return {
                "action": "prune",
                "reason": f"{self.novelty.zero_gain_streak} probes with no deterministic state gain",
                "stats": self.novelty.stats(),
            }
        return {"action": "continue", "stats": self.novelty.stats()}

    def as_dict(self) -> dict[str, Any]:
        return {
            name: {"config": l.config, "revisions": l.revisions,
                   **({"history": l.history[-3:]} if l.history else {})}
            for name, l in self.layers.items()
        } | {"novelty": self.novelty.stats()}


_SCRIPT_STYLE = re.compile(r"<script[\s\S]*?</script>|<style[\s\S]*?</style>", re.I)
_TAG = re.compile(r"<[^>]+>")
_WS = re.compile(r"[ \t]{2,}")


def _summarize_html(html: str) -> str:
    """HTML 压缩：去脚本样式、去标签、压空白。

    保留**文本与属性里的路径**——那才是端点和参数的来源，标签本身信息量为零。
    直接把几 MB 的 HTML 丢给模型是纯浪费：它读不完，而且会开始编。
    """
    if "<" not in html:
        return html
    s = _SCRIPT_STYLE.sub(" ", html)
    s = _TAG.sub(" ", s)
    s = _WS.sub(" ", s)
    return re.sub(r"\n{3,}", "\n\n", s).strip()
