#!/usr/bin/env python3
"""观察池 —— 给模型一个"说它看到了什么"的地方。

## 为什么这是这次改造的第一件事

现在的产出结构只有三种：`verdicts`（裁决）、`hypotheses`（新假设）、`excluded`（排除）。
模型在跑的过程中如果看到"这个登录流程里有个奇怪的重定向"、"这两个接口的参数
一模一样但一个校验了一个没有"——**它没有地方说**。

横向联想是漏洞挖掘的核心动作，而架构里没有它的位置。于是模型的能力被压成
"按契约回答被问到的问题"。

## 借鉴了什么

**Generative Agents 的记忆检索**：不是把所有观察都塞进下一轮（那会立刻炸掉上下文），
而是按三个因子打分取前 k 条：

    score = 0.3·recency + 0.4·importance + 0.3·relevance

  recency    指数衰减，越新越靠前
  importance 这条观察有多"重"（规则估，不额外调模型）
  relevance  和当前任务的词重叠度

**Reflexion 的反思记忆**：存"为什么"而不只是"是什么"。

## 一条硬约束（来自 "A Lesson Is an Untested Counterfactual"）

存进池子的观察**默认是不可信的推测**，只有显式标了 `confirmed` 的才算经过验证。
这条很重要：如果观察和证据混在一起，模型会把自己上一轮的猜测当成事实继续推论，
错误会沿轮次放大。所以池子里的条目永远带 `confidence`，注入 prompt 时也带着。
"""

from __future__ import annotations

import math
import re
import time
from dataclasses import dataclass, field
from typing import Any, Iterable

# 让"这条观察值得记"的信号。全部是规则，不调模型——
# 额外一次调用换一个 1-10 的分数不划算，而且规则的行为可预测。
_WEIGHT_SIGNALS = [
    (re.compile(r"(但是|然而|却|反而|不一致|矛盾|奇怪|反常|意外|异常|不对|可疑)"), 3),
    (re.compile(r"(因为|所以|说明|意味着|推测|可能|怀疑)"), 2),
    (re.compile(r"(/api/|/v[0-9]/|\?[a-z_]+=|id=|token|session|cookie)", re.I), 2),
    (re.compile(r"(\d{3}\b|状态码|返回|响应)"), 1),
    (re.compile(r"(之前|刚才|上一轮|上次|对比|相比)"), 2),
]

_KIND_WEIGHT = {
    "anomaly": 8,       # 看到了反常
    "pattern": 6,       # 看出了规律
    "question": 5,      # 提出了疑问
    "seed": 7,          # 可能长出假设
    "note": 3,          # 一般记录
}


@dataclass
class Observation:
    """一条观察。

    它**不是证据**。证据要能被系统读取的文件/argv 支撑；观察只是模型的一句话。
    """
    text: str
    where: str = ""                 # 哪个目标/端点
    kind: str = "note"              # anomaly / pattern / question / seed / note
    confidence: str = "speculative" # speculative / likely / confirmed
    round: int = 0
    created: float = field(default_factory=time.time)
    tags: list[str] = field(default_factory=list)

    @property
    def importance(self) -> int:
        """1-10 的重要性。规则估。"""
        score = _KIND_WEIGHT.get(self.kind, 3)
        for rx, w in _WEIGHT_SIGNALS:
            if rx.search(self.text):
                score += w
        if self.confidence == "confirmed":
            score += 2
        if len(self.text) < 12:       # 太短的多半没信息
            score -= 2
        return max(1, min(10, score))

    def as_dict(self) -> dict[str, Any]:
        return {"text": self.text[:300], "where": self.where, "kind": self.kind,
                "confidence": self.confidence, "round": self.round,
                "importance": self.importance}

    def render(self) -> str:
        """注入 prompt 的形式。confidence 一定要带上——
        不带的话，下一轮的模型会把自己的旧猜测当成既成事实。"""
        mark = {"confirmed": "✓", "likely": "~", "speculative": "?"}.get(self.confidence, "?")
        loc = f" @{self.where}" if self.where else ""
        return f"- {mark} [{self.kind}]{loc} {self.text[:220]}"


class ObservationPool:
    """按三因子检索的观察池。"""

    def __init__(self, *, decay_half_life_s: float = 3600.0,
                 weights: tuple[float, float, float] = (0.3, 0.4, 0.3)) -> None:
        self.items: list[Observation] = []
        self.half_life = max(1.0, decay_half_life_s)
        self.w_recency, self.w_importance, self.w_relevance = weights

    def add(self, obs: Observation) -> Observation:
        # 完全相同的文本只留一条（模型偶尔会重复说同一句话）
        for existing in self.items:
            if existing.text.strip() == obs.text.strip():
                existing.round = max(existing.round, obs.round)
                if obs.confidence == "confirmed":
                    existing.confidence = "confirmed"
                return existing
        self.items.append(obs)
        return obs

    def extend(self, items: Iterable[Observation]) -> None:
        for o in items:
            self.add(o)

    # ── 检索

    def _recency(self, obs: Observation, now: float) -> float:
        age = max(0.0, now - obs.created)
        return math.exp(-age / self.half_life)          # 0..1

    @staticmethod
    def _relevance(obs: Observation, query: str) -> float:
        """词重叠。不用 embedding——目标是"别把无关的塞进去"，
        词重叠已经够用，而且行为可解释。"""
        if not query:
            return 0.5
        q = {w for w in re.split(r"[^a-z0-9_/]+", query.lower()) if len(w) > 2}
        if not q:
            return 0.5
        t = {w for w in re.split(r"[^a-z0-9_/]+", (obs.text + " " + obs.where).lower()) if len(w) > 2}
        if not t:
            return 0.0
        return len(q & t) / len(q)

    def retrieve(self, query: str = "", k: int = 8, *, now: float | None = None,
                 kinds: Iterable[str] | None = None) -> list[Observation]:
        now = now or time.time()
        pool = self.items
        if kinds is not None:
            allow = set(kinds)
            pool = [o for o in pool if o.kind in allow]

        def score(o: Observation) -> float:
            return (self.w_recency * self._recency(o, now)
                    + self.w_importance * (o.importance / 10.0)
                    + self.w_relevance * self._relevance(o, query))

        ranked = sorted(pool, key=score, reverse=True)
        return ranked[:max(0, k)]

    # ── 输出

    def render_block(self, query: str = "", k: int = 8, *, now: float | None = None) -> str:
        """给 prompt 用的文本块。没有观察时返回空串（调用方决定要不要加小标题）。"""
        picked = self.retrieve(query, k, now=now)
        if not picked:
            return ""
        lines = ["## 我之前的观察（**未经验证**，不是结论）",
                 "下列条目是过往轮次里留意到的现象。带 ? 的是纯推测，"
                 "带 ~ 的是有一定依据，带 ✓ 的已核实。**不要把它们当作已经确认的事实**，"
                 "但如果其中一条正好解释你现在的困惑，那可能值得顺着它往下看。", ""]
        lines += [o.render() for o in picked]
        return "\n".join(lines)

    def as_dict(self, k: int = 20) -> dict[str, Any]:
        return {
            "total": len(self.items),
            "by_kind": _count(o.kind for o in self.items),
            "by_confidence": _count(o.confidence for o in self.items),
            "top": [o.as_dict() for o in self.retrieve("", k)],
        }


def _count(items: Iterable[str]) -> dict[str, int]:
    out: dict[str, int] = {}
    for i in items:
        out[i] = out.get(i, 0) + 1
    return out


def parse_observations(raw: Any, *, round_no: int = 0) -> list[Observation]:
    """把模型交回的 observations 字段解析成对象。

    宽容解析：模型可能给字符串数组、对象数组、或者干脆没给。
    给错了就当没给——**不能因为格式不对让整轮产出作废**。
    """
    out: list[Observation] = []
    if not isinstance(raw, list):
        return out
    for item in raw[:30]:
        if isinstance(item, str):
            t = item.strip()
            if len(t) >= 6:
                out.append(Observation(text=t, round=round_no))
            continue
        if not isinstance(item, dict):
            continue
        text = str(item.get("text") or item.get("observation") or "").strip()
        if len(text) < 6:
            continue
        conf = str(item.get("confidence") or "speculative").lower()
        out.append(Observation(
            text=text,
            where=str(item.get("where") or item.get("target") or "")[:120],
            kind=str(item.get("kind") or "note").lower()[:20],
            confidence=conf if conf in ("speculative", "likely", "confirmed") else "speculative",
            round=round_no,
            tags=[str(t)[:30] for t in (item.get("tags") or [])][:5],
        ))
    return out
