#!/usr/bin/env python3
"""脚手架参数进化 —— 在线自进化的最小可用形态。

## 诚实地划清边界

Darwin Gödel Machine 那类"让 agent 改自己的代码"需要：大量带隔离环境的
评测样本、每次运行数万美元、以及一整套防作弊的物理隔离（论文附录里
记录了自修改 agent 为拿高分偷偷删掉检测标记的事）。

**这些条件现在一个都不具备。** 所以这里做的不是代码进化，是**参数进化**：
固定探测逻辑，用无梯度优化搜索那组最优参数（并发数、采样轮次、
重试间隔、差分维度权重）。这是能在一天内跑完、能看出效果的版本。

## 为什么这也算"进化"

黑盒探测的收益对参数极敏感：并发数太小撞不进竞态窗口，太大被 WAF 拦；
采样轮次太少漏检，太多浪费时间。这些参数在不同目标上的最优值不同，
事先拍脑袋定的值必然次优。

用 nevergrad 的成熟实现做搜索，比手调快一个量级，而且结果可复现。

## 评分函数怎么定

需要 ground truth。用本地靶机——它埋了已知的几处缺陷，能算出
"检出数 / 误报数"。没有靶场的真实项目上，这个模块不适用：
**没有评测信号的进化是空转**，这一点必须写在用法里而不是藏在代码里。
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Callable

try:
    import nevergrad as ng
    HAS_NG = True
except Exception:      # pragma: no cover
    HAS_NG = False


# 搜索空间：每一项都对应一个真实存在的取舍
SPACE = {
    "concurrency": (4, 32),        # 竞态的并发数：小撞不进窗口，大被限流
    "rounds": (1, 6),              # 采样轮次：竞态窗口间歇性打开
    "samples": (2, 10),            # 基线采样数：太少判不出稳定形态
    "qps": (5.0, 60.0),            # 全局速率：太快触发 WAF
    "syntax_variants": (2, 7),     # 语法维跑几种变异：收益递减
    "protocol_variants": (0, 5),   # 协议维跑几种
}


@dataclass
class Strategy:
    """一组可执行的探测参数。"""
    concurrency: int = 10
    rounds: int = 3
    samples: int = 5
    qps: float = 20.0
    syntax_variants: int = 7
    protocol_variants: int = 5

    def as_dict(self) -> dict[str, Any]:
        return {
            "concurrency": int(self.concurrency),
            "rounds": int(self.rounds),
            "samples": int(self.samples),
            "qps": round(float(self.qps), 1),
            "syntax_variants": int(self.syntax_variants),
            "protocol_variants": int(self.protocol_variants),
        }


@dataclass
class Generation:
    """一代的结果。"""
    gen: int
    strategy: Strategy
    score: float
    detail: dict[str, Any] = field(default_factory=dict)


def evolve(evaluate: Callable[[Strategy], tuple[float, dict[str, Any]]], *,
           budget: int = 24, seed: int = 0) -> dict[str, Any]:
    """用 nevergrad 搜索参数。

    `evaluate(strategy) -> (score, detail)`，score 越大越好。
    评分必须来自**真实执行**（比如靶场检出率），不能是模型自评——
    模型自评会收敛到"它自己觉得好"的参数，而那和检出率没有必然关系。
    """
    history: list[Generation] = []

    if not HAS_NG:
        # 没有 nevergrad 时退化成网格，至少能跑
        grid = [
            Strategy(concurrency=c, rounds=r, samples=s, qps=q)
            for c in (8, 16) for r in (2, 4) for s in (3, 6) for q in (15.0, 30.0)
        ]
        best_s, best_score, best_detail = grid[0], float("-inf"), {}
        for g in grid[: max(1, budget)]:
            score, detail = evaluate(g)
            history.append(Generation(len(history) + 1, g, score, detail))
            if score > best_score:
                best_s, best_score, best_detail = g, score, detail
        return {
            "engine": "grid (nevergrad unavailable)",
            "best": best_s.as_dict(),
            "score": best_score,
            "best_detail": best_detail,
            "history": [{"gen": h.gen, "score": h.score, "strategy": h.strategy.as_dict()} for h in history],
        }

    inst = ng.p.Instrumentation(
        concurrency=ng.p.Scalar(lower=SPACE["concurrency"][0], upper=SPACE["concurrency"][1]).set_integer_casting(),
        rounds=ng.p.Scalar(lower=SPACE["rounds"][0], upper=SPACE["rounds"][1]).set_integer_casting(),
        samples=ng.p.Scalar(lower=SPACE["samples"][0], upper=SPACE["samples"][1]).set_integer_casting(),
        qps=ng.p.Scalar(lower=SPACE["qps"][0], upper=SPACE["qps"][1]),
        syntax_variants=ng.p.Scalar(lower=SPACE["syntax_variants"][0], upper=SPACE["syntax_variants"][1]).set_integer_casting(),
        protocol_variants=ng.p.Scalar(lower=SPACE["protocol_variants"][0], upper=SPACE["protocol_variants"][1]).set_integer_casting(),
    )
    optimizer = ng.optimizers.NGOpt(parametrization=inst, budget=budget, num_workers=1)
    optimizer.parametrization.random_state.seed(seed)

    best_score = float("-inf")
    best_strategy: Strategy | None = None
    best_detail: dict[str, Any] = {}

    for i in range(budget):
        cand = optimizer.ask()
        kwargs = cand.kwargs
        s = Strategy(
            concurrency=int(kwargs["concurrency"]),
            rounds=int(kwargs["rounds"]),
            samples=int(kwargs["samples"]),
            qps=float(kwargs["qps"]),
            syntax_variants=int(kwargs["syntax_variants"]),
            protocol_variants=int(kwargs["protocol_variants"]),
        )
        score, detail = evaluate(s)
        history.append(Generation(i + 1, s, score, detail))
        # nevergrad 是最小化，这里取负
        optimizer.tell(cand, -score)
        if score > best_score:
            best_score, best_strategy, best_detail = score, s, detail

    return {
        "engine": f"nevergrad/{type(optimizer).__name__}",
        "best": (best_strategy or Strategy()).as_dict(),
        "score": best_score,
        "best_detail": best_detail,
        "history": [{"gen": h.gen, "score": h.score, "strategy": h.strategy.as_dict()} for h in history],
        "note": ("parameter evolution only — the probing logic itself is fixed. Code-level "
                 "self-modification requires an evaluation harness and physical isolation that "
                 "does not exist yet, and without those it optimises a fiction"),
    }
