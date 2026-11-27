#!/usr/bin/env python3
"""状态机反推 —— 从纯黑盒交互里恢复目标的近似有限状态机。

## 为什么这件事在黑盒里可行

白盒能读代码画状态机，黑盒不行。但黑盒有一个白盒没有的东西：
**大量真实的 (请求, 响应) 序列**。把响应的结构指纹当状态标签，
序列自然就长成一张图。

这不是精确的状态机——同一个状态可能被拆成两个指纹，两个状态也可能撞成
一个。但对找漏洞够用，因为要找的是**不该存在的转移**：

  - 跳步：从"未认证"直接到"已下单"，中间没有过"已认证"
  - 回溯：从"已支付"回到"已下单"（业务上通常不允许）
  - 跨身份共享：A 走到状态 X 之后，B 不经任何请求就进入了 X
  - 不确定：同一状态 + 同一动作，产出两个不同状态（非原子）

## 与主动自动机学习（L*）的区别

L* 需要能等价查询（membership query）——即"这个输入序列会不会被接受"。
黑盒 Web 目标不给这个接口，你只能真发请求，而每次请求可能改变服务端状态。
所以这里不做学习，只做**观察与比对**：先按正常流程走一遍得到图，
再把图当参照去找偏离。成本低一个量级，也够用。
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .core import Response, SessionPool


@dataclass
class Transition:
    """一次状态转移。"""
    from_state: str
    action: str          # "METHOD path"
    to_state: str
    identity: str
    status: int


@dataclass
class Machine:
    """观察到的状态机。状态 = 响应结构指纹。"""
    transitions: list[Transition] = field(default_factory=list)
    # (identity, from_state, action) -> 观察到的 to_state 集合
    _observe: dict[tuple[str, str, str], set[str]] = field(default_factory=dict)
    # 每个状态被哪些身份到达过
    _reached_by: dict[str, set[str]] = field(default_factory=dict)

    def record(self, prev: Response | None, action: str, resp: Response) -> None:
        if resp.error:
            return
        from_state = prev.fingerprint if prev is not None else "START"
        to_state = resp.fingerprint
        self.transitions.append(Transition(from_state, action, to_state, resp.identity, resp.status))
        self._observe.setdefault((resp.identity, from_state, action), set()).add(to_state)
        self._reached_by.setdefault(to_state, set()).add(resp.identity)

    # ── 异常

    def nondeterministic(self) -> list[dict[str, Any]]:
        """同一身份、同一状态、同一动作，产出了不同的下一状态。

        这是**服务端非原子**的直接证据，也是最容易自动化的一条：
        不需要理解业务，只需要重复同一个动作看结果稳不稳。
        """
        out = []
        for (ident, src, action), dests in self._observe.items():
            if len(dests) > 1:
                out.append({
                    "kind": "nondeterministic-transition",
                    "identity": ident,
                    "from": src,
                    "action": action,
                    "to": sorted(dests),
                    "detail": f"same action from the same state produced {len(dests)} different states",
                })
        return out

    def shared_states(self) -> list[dict[str, Any]]:
        """同一状态被多个身份到达过。

        不一定是漏洞——公共页面本来人人可见。但如果某个状态是通过
        **写操作**到达的，而另一个身份也能到达，那就要看它是不是别人的资源。
        """
        out = []
        for state, idents in self._reached_by.items():
            if len(idents) > 1:
                out.append({
                    "kind": "shared-state",
                    "state": state,
                    "identities": sorted(idents),
                    "detail": f"{len(idents)} identities reached the same response structure",
                })
        return out

    def unexpected_edges(self, expected: list[tuple[str, str, str]]) -> list[dict[str, Any]]:
        """观测到但不在预期图里的转移。

        `expected` 是人工或模型给出的"正常流程"三元组 (identity, from_action_path, to_state)。
        实践里更常用的是"按路径前缀判断"，这里只做严格三元组比较，
        宽松版交给上层。
        """
        allowed = set(expected)
        out = []
        for t in self.transitions:
            key = (t.identity, t.action, t.to_state)
            if key not in allowed:
                out.append({
                    "kind": "unexpected-edge",
                    "identity": t.identity,
                    "action": t.action,
                    "from": t.from_state,
                    "to": t.to_state,
                    "status": t.status,
                })
        return out

    def as_dict(self) -> dict[str, Any]:
        states = {t.from_state for t in self.transitions} | {t.to_state for t in self.transitions}
        return {
            "states": len(states),
            "transitions": len(self.transitions),
            "identities": sorted({t.identity for t in self.transitions}),
            "edges": [
                {"from": t.from_state, "action": t.action, "to": t.to_state,
                 "identity": t.identity, "status": t.status}
                for t in self.transitions[:200]
            ],
            "anomalies": self.nondeterministic() + self.shared_states(),
        }

    def save(self, path: str | Path) -> None:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(self.as_dict(), ensure_ascii=False, indent=2), encoding="utf-8")


def walk_flow(pool: SessionPool, machine: Machine, *, identity: str,
              steps: list[dict[str, Any]], reset_identity: str | None = None) -> dict[str, Any]:
    """按给定步骤走一遍流程，把每一步的转移记进状态机。

    `reset_identity` 用于"另起一个身份重走同一条流程"——这是发现
    "状态被跨身份共享"的手段：A 走到的状态，B 也能到达，且 B 没有经过
    任何写操作，那这个状态很可能是 A 的资源被 B 读到了。
    """
    active = reset_identity or identity
    prev: Response | None = None
    trace = []
    for step in steps:
        method = step.get("method", "GET")
        path = step.get("path", "/")
        r = pool.send(active, method, path,
                      params=step.get("params"),
                      data=step.get("body"),
                      headers=step.get("headers"))
        action = f"{method} {path}"
        machine.record(prev, action, r)
        trace.append({
            "action": action,
            "identity": active,
            "status": r.status,
            "fingerprint": r.fingerprint,
            "error": r.error,
        })
        prev = r
    return {
        "identity": active,
        "steps": trace,
        "states_seen": len({t["fingerprint"] for t in trace}),
    }
