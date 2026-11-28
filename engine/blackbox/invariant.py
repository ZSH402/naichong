#!/usr/bin/env python3
"""不变量验证 —— 把状态机生成的测试点变成可执行的检查。

## 无害化是这里的第一个约束，不是最后一个

`bizmodel` 生成的测试点里，大部分需要**真的创建对象、真的重复提交**。
对一个生产系统来说那是写操作：会留下垃圾数据、会触发业务通知、
极端情况下会扣钱。

所以执行器默认 **allow_write=False**，只跑不产生数据的测试：
  - `skip-create`   对不存在的对象调动作 → 服务端应当 404/403，不产生任何记录
  - `post-delete`   仅在对象本来就不存在时等价于 skip-create

需要真写入的（cross-object / repeat / duplicate-create）会被**列出来但不执行**，
并明确标注"要做这条需要写入权限的确认"。

## 判定为什么只用状态码

理想判据是"数据归属变了没有"，但那需要读别人的数据——正好是我们要避免的事。
所以这里退一步：**只看"这一步该不该被允许"**。

  skip-create 返回 2xx  →  异常（该对象不存在却能对该对象执行动作）
  skip-create 返回 4xx  →  符合预期

状态码判据弱，但它不接触数据，而且能把"明显不对的"筛出来。
真正的确认留给人工或后续带凭据的定向测试。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from .core import SessionPool
from .credentials import CredentialPool
from .guard import RateLimit


@dataclass
class Case:
    """一条可执行的检查。"""
    test: str
    method: str
    path: str
    resource: str = ""
    action: str = ""
    how: str = ""
    expect_if_safe: str = ""
    priority: int = 0
    writes_data: bool = False
    needs_identity: bool = False


@dataclass
class Outcome:
    """一条检查的结果。"""
    case: Case
    executed: bool
    status: int = 0
    verdict: str = "skipped"        # ok / suspicious / unknown / skipped
    reason: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "test": self.case.test,
            "action": f"{self.case.method} {self.case.path}",
            "executed": self.executed,
            "status": self.status,
            "verdict": self.verdict,
            "reason": self.reason[:160],
        }


def _to_cases(items: Iterable[dict[str, Any]]) -> list[Case]:
    """把 bizmodel 的测试点转成 Case。跳过缺 method/path 的（read-write-asymmetry 那类）。"""
    out: list[Case] = []
    for it in items:
        act = str(it.get("action", ""))
        if " " not in act:
            continue                       # 描述性条目，不含具体请求
        method, _, path = act.partition(" ")
        # 把 {id} / <id> / 123 占位统一替换成一个不可能存在的 id
        for ph in ("{id}", "<id>", ":id"):
            path = path.replace(ph, "999999999")
        out.append(Case(
            test=str(it.get("test", "")),
            method=method.strip().upper(),
            path=path.strip(),
            resource=str(it.get("resource", "")),
            action=act,
            how=str(it.get("how", "")),
            expect_if_safe=str(it.get("expect_if_safe", "")),
            priority=int(it.get("priority", 0)),
            writes_data=bool(it.get("writes_data")),
            needs_identity=bool(it.get("needs_identity")),
        ))
    return out


def run(items: Iterable[dict[str, Any]], pool: SessionPool, *,
        creds: CredentialPool | None = None,
        rate: RateLimit | None = None,
        allow_write: bool = False,
        max_cases: int = 30) -> dict[str, Any]:
    """执行检查。

    `allow_write=False`（默认）时，写数据的用例只列不跑。
    """
    cases = _to_cases(items)[:max_cases]
    outcomes: list[Outcome] = []

    # 选身份：有验证过的凭据就用它，否则匿名
    ident = "anonymous"
    if creds is not None:
        usable = creds.usable()
        if usable:
            ident = usable[0].name

    for c in cases:
        if c.writes_data and not allow_write:
            outcomes.append(Outcome(c, executed=False, verdict="skipped",
                                    reason="would write data — needs explicit approval "
                                           "(pass allow_write=true) before running"))
            continue
        if c.needs_identity and (creds is None or not creds.usable()):
            outcomes.append(Outcome(c, executed=False, verdict="skipped",
                                    reason="requires a verified credential — without one this "
                                           "compares two anonymous sessions and always says 'no difference'"))
            continue
        if rate is not None and not rate.acquire(timeout=30):
            outcomes.append(Outcome(c, executed=False, verdict="unknown", reason="rate limited"))
            continue

        r = pool.send(ident, c.method, c.path)
        if rate is not None:
            rate.record(r.error == "")
        if r.error:
            outcomes.append(Outcome(c, executed=True, verdict="unknown",
                                    reason=f"request failed: {r.error[:80]}"))
            continue

        ok_status = 200 <= r.status < 300
        if c.test in ("skip-create", "post-delete"):
            if ok_status:
                outcomes.append(Outcome(c, executed=True, status=r.status, verdict="suspicious",
                                        reason=f"action succeeded ({r.status}) on an object that should not "
                                               f"exist — check whether it created a record"))
            elif r.status in (400, 401, 403, 404, 409, 410, 422):
                outcomes.append(Outcome(c, executed=True, status=r.status, verdict="ok",
                                        reason=f"rejected with {r.status}, as expected"))
            else:
                outcomes.append(Outcome(c, executed=True, status=r.status, verdict="unknown",
                                        reason=f"unexpected status {r.status}"))
        else:
            outcomes.append(Outcome(c, executed=True, status=r.status, verdict="unknown",
                                    reason=f"{r.status} — this test needs a semantic judgement, "
                                           f"status code alone is not decisive"))

    suspicious = [o for o in outcomes if o.verdict == "suspicious"]
    return {
        "identity": ident,
        "cases": len(cases),
        "executed": len([o for o in outcomes if o.executed]),
        "skipped_write": len([o for o in outcomes if o.verdict == "skipped" and o.case.writes_data]),
        "suspicious": len(suspicious),
        "results": [o.as_dict() for o in outcomes],
        "note": (
            "no write-capable test was run — that is the safe default, not a sign the target is "
            "free of business-logic flaws"
            if not allow_write else
            "write-capable tests were allowed; verify the target tolerates this"
        ),
    }
