#!/usr/bin/env python3
"""业务状态机建模 —— 从端点清单推出"这个业务有哪些状态、怎么转"。

## 换起点的关键一步

老套做法的起点是"端点 → 套 payload"。起点错了，因为现代系统的漏洞不在
单个请求的格式上，而在**请求序列的合法性**上：单独看每一步都合规，
连起来就越权了。

要测序列，先得有模型。这个模块从端点清单里推三样东西：

    资源   /api/order/<id>          → 资源 order
    动作   /api/order/<id>/pay      → 动作 pay（状态转换）
    归属   /api/order/<id>          → 带了对象标识，说明有归属概念

## 状态怎么来（不用 LLM，全部确定性）

从**动词语义**推：POST 创建、PUT/PATCH 更新、DELETE 删除、带动作段的路径是转换。
这套映射在 REST 里足够稳定，推不准的（比如全 POST 的 RPC 风格）就标为未知，
不硬猜——**猜错的状态机会生成一堆无效测试，比没有模型更耗时间**。

## 输出的用途

`Transition` 里的 `requires` 是"这一步在业务上需要什么前置状态"。
测试就是**绕过这些前置**：直接调终态动作、重复调创建、跨状态回退。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable

# 路径段里的对象标识形态：纯数字、UUID、以及常见的 {id} 占位
_OBJ_ID = re.compile(r"^(?:\d+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
                     r"|\{[a-zA-Z_]+\}|:[a-zA-Z_]+|<[a-zA-Z_]+>)$", re.I)

# 动作段：路径最后一段是动词时，说明它是状态转换而不是资源
_VERBS = {
    "create", "add", "new", "submit", "save", "update", "edit", "modify",
    "delete", "remove", "destroy", "cancel", "close", "reopen",
    "approve", "reject", "confirm", "verify", "validate", "audit",
    "pay", "refund", "charge", "transfer", "settle",
    "publish", "unpublish", "archive", "restore", "revert",
    "enable", "disable", "activate", "deactivate", "lock", "unlock",
    "send", "resend", "invite", "join", "leave", "quit",
    "upload", "download", "export", "import", "share", "copy", "move",
    "reset", "retry", "start", "stop", "pause", "resume", "run", "exec",
}

# 这些动作在业务上通常是"不可逆"或"有副作用"的——测试优先级更高
IRREVERSIBLE = {"pay", "refund", "charge", "transfer", "settle", "delete",
                "remove", "destroy", "approve", "confirm", "publish"}


@dataclass
class Action:
    """一个端点上的一次操作。"""
    method: str
    path: str
    resource: str = ""          # 动作作用的资源
    verb: str = ""              # 动作名（路径最后一段是动词时）
    object_id: str = ""         # 路径里的对象标识占位（有则说明是"对某个具体对象"）
    has_own_object: bool = False  # 路径里出现了对象标识

    @property
    def key(self) -> str:
        return f"{self.method} {self.path}"

    @property
    def is_state_change(self) -> bool:
        """是否改变服务端状态。GET 不改，其余基本都改。"""
        return self.method.upper() not in ("GET", "HEAD", "OPTIONS")

    def as_dict(self) -> dict[str, Any]:
        return {"method": self.method, "path": self.path, "resource": self.resource,
                "verb": self.verb, "object_slot": self.object_id}


@dataclass
class Transition:
    """一次状态转换及其业务前置。"""
    action: Action
    requires: list[str] = field(default_factory=list)   # 业务上需要的前置状态
    produces: str = ""                                  # 转换后的状态标签
    irreversible: bool = False
    rationale: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "action": self.action.key,
            "resource": self.action.resource,
            "requires": self.requires,
            "produces": self.produces,
            "irreversible": self.irreversible,
            "why": self.rationale,
        }


@dataclass
class ResourceModel:
    """一个资源的模型。"""
    name: str
    create: list[Action] = field(default_factory=list)
    read: list[Action] = field(default_factory=list)
    update: list[Action] = field(default_factory=list)
    delete: list[Action] = field(default_factory=list)
    transitions: list[Transition] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "resource": self.name,
            "create": [a.key for a in self.create],
            "read": [a.key for a in self.read],
            "update": [a.key for a in self.update],
            "delete": [a.key for a in self.delete],
            "transitions": [t.as_dict() for t in self.transitions],
        }


def parse_action(method: str, path: str) -> Action:
    """把 (method, path) 解析成结构化的动作。"""
    clean = path.split("?")[0].split("#")[0]
    segs = [s for s in clean.split("/") if s]
    act = Action(method=method.upper(), path=clean)

    # 资源名：第一个非 api/vN 的静态段
    res_idx = -1
    for i, seg in enumerate(segs):
        low = seg.lower()
        if low in ("api", "v1", "v2", "v3", "v4", "rest", "open", "internal", "public"):
            continue
        if _OBJ_ID.match(seg):
            continue
        res_idx = i
        act.resource = low
        break

    # 对象标识：资源段之后出现的 id 形态
    if res_idx >= 0:
        for seg in segs[res_idx + 1:]:
            if _OBJ_ID.match(seg):
                act.object_id = seg
                act.has_own_object = True
                break

    # 动词：最后一段是已知动词
    if segs:
        last = segs[-1].lower()
        if last in _VERBS:
            act.verb = last

    return act


def build(actions: Iterable[tuple[str, str]]) -> dict[str, ResourceModel]:
    """从端点清单建资源模型。

    输入是 (method, path) 序列——这个数据普查阶段已经采到了。
    """
    models: dict[str, ResourceModel] = {}
    seen: set[str] = set()

    for method, path in actions:
        a = parse_action(method, path)
        if a.key in seen:
            continue
        seen.add(a.key)
        if not a.resource:
            continue
        m = models.setdefault(a.resource, ResourceModel(name=a.resource))

        m_method = a.method.upper()
        if m_method in ("GET", "HEAD"):
            m.read.append(a)
            continue
        if a.verb in ("delete", "remove", "destroy"):
            m.delete.append(a)
            continue
        if a.verb in ("update", "edit", "modify", "save"):
            m.update.append(a)
            continue
        if a.verb:
            # 状态转换动作：需要对象已存在
            t = Transition(
                action=a,
                requires=[f"{a.resource}:exists"] if a.has_own_object or a.object_id else [],
                produces=f"{a.resource}:{a.verb}",
                irreversible=a.verb in IRREVERSIBLE,
                rationale=(f"'{a.verb}' 是对已存在对象的动作——单独调用它只有当对象处于"
                           f"合法前置状态时才该成功。测试点：对象不存在时调用、"
                           f"对象属于别人时调用、重复调用"),
            )
            m.transitions.append(t)
            continue
        if m_method == "POST":
            m.create.append(a)
            continue
        if m_method in ("PUT", "PATCH"):
            m.update.append(a)
            continue

    return models


def illegal_transitions(models: dict[str, ResourceModel]) -> list[dict[str, Any]]:
    """列出所有"值得测的非法跃迁"。

    这不是漏洞列表，是**测试清单**。每一条都要实际发请求才能判真假。
    """
    out: list[dict[str, Any]] = []
    for res, m in models.items():
        for t in m.transitions:
            a = t.action
            base = {"resource": res, "action": a.key, "verb": a.verb}

            # 1. 没有对象 → 直接调动作（跳过创建）
            out.append({**base, "test": "skip-create",
                        "how": f"以不存在的 {a.object_id or '<id>'} 调 {a.key}",
                        "expect_if_safe": "404/403，而不是 200 或创建出记录",
                        "priority": 8 if t.irreversible else 6})

            # 2. 重复调用（幂等性）
            out.append({**base, "test": "repeat",
                        "how": f"同一对象连续两次 {a.key}",
                        "expect_if_safe": "第二次应 409/幂等返回同一结果，而不是产生第二条记录",
                        "priority": 9 if t.irreversible else 5,
                        # 重复调用一个真实的动作 = 真的执行两次。会改数据。
                        "writes_data": True})

            # 3. 跨对象（用别人的对象 id）
            if a.has_own_object:
                out.append({**base, "test": "cross-object",
                            "how": f"用身份 B 的凭据对身份 A 的对象调 {a.key}",
                            "expect_if_safe": "403，而不是 200",
                            "priority": 10,
                            # 需要先由 A 创建真对象 → 写数据
                            "writes_data": True, "needs_identity": True})

            # 4. 回退（删了之后再调）
            if m.delete:
                out.append({**base, "test": "post-delete",
                            "how": f"先 DELETE 该对象，再调 {a.key}",
                            "expect_if_safe": "404/410，而不是仍能转换",
                            "priority": 7, "writes_data": True})

        # 5. 创建类接口的重复提交（防重复下单/重复注册）
        for c in m.create:
            out.append({"resource": res, "action": c.key, "test": "duplicate-create",
                        "how": f"同一参数连续两次 {c.key}",
                        "expect_if_safe": "第二次应被拒（幂等键/唯一约束），而不是产生两条",
                        "priority": 9 if any(k in res for k in ("order", "pay", "book", "apply")) else 6,
                        "writes_data": True})

        # 6. 只读资源却存在写动作（权限模型可疑）
        if m.read and (m.update or m.delete) and any(a.has_own_object for a in m.read):
            out.append({"resource": res, "action": f"{len(m.read)} read + write ops",
                        "test": "read-write-asymmetry",
                        "how": f"{res} 同时对不同对象提供读写，检查读接口是否校验归属",
                        "expect_if_safe": "读接口也校验归属，而不只是写接口",
                        "priority": 8})

    out.sort(key=lambda x: -int(x.get("priority", 0)))
    return out
