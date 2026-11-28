#!/usr/bin/env python3
"""资产关系图 —— 从"一堆域名"里看出"一套基础设施"。

## 为什么这层决定打哪里

实测 95 个目标里，`login.dingtalk.com` 是 9 个不同子域的共同认证入口。
这个事实本身是路径图：**任何能改进认证体系的问题，一次影响 9 个入口；
反过来，从任意一个入口摸清认证的实现，能推及其余 8 个**。

而把这些目标当成 95 个独立个体来测，就永远看不到这条线。

## 关系从哪来（都不需要额外请求）

    redirect-target  同一个跳转目标 → 共用认证/网关
    ip / cidr        同 IP 或同 /24 → 同一套基础设施（很可能同一批运维）
    tech             同 Server 头 / 同框架 → 同一套部署模板，漏洞同源
    cert             同证书 → 同一主体签发，可能跨业务线
    title-hash       同页面标题结构 → 同一套代码复制部署

前四条用已采集的数据就能算，不需要再发请求。
"""

from __future__ import annotations

import ipaddress
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Iterable


@dataclass
class Node:
    host: str
    ip: str = ""
    server: str = ""
    status: int = 0
    kind: str = ""
    redirect_to: str = ""
    tags: dict[str, Any] = field(default_factory=dict)


@dataclass
class Edge:
    src: str
    dst: str
    rel: str
    detail: str = ""


class AssetGraph:
    """资产关系图。故意做得简单——关系只有五六种，用 dict 就够。

    不引入图数据库的理由：关系数量在几百到几千的量级，
    内存里算完直接输出比建库快得多，也少一个依赖。
    """

    def __init__(self) -> None:
        self.nodes: dict[str, Node] = {}
        self.edges: list[Edge] = []

    def add(self, node: Node) -> None:
        self.nodes[node.host] = node

    # ── 建边

    def build(self) -> None:
        self.edges = []

        # 1) 同一个跳转目标 → 共用认证入口
        by_redirect: dict[str, list[str]] = defaultdict(list)
        for n in self.nodes.values():
            if n.redirect_to:
                by_redirect[n.redirect_to].append(n.host)
        for target, hosts in by_redirect.items():
            for i, a in enumerate(hosts):
                for b in hosts[i + 1:]:
                    self.edges.append(Edge(a, b, "shared-auth",
                                           f"both redirect to {target[:60]}"))

        # 2) 同一 /24 → 同一套基础设施
        by_net: dict[str, list[str]] = defaultdict(list)
        for n in self.nodes.values():
            if not n.ip:
                continue
            try:
                net = str(ipaddress.ip_network(f"{n.ip}/24", strict=False))
            except Exception:
                continue
            by_net[net].append(n.host)
        for net, hosts in by_net.items():
            if len(hosts) < 2:
                continue
            for i, a in enumerate(hosts):
                for b in hosts[i + 1:]:
                    self.edges.append(Edge(a, b, "same-subnet", net))

        # 3) 同 Server → 同一套部署模板
        by_server: dict[str, list[str]] = defaultdict(list)
        for n in self.nodes.values():
            sv = (n.server or "").strip()
            if sv and sv.lower() not in ("", "cloudflare"):
                by_server[sv].append(n.host)
        for sv, hosts in by_server.items():
            if len(hosts) < 2 or len(hosts) > 40:      # 太常见的 Server 头没有区分度
                continue
            for i, a in enumerate(hosts):
                for b in hosts[i + 1:]:
                    self.edges.append(Edge(a, b, "same-server", sv[:40]))

    # ── 查询

    def cluster_of(self, host: str) -> dict[str, Any]:
        """一个目标所在的关系簇：它和谁共享什么。"""
        rel: dict[str, list[str]] = defaultdict(list)
        for e in self.edges:
            if e.src == host:
                rel[e.rel].append(e.dst)
            elif e.dst == host:
                rel[e.rel].append(e.src)
        return {k: sorted(set(v)) for k, v in rel.items()}

    def hubs(self, limit: int = 15) -> list[dict[str, Any]]:
        """被最多关系连到的节点。这些是"从这里能辐射到最多其它资产"的入口。"""
        deg: dict[str, int] = defaultdict(int)
        for e in self.edges:
            deg[e.src] += 1
            deg[e.dst] += 1
        top = sorted(deg.items(), key=lambda kv: -kv[1])[:limit]
        return [{"host": h, "degree": d, **{"cluster": self.cluster_of(h)}} for h, d in top]

    def shared_infrastructure(self) -> list[dict[str, Any]]:
        """共用基础设施的组——打穿一个等于理解全部。"""
        groups: dict[str, set[str]] = defaultdict(set)
        for e in self.edges:
            if e.rel in ("shared-auth", "same-subnet", "same-server"):
                groups[f"{e.rel}:{e.detail}"].update([e.src, e.dst])
        out = []
        for key, hosts in sorted(groups.items(), key=lambda kv: -len(kv[1])):
            rel, _, detail = key.partition(":")
            out.append({"relation": rel, "detail": detail, "hosts": sorted(hosts), "size": len(hosts)})
        return out

    def as_dict(self) -> dict[str, Any]:
        return {
            "nodes": len(self.nodes),
            "edges": len(self.edges),
            "by_relation": _count([e.rel for e in self.edges]),
            "shared_infrastructure": self.shared_infrastructure()[:10],
            "hubs": self.hubs(10),
        }


def _count(items: Iterable[str]) -> dict[str, int]:
    out: dict[str, int] = {}
    for i in items:
        out[i] = out.get(i, 0) + 1
    return out


def build_from_records(records: Iterable[dict[str, Any]]) -> AssetGraph:
    """从 campaign 的记录直接建图。字段缺失的节点会被跳过而不是报错——
    普查阶段总有连不上的目标，不能因为一个坏记录让整张图建不出来。"""
    g = AssetGraph()
    for r in records:
        host = r.get("host")
        if not isinstance(host, str):
            continue
        extra = r.get("extra") or {}
        g.add(Node(
            host=host,
            ip=str(extra.get("ip") or ""),
            server=str(extra.get("server") or ""),
            status=int(r.get("status") or 0),
            kind=str(r.get("kind") or ""),
            redirect_to=str(extra.get("redirect_to") or ""),
        ))
    g.build()
    return g
