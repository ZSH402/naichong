#!/usr/bin/env python3
"""攻击路径图分析（Kùzu 嵌入式图数据库）。

## 为什么在 DuckDB 之上还要一层图

DuckDB 用递归 CTE 也能算传递闭包，但两类问题它做不了：

1. **枢纽分析**（chokepoint）：哪些资产被最多攻击路径穿过？这类"逐节点聚合路径"
   的查询在 SQL 里要写窗口函数叠递归，而在图里是 `MATCH p=(...)-[*]->(...)` 再按
   节点 group —— 这是图库的主场。
2. **最短路径的剪枝**：SQL 的递归 CTE 会把所有 ≤N 跳的路径全物化再排序，
   深一跳就是指数增长；图库的 `* SHORTEST` 做的是 BFS，只出一条。

两者不是替代关系：**聚合统计归 DuckDB，路径推理归图**。数据只有一份（JSONL），
两边都是读它。

## 业界参考

- **Prowler 的 Attack Paths**：基于 Cartography 的通用图 schema，并把查询模式化
  （提权子模式、网络暴露模式）。它的文档里专门警告要避免笛卡尔积——
  写法是 `MATCH (a),(b), p=...` 而不是 `MATCH (a), (b)` 后再过滤，
  否则中间结果按笛卡尔积膨胀。
- **BloodHound**：AD 攻击路径的事实标准，用 Neo4j + Cypher 表达"从低权用户到
  Domain Admin 的最短路径"。这里抄的是它的核心表达：**路径是边的序列，
  每条边带"信任了什么"**。

## Kùzu 的语法差异

Kùzu 0.11 不支持 Neo4j 的 `shortestPath()` 函数，但支持它自己的
`[:pivots* SHORTEST 1..5]` 写法。实测三种写法都通：
  - `p=(a)-[:pivots* SHORTEST 1..5]->(b)`   ← 首选，BFS 剪枝
  - `p=(a)-[:pivots*1..5]->(b) ... ORDER BY length(p) LIMIT 1`  ← 全物化后排序，数据大时慢
"""
from __future__ import annotations

import json
import os
import shutil
from typing import Any

import kuzu

from store import DEFAULT_ROOT, Asset


def Asset_host_id(host: str) -> str:
    return Asset.host_id(host)

SCHEMA = [
    "CREATE NODE TABLE IF NOT EXISTS asset("
    "  asset_id STRING, kind STRING, host STRING, port INT64,"
    "  service STRING, title STRING, PRIMARY KEY(asset_id))",
    "CREATE NODE TABLE IF NOT EXISTS finding("
    "  finding_id STRING, title STRING, severity STRING, status STRING,"
    "  PRIMARY KEY(finding_id))",
    # 发现影响资产。方向是 finding -> asset，语义是"这条发现落在哪个资产上"。
    "CREATE REL TABLE IF NOT EXISTS affects(FROM finding TO asset)",
    # 资产间的攻击跳转。trusts 是这条边的核心：下游信任了上游的什么
    # （凭据、令牌、配置文件、网络位置）。没有 trusts 的边等于"可能相关"，
    # 在报告里说服力很弱。
    "CREATE REL TABLE IF NOT EXISTS pivots(FROM asset TO asset, trusts STRING, kind STRING)",
    # 层级包含：host -> port -> url。这条边回答的是"这个 URL 跑在哪台机器的
    # 哪个端口上"，而不是"从 A 能跳到 B"。两者语义完全不同，混在一起会让
    # 攻击链里混进一堆"部署关系"，路径就不再是攻击路径了。
    "CREATE REL TABLE IF NOT EXISTS contains(FROM asset TO asset)",
]


class AttackGraph:
    """从 JSONL 构建攻击路径图。"""

    def __init__(self, root: str = DEFAULT_ROOT, db_dir: str | None = None):
        self.root = root
        self.db_dir = db_dir or os.path.join(root, "graph.db")
        # 连接只建一次。Kùzu 的 Database 打开有成本，每次查询新建不仅慢，
        # 还会因为句柄竞争产生难以理解的运行时错误。
        self._db: kuzu.Database | None = None
        self._con: kuzu.Connection | None = None
        # 建图时因端点缺失而跳过的边。调用方应当把它们打出来——
        # 静默丢失的攻击链会让"没有这条路"和"数据没对上"看起来一样。
        self.last_skipped: list[dict[str, str]] = []

    # ---------- 构建 ----------

    def build(self, fresh: bool = True) -> dict[str, int]:
        """从 JSONL 全量重建图。

        为什么全量而不是增量：一次作业的边通常几十到几百条，重建成本远低于
        维护增量一致性的复杂度。数据量真的上来了再谈增量。
        """
        # ⚠️ Kùzu 0.11 的 Database(path) 落盘是**单个文件**，不是目录。
        # 早先这里用 os.path.isdir 判断"是否已建库"，结果永远为 False，
        # 于是每次查询都触发一次全量重建，第二次就撞主键。
        if fresh and os.path.exists(self.db_dir):
            if os.path.isdir(self.db_dir):
                shutil.rmtree(self.db_dir)
            else:
                os.remove(self.db_dir)
        os.makedirs(os.path.dirname(self.db_dir) or ".", exist_ok=True)
        db = kuzu.Database(self.db_dir)
        con = kuzu.Connection(db)
        for ddl in SCHEMA:
            con.execute(ddl)

        assets = self._read("assets")
        findings = self._read("findings")
        edges = self._read("edges")

        for a in assets:
            con.execute(
                "CREATE (:asset {asset_id:$i, kind:$k, host:$h, port:$p,"
                " service:$s, title:$t})",
                {"i": a.get("asset_id", ""), "k": a.get("kind", ""),
                 "h": a.get("host", ""), "p": a.get("port"),
                 "s": a.get("service", ""), "t": a.get("title", "")},
            )
        for f in findings:
            con.execute(
                "CREATE (:finding {finding_id:$i, title:$t, severity:$s, status:$st})",
                {"i": f.get("finding_id", ""), "t": f.get("title", ""),
                 "s": f.get("severity", ""), "st": f.get("status", "")},
            )
            # 只有资产节点存在时才连边，否则 Kùzu 会因找不到端点而报错
            if f.get("asset_id"):
                con.execute(
                    "MATCH (f:finding {finding_id:$fi}), (a:asset {asset_id:$ai})"
                    " CREATE (f)-[:affects]->(a)",
                    {"fi": f["finding_id"], "ai": f["asset_id"]},
                )
        # —— 层级边：parent_id 指向谁就连一条 contains ——
        # 这一步让"孤岛"的判定变得准确：一台主机上只有端口、端口上只有 URL，
        # 它们在网络上没被扫过任何关系，但仍然是有归属的，不该算孤岛。
        known_ids = {a.get("asset_id", "") for a in assets}
        contains_linked = 0
        for a in assets:
            pid = a.get("parent_id") or ""
            if not pid or pid not in known_ids:
                continue
            con.execute(
                "MATCH (p:asset {asset_id:$p}), (c:asset {asset_id:$c})"
                " CREATE (p)-[:contains]->(c)",
                {"p": pid, "c": a["asset_id"]},
            )
            contains_linked += 1

        # 建边时端点可能不存在（asset_id 拼法不一致、或资产还没入库）。
        # Kùzu 的 MATCH...CREATE 匹配不到就安静地不建——这是**静默丢边**，
        # 比报错危险得多：图上看起来少了一条路，人却以为是"没有这条路"。
        # 所以这里先查端点是否存在，不存在就记进 skipped 一并返回。
        known = {a.get("asset_id", "") for a in assets}
        skipped: list[dict[str, str]] = []
        linked = 0
        for e in edges:
            src, dst = e.get("src", ""), e.get("dst", "")
            if not src or not dst:
                skipped.append({"edge": f"{src}->{dst}", "why": "端点为空"})
                continue
            if src not in known or dst not in known:
                missing = [x for x in (src, dst) if x not in known]
                skipped.append({"edge": f"{src}->{dst}", "why": f"端点不存在: {missing}"})
                continue
            con.execute(
                "MATCH (a:asset {asset_id:$s}), (b:asset {asset_id:$d})"
                " CREATE (a)-[:pivots {trusts:$t, kind:$k}]->(b)",
                {"s": src, "d": dst, "t": e.get("trusts", ""), "k": e.get("kind", "")},
            )
            linked += 1
        counts = {
            "assets": len(assets), "findings": len(findings),
            "edges": len(edges), "linked": linked, "skipped": len(skipped),
            "contains": contains_linked,
        }
        self.last_skipped = skipped
        # 建完就缓存连接；后续查询直接复用，不再重开
        self._db, self._con = db, con
        return counts

    def _read(self, name: str) -> list[dict[str, Any]]:
        """读 JSONL 并在**读时**按主键去重。

        JSONL 本身刻意是 append-only 的：同一条资产被多轮观测到就多写一行，
        那是历史，不该在写的时候覆盖。但建图需要的是「当前视图」，
        而 Kùzu 的主键约束不允许重复——所以去重放在这里，写侧保持纯粹。

        这个 bug 是实测撞出来的：nmap 和 httpx 各跑一次，两边都会产出
        host:10.0.0.5，建图直接报 duplicated primary key。
        """
        p = os.path.join(self.root, f"{name}.jsonl")
        if not os.path.exists(p):
            return []
        key_of = {"assets": "asset_id", "findings": "finding_id",
                  "evidence": "evidence_id"}.get(name)
        merged: dict[str, dict[str, Any]] = {}
        order: list[str] = []
        with open(p, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                k = str(rec.get(key_of, "")) if key_of else ""
                if not k:
                    order.append(str(len(order)))     # 无主键的行原样保留
                    merged[str(len(merged))] = rec
                    continue
                if k not in merged:
                    order.append(k)
                merged[k] = rec                       # 后写的覆盖前写的 = 更新的观测
        return [merged[k] for k in order]

    # ---------- 查询 ----------

    def _conn(self) -> kuzu.Connection:
        if self._con is not None:
            return self._con
        if not os.path.exists(self.db_dir):
            self.build()
            return self._con  # type: ignore[return-value]
        self._db = kuzu.Database(self.db_dir)
        self._con = kuzu.Connection(self._db)
        return self._con

    def _rows(self, query: str, params: dict | None = None) -> list[Any]:
        con = self._conn()
        r = con.execute(query, params or {})
        rows = []
        while r.has_next():
            rows.append(r.get_next())
        return rows

    def reachable_from(self, entry: str, max_hops: int = 5) -> list[dict[str, Any]]:
        """从某个入口出发能到达的资产，按跳数排序。"""
        rows = self._rows(
            f"MATCH (a:asset {{asset_id:$e}})-[p:pivots*1..{int(max_hops)}]->(b:asset)"
            " RETURN b.asset_id, b.kind, length(p) ORDER BY length(p)",
            {"e": entry},
        )
        return [{"asset_id": r[0], "kind": r[1], "hops": r[2]} for r in rows]

    def shortest_path(self, src: str, dst: str, max_hops: int = 6) -> list[dict[str, Any]]:
        """两点之间最短攻击路径。

        用 Kùzu 的 SHORTEST 关键字（BFS 剪枝），不是全物化后排序——
        后者在深路径上会指数爆炸。
        """
        rows = self._rows(
            f"MATCH (a:asset {{asset_id:$s}}),(b:asset {{asset_id:$d}}),"
            f" p=(a)-[:pivots* SHORTEST 1..{int(max_hops)}]->(b)"
            " RETURN nodes(p)",
            {"s": src, "d": dst},
        )
        if not rows:
            return []
        nodes = rows[0][0] or []
        return [{"asset_id": n.get("asset_id"), "kind": n.get("kind")} for n in nodes]

    def chokepoints(self, limit: int = 10) -> list[dict[str, Any]]:
        """枢纽资产：被最多"其它资产出发的路径"穿过的节点。

        这是图库相对 SQL 递归 CTE 的真正增量——"逐节点聚合路径"在 SQL 里
        要窗口函数叠递归，在这里是一句 group by。
        """
        rows = self._rows(
            "MATCH (a:asset)-[p:pivots*1..4]->(m:asset)"
            " RETURN m.asset_id, count(p) AS hits ORDER BY hits DESC LIMIT "
            + str(int(limit))
        )
        return [{"asset_id": r[0], "paths_through": r[1]} for r in rows]

    def isolated_assets(self) -> list[dict[str, Any]]:
        """孤岛：没有任何跳转边、也没有任何发现的资产。

        对应"扫描到了但完全没碰"——这是下一轮最该看的地方。
        """
        # 孤岛 = 在网络关系上完全孤立。层级边（contains）不算"关系"——
        # 一个端口挂在主机下并不能说明它被探查过，所以只有 pivots 和 findings
        # 能把它从孤岛里救出来。但 contains 的存在会让"主机"节点本身
        # 因为"有子节点"而显得不孤立，这是对的：有子节点的主机显然被关注过。
        rows = self._rows(
            "MATCH (a:asset)"
            " WHERE NOT EXISTS { MATCH (a)-[:pivots]->(:asset) }"
            "   AND NOT EXISTS { MATCH (a)<-[:pivots]-(:asset) }"
            "   AND NOT EXISTS { MATCH (:finding)-[:affects]->(a) }"
            "   AND NOT EXISTS { MATCH (a)-[:contains]->(:asset) }"
            " RETURN a.asset_id, a.kind, a.service"
        )
        return [{"asset_id": r[0], "kind": r[1], "service": r[2]} for r in rows]

    def paths_to_severity(self, severity: str = "critical",
                          max_hops: int = 4) -> list[dict[str, Any]]:
        """通往带指定严重性发现的资产的所有路径。

        报告里最有用的一张表：从任意资产出发，几步能摸到 critical。
        """
        rows = self._rows(
            f"MATCH p=(a:asset)-[:pivots*1..{int(max_hops)}]->(b:asset)"
            " <-[:affects]-(f:finding)"
            " WHERE f.severity = $sev"
            " RETURN a.asset_id, b.asset_id, f.title, length(p)"
            " ORDER BY length(p)",
            {"sev": severity},
        )
        return [{"from": r[0], "to": r[1], "finding": r[2], "hops": r[3]} for r in rows]

    def host_assets(self, host: str) -> list[dict[str, Any]]:
        """某台主机下的全部资产（端口 + URL），按层级展开。

        这是加了 contains 边之后才可能的问题：以前只能按字符串前缀 grep
        `10.0.0.5`，会把 `10.0.0.55` 也匹配进来。
        """
        rows = self._rows(
            "MATCH (h:asset {asset_id:$h})-[:contains]->(p:asset)"
            " OPTIONAL MATCH (p)-[:contains]->(u:asset)"
            " RETURN p.asset_id, p.kind, p.service, u.asset_id, u.title",
            {"h": Asset_host_id(host)},
        )
        out: dict[str, dict[str, Any]] = {}
        for pid, pkind, svc, uid, utitle in rows:
            if pid and pid not in out:
                out[pid] = {"asset_id": pid, "kind": pkind, "service": svc, "children": []}
            if uid and pid in out:
                out[pid]["children"].append({"asset_id": uid, "title": utitle})
        return list(out.values())

    def summary(self) -> dict[str, int]:
        def one(q: str) -> int:
            rows = self._rows(q)
            return int(rows[0][0]) if rows else 0
        return {
            "assets": one("MATCH (a:asset) RETURN count(a)"),
            "findings": one("MATCH (f:finding) RETURN count(f)"),
            "pivots": one("MATCH ()-[p:pivots]->() RETURN count(p)"),
            "contains": one("MATCH ()-[c:contains]->() RETURN count(c)"),
            "isolated": len(self.isolated_assets()),
        }


def _main() -> int:
    import argparse

    ap = argparse.ArgumentParser(description="攻击路径图分析（Kùzu）")
    ap.add_argument("--root", default=DEFAULT_ROOT)
    ap.add_argument("--build", action="store_true", help="从 JSONL 重建图")
    ap.add_argument("--summary", action="store_true")
    ap.add_argument("--from", dest="entry", default="", help="列出从该资产可达的")
    ap.add_argument("--path", nargs=2, default=[], metavar=("SRC", "DST"),
                    help="两点最短攻击路径")
    ap.add_argument("--chokepoints", action="store_true", help="枢纽资产")
    ap.add_argument("--isolated", action="store_true", help="孤岛资产（完全没碰）")
    ap.add_argument("--critical-paths", action="store_true", help="通往 critical 的路径")
    ap.add_argument("--host", default="", help="展开某台主机下的端口与 URL")
    a = ap.parse_args()

    g = AttackGraph(a.root)
    if a.build:
        print("构建:", g.build())
    if a.summary:
        print("图概况:", g.summary())
    if a.entry:
        for r in g.reachable_from(a.entry):
            print(f"  {r['hops']} 跳 -> {r['asset_id']}（{r['kind']}）")
    if a.path:
        p = g.shortest_path(a.path[0], a.path[1])
        print("  最短路径:", " -> ".join(x["asset_id"] or "" for x in p) or "（不可达）")
    if a.chokepoints:
        for r in g.chokepoints():
            print(f"  {r['asset_id']:<36} 被 {r['paths_through']} 条路径穿过")
    if a.isolated:
        for r in g.isolated_assets():
            print(f"  {r['asset_id']:<36} {r['kind']:<6} {r['service']}")
    if a.host:
        for p_ in g.host_assets(a.host):
            print(f"  {p_['asset_id']:<28} {p_['kind']:<6} {p_['service']}")
            for ch in p_["children"]:
                print(f"      -> {ch['asset_id']}  {ch['title']}")
    if a.critical_paths:
        for r in g.paths_to_severity():
            print(f"  [{r['hops']}] {r['from']} -> {r['to']}  ({r['finding']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
