#!/usr/bin/env python3
"""扫描产物的统一存储与查询层（DuckDB）。

## 为什么要这一层

在这之前，一次作业的产物散在文件系统里：nmap 的 XML、httpx 的 JSONL、ffuf 的 JSON、
每个动作落盘的证据目录。要回答"这个网段还有哪些没打穿"、"哪些资产同时开了 22 和 3389"，
只能现写 Python 或者 grep 一堆文件。

## 业界怎么做的（两个共识）

参考 [DuckDB for Security Engineers](https://jaredgore.com/blog/duckdb-intro/) 的做法，
成熟实践有两个共同点：

1. **不建表导入，用 VIEW 直接映射文件。** 扫描产物是持续产生的，每次导入一遍
   （ETL）本身就是负担；DuckDB 能直接 `read_json_auto('xxx.jsonl')`，
   数据一落盘就能查。
2. **字段标准化再 JOIN。** 不同工具对同一个概念的叫法不同（resource_id / AssetID），
   用 CREATE VIEW 把各自映射到统一列名，之后所有查询都打在统一视图上。

对 10 万条 findings，DuckDB 约 2 秒，等价 Python 脚本 20 秒以上——差别不在快，
在于**查询是交互式的**，可以边看边改，而写脚本每次都要重跑。

## 分工

- **Python 负责解析**：nmap XML / httpx JSONL / ffuf JSON 的格式差异在这里吃掉，
  统一落成规范化 JSONL（可增量追加，天然 append-only，符合证据不许改写的性质）
- **DuckDB 负责查询**：只读规范化后的 JSONL，SQL 随意切
"""
from __future__ import annotations

import json
import os
import xml.etree.ElementTree as ET
from typing import Any, Iterable, Literal

import duckdb
from pydantic import BaseModel, ConfigDict, Field

# —————————————————————— 规范化模型 ——————————————————————

AssetKind = Literal["host", "port", "url"]
FindingStatus = Literal["open", "accepted", "rejected", "inconclusive"]
Severity = Literal["critical", "high", "medium", "low", "info"]


class Asset(BaseModel):
    """一个可被攻击的对象。

    `asset_id` 是稳定标识：host 用 IP，port 用 ip:port，url 用 URL 本身。
    之所以要求稳定，是为了让 findings / evidence 能挂上去，且跨轮次能对齐。
    """

    model_config = ConfigDict(extra="forbid")

    asset_id: str
    kind: AssetKind
    host: str = ""
    port: int | None = None
    scheme: str = ""
    service: str = ""
    product: str = ""
    version: str = ""
    title: str = ""
    status_code: int | None = None
    source: str = ""
    note: str = ""
    # 父资产的 asset_id。三层模型：host -> port -> url。
    #
    # 为什么需要它：实测发现 `10.0.0.5:80`（端口）和 `http://10.0.0.5/`（URL）
    # 根本是同一个东西的两个视角，但 asset_id 拼法不同，在图上成了两个互不相连
    # 的节点。结果端口类资产全部显示为"孤岛"，而它们其实和 URL 有明确关系。
    # 加上父指针之后，"这个 URL 跑在哪台主机的哪个端口上"就是图里的边，不再靠猜。
    parent_id: str = ""

    @staticmethod
    def host_id(host: str) -> str:
        return f"host:{host}"

    @classmethod
    def for_host(cls, host: str, source: str = "") -> "Asset":
        """主机节点。三个构造函数里只有它用 `host:` 前缀，避免和 `ip:port` 混淆。"""
        return cls(asset_id=cls.host_id(host), kind="host", host=host, source=source)

    @classmethod
    def for_port(cls, host: str, port: int, service: str = "",
                 product: str = "", version: str = "", source: str = "") -> "Asset":
        return cls(asset_id=f"{host}:{port}", kind="port", host=host, port=port,
                   service=service, product=product, version=version, source=source,
                   parent_id=cls.host_id(host))

    @classmethod
    def for_url(cls, url: str, title: str = "", status_code: int | None = None,
                source: str = "") -> "Asset":
        scheme, host, port = _split_url(url)
        # 有显式端口就挂到端口节点下，否则挂到主机的默认端口上。
        # 默认端口按 scheme 推（http=80 / https=443），推不出来就挂主机。
        if port is None:
            port = {"http": 80, "https": 443}.get(scheme)
        parent = f"{host}:{port}" if port else cls.host_id(host)
        return cls(asset_id=url, kind="url", host=host, port=port, scheme=scheme,
                   title=title, status_code=status_code, source=source,
                   parent_id=parent)


class Finding(BaseModel):
    """一条发现。severity 用词与业界一致，便于和外部报告对齐。"""

    model_config = ConfigDict(extra="forbid")

    finding_id: str
    asset_id: str
    title: str
    severity: Severity = "info"
    status: FindingStatus = "open"
    detail: str = ""
    evidence_id: str = ""
    source: str = ""


class Evidence(BaseModel):
    """一条证据。只追加，不覆盖——证据被改写就不再是证据。"""

    model_config = ConfigDict(extra="forbid")

    evidence_id: str
    command: str = ""
    stdout_path: str = ""
    ts: str = ""
    note: str = ""


class Edge(BaseModel):
    """资产/发现之间的关系。

    `trusts` 描述下游信任了上游的什么（哪个字段、哪个令牌、哪个标识）——
    这是攻击链的核心，不是简单的"有连接"。
    """

    model_config = ConfigDict(extra="forbid")

    src: str
    dst: str
    kind: str = ""
    trusts: str = ""


def _split_url(url: str) -> tuple[str, str, int | None]:
    """拆出 (scheme, host, port)。端口缺省返回 None，由调用方按 scheme 推。"""
    scheme = url.split("://", 1)[0].lower() if "://" in url else ""
    rest = url.split("://", 1)[-1]
    netloc = rest.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    host, _, port_s = netloc.rpartition(":")
    if not host:            # 没有冒号
        return scheme, netloc, None
    try:
        return scheme, host, int(port_s)
    except ValueError:      # IPv6 或非数字端口，退回整体当 host
        return scheme, netloc, None


# —————————————————————— 解析器：各工具输出 → 规范化记录 ——————————————————————

def parse_nmap_xml(path: str) -> list[Asset]:
    """解析 nmap -oX 的 XML 输出。

    只取 open 端口：closed/filtered 对攻击面没有直接意义，留在库里只是噪音。
    """
    out: list[Asset] = []
    try:
        root = ET.parse(path).getroot()
    except (ET.ParseError, OSError):
        return out
    for host in root.iter("host"):
        addr = host.find("address")
        if addr is None:
            continue
        ip = addr.get("addr", "")
        # 先产主机节点：三层模型的根。没有它，端口和 URL 之间就没有共同祖先，
        # "这台机器上有什么"就退化成按字符串前缀猜。
        if ip:
            out.append(Asset.for_host(ip, source="nmap"))
        for port in host.iter("port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            svc = port.find("service")
            out.append(Asset.for_port(
                host=ip,
                port=int(port.get("portid", "0")),
                service=(svc.get("name", "") if svc is not None else ""),
                product=(svc.get("product", "") if svc is not None else ""),
                version=(svc.get("version", "") if svc is not None else ""),
                source="nmap",
            ))
    return out


def parse_httpx_jsonl(path: str) -> list[Asset]:
    """解析 httpx 的 -json 输出（每行一个 JSON 对象）。"""
    out: list[Asset] = []
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                except ValueError:
                    continue
                url = d.get("url") or d.get("input") or ""
                if not url:
                    continue
                a = Asset.for_url(
                    url=url,
                    title=str(d.get("title") or ""),
                    status_code=d.get("status_code"),
                    source="httpx",
                )
                out.append(a)
                # 同时补端口与主机节点：只发现 URL 而没扫端口是常态，
                # 缺了父节点这条 URL 在图里就是孤岛。
                if a.host:
                    out.append(Asset.for_host(a.host, source="httpx"))
                    if a.port:
                        out.append(Asset.for_port(a.host, a.port,
                                                  service=a.scheme, source="httpx"))
    except OSError:
        pass
    return out


def parse_ffuf_json(path: str) -> list[Asset]:
    """解析 ffuf 的 -of json 输出。

    ffuf 的输出是 {"results": [...]}；每个 result 有 url / status / length。
    这里把它当成"发现了一个可访问的 URL"来看，而不是"一个漏洞"——
    有没有漏洞要靠人（或后续分析）判断，不能由工具名决定。
    """
    out: list[Asset] = []
    try:
        d = json.load(open(path, encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return out
    for r in d.get("results") or []:
        url = r.get("url") or ""
        if not url:
            continue
        a = Asset.for_url(url=url, status_code=r.get("status"), source="ffuf")
        out.append(a)
        if a.host:
            out.append(Asset.for_host(a.host, source="ffuf"))
            if a.port:
                out.append(Asset.for_port(a.host, a.port,
                                          service=a.scheme, source="ffuf"))
    return out


# —————————————————————— 存储 ——————————————————————

DEFAULT_ROOT = "/root/tpctf/findings"


class Store:
    """一次作业的数据仓库：规范化 JSONL + DuckDB 视图。

    目录结构（append-only，便于审计和回放）：
        <root>/assets.jsonl
        <root>/findings.jsonl
        <root>/evidence.jsonl
        <root>/edges.jsonl
    """

    def __init__(self, root: str = DEFAULT_ROOT):
        self.root = root
        os.makedirs(root, exist_ok=True)
        self.con = duckdb.connect()  # 内存库，数据始终以文件为准
        self._views_ready = False

    # ---------- 写入 ----------

    def _path(self, name: str) -> str:
        return os.path.join(self.root, f"{name}.jsonl")

    def append(self, name: Literal["assets", "findings", "evidence", "edges"],
               records: Iterable[BaseModel]) -> int:
        """追加记录。

        同一次 append 内按 asset_id 去重（保留最后一条）：解析器现在会为同一个
        主机/端口产出多条（nmap 一台机器一条、httpx 一个 URL 一条），不去重会在
        Kùzu 里撞主键。跨次 append 的重复仍然保留——那是不同时刻的观测，
        属于历史，不该被覆盖。
        """
        n = 0
        seen: set[str] = set()
        rows: list[BaseModel] = []
        for r in records:
            # 去重要用**同一套字段**取和比。
            # 早先 key 兼容 asset_id / finding_id / evidence_id，
            # 但过滤重复时硬编码成 getattr(x, "asset_id")——finding 和 evidence
            # 根本没有 asset_id，比较恒为 True，于是重复项一条都没去掉。
            key = ""
            for attr in ("asset_id", "finding_id", "evidence_id"):
                v = getattr(r, attr, None)
                if v:
                    key = str(v)
                    break
            if key and key in seen:
                rows = [x for x in rows if not any(
                    str(getattr(x, a, "") or "") == key
                    for a in ("asset_id", "finding_id", "evidence_id"))]
            if key:
                seen.add(key)
            rows.append(r)
        with open(self._path(name), "a", encoding="utf-8") as fh:
            for r in rows:
                fh.write(json.dumps(r.model_dump(), ensure_ascii=False) + "\n")
                n += 1
        self._views_ready = False  # 有新数据，视图需重建
        return n

    # ---------- 视图 ----------

    def ensure_views(self) -> None:
        """建视图。用 VIEW 而不是表：数据始终以 JSONL 为准，
        视图只是查询入口——这样任何一次追加都立刻可查，不需要导入步骤。"""
        if self._views_ready:
            return
        for name, ddl in (
            ("assets", "asset_id VARCHAR, kind VARCHAR, host VARCHAR, port INTEGER, "
                       "scheme VARCHAR, service VARCHAR, product VARCHAR, version VARCHAR, "
                       "title VARCHAR, status_code INTEGER, source VARCHAR, note VARCHAR"),
            ("findings", "finding_id VARCHAR, asset_id VARCHAR, title VARCHAR, "
                         "severity VARCHAR, status VARCHAR, detail VARCHAR, "
                         "evidence_id VARCHAR, source VARCHAR"),
            ("evidence", "evidence_id VARCHAR, command VARCHAR, stdout_path VARCHAR, "
                         "ts VARCHAR, note VARCHAR"),
            ("edges", "src VARCHAR, dst VARCHAR, kind VARCHAR, trusts VARCHAR"),
        ):
            p = self._path(name)
            if os.path.exists(p) and os.path.getsize(p) > 0:
                # read_json_auto 会按文件推断列；显式给列类型可避免空文件/缺列导致视图失败。
                #
                # 路径必须转义：早先是 f-string 直接拼进 SQL，工作目录名里
                # 只要有一个单引号（`o'brien-case` 这种）就整条语句语法错误，
                # 而且报错发生在建视图阶段——所有查询一起挂掉，看起来像"库坏了"。
                # DuckDB 的字符串字面量用两个单引号转义，和标准 SQL 一致。
                safe_p = p.replace("'", "''")
                self.con.execute(
                    f"CREATE OR REPLACE VIEW {name} AS "
                    f"SELECT * FROM read_json_auto('{safe_p}', format='newline_delimited')"
                )
            else:
                # 没有数据也建空视图，查询才不会因为"表不存在"而失败
                cols = []
                for pair in ddl.split(","):
                    cname, ctype = pair.strip().split(" ", 1)
                    cols.append(f"CAST(NULL AS {ctype}) AS {cname}")
                self.con.execute(
                    f"CREATE OR REPLACE VIEW {name} AS SELECT {', '.join(cols)} WHERE 1=0"
                )
        self._views_ready = True

    # ---------- 查询 ----------

    def query(self, sql: str) -> list[dict[str, Any]]:
        self.ensure_views()
        cur = self.con.execute(sql)
        cols = [d[0] for d in cur.description] if cur.description else []
        return [dict(zip(cols, row)) for row in cur.fetchall()]

    # —— 几个开箱即用的查询 ——

    def open_ports(self) -> list[dict[str, Any]]:
        """所有开着的服务端口，按 host 聚合，便于看单机暴露面。"""
        return self.query("""
            SELECT host, port, service, product, version, source
            FROM assets
            WHERE kind = 'port'
            ORDER BY host, port
        """)

    def untested_assets(self) -> list[dict[str, Any]]:
        """有资产但没有任何 finding 的——这就是"还没打的地方"。"""
        return self.query("""
            SELECT a.asset_id, a.kind, a.service, a.title
            FROM assets a
            LEFT JOIN findings f ON f.asset_id = a.asset_id
            WHERE f.asset_id IS NULL
            GROUP BY a.asset_id, a.kind, a.service, a.title
            ORDER BY a.kind, a.asset_id
        """)

    def findings_by_severity(self) -> list[dict[str, Any]]:
        return self.query("""
            SELECT severity, COUNT(*) AS n
            FROM findings
            GROUP BY severity
            ORDER BY CASE severity
                WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3
                WHEN 'low' THEN 4 ELSE 5 END
        """)

    def attack_chains(self, max_len: int = 5) -> list[dict[str, Any]]:
        """边表上的传递闭包：从任意节点出发可到达的链路。

        用递归 CTE 而不是 Python 图算法——数据已经在库里，让 SQL 做它擅长的事。
        """
        return self.query(f"""
            WITH RECURSIVE chain(src, dst, depth, path) AS (
                SELECT src, dst, 1, [src, dst] FROM edges
                UNION ALL
                SELECT c.src, e.dst, c.depth + 1, list_append(c.path, e.dst)
                FROM chain c JOIN edges e ON e.src = c.dst
                WHERE c.depth < {int(max_len)} AND NOT list_contains(c.path, e.dst)
            )
            SELECT src, dst, depth, path FROM chain ORDER BY depth DESC, src
        """)

    def summary(self) -> dict[str, int]:
        self.ensure_views()
        return {
            "assets": self.query("SELECT COUNT(*) AS n FROM assets")[0]["n"],
            "findings": self.query("SELECT COUNT(*) AS n FROM findings")[0]["n"],
            "evidence": self.query("SELECT COUNT(*) AS n FROM evidence")[0]["n"],
            "edges": self.query("SELECT COUNT(*) AS n FROM edges")[0]["n"],
        }


# —————————————————————— CLI ——————————————————————
# 让这一层能独立使用，不必每次写 Python：扫描跑完直接 ingest，然后 SQL 随便查。

def _main() -> int:
    import argparse

    ap = argparse.ArgumentParser(description="扫描产物存储与查询（DuckDB）")
    ap.add_argument("--root", default=DEFAULT_ROOT, help="数据目录")
    ap.add_argument("--ingest", nargs=2, action="append", default=[],
                    metavar=("KIND", "PATH"),
                    help="导入工具输出：nmap|httpx|ffuf + 文件路径（可重复）")
    ap.add_argument("--query", default="", help="执行任意 SQL")
    ap.add_argument("--untested", action="store_true", help="列出有资产但没有 finding 的")
    ap.add_argument("--ports", action="store_true", help="列出所有开放端口")
    ap.add_argument("--severity", action="store_true", help="按严重性统计")
    ap.add_argument("--chains", action="store_true", help="列出攻击链（边表传递闭包）")
    a = ap.parse_args()

    st = Store(a.root)

    parsers = {"nmap": parse_nmap_xml, "httpx": parse_httpx_jsonl, "ffuf": parse_ffuf_json}
    for kind, path in a.ingest:
        fn = parsers.get(kind)
        if not fn:
            print(f"未知类型 {kind}，可选：{', '.join(parsers)}")
            continue
        recs = fn(path)
        n = st.append("assets", recs)
        print(f"{kind}: 解析 {len(recs)} 条，写入 {n} 条 -> {a.root}")

    if a.query or a.untested or a.ports or a.severity or a.chains:
        print(st.summary())
    if a.ports:
        for r in st.open_ports():
            print(f"  {r['host']}:{r['port']:<6} {r['service']:<12} {r['product']} {r['version']}")
    if a.untested:
        rows = st.untested_assets()
        print(f"\n未测资产 {len(rows)} 个：")
        for r in rows:
            print(f"  {r['asset_id']:<40} {r['kind']}")
    if a.severity:
        print("\n按严重性：")
        for r in st.findings_by_severity():
            print(f"  {r['severity']:<10} {r['n']}")
    if a.chains:
        rows = st.attack_chains()
        print(f"\n攻击链 {len(rows)} 条：")
        for r in rows:
            print(f"  [{r['depth']}] {' -> '.join(r['path'])}")
    if a.query:
        for r in st.query(a.query):
            print(r)
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
