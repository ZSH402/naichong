#!/usr/bin/env python3
"""批量作业编排 —— 把"一次测一个"变成"一批资产跑到底"。

## 为什么这层是必需品而不是便利品

真实项目动辄几百个资产。早先是人工写循环脚本：跑完 95 个目标，结果是
95 份独立 JSON，谁在跑、跑到第几个、哪些值得深挖，全部靠人肉整理。
中途进程一挂，前面的结果全丢在内存里。

四个硬需求：
  1. **断点续跑** —— 每个目标一完成就落盘，挂了重跑只补没做完的
  2. **并发隔离** —— 某个目标卡住（超时/证书错/黑洞 IP）不能拖慢整批
  3. **按目标限速** —— 主站 2 QPS 都可能触发风控，边缘站 10 QPS 无所谓，
                       全局一个值必然是一边太吵一边太慢
  4. **结果聚合** —— 跑完要能一眼看出"哪些可测、哪些是墙、哪些值得深挖"

## 设计取舍

**状态用 JSONL 追加，不用数据库。** 一行一个目标的最终结果，写完立刻 flush。
好处是进程被杀时最多丢一行，而且文件本身就能当报告看；坏处是不支持事务——
但对"普查"这种幂等操作，重跑一个目标是安全的。

**每个目标内部串行，目标之间并发。** 同一个目标的并发请求最容易触发风控，
而且会污染差分测试（同一时刻多个请求让服务端状态不可预测）。
"""

from __future__ import annotations

import json
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable

from .core import Identity, SessionPool
from .guard import RateLimit


@dataclass
class Target:
    """一个待测资产。"""
    host: str
    # 优先级线索（来自上游资产发现）：业务等级、技术栈、命中的已知特征
    tags: dict[str, Any] = field(default_factory=dict)

    @property
    def url(self) -> str:
        return self.host if self.host.startswith("http") else f"https://{self.host}"


@dataclass
class Record:
    """一个目标的最终结果。落盘的单位就是它。"""
    host: str
    started: float
    finished: float
    ok: bool
    # 分类结论
    kind: str = "unknown"          # page / spa / api / auth-wall / challenge / forbidden / dead
    status: int = 0
    endpoints: int = 0
    js_fetched: int = 0
    leaks: list[dict[str, Any]] = field(default_factory=list)
    # 可测性评分（越高越值得深挖）
    score: int = 0
    reasons: list[str] = field(default_factory=list)
    error: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "kind": self.kind,
            "status": self.status,
            "endpoints": self.endpoints,
            "js_fetched": self.js_fetched,
            "score": self.score,
            "reasons": self.reasons,
            "leaks": self.leaks[:8],
            "durability": round(self.finished - self.started, 1),
            **({"error": self.error} if self.error else {}),
            **({"extra": self.extra} if self.extra else {}),
        }


class Campaign:
    """一批资产的普查作业。"""

    def __init__(self, out_dir: str | Path, *, qps_per_target: float = 3.0,
                 concurrency: int = 4, timeout: float = 10.0) -> None:
        self.dir = Path(out_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.state_path = self.dir / "campaign.jsonl"
        self.qps = qps_per_target
        self.concurrency = max(1, concurrency)
        self.timeout = timeout
        self._done: dict[str, dict[str, Any]] = {}
        self._load()

    # ── 断点续跑

    def _load(self) -> None:
        """读回已完成的目标。同 host 后写覆盖先写（允许重跑单个目标）。"""
        if not self.state_path.is_file():
            return
        for line in self.state_path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if line == "":
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                # 半行（进程在写的时候被杀）——跳过，下次重跑这个目标
                continue
            if isinstance(rec, dict) and isinstance(rec.get("host"), str):
                self._done[rec["host"]] = rec

    def _persist(self, rec: Record) -> None:
        payload = rec.as_dict()
        with self.state_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(payload, ensure_ascii=False) + "\n")
            fh.flush()
            os.fsync(fh.fileno())      # 崩溃时最多丢当前这一行
        self._done[rec.host] = payload

    @property
    def done_count(self) -> int:
        return len(self._done)

    def pending(self, targets: Iterable[Target]) -> list[Target]:
        seen: set[str] = set()
        out: list[Target] = []
        for t in targets:
            if t.host in seen:
                continue
            seen.add(t.host)
            if t.host in self._done:
                continue
            out.append(t)
        return out

    # ── 单个目标

    def probe_one(self, target: Target, handler: Callable[[SessionPool, RateLimit, Target], Record]) -> Record:
        """跑一个目标。handler 内部只用给定的 pool/rate，保证限速是按目标算的。"""
        started = time.time()
        pool = SessionPool(target.url, timeout=self.timeout, verify_tls=False)
        # 身份名要唯一确定，且 handler 不该硬编码它——
        # 早先这里叫 "anon"、handler 里写 "anonymous"，于是每一次请求都返回
        # `unknown identity`，308 个目标全被判成 dead。这类"字符串对不上"的坑
        # 静默、批量、看起来像"目标全挂了"。
        pool.add(Identity(name="anonymous", role="anonymous"))
        # 每个目标自己的限速器：主站和边缘站本来就该不同速率
        rate = RateLimit(max_qps=self.qps)
        try:
            rec = handler(pool, rate, target)
            rec.started, rec.finished = started, time.time()
            rec.ok = rec.error == ""
        except Exception as exc:                     # 隔离：一个目标炸了不影响整批
            rec = Record(host=target.host, started=started, finished=time.time(),
                         ok=False, error=f"{type(exc).__name__}: {str(exc)[:150]}")
        finally:
            pool.close()
        self._persist(rec)
        return rec

    # ── 整批

    def run(self, targets: Iterable[Target],
            handler: Callable[[SessionPool, RateLimit, Target], Record],
            *, on_done: Callable[[Record], None] | None = None) -> list[Record]:
        todo = self.pending(targets)
        results: list[Record] = []
        if not todo:
            return results
        with ThreadPoolExecutor(max_workers=self.concurrency) as ex:
            futures = {ex.submit(self.probe_one, t, handler): t for t in todo}
            for fut in as_completed(futures):
                try:
                    rec = fut.result()
                except Exception as exc:             # probe_one 已经兜了一层，这里再兜
                    t = futures[fut]
                    rec = Record(host=t.host, started=0, finished=0, ok=False,
                                 error=f"unhandled: {type(exc).__name__}")
                    self._persist(rec)
                results.append(rec)
                if on_done is not None:
                    on_done(rec)
        return results

    # ── 聚合

    def report(self) -> dict[str, Any]:
        """整批的结论：按可测性排序，按类型分组。"""
        rows = list(self._done.values())
        rows.sort(key=lambda r: -int(r.get("score", 0)))
        by_kind: dict[str, int] = {}
        for r in rows:
            k = str(r.get("kind", "unknown"))
            by_kind[k] = by_kind.get(k, 0) + 1
        worth = [r for r in rows if int(r.get("score", 0)) > 0]
        return {
            "total": len(rows),
            "by_kind": by_kind,
            "worth_investigating": len(worth),
            "top": [
                {"host": r["host"], "kind": r.get("kind"), "score": r.get("score"),
                 "endpoints": r.get("endpoints"), "reasons": r.get("reasons", [])[:3]}
                for r in worth[:25]
            ],
            "next": (
                "pick from `top`: they have reachable content, and the higher the score "
                "the more surface there is to test"
                if worth else
                "nothing scored above zero — every target was a wall, an empty shell or dead. "
                "This is a coverage result, not a security result"
            ),
        }
