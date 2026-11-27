#!/usr/bin/env python3
"""跨目标异常共振 —— 判断一个怪现象是"开发者手滑"还是"底层组件 0day"。

## 核心判据

单看一个目标的怪异响应，没法区分：
  - 这个开发写错了（只影响这一家）
  - 这套框架/CDN/反代有通用缺陷（影响所有用它的）

HTTP Terminator 给出的黄金判据是：**同一个新探针在多个不同部署环境里
都引发相似异常**，那大概率是通用软件问题。

这是可自动化的：把每个异常压成一个指纹，跨目标做聚类，同簇里出现
多个独立目标就抬优先级。不需要模型参与判断。

## 为什么用 MinHash 而不是精确匹配

异常详情的措辞每次都不一样（端口号、路径、时间戳），精确匹配会把
同一个缺陷拆成一堆独立观察。MinHash + LSH 能容忍这种抖动，
而且是子线性查询——观察数量上千时仍然快。

用 datasketch 的现成实现，不自己写哈希。
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any, Iterable

try:
    from datasketch import MinHash, MinHashLSH
    HAS_DATASKETCH = True
except Exception:      # pragma: no cover
    HAS_DATASKETCH = False


@dataclass
class Observation:
    """一条来自某个目标的异常观察。"""
    target: str
    kind: str
    endpoint: str
    detail: str

    def tokens(self) -> list[str]:
        """把观察切成可比较的 shingle。

        刻意**抹掉**会随目标变化的东西（端口、IP、路径段、数字），
        保留描述异常性质的词。这样同一个缺陷在不同目标上会得到相近的指纹。
        """
        s = f"{self.kind} {self.endpoint} {self.detail}".lower()
        s = re.sub(r"\b\d+\b", "N", s)              # 数字归一
        s = re.sub(r"\b[0-9a-f]{8,}\b", "H", s)      # 哈希归一
        s = re.sub(r"/[a-z0-9_\-]{1,20}", "/P", s)   # 路径段归一
        words = re.split(r"[^a-z]+", s)
        words = [w for w in words if len(w) > 2]
        # 同时给 3-gram 和 unigram。
        # 只用 3-gram 时短描述（"stack trace leaked file"）的 shingle 太少，
        # MinHash 的估计方差大，同一个缺陷换个措辞就聚不上——实测阈值 0.55
        # 下两条同类栈泄露会各自成簇。补上 unigram 后相似度信号稳得多。
        out = list(words)
        for i in range(len(words) - 2):
            out.append(" ".join(words[i:i + 3]))
        return out

    def as_dict(self) -> dict[str, Any]:
        return {"target": self.target, "kind": self.kind,
                "endpoint": self.endpoint, "detail": self.detail[:160]}


@dataclass
class Cluster:
    """一组相似的观察。"""
    members: list[Observation] = field(default_factory=list)

    @property
    def targets(self) -> set[str]:
        return {m.target for m in self.members}

    @property
    def resonant(self) -> bool:
        """**跨目标出现**才算共振。

        同一个目标上的多条相似观察不构成共振——那多半是同一个缺陷的多个表现。
        """
        return len(self.targets) >= 2

    @property
    def priority(self) -> str:
        n = len(self.targets)
        if n >= 3:
            return "high"
        if n == 2:
            return "medium"
        return "low"

    def as_dict(self) -> dict[str, Any]:
        return {
            "targets": sorted(self.targets),
            "target_count": len(self.targets),
            "observations": len(self.members),
            "resonant": self.resonant,
            "priority": self.priority,
            "kinds": sorted({m.kind for m in self.members}),
            "sample": [m.as_dict() for m in self.members[:3]],
            "note": ("same anomaly shape on independent targets — likely a shared component "
                     "(framework / CDN / reverse proxy), worth reporting as one issue"
                     if self.resonant else "single target only — treat as a local defect"),
        }


def cluster(observations: Iterable[Observation], *, threshold: float = 0.45) -> list[Cluster]:
    """把观察聚类。

    阈值 0.45：在"加 unigram 之后"的 shingle 上实测的折中值。
    再低会把不同类型的异常并进来（比如把 stack-trace 和 path-leak 混在一起），
    再高会把同一缺陷因措辞抖动拆成多个簇。这个数值得用真实观察调，
    拍脑袋定的阈值会让共振雷达要么全响要么全哑。"""
    obs = list(observations)
    if not obs:
        return []

    if not HAS_DATASKETCH:
        # 没有 datasketch 时降级到"按 kind 精确分组"，并在结果里说明
        by_kind: dict[str, Cluster] = {}
        for o in obs:
            by_kind.setdefault(o.kind, Cluster()).members.append(o)
        out = list(by_kind.values())
        for c in out:
            c.members[0].detail += "  [cluster: exact-kind only, datasketch unavailable]"
        return out

    lsh = MinHashLSH(threshold=threshold, num_perm=64)
    hashes: dict[int, MinHash] = {}
    for i, o in enumerate(obs):
        m = MinHash(num_perm=64)
        for tok in o.tokens():
            m.update(tok.encode())
        hashes[i] = m
        lsh.insert(str(i), m)

    seen: set[int] = set()
    clusters: list[Cluster] = []
    for i, m in hashes.items():
        if i in seen:
            continue
        group = [i]
        seen.add(i)
        for j in lsh.query(m):
            jj = int(j)
            if jj in seen:
                continue
            seen.add(jj)
            group.append(jj)
        clusters.append(Cluster(members=[obs[k] for k in group]))

    # 共振的排前面，其次按观察数
    clusters.sort(key=lambda c: (not c.resonant, -len(c.targets), -len(c.members)))
    return clusters


def summarize(clusters: list[Cluster]) -> dict[str, Any]:
    resonant = [c for c in clusters if c.resonant]
    return {
        "clusters": len(clusters),
        "resonant_clusters": len(resonant),
        "high_priority": len([c for c in clusters if c.priority == "high"]),
        "detail": [c.as_dict() for c in clusters[:15]],
        "action": (
            "none — every cluster is confined to a single target"
            if not resonant else
            f"{len(resonant)} cluster(s) span multiple independent targets; "
            "prioritise them as shared-component issues and verify on a third target before reporting"
        ),
    }
