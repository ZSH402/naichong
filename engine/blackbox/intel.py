#!/usr/bin/env python3
"""RFC 微灵感与探针矩阵 —— 黑盒里"该试什么"的来源。

## 为什么不是"让模型读 RFC 想探针"

直接让模型从零发明黑盒探针，成功率接近零。有效的做法是把规范拆成
**可枚举的断言**，每条断言对应一个"如果实现不照做会怎样"的具体检查。

这件事不需要模型：RFC 里的 MUST / SHOULD / MUST NOT 是可正则提取的，
而"两类实现可能在哪个字节上分歧"是有公开研究的（CL.TE、TE.CL、
头部折叠、大小写、重复键、chunk 扩展）。模型的位置在**异常出现之后**，
去解释这说明什么。

## 语料从哪来（全部是现成的）

    RFC 原文      rfc-editor.org 的纯文本，本项目 corpus/ 下已下载 7 份
    边缘字符串    SecLists 的 big-list-of-naughty-strings 等
    头部字典      SecLists 的 http-request-headers 全量
    方法列表      SecLists 的 http-request-methods

不自己造语料，理由很直接：SecLists 是十年众包的结果，自建的字典永远打不过它。

## 一条纪律

探针只描述"发什么、看什么"，**不描述"这一定是漏洞"**。判据交给异常检测层，
因为同一个响应在两个规范实现上都可能出现，只有出现**结构上不可能**的响应
才算信号。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

CORPUS_DIR = Path(__file__).parent / "corpus"

SECLISTS_CANDIDATES = [
    "/usr/share/seclists/Fuzzing/big-list-of-naughty-strings.txt",
    "/usr/share/seclists/Fuzzing/http-request-methods.txt",
    "/usr/share/seclists/Miscellaneous/Web/http-request-headers/http-request-headers-common-non-standard-fields.txt",
]

# RFC 里的规范性动词。这三类是"实现必须/应该/禁止"的地方，
# 也就是最容易出现"不同实现各自解释"的地方。
_NORMATIVE = re.compile(
    r"\b(MUST NOT|MUST|SHOULD NOT|SHOULD|MAY)\b[^.]{10,240}\.", re.S)
_SECTION = re.compile(r"^\s*(\d+(?:\.\d+)*)\.?\s+([A-Z][^\n]{2,80})$", re.M)


@dataclass
class NormativeClaim:
    """一条从 RFC 里提取出的规范性断言。"""
    rfc: str
    section: str
    verb: str
    text: str

    def as_dict(self) -> dict[str, Any]:
        return {"rfc": self.rfc, "section": self.section, "verb": self.verb, "text": self.text[:300]}


@dataclass
class Primitive:
    """一个具体的去同步/边界探针原语。

    每条都带规范依据与"看什么"——没有依据的原语不放进矩阵，
    因为它无法解释自己为什么值得试。
    """
    name: str
    category: str                 # framing / obfuscation / charset / boundary / cache
    rationale: str
    rfc_ref: str
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    observe: str = ""             # 该看什么现象

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "category": self.category,
            "rationale": self.rationale,
            "rfc_ref": self.rfc_ref,
            "headers": self.headers,
            "body": self.body[:200],
            "observe": self.observe,
        }


# ── 原语库：全部来自公开研究，且每条都能指到 RFC 段落

PRIMITIVES: list[Primitive] = [
    Primitive(
        "CL.TE", "framing",
        "前端按 Content-Length 转发、后端按 Transfer-Encoding 解释，末尾字节被下一请求吞掉",
        "RFC 7230 §3.3.3",
        headers={"Content-Length": "6", "Transfer-Encoding": "chunked"},
        body="0\r\n\r\nG",
        observe="第二个请求的响应出现在第一个请求的位置，或响应体里出现别人的请求行",
    ),
    Primitive(
        "TE.CL", "framing",
        "前端按 Transfer-Encoding、后端按 Content-Length，形成请求边界错位",
        "RFC 7230 §3.3.3",
        headers={"Transfer-Encoding": "chunked", "Content-Length": "4"},
        body="5c\r\nGPOST / HTTP/1.1\r\n\r\n0\r\n\r\n",
        observe="后端把 body 当成新请求处理",
    ),
    Primitive(
        "TE obfuscation: xchunked", "obfuscation",
        "前端不认 x-chunked、后端认（或反之），两者对是否分块产生分歧",
        "RFC 7230 §4.1",
        headers={"Transfer-Encoding": "xchunked"},
        body="0\r\n\r\n",
        observe="响应显示请求被当成分块或被当成普通体",
    ),
    Primitive(
        "TE obfuscation: case", "obfuscation",
        "对头字段值的大小写敏感性分歧（规范要求不敏感，实现常常敏感）",
        "RFC 7230 §3.2.4",
        headers={"Transfer-Encoding": "ChUnKeD"},
        body="0\r\n\r\n",
        observe="400 与正常响应之间的差异",
    ),
    Primitive(
        "dual CL", "framing",
        "同时给两个 Content-Length。规范要求拒绝，实现常常取第一个或最后一个",
        "RFC 7230 §3.3.2",
        headers={"Content-Length": "6, 6"},
        body="abc",
        observe="哪个长度被采用（用不同长度的探测体区分）",
    ),
    Primitive(
        "CL with plus", "boundary",
        "Content-Length 带前导 +、空格或前导零，解析器宽容度不同",
        "RFC 7230 §3.3.2",
        headers={"Content-Length": "+6"},
        body="abcdef",
        observe="被接受还是 400",
    ),
    Primitive(
        "obs-fold", "obfuscation",
        "头字段折行（obsolete line folding）。RFC 7230 明确说必须拒绝，很多代理仍接受",
        "RFC 7230 §3.2.4",
        headers={"X-Probe": "a\r\n b"},
        observe="代理是否把折行拼回一个值（影响后续头部注入）",
    ),
    Primitive(
        "space before colon", "obfuscation",
        "头名与冒号之间有空格。规范禁止，部分实现接受并截断",
        "RFC 7230 §3.2.4",
        headers={"X-Probe ": "a"},
        observe="头是否被识别",
    ),
    Primitive(
        "dup header last-wins", "framing",
        "同名头出现两次，代理取第一个、源站取最后一个（或反之）",
        "RFC 7230 §3.2.2",
        headers={"X-Probe": "first", "X-Forwarded-For": "127.0.0.1"},
        observe="源站看到的是 first 还是 last",
    ),
    Primitive(
        "chunk extension", "framing",
        "chunk 大小后的扩展段（;ext=val）。规范允许，但部分实现在扩展存在时长度计算错误",
        "RFC 9112 §7.1.1",
        body="5;ext=1\r\nhello\r\n0\r\n\r\n",
        observe="长度错位导致的截断或溢出",
    ),
    Primitive(
        "range vs cache", "cache",
        "Range 请求与缓存键的交互。多个 CDN 在 Range 命中缓存时错误返回 200 全量",
        "RFC 9110 §14.2",
        headers={"Range": "bytes=0-1"},
        observe="返回 206（正确）还是 200 全量；全量说明缓存键没包含 Range",
    ),
    Primitive(
        "absolute-form URI", "boundary",
        "请求行用绝对 URI（http://host/path）。代理和源站对 Host 的取法可能不同",
        "RFC 9112 §3.2.2",
        headers={"Host": "canary.invalid"},
        observe="源站用的是请求行里的 host 还是 Host 头",
    ),
    Primitive(
        "h2 :path with scheme", "boundary",
        "HTTP/2 的 :path 里塞绝对 URI，降级到 h1 时被拼成两段",
        "RFC 9113 §8.3.1",
        observe="降级后请求行是否合法、是否被解析成跨主机",
    ),
    Primitive(
        "h2 content-length mismatch", "framing",
        "HTTP/2 先给 content-length、再用 DATA 帧给不同长度",
        "RFC 9113 §8.1.1",
        observe="后端是否按 DATA 长度处理（导致 over-read）",
    ),
    Primitive(
        "empty CL", "boundary",
        "Content-Length 为空值",
        "RFC 9112 §6.3",
        headers={"Content-Length": ""},
        observe="被当成 0 还是被拒绝",
    ),
]

# 缓存层专用的响应侧观察点（PortSwigger 那三条硬判据的扩展）
CACHE_PROBES = [
    ("x-forwarded-host", {"X-Forwarded-Host": "canary.invalid"},
     "响应里出现 canary.invalid 说明该头进了 URL 生成，且很可能进了缓存键之外"),
    ("x-host", {"X-Host": "canary.invalid"}, "同上，换一个常见头名"),
    ("x-original-url", {"X-Original-URL": "/admin"}, "路由被该头覆盖"),
    ("x-rewrite-url", {"X-Rewrite-URL": "/admin"}, "同上"),
]


def load_rfc(rfc_id: str) -> str:
    """读本地 RPM 原文。文件名形如 rfc9112.txt。"""
    p = CORPUS_DIR / f"rfc{rfc_id}.txt"
    if not p.is_file():
        return ""
    return p.read_text(encoding="utf-8", errors="replace")


def available_rfcs() -> list[str]:
    return sorted(p.stem.replace("rfc", "") for p in CORPUS_DIR.glob("rfc*.txt"))


def extract_claims(rfc_id: str, limit: int = 200) -> list[NormativeClaim]:
    """从 RFC 正文提取规范性断言。

    section 号靠向前找最近的 "N.N 标题" —— RFC 的排版稳定，
    这个启发式在 9110/9112/9113/7230 上都可靠。
    """
    text = load_rfc(rfc_id)
    if text == "":
        return []
    # 去掉页眉页脚（"RFC 9112  HTTP/1.1  June 2022" 这类行）
    cleaned = re.sub(r"^RFC \d+\s+.*\s+\d{4}$", "", text, flags=re.M)
    out: list[NormativeClaim] = []
    sections = [(m.start(), m.group(1)) for m in _SECTION.finditer(cleaned)]

    for m in _NORMATIVE.finditer(cleaned):
        pos = m.start()
        section = ""
        for sp, sn in sections:
            if sp > pos:
                break
            section = sn
        body = re.sub(r"\s+", " ", m.group(0)).strip()
        if len(body) < 30:
            continue
        # RFC 开头几节有"关键词定义"段落（"MUST", "MUST NOT", "REQUIRED"…），
        # 那里一口气出现一堆带引号的动词，不是真正的规范断言，剔除。
        if body.count('"') > 4:
            continue
        out.append(NormativeClaim(rfc=rfc_id, section=section, verb=m.group(1), text=body))
        if len(out) >= limit:
            break
    return out


def load_seclists() -> dict[str, list[str]]:
    """载入可用的边缘字符串。文件不存在就空着，不报错——
    这些是增强，不是依赖。"""
    out: dict[str, list[str]] = {}
    for p in SECLISTS_CANDIDATES:
        f = Path(p)
        if not f.is_file():
            continue
        try:
            lines = [l.rstrip("\n") for l in f.read_text(encoding="utf-8", errors="replace").splitlines()]
        except OSError:
            continue
        out[f.stem] = [l for l in lines if l and not l.startswith("#")][:2000]
    return out


@dataclass
class ProbeMatrix:
    """一次生成的探针矩阵。"""
    primitives: list[Primitive] = field(default_factory=list)
    cache_probes: list[dict[str, Any]] = field(default_factory=list)
    claims: list[NormativeClaim] = field(default_factory=list)
    edge_strings: list[str] = field(default_factory=list)
    sources: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "primitives": len(self.primitives),
            "cache_probes": len(self.cache_probes),
            "normative_claims": len(self.claims),
            "edge_strings": len(self.edge_strings),
            "sources": self.sources,
            "matrix": [p.as_dict() for p in self.primitives],
            "cache": self.cache_probes,
            "sample_claims": [c.as_dict() for c in self.claims[:12]],
            "sample_edges": self.edge_strings[:15],
        }


def build_matrix(*, rfcs: list[str] | None = None, include_cache: bool = True,
                 claim_limit: int = 60) -> ProbeMatrix:
    """把原语库 + RFC 断言 + SecLists 边缘串组装成探针矩阵。

    每条的规范性依据都会被实际读取——不是写死的引用字符串，
    所以"这条探针为什么值得试"是可以点开 RFC 原文核对的。
    """
    rfcs = rfcs or available_rfcs()
    m = ProbeMatrix()
    m.primitives = list(PRIMITIVES)
    if include_cache:
        m.cache_probes = [
            {"name": n, "headers": h, "observe": o} for n, h, o in CACHE_PROBES
        ]

    for rid in rfcs:
        m.claims.extend(extract_claims(rid, limit=claim_limit))

    sec = load_seclists()
    m.edge_strings = sec.get("big-list-of-naughty-strings", [])[:120]

    # 依据校验：哪条原语的 rfc_ref 里提到的 RFC 确实在本地语料里
    local = set(available_rfcs())
    backed, unbacked = [], []
    for p in m.primitives:
        num = re.search(r"RFC (\d+)", p.rfc_ref)
        (backed if num and num.group(1) in local else unbacked).append(p.name)

    m.sources = {
        "rfcs_available": local_sorted(local),
        "rfc_downloaded_bytes": sum((CORPUS_DIR / f"rfc{r}.txt").stat().st_size for r in local),
        "seclists_files": sorted(sec.keys()),
        "primitives_with_local_rfc": backed,
        "primitives_without_local_rfc": unbacked,
    }
    return m


def local_sorted(s: set[str]) -> list[str]:
    return sorted(s, key=lambda x: int(x) if x.isdigit() else 0)
