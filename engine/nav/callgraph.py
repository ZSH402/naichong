#!/usr/bin/env python3
"""调用图与代码切片 —— 白盒引擎的感知层。

## 为什么需要这一层

没有它，模型看到的只是"某个字符串在哪几行出现过"。有了它，才能回答三个
决定误报率的问题：

  **可达**  —— 这段代码有没有调用方？（死代码不构成漏洞）
  **邻域**  —— 这个函数被谁调用、又调用了谁？（切片喂给模型，替代整文件）
  **同构**  —— 补丁修的那个检查，在哪些兄弟函数里缺失？

## 为什么不自己写解析器

用 tree-sitter 的现成语法树。它在 GitHub、Neovim、Aider 里都是标准件，
多语言覆盖和错误恢复都打磨过。这里只做两件事：**抽符号**、**连边**。

## 输出契约

所有子命令输出一行 JSON 到 stdout，出错时退出码非 0 并把原因写到 stderr。
这样 TS 侧只认一种格式，不需要为每个子命令写一套解析。

定位一律用 `file:line`，因为它是人能直接跳转过去核对的最小单位。
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

from tree_sitter import Language, Parser

# 每个语言用预编译的 wheel。不用 tree_sitter_language_pack：那个包会在
# 首次调用时联网下载语法文件，隔离环境里必然卡死（实测会挂满超时）。
# 预编译包把语法直接塞进 wheel，装上就能用，适合离线环境。
_LANG_MODULE = {
    "python": ("tree_sitter_python", None),
    "javascript": ("tree_sitter_javascript", None),
    "typescript": ("tree_sitter_typescript", "language_typescript"),
    "tsx": ("tree_sitter_typescript", "language_tsx"),
    "go": ("tree_sitter_go", None),
    "rust": ("tree_sitter_rust", None),
    "java": ("tree_sitter_java", None),
    "c": ("tree_sitter_c", None),
    "cpp": ("tree_sitter_cpp", None),
}

_parser_cache: dict[str, Parser | None] = {}


def get_parser(lang: str) -> Parser | None:
    """按语言取 parser。装不上就返回 None，由调用方跳过——不静默当成解析成功。"""
    if lang in _parser_cache:
        return _parser_cache[lang]
    spec = _LANG_MODULE.get(lang)
    if spec is None:
        _parser_cache[lang] = None
        return None
    modname, fnname = spec
    try:
        mod = __import__(modname)
        if fnname is not None:
            lang_obj = getattr(mod, fnname)()
        else:
            lang_obj = mod.language()
        parser = Parser(Language(lang_obj))
    except Exception:
        parser = None
    _parser_cache[lang] = parser
    return parser

# 每种语言的节点类型名。tree-sitter 的语法各不相同，这里做一层归一化：
#   func —— 定义节点（函数、方法、构造函数都算）
#   call —— 调用节点
#   name —— 取名字的子节点类型
LANGS: dict[str, dict[str, Any]] = {
    "python": {"func": {"function_definition"}, "call": {"call"}, "name": {"identifier"}},
    "javascript": {
        "func": {"function_declaration", "method_definition", "arrow_function", "function"},
        "call": {"call_expression"},
        "name": {"identifier", "property_identifier"},
    },
    "typescript": {
        "func": {"function_declaration", "method_definition", "arrow_function", "function_signature"},
        "call": {"call_expression"},
        "name": {"identifier", "property_identifier"},
    },
    "go": {"func": {"function_declaration", "method_declaration"}, "call": {"call_expression"}, "name": {"identifier", "field_identifier"}},
    "rust": {"func": {"function_item"}, "call": {"call_expression"}, "name": {"identifier", "field_identifier"}},
    "java": {"func": {"method_declaration", "constructor_declaration"}, "call": {"method_invocation"}, "name": {"identifier"}},
    "c": {"func": {"function_definition"}, "call": {"call_expression"}, "name": {"identifier"}},
    "cpp": {"func": {"function_definition"}, "call": {"call_expression"}, "name": {"identifier", "field_identifier"}},
}

EXT_LANG = {
    ".py": "python",
    ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript", ".jsx": "javascript",
    ".ts": "typescript", ".tsx": "typescript",
    ".go": "go",
    ".rs": "rust",
    ".java": "java",
    ".c": "c", ".h": "c",
    ".cc": "cpp", ".cpp": "cpp", ".hpp": "cpp",
}

SKIP_DIRS = {
    "node_modules", ".git", "dist", "build", "out", "target", "vendor",
    "third_party", "third-party", ".venv", "venv", "__pycache__", ".next",
    "coverage", ".mypy_cache", ".pytest_cache",
}

MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_FILES = 4000


def walk_sources(root: Path) -> list[tuple[Path, str]]:
    """收集可解析的源文件。跳过明显的非源码目录与大文件。"""
    found: list[tuple[Path, str]] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
        for fn in filenames:
            lang = EXT_LANG.get(Path(fn).suffix.lower())
            if lang is None:
                continue
            p = Path(dirpath) / fn
            try:
                if p.stat().st_size > MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            found.append((p, lang))
            if len(found) >= MAX_FILES:
                return found
    return found


def node_text(src: bytes, node) -> str:
    return src[node.start_byte:node.end_byte].decode("utf-8", "replace")


def name_of(src: bytes, node, cfg: dict[str, Any]) -> str | None:
    """从定义/调用节点里取名字。

    先看 `name` 字段（多数语法都有），再退回第一个标识符子节点。
    取不到名字的节点直接跳过——比给它编一个 `anonymous@123` 更好，
    因为下游会拿这个名字去搜调用点，假名字只会制造噪音。
    """
    nm = node.child_by_field_name("name")
    if nm is not None:
        return node_text(src, nm)
    for ch in node.children:
        if ch.type in cfg["name"]:
            return node_text(src, ch)
    return None


def callee_of(src: bytes, node, cfg: dict[str, Any]) -> str | None:
    """取调用点的被调名。

    `foo.bar()` 取 `bar` 而不是 `foo` —— 因为下游要按名字找定义，
    而 `bar` 才是被定义的那个。代价是不同对象上的同名方法会被合并，
    这在建图阶段可以接受（宁可多连不可漏连，漏连会让人误判成死代码）。
    """
    fn = node.child_by_field_name("function")
    if fn is None:
        return None
    if fn.type in cfg["name"]:
        return node_text(src, fn)
    member = fn.child_by_field_name("property") or fn.child_by_field_name("field")
    if member is not None:
        return node_text(src, member)
    # 再退一层：取最后一个标识符
    last = None
    for ch in fn.children:
        if ch.type in cfg["name"]:
            last = node_text(src, ch)
    return last


def build_graph(root: Path) -> dict[str, Any]:
    """建图：节点是定义，边是"某定义体内出现了对另一个名字的调用"。

    注意边是**按名字连的**，不是按符号表。多语言混合仓库里没有统一的
    符号解析器，做精确解析会引入一大堆语言特定逻辑；而按名字连的图
    对三个用途（可达、邻域、同构）已经够用，代价是同名函数会串在一起。
    """
    defs: dict[str, list[dict[str, Any]]] = {}
    calls: list[dict[str, Any]] = []
    files = walk_sources(root)
    missing: set[str] = set()

    for path, lang in files:
        cfg = LANGS.get(lang)
        if cfg is None:
            continue
        parser = get_parser(lang)
        if parser is None:
            missing.add(lang)
            continue
        try:
            src = path.read_bytes()
            tree = parser.parse(src)
        except Exception:
            continue

        rel = str(path.relative_to(root))
        # 顶层作用域当成一个虚拟定义。真实代码里大量调用发生在**匿名函数**里
        # （`app.post('/x', (req,res) => { save(...) })`），那些调用没有具名宿主，
        # 如果不给它们一个归属，边就全丢了——而丢边会让可达性判断把活代码当死代码，
        # 这正是"误杀真漏洞"的来源之一。
        top = f"<top:{rel}>"
        defs.setdefault(top, []).append({
            "name": top,
            "file": rel,
            "line": 1,
            "end_line": tree.root_node.end_point[0] + 1,
            "lang": lang,
            "toplevel": True,
        })
        stack = [(tree.root_node, top)]
        while stack:
            node, enclosing = stack.pop()
            if node.type in cfg["func"]:
                nm = name_of(src, node, cfg)
                if nm is not None:
                    rec = {
                        "name": nm,
                        "file": rel,
                        "line": node.start_point[0] + 1,
                        "end_line": node.end_point[0] + 1,
                        "lang": lang,
                    }
                    defs.setdefault(nm, []).append(rec)
                    # 函数体内的调用归属到它
                    for ch in node.children:
                        stack.append((ch, nm))
                    continue
            if node.type in cfg["call"]:
                callee = callee_of(src, node, cfg)
                if callee is not None and enclosing is not None:
                    calls.append({
                        "from": enclosing,
                        "to": callee,
                        "file": rel,
                        "line": node.start_point[0] + 1,
                    })
            for ch in node.children:
                stack.append((ch, enclosing))

    return {
        "root": str(root),
        "files": len(files),
        "defs": defs,
        "calls": calls,
        "unsupported": sorted(missing),
    }


def index_graph(g: dict[str, Any]) -> tuple[dict[str, list[str]], dict[str, list[str]]]:
    """建正向与反向索引。只保留"能连上定义"的边——连不上的调用多半是
    库函数或外部 API，它们对"可达性"判断没有帮助，留着只会撑大输出。"""
    known = set(g["defs"].keys())
    fwd: dict[str, list[str]] = {}
    rev: dict[str, list[str]] = {}
    for c in g["calls"]:
        f, t = c["from"], c["to"]
        if t not in known or f not in known:
            continue
        fwd.setdefault(f, []).append(t)
        rev.setdefault(t, []).append(f)
    return fwd, rev


def cmd_build(args: argparse.Namespace) -> None:
    root = Path(args.root).resolve()
    g = build_graph(root)
    fwd, rev = index_graph(g)
    functions = sum(1 for v in g["defs"].values() for d in v if not d.get("toplevel"))
    out = {
        "root": g["root"],
        "files": g["files"],
        **({"unsupported_langs": g["unsupported"]} if g["unsupported"] else {}),
        "functions": functions,
        "call_edges": sum(len(v) for v in fwd.values()),
        "unresolved_calls": len(g["calls"]) - sum(len(v) for v in fwd.values()),
        "out_degree_top": sorted(
            ({"name": k, "calls": len(v)} for k, v in fwd.items()), key=lambda x: -x["calls"]
        )[:15],
        "in_degree_top": sorted(
            ({"name": k, "callers": len(v)} for k, v in rev.items()), key=lambda x: -x["callers"]
        )[:15],
    }
    if args.out:
        payload = {"defs": g["defs"], "calls": g["calls"]}
        Path(args.out).write_text(json.dumps(payload), encoding="utf-8")
        out["saved"] = args.out
    print(json.dumps(out, ensure_ascii=False))


def cmd_callers(args: argparse.Namespace) -> None:
    g = build_graph(Path(args.root).resolve())
    _fwd, rev = index_graph(g)
    callers = sorted(set(rev.get(args.symbol, [])))
    print(json.dumps({
        "symbol": args.symbol,
        "defined": g["defs"].get(args.symbol, []),
        "callers": callers,
        "caller_count": len(callers),
        "note": (
            "no caller found — if this symbol is the code a claim targets, the claim is likely unreachable"
            if not callers else "reachable from at least one other function"
        ),
    }, ensure_ascii=False))


def cmd_slice(args: argparse.Namespace) -> None:
    """取 N 跳邻域。这是喂给模型的"最小充分上下文"：
    整个文件会稀释注意力，单个函数又丢了调用方契约。"""
    g = build_graph(Path(args.root).resolve())
    fwd, rev = index_graph(g)
    seen = {args.symbol}
    frontier = {args.symbol}
    for _ in range(max(1, args.hops)):
        nxt: set[str] = set()
        for s in frontier:
            for x in fwd.get(s, []):
                if x not in seen:
                    nxt.add(x)
            for x in rev.get(s, []):
                if x not in seen:
                    nxt.add(x)
        seen |= nxt
        frontier = nxt
        if not frontier:
            break
    nodes = []
    for s in sorted(seen):
        for d in g["defs"].get(s, []):
            nodes.append({"symbol": s, **d})
    edges = [
        {"from": c["from"], "to": c["to"], "file": c["file"], "line": c["line"]}
        for c in g["calls"]
        if c["from"] in seen and c["to"] in seen
    ]
    print(json.dumps({
        "center": args.symbol,
        "hops": args.hops,
        "nodes": nodes[:400],
        "edges": edges[:800],
        "truncated": len(nodes) > 400 or len(edges) > 800,
    }, ensure_ascii=False))



# ─────────────────────────────────────────────────────────────────────────────
# 路由簇分析（引擎 B 的雏形）
#
# 访问控制漏洞的形态很特殊：**不存在危险代码行**，缺的是本该存在的那一行。
# 所以找它的方式不是追污点流，而是**对比**——同一簇（前缀相同、操作同一类
# 资源）里多数端点都挂了守卫，少数没挂，那一小撮就是嫌疑。
#
# 这个思路来自 Refute-or-Promote 与 ABSENTIA 的共识：先把"路由—守卫"图谱
# 确定性地画出来，再让语义判断只处理少数差异点。
# ─────────────────────────────────────────────────────────────────────────────

ROUTE_RE = re.compile(
    r"""(?:\b(?:router|app|server|api|r)\s*\.\s*(?P<m1>get|post|put|patch|delete|all)\s*\(
        |@\w*\.?(?:route|get|post|put|patch|delete|mapping)\s*\(
        |Route::(?P<m2>get|post|put|patch|delete|any)\s*\()""",
    re.VERBOSE,
)
PATH_RE = re.compile(r"""['"](?P<p>/[A-Za-z0-9_\-./:{}*]*)['"]""")

GUARD_HINTS = [
    (re.compile(r"\b(requireAuth|ensureAuth|authMiddleware|authenticate|isAuthenticated|requireLogin)\b", re.I), "auth"),
    (re.compile(r"\b(requireRole|hasRole|isAdmin|checkPermission|authorize|can\()", re.I), "authz"),
    (re.compile(r"\b(tenant|org_id|owner_id|user_id)\s*(===|==|!==|!=)", re.I), "tenant-scope"),
    (re.compile(r"(@login_required|@jwt_required|@permission_required|Depends\()", re.I), "decorator"),
]


def scan_routes(root: Path) -> dict[str, Any]:
    """扫描路由注册点，按前缀分簇，并标出每条的守卫覆盖。

    守卫判定看**注册点所在行及前两行**——绝大多数框架把中间件写成
    `router.post(path, a, b, handler)` 或者紧邻的装饰器，隔得远的基本不是
    这条路由的守卫。宁可漏判（把守卫当没有）也不误判（把无关中间件当守卫），
    因为漏判只会多一条待人工确认，误判会直接隐藏一个真漏洞。
    """
    clusters: dict[str, list[dict[str, Any]]] = {}
    files = walk_sources(root)
    for path, _lang in files:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if not ROUTE_RE.search(text):
            continue
        lines = text.split("\n")
        rel = str(path.relative_to(root))
        for i, line in enumerate(lines):
            rm = ROUTE_RE.search(line)
            if rm is None:
                continue
            pm = PATH_RE.search(line)
            if pm is None:
                continue
            route = pm.group("p")
            method = (rm.groupdict().get("m1") or rm.groupdict().get("m2") or "?").upper()

            guards: list[str] = []
            for j in range(max(0, i - 2), min(len(lines), i + 2)):
                for rx, kind in GUARD_HINTS:
                    if rx.search(lines[j]):
                        guards.append(kind)
            guards = sorted(set(guards))

            # 簇键：前两段路径。`/api/user/export` 与 `/api/user/:id` 同簇。
            seg = [x for x in route.split("/") if x]
            prefix = "/" + "/".join(seg[:2]) if seg else "/"
            clusters.setdefault(prefix, []).append({
                "method": method,
                "path": route,
                "file": rel,
                "line": i + 1,
                "guards": guards,
            })

    out = []
    for prefix, routes in sorted(clusters.items()):
        guarded = [r for r in routes if r["guards"]]
        unguarded = [r for r in routes if not r["guards"]]
        # 只有当同簇里确实有对照（至少一条有守卫）时，孤立无守卫才值得报
        suspicious = unguarded if guarded else []
        out.append({
            "prefix": prefix,
            "routes": len(routes),
            "guarded": len(guarded),
            "unguarded": [
                {"method": r["method"], "path": r["path"], "file": r["file"], "line": r["line"]}
                for r in unguarded
            ],
            "suspicious": [
                {"method": r["method"], "path": r["path"], "file": r["file"], "line": r["line"]}
                for r in suspicious
            ],
        })
    return {
        "clusters": [c for c in out if c["routes"] > 0],
        "total_routes": sum(c["routes"] for c in out),
        "suspicious_total": sum(len(c["suspicious"]) for c in out),
    }


def cmd_routes(args: argparse.Namespace) -> None:
    print(json.dumps(scan_routes(Path(args.root).resolve()), ensure_ascii=False))



def main() -> None:
    ap = argparse.ArgumentParser(description="调用图与切片（tree-sitter）")
    sub = ap.add_subparsers(dest="cmd", required=True)

    b = sub.add_parser("build", help="建图并输出统计")
    b.add_argument("root")
    b.add_argument("--out", default="", help="把完整图存成 JSON")

    c = sub.add_parser("callers", help="谁调用了这个符号")
    c.add_argument("root")
    c.add_argument("symbol")

    s = sub.add_parser("slice", help="取 N 跳邻域")
    s.add_argument("root")
    s.add_argument("symbol")
    s.add_argument("--hops", type=int, default=2)

    r = sub.add_parser("routes", help="路由簇与守卫覆盖（找漏守卫的兄弟端点）")
    r.add_argument("root")

    args = ap.parse_args()
    {"build": cmd_build, "callers": cmd_callers, "slice": cmd_slice, "routes": cmd_routes}[args.cmd](args)


if __name__ == "__main__":
    main()
