#!/usr/bin/env python3
"""黑盒探测统一入口。所有子命令输出一行 JSON 到 stdout。

设计原则：TS 侧只认一种格式，不为每个子命令写一套解析。
出错时退出码非 0 并把原因写进 JSON 的 error 字段（不是 stderr），
因为调用方往往是脚本，读 stdout 比读 stderr 可靠。

用法：
    python3 -m blackbox.cli map      --base URL --ids a=cookie:... --ids b=
    python3 -m blackbox.cli diff     --base URL --path /api/x --ids ...
    python3 -m blackbox.cli anomaly  --base URL --path /api/x --ids ...
    python3 -m blackbox.cli race     --base URL --path /api/redeem --ids ... --count 10
    python3 -m blackbox.cli probe    --base URL --ids ... --paths /a,/b
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from . import anomaly as anomaly_mod
from . import assetgraph as assetgraph_mod
from . import bizmodel as bizmodel_mod
from . import campaign as campaign_mod
from . import classify as classify_mod
from . import evolve as evolve_mod
from . import invariant as invariant_mod
from . import jsintel as jsintel_mod
from .credentials import Credential, CredentialPool
from . import intel as intel_mod
from . import resonance as resonance_mod
from . import race as race_mod
from . import surface as surface_mod
from .core import (Identity, SessionPool, behavior_matrix, identity_matrix,
                   protocol_matrix, syntax_matrix)
from .guard import EarlyExit, NoveltyTracker, RateLimit, Scope
from .orchestrate import Scaffold
from .statemachine import Machine, walk_flow


def _parse_identity(spec: str) -> Identity:
    """解析身份规格：`name=cookie:k=v;k2=v2,bearer:token,role=user`

    为什么要这么土的格式：黑盒脚本经常在 shell 里拼命令，
    JSON 会被引号吃掉。key=value 形式最好传。
    """
    name, _, rest = spec.partition("=")
    role = "user"
    headers: dict[str, str] = {}
    cookies: dict[str, str] = {}
    for part in rest.split(","):
        part = part.strip()
        if part == "":
            continue
        if part.startswith("cookie:"):
            for kv in part[len("cookie:"):].split(";"):
                k, _, v = kv.partition("=")
                if k.strip():
                    cookies[k.strip()] = v.strip()
        elif part.startswith("bearer:"):
            headers["Authorization"] = "Bearer " + part[len("bearer:"):].strip()
        elif part.startswith("basic:"):
            import base64

            headers["Authorization"] = "Basic " + base64.b64encode(part[len("basic:"):].encode()).decode()
        elif part.startswith("header:"):
            kv = part[len("header:"):]
            k, _, v = kv.partition("=")
            if k:
                headers[k.strip()] = v
        elif part.startswith("role="):
            role = part[len("role="):]
    return Identity(name=name.strip() or "anon", role=role, headers=headers, cookies=cookies)


def _build_pool(args: argparse.Namespace) -> SessionPool:
    pool = SessionPool(args.base, timeout=args.timeout)
    specs = args.ids or []
    if not specs:
        specs = ["anonymous="]
    for s in specs:
        pool.add(_parse_identity(s))
    return pool


def _emit(obj: dict[str, Any], code: int = 0) -> None:
    print(json.dumps(obj, ensure_ascii=False))
    sys.exit(code)


# ── 子命令

def cmd_map(args: argparse.Namespace) -> None:
    pool = _build_pool(args)
    surf = surface_mod.Surface(base=args.base)
    seeds = [p.strip() for p in (args.paths or "/").split(",") if p.strip()]
    for ident in pool.names():
        for path in seeds:
            r = pool.send(ident, "GET", path)
            if r.error:
                continue
            surface_mod.harvest(r, surf, method="GET")
    matrix = surface_mod.probe_surface(pool, surf, identities=pool.names(),
                                       per_identity_limit=args.limit)
    out = surf.as_dict() | {"matrix": matrix["matrix"], "tested_requests": matrix["tested_requests"]}
    if args.save:
        surf.save(args.save)
        out["saved"] = args.save
    _emit(out)


def cmd_diff(args: argparse.Namespace) -> None:
    pool = _build_pool(args)
    scope = Scope.from_list([args.host] if args.host else [], deny_ports=args.deny_port or [])
    if args.host:
        ok, why = scope.check(args.base + args.path)
        if not ok:
            _emit({"error": f"scope check failed: {why}"}, 2)

    out: dict[str, Any] = {"base": args.base, "path": args.path}
    # 行为矩阵放在最前面：它是模型直接能读的形态，后面的原始差分是给机器用的
    out["behavior"] = behavior_matrix(
        pool, args.method, args.path, body=args.body,
        sensitive_markers=[s for s in (args.markers or "").split(",") if s])
    out["identity"] = identity_matrix(
        pool, args.method, args.path,
        data=args.body,
        sensitive_markers=[s for s in (args.markers or "").split(",") if s],
    )
    if args.param:
        out["syntax"] = syntax_matrix(pool, pool.names()[0], args.method, args.path,
                                      base_params={args.param: args.value}, key=args.param)
    out["protocol"] = protocol_matrix(pool, pool.names()[0], args.method, args.path)
    _emit(out)


def cmd_anomaly(args: argparse.Namespace) -> None:
    pool = _build_pool(args)
    ident = pool.names()[0]
    baseline = anomaly_mod.collect(pool, ident, args.method, args.path, samples=args.samples)
    findings: list[dict[str, Any]] = []

    # 结构硬判据：不依赖基线
    r = pool.send(ident, args.method, args.path)
    if not r.error:
        findings += [a.as_dict() for a in anomaly_mod.structural_checks(r)]
        a = anomaly_mod.detect(baseline, r)
        if a is not None:
            findings.append(a.as_dict())

    # 跨身份
    if len(pool.names()) > 1:
        findings += [a.as_dict() for a in anomaly_mod.identity_anomalies(
            pool, args.method, args.path,
            sensitive_markers=[s for s in (args.markers or "").split(",") if s])]

    _emit({"baseline": baseline.as_dict(), "anomalies": findings,
           "count": len(findings),
           "note": ("no anomaly found — this means the responses matched the baseline and no "
                    "structural marker appeared; it does NOT mean the endpoint is safe")
           if not findings else ""})


def cmd_race(args: argparse.Namespace) -> None:
    pool = _build_pool(args)
    spec = {
        "identity": pool.names()[0],
        "method": args.method,
        "path": args.path,
        "body": args.body,
        "headers": {},
    }
    reset_fn = None
    if args.reset_url:
        ident = pool.names()[0]
        reset_fn = lambda: pool.send(ident, "GET", args.reset_url)  # noqa: E731
    out = race_mod.race_probe(args.base, spec, count=args.count, session=pool, reset_fn=reset_fn)
    _emit(out)


def cmd_state(args: argparse.Namespace) -> None:
    pool = _build_pool(args)
    machine = Machine()
    flows = json.loads(args.steps)
    traces = []
    for flow in flows:
        ident = flow.get("identity") or pool.names()[0]
        traces.append(walk_flow(pool, machine, identity=ident, steps=flow.get("steps", [])))
    if args.save:
        machine.save(args.save)
    out = machine.as_dict() | {"traces": traces}
    if args.save:
        out["saved"] = args.save
    _emit(out)


def cmd_probe(args: argparse.Namespace) -> None:
    """一站式：测绘 → 差分 → 竞态 → 异常。给模型一个入口就够。"""
    pool = _build_pool(args)
    scaffold = Scaffold()
    rate = RateLimit(max_qps=args.qps)
    # P0-3：和 scaffold 共用同一个 tracker。
    # 早先这里 new 了一个独立实例，输出里 scaffold.novelty 和 guard.novelty
    # 的 zero_gain_streak 一个 0 一个 2——熔断逻辑有两个真理来源。
    novelty = scaffold.novelty
    early = EarlyExit()
    cfg_pull_js = True

    paths = [p.strip() for p in args.paths.split(",") if p.strip()]
    report: dict[str, Any] = {"base": args.base, "paths": paths, "stages": {}}

    # ── 1. 测绘（含外部 JS）
    surf = surface_mod.Surface(base=args.base)
    js_stats: list[dict[str, Any]] = []
    sheets: list[str] = []
    for ident in pool.names():
        for p in paths:
            # 限速用 acquire（阻塞等待），不是 allow（超了就放弃）。
            # 早先用 allow，qps=2 时第 3 个请求就把整轮作业终止了——
            # 越保守的限速 = 越早的死法。
            if not rate.acquire(timeout=60):
                report["stopped"] = "rate limit: could not acquire a slot within 60s (is qps configured to 0?)"
                break
            r = pool.send(ident, "GET", p)
            rate.record(r.error == "")
            if r.error:
                continue
            surface_mod.harvest(r, surf)
            sheets.append(p)
            obs = scaffold.observe(r.status, r.headers, r.body)
            novelty.observe(
                errors=[h for h in ["stack", "sql", "debug"] if h in str(obs["body"]).lower()],
                params=r.json_keys(),
            )
            # 拉页面引用的同源 JS —— SPA 的路由全在那里
            if cfg_pull_js:
                for _ in range(3):          # 每个页面最多 3 个脚本，避免爬站
                    st = surface_mod.harvest_js(pool, ident, surf, r.body, r.url or f"{args.base}{p}")
                    js_stats.append(st)
                    if st["endpoints_added"] == 0:
                        break

    probe_result = surface_mod.probe_surface(pool, surf, identities=pool.names(),
                                             per_identity_limit=args.limit) if surf.endpoints else {"matrix": [], "tested_requests": 0}

    # 感知盲区判定：什么都没挖到，和"目标干净"是两件事
    blind = []
    redirects = [l for l in surf.leaks if l["kind"] in ("redirect-target", "redirect-param")]
    if len(surf.endpoints) == 0 and redirects:
        blind.append("every entry redirected away — this target is behind an auth wall, "
                     "not empty. Supply an authenticated identity (--ids with a real cookie/token) "
                     "or test the redirect parameters themselves")
    elif len(surf.endpoints) == 0:
        blind.append("no endpoint discovered — the response contained no links, forms or JS routes "
                     "(SPA shell, or the entry path is not a page)")
    if len(surf.leaks) == 0:
        blind.append("no framework/version/path leak in the response")
    report["stages"]["map"] = {
        "endpoints": len(surf.endpoints),
        "leaks": surf.leaks[:10],
        "js": js_stats[:5],
        **({"matrix": probe_result["matrix"]} if probe_result["matrix"] else {}),
        **({"blind_spots": blind} if blind else {}),
    }

    # 2. 差分 + 异常
    diffs = []
    for p in paths:
        ok, _ = early.guard()
        if not ok:
            break
        if not rate.acquire(timeout=60):
            report["stopped"] = "rate limit: could not acquire a slot within 60s"
            break
        d = identity_matrix(pool, "GET", p,
                            sensitive_markers=[s for s in (args.markers or "").split(",") if s])
        rate.record(True)
        for diff in d["differences"]:
            if diff.get("sensitive"):
                early.trip("cross-identity data exposure confirmed",
                           {"endpoint": p, "evidence": diff})
            diffs.append(diff)
        inter = scaffold.inter_reflect(gained=bool(d["differences"]))
        if inter["action"] == "prune":
            report["stages"].setdefault("pruned", []).append(p)
    report["stages"]["diff"] = {
        "differences": diffs[:20],
        **({"note": "only one identity configured — differential testing needs at least two "
                    "(e.g. two tenants, or user vs anonymous) to mean anything"}
           if len(pool.names()) < 2 else {}),
    }

    # 3. 竞态（只对 POST 路径跑）
    if args.race_path:
        reset_fn = None
        if args.reset_url:
            _ident = pool.names()[0]
            reset_fn = lambda: pool.send(_ident, "GET", args.reset_url)  # noqa: E731
        report["stages"]["race"] = race_mod.race_probe(
            args.base, {"identity": pool.names()[0], "method": "POST",
                        "path": args.race_path, "body": args.race_body},
            count=args.count, session=pool, reset_fn=reset_fn)

    report["scaffold"] = scaffold.as_dict()
    report["guard"] = {"rate": {"qps": args.qps}, "novelty": novelty.stats(),
                       "early_exit": {"tripped": early.tripped, "reason": early.reason,
                                      "evidence": early.evidence}}
    _emit(report)


def cmd_intel(args: argparse.Namespace) -> None:
    """RFC 微灵感：原语矩阵 + 规范断言 + 边缘语料。"""
    m = intel_mod.build_matrix(rfcs=args.rfcs.split(",") if args.rfcs else None,
                               include_cache=not args.no_cache)
    out = m.as_dict()
    if not args.full:
        out.pop("matrix", None)
        out.pop("cache", None)
    _emit(out)


def cmd_resonance(args: argparse.Namespace) -> None:
    """跨目标共振：把多个目标的异常聚成簇，标出跨目标的那些。"""
    raw = json.loads(args.observations)
    obs = [resonance_mod.Observation(**o) for o in raw]
    clusters = resonance_mod.cluster(obs, threshold=args.threshold)
    _emit(resonance_mod.summarize(clusters))


def cmd_evolve(args: argparse.Namespace) -> None:
    """参数进化：需要一个能给出评分的靶场。

    评分函数在 CLI 里只支持内置靶机——真实项目上必须先有 ground truth，
    否则进化会收敛到一个自洽但无意义的参数组合。
    """
    import subprocess
    import time

    port = args.port
    proc = subprocess.Popen([sys.executable, "-m", "blackbox.target", "--port", str(port)],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2.0)
    base = f"http://127.0.0.1:{port}"

    def fetch(path: str, headers: dict | None = None) -> tuple[int, str, str]:
        import urllib.request
        req = urllib.request.Request(base + path, headers=headers or {})
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, r.read().decode("utf-8", "replace"), r.headers.get("set-cookie", "") or ""
        except Exception as exc:
            return 0, str(exc), ""

    def login(user: str) -> str:
        import urllib.parse
        import urllib.request
        data = urllib.parse.urlencode({"user": user}).encode()
        req = urllib.request.Request(base + "/api/login", data=data,
                                     headers={"Content-Type": "application/x-www-form-urlencoded"})
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                sc = r.headers.get("set-cookie", "") or ""
                return sc.split("sid=")[-1].split(";")[0]
        except Exception:
            return ""

    # 靶机已知缺陷：检出这些算命中
    KNOWN = ["cross-identity-leak", "stack-trace", "path-leak", "race-detected", "field-appearance"]

    def evaluate(strategy) -> tuple[float, dict]:
        sid = login("alice")
        if sid == "":
            return 0.0, {"error": "login failed"}
        try:
            proc_name = "probe"
            argv = [sys.executable, "-m", "blackbox.cli", proc_name, "--base", base,
                    "--paths", "/,/api/invoice/2,/api/debug?crash=1,/api/search",
                    "--ids", f"alice=cookie:sid={sid},role=user",
                    "--markers", "bob,9500",
                    "--race-path", "/api/redeem", "--race-body", "coupon=WELCOME",
                    "--reset-url", "/api/reset",
                    "--qps", str(strategy.qps)]
            r = subprocess.run(argv, capture_output=True, timeout=180,
                               cwd=str(Path(__file__).parent.parent))
            out = json.loads(r.stdout.decode().strip().split("\n")[-1] or "{}")
        except Exception as exc:
            return 0.0, {"error": f"{type(exc).__name__}: {exc}"[:120]}
        finally:
            try:
                fetch("/api/reset")
            except Exception:
                pass

        hit = set()
        for d in (out.get("stages", {}).get("diff", {}).get("differences") or []):
            if d.get("sensitive"):
                hit.add("cross-identity-leak")
        race = out.get("stages", {}).get("race", {})
        if race.get("verdict") == "race-detected":
            hit.add("race-detected")
        for leak in (out.get("stages", {}).get("map", {}).get("leaks") or []):
            if leak.get("kind") == "path":
                hit.add("path-leak")
        detected = len(hit & set(KNOWN))
        # 评分：命中为主（0-1 归一），并发越高耗时越长做轻微惩罚
        score = detected / 3.0 - strategy.concurrency / 400.0
        return score, {"detected": sorted(hit), "verdicts": {"race": race.get("verdict")}}

    try:
        result = evolve_mod.evolve(evaluate, budget=args.budget, seed=args.seed)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
    _emit(result)


def _survey_handler(pool, rate, target) -> "campaign_mod.Record":
    """campaign 的单目标处理：探测 → 提取 → 分类 → 打分。"""
    import time as _t

    rec = campaign_mod.Record(host=target.host, started=_t.time(), finished=0.0, ok=True)
    if not rate.acquire(60):
        rec.error = "rate limit"; return rec
    ident = pool.names()[0] if pool.names() else "anonymous"
    r = pool.send(ident, "GET", "/")
    rate.record(r.error == "")
    if r.error:
        rec.error = r.error[:80]; rec.kind = "dead"; return rec

    surf = surface_mod.Surface(base=target.url)
    surface_mod.harvest(r, surf)
    js_stats = {"fetched": 0}
    js_intel = []
    if "<script" in (r.body or "") or "<form" in (r.body or ""):
        js_stats = surface_mod.harvest_js(pool, ident, surf, r.body, r.url or target.url)
        # JS 深度分析：调用点带方法，比裸路径可靠
        for u in []:
            pass
    rec.leaks = surf.leaks[:10]
    rec.endpoints = len(surf.endpoints)
    rec.js_fetched = int(js_stats.get("fetched") or 0)
    rec.status = r.status

    v = classify_mod.classify(
        status=r.status, headers=r.headers, body=r.body or "",
        content_type=(r.headers.get("content-type") or ""),
        endpoints=rec.endpoints, js_fetched=rec.js_fetched, leaks=len(rec.leaks))
    rec.kind, rec.score, rec.reasons = v.kind, v.score, v.reasons
    rec.extra = {"server": r.headers.get("server", "")[:40],
                 "redirect_to": (r.headers.get("location") or "")[:80],
                 **(js_stats if js_stats.get("fetched") else {})}
    rec.finished = _t.time()
    return rec


def cmd_batch(args: argparse.Namespace) -> None:
    """批量普查：给一个 host 列表，跑完出聚合报告 + 资产关系。"""
    hosts = [h.strip() for h in args.hosts.split(",") if h.strip()]
    if args.hosts_file:
        hosts += [l.strip() for l in open(args.hosts_file) if l.strip() and not l.startswith("#")]
    targets = [campaign_mod.Target(host=h) for h in dict.fromkeys(hosts)]

    camp = campaign_mod.Campaign(args.out, qps_per_target=args.qps,
                                 concurrency=args.concurrency)
    resumed = camp.done_count
    done = camp.run(targets, _survey_handler)
    rep = camp.report()

    graph = assetgraph_mod.build_from_records(list(camp._done.values()))
    out = {
        "resumed_from": resumed,
        "ran_this_time": len(done),
        **rep,
        "asset_graph": graph.as_dict(),
        "state_file": str(camp.state_path),
    }
    _emit(out)


def cmd_biz(args: argparse.Namespace) -> None:
    """业务状态机：从端点清单生成非法跃迁测试，并（在安全范围内）执行。"""
    endpoints = json.loads(args.endpoints) if args.endpoints else []
    actions = []
    for e in endpoints:
        if isinstance(e, str) and " " in e:
            m, _, p = e.partition(" ")
            actions.append((m, p))
        elif isinstance(e, (list, tuple)) and len(e) == 2:
            actions.append((e[0], e[1]))
    if not actions:
        _emit({"error": "endpoints required as JSON: [[\"POST\",\"/api/order\"],[\"GET\",\"/api/order/1\"]]"}, 2)

    models = bizmodel_mod.build(actions)
    tests = bizmodel_mod.illegal_transitions(models)
    report: dict[str, Any] = {
        "resources": [m.as_dict() for m in models.values()],
        "test_points": tests[:40],
        "total_tests": len(tests),
    }

    if args.execute:
        pool = _build_pool(args)
        creds = None
        if args.ids:
            creds = CredentialPool(args.base, pool)
            for spec in args.ids:
                ident = _parse_identity(spec)
                creds.add(Credential(name=ident.name, role=ident.role,
                                     headers=ident.headers, cookies=ident.cookies,
                                     verify_path=args.verify_path))
            report["credentials"] = creds.verify_all()
        report["execution"] = invariant_mod.run(
            tests, pool, creds=creds,
            rate=RateLimit(max_qps=args.qps), allow_write=args.allow_write)
    _emit(report)


def main() -> None:
    ap = argparse.ArgumentParser(prog="blackbox", description="纯黑盒探测原语")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def add_common(p: argparse.ArgumentParser) -> None:
        p.add_argument("--base", required=True, help="目标根 URL")
        p.add_argument("--ids", action="append", default=[],
                       help="身份规格，可多次给：name=cookie:k=v;k2=v2,role=user")
        p.add_argument("--timeout", type=float, default=15.0)
        p.add_argument("--host", default="", help="范围白名单里的主机名（给了就强制校验）")
        p.add_argument("--deny-port", type=int, action="append", default=[])
        p.add_argument("--markers", default="", help="只有某个身份才该看到的标记，逗号分隔")

    m = sub.add_parser("map", help="端点测绘")
    add_common(m)
    m.add_argument("--paths", default="/", help="起点路径，逗号分隔")
    m.add_argument("--limit", type=int, default=40)
    m.add_argument("--save", default="")
    m.set_defaults(func=cmd_map)

    d = sub.add_parser("diff", help="四维差分")
    add_common(d)
    d.add_argument("--method", default="GET")
    d.add_argument("--path", required=True)
    d.add_argument("--body", default=None)
    d.add_argument("--param", default="")
    d.add_argument("--value", default="1")
    d.set_defaults(func=cmd_diff)

    a = sub.add_parser("anomaly", help="基线与异常检测")
    add_common(a)
    a.add_argument("--method", default="GET")
    a.add_argument("--path", required=True)
    a.add_argument("--samples", type=int, default=5)
    a.set_defaults(func=cmd_anomaly)

    r = sub.add_parser("race", help="单包竞态探测")
    add_common(r)
    r.add_argument("--method", default="POST")
    r.add_argument("--path", required=True)
    r.add_argument("--body", default="")
    r.add_argument("--count", type=int, default=10)
    r.add_argument("--reset-url", default="",
                   help="两组测试之间调用的重置地址（一次性接口必填，否则第二组测的是耗尽态）")
    r.set_defaults(func=cmd_race)

    s = sub.add_parser("state", help="状态机反推")
    add_common(s)
    s.add_argument("--steps", required=True, help='JSON: [{"identity":"a","steps":[{"path":"/x"}]}]')
    s.add_argument("--save", default="")
    s.set_defaults(func=cmd_state)

    p = sub.add_parser("probe", help="一站式探测")
    add_common(p)
    p.add_argument("--paths", required=True, help="要测的路径，逗号分隔")
    p.add_argument("--race-path", default="")
    p.add_argument("--race-body", default="")
    p.add_argument("--reset-url", default="")
    p.add_argument("--count", type=int, default=10)
    p.add_argument("--qps", type=float, default=20.0)
    p.add_argument("--limit", type=int, default=20, help="每个身份最多探测多少个端点")
    p.set_defaults(func=cmd_probe)

    it = sub.add_parser("intel", help="RFC 微灵感矩阵")
    add_common(it)
    it.add_argument("--rfcs", default="", help="逗号分隔的 RFC 编号，空=全部本地语料")
    it.add_argument("--no-cache", action="store_true")
    it.add_argument("--full", action="store_true", help="输出完整矩阵（体积大）")
    it.set_defaults(func=cmd_intel, base=it.get_default("base") or "")

    rs = sub.add_parser("resonance", help="跨目标异常共振聚类")
    add_common(rs)
    rs.add_argument("--observations", required=True,
                    help='JSON: [{"target":"a","kind":"stack-trace","endpoint":"/x","detail":"..."}]')
    rs.add_argument("--threshold", type=float, default=0.45)
    rs.set_defaults(func=cmd_resonance)

    ev = sub.add_parser("evolve", help="参数进化（内置靶场评分）")
    add_common(ev)
    ev.add_argument("--port", type=int, default=8123)
    ev.add_argument("--budget", type=int, default=12)
    ev.add_argument("--seed", type=int, default=0)
    ev.set_defaults(func=cmd_evolve)

    bt = sub.add_parser("batch", help="批量普查 + 聚合 + 资产关系")
    add_common(bt)
    bt.add_argument("--hosts", default="", help="逗号分隔的 host")
    bt.add_argument("--hosts-file", default="", help="每行一个 host 的文件")
    bt.add_argument("--out", required=True, help="作业目录（状态与报告落这里）")
    bt.add_argument("--concurrency", type=int, default=4)
    bt.add_argument("--qps", type=float, default=3.0, help="每个目标的 qps")
    bt.set_defaults(func=cmd_batch)

    bz = sub.add_parser("biz", help="业务状态机与不变量测试")
    add_common(bz)
    bz.add_argument("--endpoints", required=True,
                    help='JSON: [["POST","/api/order"],["GET","/api/order/1"]]')
    bz.add_argument("--execute", action="store_true", help="真的执行（默认只生成测试点）")
    bz.add_argument("--allow-write", action="store_true", help="允许会产生写入的测试")
    bz.add_argument("--verify-path", default="/", help="凭据验证探针路径")
    bz.add_argument("--qps", type=float, default=3.0)
    bz.set_defaults(func=cmd_biz)

    args = ap.parse_args()
    try:
        args.func(args)
    except SystemExit:
        raise
    except Exception as exc:      # 兜底：任何未捕获异常都变成结构化输出
        _emit({"error": f"{type(exc).__name__}: {str(exc)[:300]}"}, 1)


if __name__ == "__main__":
    main()
