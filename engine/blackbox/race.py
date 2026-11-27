#!/usr/bin/env python3
"""竞态与协议层探测 —— 黑盒里唯一需要 socket 级控制的部分。

## 为什么需要单包攻击

普通并发请求的到达时间差由网络和调度决定，通常是几毫秒到几十毫秒，
而很多竞态窗口只有几百微秒。两者差两个数量级，所以"多发几个请求"永远
撞不进那个窗口。

James Kettle 的单包攻击（Single-Packet Attack）解决的是这件事：
把 N 个请求的最后 1 个字节攒起来，用**一次 sendall** 发出去。
TCP 会把它们放进同一个数据包，于是服务端几乎同时看到所有请求的结尾，
到达窗口能压到 0.3~1 毫秒。

## 这里实现的两件事

**单包同步**：HTTP/2 下每个 stream 的最后一个 DATA 帧合并发送。
**子状态探测**：先顺序发 N 次看基线，再单包并发发 N 次看结果分布。
  如果分布出现分歧（同样的请求，有的成功有的失败，或者返回的 id 不连续），
  说明服务端存在非原子的隐藏状态——那正是竞态漏洞的可利用前提。

## 不做什么

不判断"这个竞态能不能造成损失"。那是业务理解，属于模型的活。
这里只负责把"非原子性"这个事实测出来，并给出可复现的原始请求。
"""

from __future__ import annotations

import socket
import ssl
import time
from dataclasses import dataclass, field
from typing import Any

try:
    import h2.config
    import h2.connection
    import h2.events
    HAS_H2 = True
except Exception:      # pragma: no cover
    HAS_H2 = False


@dataclass
class RaceResult:
    """一次并发重放的结果。"""
    label: str
    statuses: list[int] = field(default_factory=list)
    bodies: list[str] = field(default_factory=list)
    elapsed_ms: float = 0.0
    error: str = ""

    @property
    def successes(self) -> int:
        """2xx 的次数。竞态判定的核心量——不是"结果是否不同"，是"成功了几次"。"""
        return sum(1 for s in self.statuses if 200 <= s < 300)

    @property
    def divergent(self) -> bool:
        """结果是否出现分歧。

        判据用**状态码集合**和**响应体去重后的数量**：同样的请求、
        同一时间发出，如果服务端给出不同结果，说明它内部有非原子状态。
        """
        if self.error:
            return False
        if len(set(self.statuses)) > 1:
            return True
        return len({b for b in self.bodies}) > 1

    def as_dict(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "requests": len(self.statuses),
            "statuses": sorted(set(self.statuses)),
            "distinct_bodies": len({b for b in self.bodies}),
            "elapsed_ms": round(self.elapsed_ms, 1),
            "divergent": self.divergent,
            **({"error": self.error} if self.error else {}),
        }


def _parse_url(url: str) -> tuple[str, int, bool]:
    from urllib.parse import urlparse

    u = urlparse(url)
    host = u.hostname or ""
    port = u.port or (443 if u.scheme == "https" else 80)
    return host, port, u.scheme == "https"


def _connect(host: str, port: int, use_tls: bool, timeout: float) -> socket.socket:
    sock = socket.create_connection((host, port), timeout=timeout)
    # 关键：禁掉 Nagle。Nagle 会把小包攒起来再发，正好抵消我们要做的事。
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    if use_tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        # ALPN 必须协商成 h2，否则服务端会退回 HTTP/1.1，单包攻击无从谈起
        ctx.set_alpn_protocols(["h2"])
        sock = ctx.wrap_socket(sock, server_hostname=host)
        if sock.selected_alpn_protocol() != "h2":
            raise RuntimeError(f"server did not negotiate h2 (got {sock.selected_alpn_protocol()})")
    return sock


def single_packet_attack(url: str, requests_spec: list[dict[str, Any]], *,
                         timeout: float = 10.0,
                         warmup: int = 1) -> RaceResult:
    """HTTP/2 单包攻击。

    requests_spec 每项形如：
        {"method": "POST", "path": "/redeem", "headers": {...}, "body": "..."}

    所有请求各自独立成 stream，body 的**最后一个字节**留到最后一轮统一发。
    这样服务端几乎同时看到所有请求的结尾，而各自的前置处理（解析头部、
    读完整 body 前的检查）已经分别跑过了——竞态窗口就开在这里。
    """
    if not HAS_H2:
        return RaceResult(label="single-packet", error="h2 not installed")

    host, port, use_tls = _parse_url(url)
    result = RaceResult(label="single-packet")
    sock: socket.socket | None = None
    started = time.perf_counter()
    try:
        sock = _connect(host, port, use_tls, timeout)
        cfg = h2.config.H2Configuration(client_side=True, header_encoding="utf-8")
        conn = h2.connection.H2Connection(config=cfg)
        conn.initiate_connection()
        sock.sendall(conn.data_to_send())

        # 预热一轮：让 TLS/连接/服务端的懒初始化都完成，
        # 否则第一次请求的额外开销会污染时序
        for _ in range(max(0, warmup)):
            sid = conn.get_next_available_stream_id()
            conn.send_headers(sid, [
                (":method", "GET"), (":path", "/"), (":scheme", "https" if use_tls else "http"),
                (":authority", host),
            ], end_stream=True)
            sock.sendall(conn.data_to_send())
            time.sleep(0.05)

        stream_ids: list[int] = []
        tails: dict[int, bytes] = {}

        # 第一轮：发到倒数第二个字节（headers + body[:-1]）
        for spec in requests_spec:
            sid = conn.get_next_available_stream_id()
            stream_ids.append(sid)
            body = (spec.get("body") or "").encode()
            hdrs = [
                (":method", spec.get("method", "POST")),
                (":path", spec.get("path", "/")),
                (":scheme", "https" if use_tls else "http"),
                (":authority", host),
            ]
            for k, v in (spec.get("headers") or {}).items():
                hdrs.append((k.lower(), v))
            if body:
                hdrs.append(("content-length", str(len(body))))
                conn.send_headers(sid, hdrs, end_stream=False)
                if len(body) > 1:
                    conn.send_data(sid, body[:-1], end_stream=False)
                tails[sid] = body[-1:]
            else:
                tails[sid] = b""
                conn.send_headers(sid, hdrs, end_stream=False)

        sock.sendall(conn.data_to_send())
        # 等一小会儿，保证所有前置帧都已经到达服务端
        time.sleep(0.1)

        # 第二轮：把所有尾字节攒进同一个发送
        for sid in stream_ids:
            tail = tails.get(sid, b"")
            conn.send_data(sid, tail, end_stream=True)
        payload = conn.data_to_send()
        sock.sendall(payload)          # ← 单包：所有请求的结尾在同一次 sendall 里

        # 收响应
        sock.settimeout(timeout)
        pending = set(stream_ids)
        responses: dict[int, dict[str, Any]] = {}
        deadline = time.time() + timeout
        while pending and time.time() < deadline:
            try:
                data = sock.recv(65535)
            except socket.timeout:
                break
            if not data:
                break
            for event in conn.receive_data(data):
                if isinstance(event, h2.events.ResponseReceived):
                    hdrs = {k.decode(): v.decode() for k, v in event.headers}
                    responses.setdefault(event.stream_id, {})["status"] = int(hdrs.get(":status", 0))
                elif isinstance(event, h2.events.DataReceived):
                    rec = responses.setdefault(event.stream_id, {})
                    rec["body"] = (rec.get("body", "") + event.data.decode("utf-8", "replace"))[:4000]
                    conn.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                elif isinstance(event, h2.events.StreamEnded):
                    pending.discard(event.stream_id)
            sock.sendall(conn.data_to_send()) if conn.data_to_send() else None

        for sid in stream_ids:
            rec = responses.get(sid, {})
            result.statuses.append(rec.get("status", 0))
            result.bodies.append(rec.get("body", ""))
    except Exception as exc:
        result.error = f"{type(exc).__name__}: {str(exc)[:160]}"
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass

    result.elapsed_ms = (time.perf_counter() - started) * 1000
    return result


def sequential_baseline(url: str, spec: dict[str, Any], count: int, *, session) -> RaceResult:
    """顺序重放的基线。和并发结果对比才知道分歧是不是竞态造成的。"""
    result = RaceResult(label="sequential")
    started = time.perf_counter()
    for _ in range(count):
        r = session.send(
            spec.get("identity", "anonymous"),
            spec.get("method", "POST"),
            spec.get("path", "/"),
            data=spec.get("body"),
            headers=spec.get("headers"),
        )
        if r.error:
            result.error = r.error
            continue
        result.statuses.append(r.status)
        result.bodies.append(r.body[:4000])
        time.sleep(0.02)
    result.elapsed_ms = (time.perf_counter() - started) * 1000
    return result


def threaded_burst(pool, spec: dict[str, Any], count: int) -> RaceResult:
    """HTTP/1.1 下的并发爆发。

    单包攻击需要 h2 目标；大量真实目标只开 HTTP/1.1。这个模式用
    多个连接同时发同一请求，到达窗口是毫秒级——够抓 sleep(1ms) 那类窗口，
    但抓不到微秒级的。定位是"没有 h2 时的可用替代"，不是等价物。

    实现上用 barrier 让所有线程在发请求前对齐，把调度抖动压到最小。
    """
    import threading

    result = RaceResult(label="threaded-burst")
    barrier = threading.Barrier(count, timeout=10)
    lock = threading.Lock()
    started = time.perf_counter()

    # 每个线程必须有自己的连接。
    # 共享 requests.Session 会串行化：HTTP/1.1 的 keep-alive 连接不能被多个线程
    # 同时使用，Session 内部还会加锁。结果就是"并发"变成排队，
    # 竞态窗口永远撞不上——实测表现为并发成功 0 次，比顺序还差。
    ident_name = spec.get("identity", "anonymous")
    ident = getattr(pool, "identities", {}).get(ident_name)
    base_headers = dict(getattr(pool, "base_headers", {}) or {})
    if ident is not None:
        base_headers.update(ident.headers)
    cookies = dict(ident.cookies) if ident is not None else {}
    timeout = getattr(pool, "timeout", 15.0)
    verify = getattr(pool, "verify_tls", False)
    base_url = getattr(pool, "base_url", url if "url" in dir() else "")
    path = spec.get("path", "/")
    target_url = path if str(path).startswith("http") else f"{base_url}{path}"

    def worker() -> None:
        import requests as _rq

        try:
            barrier.wait()
        except Exception:
            return
        try:
            resp = _rq.request(
                spec.get("method", "POST"), target_url,
                data=spec.get("body"), headers={**base_headers, **(spec.get("headers") or {})},
                cookies=cookies, timeout=timeout, allow_redirects=False, verify=verify,
            )
            with lock:
                result.statuses.append(resp.status_code)
                result.bodies.append(resp.text[:4000])
        except Exception as exc:
            with lock:
                result.error = result.error or f"{type(exc).__name__}: {exc}"[:160]

    threads = [threading.Thread(target=worker) for _ in range(count)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=20)
    result.elapsed_ms = (time.perf_counter() - started) * 1000
    return result


def race_probe(url: str, spec: dict[str, Any], *, count: int = 10,
               session=None, reset_fn=None, rounds: int = 3) -> dict[str, Any]:
    """完整的一次竞态探测。

    ## 为什么必须多轮

    竞态窗口是"有时候开、有时候不开"的。实测同一个靶子：
    第一轮并发成功 4/8（顺序 1/8），第二、三轮只有 1/8——窗口只有 5 毫秒时，
    线程能不能同时挤进去取决于调度。

    **用单轮结果下结论，两个方向都会错**：命中一次就报"有竞态"可能是巧合，
    没命中就报"没竞态"则是漏报。所以这里跑多轮，任一轮出现并发超发即判定，
    并把每轮的数据都列出来——让人能看出这是稳定复现还是碰巧撞上。

    ## 两组必须从同一初始状态出发

    一次性消耗型接口（优惠券、余额、邀请码）在第一组就耗尽了，
    不重置的话第二组测的是"耗尽态"，结论完全反了。
    """
    rounds_data: list[dict[str, Any]] = []
    any_race = False
    last_reason = ""
    last_verdict = "inconclusive"

    for r in range(max(1, rounds)):
        if reset_fn is not None:
            try:
                reset_fn()
            except Exception:
                pass
        seq = sequential_baseline(url, spec, count, session=session) if session is not None \
            else RaceResult(label="sequential", error="no session provided")
        if reset_fn is not None:
            try:
                reset_fn()
            except Exception:
                pass
        specs = [{**spec} for _ in range(count)]
        par = single_packet_attack(url, specs)
        # h2 不可用（或目标不支持）时，用线程并发作为替代，并如实标注
        burst = threaded_burst(session, spec, count) if session is not None else None
        if par.error and burst is not None:
            par = burst

        seq_ok, par_ok = seq.successes, par.successes
        if par.error:
            verdict, reason = "unknown", f"concurrent burst failed: {par.error}"
        elif seq.error:
            verdict, reason = "unknown", f"sequential baseline failed: {seq.error}"
        elif par_ok > seq_ok:
            verdict = "race-detected"
            reason = (f"sequential replay succeeded {seq_ok}/{count} times (correct behaviour), "
                      f"but {count} concurrent requests succeeded {par_ok} times — "
                      f"the same operation was applied more than once")
            any_race = True
        elif par_ok == seq_ok and seq_ok > 0:
            verdict, reason = "no-race", f"both produced {seq_ok} success(es) out of {count}"
        elif par_ok == 0 and seq_ok == 0:
            verdict, reason = "no-effect", "neither replay succeeded — wrong request, not a safe endpoint"
        else:
            verdict, reason = "concurrent-worse", f"concurrent {par_ok} < sequential {seq_ok} — likely rate limiting"

        last_verdict, last_reason = verdict, reason
        rounds_data.append({
            "round": r + 1,
            "sequential": seq.as_dict(),
            "concurrent": par.as_dict(),
            "verdict": verdict,
            "successes": {"sequential": seq_ok, "concurrent": par_ok},
        })

    # 最终判定：任一轮命中即为有竞态；全部轮次都无命中才算没有
    if any_race:
        final, why = "race-detected", next(d["round"] for d in rounds_data if d["verdict"] == "race-detected")
        last_reason = f"detected in round {why} of {rounds} — " + last_reason
        last_verdict = "race-detected"
    elif all(d["verdict"] == "no-race" for d in rounds_data):
        final, last_reason = "no-race", f"no divergence across {rounds} rounds"
    elif all(d["verdict"] == "no-effect" for d in rounds_data):
        final = "no-effect"
    else:
        final = last_verdict

    return {
        "url": url,
        "count": count,
        "rounds": rounds,
        "rounds_data": rounds_data,
        "verdict": final,
        "successes": rounds_data[-1]["successes"] if rounds_data else {"sequential": 0, "concurrent": 0},
        "reason": last_reason,
    }
