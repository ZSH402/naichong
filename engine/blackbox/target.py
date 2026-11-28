#!/usr/bin/env python3
"""本地黑盒靶机 —— 故意做出五类可被外部观测的缺陷。

存在的理由：黑盒探测的每一条判据都必须能被**已知答案**验证。
自造靶机是唯一能做到这一点的办法——知道漏洞在哪、什么形态，
才能判断探测器是把真信号抓出来了，还是在对噪声编故事。

刻意埋的六处：
  1. BOLA        GET  /api/invoice/<id>      不校验归属，A 能读 B 的
  2. 参数污染     GET  /api/search?id=1&id=2  取第一个，与代理取最后一个冲突
  3. 栈泄露       GET  /api/debug?crash=1     除零，把 traceback 打给客户端
  4. 竞态         POST /api/redeem            余额检查与扣减之间有 5ms 窗口
  5. 状态机       POST /api/login → /api/checkout  跳过 login 也能到 checkout
  6. 诱饵迷宫     GET  /trap/<n>              无限派生链接，后端状态零变化

启动：python3 -m blackbox.target --port 8099
"""

from __future__ import annotations

import argparse
import json
import random
import threading
import time
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

# 两个用户各有一张发票，互相不该可见
INVOICES = {
    "1": {"owner": "alice", "amount": 1200, "memo": "consulting-2026-03"},
    "2": {"owner": "bob", "amount": 9500, "memo": "hardware-2026-01"},
}

BALANCES = {"alice": 100, "bob": 100}
PRICE = 100
COUPONS = {"WELCOME": 1}

SESSIONS: dict[str, str] = {}      # sid -> user
REDEEM_LOCK = threading.Lock()     # 存在但不使用 —— 这正是竞态的成因


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args) -> None:   # 静音
        pass

    # ── 工具

    def _json(self, code: int, body: dict) -> None:
        raw = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _html(self, code: int, body: str) -> None:
        raw = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _user(self) -> str | None:
        cookie = self.headers.get("Cookie", "")
        for part in cookie.split(";"):
            k, _, v = part.strip().partition("=")
            if k == "sid" and v in SESSIONS:
                return SESSIONS[v]
        return None

    def _params(self) -> list[tuple[str, str]]:
        """返回**原始**查询串里的 (k, v) 序列，不做去重。

        `parse_qs` 会把重复键合并成数组，那样就看不到 `id=1&id=2` 的原始顺序了，
        而这正是参数污染要观测的东西。
        """
        q = urlparse(self.path).query
        out = []
        for seg in q.split("&"):
            if not seg:
                continue
            k, _, v = seg.partition("=")
            out.append((k, v))
        return out

    # ── 路由

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        params = self._params()

        if path == "/":
            self._html(200, """<html><body>
              <h1>Acme Billing</h1>
              <a href="/api/invoice/1">invoice 1</a>
              <a href="/api/invoice/2">invoice 2</a>
              <a href="/api/search?id=1">search</a>
              <form action="/api/login" method="POST"><input name="user"></form>
              <script>fetch('/api/checkout').catch(()=>{})</script>
            </body></html>""")
            return

        if path.startswith("/api/invoice/"):
            inv_id = path.rsplit("/", 1)[-1]
            inv = INVOICES.get(inv_id)
            if inv is None:
                self._json(404, {"error": "not found"})
                return
            user = self._user()
            if user is None:
                self._json(401, {"error": "login required"})
                return
            # 缺陷 1：只检查"登录了"，不检查"是不是你的"
            self._json(200, {"invoice_id": inv_id, **inv})
            return

        if path == "/api/search":
            # 缺陷 2：取第一个 id；而多数代理/框架会取最后一个
            first = next((v for k, v in params if k == "id"), None)
            last = next((v for k, v in reversed(params) if k == "id"), None)
            self._json(200, {"used": first, "would_be_used_by_last_wins": last,
                             "results": [f"row-{first}"] if first else []})
            return

        if path == "/api/debug":
            if "crash" in dict(params):
                # 缺陷 3：把服务端栈帧原样返回
                try:
                    1 / 0
                except ZeroDivisionError:
                    self._html(500, "<pre>" + traceback.format_exc() + "</pre>")
                return
            self._json(200, {"ok": True})
            return

        if path == "/api/checkout":
            user = self._user()
            if user is None:
                # 缺陷 5：这里只判"有没有会话"，不判"是不是走完了登录流程"
                self._json(200, {"status": "order placed", "user": "anonymous"})
                return
            self._json(200, {"status": "order placed", "user": user})
            return

        if path == "/api/reset":
            BALANCES["alice"] = 100
            BALANCES["bob"] = 100
            COUPONS["WELCOME"] = 1
            self._json(200, {"reset": True})
            return

        if path.startswith("/trap/"):
            # 缺陷 6：无限派生，后端状态零变化
            n = int(path.rsplit("/", 1)[-1] or "0")
            links = "".join(f'<a href="/trap/{n * 10 + i}">t{n * 10 + i}</a>' for i in range(1, 4))
            self._html(200, f"<html><body><p>decoy level {n}</p>{links}</body></html>")
            return

        self._json(404, {"error": "no route"})

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        form = dict(p.partition("=")[::2] for p in raw.split("&") if p)

        if path == "/api/login":
            user = form.get("user", "")
            if user not in BALANCES:
                self._json(403, {"error": "unknown user"})
                return
            sid = f"s{random.randint(100000, 999999)}"
            SESSIONS[sid] = user
            body = json.dumps({"ok": True, "user": user}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Set-Cookie", f"sid={sid}; Path=/")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if path == "/api/redeem":
            user = self._user()
            if user is None:
                self._json(401, {"error": "login required"})
                return
            coupon = form.get("coupon", "")
            if coupon not in COUPONS or COUPONS[coupon] <= 0:
                self._json(409, {"error": "coupon exhausted"})
                return
            # 缺陷 4：检查与扣减之间没有原子性
            if BALANCES[user] >= PRICE:
                time.sleep(0.02)               # ← 窗口（20ms：5ms 太小，调度抖动会让并发撞不进去）
                BALANCES[user] -= PRICE
                COUPONS[coupon] -= 1
                self._json(200, {"status": "redeemed", "balance": BALANCES[user]})
                return
            self._json(402, {"error": "insufficient balance", "balance": BALANCES[user]})
            return

        self._json(404, {"error": "no route"})


def serve(port: int = 8099) -> ThreadingHTTPServer:
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    srv.daemon_threads = True
    return srv


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8099)
    args = ap.parse_args()
    srv = serve(args.port)
    print(f"靶机: http://127.0.0.1:{args.port}")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
