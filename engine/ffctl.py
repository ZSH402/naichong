#!/usr/bin/env python3
"""极简 Firefox Marionette 客户端。

用途：直接用**已登录的浏览器**执行 JS —— 不必再猜 API、不必解密 cookie。
Marionette 是 Firefox 内置的自动化协议，连上就能 newSession / navigate / executeScript。

协议：TCP 2828，消息是 `<十进制长度>:<JSON>`。
"""
import json
import socket
import sys
import time


class Marionette:
    def __init__(self, host="127.0.0.1", port=2828, timeout=60):
        self.s = socket.create_connection((host, port), timeout=timeout)
        self.buf = b""
        self.msgid = 0
        self._recv()  # 服务端先发一行握手
        self.send({"applicationType": "gecko", "marionetteProtocol": 3})

    def _recv(self):
        while b":" not in self.buf:
            chunk = self.s.recv(65536)
            if not chunk:
                raise ConnectionError("marionette 断开")
            self.buf += chunk
        head, _, rest = self.buf.partition(b":")
        n = int(head)
        self.buf = rest
        while len(self.buf) < n:
            chunk = self.s.recv(65536)
            if not chunk:
                raise ConnectionError("marionette 断开")
            self.buf += chunk
        raw, self.buf = self.buf[:n], self.buf[n:]
        return json.loads(raw)

    def send(self, obj):
        data = json.dumps(obj).encode()
        self.s.sendall(str(len(data)).encode() + b":" + data)
        return self._recv()

    def cmd(self, name, params=None):
        self.msgid += 1
        r = self.send({"id": self.msgid, "name": name, "parameters": params or {}})
        if r.get("error"):
            raise RuntimeError(f"{name}: {r['error'].get('message')}")
        return r.get("result")

    def newsession(self):
        try:
            return self.cmd("WebDriver:NewSession", {"capabilities": {}})
        except RuntimeError:
            return None  # 已有会话时忽略

    def goto(self, url):
        return self.cmd("WebDriver:Navigate", {"url": url})

    def js(self, script, args=None, timeout_ms=30000):
        r = self.cmd("WebDriver:ExecuteScript",
                     {"script": script, "args": args or [], "scriptTimeout": timeout_ms})
        return r.get("value") if isinstance(r, dict) else r

    def js_async(self, script, args=None, timeout_ms=30000):
        r = self.cmd("WebDriver:ExecuteAsyncScript",
                     {"script": script, "args": args or [], "scriptTimeout": timeout_ms})
        return r.get("value") if isinstance(r, dict) else r


if __name__ == "__main__":
    m = Marionette()
    m.newsession()
    print("handles:", json.dumps(m.cmd("WebDriver:GetWindowHandles")))
    print("url:", m.js("return document.location.href"))
