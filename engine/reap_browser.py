#!/usr/bin/env python3
"""清理浏览器残留进程以回收内存。

为什么单独写成脚本文件：`pkill -f 'contentproc'` 这类命令会把**自己的命令行**
也匹配进去，导致把自己所在的 shell 一起 SIGKILL（这个坑已经踩了三次）。
脚本内容不进入 cmdline，只有脚本路径，所以按内容匹配时绝不会命中自己。
"""
import os
import signal
import sys

# 目标特征：firefox 的渲染/插件/崩溃上报子进程。这些在主进程退出后会变成孤儿，
# 继续占着几百 MB 到 1 GB 内存不放。
PATTERNS = ["contentproc", "crashhelper", "Isolated Web Co", "Web Content"]
SELF = os.getpid()


def main() -> int:
    killed = 0
    freed_kb = 0
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        p = int(pid)
        if p == SELF:
            continue
        try:
            cmd = open(f"/proc/{p}/cmdline", "rb").read().decode("utf-8", "replace")
        except OSError:
            continue
        if not any(pat in cmd for pat in PATTERNS):
            continue
        # 只清浏览器残留，别误伤别的进程
        if "firefox" not in cmd and "Isolated Web Co" not in cmd and "Web Content" not in cmd:
            continue
        try:
            rss = 0
            for line in open(f"/proc/{p}/status"):
                if line.startswith("VmRSS:"):
                    rss = int(line.split()[1])
                    break
            os.kill(p, signal.SIGKILL)
            killed += 1
            freed_kb += rss
            print(f"killed pid={p} rss={rss // 1024}MB")
        except OSError:
            pass
    print(f"共清理 {killed} 个进程，释放约 {freed_kb // 1024} MB")
    return 0


if __name__ == "__main__":
    sys.exit(main())
