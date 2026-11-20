#!/usr/bin/env python3
"""执行层封装：把 Rust supervisor（nai-run）接进 Python。

## 这一层解决的三件事

1. **孤儿进程**。此前用 `subprocess.Popen` + `os.killpg`，而 setsid 出来的孙进程
   早就不在原进程组里，killpg 够不到——实测浏览器主进程死后 7 个 contentproc
   还占着 1.3GB。Rust 那边用 cgroup 枚举兜底，实测能杀掉 killpg 杀不到的进程
   （回报里的 `killed` 计数就是这群"逃逸者"）。
2. **OOM 归因**。两路 QEMU 各 2G 把机器压死，事后说不清谁吃的。现在每次运行都有
   `peak_mem_kb` 和 `oom_kill` 计数，能直接指出是谁触发了限额。
3. **超时语义**。SIGTERM → 宽限 → SIGKILL，且最后一定遍历 cgroup 收尸。

## 降级策略

二进制不存在或平台不支持时，退回 `subprocess`。这不理想（又回到孤儿问题），
但比"因为执行层没编译好就跑不了任务"要好。降级会在结果里标 `supervised=False`，
让调用方知道自己失去了哪些保障。
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from typing import Any

from pydantic import BaseModel, ConfigDict

RUNNER = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                      "runner", "target", "release", "nai-run")


class RunResult(BaseModel):
    """一次受监管运行的完整结果。"""

    model_config = ConfigDict(extra="allow")

    exit: int = -1
    signal: int = 0
    elapsed_ms: int = 0
    peak_mem_kb: int = 0
    timed_out: bool = False
    killed: int = 0
    oom_kill: int = 0
    # 超时原因："total_wall"（跑太久）/ "idle"（无输出被判卡死）/ ""（没超时）。
    # 两者要分开：跑太久和卡死是不同的问题，处理方式也不同。
    kill_reason: str = ""
    # 是否真的走了 supervisor。False 表示降级到裸 subprocess，
    # 此时 peak_mem_kb / oom_kill / killed 都不可信。
    supervised: bool = True
    log_path: str = ""
    note: str = ""

    @property
    def ok(self) -> bool:
        return self.exit == 0 and self.signal == 0

    @property
    def shell_code(self) -> int:
        """按 shell 惯例折算的退出码。

        `exit` 字段刻意保持精确语义：-1 表示"没有正常退出码"（被信号终止），
        真实原因看 `signal`。但很多调用方只想要一个数字来判断成败，
        所以这里按惯例折算：超时=124，信号=128+sig。
        """
        if self.timed_out:
            return 124
        if self.signal:
            return 128 + self.signal
        return self.exit

    def describe(self) -> str:
        if not self.supervised:
            return f"退出 {self.exit}（未受监管：{self.note}）"
        bits = [f"退出 {self.exit}"]
        if self.signal:
            bits.append(f"信号 {self.signal}")
        bits.append(f"{self.elapsed_ms}ms")
        if self.peak_mem_kb:
            bits.append(f"峰值 {self.peak_mem_kb // 1024}MB")
        if self.timed_out:
            bits.append({"idle": "卡住(idle)", "total_wall": "超时(total_wall)"}
                        .get(self.kill_reason, "超时"))
        if self.killed:
            bits.append(f"清理 {self.killed} 个逃逸进程")
        if self.oom_kill:
            bits.append(f"OOM 触发 {self.oom_kill} 次")
        return " · ".join(bits)


def available() -> bool:
    return os.path.exists(RUNNER) and os.access(RUNNER, os.X_OK)


def run(
    cmd: list[str],
    *,
    timeout: int = 900,
    idle: int = 0,
    grace: int = 10,
    mem: str = "",
    cpu: float | None = None,
    pids: int | None = None,
    cwd: str = "",
    log: str = "",
    env: dict[str, str] | None = None,
) -> RunResult:
    """跑一个命令，带资源限额与进程树清理。

    `mem` 用人类可读形式（"1G" / "512M"）。限额是**硬上限**：超了就是 OOM，
    不是"尽量"。这也是故意的——软限额在真出事时等于没有。
    """
    if not available():
        return _fallback(cmd, timeout=timeout, cwd=cwd, log=log)

    args = [RUNNER, "--timeout", str(int(timeout)), "--grace", str(int(grace))]
    if idle:
        args += ["--idle-timeout", str(int(idle))]
    if mem:
        args += ["--mem", mem]
    if cpu:
        args += ["--cpu", str(cpu)]
    if pids:
        args += ["--pids", str(int(pids))]
    if cwd:
        args += ["--cwd", cwd]
    if log:
        args += ["--log", log]
    args += ["--"] + cmd

    try:
        proc = subprocess.run(args, capture_output=True, timeout=timeout + grace + 30,
                              env=env)
    except subprocess.TimeoutExpired:
        # supervisor 自己超时了，说明它卡在更底层；此时只能相信它已经尽力清理
        return RunResult(exit=-1, timed_out=True, supervised=True,
                         log_path=log, note="supervisor 自身超时")

    out = proc.stdout.decode("utf-8", "replace").strip()
    try:
        data: dict[str, Any] = json.loads(out.splitlines()[-1]) if out else {}
    except (ValueError, IndexError):
        return RunResult(
            exit=proc.returncode, supervised=True, log_path=log,
            note=f"无法解析 supervisor 输出：{out[:120] or proc.stderr.decode('utf-8','replace')[:120]}",
        )
    return RunResult(**{**data, "supervised": True, "log_path": log})


def _fallback(cmd: list[str], *, timeout: int, cwd: str, log: str) -> RunResult:
    """没有 supervisor 时的降级路径。

    刻意做得朴素：这里不试图去修进程树问题——那正是 supervisor 存在的理由。
    降级只是让任务还能跑，并在结果里明确标记"保障缺失"。
    """
    import time
    started = time.time()
    fh = open(log, "wb") if log else subprocess.DEVNULL
    try:
        proc = subprocess.run(cmd, stdout=fh, stderr=subprocess.STDOUT,
                              cwd=cwd or None, timeout=timeout)
        code, sig, timed = proc.returncode, 0, False
    except subprocess.TimeoutExpired:
        code, sig, timed = -1, 9, True
    except OSError as exc:
        code, sig, timed = -1, 0, False
        note = str(exc)
    else:
        note = "未找到 nai-run，降级为 subprocess；孤儿清理与 OOM 归因不可用"
    finally:
        if log and hasattr(fh, "close"):
            fh.close()
    return RunResult(
        exit=code, signal=sig, timed_out=timed, supervised=False,
        elapsed_ms=int((time.time() - started) * 1000), log_path=log,
        note=locals().get("note", ""),
    )


def _main() -> int:
    import argparse

    ap = argparse.ArgumentParser(description="执行层：受监管地跑命令")
    ap.add_argument("--timeout", type=int, default=900)
    ap.add_argument("--grace", type=int, default=10)
    ap.add_argument("--idle", type=int, default=0, help="无输出多少秒判定卡死")
    ap.add_argument("--mem", default="")
    ap.add_argument("--cpu", type=float, default=None)
    ap.add_argument("--pids", type=int, default=None)
    ap.add_argument("--cwd", default="")
    ap.add_argument("--log", default="")
    ap.add_argument("cmd", nargs=argparse.REMAINDER)
    a = ap.parse_args()
    cmd = a.cmd[1:] if a.cmd and a.cmd[0] == "--" else a.cmd
    if not cmd:
        ap.error("缺少命令")
    r = run(cmd, timeout=a.timeout, idle=a.idle, grace=a.grace, mem=a.mem,
            cpu=a.cpu, pids=a.pids, cwd=a.cwd, log=a.log)
    print(r.model_dump_json())
    print(r.describe(), flush=True)
    return 0 if r.ok else 1


if __name__ == "__main__":
    raise SystemExit(_main())
