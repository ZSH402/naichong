#!/usr/bin/env python3
"""覆盖率引导 fuzz + 符号求解 —— 引擎 D 的最小可用实现。

## 为什么不用 afl / libFuzzer

这台机器上都没有。但**它们做的事情可以用 gcc + gcov 复现**——AFL 的
`--coverage` 模式本来就是这么干的：编译时插桩，运行时收集"哪些边被执行过"，
把带来新覆盖的输入留下来当种子。核心循环只有三步：变异、执行、看覆盖增量。

差异要说清楚：gcov 的粒度是**行**不是边，反馈比 AFL 的边覆盖率粗，
发现长条件链的能力弱一档。所以这个实现定位是"能跑通闭环、能找到浅层缺陷"，
不是替代专业 fuzzer。

## 为什么崩溃判定交给 ASan

`-fsanitize=address` 会把越界/悬垂访问变成**确定性的中止**，而不是"也许崩也许不崩"。
对于不崩溃但越界的输入（读越界常常静默），没有 ASan 就永远看不见。
所以 build 默认带 ASan，这是让"没崩"和"没越界"能区分开的前提。

## 符号求解用来干什么

不是全自动符号执行——那需要把整条路径约束下来，工程量是另一个量级。
这里的用途窄而明确：**你怀疑某个检查挡住了路，问它"什么样的输入能过"**。
给定一个约束表达式，z3 给出一个解；拿到解就去实测。这一步把
"猜一个能过校验的值"从试错变成计算。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

# 变异用的字典：真实目标是文件格式解析器时，这些字节能显著提高命中率
DICT = [
    b"\x00", b"\xff", b"\x7f", b"\x80", b"\n", b"\r\n", b"%s", b"%n",
    b"../", b"../../", b"/etc/passwd", b"<", b">", b"'", b'"', b"\\",
    b"AAAA", b"\xde\xad\xbe\xef", b"PK\x03\x04", b"\x89PNG",
]


def run(cmd: list[str], timeout: float = 10.0, cwd: str | None = None,
        stdin_data: bytes | None = None) -> tuple[int, bytes, bytes]:
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=timeout, cwd=cwd,
                           input=stdin_data)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, b"", b"<timeout>"
    except FileNotFoundError as exc:
        return 127, b"", str(exc).encode()


# ───────────────────────────────────────────────────────────── build

def cmd_build(args: argparse.Namespace) -> None:
    """编译带插桩的靶子。默认同时开 ASan 和覆盖率。"""
    src = Path(args.src).resolve()
    out = Path(args.out).resolve()
    if not src.is_file():
        print(json.dumps({"ok": False, "error": f"source not found: {src}"}))
        return

    workdir = out.parent
    workdir.mkdir(parents=True, exist_ok=True)

    if args.lang == "c++":
        cc = args.compiler or "g++"
    else:
        cc = args.compiler or "gcc"

    # 有 afl-clang-fast 就用它：编译期插桩是**边级**反馈，比 gcov 的行覆盖
    # 精细一个量级，长条件链才撞得过去。
    afl_cc = shutil.which(args.afl_cc or "afl-clang-fast")
    use_afl = args.engine in ("auto", "afl") and afl_cc is not None and args.lang == "c"
    if use_afl:
        cc = afl_cc
        os.environ["AFL_LLVM_INSTRUMENT"] = args.afl_instrument

    flags = ["-g"]
    # 关键差异：**AFL 模式不能加 -O0**。
    # 实测同一个 12 行程序：-O0 下 showmap 只注册 2 条边，去掉 -O0 是 4 条。
    # 边数掉一半意味着覆盖率反馈几乎没有区分度，fuzzer 退化成瞎撞——
    # 表现是"跑了几万次一个崩溃都没有"，看起来像目标很安全，其实是模式坏了。
    if not use_afl:
        flags.append("-O0")
    if not args.no_asan:
        flags.append("-fsanitize=address")
    if not args.no_coverage and not use_afl:
        # AFL 的插桩与 gcov 的 --coverage 抢同一个插桩位，二选一
        flags += ["--coverage", "-fprofile-arcs", "-ftest-coverage"]
    flags += (args.extra or [])

    rc, _o, err = run([cc, *flags, "-o", str(out), str(src)], timeout=180, cwd=str(workdir))
    gcno = sorted(workdir.glob("*.gcno"))
    print(json.dumps({
        "ok": rc == 0,
        "binary": str(out),
        "compiler": cc,
        "flags": flags,
        "asan": not args.no_asan,
        "coverage": not args.no_coverage,
        "afl_instrumented": use_afl,
        # 没有 .gcno 就意味着覆盖率根本没插进去，必须如实报出来
        "gcno_files": [p.name for p in gcno][:5],
        **({"error": err.decode("utf-8", "replace")[:800]} if rc != 0 else {}),
    }, ensure_ascii=False))


# ───────────────────────────────────────────────────────────── coverage

LINE_RE = re.compile(r"^\s*([0-9]+|#####|-):\s*(\d+):(.*)$")


def coverage_of(binary: Path, workdir: Path, source_name: str) -> dict[str, int]:
    """解析 gcov 输出，返回 {行号: 执行次数}。

    只跑 gcov 不够——它读的是 `.gcda`，那是**上一次运行**累积的计数。
    所以调用前必须先执行一次目标，否则拿到的是空数据（或者更糟，是上次的残留）。
    """
    for f in workdir.glob("*.gcda"):
        pass  # gcda 由目标运行时写出，这里只读
    rc, _o, err = run(["gcov", source_name], timeout=60, cwd=str(workdir))
    if rc != 0:
        return {}
    gcov_file = workdir / (Path(source_name).name + ".gcov")
    if not gcov_file.is_file():
        return {}
    hits: dict[str, int] = {}
    for line in gcov_file.read_text(encoding="utf-8", errors="replace").splitlines():
        m = LINE_RE.match(line)
        if m is None:
            continue
        count, lineno, _src = m.groups()
        if count == "-":
            continue
        hits[lineno] = 0 if count == "#####" else int(count)
    return hits


def clean_cov(workdir: Path) -> None:
    for pat in ("*.gcda", "*.gcov"):
        for f in workdir.glob(pat):
            try:
                f.unlink()
            except OSError:
                pass


def cmd_run(args: argparse.Namespace) -> None:
    """跑一个输入，报告覆盖行与是否崩溃。"""
    binary = Path(args.bin).resolve()
    workdir = binary.parent
    clean_cov(workdir)

    data = Path(args.input).read_bytes() if args.mode == "stdin" and args.input else None
    argv = [str(binary)]
    if args.mode == "argv":
        if not args.input:
            print(json.dumps({"ok": False, "error": "--input required for argv mode"}))
            return
        argv.append(Path(args.input).read_text(errors="replace").strip())

    rc, out, err = run(argv, timeout=args.timeout, cwd=str(workdir), stdin_data=data)
    cov = coverage_of(binary, workdir, args.source) if args.source else {}
    text = (out + err).decode("utf-8", "replace")
    print(json.dumps({
        "ok": True,
        "exit": rc,
        "crashed": rc not in (0, 124) or "AddressSanitizer" in text,
        "asan": "AddressSanitizer" in text,
        "lines_hit": len([v for v in cov.values() if v > 0]),
        "output": text[:400],
    }, ensure_ascii=False))


# ───────────────────────────────────────────────────────────── fuzz

def mutate(seed: bytes, rng: random.Random, max_len: int = 4096) -> bytes:
    """一组朴素的变异算子。

    刻意不做"聪明"的变异（比如语法感知）——覆盖率反馈本身就会把笨变异
    引到有用的方向，这是 AFL 的核心经验：**反馈比变异质量更重要**。
    """
    b = bytearray(seed)
    for _ in range(rng.randint(1, 4)):
        op = rng.choice(["flip", "byte", "insert", "delete", "dup", "dict", "splice"])
        if op == "flip" and b:
            i = rng.randrange(len(b))
            b[i] ^= 1 << rng.randrange(8)
        elif op == "byte" and b:
            b[rng.randrange(len(b))] = rng.randrange(256)
        elif op == "insert":
            i = rng.randrange(len(b) + 1)
            b[i:i] = bytes(rng.randrange(256) for _ in range(rng.randint(1, 8)))
        elif op == "delete" and len(b) > 1:
            i = rng.randrange(len(b))
            del b[i:i + rng.randint(1, 4)]
        elif op == "dup" and b:
            i = rng.randrange(len(b))
            b += b[i:i + rng.randint(1, 16)]
        elif op == "dict":
            i = rng.randrange(len(b) + 1)
            b[i:i] = rng.choice(DICT)
        elif op == "splice" and b:
            i = rng.randrange(len(b))
            b = b[:i] + bytes(rng.randrange(256) for _ in range(rng.randint(2, 12)))
        if len(b) > max_len:
            b = b[:max_len]
    return bytes(b)


def fuzz_with_afl(args: argparse.Namespace) -> bool:
    """用 AFL++ 跑。返回 False 表示环境不满足，让调用方退回内置循环。

    为什么优先 AFL：它的变异引擎、语料最小化（cmin/tmin）、
    持久化队列和崩溃去重都是十几年打磨出来的，自己写一个只能到它的零头。
    这里只负责把"编译好的二进制 + 种子目录"翻译成它的命令行，
    再把它的产出翻译成统一 JSON——胶水代码不该重造引擎。
    """
    afl = shutil.which("afl-fuzz")
    if afl is None:
        return False
    binary = Path(args.bin).resolve()
    if not binary.is_file():
        return False

    workdir = binary.parent
    seeds = Path(args.seed_dir).resolve() if args.seed_dir else (workdir / ".seeds")
    seeds.mkdir(parents=True, exist_ok=True)
    if not any(seeds.iterdir()):
        # AFL 不接受空种子目录，塞几个最小的进去
        for i, s in enumerate([b"AAAA", b"A", bytes(4)]):
            (seeds / f"seed{i}").write_bytes(s)

    outdir = workdir / "afl-out"
    if outdir.exists():
        shutil.rmtree(outdir, ignore_errors=True)

    env = dict(os.environ)
    env.update({
        "AFL_SKIP_CPUFREQ": "1",
        "AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES": "1",
        "AFL_NO_AFFINITY": "1",
        "AFL_QUIET": "1",
        # 有 ASan 时必须放开内存上限，否则 fork server 会被自己限制死
        "AFL_MAP_SIZE": "65536",
        **(dict() if args.asan is False else {"AFL_USE_ASAN": "1"}),
    })
    cmd = [afl, "-i", str(seeds), "-o", str(outdir), "-V", str(int(args.time_budget)), "--", str(binary)]
    if args.mode == "argv":
        cmd.append("@@")
    try:
        subprocess.run(cmd, capture_output=True, timeout=args.time_budget + 90, env=env, cwd=str(workdir))
    except subprocess.TimeoutExpired:
        pass

    crash_dir = outdir / "default" / "crashes"
    crashes = []
    if crash_dir.is_dir():
        for f in sorted(crash_dir.iterdir()):
            if f.name.startswith("README"):
                continue
            data = f.read_bytes()
            dest = workdir / f"pov-{f.name}"
            dest.write_bytes(data)
            crashes.append({
                "iteration": -1,
                "exit": -1,
                "asan": True,
                "input_file": str(dest),
                "input_len": len(data),
                "output": "reported by afl-fuzz (see afl-out/default/crashes)",
            })

    stats: dict[str, str] = {}
    fs = outdir / "default" / "fuzzer_stats"
    if fs.is_file():
        for line in fs.read_text(errors="replace").splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                stats[k.strip()] = v.strip()

    print(json.dumps({
        "ok": True,
        "engine": "afl++",
        "executions": int(stats.get("execs_done", "0") or 0),
        "elapsed_sec": args.time_budget,
        "exec_per_sec": float(stats.get("execs_per_sec", "0").replace("%", "") or 0),
        "corpus": int(stats.get("corpus_count", "0") or 0),
        "edges_found": int(stats.get("edges_found", "0") or 0),
        "crashes": crashes,
        "note": (
            "no crash found — this says nothing about memory safety; it only means the fuzzer "
            f"did not hit one in {args.time_budget}s"
            if not crashes else f"{len(crashes)} crash(es) copied next to the binary"
        ),
        "stats_path": str(fs) if fs.is_file() else "",
    }, ensure_ascii=False))
    return True


def cmd_fuzz(args: argparse.Namespace) -> None:
    """覆盖率引导循环。

    留种规则只有一条：**这个输入带来了之前没见过的行**。这比"看起来有意思"
    客观得多，也是覆盖率反馈的全部价值——它把"什么算有趣"从主观判断
    变成了可测量的事。
    """
    binary = Path(args.bin).resolve()
    workdir = binary.parent
    if not binary.is_file():
        print(json.dumps({"ok": False, "error": f"binary not found: {binary}"}))
        return

    if args.engine in ("auto", "afl") and fuzz_with_afl(args):
        return
    if args.engine == "afl":
        print(json.dumps({"ok": False, "error": "afl-fuzz not available"}))
        return

    rng = random.Random(args.seed)
    corpus: list[bytes] = []
    seed_dir = Path(args.seed_dir) if args.seed_dir else None
    if seed_dir and seed_dir.is_dir():
        for f in sorted(seed_dir.iterdir())[:200]:
            if f.is_file() and f.stat().st_size < 8192:
                corpus.append(f.read_bytes())
    if not corpus:
        # 没给种子就从空开始——有些解析器对空输入就走得很深
        corpus = [b"", b"A", b"AAAA", b"\x00" * 4, b"GET / HTTP/1.0\r\n\r\n"]

    seen_lines: set[str] = set()
    found: list[dict] = []
    execs = 0
    start = os.times().elapsed

    for it in range(args.iterations):
        if args.time_budget and (os.times().elapsed - start) > args.time_budget:
            break
        seed = rng.choice(corpus)
        data = mutate(seed, rng)

        clean_cov(workdir)
        tmp = workdir / ".fuzz_input"
        tmp.write_bytes(data)

        argv = [str(binary)]
        stdin_data = None
        if args.mode == "argv":
            # 变异出来的字节里常有 NUL 和换行，直接当参数会 exec 失败
            # （embedded null byte）。latin-1 能无损装下任意字节。
            arg = data.replace(b"\x00", b"").replace(b"\n", b"")[:4096]
            argv.append(arg.decode("latin-1"))
        else:
            stdin_data = data

        rc, out, err = run(argv, timeout=5.0, cwd=str(workdir), stdin_data=stdin_data)
        execs += 1
        text = (out + err).decode("utf-8", "replace")

        crashed = rc not in (0, 124) or "AddressSanitizer" in text
        if crashed:
            # 崩溃优先留证：把输入单独存一份，后面可以直接复现
            crash_file = workdir / f"crash-{len(found)}.bin"
            crash_file.write_bytes(data)
            found.append({
                "iteration": it,
                "exit": rc,
                "asan": "AddressSanitizer" in text,
                "input_file": str(crash_file),
                "input_len": len(data),
                "output": text[:300],
            })
            if len(found) >= args.max_crashes:
                break

        cov = coverage_of(binary, workdir, args.source) if args.source else {}
        new_lines = {ln for ln, c in cov.items() if c > 0} - seen_lines
        if new_lines:
            seen_lines |= new_lines
            corpus.append(data)

        tmp.unlink(missing_ok=True)

    elapsed = os.times().elapsed - start
    print(json.dumps({
        "ok": True,
        "executions": execs,
        "elapsed_sec": round(elapsed, 1),
        "exec_per_sec": round(execs / elapsed, 1) if elapsed > 0 else 0,
        "corpus": len(corpus),
        "lines_covered": len(seen_lines),
        "crashes": found,
        "note": (
            "no crash found — this says nothing about memory safety; it only means these "
            f"{execs} executions did not hit one"
            if not found else f"{len(found)} crash(es) saved next to the binary"
        ),
    }, ensure_ascii=False))


# ───────────────────────────────────────────────────────────── solve

def cmd_solve(args: argparse.Namespace) -> None:
    """用 z3 求一组满足约束的输入值。

    约束写成 Python 表达式，变量用 `x`、`y`、`z`（整数）。
    用途是"过检查"：想知道 `if (len > 100 && len % 7 == 0)` 要什么 len，
    直接把条件写进去求解，比盲试快得多。
    """
    try:
        import z3  # noqa: PLC0415
    except Exception as exc:
        print(json.dumps({"ok": False, "error": f"z3 unavailable: {exc}"}))
        return

    env = {"x": z3.Int("x"), "y": z3.Int("y"), "z": z3.Int("z"), "z3": z3}
    s = z3.Solver()
    s.set("timeout", args.timeout_ms)
    try:
        for cond in args.constraint:
            s.add(eval(cond, {"__builtins__": {}}, env))  # noqa: S307
    except Exception as exc:
        print(json.dumps({"ok": False, "error": f"bad constraint: {exc}"}))
        return

    res = s.check()
    if res == z3.unsat:
        print(json.dumps({"ok": True, "satisfiable": False, "note": "constraints are contradictory"}))
        return
    if res == z3.unknown:
        print(json.dumps({"ok": True, "satisfiable": None, "note": "solver timed out or gave up"}))
        return
    m = s.model()
    vals = {str(d): m[d].as_long() for d in m.decls()}
    print(json.dumps({
        "ok": True,
        "satisfiable": True,
        "assignment": vals,
        "note": "a satisfying assignment — feed it to the target and observe, do not assume it is the only one",
    }, ensure_ascii=False))


def main() -> None:
    ap = argparse.ArgumentParser(description="覆盖率引导 fuzz + 约束求解")
    sub = ap.add_subparsers(dest="cmd", required=True)

    b = sub.add_parser("build")
    b.add_argument("src")
    b.add_argument("-o", "--out", required=True)
    b.add_argument("--compiler", default="")
    b.add_argument("--lang", choices=["c", "c++"], default="c")
    b.add_argument("--no-asan", action="store_true")
    b.add_argument("--no-coverage", action="store_true")
    b.add_argument("--extra", nargs="*", default=[])
    b.add_argument("--engine", choices=["auto", "afl", "gcc"], default="auto",
                   help="afl=afl-clang-fast 插桩（推荐），gcc=纯 gcov")
    b.add_argument("--afl-cc", default="", help="自定义 afl 编译器包装器")
    b.add_argument("--afl-instrument", default="CLASSIC",
                   help="AFL_LLVM_INSTRUMENT；PCGUARD 在小程序上实测不插桩")

    r = sub.add_parser("run")
    r.add_argument("bin")
    r.add_argument("--input", default="")
    r.add_argument("--mode", choices=["argv", "stdin"], default="stdin")
    r.add_argument("--source", default="")
    r.add_argument("--timeout", type=float, default=10.0)

    f = sub.add_parser("fuzz")
    f.add_argument("bin")
    f.add_argument("--source", required=True, help="源文件名（gcov 要用），如 target.c")
    f.add_argument("--seed-dir", default="")
    f.add_argument("--iterations", type=int, default=200)
    f.add_argument("--time-budget", type=float, default=60.0)
    f.add_argument("--max-crashes", type=int, default=3)
    f.add_argument("--mode", choices=["argv", "stdin"], default="stdin")
    f.add_argument("--seed", type=int, default=0)
    f.add_argument("--engine", choices=["auto", "afl", "gcc"], default="auto",
                   help="auto=有 afl-fuzz 就用，否则退回内置循环")
    f.add_argument("--asan", dest="asan", action="store_true", default=True)
    f.add_argument("--no-asan", dest="asan", action="store_false")

    sv = sub.add_parser("solve")
    sv.add_argument("constraint", nargs="+", help='如 "x > 100" "x %% 7 == 0"')
    sv.add_argument("--timeout-ms", type=int, default=5000)

    args = ap.parse_args()
    {"build": cmd_build, "run": cmd_run, "fuzz": cmd_fuzz, "solve": cmd_solve}[args.cmd](args)


if __name__ == "__main__":
    main()
