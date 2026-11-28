/**
 * 实证预言机：让每一条结论都能在受控环境里真的跑一遍。
 *
 * ## 这是整条链上唯一能杀死"看起来对"的环节
 *
 * 前面几层的输出都还只是"论证"：证据强度够、锚点对得上、代码事实支持。
 * 但一份渗透报告里真正的分水岭是另一句话——**你到底有没有打通它**。
 * 没有这一层，系统产出的每条结论最终都要靠人去重放一遍，那自动化的价值
 * 就只剩"帮忙整理线索"。
 *
 * ## 为什么直接调 nai-run 而不是自己写 spawn
 *
 * 因为跑不可信的东西需要的是一整套底座：cgroup 限额、三判据超时
 * （总时长 / 无输出）、信号升级（TERM → 宽限 → KILL）、进程树清理、
 * OOM 归因。这些在 engine/runner 里已经实现并验证过（721 条 CVE 索引那轮
 * 之外，进程树那部分有独立的四组实测）。这里只做一件事：
 * **把它的输出变成证据**。
 *
 * ## 判定的三种结果，语义必须分开
 *
 *   hit      —— 命令跑完，输出符合预期声明 → 这是 proof，能推进确认
 *   miss     —— 命令跑完，但输出不符合预期 → 这是 refutation（advisory）
 *   unknown  —— 跑不起来（超时/被 OOM 杀/二进制不存在）→ **什么都不能说明**
 *
 * 第三条最容易被写错：把"没跑起来"读成"漏洞不存在"，就是用环境故障冒充阴性结论。
 * 这和 coverage.ts 里 inconclusive ≠ clean 是同一条原则。
 */
import { execFile } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
const execFileAsync = promisify(execFile);
/** 找到默认的 nai-run 位置。找不到返回 null，由调用方决定降级还是报错。 */
export function findRunner() {
    const candidates = [
        process.env['NAI_RUN'],
        '/root/tpctf/runner/target/release/nai-run',
        path.resolve(process.cwd(), 'engine/runner/target/release/nai-run'),
        path.resolve(process.cwd(), '../engine/runner/target/release/nai-run'),
    ];
    for (const c of candidates) {
        if (c === undefined || c === null || c === '')
            continue;
        try {
            fs.accessSync(c, fs.constants.X_OK);
            return c;
        }
        catch {
            continue;
        }
    }
    return null;
}
/**
 * 在沙箱里跑一条命令。
 *
 * 无论 supervisor 是否可用都会返回结果，但 `supervised` 会如实置位：
 * 降级路径下没有 cgroup、没有进程树清理，调用方必须知道这件事。
 */
export async function runInSandbox(opts) {
    const timeout = opts.timeoutSec ?? 60;
    const grace = opts.graceSec ?? 5;
    const log = opts.logPath ?? path.join(os.tmpdir(), `secops-oracle-${String(Date.now())}.log`);
    const args = [
        '--timeout', String(timeout),
        '--grace', String(grace),
        '--log', log,
    ];
    if (opts.idleSec !== undefined && opts.idleSec > 0)
        args.push('--idle-timeout', String(opts.idleSec));
    if (opts.mem !== undefined && opts.mem !== '')
        args.push('--mem', opts.mem);
    if (opts.cwd !== undefined && opts.cwd !== '')
        args.push('--cwd', opts.cwd);
    args.push('--', ...opts.argv);
    try {
        const { stdout } = await execFileAsync(opts.runnerPath, args, {
            maxBuffer: 4 * 1024 * 1024,
            // supervisor 自己卡死时的兜底：比它自己的超时再宽一点
            timeout: (timeout + grace + 30) * 1000,
        });
        const lines = stdout.trim().split('\n');
        const last = lines[lines.length - 1] ?? '{}';
        const parsed = JSON.parse(last);
        return {
            exit: parsed.exit ?? -1,
            signal: parsed.signal ?? 0,
            elapsed_ms: parsed.elapsed_ms ?? 0,
            peak_mem_kb: parsed.peak_mem_kb ?? 0,
            timed_out: parsed.timed_out ?? false,
            kill_reason: parsed.kill_reason ?? '',
            killed: parsed.killed ?? 0,
            oom_kill: parsed.oom_kill ?? 0,
            supervised: parsed.supervised ?? true,
            note: parsed.note ?? '',
            log_path: log,
            argv: [...opts.argv],
        };
    }
    catch (err) {
        const e = err;
        if (e.stdout !== undefined && e.stdout.trim() !== '') {
            // supervisor 跑到了但报了错：它的输出比我们的猜测可信
            try {
                const lines = e.stdout.trim().split('\n');
                const parsed = JSON.parse(lines[lines.length - 1] ?? '{}');
                return {
                    exit: parsed.exit ?? -1,
                    signal: parsed.signal ?? 0,
                    elapsed_ms: parsed.elapsed_ms ?? 0,
                    peak_mem_kb: parsed.peak_mem_kb ?? 0,
                    timed_out: parsed.timed_out ?? false,
                    kill_reason: parsed.kill_reason ?? '',
                    killed: parsed.killed ?? 0,
                    oom_kill: parsed.oom_kill ?? 0,
                    supervised: parsed.supervised ?? true,
                    note: parsed.note ?? '',
                    log_path: log,
                    argv: [...opts.argv],
                };
            }
            catch {
                // 落到下面的降级
            }
        }
        return {
            exit: -1,
            signal: 0,
            elapsed_ms: 0,
            peak_mem_kb: 0,
            timed_out: e.code === 'ETIMEDOUT',
            kill_reason: e.code === 'ETIMEDOUT' ? 'supervisor_hang' : '',
            killed: 0,
            oom_kill: 0,
            // 没走 supervisor：这是降级，资源字段不可信
            supervised: false,
            note: `supervisor unavailable: ${e.code ?? String(err).slice(0, 80)}`,
            log_path: log,
            argv: [...opts.argv],
        };
    }
}
/** 读回沙箱日志。带字节上限——PoC 的输出可能很大。 */
export function readLog(logPath, maxBytes = 64 * 1024) {
    try {
        const st = fs.statSync(logPath);
        const fd = fs.openSync(logPath, 'r');
        const len = Math.min(st.size, maxBytes);
        const buf = Buffer.alloc(len);
        fs.readSync(fd, buf, 0, len, Math.max(0, st.size - len));
        fs.closeSync(fd);
        return buf.toString('utf8');
    }
    catch {
        return '';
    }
}
/**
 * 判定一次运行。
 *
 * 顺序很重要：**先判"跑没跑起来"，再判"结果对不对"**。
 * 反过来会把超时/OOM 当成"输出不符合期望"，进而当成漏洞不存在。
 */
export function judge(result, expect, logText) {
    // 1. 环境层：这次运行本身是否可信
    if (!result.supervised) {
        return { outcome: 'unknown', reason: `没有走 supervisor（${result.note}），资源与进程树不可信，本次结果不计入` };
    }
    if (result.timed_out) {
        return {
            outcome: 'unknown',
            reason: `运行超时（${result.kill_reason}，${String(result.elapsed_ms)}ms）：目标可能只是慢，不能读成"漏洞不存在"`,
        };
    }
    if (result.oom_kill > 0) {
        return { outcome: 'unknown', reason: '进程被 OOM killer 杀掉：这是资源上限，不是目标行为' };
    }
    // 2. 断言层：命中与否
    switch (expect.type) {
        case 'exit-code': {
            const ok = expect.exact !== undefined
                ? result.exit === expect.exact
                : expect.nonZero === true
                    ? result.exit !== 0
                    : result.exit === 0;
            return ok
                ? { outcome: 'hit', reason: `退出码 ${String(result.exit)} 符合期望` }
                : { outcome: 'miss', reason: `退出码 ${String(result.exit)} 不符合期望` };
        }
        case 'output-contains': {
            const ok = logText.includes(expect.text);
            return ok
                ? { outcome: 'hit', reason: `输出包含 "${expect.text}"` }
                : { outcome: 'miss', reason: `输出不含 "${expect.text}"（日志 ${String(logText.length)} 字节）` };
        }
        case 'output-matches': {
            let re;
            try {
                re = new RegExp(expect.pattern);
            }
            catch {
                return { outcome: 'unknown', reason: `期望的正则无效：${expect.pattern}` };
            }
            const m = logText.match(re);
            return m !== null
                ? { outcome: 'hit', reason: `输出匹配 /${expect.pattern}/：${m[0].slice(0, 80)}` }
                : { outcome: 'miss', reason: `输出不匹配 /${expect.pattern}/` };
        }
        case 'sanitizer': {
            const kind = expect.kind ?? 'address';
            const markers = {
                address: /(ERROR: AddressSanitizer|heap-buffer-overflow|stack-buffer-overflow|use-after-free|global-buffer-overflow|SEGV on unknown address)/i,
                memory: /(WARNING: MemorySanitizer|use-of-uninitialized-value)/i,
                undefined: /(runtime error:|UndefinedBehaviorSanitizer)/i,
                thread: /(WARNING: ThreadSanitizer|data race)/i,
            };
            const re = markers[kind] ?? markers['address'];
            const m = logText.match(re);
            if (m !== null) {
                return { outcome: 'hit', reason: `${kind} sanitizer 报告了问题：${m[0]}` };
            }
            // 完全没有 sanitizer 输出的特征：可能是没编译进去，不能当成阴性
            const anySan = /(Sanitizer|runtime error:)/i.test(logText);
            return anySan
                ? { outcome: 'miss', reason: `sanitizer 有输出但没有 ${kind} 类报告` }
                : {
                    outcome: 'unknown',
                    reason: 'no sanitizer output at all — the target is probably not instrumented, so this run says nothing ' +
                        'about memory safety',
                };
        }
        case 'canary': {
            // canary 是最强的一类：目标返回了一个只有服务端才知道的随机串，
            // 证明的是"真的读到了"，不是"响应看起来像读到了"
            const ok = logText.includes(expect.token);
            return ok
                ? { outcome: 'hit', reason: `canary "${expect.token}" 出现在输出里——目标确实泄露了该内容` }
                : { outcome: 'miss', reason: `canary "${expect.token}" 未出现` };
        }
        default:
            return { outcome: 'unknown', reason: 'unhandled expectation type' };
    }
}
