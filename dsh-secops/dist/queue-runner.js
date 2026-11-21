/**
 * 跨进程任务执行器。
 *
 * 设计要点：
 *   - **进程组**：spawn 时 detached=true，终止时 kill(-pid) 打整个进程组。
 *     否则外部 worker 再 fork 的子进程会在超时后变成孤儿，这正是"跨进程调度"最典型的漏。
 *   - **证据先行**：stdout/stderr 直接写文件，不进内存；结束写 meta.json。
 *   - **恢复**：启动时把上个进程遗留的 running 降级为 interrupted，可配置自动重投。
 *   - **幂等**：任务 id 由调用方给定或按内容派生，同 id 重复提交只保留一条。
 */
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { TaskQueueStore } from "./queue-store.js";
import { netnsCommand } from "./netns.js";
const DEFAULT_TIMEOUT_MS = 120_000;
const MAX_CAPTURE_FILE_BYTES = 64 * 1024 * 1024;
function deriveId(kind, argv, cwd) {
    const h = createHash('sha256').update(`${kind}\u0000${cwd}\u0000${argv.join('\u0000')}`).digest('hex');
    return `${kind}-${h.slice(0, 12)}`;
}
export class QueueRunner {
    store;
    evidenceRoot;
    concurrency;
    defaultTimeoutMs;
    requeueInterrupted;
    netns;
    onFinish;
    logger;
    running = new Map();
    /** 任务的额外环境变量。只活在这个进程里，绝不写进 queue.jsonl。 */
    extraEnv = new Map();
    closed = false;
    pumpScheduled = false;
    constructor(options) {
        this.store = new TaskQueueStore(options.queueFile);
        this.evidenceRoot = options.evidenceRoot;
        this.concurrency = Math.max(1, options.concurrency ?? 2);
        this.defaultTimeoutMs = Math.max(1, options.defaultTimeoutMs ?? DEFAULT_TIMEOUT_MS);
        this.requeueInterrupted = options.requeueInterrupted ?? false;
        this.netns = options.netns;
        this.onFinish = options.onFinish;
        this.logger = options.logger;
        fs.mkdirSync(this.evidenceRoot, { recursive: true });
    }
    /** 加载队列并处理上次运行遗留的任务。 */
    start() {
        this.store.load();
        const recovered = this.store.recoverInterrupted();
        if (recovered.length > 0) {
            this.logger?.warn(`queue: ${recovered.length} task(s) were running when the process died: ${recovered.join(', ')}`);
            if (this.requeueInterrupted) {
                for (const id of recovered)
                    this.store.markFinished(id, 'queued', { note: 'requeued after interruption' });
            }
        }
        this.schedulePump();
        return { recovered };
    }
    submit(input) {
        if (this.closed)
            throw new Error('queue: runner is closed');
        if (input.argv.length === 0)
            throw new Error('queue: argv must not be empty');
        const cwd = input.cwd ?? process.cwd();
        const id = input.id ?? deriveId(input.kind, input.argv, cwd);
        // env 不进 store：它要携带的是 API key 一类的东西，而 store.submit 会把任务
        // 原样 append 进 queue.jsonl——那样 key 就明文躺在一份长期保留、还会被
        // 反复读回重放的 JSONL 里。env 只在 spawn 那一刻有用，所以只留在内存。
        //
        // 代价：进程重启后排队中的任务丢掉 env。这可以接受——重启本来就会把
        // running 降级成 interrupted 重排，重新提交时 env 会重新给到；
        // 而「key 不落盘」是硬要求，不能拿它的代价去换重放便利。
        const task = this.store.submit({
            id,
            kind: input.kind,
            argv: input.argv,
            cwd,
            timeoutMs: Math.max(1, input.timeoutMs ?? this.defaultTimeoutMs),
            createdAt: Date.now(),
        });
        if (input.env !== undefined)
            this.extraEnv.set(task.id, input.env);
        this.schedulePump();
        return task;
    }
    get(id) {
        return this.store.get(id);
    }
    list() {
        return this.store.list();
    }
    /** 任务到达终态后释放它携带的 env —— key 不该在内存里留到最后。 */
    releaseEnv(taskId) {
        this.extraEnv.delete(taskId);
    }
    /** 取消一个任务：排队中的直接标记，运行中的终止进程组。 */
    cancel(id) {
        const task = this.store.get(id);
        if (task === undefined)
            return false;
        if (task.status === 'queued') {
            this.store.markFinished(id, 'cancelled', { note: 'cancelled before start' });
            this.releaseEnv(id);
            const finished = this.store.get(id);
            if (finished !== undefined) {
                try {
                    this.onFinish?.(finished);
                }
                catch {
                    /* 回调失败不影响取消 */
                }
            }
            return true;
        }
        const entry = this.running.get(id);
        if (entry === undefined)
            return false;
        entry.controller.abort();
        return true;
    }
    /**
     * 等待队列彻底静止（测试与优雅退出用）。
     *
     * 必须同时判 running 与 queued：`pump()` 走 microtask，submit 之后立刻
     * 检查会看到一个既没有 running 也还没启动的空窗，从而提前返回。
     */
    async drain() {
        for (;;) {
            await new Promise((r) => setTimeout(r, 15));
            this.pump();
            const pending = this.store.list().some((t) => t.status === 'queued' || t.status === 'running');
            if (!pending && this.running.size === 0)
                return;
        }
    }
    close() {
        this.closed = true;
        for (const entry of this.running.values())
            entry.controller.abort();
    }
    /**
     * 等单个任务进入终态。
     *
     * 只轮询 store，不依赖 onFinish——onFinish 是旁路回调，回调抛错不该让等待方
     * 永远挂住。同时保证被 abort 时立即返回当前状态而不是抛错：调用方需要的是
     * "现在到哪一步了"，不是异常。
     */
    async waitFor(id, options = {}) {
        const pollMs = Math.max(5, options.pollMs ?? 20);
        for (;;) {
            const task = this.store.get(id);
            if (task === undefined)
                return undefined;
            if (task.status !== 'queued' && task.status !== 'running')
                return task;
            if (options.signal?.aborted === true)
                return this.store.get(id);
            await new Promise((r) => setTimeout(r, pollMs));
        }
    }
    schedulePump() {
        if (this.pumpScheduled || this.closed)
            return;
        this.pumpScheduled = true;
        queueMicrotask(() => {
            this.pumpScheduled = false;
            this.pump();
        });
    }
    pump() {
        if (this.closed)
            return;
        while (this.running.size < this.concurrency) {
            const next = this.store.list().find((t) => t.status === 'queued');
            if (next === undefined)
                return;
            void this.run(next);
        }
    }
    async run(task) {
        const attempt = task.attempts + 1;
        this.store.markRunning(task.id, attempt);
        const evidenceDir = path.join(this.evidenceRoot, task.id);
        fs.mkdirSync(evidenceDir, { recursive: true });
        const stdoutFile = path.join(evidenceDir, 'stdout.log');
        const stderrFile = path.join(evidenceDir, 'stderr.log');
        const controller = new AbortController();
        this.running.set(task.id, { taskId: task.id, controller });
        const startedAt = Date.now();
        let timedOut = false;
        const timer = setTimeout(() => {
            timedOut = true;
            controller.abort();
        }, task.timeoutMs);
        let exitCode = null;
        let signalName = null;
        let spawnError;
        let spawnErrorCode;
        try {
            exitCode = await new Promise((resolve) => {
                const out = fs.createWriteStream(stdoutFile, { flags: 'a' });
                const err = fs.createWriteStream(stderrFile, { flags: 'a' });
                let outBytes = 0;
                let errBytes = 0;
                // netns 启用时，整条命令被 bwrap 包裹：断直连 + 只留代理通道。
                const launch = this.netns === undefined
                    ? { cmd: task.argv[0], args: task.argv.slice(1) }
                    : (() => {
                        const wrapped = netnsCommand({
                            argv: task.argv,
                            workdir: task.cwd,
                            proxySocket: this.netns.proxySocket,
                            ...(this.netns.proxyPort === undefined ? {} : { proxyPort: this.netns.proxyPort }),
                            ...(this.netns.writableRoots === undefined ? {} : { writableRoots: this.netns.writableRoots }),
                        });
                        return { cmd: wrapped[0], args: wrapped.slice(1) };
                    })();
                const child = spawn(launch.cmd, launch.args, {
                    cwd: task.cwd,
                    // 独立进程组：终止时才能连带杀掉 worker 自己 fork 的子进程。
                    detached: true,
                    stdio: ['ignore', 'pipe', 'pipe'],
                    // 任务自带的环境覆盖进程环境：候选声明的依赖（例如 rea 要的
                    // GHIDRA_INSTALL_DIR、strix 要的 LLM_API_KEY）必须随任务到达执行层，
                    // 不能指望 shell 里 export 过。来源是内存里的 extraEnv，不是持久化的 task.env。
                    env: (() => {
                        const extra = this.extraEnv.get(task.id);
                        return extra === undefined ? process.env : { ...process.env, ...extra };
                    })(),
                });
                const killGroup = (signal) => {
                    try {
                        if (child.pid !== undefined)
                            process.kill(-child.pid, signal);
                    }
                    catch {
                        try {
                            child.kill(signal);
                        }
                        catch {
                            /* already gone */
                        }
                    }
                };
                controller.signal.addEventListener('abort', () => killGroup('SIGTERM'), { once: true });
                child.stdout?.on('data', (chunk) => {
                    outBytes += chunk.length;
                    if (outBytes <= MAX_CAPTURE_FILE_BYTES)
                        out.write(chunk);
                });
                child.stderr?.on('data', (chunk) => {
                    errBytes += chunk.length;
                    if (errBytes <= MAX_CAPTURE_FILE_BYTES)
                        err.write(chunk);
                });
                // 等流真正落盘再 resolve。
                //
                // 之前是 out.end() 后立刻 resolve，然后下游（证据归档）马上读 stdout.log——
                // 写流还没 flush 完，读到的就是空文件。表现是「任务成功、产物齐全，
                // 但证据偶尔被判为不含锚点而丢弃」，约 20% 概率，随机且难复现。
                // 在真实评估里这就是「某个发现偶尔没进证据库」，几乎不可能事后定位。
                const flushThen = (value) => {
                    const settled = (stream) => stream.closed ? Promise.resolve() : new Promise((r) => stream.once('close', () => r()));
                    void Promise.all([settled(out), settled(err)]).then(() => resolve(value));
                };
                child.on('error', (e) => {
                    spawnError = String(e);
                    spawnErrorCode = e.code;
                    out.end();
                    err.end();
                    flushThen(null);
                });
                child.on('close', (code, signal) => {
                    signalName = signal;
                    out.end();
                    err.end();
                    flushThen(code);
                });
            });
        }
        catch (error) {
            spawnError = String(error);
        }
        finally {
            clearTimeout(timer);
            this.running.delete(task.id);
        }
        const endedAt = Date.now();
        const status = spawnError !== undefined ? 'failed' : timedOut ? 'failed' : exitCode === 0 ? 'done' : 'failed';
        fs.writeFileSync(path.join(evidenceDir, 'meta.json'), JSON.stringify({
            taskId: task.id,
            kind: task.kind,
            argv: task.argv,
            cwd: task.cwd,
            status,
            exitCode,
            ...(signalName === null ? {} : { signal: signalName }),
            timedOut,
            attempt,
            startedAt,
            endedAt,
            durationMs: endedAt - startedAt,
            ...(spawnError === undefined ? {} : { spawnError }),
            ...(spawnErrorCode === undefined ? {} : { spawnErrorCode }),
        }, null, 2), 'utf8');
        this.store.markFinished(task.id, status, {
            exitCode,
            evidenceDir,
            ...(spawnError !== undefined ? { note: spawnError } : timedOut ? { note: `timed out after ${task.timeoutMs}ms` } : {}),
        });
        this.logger?.info(`queue: ${task.id} ${status} (exit=${String(exitCode)})`);
        // spawn 已经结束，env 不再需要；key 在内存里多留一秒都是多余的暴露面。
        this.releaseEnv(task.id);
        // 终态回调：上层据此把证据归档、更新 claim。
        const finished = this.store.get(task.id);
        if (finished !== undefined && this.onFinish !== undefined) {
            try {
                this.onFinish(finished);
            }
            catch (error) {
                this.logger?.warn(`queue: onFinish handler failed for ${task.id}: ${String(error)}`);
            }
        }
        this.schedulePump();
    }
}
