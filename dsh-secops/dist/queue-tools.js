/**
 * 跨进程调度的模型侧工具：提交任务、查询队列。
 *
 * 工具的 `output.schema` 必须是 lossless JSON，`render` 产模型可见文本。
 * 这里刻意让 `worker_submit` 只返回任务 id 与最终状态 —— 输出正文留在证据目录，
 * 由模型用 fs 工具按需读取，避免把大块 stdout 灌进上下文。
 */
import fs from 'node:fs';
import path from 'node:path';
import { digestArtifact, digestArtifactStrict } from "./replay.js";
const STATUS_SCHEMA = {
    type: 'object',
    properties: {
        id: { type: 'string' },
        kind: { type: 'string' },
        status: { type: 'string' },
        attempts: { type: 'number' },
        exitCode: { type: 'number' },
        evidenceDir: { type: 'string' },
        note: { type: 'string' },
        archived: { type: 'boolean', description: 'Whether the artifact became claim evidence.' },
        claimId: { type: 'string' },
        rejectReason: { type: 'string', description: 'Why the artifact was rejected as evidence.' },
    },
    required: ['id', 'status'],
};
export function queueTools(runner, options = {}) {
    const submit = {
        name: 'worker_submit',
        description: 'Submit a command to the persistent cross-process queue. Returns immediately with a task id; ' +
            'the command runs in its own process group with a timeout, and stdout/stderr land in the evidence directory. ' +
            'Use worker_status to poll. Identical (kind, argv, cwd) submissions are idempotent.',
        parameters: {
            type: 'object',
            properties: {
                kind: { type: 'string', description: 'Task category, e.g. "http-diff" or "nuclei".' },
                argv: {
                    type: 'array',
                    items: { type: 'string' },
                    description: 'Executable and arguments. Never shell-interpreted; use ["sh","-c",...] if you need a shell.',
                },
                cwd: { type: 'string', description: 'Working directory. Defaults to the harness cwd.' },
                timeout_ms: { type: 'number', description: 'Per-task timeout in milliseconds.' },
                claim_id: {
                    type: 'string',
                    description: 'Optional claim to attach the task artifacts to. Relevance is judged by argv and by the produced output — ' +
                        'a self-written narration is not evidence. Repeating the same tool does not count as an independent path.',
                },
            },
            required: ['kind', 'argv'],
        },
        output: {
            schema: STATUS_SCHEMA,
            render: (_args, value) => [{ type: 'text', text: JSON.stringify(value) }],
        },
        execute: async (args) => {
            const input = args;
            if (input.claim_id !== undefined && options.claimExists !== undefined && !options.claimExists(input.claim_id)) {
                return { id: '', kind: input.kind, status: 'rejected', attempts: 0, note: `unknown claim: ${input.claim_id}` };
            }
            const task = runner.submit({
                kind: input.kind,
                argv: input.argv,
                ...(input.cwd === undefined ? {} : { cwd: input.cwd }),
                ...(input.timeout_ms === undefined ? {} : { timeoutMs: input.timeout_ms }),
            });
            if (input.claim_id !== undefined)
                options.link?.(task.id, { claimId: input.claim_id });
            return {
                id: task.id,
                kind: task.kind,
                status: task.status,
                attempts: task.attempts,
            };
        },
    };
    const status = {
        name: 'worker_status',
        description: 'Read queue state. With id: that task. Without id: the most recent tasks. ' +
            'stdout/stderr are not inlined — read them from the evidence directory.',
        parameters: {
            type: 'object',
            properties: {
                id: { type: 'string', description: 'Task id. Omit to list recent tasks.' },
                limit: { type: 'number', description: 'When listing, how many to return (default 20).' },
            },
        },
        output: {
            schema: {
                type: 'object',
                properties: {
                    tasks: { type: 'array', items: STATUS_SCHEMA },
                },
                required: ['tasks'],
            },
            render: (_args, value) => [{ type: 'text', text: JSON.stringify(value, null, 2) }],
        },
        execute: async (args) => {
            const input = (args ?? {});
            if (input.id !== undefined) {
                const task = runner.get(input.id);
                return { tasks: task === undefined ? [] : [project(task, options.outcomeOf?.(task.id))] };
            }
            const limit = Math.max(1, input.limit ?? 20);
            const all = runner.list();
            return { tasks: all.slice(-limit).map((t) => project(t, options.outcomeOf?.(t.id))) };
        },
    };
    return [submit, status];
}
function project(task, outcome) {
    return {
        id: task.id,
        kind: task.kind,
        status: task.status,
        attempts: task.attempts,
        ...(task.exitCode === undefined || task.exitCode === null ? {} : { exitCode: task.exitCode }),
        ...(task.evidenceDir === undefined ? {} : { evidenceDir: task.evidenceDir }),
        ...(task.note === undefined ? {} : { note: task.note }),
        // 归档结果必须回传：模型需要知道证据有没有被采纳、为什么没被采纳。
        ...(outcome === undefined
            ? {}
            : outcome.archived
                ? { archived: true, claimId: outcome.claimId }
                : { archived: false, claimId: outcome.claimId, rejectReason: outcome.reason }),
    };
}
/** 注册队列工具。返回卸载器。 */
export function installQueueTools(ctx, runner, options = {}) {
    for (const tool of queueTools(runner, options))
        ctx.tools.register(tool);
}
/** 产物摘要上限：只读开头一段，足够匹配锚点，又不把大文件读进内存。 */
const ARTIFACT_SNIFF_BYTES = 8192;
/** 从证据目录读 stdout/stderr 摘要作为 artifact 判据。 */
function sniffArtifact(evidenceDir) {
    if (evidenceDir === undefined)
        return undefined;
    const parts = [];
    for (const name of ['stdout.log', 'stderr.log']) {
        try {
            const buf = Buffer.alloc(ARTIFACT_SNIFF_BYTES);
            const fd = fs.openSync(path.join(evidenceDir, name), 'r');
            let read = 0;
            try {
                read = fs.readSync(fd, buf, 0, ARTIFACT_SNIFF_BYTES, 0);
            }
            finally {
                fs.closeSync(fd);
            }
            if (read > 0)
                parts.push(buf.subarray(0, read).toString('utf8'));
        }
        catch {
            /* 文件不存在就跳过 */
        }
    }
    return parts.length === 0 ? undefined : parts.join('\n');
}
export function createEvidenceArchiver(claimStore) {
    const pending = new Map();
    const outcomes = new Map();
    let rejection;
    return {
        onFinish(task) {
            const link = pending.get(task.id);
            if (link === undefined)
                return;
            pending.delete(task.id);
            // 先记形态再挂证据：形态是这条断言「在什么世界里得出的」这个事实，
            // 和证据成败无关——即使这次执行失败了也该记下来（只是没证据可挂）。
            claimStore.setShape?.(link.claimId, link.shape);
            // 只有成功结束才算证据：失败任务说明命令没跑通，不是对断言的观测。
            if (task.status !== 'done' || task.evidenceDir === undefined)
                return;
            const artifact = sniffArtifact(task.evidenceDir);
            // executed 用实际 argv：这是「证据必须触及断言锚点」的主判据，
            // 模型无法只靠自述把无关命令冒充成证据。
            // source + baselineDigest 让证据可重放：claim_verify 会用同一 argv 重跑并比对骨架。
            const result = claimStore.attach(link.claimId, {
                ref: `task:${task.id}`,
                pathKey: `task:${task.kind}`,
                note: `queue task ${task.kind} exit=${String(task.exitCode)} evidence=${task.evidenceDir}`,
                // task.argv 来自队列里的真实任务记录，不是模型现编的 → 标记可信。
                ...(task.argv === undefined ? {} : { executed: task.argv.join(' '), executedTrusted: true }),
                // artifact 是 worker 落盘的真实产物（task.evidenceDir），由系统读取，
                // 不是模型传入的文本 → 显式声明可信来源。
                ...(artifact === undefined ? {} : { artifact, artifactTrusted: true }),
                ...(task.argv === undefined
                    ? {}
                    : {
                        source: {
                            kind: 'worker',
                            taskId: task.id,
                            argv: [...task.argv],
                            cwd: task.cwd ?? process.cwd(),
                        },
                        baselineDigest: digestArtifact(artifact ?? '', ''),
                        baselineStrictDigest: digestArtifactStrict(artifact ?? '', ''),
                    }),
            });
            if (result.ok) {
                outcomes.set(task.id, { archived: true, claimId: link.claimId });
            }
            else {
                const reason = result.reason ?? 'rejected';
                rejection = { taskId: task.id, claimId: link.claimId, reason };
                outcomes.set(task.id, { archived: false, claimId: link.claimId, reason });
            }
        },
        options: {
            link: (taskId, link) => pending.set(taskId, { claimId: link.claimId, ...(link.shape === undefined ? {} : { shape: link.shape }) }),
            claimExists: (id) => claimStore.get(id) !== undefined,
        },
        pendingCount: () => pending.size,
        lastRejection: () => rejection,
        outcomeOf: (taskId) => outcomes.get(taskId),
    };
}
