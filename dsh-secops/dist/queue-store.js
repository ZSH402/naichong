/**
 * 跨进程任务队列的持久化层。
 *
 * 介质选择：**append-only JSONL 文件**，不是 session log。
 * 理由：队列是跨会话、跨进程的；session log 是会话级且属于 agent 的对话记录，
 * 把调度状态塞进去会让"会话"和"任务"两种生命周期纠缠在一起。
 *
 * 恢复语义：进程崩溃后 `running` 状态的任务不可能还在跑（子进程随父进程组结束），
 * 加载时统一降级为 `interrupted`，由调用方决定重投还是标记失败。
 */
import fs from 'node:fs';
import path from 'node:path';
/** 一条 append-only 的任务日志。 */
export class TaskQueueStore {
    file;
    tasks = new Map();
    constructor(file) {
        this.file = file;
        fs.mkdirSync(path.dirname(file), { recursive: true });
    }
    /** 从磁盘重放全部记录，返回恢复后的任务表。 */
    load() {
        this.tasks = new Map();
        if (!fs.existsSync(this.file))
            return this.tasks;
        const text = fs.readFileSync(this.file, 'utf8');
        for (const line of text.split('\n')) {
            if (line.trim().length === 0)
                continue;
            let rec;
            try {
                rec = JSON.parse(line);
            }
            catch {
                // 崩溃可能留下半行，跳过即可 —— append-only 的价值就在这里。
                continue;
            }
            this.applyRecord(rec);
        }
        return this.tasks;
    }
    applyRecord(rec) {
        switch (rec.t) {
            case 'submit': {
                if (this.tasks.has(rec.task.id))
                    return;
                this.tasks.set(rec.task.id, { ...rec.task, status: 'queued', attempts: 0 });
                return;
            }
            case 'start': {
                const prev = this.tasks.get(rec.id);
                if (prev === undefined)
                    return;
                this.tasks.set(rec.id, { ...prev, status: 'running', attempts: rec.attempt, startedAt: rec.at });
                return;
            }
            case 'finish': {
                const prev = this.tasks.get(rec.id);
                if (prev === undefined)
                    return;
                this.tasks.set(rec.id, {
                    ...prev,
                    status: rec.status,
                    endedAt: rec.at,
                    ...(rec.exitCode === undefined ? {} : { exitCode: rec.exitCode }),
                    ...(rec.evidenceDir === undefined ? {} : { evidenceDir: rec.evidenceDir }),
                    ...(rec.note === undefined ? {} : { note: rec.note }),
                });
                return;
            }
            case 'recover': {
                for (const id of rec.ids) {
                    const prev = this.tasks.get(id);
                    if (prev === undefined || prev.status !== 'running')
                        continue;
                    this.tasks.set(id, { ...prev, status: 'interrupted', endedAt: rec.at, note: 'process exited while running' });
                }
                return;
            }
        }
    }
    append(rec) {
        fs.appendFileSync(this.file, `${JSON.stringify(rec)}\n`, 'utf8');
        this.applyRecord(rec);
    }
    /** 提交一个任务。同 id 重复提交是幂等的。 */
    submit(task) {
        const existing = this.tasks.get(task.id);
        if (existing !== undefined)
            return existing;
        this.append({ t: 'submit', task });
        return this.tasks.get(task.id);
    }
    markRunning(id, attempt) {
        this.append({ t: 'start', id, at: Date.now(), attempt });
    }
    markFinished(id, status, extra = {}) {
        this.append({ t: 'finish', id, status, at: Date.now(), ...extra });
    }
    /** 把上一进程遗留的 running 任务降级为 interrupted。 */
    recoverInterrupted() {
        const stale = [...this.tasks.values()].filter((t) => t.status === 'running').map((t) => t.id);
        if (stale.length > 0)
            this.append({ t: 'recover', ids: stale, at: Date.now() });
        return stale;
    }
    get(id) {
        return this.tasks.get(id);
    }
    list() {
        return [...this.tasks.values()].sort((a, b) => a.createdAt - b.createdAt);
    }
    get size() {
        return this.tasks.size;
    }
}
