/**
 * 人才档案：每个 agent 的履历。
 *
 * 刻意只做记录，不自动改选择。理由和 Model Fallback 那边一样：样本量小时
 * 统计不可信，让一次偶发失败自动降权，会把「今天网络抖了一下」固化成
 * 「这个工具永远排最后」。档案的价值在于让人和模型看见「谁在什么形态上失手过」，
 * 而不是替它们做决定。
 *
 * 真要让战绩参与排序，用 preferProven 显式打开，并且只在样本量足够时生效。
 */
import fs from 'node:fs';
import path from 'node:path';
const MIN_SAMPLES_FOR_RANKING = 5;
export class Roster {
    records = new Map();
    storePath;
    constructor(storePath) {
        this.storePath = storePath;
        if (storePath !== undefined)
            this.load();
    }
    record(input) {
        const existing = this.records.get(input.agentId) ?? {
            id: input.agentId,
            runs: 0,
            settled: 0,
            inconclusive: 0,
            failed: 0,
            foundCount: 0,
            totalMs: 0,
            byShape: {},
        };
        const rec = { ...existing, byShape: { ...existing.byShape } };
        rec.runs += 1;
        if (input.outcome === 'settled')
            rec.settled += 1;
        else if (input.outcome === 'inconclusive')
            rec.inconclusive += 1;
        else if (input.outcome === 'failed') {
            rec.failed += 1;
            rec.lastFault = input.fault;
        }
        if (input.found === true)
            rec.foundCount += 1;
        if (input.durationMs !== undefined)
            rec.totalMs += input.durationMs;
        rec.lastRunAt = input.at ?? Date.now();
        rec.lastOutcome = input.outcome;
        if (input.shape !== undefined) {
            const s = rec.byShape[input.shape] ?? { runs: 0, settled: 0, found: 0 };
            s.runs += 1;
            if (input.outcome === 'settled')
                s.settled += 1;
            if (input.found === true)
                s.found += 1;
            rec.byShape[input.shape] = s;
        }
        this.records.set(input.agentId, rec);
    }
    get(agentId) {
        return this.records.get(agentId);
    }
    view() {
        return [...this.records.values()].sort((a, b) => b.runs - a.runs);
    }
    /**
     * 战绩打分，用于 preferProven 排序。区间 0..1。
     *
     * 样本不足时不参与排序（返回 undefined），避免「跑过一次就成功」被当成 100%。
     */
    successScore(agentId) {
        const rec = this.records.get(agentId);
        if (rec === undefined || rec.runs < MIN_SAMPLES_FOR_RANKING)
            return undefined;
        return rec.settled / rec.runs;
    }
    /** 某 agent 在某形态上的表现，给选择时做参考。 */
    shapeScore(agentId, shape) {
        const s = this.records.get(agentId)?.byShape[shape];
        if (s === undefined || s.runs < MIN_SAMPLES_FOR_RANKING)
            return undefined;
        return s.settled / s.runs;
    }
    load() {
        if (this.storePath === undefined)
            return;
        try {
            const raw = fs.readFileSync(this.storePath, 'utf8');
            for (const line of raw.split('\n')) {
                const t = line.trim();
                if (t === '')
                    continue;
                try {
                    const rec = JSON.parse(t);
                    if (typeof rec.id === 'string')
                        this.records.set(rec.id, { ...rec, byShape: rec.byShape ?? {} });
                }
                catch {
                    // 半行跳过：写入中途崩溃不该让整个档案报废
                }
            }
        }
        catch {
            /* 文件不存在就是空的 */
        }
    }
    /** 覆盖写全量快照（last-wins，与 claim 快照一致）。 */
    persist() {
        if (this.storePath === undefined)
            return;
        try {
            fs.mkdirSync(path.dirname(this.storePath), { recursive: true });
            const lines = [...this.records.values()].map((r) => JSON.stringify(r));
            fs.writeFileSync(this.storePath, lines.join('\n') + (lines.length === 0 ? '' : '\n'), 'utf8');
        }
        catch {
            /* 写不了不影响运行 */
        }
    }
}
