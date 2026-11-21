/**
 * 覆盖账本：记住「什么还没测」，和「测出了什么」一样重要。
 *
 * 借鉴自 redamon 的 coverage stamps（graph_db/coverage_stamps.py）。它的设计里
 * 有一条原则值得原样搬过来：
 *
 *   没有 stamp，但同项目里别的 host 有 stamp  → 这个 host「未扫描」
 *   整个项目一条 stamp 都没有               → 只能说「覆盖未记录」，不能说「未扫描」
 *
 * 这和 claim 系统里 `inconclusive ≠ clean` 是同一条原则：**没有数据不等于阴性**。
 * 把「没测过」和「测过没发现」混为一谈，是安全评估里最常见也最难发现的一类错误。
 *
 * 为什么这套东西必须有：真实观测里，六轮分析全压在同一条路上，没有任何机制说
 * 「A、B、C 都试过了，还剩 D」。人靠记忆做这件事，模型靠上下文做这件事，
 * 而上下文会被压缩、会被遗忘。账本不会。
 */
import fs from 'node:fs';
import path from 'node:path';
export class CoverageLedger {
    /** asset → check → 最新一条 stamp（后写覆盖先写）。 */
    byAsset = new Map();
    storePath;
    /** 整个账本一共记录过几条——用来区分「未扫描」和「未记录」。 */
    total = 0;
    constructor(storePath) {
        this.storePath = storePath;
        if (storePath !== undefined)
            this.load();
    }
    stamp(input) {
        const record = { ...input, at: input.at ?? Date.now() };
        let checks = this.byAsset.get(record.asset);
        if (checks === undefined) {
            checks = new Map();
            this.byAsset.set(record.asset, checks);
        }
        checks.set(record.check, record);
        this.total += 1;
        this.append(record);
        return record;
    }
    load() {
        if (this.storePath === undefined)
            return;
        let raw;
        try {
            raw = fs.readFileSync(this.storePath, 'utf8');
        }
        catch {
            return;
        }
        for (const line of raw.split('\n')) {
            const t = line.trim();
            if (t === '')
                continue;
            try {
                const s = JSON.parse(t);
                if (typeof s.asset !== 'string' || typeof s.check !== 'string')
                    continue;
                // last-wins：同一 (asset, check) 后写的覆盖先写的
                let checks = this.byAsset.get(s.asset);
                if (checks === undefined) {
                    checks = new Map();
                    this.byAsset.set(s.asset, checks);
                }
                checks.set(s.check, s);
                this.total += 1;
            }
            catch {
                /* 半行跳过 */
            }
        }
    }
    append(record) {
        if (this.storePath === undefined)
            return;
        try {
            fs.mkdirSync(path.dirname(this.storePath), { recursive: true });
            fs.appendFileSync(this.storePath, JSON.stringify(record) + '\n', 'utf8');
        }
        catch {
            /* 写不了不影响判定 */
        }
    }
    /**
     * 判定一个资产的覆盖情况。
     *
     * `checks` 是「应该做哪些检查」的清单。给了它才能算出 gaps；
     * 不给就只能报「记录了什么」。
     */
    of(asset, checks = []) {
        const stamps = [...(this.byAsset.get(asset)?.values() ?? [])];
        const done = new Set(stamps.map((s) => s.check));
        const gaps = checks.filter((c) => !done.has(c));
        let state;
        if (stamps.length === 0) {
            // 关键区分：整个账本一条都没有 = 覆盖未记录；别处有记录但这里没有 = 未扫描
            state = this.total === 0 ? 'not-recorded' : 'not-scanned';
        }
        else if (stamps.every((s) => s.status === 'complete') && gaps.length === 0) {
            state = 'covered';
        }
        else if (stamps.every((s) => s.status === 'complete')) {
            state = 'partial';
        }
        else if (stamps.some((s) => s.status === 'partial' || s.status === 'failed')) {
            state = 'partial';
        }
        else {
            // 全是 no-input：没东西可查，算不得覆盖
            state = 'not-scanned';
        }
        const verdict = (() => {
            switch (state) {
                case 'not-recorded':
                    return '覆盖未记录（不是「未扫描」——这个账本里还没有任何记录）';
                case 'not-scanned':
                    return stamps.length === 0 ? '未扫描' : '只有 no-input 记录，等于没测';
                case 'partial':
                    return `部分覆盖：${stamps.map((s) => `${s.check}=${s.status}`).join(', ')}${gaps.length === 0 ? '' : `；未做 ${gaps.join(', ')}`}`;
                case 'covered':
                    return `已覆盖：${stamps.map((s) => s.check).join(', ')}`;
            }
        })();
        return { asset, state, stamps, gaps, verdict };
    }
    /** 所有记录过的资产。 */
    assets() {
        return [...this.byAsset.keys()];
    }
    /** 全局摘要：多少资产、哪些还是未扫描。 */
    summary(checks = []) {
        const gaps = [];
        for (const asset of this.byAsset.keys()) {
            const cov = this.of(asset, checks);
            if (cov.gaps.length > 0 || cov.state === 'partial' || cov.state === 'not-scanned') {
                gaps.push({ asset, missing: cov.gaps.length > 0 ? cov.gaps : ['(partial)'] });
            }
        }
        return { assets: this.byAsset.size, recorded: this.total > 0, gaps };
    }
    get size() {
        return this.total;
    }
}
const VIEW_SCHEMA = {
    type: 'object',
    properties: {
        recorded: { type: 'boolean', description: 'False means the ledger has no entries at all — that is "coverage not recorded", not "nothing was tested".' },
        assets: { type: 'number' },
        items: {
            type: 'array',
            items: {
                type: 'object',
                properties: {
                    asset: { type: 'string' },
                    state: { type: 'string', description: 'covered | partial | not-scanned | not-recorded' },
                    verdict: { type: 'string' },
                    missing: { type: 'array', items: { type: 'string' } },
                },
                required: ['asset', 'state', 'verdict'],
            },
        },
    },
    required: ['recorded', 'assets', 'items'],
};
/**
 * 覆盖查询工具。
 *
 * 只读。记账由太尉在执行后自动完成——让模型手动填覆盖率，
 * 它会在「还没测」和「测了没发现」之间含混过去，而这两个必须分开。
 */
export function coverageTools(ledger, options = {}) {
    return [
        {
            name: 'coverage_view',
            description: 'Show what has actually been checked and what has not. Each asset carries stamps per check with a status ' +
                '(complete / partial / no-input / failed). Three states matter and are kept distinct: "not-scanned" means the ledger ' +
                'has other entries but none for this asset; "not-recorded" means nothing has been recorded at all and you must not ' +
                'read that as clean. Use this before repeating a check — repeating a covered check tends to reproduce the same result.',
            parameters: {
                type: 'object',
                properties: {
                    asset: { type: 'string', description: 'Optional: one asset. Omit for all.' },
                },
            },
            output: {
                schema: VIEW_SCHEMA,
                render: (_a, v) => {
                    const r = v;
                    const lines = [`recorded=${String(r.recorded)} assets=${String(r.assets)}`];
                    for (const it of (r.items ?? [])) {
                        const miss = (it.missing ?? []);
                        lines.push(`  ${String(it.asset)} — ${String(it.state)}${miss.length === 0 ? '' : `; missing: ${miss.join(',')}`}`);
                        lines.push(`    ${String(it.verdict)}`);
                    }
                    return [{ type: 'text', text: lines.join('\n') }];
                },
            },
            async execute(args) {
                const checks = options.checks ?? [];
                const one = typeof args.asset === 'string' ? args.asset : undefined;
                const assets = one === undefined ? ledger.assets() : [one];
                return {
                    recorded: ledger.size > 0,
                    assets: ledger.size,
                    items: assets.map((a) => {
                        const cov = ledger.of(a, checks);
                        return { asset: a, state: cov.state, verdict: cov.verdict, missing: [...cov.gaps] };
                    }),
                };
            },
        },
    ];
}
export function installCoverageTools(ctx, ledger, options = {}) {
    for (const tool of coverageTools(ledger, options))
        ctx.tools.register(tool);
}
