/**
 * 资产库：把散落在证据文件里的扫描结果变成可查询的结构。
 *
 * 之前的状态：nmap 报 `22/tcp ssh, 445/tcp netbios-ssn, 5432/tcp postgresql`，
 * 这三个服务就停在那条 detail 字符串里。下一轮再派活时没人知道 445 已经开着——
 * 除非模型自己去翻日志想起来。
 *
 * 真实渗透里，「看到 445 开放 → 转向 SMB 枚举 → 拿到共享列表」这条推导是靠
 * 资产之间的父子关系驱动的，不是靠记忆。没有资产层，每一次都是从头开始。
 *
 * 这里刻意做得扁平：host → service / endpoint / share。不做完整攻击面图——
 * 那需要图数据库和大量关系推断，而当前真正的痛点是「扫描结果没有落成结构」，
 * 先解决这个，别一步跨到图。
 */
import fs from 'node:fs';
import path from 'node:path';
const OUTCOME_RANK = { clean: 0, exposure: 1, finding: 2 };
function mergeSeen(prev, next) {
    const out = { ...(prev ?? {}) };
    for (const [k, v] of Object.entries(next)) {
        const cur = out[k];
        // 同一方向多次检查取最强结论：后来的一次「干净」不该覆盖之前的「有发现」。
        if (cur === undefined || OUTCOME_RANK[v] > OUTCOME_RANK[cur])
            out[k] = v;
    }
    return out;
}
export class AssetStore {
    byId = new Map();
    /** 断言 → 它关联的资产。反向索引，按 claim 查资产时不用扫全表。 */
    byClaim = new Map();
    storePath;
    constructor(storePath) {
        this.storePath = storePath;
        if (storePath !== undefined)
            this.load();
    }
    record(input) {
        const at = input.at ?? Date.now();
        const existing = this.byId.get(input.id);
        const next = {
            id: input.id,
            kind: input.kind,
            ...(input.parent === undefined
                ? existing?.parent === undefined
                    ? {}
                    : { parent: existing.parent }
                : { parent: input.parent }),
            attrs: { ...(existing?.attrs ?? {}), ...(input.attrs ?? {}) },
            firstSeen: existing?.firstSeen ?? at,
            lastSeen: at,
            seen: mergeSeen(existing?.seen, input.seen ?? {}),
            claimIds: [...new Set([...(existing?.claimIds ?? []), ...(input.claimIds ?? [])])],
        };
        this.byId.set(input.id, next);
        for (const cid of next.claimIds) {
            let set = this.byClaim.get(cid);
            if (set === undefined) {
                set = new Set();
                this.byClaim.set(cid, set);
            }
            set.add(input.id);
        }
        this.append(next);
        return next;
    }
    /** 把一个方向在某目标上的结论盖到该资产上。 */
    markChecked(id, direction, outcome) {
        const existing = this.byId.get(id);
        if (existing === undefined)
            return;
        this.record({ id, kind: existing.kind, seen: { [direction]: outcome } });
    }
    get(id) {
        return this.byId.get(id);
    }
    /** 一条断言涉及哪些资产。 */
    assetsOf(claimId) {
        return [...(this.byClaim.get(claimId) ?? [])].map((id) => this.byId.get(id)).filter((a) => a !== undefined);
    }
    list(filter = {}) {
        let all = [...this.byId.values()];
        if (filter.kind !== undefined)
            all = all.filter((a) => a.kind === filter.kind);
        if (filter.parent !== undefined)
            all = all.filter((a) => a.parent === filter.parent);
        const dir = filter.direction;
        if (dir !== undefined)
            all = all.filter((a) => a.seen[dir] !== undefined);
        if (filter.unchecked === true)
            all = all.filter((a) => Object.keys(a.seen).length === 0);
        const cid = filter.claimId;
        if (cid !== undefined)
            all = all.filter((a) => a.claimIds.includes(cid));
        all.sort((a, b) => (a.kind === b.kind ? a.id.localeCompare(b.id) : a.kind.localeCompare(b.kind)));
        return filter.limit === undefined ? all : all.slice(0, filter.limit);
    }
    /** 某台主机下的全部服务与端点。 */
    children(host) {
        return this.list({ parent: host });
    }
    summary() {
        const byKind = {};
        let withFindings = 0;
        let unchecked = 0;
        for (const a of this.byId.values()) {
            byKind[a.kind] = (byKind[a.kind] ?? 0) + 1;
            if (Object.values(a.seen).some((v) => v === 'finding'))
                withFindings += 1;
            if (Object.keys(a.seen).length === 0)
                unchecked += 1;
        }
        return { total: this.byId.size, byKind, withFindings, unchecked };
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
                const a = JSON.parse(t);
                if (typeof a.id !== 'string' || typeof a.kind !== 'string')
                    continue;
                const prev = this.byId.get(a.id);
                const next = {
                    ...a,
                    claimIds: [...new Set([...(prev?.claimIds ?? []), ...(a.claimIds ?? [])])],
                    attrs: { ...(prev?.attrs ?? {}), ...(a.attrs ?? {}) },
                    seen: mergeSeen(prev?.seen, a.seen ?? {}),
                    firstSeen: Math.min(prev?.firstSeen ?? a.firstSeen, a.firstSeen),
                    lastSeen: Math.max(prev?.lastSeen ?? a.lastSeen, a.lastSeen),
                };
                this.byId.set(a.id, next);
                for (const cid of next.claimIds) {
                    let set = this.byClaim.get(cid);
                    if (set === undefined) {
                        set = new Set();
                        this.byClaim.set(cid, set);
                    }
                    set.add(a.id);
                }
            }
            catch {
                /* 半行跳过 */
            }
        }
    }
    append(a) {
        if (this.storePath === undefined)
            return;
        try {
            fs.mkdirSync(path.dirname(this.storePath), { recursive: true });
            fs.appendFileSync(this.storePath, JSON.stringify(a) + '\n', 'utf8');
        }
        catch {
            /* 写不了不影响内存里的判定 */
        }
    }
}
// ── 从工具输出里提取资产 ─────────────────────────────────────
/** 从 URL 取 host（含端口）。 */
function hostOfUrl(url) {
    try {
        const u = new URL(url);
        return u.port === '' ? u.hostname : `${u.hostname}:${u.port}`;
    }
    catch {
        return undefined;
    }
}
/**
 * 按方向解析工具输出，产出资产。
 *
 * 只认能确定解析的格式（nmap 的端口行、nuclei 的 url 字段、enum4linux 的 shares）。
 * 认不出来就返回空数组——猜出来的资产比没有更糟，它会让后续推导建立在假数据上。
 */
export function extractAssets(direction, detail, target, at) {
    const out = [];
    const ts = at ?? Date.now();
    void ts;
    if (direction === 'internal-ad' || direction === 'web-pentest') {
        // nmap 风格：`22/tcp ssh, 445/tcp netbios-ssn`
        const hostMatch = /^([^\s,]+)/.exec(target);
        const host = hostOfUrl(target) ?? hostMatch?.[1] ?? target;
        if (host !== undefined && host !== '') {
            out.push({ id: host, kind: 'host', attrs: { source: direction } });
            for (const m of detail.matchAll(/(\d+)\/tcp\s+([\w.-]+)/g)) {
                out.push({
                    id: `${host}:${m[1]}`,
                    kind: 'service',
                    parent: host,
                    attrs: { port: m[1] ?? '', service: m[2] ?? '' },
                });
            }
        }
    }
    if (direction === 'web-pentest' && /^https?:\/\//i.test(target)) {
        const host = hostOfUrl(target);
        if (host !== undefined) {
            out.push({ id: host, kind: 'host', attrs: { source: direction } });
            out.push({ id: target, kind: 'endpoint', parent: host, attrs: { url: target } });
        }
    }
    if (direction === 'internal-ad') {
        // enum4linux 的共享列表：`shares: pub,IPC$`
        const m = /shares:\s*([^[]+)/i.exec(detail);
        if (m?.[1] !== undefined) {
            const host = /^([^\s:]+)/.exec(target)?.[1] ?? target;
            for (const name of m[1].split(',').map((x) => x.trim()).filter((x) => x !== '')) {
                out.push({ id: `${host}:share:${name}`, kind: 'share', parent: host, attrs: { name } });
            }
        }
    }
    if (direction === 'crypto') {
        const host = target.includes(':') ? target : `${target}:443`;
        out.push({ id: host, kind: 'host', attrs: { source: direction } });
        out.push({ id: `${host}/tls`, kind: 'service', parent: host, attrs: { service: 'tls' } });
    }
    if (direction === 'binary-reverse' || direction === 'code-audit') {
        out.push({ id: target, kind: 'file', attrs: { source: direction } });
    }
    return out;
}
const ASSET_SCHEMA = {
    type: 'object',
    properties: {
        total: { type: 'number' },
        unchecked: { type: 'number', description: 'Assets no check has touched yet — the real blind spots.' },
        with_findings: { type: 'number' },
        assets: {
            type: 'array',
            items: {
                type: 'object',
                properties: {
                    id: { type: 'string' },
                    kind: { type: 'string' },
                    parent: { type: 'string' },
                    seen: { type: 'string', description: 'direction=outcome pairs' },
                    claims: { type: 'array', items: { type: 'string' }, description: 'Claim ids established about this asset.' },
                },
                required: ['id', 'kind'],
            },
        },
    },
    required: ['total', 'assets'],
};
/**
 * 资产查询工具。
 *
 * 只说「有哪些资产、各自被谁查过、结论是什么」。不提建议——建议属于丞相。
 */
export function assetTools(store) {
    return [
        {
            name: 'asset_list',
            description: 'Query the asset store built from previous scans: hosts, services, endpoints, shares, files, what each was ' +
                'checked with, and what came out. Use it before picking the next target area — an asset that has never been ' +
                'checked (unchecked) is a blind spot, and a host whose 445/tcp is open is the natural next thing to enumerate. ' +
                'Saves rediscovering what the last run already established.',
            parameters: {
                type: 'object',
                properties: {
                    id: { type: 'string', description: 'Optional: one asset by id.' },
                    kind: { type: 'string', description: 'host | service | endpoint | share | file' },
                    parent: { type: 'string', description: 'Only assets under this host.' },
                    unchecked: { type: 'boolean', description: 'Only assets no check has touched.' },
                    claim_id: { type: 'string', description: 'Only assets linked to this claim.' },
                    limit: { type: 'number' },
                },
            },
            output: {
                schema: ASSET_SCHEMA,
                render: (_a, v) => {
                    const r = v;
                    const lines = [`total=${String(r.total)} unchecked=${String(r.unchecked ?? 0)} with_findings=${String(r.with_findings ?? 0)}`];
                    for (const a of (r.assets ?? [])) {
                        lines.push(`  ${String(a.kind)} ${String(a.id)}` +
                            (typeof a.parent === 'string' ? ` (under ${a.parent})` : '') +
                            (typeof a.seen === 'string' && a.seen !== '' ? ` [${a.seen}]` : ' [unchecked]') +
                            (a.claims?.length ? ` claims:${a.claims.join(',')}` : ''));
                    }
                    return [{ type: 'text', text: lines.join('\n') }];
                },
            },
            async execute(args) {
                const one = typeof args.id === 'string' ? store.get(args.id) : undefined;
                const list = one === undefined
                    ? store.list({
                        ...(typeof args.kind === 'string' ? { kind: args.kind } : {}),
                        ...(typeof args.parent === 'string' ? { parent: args.parent } : {}),
                        ...(args.unchecked === true ? { unchecked: true } : {}),
                        ...(typeof args.claim_id === 'string' ? { claimId: args.claim_id } : {}),
                        ...(typeof args.limit === 'number' ? { limit: args.limit } : {}),
                    })
                    : [one];
                const sum = store.summary();
                return {
                    total: sum.total,
                    unchecked: sum.unchecked,
                    with_findings: sum.withFindings,
                    assets: list.map((a) => ({
                        id: a.id,
                        kind: a.kind,
                        ...(a.parent === undefined ? {} : { parent: a.parent }),
                        seen: Object.entries(a.seen).map(([k, v]) => `${k}=${v}`).join(','),
                        ...(a.claimIds.length === 0 ? {} : { claims: [...a.claimIds] }),
                    })),
                };
            },
        },
    ];
}
