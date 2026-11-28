/**
 * 结构画像：动手之前先看数据的形状。
 *
 * 真实教训：六轮、两个半小时，模型手上有一份 50295 条规则的图，却只能靠 bash
 * 和 python 从零做图分析。它数的是「模拟 200 轮不收敛」，而这份数据的真相是
 * 「2475 层逐层推进」——两个数字指向完全相反的解释，而算对只需要遍历一次。
 *
 * 更关键的是：2475 这个数字和出题人说的时间线对得上，看到它就会想到「分层电路」；
 * 看到「200 轮不收敛」只会想到「系统坏了」。**同一个现象，量对了就是线索，
 * 量错了就是噪音。**
 *
 * 所以这个工具存在的理由不是「帮它算」，是让它在分析之前先拿到正确的量。
 */
import fs from 'node:fs';
/** 解析一行 `A, B -> C, -D`。容忍括号、斜杠、多余空格。 */
export function parseRuleLine(line) {
    const arrow = line.indexOf('->');
    if (arrow === -1)
        return undefined;
    const split = (s) => s
        .replace(/[()]/g, ' ')
        .split(/[,/]/)
        .map((x) => x.trim())
        .filter((x) => x.length > 0);
    const conds = split(line.slice(0, arrow));
    const right = split(line.slice(arrow + 2));
    const adds = [];
    const removes = [];
    for (const t of right) {
        if (t.startsWith('-'))
            removes.push(t.slice(1).trim());
        else
            adds.push(t);
    }
    if (conds.length === 0)
        return undefined;
    return { conds, adds, removes };
}
/**
 * 算层数：找 `X -> ... -X ... Y` 这样的推进，从 X 走到 Y，一路数下去。
 *
 * 这不是通用图论里的「层」，是这类规则系统特有的：每层一个标记 tag，
 * 出现即自毁并把下一个标记推出来。识别出来的长度就是轮数。
 */
function measureLayers(rules) {
    // 自我回收：结论里删掉了自己
    const next = new Map();
    for (const r of rules) {
        for (const gone of r.removes) {
            if (!r.conds.includes(gone))
                continue;
            const successor = r.adds.find((a) => a !== gone);
            if (successor !== undefined && !next.has(gone))
                next.set(gone, successor);
        }
    }
    if (next.size === 0)
        return { layers: 0, longestChain: 0 };
    // 每条链走到不能走为止；用记忆化避免重复遍历
    const memo = new Map();
    const depth = (node, seen) => {
        const cached = memo.get(node);
        if (cached !== undefined)
            return cached;
        if (seen.has(node))
            return 0;
        const nxt = next.get(node);
        if (nxt === undefined)
            return 0;
        seen.add(node);
        const d = 1 + depth(nxt, seen);
        seen.delete(node);
        memo.set(node, d);
        return d;
    };
    let longest = 0;
    for (const node of next.keys())
        longest = Math.max(longest, depth(node, new Set()));
    // 链长 + 1 = 层数（起点那层也算）
    return { layers: longest + 1, longestChain: longest + 1 };
}
/** 强连通分量：Tarjan。只关心「有没有真环、最大环多大」。 */
function cycleStats(nodes, edges) {
    const index = new Map();
    const low = new Map();
    const onStack = new Set();
    const stack = [];
    let counter = 0;
    let cycles = 0;
    let largest = 0;
    const strongconnect = (v) => {
        index.set(v, counter);
        low.set(v, counter);
        counter += 1;
        stack.push(v);
        onStack.add(v);
        for (const w of edges.get(v) ?? []) {
            if (!index.has(w)) {
                strongconnect(w);
                low.set(v, Math.min(low.get(v), low.get(w)));
            }
            else if (onStack.has(w)) {
                low.set(v, Math.min(low.get(v), index.get(w)));
            }
        }
        if (low.get(v) === index.get(v)) {
            const comp = [];
            for (;;) {
                const w = stack.pop();
                if (w === undefined)
                    break;
                onStack.delete(w);
                comp.push(w);
                if (w === v)
                    break;
            }
            // 单节点且无自环不算环
            const selfLoop = (edges.get(v) ?? new Set()).has(v);
            if (comp.length > 1 || (comp.length === 1 && selfLoop)) {
                cycles += 1;
                largest = Math.max(largest, comp.length);
            }
        }
    };
    for (const n of nodes)
        if (!index.has(n))
            strongconnect(n);
    return { cycles, largest };
}
export function profileGraph(text) {
    const rules = [];
    for (const line of text.split('\n')) {
        const t = line.trim();
        if (t === '' || t.startsWith('#'))
            continue;
        const r = parseRuleLine(t);
        if (r !== undefined)
            rules.push(r);
    }
    const nodes = new Set();
    const fanIn = new Map();
    const fanOut = new Map();
    const edges = new Map();
    for (const r of rules) {
        for (const c of r.conds)
            nodes.add(c);
        for (const a of r.adds)
            nodes.add(a);
        for (const d of r.removes)
            nodes.add(d);
        for (const c of r.conds) {
            fanOut.set(c, (fanOut.get(c) ?? 0) + 1);
            for (const a of r.adds) {
                let set = edges.get(c);
                if (set === undefined) {
                    set = new Set();
                    edges.set(c, set);
                }
                set.add(a);
            }
        }
        for (const a of r.adds)
            fanIn.set(a, (fanIn.get(a) ?? 0) + 1);
    }
    let selfRetracting = 0;
    for (const r of rules) {
        if (r.removes.some((gone) => r.conds.includes(gone)))
            selfRetracting += 1;
    }
    const { layers, longestChain } = measureLayers(rules);
    const { cycles, largest } = cycleStats([...nodes], edges);
    const top = (m) => [...m.entries()]
        .sort((a, b) => b[1] - a[1])
        .slice(0, 5)
        .map(([node, count]) => ({ node: node.length > 40 ? `${node.slice(0, 37)}...` : node, count }));
    const verdict = layers > 50
        ? `这是一个分层推进结构：${String(layers)} 层，每层一个标记 tag 出现即自毁并推下一层。想拿到结果要把层展开后求解，而不是反复模拟收敛。`
        : cycles > 0
            ? `存在 ${String(cycles)} 个强连通分量（最大 ${String(largest)} 个节点），是带环的约束系统，不是分层结构。`
            : `是一个 ${String(nodes.size)} 节点的有向无环图，${String(rules.length)} 条规则。`;
    return {
        nodes: nodes.size,
        edges: [...edges.values()].reduce((s, x) => s + x.size, 0),
        selfRetracting,
        layers,
        longestChain,
        cycles,
        largestCycle: largest,
        fanInTop: top(fanIn),
        fanOutTop: top(fanOut),
        verdict,
    };
}
/** 从文件读并画像。文件不存在时返回 undefined，不抛。 */
export function profileFile(path) {
    try {
        return profileGraph(fs.readFileSync(path, 'utf8'));
    }
    catch {
        return undefined;
    }
}
// ── 模型侧工具 ───────────────────────────────────────────────
const PROFILE_SCHEMA = {
    type: 'object',
    properties: {
        nodes: { type: 'number' },
        edges: { type: 'number' },
        layers: { type: 'number', description: 'Number of sequential layers in the rule system. High values mean a phased circuit.' },
        longest_chain: { type: 'number' },
        self_retracting: { type: 'number', description: 'Rules that retract their own tag — the signature of layered execution.' },
        cycles: { type: 'number' },
        largest_cycle: { type: 'number' },
        verdict: { type: 'string' },
        fan_in_top: { type: 'array', items: { type: 'object', properties: { node: { type: 'string' }, count: { type: 'number' } }, required: ['node', 'count'] } },
        fan_out_top: { type: 'array', items: { type: 'object', properties: { node: { type: 'string' }, count: { type: 'number' } }, required: ['node', 'count'] } },
    },
    required: ['nodes', 'edges', 'layers', 'verdict'],
};
/**
 * 结构画像工具。
 *
 * 描述里刻意写明「分析之前先跑这个」，因为真实故障是反过来的：
 * 模型直接开写模拟器，跑了几小时才想到该先看形状。
 */
export function graphProfileTools(options = {}) {
    return [
        {
            name: 'graph_profile',
            description: 'Profile the shape of a rule/graph file before writing any solver. Parses lines of the form `A, B -> C, -D` and reports ' +
                'node/edge counts, fan-in/fan-out, strongly connected components, and — most importantly — how many sequential LAYERS the ' +
                'rules form. Run this first: a rule system with hundreds of layers behaves completely differently from a flat constraint ' +
                'set, and simulating it round by round will look like "it never converges" when it is actually just walking the layers. ' +
                'Use the reported layer count to decide whether you need a layered model instead of a trial-and-error loop.',
            parameters: {
                type: 'object',
                properties: {
                    path: { type: 'string', description: 'File to profile.' },
                },
                required: ['path'],
            },
            output: {
                schema: PROFILE_SCHEMA,
                render: (_a, v) => {
                    const r = v;
                    return [
                        {
                            type: 'text',
                            text: [
                                `nodes=${String(r.nodes)} edges=${String(r.edges)}`,
                                `layers=${String(r.layers)} longest_chain=${String(r.longest_chain)} self_retracting=${String(r.self_retracting)}`,
                                `cycles=${String(r.cycles)} largest_cycle=${String(r.largest_cycle)}`,
                                `verdict: ${String(r.verdict)}`,
                            ].join('\n'),
                        },
                    ];
                },
            },
            async execute(args) {
                const path = String(args.path ?? '');
                const profile = profileFile(path);
                if (profile === undefined) {
                    return { nodes: 0, edges: 0, layers: 0, verdict: `cannot read "${path}"`, cycles: 0 };
                }
                options.onProfile?.(profile);
                return {
                    nodes: profile.nodes,
                    edges: profile.edges,
                    layers: profile.layers,
                    longest_chain: profile.longestChain,
                    self_retracting: profile.selfRetracting,
                    cycles: profile.cycles,
                    largest_cycle: profile.largestCycle,
                    verdict: profile.verdict,
                    fan_in_top: [...profile.fanInTop],
                    fan_out_top: [...profile.fanOutTop],
                };
            },
        },
    ];
}
export function installGraphProfileTools(ctx, options = {}) {
    for (const tool of graphProfileTools(options))
        ctx.tools.register(tool);
}
