/**
 * 丞相：任务理解、情报整理、生成可验证假设。
 *
 * 全部是确定性代码，这一点是设计决定而不是省事。丞相要做的事——
 * 盘点已知、找缺口、提假设——依据的是**结构**（哪些 claim 停在 hypothesis、
 * 哪些证据只有一条独立路径、哪些方向从没跑过），不是语义。让模型来读这些
 * 结构，只会把一个能算对的问题变成一个可能算错的问题。
 *
 * 真正需要语义的地方（这个目标可能有什么漏洞）由会话里的主模型承担，
 * 丞相负责把它框在可验证的范围内：每条假设必须带 direction + target + 可证伪条件。
 */
import { detectTargetShape } from "../agent-registry.js";
let counter = 0;
function nextId() {
    counter += 1;
    return `H-${String(counter).padStart(3, '0')}`;
}
export class Chancellor {
    registry;
    knowledge;
    coverage;
    assets;
    now;
    constructor(options) {
        this.registry = options.registry;
        this.knowledge = options.knowledge;
        this.coverage = options.coverage;
        this.assets = options.assets;
        this.now = options.now ?? Date.now;
    }
    /**
     * 盘一遍当前局面，产出假设清单。
     *
     * 四个来源，全部可判定：
     *   coverage-gap   —— 这个方向有能判定的 agent，但从来没对它跑过
     *   weak-evidence  —— 断言只有一条独立路径，可能存在系统性误判
     *   conflict       —— 同一断言既被证实又被推翻过
     *   manual         —— 调用方直接给的假设，原样纳入
     */
    /**
     * 按目标形态反查一个真能吃下它的方向。
     *
     * 形态是已经判出来的事实，用它反查方向比用「上次是哪个方向」更可靠，
     * 因为断言可能来自另一条派活链，甚至另一台机器。
     */
    pickDirectionForShape(shape, candidates) {
        for (const d of candidates) {
            if (this.registry.accepting(d, shape).length > 0)
                return d;
        }
        return undefined;
    }
    assess(input) {
        const shape = detectTargetShape(input.target);
        const wanted = input.directions ?? ['web-pentest', 'mcp-security', 'code-audit', 'binary-reverse', 'ai-security', 'internal-ad', 'crypto', 'post-exploit'];
        const hypotheses = [];
        const blockers = [];
        const skipped = [];
        const covered = new Set();
        // 1) 覆盖缺口：哪些方向能吃这个形态、有可用 agent、但还没跑过
        const claims = this.knowledge.claims();
        for (const c of claims) {
            if (c.lastDirection !== undefined)
                covered.add(c.lastDirection);
        }
        for (const direction of wanted) {
            // 用 accepting 而不是 available：后者只排序不过滤，
            // 让一个明确声明「不吃 url」的 agent 生成一条假设，等于让它去测一件它测不了的事。
            const ready = this.registry.accepting(direction, shape);
            if (ready.length === 0) {
                // 只在调用方**明确要求**这个方向时才报缺口。
                // 自动铺开八方向时报「web 工具吃不下二进制」，是拿显而易见的结论占版面——
                // 那种输出会淹掉真正的假设，读的人很快就学会跳过后面的内容。
                if (input.directions !== undefined) {
                    const all = this.registry.list(direction);
                    blockers.push(`${direction}：没有能吃 "${shape}" 形态的可用 agent（${all.length === 0 ? '未注册任何候选' : all.map((a) => `${a.id}${a.unavailable ? ':missing' : ''}`).join(', ')}）`);
                }
                continue;
            }
            // 已经查过且完整的方向，不再生成「存在弱点」这种假设。
            // 没有这一步，系统会一遍遍把同样的检查派出去——这正是实战里
            // 六轮全压在同一条路上的原因：没有任何东西记得「这条已经走过」。
            const cov = this.coverage?.of(input.target, [direction]);
            if (cov !== undefined && cov.state === 'covered') {
                skipped.push({ direction, reason: `已完整覆盖（${cov.verdict}），不再重复` });
                continue;
            }
            const lead = ready[0];
            const partialNote = cov !== undefined && cov.state === 'partial' ? `上次只做到部分覆盖（${cov.verdict}），这次补完` : '';
            hypotheses.push({
                id: nextId(),
                statement: `目标 "${clip(input.target)}" 在 ${direction} 方向存在可被 ${lead.id} 观测到的弱点`,
                falsifiableBy: `用 ${lead.id} 对该目标执行一次 ${direction} 检查；若输出中不含任何该工具定义的有效命中，则这条假设不成立`,
                direction,
                target: input.target,
                rationale: `${direction} 方向有可用 agent ${lead.id}（形态 ${shape} 适配）` +
                    (partialNote === '' ? '，且此前未对该目标留下完整证据' : `；${partialNote}`),
                priority: direction === 'web-pentest' || direction === 'mcp-security' ? 'high' : 'medium',
                origin: 'coverage-gap',
            });
        }
        // 2) 证据不足：只有一条独立路径的断言
        for (const c of claims) {
            if (c.status === 'verified')
                continue;
            if (c.evidenceCount > 0 && c.independentPaths < 2) {
                // 方向不能瞎猜：断言来自哪个方向没记下来时，按目标形态反查一个真能复核它的方向。
                // 之前这里默认 'web-pentest'，结果给一个二进制目标的断言挂上了 web 任务，
                // 派出去必然 no-fit——白占一条计划位，还误导了汇总。
                const direction = c.lastDirection ?? this.pickDirectionForShape(shape, wanted);
                if (direction === undefined) {
                    blockers.push(`断言「${clip(c.claim, 40)}」需要人工指定复核方向：没有方向能处理 "${shape}" 形态`);
                    continue;
                }
                const inferred = c.lastDirection === undefined;
                hypotheses.push({
                    id: nextId(),
                    statement: `断言「${clip(c.claim, 80)}」的证据来自单一方法，可能不成立`,
                    falsifiableBy: `换一个不同工具或不同入口复核该断言；若复核结果与现有证据矛盾，则原证据不可靠`,
                    direction,
                    target: c.lastTarget ?? input.target,
                    rationale: `现有 ${c.evidenceCount} 条证据只覆盖 ${c.independentPaths} 条独立路径，未达到确认门槛` +
                        (inferred ? `；方向由目标形态 "${shape}" 反查得出` : ''),
                    priority: 'high',
                    origin: 'weak-evidence',
                });
            }
        }
        // 3) 上次没定论：还有高适配度候选没试过
        const last = this.knowledge.lastDispatch?.();
        if (last !== undefined && last.stopReason === 'inconclusive') {
            const untried = (last.untried ?? []).filter((u) => u.fitness > 0);
            if (untried.length > 0) {
                hypotheses.push({
                    id: nextId(),
                    statement: `上一次 ${last.direction} 派活没有定论，换 ${untried[0].agent} 可能给出结论`,
                    falsifiableBy: `用 ${untried[0].agent} 对同一目标再跑一次；若仍然没有结构化结论，说明该形态下这批 agent 都判不了，需要换方法而不是换工具`,
                    direction: last.direction,
                    target: last.target,
                    rationale: `上次以 ${last.stopReason} 收手，仍有 ${untried.map((u) => `${u.agent}(fitness=${u.fitness})`).join(', ')} 未试`,
                    priority: 'medium',
                    origin: 'weak-evidence',
                });
            }
        }
        // 3.5) 资产驱动的下一步：已发现的服务本身指向该往哪打
        const openServices = (this.assets?.list({ kind: 'service' }) ?? []).filter((a) => a.seen['internal-ad'] === undefined);
        for (const svc of openServices.slice(0, 3)) {
            const port = svc.id.split(':').pop() ?? '';
            // 只看能直接推出方向的端口，不做通用端口字典——那会生成一堆没有依据的假设。
            const direction = port === '445' || port === '139' ? 'internal-ad'
                : port === '443' || port === '8443' ? 'crypto'
                    : port === '80' || port === '8080' || port === '8000' ? 'web-pentest'
                        : undefined;
            if (direction === undefined)
                continue;
            hypotheses.push({
                id: nextId(),
                statement: `资产 ${svc.id} 开放，需要针对该服务做 ${direction} 方向的检查`,
                falsifiableBy: `对 ${svc.id} 执行一次 ${direction} 检查；若该服务不接受任何探测或返回明确的拒绝，则这条假设不成立`,
                direction,
                target: svc.parent ?? svc.id,
                rationale: `上一轮扫描发现 ${svc.id} 开放，但还没有 ${direction} 方向的检查记录`,
                priority: 'high',
                origin: 'coverage-gap',
            });
        }
        // 4) 人工假设原样纳入
        for (const m of input.manual ?? []) {
            hypotheses.push({
                id: nextId(),
                statement: m.statement,
                falsifiableBy: m.falsifiableBy,
                direction: m.direction,
                target: input.target,
                rationale: '调用方显式提出',
                priority: m.priority ?? 'high',
                origin: 'manual',
            });
        }
        const understanding = claims.length === 0
            ? `尚未对该目标留下任何证据；识别为 ${shape} 形态，${wanted.length} 个方向里 ${hypotheses.length} 条假设可立即验证`
            : `已有 ${claims.length} 条断言（${claims.filter((c) => c.status === 'verified').length} 条确认），` +
                `识别为 ${shape} 形态，本次提出 ${hypotheses.length} 条待验证假设`;
        return {
            target: input.target,
            shape,
            understanding,
            hypotheses: sortHypotheses(hypotheses),
            blockers,
            covered: [...covered],
            skipped,
        };
    }
}
const PRIORITY_ORDER = { high: 0, medium: 1, low: 2 };
function sortHypotheses(list) {
    return [...list].sort((a, b) => PRIORITY_ORDER[a.priority] - PRIORITY_ORDER[b.priority]);
}
function clip(s, max = 60) {
    return s.length <= max ? s : `${s.slice(0, max - 3)}...`;
}
