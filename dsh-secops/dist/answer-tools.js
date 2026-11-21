/**
 * 答案闸门：声称找到答案，必须挂一条已被证据确认的 claim。
 *
 * 这一层存在的理由很具体：捷径最危险的后果不是浪费时间，是**它会成功**。
 * 一个 `grep` 出来的字符串如果恰好长得像答案，模型会直接报出去，
 * 而那个答案没有任何利用或推导撑着。事后你没法区分「真解出来的」和
 * 「碰巧搜到的」——整个系统的可信度就毁在这上面。
 *
 * 所以把「报告答案」做成一个有前置条件的动作：
 *   - 有 claim，且状态是 confirmed
 *   - 独立路径 >= 阈值（同一件事做两遍不算）
 *   - 证据通过了锚点校验（claim_evidence 已经卡过一次）
 *
 * 不满足就明确拒绝，并告诉它还缺什么。**拒绝时不说答案对不对**——
 * 我们说不了，也不该假装能说。
 */
import { CONFIRM_THRESHOLD, verificationOf } from "./provenance.js";
const ANSWER_SCHEMA = {
    type: 'object',
    properties: {
        accepted: { type: 'boolean', description: 'Whether the answer is backed by confirmed evidence.' },
        answer: { type: 'string' },
        claim: { type: 'string' },
        status: { type: 'string' },
        independent_paths: { type: 'number' },
        evidence_count: { type: 'number' },
        missing: {
            type: 'array',
            items: { type: 'string' },
            description: 'What is still required before this answer can be treated as established.',
        },
        warnings: {
            type: 'array',
            items: { type: 'string' },
            description: 'Weakened but not blocking — e.g. a proof with no baseline comparison.',
        },
        verdict: { type: 'string', description: 'established | unverified' },
        verification: {
            type: 'string',
            description: 'none | reproducible (replay matched) | calibrated (replay + detector control sample) | cross-checked (replay + baseline comparison)',
        },
    },
    required: ['accepted', 'answer', 'verdict'],
};
/**
 * 判断一条答案能不能算「已确认」。纯函数，可单测。
 *
 * 注意它只说形式上够不够，不说内容对不对——后者需要外部裁决者。
 * 这条边界必须守住：一个只会说「形式上够了」的闸门是诚实的，
 * 一个声称能判断对错的闸门是在骗人。
 */
export function judgeAnswer(claim, options = {}) {
    const threshold = options.threshold ?? CONFIRM_THRESHOLD;
    if (claim === undefined) {
        return {
            accepted: false,
            verdict: 'unverified',
            missing: ['no claim was asserted — an answer without a claim is a guess'],
            warnings: [],
        };
    }
    const missing = [];
    if (claim.status !== 'confirmed') {
        missing.push(`claim status is "${claim.status}", needs "confirmed"`);
    }
    if (claim.independentPaths < threshold) {
        missing.push(`${String(claim.independentPaths)} independent path(s), needs ${String(threshold)} — the same check run twice is still one path`);
    }
    if (claim.evidence.length === 0) {
        missing.push('claim carries no evidence');
    }
    // 对照缺失只警告不拒绝：RCE 回显、服务崩溃这类漏洞没有「正常情况」可比。
    const warnings = [];
    const hasProof = claim.evidence.some((e) => e.role !== 'baseline' && e.role !== 'control');
    const hasBaseline = claim.evidence.some((e) => e.role === 'baseline');
    const hasControl = claim.evidence.some((e) => e.role === 'control');
    if (hasProof && !hasBaseline) {
        warnings.push(hasControl
            ? 'no target baseline — the detector itself was calibrated against a known sample (role=control), ' +
                'but nothing shows what this target looks like under normal conditions. ' +
                'For classes without a normal state (binary hardening, TLS config) that is the ceiling; say so explicitly.'
            : 'no baseline evidence — a reviewer cannot tell this from a response the endpoint always returns; ' +
                'add a normal-input run as role=baseline (or role=control if the class has no normal state)');
    }
    // 验证强度要么由 caller 给出（来自真实 claim），要么按「没有重跑记录」处理。
    const verification = options.verification ?? 'none';
    if (verification === 'none' && missing.length === 0) {
        warnings.push('no replay record — the evidence was accepted but never re-run; ' +
            'claim_verify replays it and compares a strict digest, which is what separates "reproducible" from "plausible"');
    }
    return {
        accepted: missing.length === 0,
        verdict: missing.length === 0 ? 'established' : 'unverified',
        verification,
        missing,
        warnings,
    };
}
export function answerTools(store) {
    return [
        {
            name: 'submit_answer',
            description: 'Report a final answer (a flag, a recovered secret, a confirmed exploit result). It only counts if it is backed by a ' +
                'claim that reached "confirmed" — meaning at least two independent evidence paths passed the anchor check. ' +
                'Use this instead of asserting an answer in prose: prose cannot be audited, and an unverified string is ' +
                'indistinguishable from a lucky guess. If it is rejected, the tool tells you exactly what is missing.',
            parameters: {
                type: 'object',
                properties: {
                    answer: { type: 'string', description: 'The answer itself.' },
                    claim_id: { type: 'string', description: 'The confirmed claim that establishes it.' },
                },
                required: ['answer', 'claim_id'],
            },
            output: {
                schema: ANSWER_SCHEMA,
                render: (_a, v) => {
                    const r = v;
                    const head = r.accepted === true
                        ? `accepted — verdict=${String(r.verdict)}, claim "${String(r.claim ?? '')}" is confirmed with ${String(r.independent_paths ?? 0)} independent path(s)`
                        : `rejected — verdict=${String(r.verdict)}`;
                    const missing = (r.missing ?? []);
                    const lines = [head];
                    for (const m of missing)
                        lines.push(`  missing: ${m}`);
                    for (const w of (r.warnings ?? []))
                        lines.push(`  warning: ${w}`);
                    if (r.accepted !== true) {
                        lines.push('  这条答案现在只是一条未验证的推测。把缺口补上再来，或者明确按推测报告它。');
                    }
                    return [{ type: 'text', text: lines.join('\n') }];
                },
            },
            async execute(args) {
                const answer = String(args.answer ?? '');
                const claimId = String(args.claim_id ?? '');
                const claim = store.get(claimId);
                const verdict = judgeAnswer(claim, claim === undefined ? {} : { verification: verificationOf(claim) });
                return {
                    accepted: verdict.accepted,
                    answer,
                    ...(claim === undefined ? {} : { claim: claim.claim, status: claim.status }),
                    ...(claim === undefined ? {} : { independent_paths: claim.independentPaths, evidence_count: claim.evidence.length }),
                    ...(claim === undefined ? {} : { status: claim.status }),
                    verification: verdict.verification ?? 'none',
                    missing: [...verdict.missing],
                    warnings: [...verdict.warnings],
                    verdict: verdict.verdict,
                };
            },
        },
    ];
}
export function installAnswerTools(ctx, store) {
    for (const tool of answerTools(store))
        ctx.tools.register(tool);
}
