/**
 * detector_check：跑检测器对照，并把结果记进账本。
 *
 * 存在的理由：一台只会报「目标不安全」的机器是不可信的。
 * 对二进制加固、TLS 配置这类没有「目标正常态」可比的检查，
 * 唯一能说明结论可信的办法是拿已知样本校准工具本身。
 * 这个工具把校准变成一次显式动作，而不是指望模型自己想起来。
 */
import { runAllControls } from "./control-check.js";
const DETECTOR_SCHEMA = {
    type: 'object',
    properties: {
        checked: { type: 'number', description: 'How many detectors were calibrated.' },
        trusted: { type: 'number', description: 'Detectors whose control sample came out clean.' },
        results: {
            type: 'array',
            items: {
                type: 'object',
                properties: {
                    agent_id: { type: 'string' },
                    verdict: { type: 'string', description: 'trusted | untrusted | error' },
                    target: { type: 'string' },
                    observed: { type: 'string' },
                    reason: { type: 'string' },
                    ref: {
                        type: 'string',
                        description: 'Pass this as ref to claim_evidence with role=control to attach the calibration.',
                    },
                },
                required: ['agent_id', 'verdict', 'ref'],
            },
        },
        unusable: {
            type: 'array',
            items: { type: 'string' },
            description: 'Detectors whose verdict cannot be used on the target; their conclusions must be discarded.',
        },
    },
    required: ['checked', 'trusted', 'results'],
};
/**
 * 给一次对照结果造一个稳定的引用串。
 *
 * 用它当 claim_evidence 的 ref：既能被人读懂（哪个工具、看到什么），
 * 也能被 claim_evidence 反过来解析出 agentId 去查账本。
 */
export function controlRef(run) {
    return `control:${run.agentId}@${run.verdict}:${run.observed.replace(/\s+/g, ',')}`;
}
export function controlTools(registry, ledger) {
    return [
        {
            name: 'detector_check',
            description: 'Calibrate the detectors themselves. Runs each detector that declares a control sample against a target whose ' +
                'answer is already known, and checks the detector reports it correctly. Use this BEFORE trusting any ' +
                'hardening / TLS / binary conclusion: for those classes there is no "normal state" of the target to compare ' +
                'against, so "the tool said so" is the only thing a verdict rests on. A detector that reports problems on a ' +
                'known-clean sample is broken, and every conclusion it produced must be discarded, not reported. ' +
                'Attach a trusted run to a claim as role=control to reach verification "calibrated".',
            parameters: {
                type: 'object',
                properties: {
                    agent_id: {
                        type: 'string',
                        description: 'Calibrate only this detector. Omit to calibrate every detector that declares a control.',
                    },
                },
            },
            output: {
                schema: DETECTOR_SCHEMA,
                render: (_a, v) => {
                    const r = v;
                    const lines = [`calibrated ${String(r.results.length)} detector(s)`];
                    for (const x of r.results) {
                        lines.push(`  ${x.verdict === 'trusted' ? 'OK  ' : 'BAD '} ${x.agent_id} — ${x.observed}`);
                        lines.push(`       ${x.reason}`);
                        lines.push(`       ref=${x.ref}`);
                    }
                    if (r.unusable.length > 0) {
                        lines.push(`  这些检测器在对照样本上就报错，它对目标的结论一律不能采信：${r.unusable.join(', ')}`);
                        lines.push('  补救方向：换检测器（同方向的其他候选）或换检测方法，而不是把它的输出写进报告。');
                    }
                    return [{ type: 'text', text: lines.join('\n') }];
                },
            },
            execute: async (args) => {
                const only = typeof args.agent_id === 'string' && args.agent_id !== '' ? [args.agent_id] : undefined;
                const runs = await runAllControls(registry, only === undefined ? {} : { only });
                ledger.recordAll(runs);
                const results = runs.map((r) => ({
                    agent_id: r.agentId,
                    verdict: r.verdict,
                    target: r.target,
                    observed: r.observed,
                    reason: r.reason,
                    ref: controlRef(r),
                }));
                return {
                    checked: results.length,
                    trusted: results.filter((r) => r.verdict === 'trusted').length,
                    results,
                    unusable: runs.filter((r) => r.verdict !== 'trusted').map((r) => r.agentId),
                };
            },
        },
    ];
}
export function installControlTools(ctx, registry, ledger) {
    for (const tool of controlTools(registry, ledger))
        ctx.tools.register(tool);
}
