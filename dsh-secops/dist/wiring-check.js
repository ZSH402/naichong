/**
 * 接线自检：启动时把「写了但没接上」喊出来。
 *
 * 真机上一轮抓到四个同类缺陷，全都是靠实跑才发现的：
 *   rea 没有 invocation            → 派活直接 refused
 *   strix 在目录不存在时写 config  → ENOENT
 *   ARTEX 少传 username            → 一直 401
 *   dirsearch 装进 venv 但不在 PATH → 工具调用失败
 *
 * 后两个是运行期环境问题，前两个是**纯静态可查的**——一个候选声明自己是 cli
 * 却没有 invocation，编译期就能发现。把这类检查放在启动时，比等第一次派活快得多，
 * 也不会让「以为注册了就可用」的判断混进 roster。
 */
/**
 * 检查一个候选的接线是否完整。纯函数。
 *
 * 判定只用声明本身，不看运行期状态——运行期的事 probe 管。
 */
export function checkCandidate(c) {
    const issues = [];
    const push = (level, code, detail) => {
        issues.push({ candidateId: c.id, level, code, detail });
    };
    if (c.kind === 'cli') {
        if (c.command === undefined || c.command.length === 0) {
            push('error', 'cli-without-command', '声明为 cli 却没有 command，probe 无从判断也不可执行');
        }
        if (c.invocation === undefined && c.requires === undefined) {
            // 这是 rea 那次的原型：注册了、probe 认为可用、派活时才 refused。
            push('error', 'missing-invocation', '没有 invocation 也没写 requires——能进 roster 但派不出去');
        }
    }
    if (c.kind === 'mcp') {
        if (c.probeCommand === undefined) {
            // mcp 候选自己没有 command，probe 默认查 command[0] 会判成「本层不驱动」。
            push('error', 'missing-probe-command', 'mcp 候选缺 probeCommand，可用性永远判不准');
        }
        // mcp 不需要 invocation：调用由 adapter 按候选 id 查绑定表，不经过 buildArgv。
        // 早期版本要求它有，是照搬 cli 的规则，结果把所有 mcp 候选都误判成接线错误。
    }
    if (c.kind === 'subagent' && c.provider === undefined) {
        push('warn', 'subagent-with-provider', '声明为 subagent 却没有 provider 名，无法定位后端');
    }
    if (c.verdict !== undefined && typeof c.verdict !== 'function') {
        push('error', 'verdict-without-capability', 'verdict 不是函数，判定能力不成立');
    }
    // 有 requires 但没有具体的可执行说明，人看了也不知道该装什么。
    if (c.requires !== undefined && c.requires.trim().length < 8) {
        push('warn', 'undocumented-requirement', `requires 太短，说不清要补什么：「${c.requires}」`);
    }
    return issues;
}
export function checkWiring(candidates) {
    const issues = [];
    for (const c of candidates)
        issues.push(...checkCandidate(c));
    const errors = issues.filter((i) => i.level === 'error').length;
    const warnings = issues.length - errors;
    return {
        checked: candidates.length,
        issues,
        errors,
        warnings,
        summary: issues.length === 0
            ? `${String(candidates.length)} 个候选接线完整`
            : `${String(candidates.length)} 个候选中 ${String(errors)} 个接线错误、${String(warnings)} 个提醒`,
    };
}
/** 启动时把问题打到日志里。error 级别说明该候选现在派不出去。 */
export function reportWiring(wiring, logger) {
    if (wiring.issues.length === 0) {
        logger?.info(`secops/wiring: ${wiring.summary}`);
        return;
    }
    for (const issue of wiring.issues) {
        const line = `secops/wiring/${issue.code}: ${issue.candidateId} — ${issue.detail}`;
        if (issue.level === 'error')
            logger?.warn(line);
        else
            logger?.info(line);
    }
    logger?.info(`secops/wiring: ${wiring.summary}`);
}
