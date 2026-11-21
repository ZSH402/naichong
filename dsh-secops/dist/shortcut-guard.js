/**
 * 捷径拦截。
 *
 * 真实观测：第六轮里出现了 `grep -ril 'tpctf|flag'`——在靶场文件里搜答案字符串。
 * 前几轮还有翻历史产物找线索的行为。
 *
 * 危害不是浪费时间，是**它可能成功**：一旦某个文件里恰好有答案形态的字符串，
 * 模型会直接报出来，而那个答案没有任何利用或推导作为支撑。这类「成功」比失败更糟，
 * 因为它会污染整个系统的可信度——你没法区分哪次是真解出来的。
 *
 * 三层处理，逐级加重：
 *   一、识别并计数（放行 + 提醒）
 *   二、超过阈值就拒绝（不只是提醒，因为提醒会被绕过：换 grep → 换 find → 换 strings）
 *   三、答案闸门：声称找到答案必须挂一条 confirmed 的 claim（见 answer-tools）
 *
 * 为什么不一上来就拒绝：真实渗透里搜关键字是合法且常见的枚举手段
 * （找 .env、找 backup、找密钥）。第一次就拦会误伤正常侦察。
 * 但同一个 profile 里搜「flag/答案」超过两次，那不是侦察，是在找捷径。
 */
import { randomUUID } from 'node:crypto';
/**
 * 默认模式针对「直接搜答案」。
 *
 * 刻意不拦 `grep password`、`find -name '*.env'` 这类——那是正常枚举。
 * 只拦明确以答案本身为目标的搜索。
 */
export const DEFAULT_SHORTCUT_PATTERNS = [
    {
        id: 'grep-answer',
        // 搜索工具 + 独立的答案词。`\b` 天然排除 flag_bin / flag_correct 这类复合词
        // （g 和 _ 都是 word 字符，之间没有边界），所以正常读题面不会被误伤。
        re: /\b(grep|rg|ag|ack)\b[^\n]*\b(flag|answer|solution)\b/i,
        why: '在文件里搜答案字符串不等于拿到答案——真实题目里 flag 不会以明文躺在文件里',
    },
    {
        id: 'find-answer-file',
        re: /\b(find|locate)\b[^\n]*-name\b[^\n]*(flag|answer)/i,
        why: '按文件名找 flag 只会找到占位文件或别人的产物',
    },
    {
        id: 'strings-answer',
        re: /\bstrings\b[^\n]*\|[^\n]*\b(grep|rg)\b[^\n]*\b(flag|answer)\b/i,
        why: '把二进制里的可打印串当答案，通常只是拿到题目里的干扰字符串',
    },
    {
        id: 'cat-answer-file',
        // 从「提醒两次」升为「第一次就拒绝」：读一个叫 flag 的文件在任何场景下都不是
        // 枚举，是绕到题目外面去拿答案。放行一次，拿到的字符串就没有任何推导支撑。
        re: /\b(cat|less|head|tail|xxd|hexdump|od|strings|base64)\b[^\n]*\/?(flag|answer)(\.txt)?\b/i,
        why: '本地直接读一个叫 flag 的文件不是解题。真实靶场里那个文件在攻击者拿不到的文件系统上，' +
            '只能通过网络打服务、建立利用链之后由靶机自己读出来',
        severity: 'deny',
    },
    {
        id: 'hunt-prior-artifacts',
        re: /\b(find|grep|rg|ls)\b[^\n]*\b(workspace|work\/|previous|prior|old)\b[^\n]*\b(flag|answer|result)\b/i,
        why: '在历史产物里翻答案，等于让别人替你解题；那些产物本身也没有结论',
    },
    // ── 下面几条是 deny：绕到题目外面拿答案，第一次就拦 ──────────────
    {
        id: 'read-target-flag',
        // 本地读一个叫 flag 的文件。`cat /flag`、`head -c 100 /flag`、`xxd /root/.../flag`
        re: /(?:^|[\s;|&(`])(?:cat|head|tail|less|more|xxd|hexdump|od|strings|base64|cp|dd|tee)\b[^\n]*[\s'"]\/?(?:root\/|tmp\/|opt\/|srv\/)?flag\b/i,
        why: '本地读 flag 文件不是解题——真实靶场里那个文件在攻击者拿不到的文件系统上。' +
            '这里的 flag 只能通过网络打服务、建立利用链后由靶机自己读出来',
        severity: 'deny',
    },
    {
        id: 'run-setuid-reader',
        // 直接执行靶机的 setuid 读 flag 程序
        re: /(?:^|[\s;|&(`])\/?readflag\b/i,
        why: '/readflag 是靶机上的 setuid 程序，正常路径是通过漏洞在靶机内部拿到执行权后调用它。' +
            '在宿主机上直接跑它，跳过的是整道题',
        severity: 'deny',
    },
    {
        id: 'container-escape-to-target',
        // 用容器命令绕过隔离，进到靶机里读文件
        re: /\bdocker\s+(?:exec|cp|run|start|attach|export|save)\b[^\n]*\b(?:ipvm|target|challenge)\b/i,
        why: '容器边界就是这道题的信任边界的一部分。用 docker exec/cp 进去拿文件，' +
            '等于从后门走进靶场——任何在那之后写下的结论都没有利用过程支撑',
        severity: 'deny',
    },
];
export const DEFAULT_SHORTCUT_POLICY = {
    warnTimes: 2,
    blockAfter: 2,
    patterns: DEFAULT_SHORTCUT_PATTERNS,
};
/** 检查一条命令是否属于「搜答案」。纯函数，好测。 */
export function detectShortcut(command, patterns = DEFAULT_SHORTCUT_PATTERNS) {
    for (const p of patterns) {
        if (p.re.test(command)) {
            return { patternId: p.id, why: p.why, command: command.slice(0, 200) };
        }
    }
    return undefined;
}
export class ShortcutGuard {
    policy;
    hits = [];
    blocks = 0;
    constructor(policy = {}) {
        this.policy = { ...DEFAULT_SHORTCUT_POLICY, ...policy };
    }
    /** 判定这次调用该怎么处理。 */
    inspect(command) {
        const hit = detectShortcut(command, this.policy.patterns);
        if (hit === undefined)
            return { action: 'allow', count: this.hits.length };
        this.hits.push(hit);
        const count = this.hits.length;
        // severity=deny 的不走「提醒两次」：绕到题目外面拿答案没有第一次可言。
        const forced = this.policy.patterns.find((p) => p.id === hit.patternId)?.severity === 'deny';
        if (forced || count > this.policy.warnTimes) {
            this.blocks += 1;
            return { action: 'deny', hit, count };
        }
        return { action: 'warn', hit, count };
    }
    stats() {
        const byPattern = {};
        for (const h of this.hits)
            byPattern[h.patternId] = (byPattern[h.patternId] ?? 0) + 1;
        return { hits: this.hits.length, blocks: this.blocks, byPattern };
    }
}
export function shortcutWarning(hit, count, willBlock) {
    return (`[secops/shortcut] 你在搜索答案，而不是推导它（第 ${String(count)} 次）。\n\n` +
        `为什么这条路不成立：${hit.why}。\n\n` +
        `更重要的是：即使你搜到一个看起来像答案的字符串，你也无法证明它——` +
        `没有利用过程、没有可复现的推导，它和随便猜一个没有区别。这类「发现」在本系统里` +
        `无法结案（提交答案需要一条 confirmed 的 claim）。\n\n` +
        (willBlock
            ? `再出现一次，这条命令会被直接拒绝。把你现在手上的线索写成假设，去攻击它的可证伪点。`
            : `把你现在手上的线索写成假设（claim_assert + falsifier），去攻击它的可证伪点。`));
}
function userMessage(text) {
    return {
        id: randomUUID(),
        role: 'user',
        source: { kind: 'user' },
        content: [{ type: 'text', text }],
    };
}
/** 挂到工具执行路径上：警告走 pre-step，拒绝走 pre-execute。 */
export function installShortcutGuard(ctx, options = {}) {
    const guard = new ShortcutGuard(options.policy);
    // 每个 agent 各留一份待投递的提醒：拒绝发生在 pre-execute，投递要在 pre-step。
    const pending = new Map();
    ctx.on('tools/pre-execute', async (exec, next) => {
        const args = exec.arguments;
        const command = typeof args?.command === 'string' ? args.command : undefined;
        if (command === undefined)
            return next();
        const verdict = guard.inspect(command);
        if (verdict.action === 'allow')
            return next();
        const agentId = 'default';
        if (verdict.action === 'deny') {
            options.logger?.warn(`secops/shortcut: 拒绝第 ${String(verdict.count)} 次搜答案 — ${verdict.hit?.patternId ?? '?'}`);
            // 拒绝时也要把说明递进去，否则模型只看到一句 deny，会换个写法再来。
            pending.set(agentId, shortcutWarning(verdict.hit, verdict.count, true));
            return { kind: 'deny', reason: `[secops/shortcut] 搜答案的第 ${String(verdict.count)} 次，已拒绝：${verdict.hit?.why ?? ''}` };
        }
        options.logger?.info(`secops/shortcut: 警告第 ${String(verdict.count)} 次搜答案 — ${verdict.hit?.patternId ?? '?'}`);
        pending.set(agentId, shortcutWarning(verdict.hit, verdict.count, false));
        return next();
    });
    ctx.on('agent/pre-step', async (payload, next) => {
        const decision = await next();
        if (decision.kind !== 'enter')
            return decision;
        const agentId = payload.agent?.id ?? 'default';
        const note = pending.get(agentId) ?? pending.get('default');
        if (note === undefined)
            return decision;
        pending.delete(agentId);
        pending.delete('default');
        return { kind: 'enter', messages: [...decision.messages, userMessage(note)] };
    });
    return guard;
}
