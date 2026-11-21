/**
 * 外部指导注入：让人能在会话跑着的时候递一句话进去。
 *
 * 实战里最痛的一件事：六轮分析，每次想推它一把都得 kill 掉重开——上下文全丢，
 * 前面几十分钟的推理作废。人在环路里的价值本来是「在关键处点一下」，
 * 而当时的实现只支持「从头再来」。
 *
 * 设计刻意做到最笨：**一个文件**。
 *   echo '换个方法，别在枚举上耗' >> <workspace>/.guidance
 * 下一轮 pre-step 就会把这句话注入进去，然后清空。
 *
 * 为什么不做成 RPC / 队列 / socket：那些都要维护连接和状态，而这个东西的使用频率
 * 是「人工偶发」。用文件，断了不丢、重启还在、任何工具都能写。
 *
 * 消费是原子的：先 rename 再读。两个进程同时写同一个文件会互相覆盖，
 * 但「人递一句话」这个场景不存在并发写，而 rename 保证了不会读到半个文件。
 */
import fs from 'node:fs';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
export const GUIDANCE_FILENAME = '.guidance';
function userMessage(text) {
    return {
        id: randomUUID(),
        role: 'user',
        source: { kind: 'user' },
        content: [{ type: 'text', text }],
    };
}
/**
 * 取出待注入的指导并清空。
 *
 * 用 rename 到临时名再读：读到的要么是完整内容，要么什么都没有。
 * 直接 read + truncate 会在两者之间留一个窗口，而那个窗口里崩溃会丢消息。
 */
export function consumeGuidance(filePath) {
    if (!fs.existsSync(filePath))
        return [];
    const staging = `${filePath}.${String(process.pid)}.${String(Date.now())}`;
    try {
        fs.renameSync(filePath, staging);
    }
    catch {
        return [];
    }
    try {
        const raw = fs.readFileSync(staging, 'utf8');
        return raw
            .split('\n')
            .map((l) => l.trim())
            .filter((l) => l.length > 0 && !l.startsWith('#'));
    }
    finally {
        try {
            fs.unlinkSync(staging);
        }
        catch {
            /* 删不掉也不影响已经读到的内容 */
        }
    }
}
/** 排队一条指导（给人和测试用，模型看不到这个函数）。 */
export function pushGuidance(filePath, text) {
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    fs.appendFileSync(filePath, `${text.trim()}\n`, 'utf8');
}
export function installGuidanceGuard(ctx, options) {
    const { filePath, logger } = options;
    ctx.on('agent/pre-step', async (payload, next) => {
        const decision = await next();
        if (decision.kind !== 'enter')
            return decision;
        const lines = consumeGuidance(filePath);
        if (lines.length === 0)
            return decision;
        logger?.info(`secops/guidance: 注入 ${String(lines.length)} 条外部指导`);
        return {
            kind: 'enter',
            messages: [
                ...decision.messages,
                userMessage(`[guidance] 有人在你运行期间递进来这几句：\n\n${lines.map((l) => `- ${l}`).join('\n')}\n\n` +
                    `按这个调整当前的做法，不要重新开始——你已经掌握的东西仍然有效。`),
            ],
        };
    });
}
