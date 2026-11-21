/**
 * CyberStrikeAI MCP 工具的绑定：候选 id → 工具名 + 参数映射 + 判据。
 *
 * 为什么单独成文件：这份映射原来在生产入口（index.ts）和验收脚本
 * （test/each-agent.mjs）各写了一份，结果生产的 ghidra 传 `target`、
 * 测试传 `binary`——**两边都错**，而且错法不同，谁也没发现。
 * 参数名和判据是「这张牌怎么用」的知识，只能有一份。
 */
/** 从 URL 或 host:port 里取主机名，给 nmap 这类只要 host 的工具用。 */
export function hostOf(target) {
    try {
        if (/^[a-z][a-z0-9+.-]*:\/\//i.test(target))
            return new URL(target).hostname;
    }
    catch {
        /* 不是合法 URL，按 host:port 处理 */
    }
    return target.split(':')[0] ?? target;
}
/**
 * 默认绑定。
 *
 * 判据只给三类：
 *   - 能确定「有/没有漏洞」的（sqlmap、nmap）
 *   - 能确定「做完了」的（ghidra）
 *   - 其余留空 —— 没有判据就报 inconclusive，比编一个结论诚实。
 *
 * 参数名一律以工具自身 schema 为准（`tools/*.yaml` 里的 name/required）。
 * nmap 的 `target`、ghidra 的 `binary`、sqlmap 的 `url` 都不是同一个词，
 * 靠记忆写必错，所以这里每条都注明来源。
 */
export function defaultMcpBindings() {
    return new Map([
        [
            'cyberstrike-sqlmap',
            {
                tool: 'sqlmap',
                args: (c) => ({ url: c.target, batch: 'true', additional_args: '--level=3 --risk=2' }),
                verdict: (r) => {
                    // 「参数不可注入」是这个工具能给出的**确定结论**，不是「没结论」。
                    // 判成 undefined 会让每一轮都把同一个已排除的方向重派一次。
                    if (/all tested parameters do not appear to be injectable|do not appear to be injectable/i.test(r.text)) {
                        return { found: false, class: 'clean', detail: 'sqlmap: tested parameters not injectable' };
                    }
                    const m = /Parameter:\s*(\S+)\s*\(([^)]*)\)/i.exec(r.text);
                    const explicit = /is vulnerable|sqlmap identified the following injection point/i.test(r.text);
                    // sqlmap 确认注入点时的实际排版是 `Parameter: id (GET)` 紧跟 `Type: boolean-based blind`。
                    // 只看 `injectable` 这个词会漏报——它出现在测试过程的措辞里，不一定出现在结论块。
                    // 两行同时出现才是「已确认」：单有 Parameter 可能只是它列参数。
                    const confirmedBlock = m !== null && /Type:\s*\S+/i.test(r.text);
                    // 只有 `Parameter:` 没有 `Type:`（也没有明确的 vulnerable 措辞）= 信息不足，
                    // 不能报 found:false——那等于替 sqlmap 宣布「这个参数没问题」。如实说不知道。
                    if (!explicit && !confirmedBlock)
                        return undefined;
                    return {
                        found: true,
                        detail: m === null ? 'injection point reported' : `${m[1]} (${m[2]})`,
                        class: 'finding',
                    };
                },
            },
        ],
        [
            'cyberstrike-dirsearch',
            {
                tool: 'dirsearch',
                args: (c) => ({ url: c.target, recursive: 'false', threads: '20' }),
                // 目录发现给的是**暴露面**，不是漏洞：一个能访问的路径本身不构成缺陷。
                // 所以报 found=false 且不设 class（设 clean 等于宣称「这个站没有隐藏路径」，
                // 而 dirsearch 只是没猜中字典里那些）。命中的路径数量与样例放 detail 里，
                // 让上层能决定要不要顺着某条路径继续——这比 inconclusive 有用得多。
                verdict: (r) => {
                    const hits = [...r.text.matchAll(/^\s*(?:\[[^\]]*\]\s*)?(\d{3})\s+-\s+\S+\s+-\s+(\S+)/gm)];
                    if (hits.length === 0)
                        return undefined;
                    const sample = hits.slice(0, 5).map((m) => `${m[1]} ${m[2]}`).join(', ');
                    return { found: false, detail: `${String(hits.length)} path(s) discovered (${sample})` };
                },
            },
        ],
        [
            'cyberstrike-nmap',
            {
                tool: 'nmap',
                args: (c) => ({ target: hostOf(c.target), timing: '4' }),
                verdict: (r) => {
                    const open = [...r.text.matchAll(/^(\d+\/tcp)\s+open\s+(\S+)/gm)];
                    if (open.length === 0)
                        return undefined;
                    return { found: true, detail: open.slice(0, 6).map((m) => `${m[1]} ${m[2]}`).join(', ') };
                },
            },
        ],
        [
            'cyberstrike-ghidra',
            {
                tool: 'ghidra',
                // 参数名必须是 `binary`（schema 里 required: binary）。写 `target` 会直接
                // 报「缺少必需的参数」；`analysis` 这个字段 schema 里不存在，传了无效。
                // project_name 每次唯一：同名项目里重复导入同一个文件会被 Ghidra 拒掉。
                args: (c) => ({ binary: c.target, project_name: `cs_${String(Date.now())}` }),
                // import + 自动分析，产出是分析日志，**没有安全判定**。
                // 只报「分析做完了没有」，不设 class。
                verdict: (r) => {
                    if (!/REPORT:\s*Import succeeded/i.test(r.text))
                        return undefined;
                    const analysis = /REPORT:\s*Analysis succeeded/i.test(r.text) ? 'analysis succeeded' : 'import only';
                    return { found: false, detail: `ghidra headless: ${analysis} (no security verdict)` };
                },
            },
        ],
    ]);
}
