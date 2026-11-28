/**
 * 两道 guard。都是同步的 —— ctx.tools.guard() 的签名是
 * `(exec: Readonly<ToolExecution>) => string | undefined`，
 * 返回非空字符串即拒绝，且单调：没有任何 guard 能 force-allow 另一个 guard 的拒绝。
 *
 * 因此这两道闸的生效不依赖插件加载顺序，也不依赖任何提示词。
 */
/**
 * 从一次工具调用里尽可能提取目标主机。
 *
 * 这是一次**静态文本提取**，不是解析器：guard 是同步的，不能做 DNS 解析、
 * 不能跟随重定向、不能看实际连接地址。它的价值是拦住"明显越界"的调用，
 * 真正的强制必须在网络层（SandboxProvider 的 netns/egress proxy）。
 *
 * 解析不出来时返回空数组 —— 调用放行，但由 budget guard 的计数兜底，
 * 并且 extractTargets 的保守性要在使用文档里写清。
 */
/**
 * 从参数里提取可能的出站目标。
 *
 * ⚠️ 旧实现只认 `http://` / `https://` 开头的 URL，注释理由是"裸域名与 IP 误判率太高"。
 * 代价是闸被大面积绕过——下面这几种都不会被提取到，因此直接放行：
 *
 *     curl evil.com:8080/x        # 省略 scheme
 *     nmap -sV 10.0.0.5           # 纯 IP
 *     nc 1.2.3.4 22               # IP + 端口分列
 *     sqlmap -u target.internal   # 裸主机名
 *
 * 对安全控制器来说，"误判率"的代价是不对称的：误判为出站只是多拒一次，
 * 漏判是整条边界失守。所以这里改成宁可多提取。
 *
 * 但也不能无脑匹配 —— 对 IPv4 做了段数/取值校验，对域名要求存在已知 TLD，
 * 避免把 `文件.tar.gz`、`v1.2.3.4` 这类版本号当成目标。
 */
const IPV4 = /\b((?:\d{1,3}\.){3}\d{1,3})\b/g;
const HOST_PORT = /\b([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+):(\d{1,5})\b/gi;
/**
 * IPv6 字面量（含方括号与压缩形式）。
 *
 * 早先只认 IPv4 与域名，`https://[::1]/x` 这类目标直接漏过范围检查——
 * 而回环/内网 IPv6 恰恰是 SSRF 和本地服务的常见入口。
 */
const IPV6_LITERAL = /\[([0-9a-fA-F:]{2,45})\]/g
    .source;
// TLD 白名单。除了公网常见后缀，必须包含**内网专用后缀**——
// 真实渗透目标里 .corp / .lan / .svc / .intranet / .office 比 .com 更常见，
// 漏掉它们等于范围闸对内网目标失效（而内网恰恰是最需要闸的地方）。
// .cluster.local 由 `local` 覆盖（正则匹配最后一个标签）。
const BARE_DOMAIN = /\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|cn|dev|local|example|test|internal|cloud|app|site|xyz|top|info|biz|me|co|ai|edu|gov|mil|int|corp|lan|svc|intranet|office|home|arpa|onion))\b/gi;
function validIpv4(v) {
    const parts = v.split('.');
    if (parts.length !== 4)
        return false;
    return parts.every((p) => {
        const n = Number(p);
        return Number.isInteger(n) && n >= 0 && n <= 255 && String(n) === p;
    });
}
export function extractTargets(toolName, args) {
    if (typeof args !== 'object' || args === null)
        return [];
    const record = args;
    const hosts = new Set();
    const add = (raw) => {
        if (raw === undefined)
            return;
        const h = raw.toLowerCase().replace(/^\[|\]$/g, '');
        if (h.length > 0)
            hosts.add(h);
    };
    /** 从任意文本扫目标：URL / 裸 IP / host:port / 裸域名，四类都收。 */
    const scan = (value) => {
        if (typeof value !== 'string' || value.length === 0)
            return;
        // 1) 完整 URL
        for (const m of value.matchAll(/https?:\/\/([^/\s:'"\]]+)/gi))
            add(m[1]);
        // 2) host:port（含域名带端口、IPv4 带端口）
        for (const m of value.matchAll(HOST_PORT))
            add(m[1]);
        // 2b) IPv6 字面量：`[::1]` / `[2001:db8::1]`
        for (const m of value.matchAll(new RegExp(IPV6_LITERAL, 'g'))) {
            const v = m[1];
            if (v !== undefined && v.includes(':'))
                add(v.toLowerCase());
        }
        // 3) 裸 IPv4（校验取值，排除 1.2.3.4 这类版本号误伤：
        //    版本号通常出现在 `v1.2.3` 这种紧邻字母的位置，用边界判断已能过滤大半）
        for (const m of value.matchAll(IPV4)) {
            if (validIpv4(m[1] ?? ''))
                add(m[1]);
        }
        // 4) 裸域名（要求已知 TLD，避免把文件名当域名）
        for (const m of value.matchAll(BARE_DOMAIN))
            add(m[1]);
    };
    // URL 形态的参数：web_fetch / web_search / 各类 fetch 工具。
    for (const key of ['url', 'uri', 'endpoint', 'target', 'host', 'hostname'])
        scan(record[key]);
    // 命令类工具：命令文本里的一切目标。
    for (const key of ['command', 'cmd', 'script', 'args', 'argv']) {
        const value = record[key];
        if (Array.isArray(value))
            value.forEach(scan);
        else
            scan(value);
    }
    void toolName;
    return [...hosts];
}
export function installScopeGuard(ctx, config) {
    // —— 显式关闭：允许，但要说清楚 ——
    // 这是唯一的"不设防"入口，且必须由配置显式声明。默认走不到这里。
    if (config.scopeMode === 'open') {
        ctx.logger.warn('secops: scopeMode="open" — 范围闸已关闭。此模式下不会拦截任何越界目标，' +
            '仅应在完全隔离的实验环境使用。');
        return;
    }
    // —— 默认路径：fail-closed ——
    // 未配置 allowedHosts 时不再"装个空闸然后放行"，而是装一个**什么都拒绝**的闸。
    // 理由：安全控制的默认必须是关。忘配是最常见的情况，而忘配不该等于不设防。
    const allowed = new Set(config.allowedHosts);
    const unconfigured = allowed.size === 0;
    if (unconfigured) {
        ctx.logger.warn('secops: allowedHosts 为空且 scopeMode="enforce" —— 所有网络出站动作都会被拒绝。' +
            '请在配置里列出授权目标（allowedHosts），或在隔离实验环境中显式设置 scopeMode="open"。');
    }
    const guard = (exec) => {
        // 只对可能在网络上出站的工具做判断；文件类工具由 workspace 沙箱管。
        const targets = extractTargets(exec.name, exec.arguments);
        // 未配置范围时，任何可识别的出站目标都拒绝。空数组不经过这里——
        // 那是"没识别出目标"，由下面的兜底统一处理。
        if (unconfigured && targets.length > 0) {
            return (`[secops/scope] 未配置授权范围（allowedHosts 为空），拒绝出站目标 "${targets[0]}"。` +
                '先列出授权目标，或显式设置 scopeMode="open"。');
        }
        for (const host of targets) {
            if (!allowed.has(host)) {
                return (`[secops/scope] target "${host}" is outside the authorized scope ` +
                    `(allowed: ${[...allowed].join(', ')})`);
            }
        }
        return undefined;
    };
    ctx.tools.guard(guard);
    ctx.logger.info(`secops: scope guard armed for ${config.allowedHosts.length} host(s)`);
}
/**
 * 工具封锁：整类能力直接拒绝。
 *
 * 与范围闸的区别：范围闸看目标主机，需要参数里带 URL；模型自己写的搜索词
 * 是自然语言，从里面抠不出主机。所以「不许联网找答案」这件事不能靠范围闸，
 * 必须按工具名封——在能力层面没有这个东西，比在提示里说「不要搜」可靠。
 */
export function installToolDenyGuard(ctx, denied) {
    if (denied.length === 0)
        return;
    const deny = new Set(denied);
    ctx.tools.guard((exec) => {
        if (!deny.has(exec.name))
            return undefined;
        return `[secops/denylist] tool "${exec.name}" is disabled for this profile`;
    });
    ctx.logger.info(`secops: denied tools: ${[...deny].join(', ')}`);
}
export function installBudgetGuard(ctx, config) {
    if (config.maxToolCalls === undefined && config.maxWallClockMs === undefined) {
        ctx.logger.info('secops: no budget configured — budget guard is inert');
        return;
    }
    const startedAt = Date.now();
    let calls = 0;
    // 计数点放在**所有拒绝分支之后**。
    //
    // 早先是首行 `calls += 1`，于是被自己拒绝的调用也吃配额：预算耗尽后
    // 模型每次重试都让 calls 继续涨，错误信息里的数字越来越离谱，
    // 而它一次真正的探测都没做。
    //
    // 已知局限：别的闸（scope / tool-deny）在**另一个 guard 里**先拒绝时，
    // 这个 guard 仍然会被调用并计数——DSH 的 guard 语义是"全部都要跑"，
    // 这里看不到最终裁决结果。要彻底解决需要把计数搬到执行 hook 上，
    // 那是另一套机制；当前改动至少保证"被自己拒绝的不再膨胀"。
    const guard = (exec) => {
        if (config.maxToolCalls !== undefined && calls >= config.maxToolCalls) {
            return `[secops/budget] tool-call budget exhausted (${calls} >= ${config.maxToolCalls})`;
        }
        if (config.maxWallClockMs !== undefined) {
            const elapsed = Date.now() - startedAt;
            if (elapsed > config.maxWallClockMs) {
                return `[secops/budget] wall-clock budget exhausted (${elapsed}ms > ${config.maxWallClockMs}ms)`;
            }
        }
        calls += 1;
        void exec;
        return undefined;
    };
    ctx.tools.guard(guard);
    ctx.logger.info(`secops: budget guard armed (maxToolCalls=${config.maxToolCalls ?? '∞'}, ` +
        `maxWallClockMs=${config.maxWallClockMs ?? '∞'})`);
}
