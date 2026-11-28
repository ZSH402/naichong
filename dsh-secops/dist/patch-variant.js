import fs from 'node:fs';
/**
 * 提取新增行。
 *
 * 用系统 `diff -u` 而不是自己按行集合做差——集合差会把"移动过位置的行"
 * 当成没变、把重复出现的行当成已有，而补丁分析恰恰要看**这一行被加在哪里**。
 * diff 是几十年打磨过的实现，没有理由自己重写一遍。
 *
 * diff 不可用时降级到集合差，并在 rationale 里如实说明。
 */
async function addedLines(before, after) {
    const os = await import('node:os');
    const path = await import('node:path');
    const { execFile } = await import('node:child_process');
    const { promisify } = await import('node:util');
    const execFileAsync = promisify(execFile);
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'secops-patch-'));
    const f1 = path.join(dir, 'before.txt');
    const f2 = path.join(dir, 'after.txt');
    fs.writeFileSync(f1, before, 'utf8');
    fs.writeFileSync(f2, after, 'utf8');
    try {
        const { stdout } = await execFileAsync('diff', ['-u', f1, f2], { maxBuffer: 8 * 1024 * 1024 });
        const out = [];
        for (const line of stdout.split('\n')) {
            if (!line.startsWith('+') || line.startsWith('+++'))
                continue;
            const t = line.slice(1).trim();
            if (t === '')
                continue;
            if (t.startsWith('//') || t.startsWith('#') || t.startsWith('*') || t.startsWith('/*'))
                continue;
            out.push(t);
        }
        return { lines: out, via: 'diff' };
    }
    catch (err) {
        // diff 的退出码 1 表示"有差异"，是正常情况
        const e = err;
        if (e.code === 1 && typeof e.stdout === 'string') {
            const out = [];
            for (const line of e.stdout.split('\n')) {
                if (!line.startsWith('+') || line.startsWith('+++'))
                    continue;
                const t = line.slice(1).trim();
                if (t === '')
                    continue;
                if (t.startsWith('//') || t.startsWith('#') || t.startsWith('*') || t.startsWith('/*'))
                    continue;
                out.push(t);
            }
            return { lines: out, via: 'diff' };
        }
        // 降级：行集合差
        const b = new Set(before.split('\n').map((l) => l.trim()));
        const out = [];
        for (const line of after.split('\n')) {
            const t = line.trim();
            if (t === '' || b.has(t))
                continue;
            if (t.startsWith('//') || t.startsWith('#') || t.startsWith('*') || t.startsWith('/*'))
                continue;
            out.push(t);
        }
        return { lines: out, via: 'fallback' };
    }
    finally {
        try {
            fs.rmSync(dir, { recursive: true, force: true });
        }
        catch { /* 清不掉不影响结果 */ }
    }
}
const PATTERNS = [
    {
        kind: 'null-guard',
        re: /\b(if\s*\([^)]*(===?\s*null|!==?\s*null|==\s*undefined|!=\s*undefined|is\s+None|isEmpty|empty\(\))|\?\?|\?\.)/,
        why: '补丁加了空值检查，说明缺失它时下游会把空值当有效数据使用',
    },
    {
        kind: 'bounds-check',
        re: /\b(if\s*\([^)]*(>=?\s*\w*(len|size|count|length|capacity)|<\s*0\b|>\s*\w*(max|limit))|\bclamp\(|\bmin\(|Math\.min)/i,
        why: '补丁加了边界检查，说明缺失它时长度/索引可以越界',
    },
    {
        kind: 'sanitizer',
        re: /\b(escape|sanitize|encode|normalize|quote|clean|strip|filter|validate|verify)\w*\s*\(/i,
        why: '补丁加了净化/校验调用，说明缺失它时不可信输入直达汇点',
    },
    {
        kind: 'auth-guard',
        re: /\b(require\w*|ensure\w*|checkPermission|authorize|hasRole|isOwner|tenant_\w*|owner_id)\b/i,
        why: '补丁加了授权检查，说明同类端点可能漏了同样的守卫',
    },
    {
        kind: 'type-check',
        re: /\b(typeof\s+\w+\s*[!=]==|instanceof\s+\w+|isinstance\(|\.length\s*[!=]==|Number\.isInteger)/,
        why: '补丁加了类型/形状校验，说明缺失它时会被传入非预期类型',
    },
];
/**
 * 提取用来反查同类代码的信号。
 *
 * 关键在**汇点通常不在新增行里**：补丁加的是检查，危险调用是原来就有的那一行。
 * 只从 added 行里提信号，会把 `res.status().send()` 这种噪音当成汇点，
 * 而真正的 `lookup(name)` 反而漏掉。
 *
 * 所以顺序是：先从修复后的全文提调用，再让新增行里出现的标识符排到后面——
 * 它们是"检查用到的"，不是"被检查保护的"。
 */
const NOISE = new Set([
    'if', 'for', 'while', 'switch', 'return', 'catch', 'function', 'console', 'log',
    'status', 'send', 'json', 'error', 'require', 'typeof', 'parseInt', 'String', 'Number',
]);
function signalsOf(added, fullText) {
    const checkNames = new Set();
    for (const l of added) {
        for (const m of l.matchAll(/\b([a-zA-Z_][a-zA-Z0-9_]{2,})\s*\(/g))
            checkNames.add(m[1]);
    }
    const sinkNames = new Set();
    for (const m of fullText.matchAll(/\b([a-zA-Z_][a-zA-Z0-9_]{2,})\s*\(/g)) {
        const name = m[1];
        if (NOISE.has(name) || checkNames.has(name))
            continue;
        sinkNames.add(name);
    }
    // 汇点优先，其次是检查里用到的名字（它们能帮助定位同类守卫）
    return [...sinkNames, ...checkNames].slice(0, 12);
}
/**
 * 生成 semgrep 规则骨架。
 *
 * 生成的规则找的是"**缺失**"：匹配危险汇点，但不带补丁里新增的那个检查。
 * 这是 semgrep 里表达"absent pattern"的常用做法——先匹配汇点，
 * 再用 `pattern-not-inside` 排除已经有检查的情形。
 */
function semgrepFor(kind, signals) {
    const sink = signals[0] ?? 'SINK';
    const notice = [
        '# 自动生成的骨架，需按目标语言与汇点改名后再跑。',
        '# 思路：找出调用汇点、但缺少补丁里那行检查的位置（即"不完整补丁"）。',
    ];
    const body = {
        'null-guard': `      - pattern: ${sink}(...)
      - pattern-not-inside: |
          if ($X == null) { ... }
          ...
      - pattern-not-inside: |
          if ($X === undefined) { ... }
          ...`,
        'bounds-check': `      - pattern: ${sink}(...)
      - pattern-not-inside: |
          if ($IDX < $LEN) { ... }
          ...`,
        sanitizer: `      - pattern: ${sink}($X, ...)
      - pattern-not-inside: |
          $SANITIZED = ${sink}($SANITIZE($X), ...)`,
        'auth-guard': `      - pattern: $APP.$M("$ROUTE", ...)
      - pattern-not-inside: |
          $APP.$M("$ROUTE", $GUARD, ...)`,
        'type-check': `      - pattern: ${sink}($X, ...)
      - pattern-not-inside: |
          if (typeof $X === "...") { ... }
          ...`,
        unknown: `      - pattern: ${sink}(...)`,
    };
    return [
        ...notice,
        'rules:',
        '  - id: variant-of-recent-fix',
        `    message: 疑似缺少与近期补丁相同性质的检查（${kind}）`,
        '    severity: WARNING',
        '    languages: [generic]',
        '    patterns:',
        body[kind] ?? body['unknown'],
    ].join('\n');
}
/**
 * 分析一次修复，提取变体查询。
 *
 * 输入是修复前 / 修复后的同一段代码（或同一文件）。返回的是**线索**：
 * 补丁在防什么、同类代码该去哪里找漏掉的地方。
 */
export async function analyzeFix(before, after) {
    const { lines: added, via } = await addedLines(before, after);
    if (added.length === 0)
        return null;
    const hit = PATTERNS.find((p) => added.some((l) => p.re.test(l)));
    const kind = hit?.kind ?? 'unknown';
    const signals = signalsOf(added, after);
    return {
        kind,
        addedLines: added.slice(0, 20),
        signals,
        semgrepRule: semgrepFor(kind, signals),
        rationale: (hit?.why ??
            '未能识别出明确的检查类型：补丁新增的行里没有典型的守卫/边界/净化模式，需要人工判断它在防什么') +
            (via === 'fallback' ? '（注意：diff 不可用，本次用行集合差近似，行移动可能被误判）' : ''),
    };
}
