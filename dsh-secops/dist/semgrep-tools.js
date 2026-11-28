/**
 * semgrep 工具：把生成的规则真的跑一遍。
 *
 * ## 为什么这一层不能省
 *
 * `patch_analyze` 产出的是一段**规则骨架**——它猜这处补丁在防什么，然后
 * 照着写一条"找缺失检查"的查询。骨架能不能跑、跑出来是不是噪音，
 * 之前完全没人验证。没验证的规则等于没写：模型会拿着它去查，查不到就
 * 得出"没有同类问题"的结论，而真实原因可能是规则语法错了。
 *
 * 所以这里做两件事：**执行**，以及**把失败原因原样回传**。
 *
 * ## 为什么是 semgrep 而不是 CodeQL
 *
 * CodeQL 更强（数据流、跨过程），但它有硬门槛：要先给目标建数据库，
 * 而建库需要完整的编译环境——这正是白盒审计里最常缺的东西。
 * semgrep 直接吃源码，一条规则几十毫秒，改完立刻能试。
 * 对"补丁变体"这种**模式查询**，semgrep 的能力边界刚好够。
 */
import { execFile } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
const execFileAsync = promisify(execFile);
function findSemgrep() {
    const candidates = [
        process.env['NC_SEMGREP'],
        path.join(os.homedir(), '.local/bin/semgrep'),
        '/usr/local/bin/semgrep',
        '/usr/bin/semgrep',
    ];
    for (const c of candidates) {
        if (c === undefined || c === null || c === '')
            continue;
        try {
            fs.accessSync(c, fs.constants.X_OK);
            return c;
        }
        catch {
            continue;
        }
    }
    return null;
}
const SCAN_SCHEMA = {
    type: 'object',
    properties: {
        ok: { type: 'boolean' },
        error: { type: 'string' },
        hits: { type: 'number' },
        findings: {
            type: 'array',
            items: {
                type: 'object',
                properties: {
                    file: { type: 'string' },
                    line: { type: 'number' },
                    message: { type: 'string' },
                    rule: { type: 'string' },
                },
                required: ['file', 'line'],
            },
        },
        note: { type: 'string' },
    },
    required: ['ok'],
};
export function semgrepTools(opts = {}) {
    const binary = opts.binaryPath ?? findSemgrep();
    const scanTool = {
        name: 'semgrep_scan',
        description: 'Run a semgrep rule against a source tree and report matches. Feed it the `semgrep_rule` field produced by ' +
            'patch_analyze to actually FIND the sibling sites that are missing the check the patch added — a rule that ' +
            'was never executed is not evidence of anything. ' +
            'Pass either a YAML rule body in `rules` or a path in `rules_path`. ' +
            'If the rule fails to parse, the parse error is returned verbatim: fix the rule, do not conclude "no hits".',
        parameters: {
            type: 'object',
            properties: {
                target: { type: 'string', description: 'Source tree or file to scan.' },
                rules: { type: 'string', description: 'Inline semgrep YAML rules.' },
                rules_path: { type: 'string', description: 'Path to a semgrep YAML file (used when rules is absent).' },
                lang: { type: 'string', description: 'Optional language filter, e.g. javascript / python / c.' },
                max_hits: { type: 'number', description: 'Cap on returned findings (default 40).' },
            },
            required: ['target'],
        },
        output: {
            schema: SCAN_SCHEMA,
            render: (_a, v) => [{ type: 'text', text: JSON.stringify(v, null, 2) }],
        },
        execute: async (args) => {
            const a = (args ?? {});
            if (binary === null) {
                return { ok: false, error: 'semgrep not installed (pip install semgrep, or set NC_SEMGREP)', hits: 0, findings: [] };
            }
            const target = typeof a['target'] === 'string' ? a['target'] : '';
            if (target === '' || !fs.existsSync(target)) {
                return { ok: false, error: `target not found: ${target}`, hits: 0, findings: [] };
            }
            let configPath = '';
            let cleanup = false;
            if (typeof a['rules'] === 'string' && a['rules'].trim() !== '') {
                const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'secops-sg-'));
                configPath = path.join(dir, 'rule.yml');
                fs.writeFileSync(configPath, a['rules'], 'utf8');
                cleanup = true;
            }
            else if (typeof a['rules_path'] === 'string' && a['rules_path'] !== '') {
                configPath = a['rules_path'];
            }
            else {
                return { ok: false, error: 'either rules or rules_path is required', hits: 0, findings: [] };
            }
            // 先校验规则再执行。
            // 这一步是被一次静默失败逼出来的：语法坏掉的规则在 semgrep 里
            // **不报错**，只返回 0 命中（实测 `pattern: (` 会走完整个流程）。
            // 而 0 命中的语义是"扫过了没有"，两者混淆的后果是——模型会得出
            // "没有同类问题"的结论。`--validate` 的退出码能区分：0 合法，非 0 非法。
            try {
                await execFileAsync(binary, ['--validate', '--config', configPath], { timeout: 120_000 });
            }
            catch (verr) {
                const ve = verr;
                const detail = (ve.stdout ?? '') + (ve.stderr ?? '');
                return {
                    ok: false,
                    error: `rule failed validation: ${detail.replace(/\s+/g, ' ').trim().slice(0, 600) || (ve.message ?? 'unknown')}`,
                    hits: 0,
                    findings: [],
                    note: 'the rule was never executed — fix it before drawing any conclusion about the code',
                };
            }
            const argv = ['--config', configPath, target, '--json', '--quiet', '--no-git-ignore'];
            if (typeof a['lang'] === 'string' && a['lang'] !== '')
                argv.push('--include', `*.${a['lang']}`);
            try {
                const { stdout } = await execFileAsync(binary, argv, { maxBuffer: 32 * 1024 * 1024, timeout: 300_000 });
                const parsed = JSON.parse(stdout || '{}');
                const results = parsed.results ?? [];
                const limit = typeof a['max_hits'] === 'number' ? a['max_hits'] : 40;
                const findings = results.slice(0, Math.max(1, limit)).map((r) => ({
                    file: r.path ?? '',
                    line: r.start?.line ?? 0,
                    ...(r.extra?.message === undefined ? {} : { message: r.extra.message }),
                    ...(r.check_id === undefined ? {} : { rule: r.check_id }),
                }));
                return {
                    ok: true,
                    hits: results.length,
                    findings,
                    ...(results.length === 0
                        ? { note: 'the rule ran and matched nothing — that is a real result, but check that the rule actually targets this code' }
                        : {}),
                };
            }
            catch (err) {
                const e = err;
                // semgrep 用非零退出码表示"有命中"，这是正常情况，要解析而不是当失败
                if (typeof e.stdout === 'string' && e.stdout.trim().startsWith('{')) {
                    try {
                        const parsed = JSON.parse(e.stdout);
                        const results = parsed.results ?? [];
                        return {
                            ok: true,
                            hits: results.length,
                            findings: results.slice(0, 40).map((r) => ({
                                file: r.path ?? '',
                                line: r.start?.line ?? 0,
                                ...(r.extra?.message === undefined ? {} : { message: r.extra.message }),
                                ...(r.check_id === undefined ? {} : { rule: r.check_id }),
                            })),
                        };
                    }
                    catch {
                        /* 落到下面 */
                    }
                }
                return {
                    ok: false,
                    error: (e.stderr ?? e.message ?? 'semgrep failed').slice(0, 800),
                    hits: 0,
                    findings: [],
                    note: 'a rule that does not parse produces no hits — fix the rule before drawing conclusions',
                };
            }
            finally {
                if (cleanup && configPath !== '') {
                    try {
                        fs.rmSync(path.dirname(configPath), { recursive: true, force: true });
                    }
                    catch {
                        /* 临时目录清不掉不影响结果 */
                    }
                }
            }
        },
    };
    return [scanTool];
}
