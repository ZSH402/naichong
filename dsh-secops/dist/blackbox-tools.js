/**
 * 黑盒探测工具 —— 把确定性原语交给模型，而不是让它自己发请求。
 *
 * ## 为什么这一层是"确定性优先"
 *
 * 纯黑盒下最不可靠的一环是"模型想测什么"。能确定下来的事必须由代码做：
 * 发请求、记响应、算差异、判竞态。模型只在**差异出现之后**被叫醒，
 * 去解释这个差异意味着什么。
 *
 * 这条分工不是偏好，是信息论上的必然：一次黑盒交互产生的信息（状态码、
 * 头部、字段集合、时序）远超模型读一遍能提取的部分，让它逐条看既浪费
 * 又不可复现。
 *
 * ## 六个动作的分工
 *
 *   map      端点测绘 + 身份可见性矩阵
 *   diff     四维差分（身份 / 语法 / 协议）
 *   anomaly  基线采样 + 结构性异常判定
 *   race     竞态探测（多轮采样，非单次结论）
 *   state    状态机反推
 *   probe    一站式：测绘 → 差分 → 竞态 → 异常
 *
 * 所有实现都在 engine/blackbox/，这里只做参数翻译与结果整形。
 */
import { execFile } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { promisify } from 'node:util';
const execFileAsync = promisify(execFile);
function defaultEngine() {
    const candidates = [
        process.env['NC_ENGINE'],
        process.cwd(),
        path.resolve(process.cwd(), '..'),
        '/root/异构agent/engine',
    ];
    for (const c of candidates) {
        if (c === undefined || c === null || c === '')
            continue;
        try {
            // eslint-disable-next-line @typescript-eslint/no-require-imports
            if (fs.existsSync(path.join(c, 'blackbox', 'cli.py')))
                return c;
        }
        catch {
            continue;
        }
    }
    return '';
}
const RESULT_SCHEMA = {
    type: 'object',
    properties: {
        ok: { type: 'boolean' },
        action: { type: 'string' },
        error: { type: 'string' },
        data: { type: 'object' },
    },
    required: ['ok', 'action'],
};
export function blackboxTools(opts = {}) {
    const engine = opts.enginePath ?? defaultEngine();
    const python = opts.pythonPath ?? 'python3';
    const call = async (args) => {
        try {
            const { stdout } = await execFileAsync(python, ['-m', 'blackbox.cli', ...args], { maxBuffer: 32 * 1024 * 1024, timeout: 600_000, cwd: engine });
            const data = JSON.parse(stdout.trim().split('\n').pop() ?? '{}');
            if (typeof data['error'] === 'string')
                return { ok: false, action: args[0] ?? '', error: data['error'], data };
            return { ok: true, action: args[0] ?? '', data };
        }
        catch (err) {
            const e = err;
            if (typeof e.stdout === 'string' && e.stdout.trim() !== '') {
                try {
                    const data = JSON.parse(e.stdout.trim().split('\n').pop() ?? '{}');
                    return { ok: false, action: args[0] ?? '', error: String(data['error'] ?? 'failed'), data };
                }
                catch {
                    /* 落到下面 */
                }
            }
            return { ok: false, action: args[0] ?? '', error: (e.stderr ?? e.message ?? 'blackbox failed').slice(0, 600) };
        }
    };
    const tool = {
        name: 'blackbox_probe',
        description: 'Deterministic black-box probing against a live HTTP target. No source code, no instrumentation. ' +
            'Six actions:\n' +
            '  map      — crawl from seed paths, harvest endpoints/params/leaks, build an identity×endpoint status matrix\n' +
            '  diff     — four-dimension differencing: identity (BOLA/IDOR), syntax (duplicate keys, type juggling), ' +
            'protocol (header variants that split proxy vs origin)\n' +
            '  anomaly  — sample a baseline, then flag structural deviations (status/field/length) plus hard ' +
            'markers that business code cannot produce (double HTTP response, inline headers, stack frames, path leaks)\n' +
            '  race     — multi-round concurrent replay vs sequential baseline. The verdict compares SUCCESS COUNTS, ' +
            'not result divergence, and repeats rounds because race windows open intermittently. Pass reset_url for ' +
            'one-shot endpoints (coupons, balances) or the second group measures an exhausted state.\n' +
            '  state    — replay step sequences and reconstruct an approximate state machine; reports ' +
            'nondeterministic transitions and states reachable by multiple identities\n' +
            '  probe    — map + diff + race + anomaly in one pass, with rate limiting and early-exit\n' +
            'Identities are passed as "name=cookie:k=v,role=user" strings. ' +
            'Discipline: a clean result means these probes found nothing — it is never evidence that the target is safe.',
        parameters: {
            type: 'object',
            properties: {
                action: { type: 'string', enum: ['map', 'diff', 'anomaly', 'race', 'state', 'probe'] },
                base: { type: 'string', description: 'Target root URL, e.g. http://127.0.0.1:8099' },
                ids: {
                    type: 'array',
                    items: { type: 'string' },
                    description: 'Identity specs: "alice=cookie:sid=abc,role=user" / "anon=" / "svc=bearer:TOKEN"',
                },
                paths: { type: 'string', description: 'Comma-separated paths (map/probe seeds, or the single path for diff/anomaly/race).' },
                method: { type: 'string', description: 'HTTP method for diff/anomaly/race (default GET; race defaults POST).' },
                body: { type: 'string', description: 'Request body (url-encoded) for race/diff.' },
                param: { type: 'string', description: 'diff: parameter name to mutate across syntax variants.' },
                markers: { type: 'string', description: 'Comma-separated markers only one identity should ever see (e.g. another user id, an amount).' },
                samples: { type: 'number', description: 'anomaly: baseline sample count (default 5).' },
                count: { type: 'number', description: 'race: concurrent request count (default 10).' },
                rounds: { type: 'number', description: 'race: sampling rounds (default 3). A single round cannot tell a real race from luck.' },
                reset_url: { type: 'string', description: 'race: URL called between rounds to restore initial state.' },
                steps: { type: 'string', description: 'state: JSON array of {"identity":"a","steps":[{"path":"/x","method":"GET"}]}' },
                host: { type: 'string', description: 'Scope allow-list host; when given, every request is checked against it.' },
                qps: { type: 'number', description: 'probe: global QPS cap (default 20).' },
            },
            required: ['action', 'base'],
        },
        output: {
            schema: RESULT_SCHEMA,
            render: (_a, v) => [{ type: 'text', text: JSON.stringify(v, null, 2) }],
        },
        execute: async (args) => {
            const a = (args ?? {});
            const action = typeof a['action'] === 'string' ? a['action'] : '';
            if (engine === '') {
                return { ok: false, action, error: 'blackbox engine not found; set NC_ENGINE to the engine directory' };
            }
            const base = typeof a['base'] === 'string' ? a['base'] : '';
            if (base === '')
                return { ok: false, action, error: 'base is required' };
            const argv = [action, '--base', base];
            const ids = Array.isArray(a['ids']) ? a['ids'].filter((x) => typeof x === 'string') : [];
            for (const id of ids)
                argv.push('--ids', id);
            if (typeof a['markers'] === 'string' && a['markers'] !== '')
                argv.push('--markers', a['markers']);
            if (typeof a['host'] === 'string' && a['host'] !== '')
                argv.push('--host', a['host']);
            const single = (key) => (typeof a[key] === 'string' ? a[key] : '');
            switch (action) {
                case 'map':
                    argv.push('--paths', single('paths') || '/');
                    return call(argv);
                case 'diff':
                    argv.push('--path', single('paths') || '/', '--method', single('method') || 'GET');
                    if (single('param') !== '')
                        argv.push('--param', single('param'));
                    if (single('body') !== '')
                        argv.push('--body', single('body'));
                    return call(argv);
                case 'anomaly':
                    argv.push('--path', single('paths') || '/', '--method', single('method') || 'GET');
                    argv.push('--samples', String(typeof a['samples'] === 'number' ? a['samples'] : 5));
                    return call(argv);
                case 'race':
                    argv.push('--path', single('paths') || '/', '--method', single('method') || 'POST');
                    argv.push('--body', single('body'));
                    argv.push('--count', String(typeof a['count'] === 'number' ? a['count'] : 10));
                    if (single('reset_url') !== '')
                        argv.push('--reset-url', single('reset_url'));
                    return call(argv);
                case 'state':
                    if (single('steps') === '')
                        return { ok: false, action, error: 'steps JSON is required for state' };
                    argv.push('--steps', single('steps'));
                    return call(argv);
                case 'probe':
                    argv.push('--paths', single('paths') || '/');
                    if (single('reset_url') !== '')
                        argv.push('--reset-url', single('reset_url'));
                    if (single('body') !== '')
                        argv.push('--race-body', single('body'));
                    argv.push('--qps', String(typeof a['qps'] === 'number' ? a['qps'] : 20));
                    return call(argv);
                default:
                    return { ok: false, action, error: `unknown action: ${action}` };
            }
        },
    };
    return [tool];
}
