/**
 * 混合执行验收：插桩编译、覆盖率引导 fuzz、约束求解。
 *
 * 这一层要证明的是**闭环真的闭上**：
 *
 *   build  → 真能编出带 ASan 的目标（"没崩"才不再等于"没问题"）
 *   fuzz   → 真能在有限执行里撞到崩溃，并把输入存下来（可复现）
 *   solve  → 真能算出满足约束的值（而不是靠猜）
 *
 * 靶子是一个必然有栈溢出的 12 行程序：`argv[1][0] == 'A'` 时把
 * 任意长度的参数 strcpy 进 8 字节缓冲。条件很好撞，正好用来验证
 * 反馈循环本身是通的，而不是验证它的运气。
 */
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'

const execFileAsync = promisify(execFile)
const results = []
const check = (l, ok, d) => {
  results.push(ok)
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${l}${ok ? '' : '  ' + JSON.stringify(d)}`)
}

const LAB = '/root/异构agent/engine/fuzz/fuzzlab.py'
const work = fs.mkdtempSync(path.join(os.tmpdir(), 'secops-fuzz-'))

const call = async (args, timeout = 300_000) => {
  try {
    const { stdout } = await execFileAsync('python3', [LAB, ...args], { maxBuffer: 8 * 1024 * 1024, timeout })
    return JSON.parse(stdout.trim().split('\n').pop() ?? '{}')
  } catch (err) {
    const e = err
    if (typeof e.stdout === 'string' && e.stdout.trim() !== '') {
      try { return JSON.parse(e.stdout.trim().split('\n').pop() ?? '{}') } catch { /* fallthrough */ }
    }
    return { ok: false, error: e.message ?? 'failed' }
  }
}

// ── 靶子
const src = path.join(work, 'target.c')
fs.writeFileSync(src, `
#include <stdio.h>
#include <string.h>
int main(void) {
    char in[256];
    char buf[8];
    if (fgets(in, sizeof in, stdin) == NULL) return 0;
    in[strcspn(in, "\\n")] = 0;
    if (in[0] == 'A') {
        strcpy(buf, in);
        printf("copy=%s\\n", buf);   /* 必须使用 buf，否则 strcpy 会被编译器优化掉 */
    }
    return 0;
}
`)

// ── 1. build：带 ASan + 覆盖率
const bin = path.join(work, 'target')
{
  const r = await call(['build', src, '-o', bin])
  check('编译成功并生成二进制', r.ok === true && fs.existsSync(bin), r)
  check('ASan 已启用', r.asan === true, r.asan)
  check('走了 AFL++ 编译期插桩', r.afl_instrumented === true, r.afl_instrumented)
}

// ── 2. run：单次执行能看到覆盖行
{
  const inp = path.join(work, 'in.txt')
  fs.writeFileSync(inp, 'AB')
  const r = await call(['run', bin, '--input', inp, '--mode', 'stdin', '--source', 'target.c'])
  check('单次运行报告覆盖行数', r.ok === true && typeof r.lines_hit === 'number', r)
  check('正常输入不误报崩溃', r.crashed === false, r.crashed)
}

// ── 3. fuzz：撞到 ASan 崩溃并落盘 PoV
{
  const r = await call(['fuzz', bin, '--source', 'target.c', '--time-budget', '60', '--mode', 'stdin', '--engine', 'afl'], 240_000)
  check('由 AFL++ 驱动', r.ok === true && r.engine === 'afl++', r.engine)
  check('fuzz 跑通并统计执行数', r.executions > 0, r.executions)
  check('覆盖率反馈有效（探到多条边）', r.edges_found > 1, r.edges_found)
  const crashes = Array.isArray(r.crashes) ? r.crashes : []
  check('撞到了崩溃', crashes.length > 0, r.note)
  check('崩溃被 ASan 确认（不是靠退出码猜）', crashes.some((c) => c.asan === true), crashes.map((c) => c.asan))
  check('PoV 输入已落盘可复现', crashes.every((c) => typeof c.input_file === 'string' && fs.existsSync(c.input_file)), crashes.map((c) => c.input_file))
  if (crashes.length > 0) {
    const replay = await call(['run', bin, '--input', crashes[0].input_file, '--mode', 'stdin', '--source', 'target.c'])
    check('落盘的 PoV 可重放', replay.ok === true && replay.crashed === true, replay)
  }
}

// ── 4. solve：约束求解
{
  const r = await call(['solve', 'x > 100', 'x % 7 == 0'])
  check('能求出满足约束的解', r.ok === true && r.satisfiable === true && typeof r.assignment?.x === 'number', r)
  check('解确实满足约束', r.assignment?.x > 100 && r.assignment?.x % 7 === 0, r.assignment)

  const u = await call(['solve', 'x > 5', 'x < 3'])
  check('矛盾约束如实报 unsat', u.ok === true && u.satisfiable === false, u)

  const two = await call(['solve', 'x * 3 == 42', 'y == x + 1'])
  check('多变量约束联立求解', two.assignment?.x === 14 && two.assignment?.y === 15, two.assignment)
}

// ── 5. 报告纪律：没有崩溃时不能声称安全
{
  const r = await call(['fuzz', path.join(work, 'nonexistent'), '--source', 'x.c', '--time-budget', '5'])
  check('二进制不存在时明确报错', r.ok === false, r)
}

const pass = results.filter(Boolean).length
console.log(`\n${pass}/${results.length} 通过`)
process.exit(pass === results.length ? 0 : 1)
