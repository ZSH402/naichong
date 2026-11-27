/**
 * CVE 索引验收。
 *
 * 这里有两个回归测试是拿真实 bug 换来的，别删：
 *
 *   1. **区间必须绑定组件**。第一版把一条 CVE 下所有 cpeMatch 的区间塞进一个
 *      扁平数组，结果 "Apache 2.0.37..2.0.63" 会把 2.4.49 判成受影响。
 *
 *   2. **NVD 的字段名是 versionEndExcluding，不是 endExcluding**。写成后者时
 *      区间只剩起点，等于"大于等于起始版本的全命中"，而且不报错——所有版本
 *      返回相同结果，看上去像排序问题。
 *
 * 两个 bug 都是静默的，所以必须有测试盯着。
 */
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { CveStore, compactNvdItem } from '../dist/cve-store.js'
import { compareVersions, inRange, parseFingerprint, productMatches } from '../dist/cve-types.js'

const results = []
const check = (l, ok, d) => {
  results.push(ok)
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${l}${ok ? '' : '  ' + JSON.stringify(d)}`)
}

// ── 1. 版本比较：真实世界里会出现的那几种
{
  const cases = [
    ['2.4.49', '2.4.51', -1, '普通数字段'],
    ['1.10', '1.9', 1, '字典序陷阱'],
    ['7.0.103', '7.0.99', 1, '多位数'],
    ['8.2p1', '8.2', 1, '带补丁后缀'],
    ['8.2p1', '8.2p2', -1, '补丁号比较'],
    ['1.0.0-rc2', '1.0.0', -1, 'rc 小于正式版'],
    ['1.0.0-alpha', '1.0.0-beta', -1, '预发布之间'],
    ['1.0', '1.0.0', 0, '末尾零等价'],
    ['2.4.49-1ubuntu1', '2.4.49', 1, '发行版修订号'],
    ['v1.2.3', '1.2.3', 0, 'v 前缀'],
  ]
  for (const [a, b, want, label] of cases) {
    const got = Math.sign(compareVersions(a, b))
    check(`compare(${a}, ${b}) = ${want}  [${label}]`, got === want, { got })
  }
}

// ── 2. 区间判断
{
  check('in [2.4.49, 2.4.51) 含起点', inRange('2.4.49', { startIncluding: '2.4.49', endExcluding: '2.4.51' }))
  check('in [2.4.49, 2.4.51) 不含终点', !inRange('2.4.51', { startIncluding: '2.4.49', endExcluding: '2.4.51' }))
  check('in (2.4.49, 2.4.51] 不含起点', !inRange('2.4.49', { startExcluding: '2.4.49', endIncluding: '2.4.51' }))
  check('无界区间接受任意版本', inRange('9.9.9', {}))
}

// ── 3. 组件匹配
{
  check('完全相同', productMatches('apache:http_server', 'apache:http_server'))
  check('只给 product 名时后缀匹配', productMatches('apache:http_server', 'http_server'))
  check('给了 vendor 就不做后缀匹配', !productMatches('f5:nginx', 'nginx:nginx'))
  check('_ 与 - 的差异不自动归一', !productMatches('apache:http-server', 'http_server'))
}

// ── 4. 指纹解析
{
  const cases = [
    ['Apache/2.4.49 (Ubuntu)', 'apache', '2.4.49'],
    ['nginx/1.18.0', 'nginx', '1.18.0'],
    ['OpenSSH_8.2p1 Ubuntu-4ubuntu0.5', 'openssh', '8.2p1'],
    ['Microsoft-IIS/10.0', 'microsoft-iis', '10.0'],
  ]
  for (const [raw, prod, ver] of cases) {
    const p = parseFingerprint(raw)
    check(`解析 "${raw}"`, p !== null && p.product === prod && p.version === ver, p)
  }
  check('纯文字返回 null', parseFingerprint('no version here') === null)
}

// ── 5. 回归：区间必须绑定组件
{
  const rec = compactNvdItem({
    cve: {
      id: 'CVE-TEST-0001',
      descriptions: [{ lang: 'en', value: 'apache 2.0.x issue' }],
      configurations: [{
        nodes: [{
          cpeMatch: [
            { vulnerable: true, criteria: 'cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*', versionStartIncluding: '2.0.37', versionEndExcluding: '2.0.64' },
            // 同一个 CVE 里另一个组件，区间完全不同
            { vulnerable: true, criteria: 'cpe:2.3:a:ibm:http_server:*:*:*:*:*:*:*:*', versionStartIncluding: '6.0', versionEndExcluding: '6.1.5' },
          ],
        }],
      }],
    },
  })
  check('两个组件各自成组', rec !== null && rec.affected.length === 2, rec?.affected.map(a => a.product))
  const ap = rec?.affected.find(a => a.product === 'apache:http_server')
  const ibm = rec?.affected.find(a => a.product === 'ibm:http_server')
  check('apache 区间只含自己的', ap?.ranges.length === 1 && ap.ranges[0].endExcluding === '2.0.64', ap?.ranges)
  check('ibm 区间只含自己的', ibm?.ranges.length === 1 && ibm.ranges[0].endExcluding === '6.1.5', ibm?.ranges)
}

// ── 6. 回归：versionEnd* 字段名
{
  const rec = compactNvdItem({
    cve: {
      id: 'CVE-TEST-0002',
      descriptions: [{ lang: 'en', value: 'x' }],
      configurations: [{ nodes: [{ cpeMatch: [
        { vulnerable: true, criteria: 'cpe:2.3:a:foo:bar:*:*:*:*:*:*:*:*', versionStartIncluding: '1.0', versionEndExcluding: '2.0' },
      ] }] }],
    },
  })
  const r = rec?.affected[0]?.ranges[0]
  check('endExcluding 被读到（不是 undefined）', r?.endExcluding === '2.0', r)
}

// ── 7. 索引与查询
{
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'secops-cve-'))
  const store = new CveStore({ path: path.join(dir, 'idx.jsonl') })
  const mk = (id, rules) => ({
    cve: {
      id,
      published: '2021-10-05T00:00:00',
      descriptions: [{ lang: 'en', value: `summary of ${id}` }],
      metrics: { cvssMetricV31: [{ cvssData: { baseScore: 9.8, baseSeverity: 'CRITICAL' } }] },
      weaknesses: [{ description: [{ value: 'CWE-22' }] }],
      configurations: [{ nodes: [{ cpeMatch: rules }] }],
    },
  })
  store.importNvd({
    vulnerabilities: [
      mk('CVE-A-0001', [{ vulnerable: true, criteria: 'cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*' }]),
      mk('CVE-A-0002', [{ vulnerable: true, criteria: 'cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*', versionStartIncluding: '2.4.0', versionEndExcluding: '2.4.51' }]),
      mk('CVE-A-0003', [{ vulnerable: true, criteria: 'cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*' }]), // 无版本约束
    ],
  })

  check('索引计数', store.stats().total === 3, store.stats())
  const at49 = store.query({ product: 'apache:http_server', version: '2.4.49' })
  check('2.4.49 命中 exact 与 range 两条', at49.length === 2, at49.map(h => h.cve.id))
  check('exact 命中标记正确', at49.find(h => h.cve.id === 'CVE-A-0001')?.matchedBy === 'exact')
  check('无约束记录默认不返回', !at49.some(h => h.cve.id === 'CVE-A-0003'))

  const withUnc = store.query({ product: 'apache:http_server', version: '2.4.49', includeUnconstrained: true })
  check('显式打开后无约束记录出现', withUnc.some(h => h.cve.id === 'CVE-A-0003' && h.matchedBy === 'no-constraint'))

  const at51 = store.query({ product: 'apache:http_server', version: '2.4.51' })
  check('2.4.51 不再命中区间那条', !at51.some(h => h.cve.id === 'CVE-A-0002'), at51.map(h => h.cve.id))

  const rangeHit = at49.find(h => h.cve.id === 'CVE-A-0002')
  check('修复版本可从 endExcluding 反推', rangeHit?.fixAt === '2.4.51', rangeHit?.fixAt)

  const none = store.query({ product: 'never-indexed', version: '1.0' })
  check('未知组件返回空', none.length === 0)

  // 落盘与恢复
  store.save()
  const reloaded = new CveStore({ path: path.join(dir, 'idx.jsonl') }).load()
  check('落盘后恢复', reloaded.stats().total === 3, reloaded.stats())
  check('恢复后查询一致', reloaded.query({ product: 'apache:http_server', version: '2.4.49' }).length === 2)
}

// ── 8. 真实 NVD 数据（存在则跑，不存在则跳过）
{
  const f = '/tmp/nvd_merged.json'
  if (!fs.existsSync(f)) {
    console.log('SKIP  真实 NVD 数据不在 /tmp/nvd_merged.json')
  } else {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'secops-cve-real-'))
    const store = new CveStore({ path: path.join(dir, 'idx.jsonl') })
    const r = store.importNvd(JSON.parse(fs.readFileSync(f, 'utf8')))
    check(`导入真实数据 ${r.imported} 条`, r.imported > 500, r)

    const known = [
      ['2.4.48', 'CVE-2021-41773', false],
      ['2.4.49', 'CVE-2021-41773', true],
      ['2.4.50', 'CVE-2021-41773', false],
      ['2.4.49', 'CVE-2021-42013', true],
      ['2.4.50', 'CVE-2021-42013', true],
      ['2.4.51', 'CVE-2021-42013', false],
    ]
    for (const [ver, id, want] of known) {
      const got = store.query({ product: 'apache:http_server', version: ver, limit: 500 }).some(h => h.cve.id === id)
      check(`真实数据 ${ver} ${want ? '命中' : '不含'} ${id}`, got === want, { got })
    }
  }
}

const pass = results.filter(Boolean).length
console.log(`\n${pass}/${results.length} 通过`)
process.exit(pass === results.length ? 0 : 1)
