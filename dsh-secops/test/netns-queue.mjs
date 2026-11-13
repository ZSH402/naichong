/** 阶段 D 集成：队列任务在 netns 中执行，只有代理通道可用。 */
import http from 'node:http'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { EgressProxy } from '../dist/egress.js'
import { QueueRunner } from '../dist/queue-runner.js'

const results = []
const check = (label, ok, detail) => {
  results.push(ok)
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}${ok ? '' : '  ' + JSON.stringify(detail)}`)
}

const upstream = http.createServer((_q, res) => res.writeHead(200).end('UPSTREAM-OK'))
await new Promise((r) => upstream.listen(0, '127.0.0.1', r))
const port = upstream.address().port

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'dsh-secops-nq-'))
const socketPath = path.join(root, 'egress.sock')
const proxy = new EgressProxy({ allowedHosts: ['127.0.0.1'], socketPath })
await proxy.start()

const runner = new QueueRunner({
  queueFile: path.join(root, 'q.jsonl'),
  evidenceRoot: path.join(root, 'ev'),
  concurrency: 1,
  netns: { proxySocket: socketPath },
})
runner.start()

const okTask = runner.submit({
  id: 'nq-allow',
  kind: 'netns',
  argv: ['curl', '-sS', '-m', '8', '--noproxy', '', `http://127.0.0.1:${port}/`],
  cwd: root,
})
const denyTask = runner.submit({
  id: 'nq-deny',
  kind: 'netns',
  argv: ['curl', '-sS', '-m', '8', '--noproxy', '', '-o', '/dev/null', '-w', '%{http_code}', 'http://10.255.255.1/'],
  cwd: root,
})
await runner.drain()

const okDone = runner.get(okTask.id)
const denyDone = runner.get(denyTask.id)
const okOut = okDone.evidenceDir ? fs.readFileSync(path.join(okDone.evidenceDir, 'stdout.log'), 'utf8') : ''
const denyOut = denyDone.evidenceDir ? fs.readFileSync(path.join(denyDone.evidenceDir, 'stdout.log'), 'utf8') : ''

check('allowed task reached upstream through proxy', okOut.includes('UPSTREAM-OK'), { status: okDone?.status, out: okOut.slice(0, 100) })
check('allowed task exit 0', okDone?.exitCode === 0, okDone?.exitCode)
check('out-of-scope task not 200', !denyOut.includes('200'), { status: denyDone?.status, out: denyOut.slice(0, 100) })

runner.close()
await proxy.stop()
upstream.close()
const failed = results.filter((r) => !r).length
console.log(`\n${results.length - failed}/${results.length} passed`)
process.exit(failed === 0 ? 0 : 1)
