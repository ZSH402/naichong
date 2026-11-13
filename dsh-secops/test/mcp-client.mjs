/**
 * MCP 客户端验收（纯协议层，不起真 server）。
 *
 * 用 Node 写一个假 server 来验证：握手顺序、请求/响应配对、
 * 通知不占 id、超时、连接断开后的错误传播。
 */
import { McpStdioClient, McpError } from '../dist/mcp-client.js'

const results = []
const check = (l, ok, d) => { results.push(ok); console.log(`${ok?'PASS':'FAIL'}  ${l}${ok?'':'  '+JSON.stringify(d)}`) }

// 假 MCP server：不依赖外部二进制，只按协议回话
const FAKE = `
let buf=''
process.stdin.setEncoding('utf8')
const send=(o)=>process.stdout.write(JSON.stringify(o)+'\\n')
let seenInit=false, seenNotified=false
process.stdin.on('data',(c)=>{
  buf+=c
  let i
  while((i=buf.indexOf('\\n'))!==-1){
    const line=buf.slice(0,i).trim(); buf=buf.slice(i+1)
    if(!line) continue
    const m=JSON.parse(line)
    if(m.method==='initialize'){ seenInit=true; send({jsonrpc:'2.0',id:m.id,result:{protocolVersion:'2024-11-05',capabilities:{tools:{}},serverInfo:{name:'fake',version:'1'}}}) }
    else if(m.method==='notifications/initialized'){ seenNotified=true }
    else if(m.method==='tools/list'){ send({jsonrpc:'2.0',id:m.id,result:{tools:[{name:'echo',description:'echo back',inputSchema:{type:'object'}},{name:'boom'}]}}) }
    else if(m.method==='tools/call'){
      if(!seenInit||!seenNotified){ send({jsonrpc:'2.0',id:m.id,error:{code:-32000,message:'handshake incomplete'}}); continue }
      if(m.params.name==='echo'){ send({jsonrpc:'2.0',id:m.id,result:{content:[{type:'text',text:'echo:'+JSON.stringify(m.params.arguments)}]}}) }
      else { send({jsonrpc:'2.0',id:m.id,result:{isError:true,content:[{type:'text',text:'tool failed'}]}}) }
    }
    else if(m.id!==undefined){ send({jsonrpc:'2.0',id:m.id,error:{code:-32601,message:'method not found'}}) }
  }
})
`

const spec = (extra = {}) => ({ command: [process.execPath, '-e', FAKE], timeoutMs: 8000, ...extra })

// ── 1. 握手 + 列工具
{
  const c = new McpStdioClient(spec())
  await c.connect()
  check('connect completes', c.info !== undefined, c.info)
  const tools = await c.listTools()
  check('tools listed', tools.length === 2, tools.map((t) => t.name))
  check('tool description kept', tools[0]?.description === 'echo back')
  c.close()
}

// ── 2. 调用成功
{
  const c = new McpStdioClient(spec())
  await c.connect()
  const r = await c.callTool('echo', { a: 1 })
  check('call returns text content', r.text.startsWith('echo:'), r.text)
  check('isError false on success', r.isError === false)
  c.close()
}

// ── 3. 工具报错要能区分（isError 而不是异常）
{
  const c = new McpStdioClient(spec())
  await c.connect()
  const r = await c.callTool('boom', {})
  check('tool-level error is isError not throw', r.isError === true, r)
  check('error text preserved', r.text.includes('tool failed'))
  c.close()
}

// ── 4. 未知工具：server 可能回 isError 也可能回 rpc error，两者都要能被识别
{
  const c = new McpStdioClient(spec())
  await c.connect()
  let err
  let res
  try { res = await c.callTool('nonexistent-method-holder', {}) } catch (e) { err = e }
  check('unknown tool is not silently success',
    (err instanceof McpError) || res?.isError === true, { err: String(err), res })
  c.close()
}

// ── 5. 关闭后调用要报错而不是挂住
{
  const c = new McpStdioClient(spec())
  await c.connect()
  c.close()
  let err
  try { await c.callTool('echo', {}) } catch (e) { err = e }
  check('closed client rejects immediately', err instanceof McpError && err.kind === 'closed', String(err))
}

// ── 6. 连不上时抛 spawn 错误
{
  const c = new McpStdioClient({ command: ['/nonexistent/mcp-server-xyz'], timeoutMs: 3000 })
  let err
  try { await c.connect() } catch (e) { err = e }
  check('missing binary fails fast', err instanceof McpError, String(err))
}

// ── 7. 超时
{
  const slow = `process.stdin.resume()` // 永不回话
  const c = new McpStdioClient({ command: [process.execPath, '-e', slow], timeoutMs: 500 })
  let err
  try { await c.connect() } catch (e) { err = e }
  check('handshake timeout is reported', err instanceof McpError && err.kind === 'timeout', String(err))
  c.close()
}

const passed = results.filter(Boolean).length
console.log(`\n${passed}/${results.length} passed`)
if (passed !== results.length) process.exitCode = 1
