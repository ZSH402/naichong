// dsh-secops 桌面壳。
//
// 只做一件事：把 `dsh web` 拉起来，用内嵌窗口加载它，关窗口时把子进程带走。
// 不重画任何界面——DSH 自己那套 GUI 已经有会话、上传、审批、模型设置、中文，
// 我们自己的面板以 client plugin 的形式挂在那套界面里。
//
// 为什么 spawn 而不是 import：dsh web 是一个长期驻留的宿主进程，生命周期
// 必须和窗口一致；放在同一进程里，Electron 退出时它的定时器和 socket 不会
// 干净收尾，第二次启动就会撞端口。

const { app, BrowserWindow, shell, dialog, session } = require('electron')
const { spawn } = require('node:child_process')
const path = require('node:path')

const PROJ = '/root/proj'
const BIN = path.join(PROJ, 'dsh/node_modules/@deepseek-ai/dsh/lib/bin.js')
const PROFILE = 'web'
const HOST = '127.0.0.1'
const PORT = Number(process.env.DSH_DESKTOP_PORT || 3081)
const READY_TIMEOUT_MS = 60_000

let server = null
let win = null
let quitting = false

/** 从子进程输出里抓一次性 token —— dsh web 第一行会打印带 token 的 URL。 */
function tokenFromLine(line) {
  const m = /token=([A-Za-z0-9_-]+)/.exec(line)
  return m === null ? undefined : m[1]
}

/**
 * 起宿主进程，等到它打印出 token 为止。
 *
 * 等 token 而不是等端口：端口通的时候服务可能还没装好中间件，
 * 这时窗口会拿到一个 401 白屏，用户只看到一片空白却不知道发生了什么。
 */
function startServer() {
  return new Promise((resolve, reject) => {
    server = spawn(
      // 用系统 node 而不是 Electron 内嵌的那份：宿主是一整套长期驻留的服务，
      // 它依赖的 worker / net 语义要和命令行下完全一致，换一个 runtime 只会
      // 让「命令行能跑、桌面里跑不了」变成一种随机故障。
      process.env.DSH_DESKTOP_NODE || 'node',
      // BIN 必须作为第一个参数：ELECTRON_RUN_AS_NODE 只是把这个二进制当 node 用，
      // 它仍然需要一个脚本路径，否则 --profile 会被 electron 自己消费掉。
      [BIN, '--profile', PROFILE, '--no-open', '--port', String(PORT), '--host', HOST],
      {
        cwd: PROJ,
        // electron 自带一个 node runtime，但 dsh 需要真正的 node 语义（worker、net）。
        // 用 ELECTRON_RUN_AS_NODE 让同一份二进制以纯 node 模式跑，省掉外部 node 依赖。
        env: { ...process.env, DSH_HOME: path.join(PROJ, 'home') },
        stdio: ['ignore', 'pipe', 'pipe'],
      },
    )

    let buffer = ''
    let failed = false
    const timer = setTimeout(() => {
      reject(new Error(`宿主在 ${READY_TIMEOUT_MS / 1000}s 内没有就绪`))
    }, READY_TIMEOUT_MS)

    const onData = (chunk) => {
      buffer += chunk.toString('utf8')
      for (const line of buffer.split('\n')) {
        const token = tokenFromLine(line)
        if (token !== undefined) {
          clearTimeout(timer)
          resolve(token)
          return
        }
        // 明确的启动失败比超时更好定位：直接把最后一行错误抛上去。
        // 只标记、不立刻 reject：DSH 把「哪个插件、为什么」写在后续若干行里，
        // 第一行到达时它们还没来。等 exit 事件再用完整输出报错。
        if (/startup failed|MISSING_CREDENTIAL/.test(line)) failed = true
      }
    }
    server.stdout.on('data', onData)
    server.stderr.on('data', onData)

    server.on('exit', (code) => {
      if (quitting) return
      clearTimeout(timer)
      const tail = buffer.trim().split('\n').slice(-40).join('\n')
      reject(new Error(failed ? tail : `宿主进程退出（code=${String(code)}）\n${tail}`))
    })
  })
}

async function boot() {
  // launch.sh 已经把宿主起好了，并把带 token 的 URL 传进来。
  // 这条路优先：宿主由 shell 启动，环境与「命令行能跑」的那份一致，
  // 不会踩到 Electron spawn 出来的环境差异。
  const preset = process.env.DSH_DESKTOP_URL
  const url = preset !== undefined && preset !== '' ? preset : `http://${HOST}:${PORT}/?token=${await startServer()}`
  win = new BrowserWindow({
    width: 1440,
    height: 940,
    minWidth: 1024,
    minHeight: 700,
    backgroundColor: '#0f1115',
    title: 'dsh-secops',
    autoHideMenuBar: true,
    webPreferences: {
      // 前端是 dsh 自己的，不需要 node 能力；关掉等于免费关掉一整类逃逸面。
      nodeIntegration: false,
      contextIsolation: true,
      sandbox: true,
    },
  })

  win.on('closed', () => {
    win = null
  })

  // 站外链接交给系统浏览器：桌面 app 里没有地址栏，误点站外链接会让人失去上下文。
  win.webContents.setWindowOpenHandler(({ url }) => {
    void shell.openExternal(url)
    return { action: 'deny' }
  })

  await win.loadURL(url)
}

function stopServer() {
  if (server === null) return
  quitting = true
  try {
    server.kill('SIGTERM')
  } catch {
    /* 已经退了 */
  }
  server = null
}

// 这台机器上的 X 是别的会话的，GPU 进程起不来。软件渲染够了——界面是文本和表格，
// 不需要硬件加速；留着 GPU 只会每次启动刷一屏 EGL 错误。
app.disableHardwareAcceleration()

app.whenReady().then(async () => {
  // 下载落盘：面板的「导出报告」用 Blob + <a download> 触发浏览器下载，
  // 而 Electron 默认会弹保存对话框——无头还好，有桌面时每次导出都要点一次
  // 路径，很烦。直接指定到系统下载目录，同名自动加序号（Electron 负责）。
  session.defaultSession.on('will-download', (_event, item) => {
    try {
      const dir = app.getPath('downloads')
      require('node:fs').mkdirSync(dir, { recursive: true })
      item.setSavePath(`${dir}/${item.getFilename()}`)
    } catch {
      /* 拿不到下载目录就退回 Electron 默认行为 */
    }
  })

  try {
    await boot()
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    // 先落日志再考虑弹框：dialog.showErrorBox 是模态的，在没有交互的环境里
    // （xvfb / CI / 无人值守）它会永久阻塞，把真正的错误信息一起吞掉——
    // 表现出来只是「进程活着但什么都不做」。
    require('node:fs').writeFileSync('/tmp/dsh-desktop-error.log', `${new Date().toISOString()}\n${message}\n`)
    console.error('[dsh-desktop] 启动失败:', message)
    stopServer()
    app.exit(1)
  }
})

// 关窗即退出：这个 app 只有一个窗口，留着后台宿主没有意义，
// 而且会占着端口让下次启动失败。
app.on('window-all-closed', () => {
  stopServer()
  app.quit()
})

app.on('before-quit', stopServer)

// 故意不做 activate 复活：单窗口桌面工具，Dock 里点一下就应该重开整个宿主。
