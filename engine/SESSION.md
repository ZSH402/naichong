# 交互式会话（IAT）· 实现说明

## 解决的什么

奶虫原来的 27 个 agent 候选全是「一次性命令 + 拿输出」。而 CTF 必需的 gdb / nc /
pwntools 都是 REPL —— 它们的价值在于「进去、看状态、再决定下一步」，预先枚举所有
交互在真实调试里做不到。

EnIGMA（[arXiv 2409.16165](https://arxiv.org/html/2409.16165v1), ICML 2025，350 道题
验证，NYU CTF 上比之前最好 agent 多解 3 倍）把这类改进称为 **Interactive Agent
Tools (IAT)**，并证明它是 CTF agent 最大的单点提升。

## 借鉴了什么

| 来源 | 借鉴点 |
|---|---|
| EnIGMA | "交互式会话与主 shell 并行"、"接口简单统一"、裸跑 gdb 要加护栏 |
| pygdbmi | **用 token 定界**而不是等 prompt；gdb MI 的 `--interpreter=mi2`；超时可分级 |
| pygdbmi 的 record 分类 | 知道要处理 `result` / `notify` / `console` 三类，但**只做定界不做完整解析** |

## 自己的三个改动

### 1. 通用会话原语，而不是工具专用命令

EnIGMA 给的是 `debug_start / debug_step / debug_continue / debug_exec` 六件套。
奶虫有 27 个候选且会继续加，每加一个工具就加一套专用命令会让工具面爆炸。

改成五个通用原语：`session_start` / `session_exec` / `session_batch` / `session_tail` /
`session_list` / `session_stop`。**具体怎么用交给领域规格**（`agents/pwn.md` 会告诉
agent 先设断点还是先 `starti`）——那是领域知识，不该硬编码进工具签名。

### 2. 用 token 定界，不等 prompt

EnIGMA 读 gdb 的 `(gdb) ` 提示符判断命令结束。**提示符可能出现在输出内容里**
（被调试程序自己打印 `(gdb)` 串），撞上就会提前返回、截断真实结果。

gdb MI 支持 `<token><command>`，响应行带同一 token 前缀。这是**协议级多路复用**，
不会撞车。实测：每条响应都精确带回自己的 token（`1^done`、`2^done,bkpt={...}`、
`4^done,value="42"`）。

### 3. 允许并发多个会话

EnIGMA 限制"同时只有 1 个交互会话"以降低复杂度。但真实场景需要一边调试一边连
远程服务（EnIGMA 自己的 Figure 3 就是在两者间来回切，只是靠串行模拟）。
这里默认允许 4 个，超限时报错并列出可关闭的会话 id。

### 附带：`session_batch`

"跑一串命令拿结果"的场景不需要每步都由模型决策。`session_batch` 把
起 → 依次执行 → 收尾压成一次调用，省掉 2N 次往返的上下文成本。
需要看中间结果再决定时，才该用 `session_exec` 逐步走。

## 实测数据

用带调试符号的 C 程序验证（`gcc -g -O0`）：

| 命令 | 耗时 | 响应 |
|---|---|---|
| `-break-insert check` | 11ms | `2^done,bkpt={number="1",addr="0x1140",func="check",line="2"}` |
| `-exec-run` | 39ms | `3^running` + `*stopped,reason="breakpoint-hit",...` |
| `-data-evaluate-expression "a"` | 1ms | `4^done,value="42"` |
| `-exec-next` | 13ms | `5^running` + `*stopped,reason="end-stepping-range"` |
| `-gdb-exit` | 19ms | `7^exit` |

**全部毫秒级，无一次超时。**

## 踩到的四个坑

**`^running` 不等于命令结束**。`-exec-run` 先回 `^running`，真正的停止要等异步的
`*stopped`。只认 `^done` 会让它等到超时。`tokenSettled` 里专门处理了这个两段式。

**首字节超时和 idle 超时是两件事**。前者问"命令执行了吗"，后者问"进程是不是卡了"。
混在一起会导致：命令还没开始就被判超时，或者进程卡死了却一直等。

**`quiet` 协议不能靠覆写实例方法实现**。我第一版在 `exec` 里改写 `this.pump`，
多次调用会叠加覆写。改成实例字段 `lastByteAt` + 统一的 `settle()` 出口。

**测试用例本身会写错**。第一版把 `echo` 发给 `sleep 30` 会话——`sleep` 不读 stdin，
当然读不到回显。测试失败先怀疑测试，不是实现。

## 测试覆盖

`tests/session.test.mjs`，15 个断言全通过：

- 会话启动有 pid
- token 定界：断点命令返回 `^done` 且含地址
- **`exec-run` 未超时 + 收到 `^running` + 收到 `*stopped`**（最容易卡死的一条）
- stopped 原因是 `breakpoint-hit`
- 读到参数值 `a=42`
- 单步返回 `end-stepping-range`
- 超过 `maxSessions` 被拒
- quiet 协议读到回显
- **quiet 协议第二次调用不串台**（不残留上次输出）
- `closeAll` 回收所有进程（包括子进程）

运行：`node tests/session.test.mjs`

## pwntools 会话（已实现）

`tools/pwn_session.py` + `protocol: 'pwn'`。桥接用 JSONL，因为纯文本没法区分
「发」和「收」两种操作。

**命令用简化语法**，不让 agent 写 JSON（每轮省下的 token 在长会话里累积可观）：

| 语法 | 语义 |
|---|---|
| `sendline:AAAA` | 发一行（自动加 `\n`），并顺带读一批回显 |
| `send:AAAA` | 发原始字节（不加换行） |
| `recv:1024` | 精确读 N 字节 |
| `recvuntil:\n` | 读到分隔符 |
| `close` | 关闭 |

**为什么值得单独一个协议**：`quiet` 只能靠"静默多久"猜结束，而 pwntools 能
**区分超时与 EOF**——在 pwn 题里把 EOF 当超时会让 agent 在程序已退出后继续等，
代价是整轮超时。实测 `/bin/true` 的 `recv` 正确返回 `[EOF]`，而活着的 `cat`
返回空但**不带** EOF 标记。

**踩的坑**：桥接启动立刻吐 `{"ready":true}`，而 spawn 是异步的——这行的数据事件
可能在第一次 `exec` 设置 pending **之后**才触发，于是被当成第一条命令的响应。
实测 `sendline:hello` 拿回来的是 ready 行。加了 `waitReady()` 显式消费握手。

## gdb 护栏（已实现）

`src/session-guard.ts`。裸跑 `gdb ./chall` 会进 REPL 阻塞到超时，这一轮时间和输出全废。
检测到就注入提示，引导改用 `session_start` 或 `-batch`。

**只提醒不拒绝**：有些 gdb 用法确实是一次性的（`--version`、`-batch -ex ...`），
而拒绝会让 agent 卡死。判据刻意保守——宁可漏报让它超时一次自己学会，
也不要误报打断一次合法的 batch 调试。

判据单测 10 条覆盖：裸跑/带 cd/串联命令要命中；MI 模式、batch、`--version`、
`which gdb`、`strings | grep gdb`、`echo "gdb is great"` 都不能误报。
