# 奶虫 · 工具链清单（2026-11-15 更新）

全部经实测验证。跑在 Kali GNU/Linux 2026.2 / Python 3.14.6。
重型工具统一装在独立 venv：`/root/proj/agents/venvs/aisec/bin/`（物理位置 `/mnt/extra/agents`）。

## ⚠️ 三个必读的坑

**1. Python 版本**。系统 `python3` 是 3.14，老包没有预编译轮子，源码构建会挂在
`ast.Str has no attribute`（3.12 起移除）。所以：

- 系统级装包只用 `apt-get install python3-xxx`
- pip 必须带 `--only-binary=:all:`，否则大概率失败
- 装不动的（angr/garak/pyrit/snyk-agent-scan）一律进 venv，用 `python3.13 -m venv`

**2. debian 占包**。`pypdf`、`RapidFuzz` 等被 apt 装过但无 RECORD 文件，pip 想接管会报
`Cannot uninstall ... no RECORD file was found`。这不是缺包，是包管理冲突——解法是 venv，不是 `--force`。

**3. 磁盘**。20G 新盘挂在 `/mnt/extra`，`/root/proj/agents` 已迁过去并软链。
`fstab` 用 `nofail` 挂载，写盘前确认 `df -h /mnt/extra` 正常。garak 的依赖链吃掉 5.9G。

## Crypto

- 系统：`z3`（约束求解）、`Crypto` pycryptodome 4.4.0、`gmpy2`、`sympy`、`ecdsa`、`hashcat`、`john`
- venv：`fpylll` 0.6.4（LLL/BKZ 格基约简）、`cypari2`（PARI/GP 绑定，替代 sage 的数论与代数）
- `RsaCtfTool`（venv，入口 `RsaCtfTool` / `rsacrack`）—— 75 种 RSA 攻击：
  wiener / boneh_durfee / fermat / hastads / common_modulus / lattice / z3_solver 等。
  实测 128 位 n 默认攻击集秒级恢复私钥。
  **不要加 `--attack all`**：会走 factordb 联网查询，外网受限时长时间重试到超时。
- `sage` 不装：`apt-get install sagemath` 要拉 985 个包，体积与编译时间不可接受。
  `fpylll` + `cypari2` 已覆盖格运算与数论两块核心，剩下极少数依赖 sage 特有构造的题
  再用在线 sagecell 兜底。

## Reverse

- 静态：`ghidra`、`radare2`/`r2`、`rizin`、`objdump`、`readelf`、`nm`、`capstone`、`fontTools`
- 动态：`gdb`、`strace`、`ltrace`
- 符号执行：`angr` 10.0.7 + `unicorn`（venv），实测可载入并推进状态
- 辅助：`binwalk`、`upx`

## Pwn

- `py:pwn` pwntools 4.15.0、`checksec`、`ROPgadget`、`one_gadget`、`patchelf`
- 调试 `gdb`；跨架构 `qemu-x86_64` / `qemu-aarch64` / `qemu-arm`；连接 `socat`
- 缺 `ropper`（依赖冲突）：`ROPgadget` 完全覆盖其功能

## Misc

- 隐写：`steghide`、`zsteg`、`binwalk`、`foremost`
- 取证：`exiftool`、`vol`（volatility3）
- 流量：`tshark`、`tcpdump`
- 通用：`file`、`7z`、`unzip`、`convert`

## Web

- `ffuf`、`gobuster`、`dirsearch`、`sqlmap`、`nuclei`、`nmap`、`curl`

## AI 安全（venv 内）

- `garak` 0.9.post2 —— LLM 探针集，入口 `venv/bin/python -m garak`
- `pyrit` 1.2.0 —— 多轮红队编排。**已从 `kind: subagent` 改成 `kind: cli`**：
  DSH 侧没有 pyrit 这个 subagent provider，原形态永远不会就绪。真实形态是
  「客户端 + 后端服务」，用前先 `pyrit_scan start-server`
- `promptfoo` —— 系统级可用
- 注意：pyrit 要 `mcp>=2.2`，snyk-agent-scan 装了 `mcp 1.30`，二者依赖冲突，
  但实测 pyrit 仍可正常导入

## MCP 安全

- `corvus`（系统级）
- `snyk-agent-scan`（venv）—— 即原 `mcp-scan`，上游改名了，旧名只打印改名警告就退出

## registry 现状（26 个候选）

```
ai-security    promptfoo, garak, pyrit
binary-reverse checksec, rabin2, radare2, rea, toolfuzz, cyberstrike-ghidra
code-audit     semgrep
crypto         sslyze, rsacrack
internal-ad    cyberstrike-nmap, enum4linux-ng
mcp-security   corvus, mcp-scan
misc           binwalk, zsteg, steghide
post-exploit   adaptix
pwn            ropgadget, one-gadget
web-pentest    cyberstrike-sqlmap, cyberstrike-dirsearch, nuclei, strix
```

本次新增：`pwn` 2 个、`misc` 3 个、`crypto` 的 `rsacrack`；`garak` 修好、`mcp-scan` 指向新包、`pyrit` 改形态。

## 剩下的缺口（已评估，不做）

- **`adaptix`**：PyPI 上的 `adaptix` 是**函数式编程库**（`Dumper`/`Chain`/`AdornedRetort`），
  不是 AdaptixC2 框架——两者同名不同物，误装会让 registry 把它判成可用。已卸载。
  真 AdaptixC2 是 Go/Rust 项目需自行编译，且 CTF 解题用不上 C2，优先级最低。
- **`sage`**：985 个依赖包，放弃（见上）
- **`ropper`**：依赖冲突，`ROPgadget` 完全覆盖


---

## 外部项目评估（2026-11-19）

按奶虫的**通用渗透**定位评估（不只是 CTF），五个项目里两个已落地、一个备料、两个仅方法论价值。

### 已落地：Claude-BugHunter（83 skills）

`github.com/elementalsouls/Claude-BugHunter` —— 681 份公开 HackerOne 报告提炼的漏洞模式。
**83 个 skill 已全部导入 `/root/proj/home/skills/`**（标准 `SKILL.md` 格式，DSH 的
`skill-filesystem` 默认扫描 `<dshHome>/skills`，无需改配置）。实测 agent 已能看到
58 个 `hunt-*` skill。

覆盖：hunt-sqli/xss/ssrf/idor/ssti/xxe/csrf/cors/race-condition/oauth/saml/jwt/ldap/
websocket/race-condition/shadow-api/spa-api/springboot/laravel/nextjs/nodejs/…
外加 `cloud-iam-deep`、`m365-entra-attack`、`okta-attack`、`vmware-vcenter-attack`、
`enterprise-vpn-attack`、`hunt-sharepoint`、`apk-redteam-pipeline` 等企业平台链。

同时提取了它的 **7-Question Gate** 验证纪律，翻成 CTF 语境落在 `SUBMIT-GATE.md`，
其中三条（Body-Diff / 唯一性 / 可重放）已嵌入编排器每轮 prompt。

### 已落地：Cloud-Bucket-Leak-Detection-Tools

`github.com/UzJu/Cloud-Bucket-Leak-Detection-Tools` v0.4.0 —— 阿里云/腾讯云/华为云/AWS
四家对象存储桶的公开读、可写、桶名悬空（可劫持）判定。
装在 `agents/Cloud-Bucket-Leak-Detection-Tools-main/`，已注册为 `cloud-bucket`
agent（`web-pentest` 方向，priority 25）。

注意 `requirements.txt` 锁了 `cffi==1.15.1`（3.13 无轮子），依赖是逐个补的：
loguru / prettytable / oss2 / cos-python-sdk-v5 / boto3 / esdk-obs-python。

### 备料未装：nukerat（post-exploit）

`github.com/nukeratframework/nukerat` —— TypeScript 写的后渗透/C2 框架，
覆盖 active-directory / cobalt-strike / edr-bypass / evasion / lateral-movement。
源码已拉到 `agents/nukerat-main/`。

**未安装的原因**：`install/linux.sh` 要装整套交叉编译链
（binutils-aarch64-linux-gnu、binutils-mingw-w64-{i686,x86-64}、gcc/g++ 交叉工具链、
cargo、rustc、golang-go、gtk-3-bin、bubblewrap），约 1–2G、十几分钟，
且脚本 `set -e` 中途失败会留下半装状态。需要时手动：

```bash
cd /root/proj/agents/nukerat-main && bash install.sh server   # 或 client / all
```

这是 `post-exploit` 方向的正解——registry 里那个 `adaptix` 条目仍未装
（PyPI 的 `adaptix` 是同名函数式编程库，已确认卸载）。

### 仅方法论：heretic

`github.com/p-e-w/heretic`（41.9k★）—— 训练无关的模型修改，通过 abliteration
移除拒绝方向、抑制套话、降低谄媚。

**不可用**：需要本地模型权重 + GPU，我们走 DeepSeek API 拿不到权重。
**方法论价值**：它的「提取拒绝方向向量并正交投影」思路，是 `ai-security` 方向
评估模型安全对齐强度的标准做法；将来若跑本地开源模型可直接用。

### 仅语料：jailbreaks

`github.com/togg53192-cmd/jailbreaks` —— 32 份完整 prompt，覆盖 26+ 模型
（DeepSeek V3/V4、GLM、Kimi、Qwen、Gemma、Claude、Gemini、Grok、Mistral、Ollama Modelfile）。

**对自己没用**（DeepSeek 对安全任务没在拒），但作为 **`ai-security` 方向的攻击
payload 语料库**有价值：目标是 LLM 应用时，这些就是现成的越狱/注入变体。
