#!/usr/bin/env python3
"""奶虫 · 单题编排器（状态机 + 时钟 + 预算 + 两阶段假设）

解决的是主控自身缺的四样东西——它们都不是知识问题，靠提示词治不好：

1. **时钟感**：每轮把「现在几点、还剩多久、本题截止」写进上下文。
   实测过它开赛五分钟了还以为没开赛。
2. **收敛**：每轮必须回答「本轮排除了哪条路」，否则不许进入下一轮。
   实测过它在「detail 接口 404」上打转四分多钟，而正确答案是这个接口本来就不该用。
3. **大胆猜测**：连续无进展就强制切换阶段——不再是「继续想」，
   而是「提出至少两条可证伪的假设，先打最快能证伪的那条」。
4. **上下文压缩**：每轮只带上一轮的结论摘要，不带原始日志。
   实测过上下文涨到 834KB，一轮调用要几分钟。

阶段规则（这就是「先收敛，卡住则大胆猜测然后证伪」的代码化）：

    converge ──(连续 2 轮无新证据)──▶ guess
       ▲                                │
       └──(任一假设被确认/拿到新证据)────┘

用法：
    python3 orchestrator.py --challenge AUTHORED-xxx --deadline-min 45
"""
from __future__ import annotations

import argparse
import fcntl
import json
import os
import re
import shlex
import signal
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone

from pydantic import ValidationError

from observation import Observation, ObservationPool, parse_observations
from models import Excluded, Hypothesis, Invariant, RoundResult, StateView, check_stall
from scopegate import Scope, ScopeGate
from store import Store
try:
    import runner as execlayer
except Exception:  # 执行层缺失不应阻断编排
    execlayer = None  # type: ignore[assignment]
try:
    from graph import AttackGraph
except Exception:  # kuzu 不可用时不阻断编排
    AttackGraph = None  # type: ignore[assignment]

PROJ = "/root/proj"
WORK_ROOT = "/root/proj/workspace"


def _store_brief(root: str, limit: int = 12) -> tuple[dict, list[dict]]:
    """取当前资产概况。存储层不可用时返回空——它是辅助视图，不该阻断解题。"""
    if not root:
        return {}, []
    try:
        st_ = Store(root)
        return st_.summary(), st_.untested_assets()[:limit]
    except Exception:
        return {}, []


def _graph_brief(root: str, limit: int = 6) -> tuple[dict, list[dict]]:
    """取攻击链概况。图库不可用时返回空——它是辅助视图，不该阻断解题。"""
    if not root or AttackGraph is None:
        return {}, []
    try:
        g = AttackGraph(root)
        if not os.path.exists(g.db_dir):
            g.build()
        return g.summary(), g.chokepoints(limit)
    except Exception:
        return {}, []


def _load_scope(path: str) -> dict:
    """读授权范围。读坏了就返回空 dict——闸那边是默认拒绝，不会因为这里失败而放行。"""
    if not path:
        return {}
    try:
        return Scope.load(path).model_dump()
    except Exception as exc:
        print(f"[orch] 警告：范围文件读取失败（{exc}），本轮不注入边界；Rego 闸仍默认拒绝", flush=True)
        return {}
STATE_DIR = "/root/tpctf/orchestrator"

# 运行锁句柄。模块级持有，保证 flock 活到进程退出。
_RUN_LOCK = None
OVERLAY = "/root/tpctf/overlay.yml"
# overlay 是可选增强：文件不在就不传，而不是让 DSH 启动失败
PATCH = f"--patch {OVERLAY} " if os.path.exists(OVERLAY) else ""
AGENT_DIR = "/root/tpctf/agents"
# 领域分类 → 领域规格文件。领域规格是「角色 + 假设模板 + 失败模式 + 验证纪律」，
# 这是专业化真正落地的地方：不是给同一份 prompt 换工具，而是换一整套先验。
DOMAINS = {
    "web": "web", "wapp": "web",
    "reverse": "reverse", "re": "reverse",
    "pwn": "pwn", "binary": "pwn",
    "crypto": "crypto", "cryptography": "crypto",
    "misc": "misc", "forensics": "misc", "stego": "misc",
    "ai": "ai-security", "llm": "ai-security", "ai-security": "ai-security",
}
BEIJING = timezone(timedelta(hours=8))

# 连续多少轮没有新证据就切换阶段。2 是实测出来的：一轮往往是"读材料"，
# 两轮还没产出就说明这条路走不通了。
CONVERGE_PATIENCE = 2
# 单题硬上限：5 小时的比赛里，一题卡超过 45 分钟就该让位给别的题。
DEFAULT_DEADLINE_MIN = 45
# 单轮墙钟上限。一轮之内上下文照样会膨胀（轮间重置治不了这个），
# 而且时钟注入只在轮首有效，跑太久模型的时间感就漂了。300 秒是实测刻度：
# 单轮墙钟可用环境变量覆盖（调试/大任务用）。
#
# 默认从 300 秒提到 900 秒。原因不是"给模型更多思考时间"，而是实测发现 300 秒
# 连**侦察**都做不完：基线里四道简单题分别耗时 499/502/512/510 秒，而真实赛题
# （内核逆向、Web 指纹枚举）单单"搞清楚这东西是什么"就要 10 分钟以上。300 秒
# 会在 ROUND.md 写出前把进程杀掉，整轮产出全丢——这比跑得慢得多得多。
ROUND_WALL_SECONDS = int(os.environ.get("ORCH_ROUND_WALL", "900"))
# 无输出超时：日志文件连续这么久没有新字节，判定卡住。
# 为什么要两个判据：总时长管"跑太久"，无输出管"卡死"——后者才是真正烧钱的那种。
# 180 秒会误杀正常的长工具调用（volatility 扫内存、angr 符号执行都可能静默数分钟）。
ROUND_IDLE_SECONDS = int(os.environ.get("ORCH_ROUND_IDLE", "420"))
# 收到 SIGTERM 后给多久收尾（让它把 ROUND.md 写完）
GRACEFUL_SECONDS = int(os.environ.get("ORCH_GRACE", "20"))
# 假设的证伪条件少于这个长度就视为敷衍——「未写」「待定」不算，
# 编排器会把质量不足的假设标出来，下一轮 prompt 里提示。
MIN_FALSIFY_LEN = 8


def now() -> datetime:
    return datetime.now(BEIJING)


def load_state(path: str) -> StateView | None:
    """读状态文件并迁移成当前契约。

    返回 None 表示"没有历史状态"，由调用方建新的。
    读坏了的文件不静默吞掉——抛出去，因为一份读不懂的状态会让后续每一轮
    都工作在错误的假设上，比直接失败更贵。
    """
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as fh:
        raw = json.load(fh)
    return StateView.from_raw(raw)


def save_state(path: str, st: StateView) -> None:
    """原子写：写临时文件 → fsync → 改名。

    早先是 `open(path, "w")` 直接覆写。SIGTERM / 磁盘满 / 断电落在写的中途，
    状态文件就是半截 JSON；下次 load_state 按 fail-loud 抛 JSONDecodeError，
    整题的历史假设与排除路径一起作废。

    `os.replace` 在同一文件系统内是原子的：读到的要么是旧内容、要么是新内容，
    不存在中间态。先 fsync 再改名，否则断电后可能出现"文件名换了、内容还在
    页缓存里"的空文件。

    另外剥掉 api_key：它是运行时凭据，不该跟着状态文件落盘。
    """
    payload = st.model_dump() if hasattr(st, "model_dump") else dict(st)
    payload["api_key"] = ""
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)
    tmp = f"{path}.tmp.{os.getpid()}"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


def acquire_run_lock(state_path: str):
    """同一个任务同时只允许一个编排进程。

    为什么需要：save_state 的原子性只保证「单次写入不产生半截文件」，
    完全不解决两个进程交替写同一份状态。实测过的现场：

      - `round` 在 6→9 之间乱跳，出现 r8 目录只有 MEMORY.md、r9 目录直接是空的
      - 一个进程起的 agent 读到的是另一个进程几分钟前写的 excluded 列表，
        prompt 里把「上一轮没有写 ROUND.md」当成模型自己的失败
      - dsh 侧报 `session "..." : flush on a closed handle`

    起锁失败直接退出，不做「等一下再试」——两个编排器并行从来不是有意为之，
    都是前一个没被真正杀掉（`| tail` 之类接管道时，杀 shell 不杀 python 子进程）。

    返回的句柄必须活到进程结束（flock 随 fd 关闭释放）。
    """
    lock_path = state_path + ".lock"
    # 用 a+ 而不是 w：w 会在 open 时就 truncate，把持锁者的 pid 抹掉；
    # 而 a+ 在未拿到锁的情形下必须能读出对方 pid。
    fh = open(lock_path, "a+", encoding="utf-8")
    try:
        fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        fh.seek(0)
        holder = fh.read().strip() or "?"
        fh.close()
        return None, holder
    fh.seek(0)
    fh.truncate()
    fh.write(str(os.getpid()))
    fh.flush()
    return fh, str(os.getpid())


def salvage_from_log(log_path: str, max_chars: int = 3000) -> str:
    """从被中断那轮的日志里回捞它最后在做什么。

    存在理由：进程被杀时 `ROUND.md` 往往还没写。实测一次 300 秒墙钟超时，
    `round` 记到 1 但假设 0、产物不存在——那一轮的工作完全消失。
    日志里其实留下了大量线索（reasoning 和工具输出），捞出来比什么都没强。

    只取尾部、只保留有信息量的行：日志里混着大量 `dsh: reasoning:` 前缀和空行。
    """
    try:
        size = os.path.getsize(log_path)
        with open(log_path, "rb") as fh:
            fh.seek(max(0, size - max_chars * 4))
            raw = fh.read().decode("utf-8", "replace")
    except OSError:
        return ""
    # 脱敏：日志里混着 ANSI 转义、WAF 拦截页的整页 HTML、几百行的栈帧。
    # 原样回灌等于把噪音当上下文，模型会在堆栈里找规律。
    raw = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", raw)              # ANSI
    raw = re.sub(r"<script[\s\S]*?</script>|<style[\s\S]*?</style>", " ", raw, flags=re.I)
    raw = re.sub(r"<[^>]{1,200}>", " ", raw)                       # HTML 标签
    raw = re.sub(r"\b[0-9a-f]{16,}\b", "<hex>", raw)              # 长哈希
    lines = []
    in_trace = 0
    for line in raw.splitlines():
        t = re.sub(r"[ \t]{2,}", " ", line.strip())
        if t == "" or t == "dsh: reasoning:":
            continue
        if t.startswith("[" + "run.sh" + "]") or t.startswith("[llm-deepseek"):
            continue
        # 栈帧只留首行信号，其余丢掉：几十行 File/at 对判断"在做什么"没帮助
        if re.search(r"^\s*(File \"|at [\w.$]+\(|#\d+ 0x)", t):
            in_trace += 1
            if in_trace > 3:
                continue
        else:
            in_trace = 0
        lines.append(t[:300])
    tail = "\n".join(lines[-25:])
    return tail[-max_chars:]


ATTACH_ROOT = "/root/tpctf/attachments"
# 交付物候选文件名。
#
# 原来是 ANSWER.txt / FLAG.txt —— 那是 CTF 的语义（一题一答案）。
# 真实渗透的产出是「发现」与「证据」，所以主档名换成 findings/report/evidence，
# 同时保留 answer 系列以兼容旧状态目录里已有的文件。
DELIVERABLE_FILES = (
    "FINDING.md", "FINDINGS.md", "finding.md", "findings.md",
    "REPORT.md", "report.md",
    "EVIDENCE.md", "evidence.md",
    "ANSWER.txt", "answer.txt",
)
# 占位符判据：这些内容等于没写答案
PLACEHOLDER_RE = re.compile(r"^(todo|tbd|unknown|待定|无|none|n/?a|-+|\?+|\.\.\.)$", re.I)


def detect_completion(challenge: str, current_ws: str,
                      hypotheses: list[dict] | None = None) -> tuple[bool, str, str]:
    """扫 workspace，看有没有产出**够格**的交付物。

    存在理由（基线 v1 实测）：四道简单题耗时 499/502/512/510 秒，全部卡在
    deadline 的 92% 附近——说明它们不是判断做完而停，是被掐停的。

    ## 早先版本的两个致命误判

    1. **扫了材料目录**。`attachments/<target>/` 是放目标源码和附件的地方，
       如果审计的开源项目自带 REPORT.md / FINDING.md，第 1 轮刚跑完就判定
       已完成并退出。现在只扫本轮的 orch-* 工作区。

    2. **零校验**。只要文件存在、长度 >= 4、首行不是占位符就结题，
       模型把"疑似存在越权"写进 FINDING.md 也会被放行。
       现在要求**至少一条 confirmed 假设**——没有实证的猜测不算完成。

    这两条都是"响亮地错"的反面：系统安静地提前退出，人以为它做完了。
    """
    # 硬门禁一：必须有实证。没有 confirmed 的假设，写再多文件也不算完成。
    if hypotheses is not None:
        if not any(h.get("status") == "confirmed" for h in hypotheses):
            return False, "", ""

    roots = [current_ws]
    try:
        for name in os.listdir(WORK_ROOT):
            if name.startswith(f"orch-{challenge}-"):
                roots.append(os.path.join(WORK_ROOT, name))
        # 注意：**不再扫 ATTACH_ROOT**。那里是目标材料目录，
        # 里面的 REPORT.md 属于被审计的项目，不是本轮的产出。
    except OSError:
        pass
    for ws in roots:
        for fn in DELIVERABLE_FILES:
            p = os.path.join(ws, fn)
            if not os.path.exists(p):
                continue
            try:
                content = open(p, encoding="utf-8", errors="replace").read().strip()
            except OSError:
                continue
            if len(content) < 4:
                continue
            if PLACEHOLDER_RE.match(content.splitlines()[0].strip()):
                continue
            return True, f"{os.path.basename(ws)}/{fn}", content
    return False, "", ""


MEMORY_FILE = "MEMORY.md"


def render_memory(st: StateView) -> str:
    """把跨轮积累渲染成一份人可读的记忆文档。

    为什么不让下一轮直接读 state.json：那是给机器看的诊断快照，字段多、噪音大。
    Archon 的做法是维护几份「全局状态文档」——整体阶段、逐项状态、局部结论——
    并且明确"agent 只加载与当前任务相关的材料，避免被无关信息干扰"。
    这里同理：MEMORY.md 只放三类东西（已确认/已排除/悬而未决），其他一概不写。
    """
    confirmed = [h for h in st.hypotheses if h.status == "confirmed"]
    refuted = [h for h in st.hypotheses if h.status == "refuted"]
    open_hyps = [h for h in st.hypotheses if h.status == "open"]

    lines = [f"# 任务记忆 · {st.challenge}", ""]
    lines.append(f"轮次 {st.round} · 阶段 {st.phase} · 累计裁决 {st.verdicts_total}")
    lines.append("")

    lines.append("## 已确认（不要重复验证）")
    if confirmed:
        for h in confirmed:
            ev = f" —— 依据：{h.evidence}" if h.evidence else ""
            lines.append(f"- {h.statement}{ev}")
    else:
        lines.append("- （无）")
    lines.append("")

    lines.append("## 已排除（不要回头再走）")
    if st.excluded:
        for e in st.excluded[-15:]:
            ev = f" —— 依据：{e.evidence}" if e.evidence else ""
            lines.append(f"- {e.path}{ev}")
    elif refuted:
        for h in refuted:
            ev = f" —— 依据：{h.evidence}" if h.evidence else ""
            lines.append(f"- {h.statement}{ev}")
    else:
        lines.append("- （无）")
    lines.append("")

    lines.append("## 悬而未决（要验，别提完就放着）")
    if open_hyps:
        for h in open_hyps[-8:]:
            fb = f" —— 证伪方式：{h.falsify_by}" if h.falsify_by else " —— （没写证伪方式）"
            lines.append(f"- {h.statement}{fb}")
    else:
        lines.append("- （无）")
    lines.append("")

    if st.stall_reasons:
        lines.append("## 停滞告警")
        for r in st.stall_reasons:
            lines.append(f"- {r}")
        lines.append("")

    if st.recent_summaries:
        lines.append("## 最近几轮落点")
        for s_ in st.recent_summaries[-3:]:
            lines.append(f"- {s_}")
        lines.append("")
    # ── 推理线索：传"为什么"，不只是"是什么"
    #
    # 早先 MEMORY.md 里只有结论（确认了什么、排除了什么、待验证什么）。
    # 模型看不到"上一轮是什么让它怀疑这里"——而理解这个业务在做什么是最贵的一步，
    # 每轮重建就等于每轮从零猜。
    # Reflexion 的做法就是把"为什么失败"也存下来，这里同理存"为什么想到"。
    obs_recent = (st.get("observations") or [])[-8:]
    if obs_recent:
        lines.append("## 最近的观察（未验证）")
        lines.append("")
        for o in obs_recent:
            mark = {"confirmed": "✓", "likely": "~", "speculative": "?"}.get(
                str(o.get("confidence", "speculative")), "?")
            lines.append(f"- {mark} [{o.get('kind','note')}] {str(o.get('text',''))[:200]}")
        lines.append("")
        lines.append("> 这些是**观察**不是结论。但如果某条解释了当前的困惑，值得顺着看。")
        lines.append("")


    return "\n".join(lines)


def write_memory(st: StateView, ws: str) -> str:
    """把记忆文档写进本轮 workspace，下一轮由 prompt 读它。"""
    text = render_memory(st)
    path = os.path.join(ws, MEMORY_FILE)
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
    except OSError:
        return ""
    return text


def load_memory(challenge: str) -> str:
    """取最近一轮写下的 MEMORY.md（任意轮次取最新）。"""
    try:
        cands = [os.path.join(WORK_ROOT, n) for n in os.listdir(WORK_ROOT)
                 if n.startswith(f"orch-{challenge}-")]
    except OSError:
        return ""
    best, best_mtime = "", 0.0
    for d in cands:
        p = os.path.join(d, MEMORY_FILE)
        try:
            mt = os.path.getmtime(p)
        except OSError:
            continue
        if mt > best_mtime:
            try:
                best = open(p, encoding="utf-8").read()
                best_mtime = mt
            except OSError:
                pass
    return best


MODES = {"blackbox": "blackbox", "whitebox": "whitebox"}


def load_mode_spec(mode: str) -> str:
    """读方法论规格（黑盒 / 白盒）。

    与 domain 规格的区别：domain 决定"打什么"（web / binary / crypto），
    mode 决定"以什么前提打"——黑盒只有外部可见信息，白盒有源码与配置。
    两者的工作顺序、判定标准、反模式都不同，所以是两份独立规格而不是一个参数的两种取值。
    """
    if not mode:
        return ""
    fn = MODES.get(mode.strip().lower())
    if not fn:
        return ""
    try:
        with open(os.path.join(AGENT_DIR, f"{fn}.md"), encoding="utf-8") as fh:
            return fh.read().strip()
    except OSError:
        return ""


def load_domain_spec(domain: str) -> str:
    """读领域规格。找不到就返回空——宁可没有，也不要塞一段错的角色设定。"""
    if not domain:
        return ""
    fn = DOMAINS.get(domain.strip().lower())
    if not fn:
        return ""
    path = os.path.join(AGENT_DIR, f"{fn}.md")
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read().strip()
    except OSError:
        return ""


def material_index(challenge: str, limit: int = 40) -> str:
    """附件清单：只给路径/大小/类型，不把内容塞进 prompt。

    这是 Anthropic 那套 just-in-time retrieval 的落地——Claude Code 也是靠
    head/tail 取片段而不是整文件入上下文。context rot 是结构性的（O(n^2) attention），
    窗口再大也逃不掉，唯一解是不让内容进来。
    """
    root = f"/root/tpctf/attachments/{challenge}"
    if not os.path.isdir(root):
        return ""
    rows: list[str] = []
    for dirpath, _dirs, files in os.walk(root):
        for fn in sorted(files)[:limit]:
            fp = os.path.join(dirpath, fn)
            try:
                sz = os.path.getsize(fp)
            except OSError:
                continue
            rel = os.path.relpath(fp, root)
            hint = ""
            if sz > 200_000:
                hint = "（大文件：不要整读，用 head/grep/file 取片段，或派 subagent）"
            rows.append(f"  - {rel}  {sz}B{hint}")
    if not rows:
        return ""
    return "**附件索引**（只给了标识，按需取片段）\n" + "\n".join(rows[:limit])


def _pick(obj, key, default=None):
    """同字段双形态取值。

    状态里的列表元素在内存中是 Pydantic 模型（excluded / invariants / observations），
    从 JSON 读回来是 dict。`obj.get()` 只对后者成立——早先 build_prompt 直接
    `e.evidence`，跑完两轮存盘后第三轮必 AttributeError，已踩一次。
    """
    return obj.get(key, default) if isinstance(obj, dict) else getattr(obj, key, default)


def build_prompt(st: dict) -> str:
    """本轮的任务书。刻意短——只带结论，不带历史日志。"""
    left = st["deadline_ts"] - time.time()
    left_min = max(0, int(left // 60))
    phase = st["phase"]
    confirmed = [h for h in st["hypotheses"] if h["status"] == "confirmed"]
    refuted = [h for h in st["hypotheses"] if h["status"] == "refuted"]
    open_h = [h for h in st["hypotheses"] if h["status"] == "open"]

    idx = material_index(st["challenge"])
    mode_spec = load_mode_spec(st.get("mode", ""))
    spec = load_domain_spec(st.get("domain", ""))
    lines = [
        f"# 第 {st['round']} 轮 · 目标 {st['challenge']}"
        + (f"（{st['domain']} 方向）" if st.get("domain") else ""),
        "",
        f"**时钟**：现在 {now().strftime('%H:%M')}（北京时间），"
        f"本题剩余 **{left_min} 分钟**，截止 {datetime.fromtimestamp(st['deadline_ts'], BEIJING).strftime('%H:%M')}。",
        f"**阶段**：`{phase}` —— "
        + ("走有明确依据的路径，本轮结束时必须说明排除了什么。"
           if phase == "converge"
           else "不再沿着老路想。提出至少两条**可证伪**的新假设，先打最快能被证伪的那条。"),
        "",
    ]

    # 停滞告警：Archon 的经验是 stall 只在连续多轮上表现为模式，
    # 所以必须由外部（这里）在每轮开头当面点出，agent 自己看不见这个趋势。
    if st.get("stall_reasons"):
        lines += [
            "⚠️ **检测到停滞**，上一轮结束时命中以下判据：",
            *[f"  - {r}" for r in st["stall_reasons"]],
            "",
            "**本轮不许沿旧路推进**。要么给出一个能一次否掉当前主线的新观测，"
            "要么明确写出「这条主线已死，理由 X」，然后换一条完全不同的路径。"
            "继续在同一个方向上做小幅调整 = 浪费整轮。",
            "",
        ]

    if st.get("task_prompt"):
        lines += ["## 本目标", st["task_prompt"], ""]

    # 资产概况：agent 只看得到本轮材料，看不到"整个作业已经发现了什么、
    # 还有哪些完全没碰"。这两段把它缺失的全局视角补上。
    if st.get("store_root"):
        brief, untested = _store_brief(st["store_root"])
        if brief.get("assets"):
            lines += [
                "## 资产概况（来自扫描产物库）",
                f"- 资产 {brief.get('assets',0)} 个 · 发现 {brief.get('findings',0)} 条"
                f" · 证据 {brief.get('evidence',0)} 条 · 关系 {brief.get('edges',0)} 条",
            ]
            if untested:
                lines.append(f"- **完全没碰过的资产 {len(untested)} 个**：")
                for u in untested:
                    lines.append(f"  - {u['asset_id']}（{u['kind']}）")
                lines.append("")
                lines.append("优先考虑这些空白点，而不是回到已有发现上做增量。")
            lines.append("")

    # 攻击链概况：把"哪几条路已经串起来了"和"哪些节点是必经之路"给它。
    # agent 自己看不到跨资产的链条，这是图库相对逐条证据的唯一增量。
    if st.get("store_root"):
        gsum, chokes = _graph_brief(st["store_root"])
        if gsum.get("pivots"):
            lines += [
                "## 攻击链概况（资产之间的关系图）",
                f"- 已知跳转边 {gsum['pivots']} 条"
                f" · 孤立资产 {gsum.get('isolated',0)} 个",
            ]
            if chokes:
                lines.append("- **必经节点**（被最多路径穿过，打穿它们收益最高）：")
                for c in chokes:
                    lines.append(f"  - {c['asset_id']}（{c['paths_through']} 条路径）")
            lines.append("")

    # 作战区：这是事实陈述，不是道德要求。
    #
    # 早先这里写的是「越界即违规，不是尽量避开」「碰范围外的东西要写清依据」——
    # 结果是模型把注意力花在自我审议授权合法性上，真机第一轮就产出了
    # 「自行填 scope 等于伪造授权」这种推理，第二轮又把 SSRF 的带外回调
    # 判成"必须碰范围外资产"直接跳过。授权是操作者的事，模型只需要坐标。
    if st.get("scope"):
        sc = st["scope"]
        lines += ["## 作战区", ""]
        if sc.get("cidrs"):
            lines.append("- 允许的网段：" + ", ".join(sc["cidrs"]))
        if sc.get("hosts"):
            lines.append("- 允许的域名：" + ", ".join(sc["hosts"]) + "（精确匹配，不含子域）")
        if sc.get("tools"):
            lines.append("- 允许的工具：" + ", ".join(sc["tools"]))
        lines += [
            "",
            "区内的东西都可以打，**包括会造成危害的操作**——内网探测、云元数据、"
            "协议走私、写操作、竞态、提权注入、带外回调，都是标准测试内容，"
            "不需要额外请示，也不该因为「可能有危害」而跳过。",
            "",
            "**方向要分清**：闸管的是「我的 socket 往哪里发」；"
            "`baseUrl=http://127.0.0.1:6379` 这类是发给目标的参数，请求由目标发出，"
            "我方出站目的地仍是目标本身——后者是攻击面，不是越界。",
            "",
            "会造成危害的操作照做，但要做成可收拾的：自造样本、记原值、测完复原、前后留快照。"
            "见到真实用户的隐私数据时停手并标注，不抄录不扩散。",
            "",
        ]

    # 已排除路径：这是跨轮省时间最有效的一块，之前只活在单轮 ROUND.md 里。
    #
    # 状态从 JSON 读回来时这里是 dict，内存里是 Pydantic 模型——两种都得认。
    # 之前只按属性访问，第二轮跑完存盘、第三轮 build_prompt 直接 AttributeError。
    if st.get("excluded"):
        lines += ["## 已排除的路径（不要回头）"]
        for e in st["excluded"][-12:]:
            if isinstance(e, dict):
                path, evidence = e.get("path", ""), e.get("evidence", "")
            else:
                path, evidence = getattr(e, "path", ""), getattr(e, "evidence", "")
            ev = f" —— 依据：{evidence}" if evidence else ""
            lines.append(f"- {path}{ev}")
        lines += ["", "回到这些路径上等于承认上一轮的结论是错的；"
                  "如果你确实要回头，先给出推翻原依据的新观测。", ""]

    # 系统不变量：假设的生成源，比"已排除路径"更靠近上游。
    #
    # 加这一块的直接原因：真机 15 条假设里 13 条是「某接口是否缺某校验」，
    # 一条都没碰状态机、资源归属、数据生命周期。不是模型不会想，是它没有可用的槽位——
    # 「已排除」只告诉它别再走哪儿，不告诉它还能往哪儿长。
    #
    # 未测出口必须显式列出来。真实教训：只测了 chapters/{n} 被 403 就认定
    # 「章节正文只有所有者能读」，而 AI 拼上下文、搜索、导出、统计这四个
    # 同样读正文的入口从没进过测试范围。
    invs = st.get("invariants") or []
    if invs:
        lines += ["## 系统不变量（假设从这里长，不从漏洞清单长）"]
        for inv in invs[-12:]:
            stmt = str(_pick(inv, "statement", ""))
            stake = str(_pick(inv, "stake", ""))
            exits = [str(x) for x in (_pick(inv, "exits", []) or [])]
            tested = {str(x) for x in (_pick(inv, "tested", []) or [])}
            untested = [e for e in exits if e not in tested]
            lines.append(f"- {stmt}" + (f"（违反获益：{stake}）" if stake else ""))
            if untested:
                lines.append(f"  未测出口：{'、'.join(untested[:8])}")
        lines += ["", "**只测了部分出口不等于验证过这条不变量。** 优先打未测出口，"
                  "或在 ROUND.md 的 invariants 里补新的不变量。", ""]

    # 方法论先于领域：黑盒/白盒决定的是"凭什么下结论"，
    # 领域规格只决定"往哪儿看"。顺序反了会让领域细节盖过判定纪律。
    if mode_spec:
        lines += ["---", mode_spec, "---", ""]
    if spec:
        # 领域规格放在最前面：它是角色，不是参考材料。
        lines += ["---", spec, "---", ""]

    # 定额注入：只带最近的若干条，并且每条都截断。
    #
    # 这里曾经是全量平铺。跑满 20-40 轮后，几十条假设（statement ≤ 300 字 +
    # evidence ≤ 160 字）把 prompt 尾部挤出去——而「硬性要求」和「三道闸」
    # 恰恰在尾部。模型不是不遵守规则，是它根本没读到。
    # 结论按时间追加，越老的越不重要，所以从尾部取。
    def _clip(t: object, n: int) -> str:
        return re.sub(r"\s+", " ", str(t)).strip()[:n]

    lines += ["**已确认的结论**（不要重复验证）"]
    if len(confirmed) > 8:
        lines.append(f"（共 {len(confirmed)} 条，只列最近 8 条；完整清单见 MEMORY.md）")
    lines += [f"- {_clip(h['statement'], 160)}" for h in confirmed[-8:]]
    if not confirmed:
        lines.append("- （无）")
    lines.append("")

    lines += ["**已排除的方向**（不要再回头）"]
    if len(refuted) > 12:
        lines.append(f"（共 {len(refuted)} 条，只列最近 12 条）")
    lines += [
        f"- {_clip(h['statement'], 140)}  ← 因：{_clip(h.get('evidence', '已被观测否定'), 100)}"
        for h in refuted[-12:]
    ]
    if not refuted:
        lines.append("- （无）")
    lines.append("")

    # ── 让模型也提假设，不只是验证
    #
    # 早先"提假设"全是丞相（确定性代码）干的：盘哪些 claim 停在 hypothesis、
    # 哪些资产没测。这套规则能穷举**已知的缺口**，但提不出"这个业务的实现
    # 在什么条件下会不成立"——那需要读懂它在做什么。
    #
    # 这里不要求空想，而是给一个触发点：从你自己的观察里挑一条，问它
    # "如果这条成立，会引出什么问题"。
    lines += ["## 你自己提假设（不只是验证我给的）"]
    lines += [
        "除了下面列出的待验证项，**必须再提至少一条来自你自己观察的假设**。",
        "写法：`origin` 填你从哪儿看出来的（哪条观察、哪个接口、哪次对比），",
        "`falsify_by` 填什么样的观测能推翻它。",
        "**说不清 origin 的假设不要提**——那是套话，不是假设。",
        "",
    ]

    lines += ["**待验证的假设**"]
    if len(open_h) > 6:
        lines.append(f"（共 {len(open_h)} 条，只列最近 6 条）")
    lines += [
        f"- [{h['id']}] {_clip(h['statement'], 180)}\n  证伪条件：{_clip(h['falsify_by'], 120)}"
        for h in open_h[-6:]
    ]
    if not open_h:
        lines.append("- （无）")
    lines.append("")
    # 观察池：按三因子检索取前 8 条。**不是全量塞**——
    # 全量会立刻炸掉上下文，而 Generative Agents 的做法就是按
    # recency/importance/relevance 打分取 top-k。
    obs_pool = ObservationPool(decay_half_life_s=1800.0)
    for rec in (st.get("observations") or []):
        try:
            obs_pool.add(Observation(
                text=str(rec.get("text", "")),
                where=str(rec.get("where", "")),
                kind=str(rec.get("kind", "note")),
                confidence=str(rec.get("confidence", "speculative")),
                round=int(rec.get("round", 0)),
            ))
        except Exception:
            continue
    query = " ".join([st.get("target", ""), st.get("domain", ""), st.get("phase", "")])
    block = obs_pool.render_block(query, 8)
    if block:
        lines += [block, ""]

    if idx:
        lines += [idx, ""]
    if st.get("last_summary"):
        lines += ["**上一轮的结果**", st["last_summary"], ""]

    # 三项告警：把上一轮暴露的问题当面点出来，而不是让它自己发现。
    if st.get("last_timed_out"):
        lines += [
            "⚠️ **上一轮超时被强制收束**（超过 "
            f"{ROUND_WALL_SECONDS} 秒）。这说明你在某一步上耗太久——"
            "本轮请先把「最小可验证的一步」做完并写进 ROUND.md，不要一上来就铺开。",
            "",
        ]
    if st.get("format_errors"):
        lines += [
            "⚠️ **上一轮 ROUND.md 格式不合格**，具体问题：",
            *[f"  - {p}" for p in st["format_errors"][-6:]],
            "请按上面给的 JSON 结构重写；格式错误会被当成无效产出，本轮不算进展。",
            "",
        ]
    if st.get("low_quality_hypotheses", 0) >= 3:
        lines += [
            "⚠️ **假设质量不足**：累计 "
            f"{st['low_quality_hypotheses']} 条假设没写清「什么观测能证明它错」。"
            "本轮的每条假设都必须给出一个**能被一次请求或一次本地实验否定**的具体观测，"
            "写「待定」「需要进一步分析」等于没提。",
            "",
        ]

    # 规则部分：这是「强制」而不是「建议」的地方
    lines += [
        "## 本轮的硬性要求",
        "",
        "1. 结束时必须把结果写进 `ROUND.md`（见下），空着等于本轮作废。",
    ]
    if open_h:
        lines += [
            f"1.5 **先裁决上轮留下的 {len(open_h)} 条假设**，再谈新想法。"
            "裁决 = 真的去跑那个证伪实验，把实际观测写下来，然后判定 "
            "`confirmed` / `refuted` / `inconclusive`。"
            "只写「大概率是 X」不算裁决——没有观测就没有判定。",
        ]
    if phase == "converge":
        lines += [
            "2. 只走有明确依据的路径。**每一条走不通的路都必须写进 ROUND.md 的「排除了什么」，"
            "并给出一句话依据**——下一轮不会再走它。",
        ]
    else:
        lines += [
            "2. 必须提出 ≥2 条新假设，每条都要带「什么观测能证明它错」。"
            "然后**先执行最快能被证伪的那条**——猜测的价值在于快速否定，不在于一次猜对。",
        ]
    lines += [
        "3. 不要在已经确认的结论上重做验证，也不要回到已排除的方向。",
        "3.5 **产出答案就收束**：一旦把答案写进指定的答案文件，本轮结束就停，"
        "不要继续验证、不要继续排除、不要为了“更保险“再跑一轮。"
        "已经写出的答案等于本题完成。",
        "4. 时间不够就如实写「本轮没结论，卡在 X」——那比重复劳动有用。",
        "",
        "## ROUND.md 格式（必须写结构化 JSON）",
        "",
        "在 ROUND.md 里放一个 ```json 代码块，内容形如：",
        "",
        '```json',
        "{",
        '  "conclusion": "一句话：这轮有什么进展，或者卡在哪",',
        '  "verdicts": [{"id": "H1", "observation": "实测到了什么", "verdict": "refuted"}],',
        '  "excluded": [{"path": "哪条路走不通", "evidence": "依据（命令/地址/对照实验）"}],',
        # 不变量放在 hypotheses 前面：顺序本身就是引导。
        # 实测 15 条假设里 13 条都是「某接口是否缺某校验」这同一个形状，
        # 一条没碰状态机、资源归属、数据生命周期——因为槽位里只给了 hypotheses。
        '  "invariants": [{"statement": "系统承诺什么（一句断言，如「章节正文只能由作品所有者读到」）", '
        '"stake": "违反它谁获益", "exits": ["能触碰这条不变量的所有入口"], "tested": ["已验证的入口"]}],',
        '  "hypotheses": [{"statement": "新假设", "falsify_by": "什么观测能证明它错", "origin": "从哪看出来的"}],',
        # 观察字段必须出现在**格式示例**里，否则模型不会写。
        # 实测：prompt 正文加了「你自己提假设」的引导，但示例 JSON 里没有
        # observations，模型就严格按示例输出，一条观察都没交回——通道形同虚设。
        # 模型是照着示例写的，不是照着散文写的。
        '  "observations": [{"text": "我留意到什么现象（不是结论）", "where": "哪个目标/端点", '
        '"kind": "anomaly|pattern|question|seed|note", "confidence": "speculative|likely|confirmed"}],',
        '  "next": "下一步一句话"',
        "}",
        "```",
        "",
        "规则：",
        "- `verdict` 只能是 `confirmed` / `refuted` / `inconclusive` 三个值之一",
        "- 每条裁决必须有 `observation` —— **没有观测就没有裁决**",
        "- 每条假设必须有 `falsify_by`，且要具体到「一次实验就能否定」；写「待定」等于没提",
        "- `invariants` 是假设的来源。**一条不变量只测了 `exits` 里的一个入口，不算验证过**——"
        "把 `tested` 如实填上，下一轮会盯没测的出口",
        "- 字段缺失或类型不对会被判为格式错误，下一轮会点名要求你修正",
        "",
        "工作目录就是本轮的 workspace；目标材料（源码、配置、资产清单等）在 `/root/tpctf/attachments/<target>/`。",
        "本轮结论请写进 workspace 下的 `FINDING.md`（或 `REPORT.md` / `EVIDENCE.md`），"
        "写了就会被视为本轮交付完成；纯过程记录写 `ROUND.md`。",
        "",
        "## 下结论前必过三道闸（来自实战误报统计）",
        "",
        "1. **Body-Diff**：拿到一个像答案的值，先换一个输入看它变不变。"
        "不变化的多半是默认值或固定回显。实测踩过：所有输入下 marker 恒为 128，"
        "一度当成“输入生效“，实际是 hint 根本没跑。",
        "2. **唯一性**：这个值是否可能撞车？标记串有没有可能匹配到别的东西？"
        "时间差是不是单次采样？单次测得的时间差不作数，必须多轮交织采样。",
        "3. **可重放**：能不能写出从起实例到拿到该值的完整命令序列？写不出来 = 还没真拿到。",
        "",
        "这三条不是比赛规则，是**排除误报的通用纪律**：报给客户之前，"
        "任何一条过不去都意味着这条发现站不住。",
    ]
    return "\n".join(lines)


def extract_json_block(text: str) -> dict | None:
    """从 ROUND.md 里抽 ```json 块。

    优先结构化输出是 P1 的核心：正则解析 Markdown 已经静默失效过一次
    （`判定=refuted（…）。` 的括号让整串比对落空，裁决闭环一声不响地停摆）。
    结构化之后，格式错误可以被**检测到并报出来**，而不是变成"本轮无进展"。
    """
    # 先用宽松的标签匹配（大小写不敏感），再对内容做括号栈扫描。
    #
    # 早先是 `r"```json\s*\n(.*?)```"` 非贪婪匹配，两个坑：
    #   1. 模型在 observation 里贴了 Markdown 代码块 —— 内层 ``` 让匹配提前截断
    #   2. 写成 ```JSON 大写标签 —— 直接不匹配
    # 两者都会降级到 legacy 正则，而 legacy 丢 excluded，等于本轮排除全丢。
    #
    # 现在的做法：找到标签后**不靠结束标签**，而是从第一个 { 起做括号栈扫描，
    # 扫描到深度归零为止。内嵌的 ``` 和字符串里的花括号都不会干扰。
    for m in re.finditer(r"```[ \t]*(?i:json)[^\n]*\n", text):
        start = text.find("{", m.end())
        if start < 0:
            continue
        depth = 0
        in_str = False
        esc = False
        for i in range(start, len(text)):
            ch = text[i]
            if esc:
                esc = False
                continue
            if ch == "\\":
                esc = True
                continue
            if ch == '"':
                in_str = not in_str
                continue
            if in_str:
                continue
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    try:
                        obj = json.loads(text[start:i + 1])
                    except json.JSONDecodeError:
                        break
                    if isinstance(obj, dict):
                        return obj
                    break
    return None



def parse_round_legacy(text: str) -> tuple[list[dict], bool, list[dict]]:
    """旧的 Markdown 正则解析，保留作为**降级路径**，但会被标记为格式问题。"""
    verdicts: list[dict] = []
    hyps: list[dict] = []
    section = ""
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("##"):
            section = s
            continue
        if not s.startswith("-"):
            continue
        body = s.lstrip("- ").strip()
        if "裁决" in section and body:
            hid, _, rest = body.partition("：")
            hid = hid.strip()
            obs, _, jd = rest.partition("判定=")
            m = re.search(r"(confirmed|refuted|inconclusive)", jd, re.I)
            jd = m.group(1).lower() if m else ""
            if hid:
                verdicts.append({"id": hid, "observation": obs.strip(" 观测= "), "verdict": jd})
        if "新假设" in section and body:
            stmt, _, fals = body.partition("怎么证伪：")
            stmt = stmt.replace("假设：", "", 1).strip(" ：:")
            fals = fals.strip()
            quality = len(fals) >= MIN_FALSIFY_LEN and fals not in {"未写", "待定", "无", "-"}
            hyps.append({
                "id": "", "statement": stmt or body[:120],
                "falsify_by": fals or "未写", "quality": "ok" if quality else "low",
            })
    progress = bool(hyps) or bool(verdicts) or ("## 结论" in text and len(text) > 200)
    return hyps, progress, verdicts


def parse_round(ws: str) -> tuple[str, list[dict], bool, list[dict], list[dict]]:
    """读本轮产物，返回 (摘要, 新假设, 是否有进展, 裁决)。

    结构化优先：先让 Pydantic 把形状钉死，再由 `RoundResult.assess()` 问语义问题。
    这一层承担了以前手写 45 行 if/else 的全部职责，而且解决了一个静默失效：
    旧代码拿整串比对 verdict，模型写 `refuted（…）`（中文括号）就整条丢失，
    裁决闭环停摆好几轮都没人发现。归一现在发生在 Verdict 的校验器里。

    没有 JSON 块时降级到 Markdown 正则，并把"降级了"本身记进格式问题——
    降级不报等于默许。

    「有进展」判据仍保守：有假设或有裁决才算，纯「我想了想」不算。
    """
    path = os.path.join(ws, "ROUND.md")
    if not os.path.exists(path):
        return ("（本轮没有写 ROUND.md）", [], False, [], [])
    text = open(path, encoding="utf-8", errors="replace").read()
    if not text.strip():
        return ("（ROUND.md 是空的）", [], False, [], [])

    obj = extract_json_block(text)
    if obj is None:
        _ROUND_PROBLEMS.append(["没有 ```json 代码块，已降级到 Markdown 正则解析"])
        hyps, progress, verdicts = parse_round_legacy(text)
        # 必须是 5 元组：调用侧 `summary, new_hyps, progress, verdicts, excluded_new = ...`
        # 解包 5 个。这里早先返回 4 个，模型没写 ```json 围栏时直接
        # ValueError: not enough values to unpack，整个编排器崩掉且状态不落盘。
        return (text[:600], hyps, progress, verdicts, [])

    try:
        rr = RoundResult.model_validate(obj)
    except ValidationError as exc:
        first = exc.errors()[0] if exc.errors() else {}
        loc = ".".join(str(x) for x in first.get("loc", ()))
        _ROUND_PROBLEMS.append([f"结构化校验失败（{loc}）: {first.get('msg', '')}"])
        hyps, progress, verdicts = parse_round_legacy(text)
        return (text[:600], hyps, progress, verdicts, [])

    # 观察单独收集：不参与 assess（不计入质量问题），只进上下文池
    for o in getattr(rr, "observations", []) or []:
        _ROUND_OBSERVATIONS.append({
            "text": o.text, "where": o.where, "kind": o.kind, "confidence": o.confidence,
        })

    # 不变量同样只进上下文池，不参与判定。
    # 它的作用不是"发现"，是给下一轮一个比漏洞清单更宽的生成源。
    for inv in getattr(rr, "invariants", []) or []:
        _ROUND_INVARIANTS.append({
            "statement": inv.statement, "stake": inv.stake,
            "exits": inv.exits, "tested": inv.tested,
        })

    problems = rr.assess()
    _ROUND_PROBLEMS.append(problems)

    hyps = []
    for h in rr.hypotheses:
        h.assess_quality()
        hyps.append({
            "id": h.id,
            "statement": h.statement[:300],
            "falsify_by": h.falsify_by or "未写",
            "quality": h.quality or "low",
        })
    verdicts = [
        {"id": v.id, "observation": v.observation[:200], "verdict": v.verdict}
        for v in rr.verdicts
    ]
    progress = bool(hyps) or bool(verdicts)
    excluded = [{"path": e.path[:200], "evidence": e.evidence[:200]} for e in rr.excluded]
    prefix = f"【格式问题 {len(problems)} 项】" if problems else ""
    return (f"{prefix}{rr.conclusion[:600]}", hyps, progress, verdicts, excluded)


# 最近一次 parse_round 的格式问题（空列表=合格）。用模块级列表是因为
# parse_round 的签名被多处调用，加返回值会牵动全部调用点。
_ROUND_PROBLEMS: list[list[str]] = []
_ROUND_OBSERVATIONS: list[dict] = []
_ROUND_INVARIANTS: list[dict] = []


def last_round_problems() -> list[str]:
    return _ROUND_PROBLEMS[-1] if _ROUND_PROBLEMS else []


def _install_scope_gate(st: dict) -> ScopeGate | None:
    """按状态里的范围配置构造范围闸。

    ## 为什么这一步之前缺失

    `ScopeGate` 在文件头 import 了，但全文从未实例化或调用——范围边界一直
    只停留在 prompt 文本里。模型"被告知"不要越界，而不是"不能"越界。
    prompt 会因为上下文膨胀被挤掉，而闸不会。

    ## 为什么没配范围时不直接拒绝

    真按 fail-closed 做会让所有现有作业瞬间停摆（它们都没配范围）。
    折中：没配时**大声记录**并且显式标到状态里，让"范围闸未生效"这件事
    可见，而不是静默通过。配了就必须过。
    """
    sc = st.get("scope") or {}
    if not (sc.get("cidrs") or sc.get("hosts")):
        st["scope_gate"] = "inactive:no-scope-configured"
        return None
    try:
        gate = ScopeGate(Scope(
            cidrs=tuple(sc.get("cidrs") or ()),
            hosts=tuple(sc.get("hosts") or ()),
            tools=tuple(sc.get("tools") or ()),
        ))
        st["scope_gate"] = "active"
        return gate
    except Exception as exc:
        # 构造失败按 fail-closed 处理：标成 broken，后面会拒绝派活
        st["scope_gate"] = f"broken:{type(exc).__name__}"
        return None


def _dsh_cmd(ws: str, patch_flag: str, prompt_path: str) -> str:
    """构造 dsh 启动命令。prompt 必须走 stdin，不能作为位置参数。

    早先写的是 `... ./run.sh {PATCH}"$(cat "$NC_PROMPT_FILE")"`，
    run.sh 再 `exec node ... "$@"` —— 于是**整个 prompt 变成 node 的命令行参数**。
    后果三个，都在真机上出现过：

      1. `ps` 能看到完整 prompt（多轮作业、含目标路径、含手法）
      2. agent 自己执行 `pkill -f <目标二进制>` 时，pattern 匹配到命令行里含同样
         字符串的 node / su 祖先进程，把自己的运行时连同编排器一起杀掉。
         真机现场：traefik 白盒第 1 轮，log 停在 reasoning 中途，末行是
         `session "...": flush on a closed handle`，整棵进程树消失
      3. 长 prompt 逼近 ARG_MAX

    headless profile 支持 `-` 读 stdin（`dsh --profile headless -`）。
    重定向写在内层 `bash -c` 里，由内层 shell 打开文件，
    不依赖 `su -c` 把外层 stdin 透传下去——那正是当初改成命令替换的原因。
    """
    return (
        f"cd {PROJ} && PROFILE=headless WORKSPACE={shlex.quote(ws)} "
        f"./run.sh {patch_flag} - < {shlex.quote(prompt_path)}"
    )


def run_round(st: dict, state_path: str) -> None:
    st["round"] += 1
    ws = os.path.join(WORK_ROOT, f"orch-{st['challenge']}-r{st['round']}-{int(time.time())}")
    _ROUND_OBSERVATIONS.clear()
    _ROUND_INVARIANTS.clear()
    gate = _install_scope_gate(st)
    if gate is not None:
        # action 必须是 connect / http_request / run_tool 三者之一，
        # 写成 "target" 会被 Rego 的默认拒绝吞掉（所有目标一律 False）。
        #
        # 字段名也要对上：connect 分支读 `input.target`（用于 cidr_contains），
        # http_request 分支读 `input.host`（精确匹配域名清单）。
        # 只传 host 的话，纯 CIDR 范围下 connect 永远不命中。
        target = st.get("target", "")
        decision = gate.check("connect", target=target)
        if not decision.allow:
            decision = gate.check("http_request", host=target)
        if not decision.allow:
            st["last_summary"] = f"本轮未派活：范围闸拒绝（{decision.reason}）"
            st["scope_denied"] = decision.reason
            save_state(state_path, st)
            return
    elif str(st.get("scope_gate", "")).startswith("broken"):
        st["last_summary"] = "本轮未派活：范围闸构造失败，按 fail-closed 拒绝"
        save_state(state_path, st)
        return
    prompt = build_prompt(st)
    env = dict(os.environ)
    # api_key 优先取状态里的（历史兼容），否则取环境变量。
    # 状态里的那份会被 save_state 剥掉（不落盘），所以实际使用时走环境变量。
    env.update({"PROFILE": "headless", "WORKSPACE": ws,
                "DEEPSEEK_API_KEY": st.get("api_key") or os.environ.get("DEEPSEEK_API_KEY", "")})
    if not env["DEEPSEEK_API_KEY"]:
        env.pop("DEEPSEEK_API_KEY")

    prompt_path = os.path.join(STATE_DIR, f"{st['challenge']}-prompt-r{st['round']}.md")
    with open(prompt_path, "w", encoding="utf-8") as fh:
        fh.write(prompt)

    started = time.time()
    log = os.path.join(STATE_DIR, f"{st['challenge']}-r{st['round']}.log")
    # prompt 走文件而不是 stdin：`su -c` 不保证把 stdin 透传给下层进程。
    #
    # ⚠️ 用 Popen + setsid 而不是 subprocess.run(timeout=...)：run 超时只会杀
    # 直接子进程，而这里隔了 su 和 run.sh 两层，孙进程（真正的 node）会活下来
    # 继续吃 CPU、继续打平台。必须按进程组整组杀。
    timed_out = False
    kill_reason = ""

    # —— supervised 路径：交给 nai-run ——
    #
    # 差别不只是"换个执行器"：nai-run 用 cgroup 记账，因此
    #   1. 能杀掉 setsid 逃出进程组的孙进程（killpg 够不到，实测孤儿的来源）
    #   2. 单轮有硬内存上限，两路一起跑不会再出现"把机器压死"
    #   3. 超时给出 peak_mem / oom_kill，OOM 能归因到具体哪一轮
    # 默认关闭：裸 subprocess 那条已经跑通过，新路径要显式开启。
    # 两条路径都要这个变量，所以放在分支之外设置。
    # 早先它写在 else 分支里，导致 supervised 路径下 prompt 文件根本传不进去。
    env["NC_PROMPT_FILE"] = prompt_path

    if st.get("supervised") and execlayer is not None and execlayer.available():
        r = execlayer.run(
            ["su", "zsh", "-s", "/bin/bash", "-c", _dsh_cmd(ws, PATCH, prompt_path)],
            timeout=ROUND_WALL_SECONDS,
            idle=ROUND_IDLE_SECONDS,
            grace=GRACEFUL_SECONDS,
            mem=st.get("round_mem", ""),
            cwd=PROJ,
            log=log,
            env=env,
        )
        # 复用后续统一处理：把 runner 的结果翻译成原来的三个变量
        elapsed = max(1, r.elapsed_ms // 1000)
        timed_out = r.timed_out
        kill_reason = r.kill_reason if r.timed_out else ""
        st["last_peak_mem_kb"] = r.peak_mem_kb
        st["last_oom_kill"] = r.oom_kill
        st["last_cleaned"] = r.killed

    else:
        with open(log, "wb") as fh:
            # prompt 通过**环境变量**传给子 shell，而不是塞进命令行。
            #
            # 这里原来写的是 f"…$(cat '{prompt_path}')…"，用的是中文引号 ——
            # bash 不认那对引号，命令替换的结果会被按空白拆成几十个参数，
            # run.sh 收到的 prompt 是碎的。表现是"轮次日志 0 字节、DSH 根本没起来"，
            # 而且全程不报错。环境变量传值没有解析环节，是唯一不会出这类问题的写法。
            proc = subprocess.Popen(
                ["su", "zsh", "-s", "/bin/bash", "-c", _dsh_cmd(ws, PATCH, prompt_path)],
                stdout=fh, stderr=subprocess.STDOUT, env=env, preexec_fn=os.setsid,
            )
            # 双判据轮询：总时长管"跑太久"，无输出管"卡死"。
            # 用轮询而不是 proc.wait(timeout=)：后者只能等一个条件，而这里要同时看两个，
            # 且需要在超时时**先温和地让它收尾**再强杀——直接 SIGKILL 会让 ROUND.md 写不出来。
            last_size = 0
            last_change = time.time()
            while proc.poll() is None:
                now_ts = time.time()
                try:
                    size = os.path.getsize(log)
                except OSError:
                    size = last_size
                if size != last_size:
                    last_size = size
                    last_change = now_ts
                if now_ts - started > ROUND_WALL_SECONDS:
                    kill_reason = "total_wall"
                    break
                if now_ts - last_change > ROUND_IDLE_SECONDS:
                    kill_reason = "idle"
                    break
                time.sleep(2)

            if kill_reason != "":
                timed_out = True
                # 先 SIGTERM 给 GRACEFUL_SECONDS 收尾（把 ROUND.md 写完），再 SIGKILL。
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    proc.wait(timeout=GRACEFUL_SECONDS)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                    except ProcessLookupError:
                        pass

    elapsed = int(time.time() - started)
    # 超时也照样读 ROUND.md：它往往已经写下本轮结论，只是没收尾。
    st["last_timed_out"] = timed_out
    st["last_kill_reason"] = kill_reason

    summary, new_hyps, progress, verdicts, excluded_new = parse_round(ws)
    # 产物缺失 → 从日志回捞，别让这一轮彻底蒸发。
    #
    # ⚠️ 这里曾经写成 `if timed_out and (...)`，是个致命的窄条件。实测 5 路并发时
    # 各轮耗时分别是 851s、222s、1003s——851s 和 222s 那两轮**不是被超时杀的**，
    # 是 agent 自己正常退出的，于是 kill_reason==""、timed_out=False，salvage 从不
    # 执行，整轮的逆向分析全部蒸发。下一轮的 prompt 里只剩一句
    # "（本轮没有写 ROUND.md）"，agent 只能从零重来，形成"跑一轮→失忆→再跑一轮"
    # 的死循环。自然退出却没留产物，比超时更常见，也更需要抢救。
    salvaged = ""
    if not progress or "没有写 ROUND.md" in summary:
        salvaged = salvage_from_log(log)
        if salvaged != "":
            how = f"因 {kill_reason} 被中断" if kill_reason else "自行结束"
            summary = (
                f"（本轮{how}，未写出 ROUND.md；以下是它最后在做的事。"
                f"请从中提炼出已确认的事实/已排除的路径，写进本轮 ROUND.md，不要重复劳动）\n"
                f"{salvaged}"
            )
            st["salvaged_rounds"] = st.get("salvaged_rounds", 0) + 1
    # 裁决回填：这是 Reflexion 的那一环——提出假设之后必须回来对照观测判真假，
    # 判死的写进 refuted（下一轮不许再碰），判活的进 confirmed（不许重复验证）。
    # ⚠️ 必须先入库再回填裁决。
    # 早先这两段是反的：裁决遍历 st["hypotheses"] 时，本轮新提的假设还没进去，
    # 于是永远匹配不上，verdicts_total 一直是 0——Reflexion 闭环从没真正跑起来过。
    # ── 假设入库：强制全局唯一 ID，模型自报的 id 只作为「本轮局部名」
    #
    # 早先是直接采信模型给的 id（注释说"裁决里引用的就是它，覆盖掉就对不上"）。
    # 问题是模型会在 build_prompt 的示例里看到 `"id": "H1"`，第 3 轮再提一个
    # 新假设也叫 H1——于是库里出现两个 H1，而下面的裁决回填是遍历全库，
    # 会把第 1 轮已经 confirmed 的 H1 一起改成 refuted，历史结论被篡改，
    # judged 还对各加 1 虚增 verdicts_total。
    #
    # 现在的做法：每轮建立 local_id -> global_id 映射，只在本轮内用局部名。
    seq = int(st.get("next_hyp_seq") or 0)
    if seq == 0:
        # 兼容老状态文件：按现有条数起步，避免与已有 id 撞
        seq = len(st["hypotheses"])
    id_map: dict[str, str] = {}
    for h in new_hyps:
        if not h["statement"]:
            continue
        local = (h.get("id") or "").strip()
        seq += 1
        gid = f"H{seq}"
        if local:
            id_map[local] = gid
        h["id"] = gid
        h["status"] = "open"
        st["hypotheses"].append(Hypothesis(**h))
    st["next_hyp_seq"] = seq

    # ── 裁决回填：只允许更新 open 的假设，settled 的一律跳过
    open_by_id = {h["id"]: h for h in st["hypotheses"] if h["status"] == "open"}
    judged = 0
    for v in verdicts:
        target = id_map.get(str(v["id"]).strip(), str(v["id"]).strip())
        h = open_by_id.get(target)
        if h is None or v["verdict"] not in {"confirmed", "refuted"}:
            continue
        h["status"] = v["verdict"]
        h["evidence"] = v["observation"][:160]
        open_by_id.pop(target, None)   # 一条假设只被裁决一次
        judged += 1
    st["verdicts_total"] = st.get("verdicts_total", 0) + judged
    # 落盘本轮观察（去重、限量：池子无限长，但状态文件不能无限长）
    new_obs = [o for o in _ROUND_OBSERVATIONS]
    if new_obs:
        # StateView 是 Pydantic 模型，没有 dict.setdefault —— 直接用 get/赋值
        obs_list = st.get("observations") or []
        existing = {str(o.get("text", "")) for o in obs_list}
        for o in new_obs:
            if str(o.get("text", "")) not in existing:
                obs_list.append({**o, "round": st["round"]})
        st["observations"] = obs_list[-80:]   # 上限 80 条
        _ROUND_OBSERVATIONS.clear()

    # 落盘本轮不变量。按 statement 去重：同一个承诺被反复写是常态，
    # 但 exits / tested 要合并——新轮次可能补上没测过的出口，这才是价值所在。
    if _ROUND_INVARIANTS:
        inv_list = st.get("invariants") or []
        by_stmt = {str(i.get("statement", "")): i for i in inv_list}
        for inv in _ROUND_INVARIANTS:
            key = str(inv.get("statement", ""))
            if key in by_stmt:
                cur = by_stmt[key]
                cur["exits"] = sorted({*cur.get("exits", []), *inv.get("exits", [])})
                cur["tested"] = sorted({*cur.get("tested", []), *inv.get("tested", [])})
                if inv.get("stake") and not cur.get("stake"):
                    cur["stake"] = inv["stake"]
            else:
                inv_list.append({**inv, "round": st["round"]})
        st["invariants"] = inv_list[-40:]
        _ROUND_INVARIANTS.clear()

    problems = last_round_problems()
    if problems:
        st["format_errors"] = (st.get("format_errors") or []) + problems
        st["format_error_rounds"] = st.get("format_error_rounds", 0) + 1
    else:
        st["format_errors"] = []
    low = [h for h in new_hyps if h.get("quality") == "low"]
    st["low_quality_hypotheses"] = st.get("low_quality_hypotheses", 0) + len(low)
    tag = "（超时收束）" if timed_out else ""
    st["last_summary"] = f"（第 {st['round']} 轮，耗时 {elapsed}s{tag}）{summary}"

    # —— 跨轮记忆：已排除路径 + 最近摘要 ——
    #
    # 参考 Archon 的规模教训：agent 反复走同一条死路是"忘记试过什么"的直接后果。
    # 之前排除路径只活在单轮 ROUND.md 里、解析完就丢，等于每一轮都从零开始排除。
    # 这里按 path 去重累积（同一路径被排除两次只会浪费 context）。
    seen_paths = {e.path for e in st.excluded}
    for e in excluded_new:
        if e["path"] and e["path"] not in seen_paths:
            st.excluded.append(Excluded(path=e["path"], evidence=e["evidence"]))
            seen_paths.add(e["path"])
    st.recent_summaries.append(st["last_summary"][:400])
    if len(st.recent_summaries) > 6:
        st.recent_summaries = st.recent_summaries[-6:]

    # ── 停滞检测与阶段切换：一次判定，禁止同轮反复覆写
    #
    # 早先是两段独立的 if：上面 stalled 就设 guess，下面 progress 又设回 converge。
    # 十五行之内同一个字段被写两次，模型永远卡在 converge ↔ guess 的乒乓里，
    # 而 phase_switches 只在前一次自增，统计也是歪的。
    signal = check_stall(st)
    st["stall_reasons"] = signal.reasons
    _phase_before = st["phase"]
    if signal.stalled:
        if _phase_before != "guess":
            st["phase"] = "guess"
            st["phase_switches"] = st.get("phase_switches", 0) + 1


    completed, where, answer = detect_completion(
        st["challenge"], ws, st.get("hypotheses"))
    if completed:
        st["completed"] = True
        st["completed_at_round"] = st["round"]
        st["answer_from_ws"] = where
        st["answer_excerpt"] = answer[:200]

    # 写记忆文档：下一轮规划时读它，而不是读原始日志（Archon 的 memory 做法）
    write_memory(st, ws)

    if progress:
        st["last_progress_round"] = st["round"]
        # 已因停滞进入 guess 的这一轮不再抢回 converge——否则同轮乒乓。
        # 让停滞判定赢：它看的是跨轮累积信号，比单轮的 progress 更抗噪。
        if st["phase"] == "guess" and not signal.stalled and _phase_before == "guess":
            st["phase"] = "converge"
            st["phase_switches"] += 1
    else:
        idle = st["round"] - st["last_progress_round"]
        if st["phase"] == "converge" and idle >= CONVERGE_PATIENCE:
            st["phase"] = "guess"
            st["phase_switches"] += 1
    save_state(state_path, st)


def main() -> int:
    ap = argparse.ArgumentParser(
        description="奶虫编排器：带时钟、收敛、假设循环与跨轮记忆的多轮作业引擎。")
    # 参数名保留 --challenge 是为了兼容既有状态目录；语义上它是「任务名」，
    # 真实渗透里传目标域名或 engagement 名（如 example.com）。
    ap.add_argument("--challenge", default="",
                    help="任务名，用于状态归档（如 example.com、内网段、engagement 名）")
    ap.add_argument("--deadline-min", type=int, default=DEFAULT_DEADLINE_MIN)
    ap.add_argument("--mode", default="",
                    choices=["", "blackbox", "whitebox"],
                    help="方法论：blackbox（仅外部可见信息）或 whitebox（有源码/配置）")
    ap.add_argument("--target", default="",
                    help="目标标识（域名/网段/系统名）；与 --challenge 等价，语义更贴合作业")
    ap.add_argument("--domain", default="",
                    help="作业方向（web/reverse/pwn/crypto/misc/ai），决定加载哪份领域规格")
    ap.add_argument("--task-prompt", default="",
                    help="把任务描述、范围边界和交付要求直接写进每轮 prompt")
    ap.add_argument("--max-rounds", type=int, default=40)
    ap.add_argument("--supervised", action="store_true",
                    help="用 nai-run（cgroup 限额 + 进程树清理）执行每轮，而不是裸 subprocess")
    ap.add_argument("--round-mem", default="", help="--supervised 下单轮内存上限，如 3G")
    ap.add_argument("--store-root", default="",
                    help="扫描产物数据目录；配置后每轮注入资产概况与未测资产")
    ap.add_argument("--scope-file", default="",
                    help="授权范围 JSON（含 cidrs/hosts/tools）；配置后写进每轮 prompt 作为边界")
    args = ap.parse_args()
    # --target 与 --challenge 等价。前者是真实作业的语汇，后者是历史参数名，
    # 保留是为了不打断既有状态目录的命名。
    # challenge 是任务名（状态归档用），target 是实际目标（scope 检查与 prompt 用）。
    # 早先是 `if args.target and not args.challenge: args.challenge = args.target`——
    # 同时给两个时 target 被直接丢掉，于是 state 里没有 target，prompt 里也没有，
    # agent 只能看到任务名 demo-test，完全不知道要打哪个域名。
    if not args.challenge and args.target:
        args.challenge = args.target
    if not args.target and args.challenge:
        args.target = args.challenge
    if not args.challenge:
        ap.error("必须提供 --target 或 --challenge")

    os.makedirs(STATE_DIR, exist_ok=True)
    state_path = os.path.join(STATE_DIR, f"{args.challenge}.json")
    # 拿运行锁：同一 challenge 不允许两个编排进程并存。
    # 句柄赋给模块级变量，保证 flock 活到进程结束。
    global _RUN_LOCK
    _RUN_LOCK, _holder = acquire_run_lock(state_path)
    if _RUN_LOCK is None:
        ap.error(f"任务 {args.challenge} 已有编排进程在跑（pid={_holder}）。"
                 f"先确认它真的结束了——`pgrep -af orchestrator.py`——再重跑。")
    st = load_state(state_path)
    if not st:
        key = ""
        try:
            import yaml
            cred = yaml.safe_load(open("/root/proj/home/.credentials.yaml", encoding="utf-8")) or {}
            key = (cred.get("refs") or {}).get("DEEPSEEK_API_KEY") or ""
        except Exception:
            pass
        st = StateView(
            challenge=args.challenge,
            domain=args.domain,
            mode=args.mode,
            target=args.target,
            task_prompt=args.task_prompt,
            round=0,
            phase="converge",
            deadline_ts=time.time() + args.deadline_min * 60,
            last_progress_round=0,
            hypotheses=[],
            last_summary="",
            phase_switches=0,
            api_key=key,
            scope=_load_scope(args.scope_file),
            store_root=args.store_root,
            supervised=args.supervised,
            round_mem=args.round_mem,
        )
        save_state(state_path, st)

    # `--deadline-min` 是「从这次启动算起」，不是「沿用上次的截止」。
    # 旧状态里过期的 deadline 会让重启立刻判到点（实测踩过一次：
    # 一启动就打印「到截止时间」，一轮都没跑）。
    # 假设库要保留（那是跨轮积累的价值），只把时间基准刷新。
    if args.domain and st.get("domain") != args.domain:
        st["domain"] = args.domain
    if getattr(args, "mode", "") and st.get("mode") != args.mode:
        st["mode"] = args.mode
    if args.task_prompt:
        st["task_prompt"] = args.task_prompt
    if st["deadline_ts"] <= time.time():
        st["deadline_ts"] = time.time() + args.deadline_min * 60
        save_state(state_path, st)

    print(f"[orch] {args.challenge} 阶段={st['phase']} 轮次={st['round']} "
          f"截止={datetime.fromtimestamp(st['deadline_ts'], BEIJING).strftime('%H:%M')}", flush=True)

    while st["round"] < args.max_rounds:
        if time.time() >= st["deadline_ts"]:
            print(f"[orch] {args.challenge} 到截止时间，停止（共 {st['round']} 轮，阶段切换 {st['phase_switches']} 次）", flush=True)
            return 0
        run_round(st, state_path)
        print(f"[orch] r{st['round']} 完成 phase={st['phase']} 假设={len(st['hypotheses'])}", flush=True)
        if st.get("completed"):
            print(
                f"[orch] {st['challenge']} 已产出答案（{st.get('answer_from_ws')}），"
                f"第 {st.get('completed_at_round')} 轮提前收束，不再开新轮",
                flush=True,
            )
            return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
