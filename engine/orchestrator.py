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
import json
import os
import re
import signal
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone

from pydantic import ValidationError

from models import Excluded, Hypothesis, RoundResult, StateView, check_stall
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
BASE = os.path.dirname(os.path.abspath(__file__))
STATE_DIR = os.path.join(BASE, "state")
OVERLAY = os.path.join(BASE, "overlay.yml")
# overlay 是可选增强：文件不在就不传，而不是让 DSH 启动失败
PATCH = f"--patch {OVERLAY} " if os.path.exists(OVERLAY) else ""
AGENT_DIR = os.path.join(BASE, "agents")
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
    os.makedirs(os.path.dirname(path), exist_ok=True)
    payload = st.to_json_dict() if isinstance(st, StateView) else st
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2)


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
    lines = []
    for line in raw.splitlines():
        t = line.strip()
        if t == "" or t == "dsh: reasoning:":
            continue
        if t.startswith("[" + "run.sh" + "]") or t.startswith("[llm-deepseek"):
            continue
        lines.append(t)
    tail = "\n".join(lines[-25:])
    return tail[-max_chars:]


ATTACH_ROOT = os.path.join(BASE, "attachments")
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


def detect_completion(challenge: str, current_ws: str) -> tuple[bool, str, str]:
    """扫本轮和历史轮次的 workspace，看有没有产出合格的交付物。

    存在理由（基线 v1 实测）：四道简单题耗时分别是 499/502/512/510 秒，
    **全部卡在 8 分钟 deadline 的 92% 附近**——说明它们不是判断做完而停，
    是被 deadline 掐停的。写完之后继续验证到时间耗尽，这是 3 倍量级的浪费。

    判据刻意保守：文件存在、内容非空、不是占位符。宁可漏判（继续跑到 deadline）
    也不要误判（东西还没写完就停）。

    注：曾有一层 `_rejected_flags()` 过滤——把平台判错的 flag 排除出「已完成」，
    防止一个错答案把整题提前钉死。那套是比赛平台的语义，真实渗透没有「平台判定
    答案对错」这回事，已随 CTF 模块一并移除。
    """
    roots = [current_ws]
    try:
        for name in os.listdir(WORK_ROOT):
            if name.startswith(f"orch-{challenge}-"):
                roots.append(os.path.join(WORK_ROOT, name))
        # ⚠️ 也必须扫材料目录：实跑发现 agent 会把产出写在这里（工作时 cwd 就是它），
        # 而只扫 orch-* 会导致"明明写完了却一直跑到 deadline"。这是基线 v2 抓到的 bug。
        att = os.path.join(ATTACH_ROOT, challenge)
        if os.path.isdir(att):
            roots.append(att)
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
    root = os.path.join(ATTACH_ROOT, challenge)
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

    # 授权范围：让 agent 一开始就知道边界在哪，而不是事后审计才发现越界。
    # 这段和 Rego 策略读的是同一份配置，所以不会有「prompt 说可以、闸说不可以」的分歧。
    if st.get("scope"):
        sc = st["scope"]
        lines += ["## 授权范围（越界即违规，不是尽量避开）", ""]
        if sc.get("cidrs"):
            lines.append("- 允许的网段：" + ", ".join(sc["cidrs"]))
        if sc.get("hosts"):
            lines.append("- 允许的域名：" + ", ".join(sc["hosts"]) + "（精确匹配，不含子域）")
        if sc.get("tools"):
            lines.append("- 允许的工具：" + ", ".join(sc["tools"]))
        lines += [
            "",
            "**范围外的一切资产都不在授权内。** 需要碰范围外的东西时，"
            "停下来写清楚「为什么必须碰、属于哪个授权依据」，而不是先做了再说。",
            "",
        ]

    # 已排除路径：这是跨轮省时间最有效的一块，之前只活在单轮 ROUND.md 里。
    if st.get("excluded"):
        lines += ["## 已排除的路径（不要回头）"]
        for e in st["excluded"][-12:]:
            ev = f" —— 依据：{e.evidence}" if e.evidence else ""
            lines.append(f"- {e.path}{ev}")
        lines += ["", "回到这些路径上等于承认上一轮的结论是错的；"
                  "如果你确实要回头，先给出推翻原依据的新观测。", ""]

    # 方法论先于领域：黑盒/白盒决定的是"凭什么下结论"，
    # 领域规格只决定"往哪儿看"。顺序反了会让领域细节盖过判定纪律。
    if mode_spec:
        lines += ["---", mode_spec, "---", ""]
    if spec:
        # 领域规格放在最前面：它是角色，不是参考材料。
        lines += ["---", spec, "---", ""]

    if confirmed:
        lines += ["**已确认的结论**（不要重复验证）"]
        lines += [f"- {h['statement']}" for h in confirmed]
        lines.append("")
    if refuted:
        lines += ["**已排除的方向**（不要再回去）"]
        lines += [f"- {h['statement']}  ← 因：{h.get('evidence', '已被观测否定')}" for h in refuted]
        lines.append("")
    if open_h:
        lines += ["**待验证的假设**"]
        lines += [f"- [{h['id']}] {h['statement']}\n  证伪条件：{h['falsify_by']}" for h in open_h]
        lines.append("")

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
        '  "hypotheses": [{"statement": "新假设", "falsify_by": "什么观测能证明它错"}],',
        '  "next": "下一步一句话"',
        "}",
        "```",
        "",
        "规则：",
        "- `verdict` 只能是 `confirmed` / `refuted` / `inconclusive` 三个值之一",
        "- 每条裁决必须有 `observation` —— **没有观测就没有裁决**",
        "- 每条假设必须有 `falsify_by`，且要具体到「一次实验就能否定」；写「待定」等于没提",
        "- 字段缺失或类型不对会被判为格式错误，下一轮会点名要求你修正",
        "",
        "工作目录就是本轮的 workspace；目标材料（源码、配置、资产清单等）在 `attachments/<target>/`。",
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
    for m in re.finditer(r"```json\s*\n(.*?)```", text, re.S):
        try:
            obj = json.loads(m.group(1))
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            return obj
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
        return (text[:600], hyps, progress, verdicts)

    try:
        rr = RoundResult.model_validate(obj)
    except ValidationError as exc:
        first = exc.errors()[0] if exc.errors() else {}
        loc = ".".join(str(x) for x in first.get("loc", ()))
        _ROUND_PROBLEMS.append([f"结构化校验失败（{loc}）: {first.get('msg', '')}"])
        hyps, progress, verdicts = parse_round_legacy(text)
        return (text[:600], hyps, progress, verdicts, [])

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


def last_round_problems() -> list[str]:
    return _ROUND_PROBLEMS[-1] if _ROUND_PROBLEMS else []


def run_round(st: dict, state_path: str) -> None:
    st["round"] += 1
    ws = os.path.join(WORK_ROOT, f"orch-{st['challenge']}-r{st['round']}-{int(time.time())}")
    prompt = build_prompt(st)
    env = dict(os.environ)
    env.update({"PROFILE": "headless", "WORKSPACE": ws, "DEEPSEEK_API_KEY": st.get("api_key", "")})
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
            ["su", "zsh", "-s", "/bin/bash", "-c",
             f"cd {PROJ} && PROFILE=headless WORKSPACE='{ws}' ./run.sh {PATCH}"
             f'"$(cat \"$NC_PROMPT_FILE\")"'],
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
                ["su", "zsh", "-s", "/bin/bash", "-c",
                 f"cd {PROJ} && PROFILE=headless WORKSPACE='{ws}' ./run.sh {PATCH}"
                 f'"$(cat "$NC_PROMPT_FILE")"'],
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
    # 新假设入库，带自增 id
    for h in new_hyps:
        if not h["statement"]:
            continue
        # 保留 agent 自己写的 id：裁决里引用的就是它，覆盖掉就对不上了。
        if not h.get("id"):
            h["id"] = f"H{len(st['hypotheses']) + 1}"
        h["status"] = "open"
        st["hypotheses"].append(Hypothesis(**h))
    judged = 0
    for v in verdicts:
        for h in st["hypotheses"]:
            if h["id"] == v["id"] and v["verdict"] in {"confirmed", "refuted"}:
                h["status"] = v["verdict"]
                h["evidence"] = v["observation"][:160]
                judged += 1
    st["verdicts_total"] = st.get("verdicts_total", 0) + judged
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

    # 停滞检测：跨轮累积量判，不花模型调用
    signal = check_stall(st)
    st["stall_reasons"] = signal.reasons
    if signal.stalled:
        st["phase"] = "guess"
        st["phase_switches"] = st.get("phase_switches", 0) + 1


    completed, where, answer = detect_completion(st["challenge"], ws)
    if completed:
        st["completed"] = True
        st["completed_at_round"] = st["round"]
        st["answer_from_ws"] = where
        st["answer_excerpt"] = answer[:200]

    # 写记忆文档：下一轮规划时读它，而不是读原始日志（Archon 的 memory 做法）
    write_memory(st, ws)

    if progress:
        st["last_progress_round"] = st["round"]
        if st["phase"] == "guess":
            # 猜测阶段拿到新证据 → 回到收敛，把新线索走扎实
            st["phase"] = "converge"
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
    if args.target and not args.challenge:
        args.challenge = args.target
    if not args.challenge:
        ap.error("必须提供 --target 或 --challenge")

    os.makedirs(STATE_DIR, exist_ok=True)
    state_path = os.path.join(STATE_DIR, f"{args.challenge}.json")
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
