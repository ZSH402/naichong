#!/usr/bin/env python3
"""奶虫数据契约（Pydantic v2）。

## 为什么要这一层

今天所有"字段丢了 / 类型不对 / 静默失效"的根因都是同一个：**裸 dict 在层与层之间流动**。
最典型的一次事故——模型把裁决写成 `判定=refuted（…）`（中文括号），而代码拿整串去比对
`{"confirmed","refuted","inconclusive"}`，于是**每一条裁决都静默丢失**，裁决闭环停摆了
好几轮都没人发现，日志上只显示"本轮无进展"。

教训不是"要更小心地比对"，而是：**校验必须发生在写入时刻，而不是消费时刻**。
数据一进系统就该被约束住，之后无论谁读都不会遇到"形状不对"的东西。

## 设计依据（业界共同做法）

1. **状态 schema 显式声明**。LangGraph 用 `TypedDict` + reducer 定义 state 形状，
   Pydantic 生态用 `BaseModel`；共同点是**形状是代码里的一等公民**，不是隐式约定。
2. **契约带版本号**。状态文件要能在版本之间迁移或明确拒绝，不能"读进来试试看"。
   这里用 `schema_version` 做锚点；未知字段一律容忍（`extra="allow"`），
   因为加字段是向后兼容的，删字段才需要迁移。
3. **序列化边界统一**。所有落盘数据必须 `model_dump(mode="json")`，保证可 JSON 化、
   无 datetime/自定义对象泄漏到磁盘。

## 三个刻意的取舍

- **值对象冻结**：`Verdict` / `Excluded` 设 `frozen=True`。它们是一次观测的记录，
  写下来就不该改——改了就等于篡改证据。
- **State 不冻结**：状态机每轮都在推进，冻结会逼出大量 `model_copy(update=...)`。
- **兼容裸 dict 接口**：`StateView` 实现了 `__getitem__` / `get` / `__setitem__`，
  这样 orchestrator.py 里几十处 `st["x"]`、`st.get("x", d)` 不需要全部重写，
  但赋值仍然经过 Pydantic 的类型校验。
"""
from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

# 契约版本。加字段不需要升版本（extra="allow" 天然兼容）；删改字段语义时必须升，
# 并在 StateView.migrate 里给出迁移路径。
SCHEMA_VERSION = 1

Phase = Literal["converge", "guess"]
HypothesisStatus = Literal["open", "confirmed", "refuted", "inconclusive"]
VerdictKind = Literal["confirmed", "refuted", "inconclusive"]
Quality = Literal["high", "low"]

# 敷衍写法：这些不是"假设"，是"我不想想了"。写进 committed 状态只会污染下一轮的判断。
PLACEHOLDER_WORDS = {
    "todo", "tbd", "unknown", "待定", "无", "none", "n/a", "na", "-", "?", "...",
    "需要进一步分析", "进一步分析", "再看看", "待确认",
}


def _is_placeholder(text: str) -> bool:
    t = (text or "").strip().lower()
    if not t:
        return True
    if t in PLACEHOLDER_WORDS:
        return True
    # 去掉标点后仍是很短的短语，基本等于没写
    core = "".join(ch for ch in t if ch.isalnum() or "\u4e00" <= ch <= "\u9fff")
    return len(core) < 4


class Verdict(BaseModel):
    """一条裁决：某个假设被观测判定为真/假/不确定。

    `observation` 强制非空——**没有观测就没有裁决**。这不是洁癖：
    今天出现过"我确认了 X"但拿不出任何命令输出的情况，写进状态后会误导后续轮次。
    """

    model_config = ConfigDict(frozen=True, extra="allow")

    id: str = ""
    observation: str = Field(min_length=1)
    verdict: VerdictKind

    @field_validator("verdict", mode="before")
    @classmethod
    def _normalize_verdict(cls, v: Any) -> Any:
        """把各种写法归一。

        真实事故：模型写成 `refuted（…）` / `confirmed。` / `REFUTED`。
        以前是拿整串比对，全部落空且不报错。现在在入口处切词归一，
        归不到三个合法值就抛校验错误——**宁可报错，不要静默**。
        """
        if not isinstance(v, str):
            return v
        s = v.strip().lower()
        for k in ("confirmed", "refuted", "inconclusive"):
            if k in s:
                return k
        if "证伪" in s or "否定" in s or "排除" in s:
            return "refuted"
        if "确认" in s or "证实" in s or "成立" in s:
            return "confirmed"
        if "不确" in s or "无法判" in s:
            return "inconclusive"
        return s


class Excluded(BaseModel):
    """一条被排除的路径。下一轮不许再走它——这是省时间最有效的一环。"""

    model_config = ConfigDict(frozen=True, extra="allow")

    path: str = Field(min_length=1)
    evidence: str = ""


class Hypothesis(BaseModel):
    """一条可证伪的假设。

    必须是**业务命题**而不是漏洞类别名。`falsify_by` 要具体到"一次实验就能否定"，
    写不出来说明它无法验证，那它的价值等于零。
    """

    # validate_assignment：裁决回填会写 h["status"]，不校验的话非法值能静静存进去，
    # 直到下一轮 build_prompt 读到才出问题——又回到"校验发生在消费时刻"。
    model_config = ConfigDict(extra="allow", validate_assignment=True)

    id: str = ""
    statement: str = Field(min_length=1)
    falsify_by: str = ""
    status: HypothesisStatus = "open"
    evidence: str = ""
    quality: Quality | None = None

    @field_validator("falsify_by")
    @classmethod
    def _reject_placeholder(cls, v: str) -> str:
        # 占位不算证伪条件，但也不炸掉整个解析——降级为空串，由 quality 标记为 low
        return "" if _is_placeholder(v) else v

    def assess_quality(self) -> str:
        """质量评级。空或敷衍的 falsify_by 一律 low。"""
        self.quality = "low" if _is_placeholder(self.falsify_by) else "high"
        return self.quality

    # ---------- dict 兼容层 ----------
    # orchestrator.py 里有 9 处按 h["status"] 这种方式读写（历史写法）。
    # 与其全部重写、不如保留形状——但赋值仍然经过校验。
    def __getitem__(self, key: str) -> Any:
        try:
            return getattr(self, key)
        except AttributeError as exc:
            raise KeyError(key) from exc

    def __setitem__(self, key: str, value: Any) -> None:
        if not hasattr(self, key):
            raise KeyError(f"未知字段 {key!r}")
        setattr(self, key, value)

    def get(self, key: str, default: Any = None) -> Any:
        return getattr(self, key, default)


class RoundResult(BaseModel):
    """一轮的产出，对应 ROUND.md 里的 ```json 块。

    字段全部带默认值：解析要**尽量成功**，而不是失败后整轮作废。
    真正严格的校验发生在 `assess()`，把问题收集成列表交给下一轮点名校正。
    """

    model_config = ConfigDict(extra="allow")

    conclusion: str = ""
    verdicts: list[Verdict] = Field(default_factory=list)
    excluded: list[Excluded] = Field(default_factory=list)
    hypotheses: list[Hypothesis] = Field(default_factory=list)
    next: str = ""

    def assess(self) -> list[str]:
        """返回格式问题清单（空 = 合格）。

        刻意不抛异常：一轮跑完被砍在写文件中间，产物不完整是常态，
        这时候把整轮判为"作废"会丢掉里面已经成立的结论。
        收集问题、写进下一轮 prompt 点名要求修正，比直接丢弃更有用。
        """
        problems: list[str] = []
        if not self.conclusion.strip():
            problems.append("conclusion 为空：本轮有什么进展或卡在哪，必须写一句话")
        if not self.hypotheses:
            problems.append("hypotheses 为空：本轮没有提出任何可证伪的假设")
        for i, h in enumerate(self.hypotheses):
            if _is_placeholder(h.falsify_by):
                problems.append(
                    f"hypotheses[{i}] 的 falsify_by 缺失或敷衍（要具体到一次实验就能否定）"
                )
        for i, v in enumerate(self.verdicts):
            if not v.observation.strip():
                problems.append(f"verdicts[{i}] 没有 observation：没有观测就没有裁决")
        return problems


class StateView(BaseModel):
    """持久化的编排状态。

    对 orchestrator.py 暴露 dict 风格的读写（`st["round"]` / `st.get("phase")`），
    但每次赋值都经过 Pydantic 校验。这样既不用重写几十处访问，
    又能在写坏类型的第一现场炸出来。
    """

    # validate_assignment 是关键：默认 False 时 `st["phase"] = "乱写"` 会被静默接受，
    # 直到下一轮 build_prompt 读到非法值才炸——那正是"校验发生在消费时刻"的老毛病。
    # 打开后，赋值当场校验，错误在第一现场暴露。
    model_config = ConfigDict(extra="allow", validate_assignment=True)

    schema_version: int = SCHEMA_VERSION
    challenge: str
    domain: str = ""
    # 方法论：blackbox（仅外部可见信息）/ whitebox（有源码与配置）。
    # 与 domain 的区别：domain 决定往哪儿看，mode 决定凭什么下结论。
    mode: str = ""
    task_prompt: str = ""
    round: int = 0
    phase: Phase = "converge"
    deadline_ts: float = 0.0
    last_progress_round: int = 0
    hypotheses: list[Hypothesis] = Field(default_factory=list)
    last_summary: str = ""
    phase_switches: int = 0
    api_key: str = ""

    # —— 诊断类字段，全部给默认值，保证老状态文件能直接读进来 ——
    last_timed_out: bool = False
    last_kill_reason: str = ""
    salvaged_rounds: int = 0
    verdicts_total: int = 0
    format_errors: list[str] = Field(default_factory=list)
    format_error_rounds: int = 0
    low_quality_hypotheses: int = 0
    completed: bool = False
    completed_at_round: int = 0
    answer_from_ws: str = ""
    answer_excerpt: str = ""

    # 已排除的路径。
    #
    # 这个字段一度只存在于单轮 ROUND.md 里、解析完就丢，跨轮从不累积。
    # 参考 Archon（北大的 Lean 形式化 agent）的经验：它把"agent 反复走同一条死路"
    # 列为规模化后的首要问题，解法是跨会话的 memory 文档。对编排器来说，
    # 「哪些路已经证明走不通、依据是什么」是下一轮最该读到的东西——
    # 它比"上一轮我干了什么"更能防止原地打转。
    excluded: list[Excluded] = Field(default_factory=list)
    # 最近几轮的结论（不含原始日志），用于停滞检测。只留尾部 N 条。
    recent_summaries: list[str] = Field(default_factory=list)
    # 最近一次停滞检测给出的理由（空 = 没停滞）。写进下一轮 prompt 当面点出。
    stall_reasons: list[str] = Field(default_factory=list)
    # 授权范围（engagement 边界）。空 = 未配置，此时 prompt 不提边界，
    # 但 Rego 闸仍然默认拒绝——两边口径一致：没有范围就是不行动。
    scope: dict[str, Any] = Field(default_factory=dict)
    # 扫描产物的数据目录。配置后每轮把资产概况和"还没打的地方"注入 prompt——
    # 这是补齐"agent 不知道全局"的缺口：它只看得到当前这一轮的材料。
    store_root: str = ""
    # 是否用执行层（nai-run）跑每一轮。开启后单轮有 cgroup 硬限额与进程树清理，
    # 能根治"孙进程变孤儿"和"两路一起跑把机器压死"。默认关，因为它是新路径，
    # 而裸 subprocess 那条已经跑通过。
    supervised: bool = False
    round_mem: str = ""
    # 执行层（nai-run）回报的上一轮指标：峰值内存用于 OOM 归因，
    # cleaned 是"killpg 够不到的逃逸进程"个数。
    last_peak_mem_kb: int = 0
    last_oom_kill: int = 0
    last_cleaned: int = 0

    # ---------- dict 兼容层 ----------
    # 这层存在的唯一理由是避免大规模重写调用点；它不改变"赋值要过校验"这一点。

    def __getitem__(self, key: str) -> Any:
        try:
            return getattr(self, key)
        except AttributeError as exc:
            raise KeyError(key) from exc

    def __setitem__(self, key: str, value: Any) -> None:
        if not hasattr(self, key):
            raise KeyError(f"未知字段 {key!r}：要加字段请先写进 StateView 定义")
        setattr(self, key, value)

    def get(self, key: str, default: Any = None) -> Any:
        return getattr(self, key, default)

    # ---------- 序列化 ----------

    def to_json_dict(self) -> dict[str, Any]:
        """落盘用。mode="json" 保证没有 datetime / 自定义对象漏进磁盘。"""
        return self.model_dump(mode="json")

    @classmethod
    def from_raw(cls, raw: dict[str, Any]) -> "StateView":
        """从磁盘读入并迁移。

        未知字段靠 extra="allow" 保留下来（老版本写的 raw_submit_hits 之类不会丢），
        缺失字段用默认值补齐。版本高于本代码时明确拒绝，而不是猜着读——
        这对应契约版本化里的 MAJOR 规则。
        """
        ver = int(raw.get("schema_version") or 0)
        if ver > SCHEMA_VERSION:
            raise ValueError(
                f"状态文件 schema_version={ver} 高于本代码支持的 {SCHEMA_VERSION}，"
                "拒绝读取（避免把未来格式误解成当前格式）"
            )
        if "challenge" not in raw or not raw.get("challenge"):
            raise ValueError("状态文件缺少 challenge 字段，无法归档")
        return cls.model_validate(raw)


class StallSignal(BaseModel):
    """停滞信号。

    为什么是规则而不是再叫一次模型：Archon 用 Review Agent 做这件事，是因为它跑
    80 小时、一次判定摊薄到可忽略。编排器一轮就 15 分钟，再为"我们是不是卡住了"
    单独付一次模型调用不划算。先用便宜的结构化信号判，判出停滞再把结论写进 prompt
    让下一轮自己换策略——这一步不花钱。

    Archon 的原话是「stall 只在连续多个会话上才表现为模式」，所以这里的判据全是
    **跨轮累积量**，不是单轮快照。
    """

    stalled: bool = False
    reasons: list[str] = Field(default_factory=list)
    counters: dict[str, float] = Field(default_factory=dict)

    def describe(self) -> str:
        if not self.stalled:
            return ""
        return "；".join(self.reasons)


def check_stall(st: "StateView", window: int = 3) -> StallSignal:
    """规则化停滞检测。

    四条判据，各自对应一种实测过的失败形态：
    1. 连续 N 轮无进展 —— 最直接的停滞。
    2. 高比例轮次靠日志回捞 —— 说明 agent 从不写 ROUND.md，跨轮记忆一直断着。
    3. 切过阶段却零裁决 —— 策略换了两回还是没落地任何结论，说明换方向也没用。
    4. 悬空假设堆积 —— 提了不验证，等于用"提假设"冒充进展。
    """
    reasons: list[str] = []
    rnd = max(st.round, 1)
    since_progress = st.round - st.last_progress_round
    open_hyps = [h for h in st.hypotheses if h.status == "open"]
    salvage_ratio = st.salvaged_rounds / rnd

    if since_progress >= window:
        reasons.append(f"连续 {since_progress} 轮没有进展（要有新假设或新裁决才算）")
    if st.round >= window and salvage_ratio >= 0.6:
        reasons.append(
            f"{st.round} 轮里有 {st.salvaged_rounds} 轮靠日志回捞"
            "（说明每轮都没写出 ROUND.md，跨轮记忆是断的）"
        )
    if st.phase_switches >= 2 and st.verdicts_total == 0:
        reasons.append(f"已切换 {st.phase_switches} 次阶段，却没有任何一条裁决落地")
    if len(open_hyps) >= 5:
        reasons.append(f"{len(open_hyps)} 条假设悬着没验证，提假设不能代替验证")

    stalled = len(reasons) >= 2 or since_progress >= window * 2
    return StallSignal(
        stalled=stalled,
        reasons=reasons,
        counters={
            "rounds_since_progress": float(since_progress),
            "salvage_ratio": round(salvage_ratio, 3),
            "open_hypotheses": float(len(open_hyps)),
            "phase_switches": float(st.phase_switches),
        },
    )
