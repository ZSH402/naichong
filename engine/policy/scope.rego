# 奶虫 · 范围闸策略（OPA / Rego v1）
#
# 存在的理由，用一次真实事故说明：比赛时为绕开自己的范围闸，把 allowedHosts
# 和 deniedTools 全清空了——在 CTF 靶机上这只是权宜，在真实渗透里等于拆掉授权边界。
# 问题不在"清空"这个动作，在于闸的口径散落在 Python 的 if 里，改起来太容易、
# 也没有任何东西能证明它现在拦得住什么。
#
# 策略挪到 Rego 之后有三个性质：
#   1. 可单测 —— scope_test.rego 里逐条断言，不依赖整个系统的运行
#   2. 可审计 —— 客户问"你怎么保证没打到范围外"，答案是这份文件加它的测试
#   3. 默认拒绝 —— default allow := false，漏配等于拒绝，而不是漏配等于放行
#
# ⚠️ 设计决定：授权范围从 **input.scope** 传进来，策略**完全不读 data**。
# 第一版写成 `object.get(data, "scope", {})`，结果是 Rego 递归错误——
# `data` 是整棵树，测试包 `data.nai.scope_test` 也在里面，测试又调用本策略，
# 于是 data -> 规则 -> data 成环。改成从 input 取之后，策略变成无状态纯函数：
# 同一份策略服务不同 engagement，只需调用方传入不同的 scope。

package nai.scope

import rego.v1

# —— 默认拒绝 ——
# 这一行是整个策略的立场。写反（default allow := true）等于把所有 if 变成黑名单。
default allow := false

# 逐层取值。Rego 没有 `object.get(a,"k",{}).get(...)` 这种方法链，只能绑中间值。
_sc := object.get(input, "scope", {})
_cidrs := object.get(_sc, "cidrs", [])
_hosts := object.get(_sc, "hosts", [])
_tools := object.get(_sc, "tools", [])

# —————————————————————————— 放行规则（收进集合）——————————————————————————

# 用集合而不是单值规则：多条规则可能同时命中（比如一个目标同时落在两个 CIDR 里），
# 单值 `_rule := ...` 会因产生多个输出而报错，集合天然容纳。

rules contains "connect.in_cidr" if {
	input.action == "connect"
	some cidr in _cidrs
	net.cidr_contains(cidr, input.target)
}

# HTTP 请求：host 必须在授权域名清单里（精确匹配，不做后缀通配）。
# 刻意不支持 *.example.com：通配会把"子域被第三方接管"变成越界入口。
rules contains "http.allowed_host" if {
	input.action == "http_request"
	host := lower(object.get(input, "host", ""))
	some h in _hosts
	host == lower(h)
}

# 执行工具：必须在白名单内。
rules contains "tool.allowed" if {
	input.action == "run_tool"
	some t in _tools
	input.tool == t
}

# 命中任意一条即放行。
allow if count(rules) > 0

# —————————————————————————— 决策出口 ——————————————————————————
# 调用方只读这一个结构，不需要知道内部有几条规则。
decision := {
	"allow": allow,
	"rule": _rule,
	"reason": reason,
	"policy_version": policy_version,
}

# 命中的规则名。多条同时命中时取排序后第一个，保证输出稳定（便于 diff 与快照测试）。
_rule := msg if {
	allow
	sorted := sort([r | some r in rules])
	msg := sorted[0]
} else := ""

# —————————————————————————— 拒绝理由 ——————————————————————————
# 拒绝理由是给人看的。审计时最有价值的不是"拒绝了"，而是"因为哪一条拒绝"。

# 默认空串。没有这一行，允许分支里 `reason` 未定义，而 `decision` 又引用了它，
# 结果是 decision 整体求值为 {}——放行的请求反而拿不到 allow=true。
# 这个坑很隐蔽：拒绝路径全都正常，只有放行路径静默变空。
default reason := ""

# 优先级最高的一种：范围数据根本没配。
# 这几乎总是漏配而不是真越界——先说清楚，免得排查方向错。
reason := "未配置授权范围（scope.cidrs / hosts / tools 全空），默认拒绝；请先补齐范围数据" if {
	not allow
	count(_cidrs) == 0
	count(_hosts) == 0
	count(_tools) == 0
}

# 有范围数据但没命中：把目标回显出来，方便对照。
#
# 必须显式排除"范围全空"的情形：Rego 的 complete rule（同名多规则 + default）
# 要求任意输入下最多一个分支成立，否则报 conflict。上一个 bug 就是
# 「未配置」和「未命中」在空 scope 时同时为真。
reason := msg if {
	not allow
	count(_cidrs) + count(_hosts) + count(_tools) > 0
	msg := sprintf("动作 %q 未命中任何放行规则（目标/工具：%s）", [
		object.get(input, "action", "<缺失>"),
		_target_desc,
	])
}

_target_desc := d if {
	d := object.get(input, "target", null)
	d != null
} else := d if {
	d := object.get(input, "host", null)
	d != null
} else := d if {
	d := object.get(input, "tool", null)
	d != null
} else := "<无>"

# —————————————————————————— 审计辅助 ——————————————————————————

# 显式暴露策略版本：改了策略就要改这个号，便于审计时对齐。
policy_version := "1"

# 供运维自查：把本次判定用到的范围回显出来，确认跑的是预期那份配置。
scope_summary := {
	"cidrs": _cidrs,
	"hosts": _hosts,
	"tools": _tools,
}
