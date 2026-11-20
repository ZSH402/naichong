# 范围闸策略的单测（Rego 原生，`opa test` 直接跑）
#
# 这份文件本身就是交付物的一部分：客户问"你怎么保证没打到范围外"，
# 答案不是"我们很小心"，而是这份测试加上 scope.rego。
#
# 范围数据放在 input.scope 里传，所以每条用例都是一次纯函数调用，
# 不依赖任何外部 data —— 这也是策略当初改成不读 data 的直接原因。

package nai.scope_test

import rego.v1

import data.nai.scope


# 范围 CIDR 内的 IP 放行
test_connect_in_cidr_allowed if {
	d := scope.decision with input as {"action": "connect", "target": "10.1.2.3", "scope": {"cidrs": ["10.0.0.0/8", "192.168.56.0/24", "2001:db8::/32"], "hosts": ["app.example.com", "api.example.com"], "tools": ["nmap", "ffuf", "curl"]}}
	d.allow == true
	d.rule == "connect.in_cidr"
}

# IPv6 前缀同样生效
test_connect_ipv6_allowed if {
	d := scope.decision with input as {"action": "connect", "target": "2001:db8::1", "scope": {"cidrs": ["10.0.0.0/8", "192.168.56.0/24", "2001:db8::/32"], "hosts": ["app.example.com", "api.example.com"], "tools": ["nmap", "ffuf", "curl"]}}
	d.allow == true
}

# 域名匹配忽略大小写
test_http_allowed_host_case_insensitive if {
	d := scope.decision with input as {"action": "http_request", "host": "APP.example.com", "scope": {"cidrs": ["10.0.0.0/8", "192.168.56.0/24", "2001:db8::/32"], "hosts": ["app.example.com", "api.example.com"], "tools": ["nmap", "ffuf", "curl"]}}
	d.allow == true
	d.rule == "http.allowed_host"
}

# 白名单工具放行
test_tool_allowed if {
	d := scope.decision with input as {"action": "run_tool", "tool": "nmap", "scope": {"cidrs": ["10.0.0.0/8", "192.168.56.0/24", "2001:db8::/32"], "hosts": ["app.example.com", "api.example.com"], "tools": ["nmap", "ffuf", "curl"]}}
	d.allow == true
	d.rule == "tool.allowed"
}

# 范围外 IP 必须拒绝（核心断言）
test_connect_outside_cidr_denied if {
	d := scope.decision with input as {"action": "connect", "target": "8.8.8.8", "scope": {"cidrs": ["10.0.0.0/8", "192.168.56.0/24", "2001:db8::/32"], "hosts": ["app.example.com", "api.example.com"], "tools": ["nmap", "ffuf", "curl"]}}
	d.allow == false
}

# 相邻网段不能因前缀相似被放过
test_adjacent_cidr_denied if {
	d := scope.decision with input as {"action": "connect", "target": "11.0.0.1", "scope": {"cidrs": ["10.0.0.0/8", "192.168.56.0/24", "2001:db8::/32"], "hosts": ["app.example.com", "api.example.com"], "tools": ["nmap", "ffuf", "curl"]}}
	d.allow == false
}

# 未授权域名拒绝
test_unknown_host_denied if {
	d := scope.decision with input as {"action": "http_request", "host": "evil.com", "scope": {"cidrs": ["10.0.0.0/8", "192.168.56.0/24", "2001:db8::/32"], "hosts": ["app.example.com", "api.example.com"], "tools": ["nmap", "ffuf", "curl"]}}
	d.allow == false
}

# 子域不等同父域授权（子域可能被第三方接管）
test_subdomain_denied if {
	d := scope.decision with input as {"action": "http_request", "host": "a.app.example.com", "scope": {"cidrs": ["10.0.0.0/8", "192.168.56.0/24", "2001:db8::/32"], "hosts": ["app.example.com", "api.example.com"], "tools": ["nmap", "ffuf", "curl"]}}
	d.allow == false
}

# 非白名单工具拒绝
test_unlisted_tool_denied if {
	d := scope.decision with input as {"action": "run_tool", "tool": "sqlmap", "scope": {"cidrs": ["10.0.0.0/8", "192.168.56.0/24", "2001:db8::/32"], "hosts": ["app.example.com", "api.example.com"], "tools": ["nmap", "ffuf", "curl"]}}
	d.allow == false
}

# 未知动作一律拒绝
test_unknown_action_denied if {
	d := scope.decision with input as {"action": "reboot", "target": "10.1.2.3", "scope": {"cidrs": ["10.0.0.0/8", "192.168.56.0/24", "2001:db8::/32"], "hosts": ["app.example.com", "api.example.com"], "tools": ["nmap", "ffuf", "curl"]}}
	d.allow == false
}

# 缺字段不能崩，要安静拒绝
test_missing_target_denied if {
	d := scope.decision with input as {"action": "connect", "scope": {"cidrs": ["10.0.0.0/8", "192.168.56.0/24", "2001:db8::/32"], "hosts": ["app.example.com", "api.example.com"], "tools": ["nmap", "ffuf", "curl"]}}
	d.allow == false
}

# 拒绝理由回显目标
test_deny_reason_mentions_target if {
	d := scope.decision with input as {"action": "connect", "target": "8.8.8.8", "scope": {"cidrs": ["10.0.0.0/8", "192.168.56.0/24", "2001:db8::/32"], "hosts": ["app.example.com", "api.example.com"], "tools": ["nmap", "ffuf", "curl"]}}
	contains(d.reason, "8.8.8.8")
}

# —————————— 没配范围时：拒绝 + 明确理由 ——————————
# 针对实际踩过的坑：范围数据漏配时，闸必须拒绝而不是全放行。

test_empty_scope_denies_everything if {
	d := scope.decision with input as {"action": "connect", "target": "10.1.2.3", "scope": {}}
	d.allow == false
}

test_empty_scope_says_what_is_missing if {
	d := scope.decision with input as {"action": "connect", "target": "10.1.2.3", "scope": {}}
	contains(d.reason, "未配置授权范围")
}

# 只有 cidrs 配了、hosts/tools 没配时，不应误报"全空"
test_partial_scope_not_reported_as_empty if {
	d := scope.decision with input as {"action": "http_request", "host": "x.com", "scope": {"cidrs": ["10.0.0.0/8"]}}
	d.allow == false
	not contains(d.reason, "未配置授权范围")
}
