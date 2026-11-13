window.__ModuleLoader__.load({
	id: "@dsh-secops/client-ui-secops",
	factory: (require) => {
		var module = { exports: {} }
		var exports = module.exports
		Object.defineProperty(exports, Symbol.toStringTag, { value: "Module" })
		let react_jsx_runtime = require("react/jsx-runtime")
		let react = require("react")

		// ── 本地化 ────────────────────────────────────────────────
		// 只做中英两份：这套系统的使用者是中文语境，英文是给外部复核者看的。
		const NS = "secops"
		const zh = {
			tab: "安全面板",
			empty: "这个会话还没有断言。跑一轮 council_run 或让主控开始工作后，这里会出现结论与证据链。",
			total: "断言",
			confirmed: "已确认",
			refuted: "已证伪",
			open: "未定论",
			verification: "验证档位",
			"v.cross-checked": "已对照",
			"v.calibrated": "已校准",
			"v.reproducible": "可复现",
			"v.none": "未验证",
			evidence: "证据",
			paths: "独立路径",
			proof: "证明",
			baseline: "对照",
			control: "校准",
			replayed: "已重放",
			blame: "归因",
			shape: "形态",
			expand: "展开证据",
			collapse: "收起",
			noEvidence: "没有证据",
			loading: "正在读取 claim 账本…",
			fetchFailed: "读取失败",
			totalLine: "共",
			byAgent: "按工具（判断准不准，只算明确归因的推翻）",
			timeCredit: "时间信用",
			remaining: "剩余",
			spent: "已用",
			debited: "已扣",
			granted: "已续期",
			expiredTag: "已耗尽",
			coverage: "覆盖账本",
			covered: "已覆盖",
			partialCovered: "部分",
			notScanned: "未扫描",
			notRecorded: "未记录",
			exportReport: "导出报告",
			credentials: "副 agent 凭据",
			credNone: "还没有配置任何副 agent 凭据。strix 这类需要 LLM key 的 agent 会被判不可用。",
			credSave: "保存",
			credClear: "清除",
			credSaved: "已保存",
			credFailed: "保存失败",
			credPlaceholder: "粘贴 key，不会回显",
			assets: "资产",
		}
		const en = {
			tab: "SecOps",
			empty: "No claims in this session yet. Run a council round or let the controller work; conclusions and evidence chains will show up here.",
			total: "claims",
			confirmed: "confirmed",
			refuted: "refuted",
			open: "open",
			verification: "verification",
			"v.cross-checked": "cross-checked",
			"v.calibrated": "calibrated",
			"v.reproducible": "reproducible",
			"v.none": "unverified",
			evidence: "evidence",
			paths: "paths",
			proof: "proof",
			baseline: "baseline",
			control: "control",
			replayed: "replayed",
			blame: "blame",
			shape: "shape",
			expand: "Show evidence",
			collapse: "Hide",
			noEvidence: "no evidence",
			loading: "Reading the claim ledger…",
			fetchFailed: "Fetch failed",
			totalLine: "of",
			byAgent: "By tool (accuracy only; unattributed refutations are not blamed)",
			timeCredit: "Time credit",
			remaining: "left",
			spent: "spent",
			debited: "charged",
			granted: "granted",
			expiredTag: "exhausted",
			coverage: "Coverage",
			covered: "covered",
			partialCovered: "partial",
			notScanned: "not scanned",
			notRecorded: "not recorded",
			exportReport: "Export report",
			assets: "assets",
		}

		// ── 派生逻辑 ──────────────────────────────────────────────
		//
		// 验证档位不在 projection 里（它是后端由证据算出来的），这里按同一套规则重算。
		// 重算而不是「让后端加字段」是刻意的：这个面板只读，后端一行都不用改；
		// 代价是规则有两份，所以下面的判定顺序必须和 provenance.ts 的 verificationOf 一致
		// —— baseline 压过 control，两者都不如「有目标对照」强。
		function verificationOf(claim) {
			const evidence = Array.isArray(claim?.evidence) ? claim.evidence : []
			const strict = evidence.some(
				(e) =>
					e?.role !== "baseline" &&
					e?.role !== "control" &&
					e?.replay?.verified === true &&
					e?.replay?.matchKind === "strict",
			)
			const hasBaseline = evidence.some((e) => e?.role === "baseline")
			const hasControl = evidence.some((e) => e?.role === "control")
			if (strict && hasBaseline) return "cross-checked"
			if (strict && hasControl) return "calibrated"
			if (strict) return "reproducible"
			return "none"
		}

		function roleCounts(claim) {
			const out = { proof: 0, baseline: 0, control: 0 }
			for (const e of claim?.evidence ?? []) {
				const role = e?.role ?? "proof"
				if (role in out) out[role] += 1
				else out.proof += 1
			}
			return out
		}

		/**
		 * 按工具统计战绩。
		 *
		 * 后端没把 credit 账本暴露出来（它不在 claims.jsonl 里，是运行时内存态），
		 * 但**判断准不准的原始事实全在 claim 里**：每条证据的 source.argv[0] 就是
		 * 产出它的工具，claim 的 status 就是这条判断的结果。所以这里按和 credit.ts
		 * 相同的口径重算一遍——按 claim 计数而不是按执行次数，只统计被明确归因的推翻。
		 *
		 * 重算出来的分和 credit.ts 的 Beta 后验不完全等价（那边有衰减和探索项），
		 * 所以这里只展示原始计数，不给分数——展示一个「看起来像分」的数字而它和
		 * 调度实际用的分不是一回事，比不展示更糟。
		 */
		function tallyAgents(claims) {
			const by = new Map()
			for (const claim of claims) {
				const tools = new Set()
				for (const e of claim?.evidence ?? []) {
					const tool = e?.source?.argv?.[0]
					if (typeof tool === 'string' && tool !== '') tools.add(tool.split('/').pop() ?? tool)
				}
				if (tools.size === 0) continue
				const blamed = new Set((claim?.blame ?? []).map((b) => String(b).split('/').pop() ?? String(b)))
				for (const tool of tools) {
					const row = by.get(tool) ?? { tool, reported: 0, confirmed: 0, refuted: 0, open: 0 }
					row.reported += 1
					if (claim?.status === 'confirmed') row.confirmed += 1
					else if (claim?.status === 'refuted') {
						if (blamed.has(tool)) row.refuted += 1
						else row.open += 1
					} else row.open += 1
					by.set(tool, row)
				}
			}
			return [...by.values()].sort((a, b) => b.confirmed + b.refuted - (a.confirmed + a.refuted) || b.reported - a.reported)
		}

		function humanMs(ms) {
			if (typeof ms !== "number" || !Number.isFinite(ms)) return "-"
			const sign = ms < 0 ? "-" : ""
			const total = Math.round(Math.abs(ms) / 1000)
			const m = Math.floor(total / 60)
			const s = total % 60
			return m === 0 ? `${sign}${String(s)}s` : `${sign}${String(m)}m${s === 0 ? "" : String(s) + "s"}`
		}

		/**
		 * 生成 Markdown 报告。
		 *
		 * 在前端拼而不是让后端出：报告就是「我能看到的这些东西的文字版」，
		 * 多一个后端端点只是多一处会与面板不一致的地方。
		 * 结构按复核者关心的顺序排：结论 → 证据 → 已证伪方向 → 覆盖缺口。
		 */
		function buildReport(claims, coverage, exportedAt) {
			const lines = []
			const confirmed = claims.filter((c) => c.status === "confirmed")
			const refuted = claims.filter((c) => c.status === "refuted")
			const open = claims.filter((c) => c.status !== "confirmed" && c.status !== "refuted")

			lines.push("# SecOps 报告", "")
			lines.push(`导出时间：${exportedAt}`)
			lines.push(`断言总数：${String(claims.length)}（已确认 ${String(confirmed.length)} / 已证伪 ${String(refuted.length)} / 未定论 ${String(open.length)}）`, "")

			const section = (title, list) => {
				if (list.length === 0) return
				lines.push(`## ${title}`, "")
				for (const c of list) {
					const verify = verificationOf(c)
					const ev = Array.isArray(c.evidence) ? c.evidence : []
					const counts = roleCounts(c)
					lines.push(`### ${String(c.claim)}`, "")
					lines.push(
						`- 状态：${String(c.status)}｜验证档位：${verify}｜独立路径：${String(c.independentPaths ?? 0)}`,
					)
					lines.push(
						`- 证据：${String(ev.length)} 条（证明 ${String(counts.proof)} / 对照 ${String(counts.baseline)} / 校准 ${String(counts.control)}）`,
					)
					if (Array.isArray(c.blame) && c.blame.length > 0) lines.push(`- 归因：${c.blame.join(", ")}`)
					if (typeof c.falsifier === "string" && c.falsifier !== "") lines.push(`- 证伪条件：${c.falsifier}`)
					if (ev.length > 0) {
						lines.push("", "证据明细：", "")
						for (const e of ev) {
							const role = e.role ?? "proof"
							const replay = e.replay?.verified === true ? ` 已重放${e.replay.matchKind === "strict" ? "(strict)" : ""}` : ""
							lines.push(`- \`${String(e.ref)}\`｜${role}｜${String(e.pathKey ?? "")}${replay}`)
							if (typeof e.note === "string" && e.note !== "") lines.push(`  - ${e.note}`)
						}
					}
					lines.push("")
				}
			}

			section("已确认的结论", confirmed)
			section("未定论的线索", open)
			section("已证伪的方向", refuted)

			if (Array.isArray(coverage) && coverage.length > 0) {
				lines.push("## 覆盖情况", "")
				const byStatus = {}
				for (const r of coverage) byStatus[r.status] = (byStatus[r.status] ?? 0) + 1
				lines.push(
					`- 记录 ${String(coverage.length)} 条：` +
						Object.entries(byStatus)
							.map(([k, v]) => `${k}=${String(v)}`)
							.join(" "),
					"",
				)
				const gaps = coverage.filter((r) => r.status === "not-scanned" || r.status === "not-recorded")
				if (gaps.length > 0) {
					lines.push("尚未覆盖：", "")
					for (const g of gaps.slice(0, 50)) lines.push(`- ${String(g.asset)} × ${String(g.check)}：${String(g.status)}`)
					lines.push("")
				}
			}

			return lines.join("\n")
		}

		function download(name, text) {
			try {
				const blob = new Blob([text], { type: "text/markdown;charset=utf-8" })
				const url = URL.createObjectURL(blob)
				const a = document.createElement("a")
				a.href = url
				a.download = name
				document.body.appendChild(a)
				a.click()
				document.body.removeChild(a)
				setTimeout(() => URL.revokeObjectURL(url), 1000)
			} catch (e) {
				window.__secopsUi = { error: String(e) }
			}
		}

		/** 覆盖状态按四态归类：covered / partial / not-scanned / not-recorded。 */
		function coverageStatusRows(rows, t) {
			const map = {
				covered: { key: "covered", label: "covered", text: t("covered"), color: C.success },
				partial: { key: "partial", label: "partial", text: t("partialCovered"), color: C.warning },
				"not-scanned": { key: "not-scanned", label: "not-scanned", text: t("notScanned"), color: C.tertiary },
				"not-recorded": { key: "not-recorded", label: "not-recorded", text: t("notRecorded"), color: C.tertiary },
			}
			const counts = {}
			for (const r of rows) counts[r?.status] = (counts[r?.status] ?? 0) + 1
			return Object.entries(counts)
				.map(([status, n]) => {
					const base = map[status] ?? { key: status, label: status, text: status, color: C.tertiary }
					return { ...base, text: `${base.text} ${String(n)}` }
				})
				.sort((a, b) => b.text.localeCompare(a.text))
		}

		// ── 配色 ──────────────────────────────────────────────────
		// 全部走 DSH 自己的语义 token：面板跟着主题走，深色浅色都不用手动适配。
		const C = {
			primary: "var(--dsw-alias-label-primary)",
			secondary: "var(--dsw-alias-label-secondary)",
			tertiary: "var(--dsw-alias-label-tertiary)",
			border: "var(--dsw-alias-border-l1, var(--dsw-alias-border-l2, rgba(127,127,127,0.24)))",
			bg: "var(--dsw-alias-bg-layer-1, transparent)",
			success: "var(--dsw-alias-state-success-primary)",
			warning: "var(--dsw-alias-state-warning-primary, #d97706)",
			danger: "var(--dsw-static-red-6, #dc2626)",
			info: "var(--dsw-static-blue-6, #2563eb)",
			code: "var(--ds-font-family-code, ui-monospace, SFMono-Regular, Menlo, monospace)",
		}

		const STATUS_COLOR = {
			confirmed: C.success,
			refuted: C.danger,
			partial: C.warning,
			hypothesis: C.tertiary,
			inference: C.info,
		}

		const VERIFY_COLOR = {
			"cross-checked": C.success,
			calibrated: C.info,
			reproducible: C.warning,
			none: C.tertiary,
		}

		// ── 小组件 ────────────────────────────────────────────────

		function Badge({ color, children, title }) {
			return react_jsx_runtime.jsx("span", {
				title: title,
				style: {
					display: "inline-block",
					padding: "0 6px",
					borderRadius: 4,
					fontSize: 11,
					lineHeight: "18px",
					color: color,
					border: `1px solid ${color}`,
					whiteSpace: "nowrap",
				},
				children: children,
			})
		}

		function Stat({ label, value, color }) {
			return react_jsx_runtime.jsxs("div", {
				style: { display: "flex", flexDirection: "column", gap: 2, minWidth: 54 },
				children: [
					react_jsx_runtime.jsx("span", {
						style: { fontSize: 17, fontWeight: 600, color: color ?? C.primary, fontFamily: C.code },
						children: value,
					}),
					react_jsx_runtime.jsx("span", {
						style: { fontSize: 10, color: C.tertiary, letterSpacing: 0.3 },
						children: label,
					}),
				],
			})
		}

		function Dot({ color }) {
			return react_jsx_runtime.jsx("span", {
				style: {
					width: 6,
					height: 6,
					borderRadius: 3,
					background: color,
					display: "inline-block",
					flexShrink: 0,
					marginTop: 6,
				},
			})
		}

		function EvidenceRow({ item, t }) {
			const role = item?.role ?? "proof"
			const replayed = item?.replay?.verified === true
			const strict = item?.replay?.matchKind === "strict"
			const relevance = item?.relevance?.strength
			const roleColor = role === "baseline" ? C.info : role === "control" ? C.warning : C.secondary
			return react_jsx_runtime.jsxs("div", {
				style: {
					display: "flex",
					gap: 6,
					alignItems: "baseline",
					flexWrap: "wrap",
					padding: "3px 0",
					borderTop: `1px dashed ${C.border}`,
					fontSize: 11,
				},
				children: [
					react_jsx_runtime.jsx(Badge, { color: roleColor, children: t(role) }),
					react_jsx_runtime.jsx("span", {
						style: { color: C.secondary, fontFamily: C.code, wordBreak: "break-all" },
						children: String(item?.ref ?? ""),
					}),
					item?.pathKey === undefined
						? null
						: react_jsx_runtime.jsx("span", { style: { color: C.tertiary, fontFamily: C.code }, children: String(item.pathKey) }),
					replayed
						? react_jsx_runtime.jsx("span", {
								style: { color: strict ? C.success : C.warning },
								children: `${t("replayed")}${strict ? " · strict" : ""}`,
							})
						: null,
					relevance === undefined
						? null
						: react_jsx_runtime.jsx("span", {
								style: { color: relevance === "strong" ? C.success : C.tertiary },
								children: `relevance=${relevance}`,
							}),
					item?.note === undefined
						? null
						: react_jsx_runtime.jsx("span", { style: { color: C.tertiary, flexBasis: "100%" }, children: String(item.note) }),
				],
			})
		}

		function ClaimCard({ claim, t }) {
			const [open, setOpen] = react.useState(false)
			const status = String(claim?.status ?? "hypothesis")
			const verify = verificationOf(claim)
			const counts = roleCounts(claim)
			const evidence = Array.isArray(claim?.evidence) ? claim.evidence : []
			const blame = Array.isArray(claim?.blame) ? claim.blame : []

			return react_jsx_runtime.jsxs("div", {
				style: {
					border: `1px solid ${C.border}`,
					borderRadius: 8,
					padding: "8px 10px",
					display: "flex",
					flexDirection: "column",
					gap: 6,
					background: C.bg,
				},
				children: [
					react_jsx_runtime.jsxs("div", {
						style: { display: "flex", gap: 8, alignItems: "flex-start" },
						children: [
							react_jsx_runtime.jsx(Dot, { color: STATUS_COLOR[status] ?? C.tertiary }),
							react_jsx_runtime.jsxs("div", {
								style: { flex: 1, minWidth: 0, display: "flex", flexDirection: "column", gap: 5 },
								children: [
									react_jsx_runtime.jsx("div", {
										style: { fontSize: 12.5, lineHeight: 1.45, color: C.primary, wordBreak: "break-word" },
										children: String(claim?.claim ?? ""),
									}),
									react_jsx_runtime.jsxs("div", {
										style: { display: "flex", gap: 6, flexWrap: "wrap", alignItems: "center" },
										children: [
											react_jsx_runtime.jsx(Badge, { color: STATUS_COLOR[status] ?? C.tertiary, children: status }),
											react_jsx_runtime.jsx(Badge, {
												color: VERIFY_COLOR[verify],
												title: t("verification"),
												children: t(`v.${verify}`),
											}),
											react_jsx_runtime.jsxs("span", {
												style: { fontSize: 11, color: C.tertiary, fontFamily: C.code },
												children: [
													`${t("evidence")} ${String(evidence.length)}`,
													counts.baseline > 0 ? ` · ${t("baseline")} ${String(counts.baseline)}` : "",
													counts.control > 0 ? ` · ${t("control")} ${String(counts.control)}` : "",
													` · ${t("paths")} ${String(claim?.independentPaths ?? 0)}`,
												],
											}),
											claim?.shape === undefined
												? null
												: react_jsx_runtime.jsx("span", {
														style: { fontSize: 11, color: C.tertiary, fontFamily: C.code },
														children: `${t("shape")}=${String(claim.shape)}`,
													}),
										],
									}),
									blame.length > 0
										? react_jsx_runtime.jsx("div", {
												style: { fontSize: 11, color: C.danger },
												children: `${t("blame")}: ${blame.join(", ")}`,
											})
										: null,
								],
							}),
							evidence.length > 0
								? react_jsx_runtime.jsx("button", {
										type: "button",
										onClick: () => setOpen((v) => !v),
										style: {
											fontSize: 11,
											color: C.secondary,
											background: "transparent",
											border: `1px solid ${C.border}`,
											borderRadius: 5,
											padding: "2px 7px",
											cursor: "pointer",
											flexShrink: 0,
										},
										children: open ? t("collapse") : t("expand"),
									})
								: null,
						],
					}),
					open && evidence.length > 0
						? react_jsx_runtime.jsx("div", {
								style: { paddingLeft: 14, display: "flex", flexDirection: "column" },
								children: evidence.map((item, i) =>
									react_jsx_runtime.jsx(EvidenceRow, { item: item, t: t }, `${String(item?.ref ?? "")}-${String(i)}`),
								),
							})
						: null,
				],
			})
		}

		// ── 主面板 ────────────────────────────────────────────────

		// 与 host 半边约定的只读端点。
		const LEDGER_ROUTE = "/secops-ledger"
		const POLL_MS = 3000

		/**
		 * 订阅 claim 账本。
		 *
		 * 用轮询而不是 projection 订阅：宿主那边的 session projection 在这套组合里
		 * 拿不到数据（两份 dsh-session 实例导致 brand check 失败），而账本文件本身
		 * 就是唯一真相。3 秒一次，面板不是实时监控，够用且不会打满 CPU。
		 */
		function useLedger() {
			const [state, setState] = react.useState({ phase: "loading", claims: [], note: undefined })
			react.useEffect(() => {
				let alive = true
				const load = async () => {
					try {
						const res = await fetch(LEDGER_ROUTE, { cache: "no-store", credentials: "same-origin" })
						if (!res.ok) {
							if (alive) setState({ phase: "error", claims: [], note: `HTTP ${String(res.status)}` })
							return
						}
						const body = await res.json()
						if (!alive) return
						setState({
							phase: "ready",
							claims: Array.isArray(body?.claims) ? body.claims : [],
							note: typeof body?.note === "string" ? body.note : undefined,
							total: typeof body?.total === "number" ? body.total : undefined,
							// 后端不提供这个服务时是 undefined —— 面板显示成「没有这一块」，
							// 而不是把整个面板卡在加载状态。
							timeCredit: body?.timeCredit,
						})
					} catch (error) {
						if (alive) setState({ phase: "error", claims: [], note: String(error && error.message ? error.message : error) })
					}
				}
				void load()
				const timer = setInterval(load, POLL_MS)
				return () => {
					alive = false
					clearInterval(timer)
				}
			}, [])
			return state
		}

		/**
		 * 订阅覆盖账本。
		 *
		 * 和 claim 账本分开取：两者的文件位置不同（claim 跟 DSH_HOME，覆盖跟工作目录），
		 * 生命周期也不同——claim 会一直累加，覆盖会被同一 (asset, check) 的新结果覆盖。
		 * 合成一个请求只会让一边的失败拖累另一边。
		 */
		function useCoverage() {
			const [state, setState] = react.useState({ rows: [], assets: [], note: undefined })
			react.useEffect(() => {
				let alive = true
				const load = async () => {
					try {
						const res = await fetch("/secops-coverage", { cache: "no-store", credentials: "same-origin" })
						if (!res.ok) return
						const body = await res.json()
						if (!alive) return
						setState({
							rows: Array.isArray(body?.rows) ? body.rows : [],
							assets: Array.isArray(body?.assets?.rows) ? body.assets.rows : [],
							note: typeof body?.note === "string" ? body.note : undefined,
						})
					} catch {
						/* 下一轮再试 */
					}
				}
				void load()
				const timer = setInterval(load, 5000)
				return () => {
					alive = false
					clearInterval(timer)
				}
			}, [])
			return state
		}

		/**
		 * 凭据状态。
		 *
		 * 只拿「配没配 + 后四位」。写入走 POST，提交后立刻重读，避免面板和磁盘不一致。
		 */
		function useCredentials() {
			const [state, setState] = react.useState({ agents: {} })
			const reload = react.useCallback(async () => {
				try {
					const res = await fetch("/secops-credentials", { cache: "no-store", credentials: "same-origin" })
					if (!res.ok) return
					const body = await res.json()
					setState({ agents: body?.agents ?? {} })
				} catch {
					/* 保持上一次的状态 */
				}
			}, [])
			react.useEffect(() => {
				void reload()
			}, [reload])
			const save = react.useCallback(
				async (agentId, key, value) => {
					try {
						const res = await fetch("/secops-credentials", {
							method: "POST",
							credentials: "same-origin",
							headers: { "content-type": "application/json" },
							body: JSON.stringify({ agentId: agentId, key: key, value: value }),
						})
						const body = await res.json().catch(() => ({}))
						if (body?.agents !== undefined) setState({ agents: body.agents })
						else await reload()
						return body?.ok === true
					} catch {
						return false
					}
				},
				[reload],
			)
			return { agents: state.agents, save }
		}

		/** 一个 agent 的凭据行：显示已配字段，可覆盖或清除。 */
		function CredentialRow({ agentId, info, save, t }) {
			const [draftKey, setDraftKey] = react.useState(info.keys[0]?.name ?? "LLM_API_KEY")
			const [draftValue, setDraftValue] = react.useState("")
			const [busy, setBusy] = react.useState(false)
			const submit = async (value) => {
				if (busy || value === "") return
				setBusy(true)
				const ok = await save(agentId, draftKey, value)
				setBusy(false)
				setDraftValue("")
				if (!ok) window.__secopsUi = { credError: "save failed" }
			}
			return react_jsx_runtime.jsxs("div", {
				style: { display: "flex", flexDirection: "column", gap: 4, padding: "4px 0" },
				children: [
					react_jsx_runtime.jsxs("div", {
						style: { display: "flex", gap: 8, alignItems: "baseline", fontSize: 11.5 },
						children: [
							react_jsx_runtime.jsx("span", { style: { fontFamily: C.code, color: C.secondary, minWidth: 150 }, children: agentId }),
							info.configured
								? react_jsx_runtime.jsx(Badge, { color: C.success, children: info.keys.map((k) => `${k.name} ${k.hint}`).join(" · ") })
								: react_jsx_runtime.jsx(Badge, { color: C.tertiary, children: t("credNone") }),
						],
					}),
					react_jsx_runtime.jsxs("div", {
						style: { display: "flex", gap: 6, alignItems: "center" },
						children: [
							react_jsx_runtime.jsx("input", {
								value: draftKey,
								onChange: (e) => setDraftKey(e.target.value),
								style: { width: 150, fontSize: 11, fontFamily: C.code, padding: "2px 6px", border: `1px solid ${C.border}`, borderRadius: 4, background: "transparent", color: C.primary },
							}),
							react_jsx_runtime.jsx("input", {
								type: "password",
								value: draftValue,
								placeholder: t("credPlaceholder"),
								onChange: (e) => setDraftValue(e.target.value),
								style: { flex: 1, minWidth: 120, fontSize: 11, fontFamily: C.code, padding: "2px 6px", border: `1px solid ${C.border}`, borderRadius: 4, background: "transparent", color: C.primary },
							}),
							react_jsx_runtime.jsx("button", {
								type: "button",
								disabled: busy || draftValue === "",
								onClick: () => void submit(draftValue),
								style: { fontSize: 11, padding: "2px 8px", border: `1px solid ${C.border}`, borderRadius: 4, background: "transparent", color: C.secondary, cursor: busy ? "default" : "pointer" },
								children: t("credSave"),
							}),
							info.configured
								? react_jsx_runtime.jsx("button", {
										type: "button",
										disabled: busy,
										onClick: () => void submit("__CLEAR__"),
										style: { fontSize: 11, padding: "2px 8px", border: `1px solid ${C.border}`, borderRadius: 4, background: "transparent", color: C.danger, cursor: "pointer" },
										children: t("credClear"),
									})
								: null,
						],
					}),
				],
			})
		}

		function SecopsPanel(props) {
			const t = props.t || ((k) => k)
			const ledger = useLedger()
			const coverage = useCoverage()
			const credentials = useCredentials()
			const claims = ledger.claims

			const stats = react.useMemo(() => {
				const by = { confirmed: 0, refuted: 0, open: 0 }
				const verify = { "cross-checked": 0, calibrated: 0, reproducible: 0, none: 0 }
				for (const c of claims) {
					const s = String(c?.status ?? "")
					if (s === "confirmed") by.confirmed += 1
					else if (s === "refuted") by.refuted += 1
					else by.open += 1
					verify[verificationOf(c)] += 1
				}
				return { by, verify }
			}, [claims])

			const agents = react.useMemo(() => tallyAgents(claims), [claims])

			/**
			 * 面板上要显示的凭据行。
			 *
			 * 不是「所有 20 个候选」——大部分工具不需要 key。这里列的是
			 * 「声明了 requiresEnv 的那些」加上「已经配过的」，后者保证配错了也能看见并清除。
			 * 硬编码 strix 是刻意的：requiresEnv 只在 host 侧的候选定义里，
			 * 前端拿不到；与其为此再加一个端点，不如在这里写明当前唯一需要 LLM key 的 agent。
			 */
			const credentialTargets = react.useMemo(() => {
				const targets = { strix: { configured: false, keys: [] } }
				for (const [id, info] of Object.entries(credentials.agents)) {
					targets[id] = info
				}
				return targets
			}, [credentials.agents])

			const ordered = react.useMemo(() => {
				const rank = { confirmed: 0, partial: 1, inference: 2, hypothesis: 3, refuted: 4 }
				return [...claims].sort((a, b) => {
					const ra = rank[String(a?.status ?? "hypothesis")] ?? 9
					const rb = rank[String(b?.status ?? "hypothesis")] ?? 9
					if (ra !== rb) return ra - rb
					return (b?.updatedAt ?? 0) - (a?.updatedAt ?? 0)
				})
			}, [claims])

			if (claims.length === 0) {
				const message =
					ledger.phase === "loading"
						? t("loading")
						: ledger.phase === "error"
							? `${t("fetchFailed")}${ledger.note === undefined ? "" : `：${ledger.note}`}`
							: `${t("empty")}${ledger.note === undefined ? "" : `（${ledger.note}）`}`
				return react_jsx_runtime.jsxs("div", {
					style: { display: "flex", flexDirection: "column", gap: 10, padding: 16 },
					children: [
						react_jsx_runtime.jsx("div", { style: { fontSize: 13, fontWeight: 600, color: C.primary }, children: t("tab") }),
						react_jsx_runtime.jsx("div", { style: { fontSize: 12, color: C.tertiary, lineHeight: 1.7 }, children: message }),
					],
				})
			}

			return react_jsx_runtime.jsxs("div", {
				style: { display: "flex", flexDirection: "column", gap: 10, padding: 12 },
				children: [
					react_jsx_runtime.jsxs("div", {
						style: { display: "flex", gap: 8, alignItems: "center", justifyContent: "flex-end" },
						children: [
							react_jsx_runtime.jsx("button", {
								type: "button",
								onClick: () => {
									const stamp = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19)
									download(`secops-report-${stamp}.md`, buildReport(claims, coverage.rows, new Date().toLocaleString("zh-CN")))
								},
								style: {
									fontSize: 11,
									color: C.secondary,
									background: "transparent",
									border: `1px solid ${C.border}`,
									borderRadius: 5,
									padding: "3px 9px",
									cursor: "pointer",
								},
								children: t("exportReport"),
							}),
						],
					}),
					ledger.timeCredit === undefined
						? null
						: react_jsx_runtime.jsxs("div", {
								style: {
									display: "flex",
									gap: 14,
									flexWrap: "wrap",
									alignItems: "baseline",
									padding: "6px 10px",
									border: `1px solid ${C.border}`,
									borderRadius: 8,
									fontSize: 11.5,
									fontFamily: C.code,
								},
								children: [
									react_jsx_runtime.jsx("span", { style: { color: C.tertiary }, children: t("timeCredit") }),
									react_jsx_runtime.jsxs("span", {
										style: { color: ledger.timeCredit.expired ? C.danger : ledger.timeCredit.remainingMs < 300000 ? C.warning : C.success },
										children: [t("remaining"), " ", humanMs(ledger.timeCredit.remainingMs)],
									}),
									react_jsx_runtime.jsxs("span", { style: { color: C.secondary }, children: [t("spent"), " ", humanMs(ledger.timeCredit.spentMs)] }),
									react_jsx_runtime.jsxs("span", { style: { color: C.secondary }, children: [t("granted"), " +", humanMs(ledger.timeCredit.grantedMs)] }),
									ledger.timeCredit.debitedMs > 0
										? react_jsx_runtime.jsxs("span", { style: { color: C.danger }, children: [t("debited"), " -", humanMs(ledger.timeCredit.debitedMs)] })
										: null,
									ledger.timeCredit.expired
										? react_jsx_runtime.jsx(Badge, { color: C.danger, children: t("expiredTag") })
										: null,
								],
							}),
					react_jsx_runtime.jsxs("div", {
						style: {
							display: "flex",
							gap: 16,
							flexWrap: "wrap",
							paddingBottom: 10,
							borderBottom: `1px solid ${C.border}`,
						},
						children: [
							react_jsx_runtime.jsx(Stat, {
								label: ledger.total === undefined ? t("total") : `${t("total")} / ${String(ledger.total)}`,
								value: claims.length,
							}),
							react_jsx_runtime.jsx(Stat, { label: t("confirmed"), value: stats.by.confirmed, color: C.success }),
							react_jsx_runtime.jsx(Stat, { label: t("refuted"), value: stats.by.refuted, color: C.danger }),
							react_jsx_runtime.jsx(Stat, { label: t("open"), value: stats.by.open, color: C.tertiary }),
							react_jsx_runtime.jsx("div", { style: { width: 1, background: C.border, margin: "0 2px" } }),
							react_jsx_runtime.jsx(Stat, { label: t("v.cross-checked"), value: stats.verify["cross-checked"], color: C.success }),
							react_jsx_runtime.jsx(Stat, { label: t("v.calibrated"), value: stats.verify.calibrated, color: C.info }),
							react_jsx_runtime.jsx(Stat, { label: t("v.reproducible"), value: stats.verify.reproducible, color: C.warning }),
						],
					}),
					agents.length > 0
						? react_jsx_runtime.jsxs("div", {
								style: { display: "flex", flexDirection: "column", gap: 4, paddingBottom: 10, borderBottom: `1px solid ${C.border}` },
								children: [
									react_jsx_runtime.jsx("div", { style: { fontSize: 11, color: C.tertiary, marginBottom: 2 }, children: t("byAgent") }),
									...agents.map((a) =>
										react_jsx_runtime.jsxs(
											"div",
											{
												style: { display: "flex", gap: 10, fontSize: 11.5, alignItems: "baseline" },
												children: [
													react_jsx_runtime.jsx("span", { style: { fontFamily: C.code, color: C.secondary, minWidth: 150 }, children: a.tool }),
													react_jsx_runtime.jsx("span", { style: { color: C.success, fontFamily: C.code }, children: `${String(a.confirmed)} ${t("confirmed")}` }),
													a.refuted > 0
														? react_jsx_runtime.jsx("span", { style: { color: C.danger, fontFamily: C.code }, children: `${String(a.refuted)} ${t("refuted")}` })
														: null,
													react_jsx_runtime.jsx("span", { style: { color: C.tertiary, fontFamily: C.code }, children: `${String(a.open)} ${t("open")}` }),
												],
											},
											a.tool,
										),
									),
								],
							})
						: null,
					coverage.rows.length > 0 || coverage.assets.length > 0
						? react_jsx_runtime.jsxs("div", {
								style: { display: "flex", flexDirection: "column", gap: 4, paddingBottom: 10, borderBottom: `1px solid ${C.border}` },
								children: [
									react_jsx_runtime.jsxs("div", {
										style: { fontSize: 11, color: C.tertiary, marginBottom: 2 },
										children: [
											t("coverage"),
											` · ${String(coverage.rows.length)} ${t("total")}`,
											coverage.assets.length > 0 ? ` · ${String(coverage.assets.length)} ${t("assets")}` : "",
										],
									}),
									...coverageStatusRows(coverage.rows, t).map((row) =>
										react_jsx_runtime.jsxs(
											"div",
											{
												style: { display: "flex", gap: 10, fontSize: 11.5, alignItems: "baseline" },
												children: [
													react_jsx_runtime.jsx("span", { style: { fontFamily: C.code, color: C.secondary, minWidth: 160 }, children: row.label }),
													react_jsx_runtime.jsx(Badge, { color: row.color, children: row.text }),
												],
											},
											row.key,
										),
									),
								],
							})
						: null,
					react_jsx_runtime.jsxs("div", {
						style: { display: "flex", flexDirection: "column", gap: 4, paddingBottom: 10, borderBottom: `1px solid ${C.border}` },
						children: [
							react_jsx_runtime.jsx("div", { style: { fontSize: 11, color: C.tertiary }, children: t("credentials") }),
							...Object.entries(credentialTargets).map(([id, info]) =>
								react_jsx_runtime.jsx(
									CredentialRow,
									{ agentId: id, info: info, save: credentials.save, t: t },
									id,
								),
							),
						],
					}),
					react_jsx_runtime.jsx("div", {
						style: { display: "flex", flexDirection: "column", gap: 8 },
						children: ordered.map((c, i) =>
							react_jsx_runtime.jsx(ClaimCard, { claim: c, t: t }, String(c?.id ?? String(i))),
						),
					}),
				],
			})
		}

		// ── 插件入口 ──────────────────────────────────────────────

		const inject = ["slots", "locale"]
		const TAB_KEY = "secops-claims"

		const PANEL_ID = "secops"

		// 左栏入口的图标。手写 path 而不是引 primitives 的图标集：
		// 那个包多一个依赖就多一处可能对不上的版本，而这里只要一个可辨识的轮廓。
		function SecopsIcon() {
			return react_jsx_runtime.jsx("svg", {
				width: 16,
				height: 16,
				viewBox: "0 0 16 16",
				fill: "none",
				stroke: "currentColor",
				strokeWidth: 1.4,
				strokeLinecap: "round",
				strokeLinejoin: "round",
				"aria-hidden": "true",
				children: react_jsx_runtime.jsxs(react.Fragment, {
					children: [
						react_jsx_runtime.jsx("path", {
							d: "M8 1.6 3.2 3.5v4.1c0 3 2 5.4 4.8 6.8 2.8-1.4 4.8-3.8 4.8-6.8V3.5L8 1.6Z",
						}),
						react_jsx_runtime.jsx("path", { d: "M5.9 8.1 7.3 9.5l2.9-2.9" }),
					],
				}),
			})
		}

		function apply(ctx) {
			// 注册成功后留一个极小的可观测标记：面板类问题（槽位名、依赖、注册顺序）
			// 全部表现成「界面里什么都没有」，没有这个只能靠翻日志。
			try {
				window.__secopsUi = { registered: true, at: Date.now() }
			} catch (e) {}

			ctx.effect(() => ctx.locale.register(NS, { zh, en }), "client-ui-secops: dictionaries")

			// 数据源不是一个现成的 hook：main 槽只注入 locale/布局 props。
			// 真正的投影在 sessions.manager 上——projectionStore(sessionId, key) 返回
			// 一个带 getSnapshot/subscribe 的 store，正是 React 的 useSyncExternalStore 需要的东西。
			// 所以这里自己把它包成一个可订阅对象，通过 register 的 inject 交给组件。
			ctx.inject(["sessions", "uiSession", "slots", "locale"], (scope) => {
				const t = scope.locale.bind(NS)
				const mgr = scope.sessions && scope.sessions.manager
				const current = scope.uiSession && scope.uiSession.adapter && scope.uiSession.adapter.current

				const sessionIdOf = () => {
					try {
						const snap = current && current.getSnapshot ? current.getSnapshot() : undefined
						if (snap === undefined || snap === null) return undefined
						return snap.id ?? snap.sessionId ?? snap.key
					} catch (e) {
						return undefined
					}
				}

				const read = () => {
					const sid = sessionIdOf()
					if (!mgr || sid === undefined) return null
					try {
						const store = mgr.projectionStore(sid, "secopsProvenance")
						return store && store.getSnapshot ? store.getSnapshot() : null
					} catch (e) {
						window.__secopsUi && window.__secopsUi.errors.push("read:" + String(e && e.message))
						return null
					}
				}

				const subscribe = (cb) => {
					const unsubs = []
					try {
						if (current && current.subscribe) unsubs.push(current.subscribe(cb))
					} catch (e) {}
					try {
						const sid = sessionIdOf()
						const store = mgr && sid !== undefined ? mgr.projectionStore(sid, "secopsProvenance") : undefined
						if (store && store.subscribe) unsubs.push(store.subscribe(cb))
					} catch (e) {}
					return () => {
						for (const u of unsubs) {
							try {
								if (typeof u === "function") u()
							} catch (e) {}
						}
					}
				}

				const source = { getSnapshot: read, subscribe }

				scope.effect(
					() =>
						scope.slots.inject("main", () => {
							const d = scope.slots.register(
								{ name: "main", key: PANEL_ID, locale: NS, inject: () => ({ secopsProjection: source }) },
								SecopsPanel,
							)
							
							return d
						}),
					"client-ui-secops: panel-body",
				)

				scope.effect(
					() =>
						scope.slots.inject("sidebar.panellist", () => {
							const d = scope.slots.register(
								{ name: "sidebar.panellist", id: PANEL_ID, order: 90, label: () => t("tab"), locale: NS },
								SecopsIcon,
							)
							
							return d
						}),
					"client-ui-secops: panellist",
				)
			})
		}

		exports.SecopsPanel = SecopsPanel
		exports.apply = apply
		exports.inject = inject
		return module.exports
	},
})
