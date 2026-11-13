#!/bin/bash
# 项目 runtime 的依赖修复器。
#
# 存在的原因：2026-11-12 在 $PROJ/dsh 下跑了一次裸 `npm install` 补依赖，
# 那个目录当时**没有 package.json**，npm 按空清单重算依赖树，prune 掉了
# 449 个包，`@deepseek-ai` 被清空、dsh 入口消失。
#
# 现在有两道防线：
#   1. package.json + package-lock.json 已生成（725 个包、397 个 @deepseek-ai），
#      `npm ci` 能精确还原到当时那棵树
#   2. 这个脚本把「还原 + 重新挂插件 + 验证」串成一步，不用再靠回忆
#
# 规则（写在代码里比写在文档里管用）：
#   - 这个目录**不要**跑 `npm install <pkg>`。要补包就补到有 manifest 的子目录去
#     （例如 profiles/web 有自己的 package.json）
#   - 真要跑，用 `npm install --package-lock-only`（只算 lock，不动 node_modules）
#
# 用法：./repair.sh
set -uo pipefail

PROJ="/root/proj"
DSH="$PROJ/dsh"
SECOPS="/root/异构agent/dsh-secops"
BIN="$DSH/node_modules/@deepseek-ai/dsh/lib/bin.js"

die() { echo "[repair] 失败：$*" >&2; exit 1; }
step() { echo "[repair] $*"; }

[ -f "$DSH/package-lock.json" ] || die "找不到 $DSH/package-lock.json —— 没有 lock 就无法精确还原"
[ -f "$DSH/package.json" ] || die "找不到 $DSH/package.json —— npm 会按空清单 prune"

# ── 1. 按 lock 还原第三方与 DSH 包
# npm ci 会先删 node_modules 再装，这是它「精确」的代价：中途失败等于什么都没有。
# 所以先确认 lock 自洽，装完再验一遍入口。
step "npm ci（按 lock 精确还原）"
( cd "$DSH" && npm ci --no-audit --no-fund ) || die "npm ci 失败（离线环境下请确认 npm cache 里有 0.2.2-rc.1 的 tarball）"

[ -f "$BIN" ] || die "还原后仍找不到 dsh 入口：$BIN"

# ── 2. 重新挂上 dsh-secops
# 它是拷进来的，不在 lock 里（源码目录的模块解析会串到另一套 cordis 实例，
# 所以不能用 symlink 指向源码）。npm ci 不会保留它，必须重放这一步。
step "同步 dsh-secops"
( cd "$SECOPS" && npm run build >/dev/null 2>&1 && ./sync-to-runtime.sh ) || die "dsh-secops 同步失败"

# ── 3. 验证
step "验证：隔离体检"
( cd "$PROJ" && ./check.sh 2>/dev/null | tail -2 ) || true

step "验证：headless 真的能出结果（这一步失败说明树还是坏的）"
WORKSPACE="$(mktemp -d)"
OUT=$( cd "$PROJ" && DEEPSEEK_API_KEY="${DEEPSEEK_API_KEY:-}" WORKSPACE="$WORKSPACE" \
  timeout 180 ./run.sh "只回答两个字：在吗" 2>/dev/null | tail -1 )
rm -rf "$WORKSPACE"
if [ "$OUT" = "在吗" ]; then
  step "通过：模型链路正常返回"
else
  die "headless 冒烟失败，返回：${OUT:-<空>}"
fi

step "全部完成。"
