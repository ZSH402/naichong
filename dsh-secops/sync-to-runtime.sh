#!/bin/bash
# 把 dsh-secops 的编译产物同步进项目 runtime。
#
# 为什么不直接 symlink：
#   symlink 后 Node 的模块解析会从源目录向上找，命中 /root/异构agent/node_modules
#   那一套 dev 依赖；而 cordis 必须与 runtime 是同一个实例，两套实例会让
#   ctx / effect 作用域全部失效。所以只拷 dist + 一份精简 package.json，
#   让它向上解析到 /root/proj/dsh/node_modules 里的 @deepseek-ai/*。
#
# 用法：./sync-to-runtime.sh
set -euo pipefail

SRC="/root/异构agent/dsh-secops"
DST="/root/proj/dsh/node_modules/dsh-secops"

[ -d "$SRC/dist" ] || { echo "[sync] 先跑 npm run build" >&2; exit 1; }

rm -rf "$DST"
mkdir -p "$DST"
cp -r "$SRC/dist" "$DST/dist"

cat > "$DST/package.json" <<'JSON'
{
  "name": "dsh-secops",
  "version": "0.1.0",
  "type": "module",
  "main": "dist/index.js",
  "exports": { ".": "./dist/index.js" }
}
JSON

echo "[sync] dsh-secops → $DST ($(ls "$DST/dist" | wc -l) modules)"

# 桌面 app 以非 root 用户运行，而这里的一切都是 root 写的：
# 新拷进去的 dist 是 root-owned 600，那个用户读不到，界面会「点开没反应」。
# 同步本来就是一次写入的收尾动作，顺手把属主带过去比让人记得手动 chown 可靠。
DESKTOP_USER="${DESKTOP_USER:-zsh}"
if [ "$(id -u)" = "0" ] && id "$DESKTOP_USER" >/dev/null 2>&1; then
  chown -R "$DESKTOP_USER:$DESKTOP_USER" "$DST" 2>/dev/null || true
  chmod -R u+rwX,go+rX "$DST" 2>/dev/null || true
  echo "[sync] 属主已交给 $DESKTOP_USER（否则桌面端读不到）"
fi
