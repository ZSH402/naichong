#!/bin/bash
# 桌面入口。
#
# 分工：这个脚本起宿主（dsh web），Electron 只负责把它们显示成一个窗口。
#
# 为什么不让 Electron 去 spawn 宿主：那条路上宿主以「Electron 主进程的环境」
# 启动，而桌面会话的环境和登录 shell 并不相同——实测同样的命令在 shell 里
# 能起、从 Electron 里 spawn 就报 "required plugins did not activate"，
# 而且详细诊断不会进 Electron 的 stdout。把启动权留在 shell 里，
# 宿主拿到的环境和「命令行能跑」的那份完全一致，故障面小一半。
set -uo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$APP_DIR" || exit 1

PROJ="/root/proj"
PORT="${DSH_DESKTOP_PORT:-3081}"
LOG="${TMPDIR:-/tmp}/dsh-desktop-host.log"
BIN="$PROJ/dsh/node_modules/@deepseek-ai/dsh/lib/bin.js"

if [ -z "${DISPLAY:-}" ] && [ -z "${WAYLAND_DISPLAY:-}" ]; then
  echo "没有可用的显示环境（DISPLAY / WAYLAND_DISPLAY 都为空）" >&2
  exit 1
fi

# 权限自检：这个 app 平时由 root 构建和同步，新写入的文件是 root-owned 600，
# 当前用户读不到时 Electron 只会报一句 EACCES 就退出，看不出所以然。
for f in "$APP_DIR/main.js" "$APP_DIR/package.json" "$BIN"; do
  if [ ! -r "$f" ]; then
    cat >&2 <<MSG
无法读取 $f —— 它属于别的用户（多半是 root）。

执行一次即可修复：
  sudo /root/proj/fix-perms.sh
MSG
    exit 1
  fi
done

# 上一个实例没退干净就让位：端口被占着时起第二个宿主只会得到一堆端口错误。
if ss -ltn 2>/dev/null | grep -q ":$PORT "; then
  echo "[launch] 端口 $PORT 已被占用，复用现有宿主" >&2
  REUSE=1
else
  REUSE=0
fi

HOST_PID=""
cleanup() {
  # 只杀掉自己起的那个宿主；复用别人起的实例时不动它。
  if [ -n "$HOST_PID" ] && kill -0 "$HOST_PID" 2>/dev/null; then
    kill "$HOST_PID" 2>/dev/null
    wait "$HOST_PID" 2>/dev/null
  fi
}
trap cleanup EXIT INT TERM

if [ "$REUSE" = "0" ]; then
  : >"$LOG"
  ( cd "$PROJ" && DSH_HOME="$PROJ/home" node "$BIN" --profile web --no-open --port "$PORT" --host 127.0.0.1 ) >>"$LOG" 2>&1 &
  HOST_PID=$!
fi

# 等宿主打印带 token 的 URL。等 token 而不是等端口：端口通的时候服务
# 可能还没装好中间件，那时窗口会拿到 401 白屏。
TOKEN=""
for _ in $(seq 1 240); do
  TOKEN=$(grep -o 'token=[A-Za-z0-9_-]*' "$LOG" 2>/dev/null | head -1 | cut -d= -f2)
  [ -n "$TOKEN" ] && break
  if [ -n "$HOST_PID" ] && ! kill -0 "$HOST_PID" 2>/dev/null; then
    echo "宿主启动失败，日志：$LOG" >&2
    tail -20 "$LOG" >&2
    exit 1
  fi
  sleep 0.5
done

if [ -z "$TOKEN" ]; then
  echo "宿主在 120 秒内没有就绪，日志：$LOG" >&2
  exit 1
fi

# Electron 只做窗口。URL 走环境变量，main.js 看到它就跳过 spawn。
DSH_DESKTOP_URL="http://127.0.0.1:$PORT/?token=$TOKEN" \
  ./node_modules/electron/dist/electron . --no-sandbox >>"${TMPDIR:-/tmp}/dsh-desktop.log" 2>&1
