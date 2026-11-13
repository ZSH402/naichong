#!/bin/bash
# 把项目与桌面 app 的属主/权限修回「桌面用户可读可执行」。
#
# 为什么需要这个：项目一直是以 root 建立的（构建、同步、改配置都在 root 下做），
# 而桌面会话属于 zsh。root 新建的文件是 600 root-owned，zsh 读不到，
# 表现出来就是「点图标没反应」或 Electron 报 EACCES。
#
# ACL 不解决问题：POSIX ACL 的 mask 会被 chmod 重置——root 写一个 600 的文件，
# default ACL 里给 zsh 的条目会变成 #effective:---，等于没给。
# 所以只能在写入之后把属主改回来。
#
# 用法：sudo /root/proj/fix-perms.sh   （或直接以 root 跑）
set -uo pipefail

DESKTOP_USER="${DESKTOP_USER:-zsh}"

if [ "$(id -u)" -ne 0 ]; then
  echo "[fix-perms] 需要 root" >&2
  exit 1
fi

chown -R "$DESKTOP_USER:$DESKTOP_USER" /root/proj /opt/dsh-desktop /root/dsh-client-ui-secops 2>/dev/null

# 可执行位跟着属主走；目录要能进。
chmod -R u+rwX,go+rX /root/proj /opt/dsh-desktop /root/dsh-client-ui-secops 2>/dev/null

# 启动器与入口必须可执行。
chmod 755 /opt/dsh-desktop/launch.sh 2>/dev/null
chmod 755 /opt/dsh-desktop/node_modules/electron/dist/electron 2>/dev/null
chmod 755 /opt/dsh-desktop/node_modules/electron/dist/chrome-sandbox 2>/dev/null

# 凭据必须 owner-only —— DSH 的 credentials-local 会在启动时硬检查 600，
# 非 600 直接 fatal（不是 warning），整个宿主起不来。
for f in /root/proj/home/.credentials.yaml /root/proj/home/credentials.json; do
  [ -f "$f" ] && chmod 600 "$f" 2>/dev/null
done

# zsh 需要能穿过 /root，但不需要列出它。
setfacl -m "u:$DESKTOP_USER:x" /root 2>/dev/null

echo "[fix-perms] done: /root/proj /opt/dsh-desktop /root/dsh-client-ui-secops -> $DESKTOP_USER"
