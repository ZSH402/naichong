#!/bin/bash
# 起一个最小 Samba 靶子，供 enum4linux-ng 的端到端测试用。
#
# 只绑 127.0.0.1，不对外。故意配成空会话 + guest 可访问 + 不强制 SMB 签名，
# 让 enum4linux-ng 能产出「可验证的发现」——没有靶子，那条 e2e 只能一直 skip。
#
# 用法：
#   ./start-smb-fixture.sh          # 起（已在跑则不动）
#   ./start-smb-fixture.sh stop     # 停
set -euo pipefail

CONF=/tmp/secops-smb-fixture.conf
SHARE=/tmp/secops-smb-pub

if [ "${1:-start}" = "stop" ]; then
  pkill -f "smbd -F -s $CONF" 2>/dev/null && echo "[smb-fixture] stopped" || echo "[smb-fixture] not running"
  exit 0
fi

if ss -ltn 2>/dev/null | grep -q ':445 '; then
  echo "[smb-fixture] something already listens on 445 — leaving it alone"
  exit 0
fi

mkdir -p "$SHARE"
echo fixture > "$SHARE/readme.txt"

cat > "$CONF" <<'EOF'
[global]
   workgroup = TESTWG
   server string = fixture
   security = user
   map to guest = bad user
   smb ports = 445
   interfaces = 127.0.0.1
   bind interfaces only = yes
   server min protocol = SMB2
   disable netbios = yes
   log level = 0
   passdb backend = tdbsam
   load printers = no
   printing = bsd
   printcap name = /dev/null

[pub]
   path = /tmp/secops-smb-pub
   guest ok = yes
   read only = yes
   browseable = yes
EOF

smbd -F -s "$CONF" >/tmp/secops-smbd.log 2>&1 &
sleep 2
if ss -ltn 2>/dev/null | grep -q ':445 '; then
  echo "[smb-fixture] listening on 127.0.0.1:445"
else
  echo "[smb-fixture] failed to start; see /tmp/secops-smbd.log" >&2
  exit 1
fi
