#!/usr/bin/env bash
# 下载 RFC 语料。幂等：已存在的文件跳过。
set -u
cd "$(dirname "$0")"
for r in 9110 9112 9113 7230 7231 6265 1035; do
  f="rfc$r.txt"
  if [ -s "$f" ]; then
    printf "跳过 rfc%-6s 已存在 (%s)\n" "$r" "$(du -h "$f" | cut -f1)"
    continue
  fi
  printf "拉取 rfc%-6s ... " "$r"
  if curl -sf "https://www.rfc-editor.org/rfc/$f" -o "$f"; then
    printf "ok (%s)\n" "$(du -h "$f" | cut -f1)"
  else
    rm -f "$f"
    printf "失败\n"
  fi
done
echo "完成。缺失的 RFC 只影响规范断言语料，不影响原语库。"
