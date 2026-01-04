#!/usr/bin/env bash
set -e

SERVICE="pf-web"
APP_DIR="/opt/pf-web"

echo "==> 停止并删除 systemd 服务: $SERVICE"
systemctl stop "$SERVICE" 2>/dev/null || true
systemctl disable "$SERVICE" 2>/dev/null || true
rm -f "/etc/systemd/system/${SERVICE}.service"
systemctl daemon-reload

echo "==> 清理 iptables 中所有 PFWEB 规则（nat 表）"

delete_by_tag() {
  local chain="$1"
  local rules
  rules="$(iptables -t nat -S "$chain" 2>/dev/null | grep 'PFWEB:' || true)"
  if [[ -z "$rules" ]]; then
    echo "  - $chain: 无 PFWEB 规则"
    return 0
  fi

  echo "  - $chain: 删除中..."
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    # -A -> -D
    del="${line/-A /-D }"
    bash -lc "iptables -t nat $del" || true
  done <<< "$rules"
}

delete_by_tag PREROUTING
delete_by_tag POSTROUTING

echo "==> 再次确认（应无输出）："
iptables -t nat -S PREROUTING | grep 'PFWEB:' || echo "  PREROUTING: OK"
iptables -t nat -S POSTROUTING | grep 'PFWEB:' || echo "  POSTROUTING: OK"

echo "==> 删除程序目录: $APP_DIR"
rm -rf "$APP_DIR"

echo "==> 完成：pf-web 已卸载清理"
echo "接下来你可以直接重新执行安装脚本。"
