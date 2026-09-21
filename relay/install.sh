#!/usr/bin/env bash
# ============================================================
# 两颗心 · 中转服务器 一键安装
#
#   curl -fsSL https://liuxincheng0983-wq.github.io/lklx/relay/install.sh | sudo bash
#
# 可选环境变量：
#   PORT=8890                 监听端口（默认 8890）
#   RELAY_TOKEN=你的口令       不给就自动生成一个
#   DOMAIN=relay.你的域名      给了就顺带装 Caddy 配 HTTPS（需要域名已解析到本机）
#
# 装完会打印服务器地址，填到 App：我的 → 服务器 → 中转服务器地址
# ============================================================
set -e

SRC="${RELAY_SRC:-https://liuxincheng0983-wq.github.io/lklx/relay/server.js}"
DIR=/opt/liangkeixin-relay
PORT="${PORT:-8890}"
SVC=liangkeixin-relay

say() { printf '\033[1;35m[两颗心]\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m[错误]\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" = "0" ] || die "请用 root 跑：curl … | sudo bash"

# ---------- 1. Node ----------
if ! command -v node >/dev/null 2>&1; then
  say "没装 Node，正在安装…"
  if command -v apt-get >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq nodejs curl ca-certificates
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y -q nodejs curl
  elif command -v yum >/dev/null 2>&1; then
    yum install -y -q nodejs curl
  else
    die "认不出包管理器，请手动装 Node 18+ 再跑一次"
  fi
fi
NODE_V=$(node -v 2>/dev/null || echo v0)
say "Node $NODE_V"

# ---------- 2. 放文件 ----------
mkdir -p "$DIR"
if [ -f ./server.js ]; then
  cp ./server.js "$DIR/server.js"
else
  say "下载 server.js …"
  curl -fsSL "$SRC" -o "$DIR/server.js" || die "下载失败，检查网络"
fi
node --check "$DIR/server.js" || die "server.js 语法错误"

# ---------- 3. 口令 ----------
if [ -n "$RELAY_TOKEN" ]; then
  TOKEN="$RELAY_TOKEN"
elif [ -f "$DIR/token" ]; then
  TOKEN="$(cat "$DIR/token")"
  say "沿用上次的口令"
else
  TOKEN="$(head -c 24 /dev/urandom | base64 | tr -d '/+=' | head -c 24)"
fi
printf '%s' "$TOKEN" > "$DIR/token"
chmod 600 "$DIR/token"

# ---------- 4. systemd ----------
say "装成开机自启的服务…"
cat > /etc/systemd/system/$SVC.service <<UNIT
[Unit]
Description=两颗心 中转服务器
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$DIR
ExecStart=$(command -v node) $DIR/server.js
Environment=PORT=$PORT
Environment=HOST=0.0.0.0
Environment=RELAY_TOKEN=$TOKEN
Restart=always
RestartSec=3
# 只读运行：自己的服务器，权限越少越好
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$DIR

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now $SVC
sleep 1

# ---------- 5. 防火墙 ----------
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
  ufw allow "$PORT"/tcp >/dev/null 2>&1 || true
  say "已放行 ufw 的 $PORT 端口"
elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
  firewall-cmd --permanent --add-port="$PORT"/tcp >/dev/null 2>&1 || true
  firewall-cmd --reload >/dev/null 2>&1 || true
  say "已放行 firewalld 的 $PORT 端口"
fi

# ---------- 6. 可选：HTTPS ----------
if [ -n "$DOMAIN" ]; then
  say "给 $DOMAIN 配 HTTPS…"
  if ! command -v caddy >/dev/null 2>&1; then
    if command -v apt-get >/dev/null 2>&1; then
      apt-get install -y -qq debian-keyring debian-archive-keyring apt-transport-https gnupg curl
      curl -1sLf https://dl.cloudsmith.io/public/caddy/stable/gpg.key \
        | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
      curl -1sLf https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt \
        > /etc/apt/sources.list.d/caddy-stable.list
      apt-get update -qq && apt-get install -y -qq caddy
    fi
  fi
  if command -v caddy >/dev/null 2>&1; then
    cat > /etc/caddy/Caddyfile <<CADDY
$DOMAIN {
    reverse_proxy 127.0.0.1:$PORT
    encode zstd gzip
}
CADDY
    systemctl reload caddy 2>/dev/null || systemctl restart caddy
    URL="https://$DOMAIN"
    say "HTTPS 好了"
  else
    say "Caddy 没装上，先用手动模式（能用，只是没有 HTTPS）"
    URL="http://$(curl -s -m 5 ifconfig.me || echo 你的公网IP):$PORT"
  fi
else
  IP="$(curl -s -m 5 ifconfig.me 2>/dev/null || hostname -I 2>/dev/null | awk '{print $1}')"
  URL="http://${IP:-你的公网IP}:$PORT"
fi

# ---------- 7. 自检 ----------
say "自检…"
if curl -fsS -m 5 "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1; then
  say "服务在跑 ✓"
else
  die "服务没起来，看日志：journalctl -u $SVC -n 50"
fi

cat <<DONE

────────────────────────────────────────────
  装好了 🎉  以后一天几万条也没人管你

  服务器地址（填到 App「我的 → 服务器」里）：
      $URL

  口令（同一个地方，填「服务器口令」）：
      $TOKEN

  常用命令：
      systemctl status  $SVC     看状态
      systemctl restart $SVC     重启
      journalctl -u $SVC -f      看日志

  提醒：
    1. 云服务商的安全组 / 防火墙也要放行 $PORT 端口，
       只开系统防火墙是不够的（阿里云、腾讯云最常见）。
    2. 想换成 HTTPS 域名：DOMAIN=relay.xxx.com 再跑一次本脚本。
────────────────────────────────────────────
DONE
