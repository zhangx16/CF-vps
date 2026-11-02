#!/usr/bin/env bash
set -Eeuo pipefail
# Run as root: bash install.sh (Debian/Ubuntu + systemd).
[[ ${EUID} -eq 0 ]] || { echo '请使用 root 或 sudo 执行'; exit 1; }
command -v systemctl >/dev/null || { echo '需要 systemd'; exit 1; }
if ! command -v python3 >/dev/null || ! command -v curl >/dev/null; then
  apt-get update
  apt-get install -y python3 curl ca-certificates
fi
python3 -c 'import sys; assert sys.version_info >= (3,9), "需要 Python 3.9+"'
REPO='zhangx16/CF-vps'
REF="${CFVPS_REF:-main}"
[[ "$REF" =~ ^[a-zA-Z0-9._/-]+$ ]] || { echo '无效版本'; exit 1; }
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT
curl -fL --retry 3 --connect-timeout 15 --max-time 120 "https://api.github.com/repos/$REPO/tarball/$REF" -o "$TMP_DIR/source.tar.gz"
mkdir "$TMP_DIR/source"
tar -xzf "$TMP_DIR/source.tar.gz" --strip-components=1 -C "$TMP_DIR/source"
python3 -m py_compile "$TMP_DIR/source/server.py" "$TMP_DIR/source/engine.py" "$TMP_DIR/source/scan_dmit_cf_fallback.py" "$TMP_DIR/source/manage.py"
id cf-vps >/dev/null 2>&1 || useradd --system --home-dir /var/lib/cf-vps --shell /usr/sbin/nologin cf-vps
install -d -m 755 /opt/cf-vps /opt/cf-vps/static /usr/local/bin
install -d -o cf-vps -g cf-vps -m 750 /var/lib/cf-vps
NEW_CONFIG=0
if [[ ! -f /etc/cf-vps.env ]]; then
  PASSWORD=$(python3 -c 'import secrets; print(secrets.token_urlsafe(24))')
  BIND="${CFVPS_BIND:-0.0.0.0}"
  PORT="${CFVPS_LISTEN_PORT:-8787}"
  [[ "$BIND" =~ ^[a-zA-Z0-9.:_-]+$ && "$PORT" =~ ^[0-9]+$ ]] || { echo '无效监听地址或端口'; exit 1; }
  python3 -c 'import ipaddress,sys; ipaddress.IPv4Address(sys.argv[1]); assert 1 <= int(sys.argv[2]) <= 65535' "$BIND" "$PORT"
  umask 077
  cat > /etc/cf-vps.env <<EOF
CFVPS_PASSWORD=$PASSWORD
CFVPS_HOST=$BIND
CFVPS_PORT=$PORT
CFVPS_DATA=/var/lib/cf-vps
EOF
  NEW_CONFIG=1
fi
if [[ "$NEW_CONFIG" -eq 0 ]]; then
  python3 - "$TMP_DIR/source" <<'PYBACKUP'
import sys
sys.path.insert(0, sys.argv[1])
import manage
manage.backup()
PYBACKUP
fi
# An explicit bind address also updates existing installs. Otherwise preserve settings.
if [[ "$NEW_CONFIG" -eq 0 && -n "${CFVPS_BIND:-}" ]]; then
  python3 - "$TMP_DIR/source" "$CFVPS_BIND" <<'PYCFG'
import ipaddress
import sys
sys.path.insert(0, sys.argv[1])
import manage
ipaddress.IPv4Address(sys.argv[2])
config = manage.read_config()
config['CFVPS_HOST'] = sys.argv[2]
manage.write_config(config)
PYCFG
fi
# Preserve runtime data, password and custom port on upgrades.
if systemctl is-active --quiet cf-vps.service; then
  systemctl stop cf-vps.service
fi
for FILE in server.py engine.py scan_dmit_cf_fallback.py manage.py dmit_prefixes.txt; do
  install -m 644 "$TMP_DIR/source/$FILE" "/opt/cf-vps/$FILE"
done
for FILE in index.html app.js style.css; do
  install -m 644 "$TMP_DIR/source/static/$FILE" "/opt/cf-vps/static/$FILE"
done
install -m 755 "$TMP_DIR/source/manage.py" /usr/local/bin/cf-vps
cat > /etc/systemd/system/cf-vps.service <<'EOF'
[Unit]
Description=CF VPS scan dashboard
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=cf-vps
Group=cf-vps
WorkingDirectory=/opt/cf-vps
EnvironmentFile=/etc/cf-vps.env
Environment=PYTHONUNBUFFERED=1
Environment=PYTHONDONTWRITEBYTECODE=1
ExecStart=/usr/bin/python3 /opt/cf-vps/server.py
Restart=on-failure
RestartSec=3
TimeoutStopSec=110
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/cf-vps
UMask=0077
LimitNOFILE=4096

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now cf-vps.service
sleep 1
if ! systemctl is-active --quiet cf-vps.service; then
  journalctl -u cf-vps.service -n 30 --no-pager
  exit 1
fi
# Open only the service's TCP port when UFW is already active; do not enable/reset a firewall.
BIND=$(python3 -c 'import sys; sys.path.insert(0,"/opt/cf-vps"); import manage; print(manage.read_config().get("CFVPS_HOST","0.0.0.0"))')
PORT=$(python3 -c 'import sys; sys.path.insert(0,"/opt/cf-vps"); import manage; print(manage.read_config().get("CFVPS_PORT","8787"))')
if [[ "$BIND" == '0.0.0.0' ]] && command -v ufw >/dev/null && LC_ALL=C ufw status | grep -q '^Status: active'; then
  ufw allow "$PORT/tcp"
fi
printf '\n安装完成。输入 cf-vps 打开管理菜单。\n'
python3 - <<'PYINFO'
import sys
sys.path.insert(0, '/opt/cf-vps')
import manage
manage.info(show_password=True)
PYINFO
printf '公网访问还需在云安全组放行对应 TCP 端口；域名 HTTPS 配置见 README。\n'
