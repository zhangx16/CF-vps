#!/usr/bin/env bash
set -Eeuo pipefail
[[ ${EUID} -eq 0 ]] || { echo '请使用 root 或 sudo 执行'; exit 1; }
command -v systemctl >/dev/null || { echo '需要 systemd'; exit 1; }
if ! command -v python3 >/dev/null || ! command -v curl >/dev/null; then
  apt-get update
  apt-get install -y python3 curl ca-certificates
fi
python3 -c 'import sys; assert sys.version_info >= (3,9), "需要 Python 3.9+"'
REF="${CFVPS_REF:-main}"
[[ "$REF" =~ ^[a-zA-Z0-9._/-]+$ ]] || { echo '无效版本'; exit 1; }
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT
curl -fL --retry 3 --connect-timeout 15 --max-time 120 "https://api.github.com/repos/zhangx16/CF-vps/tarball/$REF" -o "$TMP_DIR/source.tar.gz"
mkdir "$TMP_DIR/source"
tar -xzf "$TMP_DIR/source.tar.gz" --strip-components=1 -C "$TMP_DIR/source"
python3 -m py_compile "$TMP_DIR/source/server.py" "$TMP_DIR/source/engine.py" "$TMP_DIR/source/adaptive.py" "$TMP_DIR/source/providers.py" "$TMP_DIR/source/probing.py" "$TMP_DIR/source/scan_dmit_cf_fallback.py" "$TMP_DIR/source/manage.py"
VERSION=$(python3 - "$TMP_DIR/source.tar.gz" <<'PY'
import sys,tarfile
with tarfile.open(sys.argv[1]) as archive:
    print(archive.next().name.split('/')[0])
PY
)
install -d -m 755 /opt/cf-vps-releases /usr/local/bin
id cf-vps >/dev/null 2>&1 || useradd --system --home-dir /var/lib/cf-vps --shell /usr/sbin/nologin cf-vps
install -d -o cf-vps -g cf-vps -m 750 /var/lib/cf-vps
PREVIOUS_RELEASE=''
SNAPSHOT=''
SWITCHED=0
WAS_ACTIVE=0
if systemctl is-active --quiet cf-vps.service; then WAS_ACTIVE=1; fi
if [[ -f /etc/cf-vps.env ]]; then cp -p /etc/cf-vps.env "$TMP_DIR/original.env"; fi
if [[ -f /etc/systemd/system/cf-vps.service ]]; then cp -p /etc/systemd/system/cf-vps.service "$TMP_DIR/original.service"; fi
rollback_on_error() {
  RESULT=$?
  trap - ERR
  set +e
  if [[ "$SWITCHED" -eq 1 && -d "$PREVIOUS_RELEASE" ]]; then
    echo '新版本部署失败，正在自动恢复上一版本及数据快照。' >&2
    systemctl stop cf-vps.service
    ln -s "$PREVIOUS_RELEASE" "$TMP_DIR/rollback-link"
    mv -Tf "$TMP_DIR/rollback-link" /opt/cf-vps
    if [[ -f "$TMP_DIR/original.service" ]]; then cp -p "$TMP_DIR/original.service" /etc/systemd/system/cf-vps.service; fi
    if [[ -n "$SNAPSHOT" ]]; then
      python3 - "$TMP_DIR/source" "$SNAPSHOT" <<'PYRESTORE'
import sys
sys.path.insert(0,sys.argv[1])
import manage
manage.restore(sys.argv[2],confirmed=True,safety_backup=False)
PYRESTORE
    elif [[ -f "$TMP_DIR/original.env" ]]; then
      cp -p "$TMP_DIR/original.env" /etc/cf-vps.env
    fi
    systemctl daemon-reload
    if [[ "$WAS_ACTIVE" -eq 1 ]]; then systemctl start cf-vps.service; fi
    echo '已执行回滚。请用 cf-vps status / logs 检查状态。' >&2
  elif [[ "$WAS_ACTIVE" -eq 1 ]]; then
    systemctl start cf-vps.service
  fi
  exit "$RESULT"
}
trap rollback_on_error ERR
if [[ -f /etc/systemd/system/cf-vps.service ]]; then systemctl stop cf-vps.service; fi
if [[ -f /etc/cf-vps.env ]]; then
  SNAPSHOT=$(python3 - "$TMP_DIR/source" <<'PYBACKUP'
import sys
sys.path.insert(0,sys.argv[1])
import manage
print(manage.backup(quiet=True))
PYBACKUP
)
  printf '升级前一致性备份：%s\n' "$SNAPSHOT"
fi
NEW_RELEASE="/opt/cf-vps-releases/$(date +%Y%m%d-%H%M%S)-$RANDOM"
install -d -m 755 "$NEW_RELEASE" "$NEW_RELEASE/static"
for FILE in server.py engine.py adaptive.py providers.py probing.py scan_dmit_cf_fallback.py manage.py dmit_prefixes.txt; do
  install -m 644 "$TMP_DIR/source/$FILE" "$NEW_RELEASE/$FILE"
done
for FILE in index.html app.js providers.js center.js style.css fonts.css; do install -m 644 "$TMP_DIR/source/static/$FILE" "$NEW_RELEASE/static/$FILE"; done
printf '%s\n' "$VERSION" > "$NEW_RELEASE/.version"
if [[ -n "$SNAPSHOT" ]]; then printf '%s\n' "$SNAPSHOT" > "$NEW_RELEASE/.rollback-backup"; chmod 600 "$NEW_RELEASE/.rollback-backup"; fi
if [[ -L /opt/cf-vps ]]; then
  PREVIOUS_RELEASE=$(readlink -f /opt/cf-vps)
elif [[ -d /opt/cf-vps ]]; then
  PREVIOUS_RELEASE="/opt/cf-vps-releases/previous-$(date +%Y%m%d-%H%M%S)-$RANDOM"
  mv /opt/cf-vps "$PREVIOUS_RELEASE"
fi
SWITCHED=1
ln -s "$NEW_RELEASE" "$TMP_DIR/new-link"
mv -Tf "$TMP_DIR/new-link" /opt/cf-vps
python3 - "$TMP_DIR/source" <<'PYCFG'
import ipaddress,os,secrets,sys
sys.path.insert(0,sys.argv[1])
import manage
config=manage.read_config()
if not config:
    config=dict(CFVPS_PASSWORD=secrets.token_urlsafe(24),CFVPS_HOST='0.0.0.0',CFVPS_PORT=os.environ.get('CFVPS_LISTEN_PORT','8787'),CFVPS_DATA='/var/lib/cf-vps')
if os.environ.get('CFVPS_BIND'):
    config['CFVPS_HOST']=os.environ['CFVPS_BIND']
ipaddress.IPv4Address(config['CFVPS_HOST'])
assert 1 <= int(config['CFVPS_PORT']) <= 65535
config.setdefault('CFVPS_BACKUP_KEEP','10')
manage.write_config(config)
PYCFG
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
python3 - "$TMP_DIR/source" <<'PYHEALTH'
import sys,time,urllib.request,urllib.error
sys.path.insert(0,sys.argv[1])
import manage
c=manage.read_config()
host=c.get('CFVPS_HOST','0.0.0.0')
if host=='0.0.0.0': host='127.0.0.1'
url='http://'+host+':'+c.get('CFVPS_PORT','8787')+'/api/jobs'
for _ in range(40):
    try:
        urllib.request.urlopen(url,timeout=1)
    except urllib.error.HTTPError as exc:
        if exc.code==401: break
    except OSError: pass
    time.sleep(.25)
else: raise SystemExit('面板健康检查失败')
PYHEALTH
if [[ -n "$PREVIOUS_RELEASE" ]]; then
  ln -s "$PREVIOUS_RELEASE" "$TMP_DIR/previous-link"
  mv -Tf "$TMP_DIR/previous-link" /opt/cf-vps-previous
fi
install -m 755 "$NEW_RELEASE/manage.py" /usr/local/bin/cf-vps
trap - ERR
python3 - <<'PYINFO'
import sys,subprocess,shutil,os
sys.path.insert(0,'/opt/cf-vps')
import manage
c=manage.read_config()
if c.get('CFVPS_HOST')=='0.0.0.0' and shutil.which('ufw'):
    state=subprocess.run(['ufw','status'],capture_output=True,text=True,env=dict(os.environ,LC_ALL='C'))
    if state.returncode==0 and 'Status: active' in state.stdout:
        subprocess.run(['ufw','allow',str(int(c['CFVPS_PORT']))+'/tcp'],check=True)
manage.prune_backups()
manage.info(show_password=True)
PYINFO
printf '\n安装完成。输入 cf-vps 打开管理菜单。公网访问需云安全组放行；可用 cf-vps domain 域名 配置 HTTPS。\n'
