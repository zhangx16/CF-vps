#!/usr/bin/env python3
"""Root-only cf-vps terminal manager. No third-party dependencies."""
import argparse
import datetime
import fcntl
import getpass
import ipaddress
import json
import os
import pwd
import secrets
import shlex
import shutil
import sqlite3
from contextlib import closing
import re
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path

APP = Path('/opt/cf-vps')
CONFIG = Path('/etc/cf-vps.env')
UNIT = Path('/etc/systemd/system/cf-vps.service')
BACKUPS = Path('/var/backups/cf-vps')
COMMAND = Path('/usr/local/bin/cf-vps')
PREVIOUS = Path('/opt/cf-vps-previous')
RELEASES = Path('/opt/cf-vps-releases')
INSTALL_URL = 'https://raw.githubusercontent.com/zhangx16/CF-vps/main/install.sh'


def run(*args, check=True, capture=False):
    return subprocess.run([str(a) for a in args], check=check, text=True,
                          stdout=subprocess.PIPE if capture else None,
                          stderr=subprocess.PIPE if capture else None)


def read_config(path=None):
    result = {}
    path = CONFIG if path is None else Path(path)
    if path.exists():
        for line in path.read_text().splitlines():
            if not line.strip() or line.lstrip().startswith('#'):
                continue
            key, sep, value = line.partition('=')
            if sep:
                parsed = shlex.split(value)
                result[key.strip()] = ' '.join(parsed)
    return result


def write_config(config):
    CONFIG.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix='.cf-vps-', dir=CONFIG.parent)
    try:
        with os.fdopen(fd, 'w') as out:
            for key, value in config.items():
                if not key.replace('_', '').isalnum() or '\n' in str(value) or '\r' in str(value):
                    raise ValueError('配置键值不能包含换行')
                value = str(value).replace('\\', '\\\\').replace('"', '\\"')
                out.write(f'{key}="{value}"\n')
        os.chmod(name, 0o600)
        os.replace(name, CONFIG)
    finally:
        Path(name).unlink(missing_ok=True)


def data_dir():
    return Path(read_config().get('CFVPS_DATA', '/var/lib/cf-vps'))


def installed():
    return CONFIG.is_file() and (APP / 'server.py').is_file() and UNIT.is_file()


def require_install():
    if not installed():
        raise ValueError('尚未安装，请先执行 cf-vps install 或菜单 1')


def active():
    return run('systemctl', 'is-active', '--quiet', 'cf-vps', check=False, capture=True).returncode == 0


def restart():
    run('systemctl', 'restart', 'cf-vps')
    time.sleep(0.5)
    if not active():
        raise ValueError('服务启动失败，请执行 cf-vps logs 查看日志')
    print('服务已重启。')


def apply_config(config):
    previous = read_config()
    write_config(config)
    try:
        restart()
    except (ValueError, subprocess.CalledProcessError):
        write_config(previous)
        run('systemctl', 'restart', 'cf-vps', check=False)
        raise ValueError('新配置启动失败，已回退原配置；请执行 cf-vps logs 查看日志')


def info(show_password=False):
    require_install()
    config = read_config()
    host = config.get('CFVPS_HOST', '0.0.0.0')
    port = config.get('CFVPS_PORT', '8787')
    state = '运行中' if active() else '已停止'
    print(f'服务：{state}\n监听：{host}:{port}\n用户名：admin')
    if host in ('0.0.0.0', '::'):
        print(f'公网访问：http://服务器公网IP:{port}（防火墙和云安全组需放行 TCP {port}）')
    else:
        print(f'访问地址：http://{host}:{port}')
    if config.get('CFVPS_DOMAIN'):
        print('HTTPS 地址：https://' + config['CFVPS_DOMAIN'])
    print(f'配置：{CONFIG}\n数据：{data_dir()}\n备份：{BACKUPS}')
    if show_password:
        print('密码：' + config.get('CFVPS_PASSWORD', '未设置'))


def backup(quiet=False):
    if not CONFIG.exists():
        raise ValueError('没有可备份的配置')
    BACKUPS.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(BACKUPS, 0o700)
    stamp = datetime.datetime.now().strftime('%Y%m%d-%H%M%S-%f')
    output = BACKUPS / f'cf-vps-{stamp}.tar.gz'
    fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(fd)
    try:
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            source = data_dir() / 'scan.db'
            if source.exists():
                # SQLite's backup API includes committed WAL records without stopping scans.
                with closing(sqlite3.connect(source, timeout=30)) as src, closing(sqlite3.connect(tmp / 'scan.db')) as dest:
                    src.backup(dest, pages=256, sleep=0.1)
            shutil.copyfile(CONFIG, tmp / 'cf-vps.env')
            if (data_dir()/'providers.json').exists():
                shutil.copyfile(data_dir()/'providers.json',tmp/'providers.json')
            (tmp / 'manifest.json').write_text(json.dumps({'format': 1, 'created': stamp}))
            with tarfile.open(output, 'w:gz') as archive:
                for path in tmp.iterdir():
                    archive.add(path, arcname=path.name, recursive=False)
    except BaseException:
        output.unlink(missing_ok=True)
        raise
    prune_backups()
    if not quiet:
        print(f'备份完成：{output}\n含配置、登录密码与已提交的任务数据；扫描无需停止。')
    return output


def install(upgrade=False):
    if upgrade and CONFIG.exists():
        print('升级安装前将自动备份当前配置与数据。')
    with tempfile.TemporaryDirectory() as tmp:
        script = Path(tmp) / 'install.sh'
        run('curl', '-fL', '--retry', '3', '--connect-timeout', '15', '--max-time', '120', INSTALL_URL, '-o', script)
        run('bash', script)


def set_access(public):
    require_install()
    config = read_config()
    config['CFVPS_HOST'] = '0.0.0.0' if public else '127.0.0.1'
    apply_config(config)
    if public:
        port = config.get('CFVPS_PORT', '8787')
        # Only add one explicit allow rule to a firewall that is already enabled.
        if shutil.which('ufw'):
            env = dict(os.environ, LC_ALL='C')
            result = subprocess.run(['ufw', 'status'], capture_output=True, text=True, env=env)
            if result.returncode == 0 and 'Status: active' in result.stdout:
                run('ufw', 'allow', f'{int(port)}/tcp')
    info()


def set_port(value):
    require_install()
    port = int(value)
    if not 1 <= port <= 65535:
        raise ValueError('端口必须在 1–65535')
    previous = read_config()
    config = dict(previous)
    config['CFVPS_PORT'] = str(port)
    domain = config.get('CFVPS_DOMAIN')
    site = Path('/etc/nginx/sites-available') / domain if domain else None
    original = site.read_text() if site and site.exists() else None
    apply_config(config)
    try:
        if site:
            if original is None or '# Managed by CF VPS' not in original:
                raise ValueError('域名配置不属于 CF VPS，无法自动修改上游端口')
            site.write_text(nginx_text(domain,port,True))
            run('nginx','-t')
            run('systemctl','reload','nginx')
    except BaseException:
        if site and original is not None:
            site.write_text(original)
        apply_config(previous)
        run('systemctl','reload','nginx',check=False)
        raise
    if config.get('CFVPS_HOST', '0.0.0.0') == '0.0.0.0':
        print(f'请在防火墙与云安全组放行新端口 TCP {port}；旧端口规则需自行移除。')
    info()


def set_password():
    require_install()
    value = getpass.getpass('新密码（留空随机生成）：')
    if not value:
        value = secrets.token_urlsafe(24)
    elif getpass.getpass('再次输入新密码：') != value:
        raise ValueError('两次密码不一致')
    if len(value) < 16 or any(c in value for c in '\n\r\0'):
        raise ValueError('密码至少 16 位，不能包含换行或空字符')
    config = read_config()
    config['CFVPS_PASSWORD'] = value
    apply_config(config)
    print(f'用户名：admin\n新密码：{value}')


def restore(path, confirmed=False, safety_backup=True):
    require_install()
    path = Path(path).expanduser().resolve(strict=True)
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        # Read only named regular files; never extract arbitrary archive paths or links.
        with tarfile.open(path, 'r:gz') as archive:
            for name in ('manifest.json', 'cf-vps.env', 'scan.db','providers.json'):
                try:
                    member = archive.getmember(name)
                except KeyError:
                    if name in ('scan.db','providers.json'):
                        continue
                    raise ValueError('不是有效的 CF VPS 备份')
                if not member.isfile() or (name not in ('scan.db','providers.json') and member.size > 65536) or (name=='providers.json' and member.size>8*1024*1024):
                    raise ValueError('备份格式无效')
                with archive.extractfile(member) as src, (tmp / name).open('wb') as dest:
                    shutil.copyfileobj(src, dest)
        if json.loads((tmp / 'manifest.json').read_text()).get('format') != 1:
            raise ValueError('不支持的备份版本')
        config = read_config(tmp / 'cf-vps.env')
        if len(config.get('CFVPS_PASSWORD', '')) < 16:
            raise ValueError('备份缺少有效登录密码')
        ipaddress.ip_address(config.get('CFVPS_HOST', '0.0.0.0'))
        if not 1 <= int(config.get('CFVPS_PORT', '8787')) <= 65535:
            raise ValueError('备份端口无效')
        provider_cache=tmp/'providers.json'
        if provider_cache.exists():
            cache=json.loads(provider_cache.read_text())
            if not isinstance(cache,dict) or cache.get('version')!=1 or not isinstance(cache.get('custom'),list) or not isinstance(cache.get('cache'),dict):
                raise ValueError('服务商缓存格式无效')
        source = tmp / 'scan.db'
        if source.exists():
            with closing(sqlite3.connect(source)) as db:
                if db.execute('PRAGMA quick_check').fetchone()[0] != 'ok':
                    raise ValueError('备份数据库损坏')
                tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                if not {'jobs', 'results'} <= tables:
                    raise ValueError('备份数据库缺少任务表')
        print(f'将恢复：{path}\n当前配置和扫描记录会先自动备份。')
        if not confirmed and input('输入 RESTORE 确认覆盖当前数据：').strip() != 'RESTORE':
            print('已取消。')
            return
        safety = backup() if safety_backup else None
        target = data_dir()
        config['CFVPS_DATA'] = str(target)
        was_active = active()
        run('systemctl', 'stop', 'cf-vps')
        try:
            target.mkdir(parents=True, exist_ok=True)
            account = pwd.getpwnam('cf-vps')
            os.chown(target, account.pw_uid, account.pw_gid)
            with (target / 'server.lock').open('a') as lock:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                os.fchown(lock.fileno(), account.pw_uid, account.pw_gid)
                for name in ('scan.db-wal', 'scan.db-shm'):
                    (target / name).unlink(missing_ok=True)
                if source.exists():
                    temp_db = target / '.restore.db'
                    shutil.copyfile(source, temp_db)
                    os.chown(temp_db, account.pw_uid, account.pw_gid)
                    os.chmod(temp_db, 0o600)
                    os.replace(temp_db, target / 'scan.db')
                else:
                    (target / 'scan.db').unlink(missing_ok=True)
                if provider_cache.exists():
                    temp_cache=target/'.restore-providers.json'
                    shutil.copyfile(provider_cache,temp_cache)
                    os.chown(temp_cache,account.pw_uid,account.pw_gid)
                    os.chmod(temp_cache,0o600)
                    os.replace(temp_cache,target/'providers.json')
                else:
                    (target/'providers.json').unlink(missing_ok=True)
                write_config(config)
        finally:
            if was_active:
                run('systemctl', 'start', 'cf-vps')
        print(f'恢复完成；恢复前备份：{safety}\n历史未完成任务可在网页手动续扫。')


def uninstall(purge=False):
    print('将删除服务与程序。' + ('同时删除配置和扫描数据。' if purge else '保留配置、扫描数据、备份和 cf-vps 管理命令，可重新安装。'))
    if input('输入 DELETE 确认卸载：').strip() != 'DELETE':
        print('已取消。')
        return
    if CONFIG.exists():
        backup()
    target = data_dir()
    # Fixed installer data directory only; never recursively delete an arbitrary config path.
    if purge and target.resolve() != Path('/var/lib/cf-vps'):
        raise ValueError('自定义数据目录请自行删除；已中止卸载')
    run('systemctl', 'disable', '--now', 'cf-vps', check=False)
    if active():
        raise ValueError('服务未成功停止，已中止删除程序和数据')
    UNIT.unlink(missing_ok=True)
    run('systemctl', 'daemon-reload')
    if APP.is_symlink():
        APP.unlink()
    elif APP.exists():
        shutil.rmtree(APP)
    PREVIOUS.unlink(missing_ok=True)
    if RELEASES.exists():
        shutil.rmtree(RELEASES)
    if purge:
        if target.exists():
            shutil.rmtree(target)
        CONFIG.unlink(missing_ok=True)
    print(f'卸载完成。管理命令和备份仍保留：{COMMAND}、{BACKUPS}')


def prune_backups():
    keep = max(1, int(read_config().get('CFVPS_BACKUP_KEEP', '10')))
    protected = set()
    for release in (APP, PREVIOUS):
        pointer = release / '.rollback-backup'
        if pointer.is_file():
            protected.add(pointer.read_text().strip())
    paths = sorted(BACKUPS.glob('cf-vps-*.tar.gz'), key=lambda p:p.stat().st_mtime, reverse=True)
    for path in paths[keep:]:
        if str(path) not in protected:
            path.unlink()


def retention(value):
    keep = int(value)
    if not 1 <= keep <= 1000:
        raise ValueError('备份保留数量应为 1–1000')
    config = read_config()
    if not config:
        raise ValueError('请先安装')
    config['CFVPS_BACKUP_KEEP'] = str(keep)
    write_config(config)
    prune_backups()
    print(f'备份保留数量已设为 {keep}；升级回滚需要的备份额外保留。')


def rollback():
    require_install()
    if not PREVIOUS.is_symlink() or not PREVIOUS.is_dir():
        raise ValueError('没有可回滚的程序版本')
    snapshot = APP / '.rollback-backup'
    if not snapshot.is_file() or not Path(snapshot.read_text().strip()).is_file():
        raise ValueError('缺少上一版本对应的数据备份，已中止回滚')
    target = PREVIOUS.resolve()
    current = APP.resolve()
    archive = Path(snapshot.read_text().strip())
    print(f'将回滚程序与配置/数据快照到上一版本：{target.name}')
    if input('输入 ROLLBACK 确认回滚：').strip() != 'ROLLBACK':
        return
    safety = backup()
    was_active = active()
    run('systemctl','stop','cf-vps')
    temp = APP.parent / '.cf-vps-rollback'
    try:
        temp.unlink(missing_ok=True)
        temp.symlink_to(target)
        os.replace(temp, APP)
        restore(archive, confirmed=True, safety_backup=False)
        shutil.copy2(APP/'manage.py', COMMAND)
        os.chmod(COMMAND, 0o755)
    except BaseException:
        temp.unlink(missing_ok=True)
        temp.symlink_to(current)
        os.replace(temp, APP)
        restore(safety, confirmed=True, safety_backup=False)
        raise
    finally:
        if was_active:
            run('systemctl','start','cf-vps')
    PREVIOUS.unlink(missing_ok=True)
    print('已回滚到上一版本；回滚前数据已保留备份。')


def nginx_text(domain, port, tls):
    challenge = 'location ^~ /.well-known/acme-challenge/ { root /var/www/html; default_type text/plain; }'
    text = f'# Managed by CF VPS\nserver {{\n listen 80;\n listen [::]:80;\n server_name {domain};\n {challenge}\n'
    text += ' location / { return 301 https://$host$request_uri; }\n}\n' if tls else ' location / { return 404; }\n}\n'
    if tls:
        text += f"""server {{
 listen 443 ssl;
 listen [::]:443 ssl;
 server_name {domain};
 ssl_certificate /etc/letsencrypt/live/{domain}/fullchain.pem;
 ssl_certificate_key /etc/letsencrypt/live/{domain}/privkey.pem;
 ssl_protocols TLSv1.2 TLSv1.3;
 client_max_body_size 80k;
 add_header Strict-Transport-Security "max-age=31536000" always;
 location / {{
  proxy_pass http://127.0.0.1:{port};
  proxy_http_version 1.1;
  proxy_set_header Host $host;
  proxy_set_header X-Real-IP $remote_addr;
  proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
  proxy_set_header X-Forwarded-Proto $scheme;
  proxy_read_timeout 300s;
  proxy_buffering off;
 }}
}}
"""
    return text


def configure_domain(domain):
    require_install()
    domain = domain.lower().strip().rstrip('.')
    if len(domain)>253 or not re.fullmatch(r'(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}',domain):
        raise ValueError('请输入有效域名，不含 https:// 或路径')
    if not shutil.which('nginx') or not shutil.which('certbot'):
        run('apt-get','update')
        run('apt-get','install','-y','nginx','certbot')
    available = Path('/etc/nginx/sites-available') / domain
    enabled = Path('/etc/nginx/sites-enabled') / domain
    available.parent.mkdir(parents=True,exist_ok=True)
    enabled.parent.mkdir(parents=True,exist_ok=True)
    if available.exists() and '# Managed by CF VPS' not in available.read_text():
        raise ValueError(f'{available} 已存在且不属于 CF VPS，请先检查该站点配置')
    old = available.read_text() if available.exists() else None
    linked = enabled.exists()
    previous_config = read_config()
    config = dict(previous_config)
    port = int(config.get('CFVPS_PORT','8787'))
    Path('/var/www/html/.well-known/acme-challenge').mkdir(parents=True,exist_ok=True)
    cert = Path('/etc/letsencrypt/live') / domain / 'fullchain.pem'
    try:
        available.write_text(nginx_text(domain,port,cert.exists()))
        if not linked:
            enabled.symlink_to(available)
        run('nginx','-t')
        run('systemctl','reload','nginx')
        run('certbot','certonly','--webroot','-w','/var/www/html','-d',domain,'--non-interactive','--agree-tos','--register-unsafely-without-email')
        available.write_text(nginx_text(domain,port,True))
        run('nginx','-t')
        config.update(CFVPS_DOMAIN=domain,CFVPS_HOST='127.0.0.1',CFVPS_TRUST_PROXY='1')
        apply_config(config)
        run('systemctl','reload','nginx')
        hooks=Path('/etc/letsencrypt/renewal-hooks/deploy')
        hooks.mkdir(parents=True,exist_ok=True)
        hook=hooks/'cf-vps-nginx.sh'
        hook.write_text('#!/bin/sh\nnginx -t && systemctl reload nginx\n')
        hook.chmod(0o755)
    except BaseException:
        write_config(previous_config)
        if old is None:
            available.unlink(missing_ok=True)
        else:
            available.write_text(old)
        if not linked:
            enabled.unlink(missing_ok=True)
        run('nginx','-t',check=False)
        run('systemctl','reload','nginx',check=False)
        run('systemctl','restart','cf-vps',check=False)
        raise
    print(f'HTTPS 已配置：https://{domain}；后端改为仅本机监听。')


def list_backups():
    paths = sorted(BACKUPS.glob('cf-vps-*.tar.gz'), reverse=True)
    if not paths:
        print('暂无备份。')
    for i, path in enumerate(paths, 1):
        print(f'{i:>2}. {path} ({path.stat().st_size / 1024:.1f} KB)')
    return paths


def menu():
    while True:
        print('\nCF VPS 管理面板\n'
              ' 1. 安装 / 重新安装\n 2. 升级（先自动备份）\n 3. 查看状态与访问地址\n'
              ' 4. 启动服务\n 5. 停止服务\n 6. 重启服务\n 7. 查看最近日志\n'
              ' 8. 备份配置与数据\n 9. 从备份恢复\n10. 开放公网访问\n'
              '11. 改为仅本机访问\n12. 修改端口\n13. 修改登录密码\n'
              '14. 查看登录密码\n15. 卸载（保留数据）\n16. 卸载并删除数据\n17. 配置域名与 HTTPS\n18. 回滚上一程序版本\n19. 设置备份保留数量\n 0. 退出')
        choice = input('请选择：').strip()
        try:
            if choice == '0':
                return
            elif choice == '1':
                install(upgrade=CONFIG.exists())
            elif choice == '2':
                install(upgrade=True)
            elif choice == '3':
                info()
            elif choice in ('4', '5', '6'):
                require_install()
                run('systemctl', {'4':'start', '5':'stop', '6':'restart'}[choice], 'cf-vps')
            elif choice == '7':
                run('journalctl', '-u', 'cf-vps', '-n', '100', '--no-pager')
            elif choice == '8':
                backup()
            elif choice == '9':
                paths = list_backups()
                value = input('输入备份序号或文件绝对路径（留空取消）：').strip()
                if value:
                    if value.isdigit():
                        index = int(value) - 1
                        if not 0 <= index < len(paths):
                            raise ValueError('备份序号无效')
                        restore(paths[index])
                    else:
                        restore(value)
            elif choice in ('10', '11'):
                set_access(choice == '10')
            elif choice == '12':
                set_port(input('新端口：').strip())
            elif choice == '13':
                set_password()
            elif choice == '14':
                info(show_password=True)
            elif choice == '17':
                configure_domain(input('域名：').strip())
            elif choice == '18':
                rollback()
            elif choice == '19':
                retention(input('备份保留数量：').strip())
            elif choice in ('15', '16'):
                uninstall(purge=choice == '16')
            else:
                print('无效选项。')
        except (ValueError, OSError, sqlite3.Error, tarfile.TarError, subprocess.CalledProcessError) as exc:
            print(f'操作失败：{exc}', file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(description='CF VPS 中文管理菜单及快捷命令')
    parser.add_argument('command', nargs='?', default='menu', choices=['menu','install','upgrade','status','info','start','stop','restart','logs','backup','backups','restore','public','private','port','password','uninstall','domain','rollback','retention'])
    parser.add_argument('value', nargs='?', help='restore 的备份路径或 port 的端口号')
    parser.add_argument('--purge', action='store_true', help='卸载时同时删除配置和扫描数据，仍保留自动备份')
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit('请使用 sudo cf-vps 或 root 执行')
    os.umask(0o077)
    lock_path = Path('/run/lock/cf-vps-manager.lock')
    with lock_path.open('a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise SystemExit('另一个 cf-vps 管理命令正在运行')
        try:
            cmd = args.command
            if cmd == 'menu':
                menu()
            elif cmd in ('install','upgrade'):
                install(upgrade=cmd == 'upgrade' or CONFIG.exists())
            elif cmd in ('status','info'):
                info(show_password=cmd == 'info')
            elif cmd in ('start','stop','restart'):
                require_install()
                run('systemctl', cmd, 'cf-vps')
            elif cmd == 'logs':
                run('journalctl', '-u', 'cf-vps', '-n', '100', '--no-pager')
            elif cmd == 'backup':
                backup()
            elif cmd == 'backups':
                list_backups()
            elif cmd == 'restore':
                if not args.value:
                    raise ValueError('用法：cf-vps restore /备份路径.tar.gz')
                restore(args.value)
            elif cmd in ('public','private'):
                set_access(cmd == 'public')
            elif cmd == 'port':
                if not args.value:
                    raise ValueError('用法：cf-vps port 8787')
                set_port(args.value)
            elif cmd == 'password':
                set_password()
            elif cmd == 'domain':
                if not args.value:
                    raise ValueError('用法：cf-vps domain scan.example.com')
                configure_domain(args.value)
            elif cmd == 'rollback':
                rollback()
            elif cmd == 'retention':
                if not args.value:
                    raise ValueError('用法：cf-vps retention 10')
                retention(args.value)
            elif cmd == 'uninstall':
                uninstall(args.purge)
        except (ValueError, OSError, sqlite3.Error, tarfile.TarError, subprocess.CalledProcessError) as exc:
            raise SystemExit(f'操作失败：{exc}')
        except (EOFError, KeyboardInterrupt):
            print('\n已退出。')


if __name__ == '__main__':
    main()
