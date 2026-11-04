#!/usr/bin/env python3
"""Authenticated, same-origin dashboard for a single local scan worker."""
import base64
import csv
import fcntl
import hmac
import io
import json
import os
import re
import signal
import threading
import time
import ipaddress
from collections import OrderedDict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit, quote

from engine import FIELDS, Manager, connect
from providers import ProviderStore

ROOT = Path(__file__).resolve().parent


def csv_disposition(ident, sources, favorites=False):
    source=sources.get(ident,{})
    name=('收藏夹' if favorites else '全部测试结果') if ident=='*' else source.get('task_name') or f"{source.get('provider_name','测试结果')}-{ident[:8]}"
    name=re.sub(r'[\x00-\x1f\x7f<>:"/\\|?*]', '_',name).strip(' .')[:100].rstrip(' .') or '测试结果'
    return 'attachment; filename="results.csv"; filename*=UTF-8\'\''+quote(name+'.csv',safe='')


class LimitedHTTPServer(ThreadingHTTPServer):
    """Bound concurrent HTTP handlers; idle sockets have their own deadline."""
    daemon_threads = True
    request_queue_size = 64

    def __init__(self, *args, **kwargs):
        self.slots = threading.BoundedSemaphore(64)
        super().__init__(*args, **kwargs)

    def process_request(self, request, address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.slots.release()


class LoginGuard:
    def __init__(self):
        self.lock = threading.Lock()
        self.entries = OrderedDict()

    def blocked(self, address):
        with self.lock:
            entry = self.entries.get(address)
            return bool(entry and entry[0] > time.monotonic() and entry[1] >= 10)

    def record(self, address, success):
        with self.lock:
            if success:
                self.entries.pop(address, None)
                return
            now = time.monotonic()
            expiry, count = self.entries.pop(address, (now + 60, 0))
            if expiry <= now:
                expiry, count = now + 60, 0
            self.entries[address] = (expiry, count + 1)
            while len(self.entries) > 4096:
                self.entries.popitem(last=False)


def make_handler(manager, password, providers=None):
    providers = providers or ProviderStore(Path(manager.path).parent / "providers.json")
    expected = 'Basic ' + base64.b64encode(('admin:' + password).encode()).decode()
    guard = LoginGuard()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            # Do not log query strings, headers or credentials.
            print(f'{self.address_string()} {self.command} {urlsplit(self.path).path}', flush=True)

        def reply(self, status, payload, kind='application/json; charset=utf-8', extra=None):
            if isinstance(payload, (dict, list)):
                payload = json.dumps(payload, ensure_ascii=False).encode()
            elif isinstance(payload, str):
                payload = payload.encode()
            self.send_response(status)
            self.send_header('Content-Type', kind)
            self.send_header('Content-Length', str(len(payload)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('X-Frame-Options', 'DENY')
            self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; font-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
            for key, value in (extra or {}).items():
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(payload)

        def authorized(self):
            address = self.client_address[0]
            # Only trust a single address inserted by a local reverse proxy.
            if os.environ.get('CFVPS_TRUST_PROXY') == '1' and ipaddress.ip_address(address).is_loopback:
                forwarded = self.headers.get('X-Real-IP', address)
                try:
                    address = str(ipaddress.ip_address(forwarded))
                except ValueError:
                    pass
            if guard.blocked(address):
                self.reply(429, {'error': '登录失败过多，请一分钟后再试'}, extra={'Retry-After':'60'})
                return False
            success = hmac.compare_digest(self.headers.get('Authorization', '').encode(), expected.encode())
            # Initial browser challenge without credentials is not a failed login.
            if self.headers.get('Authorization'):
                guard.record(address, success)
            if not success:
                self.reply(401, {'error': '请使用 admin 和安装时生成的密码登录'}, extra={'WWW-Authenticate': 'Basic realm="CF VPS"'})
                return False
            return True

        def do_GET(self):
            if not self.authorized():
                return
            parsed = urlsplit(self.path)
            query = parse_qs(parsed.query)
            try:
                if parsed.path in ('/', '/app.js', '/style.css', '/fonts.css', '/providers.js', '/center.js'):
                    name, kind = {'/': ('index.html', 'text/html; charset=utf-8'), '/app.js': ('app.js', 'text/javascript; charset=utf-8'), '/style.css': ('style.css', 'text/css; charset=utf-8'), '/fonts.css': ('fonts.css', 'text/css; charset=utf-8'), '/providers.js': ('providers.js', 'text/javascript; charset=utf-8'), '/center.js': ('center.js', 'text/javascript; charset=utf-8')}[parsed.path]
                    self.reply(200, (ROOT / 'static' / name).read_bytes(), kind)
                elif parsed.path == '/api/jobs':
                    self.reply(200, manager.jobs())
                elif parsed.path == '/api/job':
                    self.reply(200,manager.job_detail(query.get('id',[''])[0]))
                elif parsed.path == '/api/results':
                    self.reply(200, manager.results(query.get('id', [''])[0], query.get('view', ['hits'])[0],
                        region=query.get('region',[''])[0], colo=query.get('colo',[''])[0],
                        search=query.get('search',[''])[0], sort=query.get('sort',['newest'])[0], cursor=query.get('cursor',[''])[0],provider=query.get('provider',[''])[0],favorites=query.get('favorites',[''])[0]=='1'))
                elif parsed.path == '/api/confirmed-export':
                    self.reply(200,manager.confirmed_text(query.get('id',[''])[0],query.get('format',['ips'])[0]),'text/plain; charset=utf-8',{'Content-Disposition':'attachment; filename=local-confirmed.txt'})
                elif parsed.path == '/api/confirmed':
                    self.reply(200,manager.confirmed(query.get('id',[''])[0]))
                elif parsed.path == '/api/catalog':
                    self.reply(200,manager.catalog())
                elif parsed.path == '/api/providers':
                    self.reply(200,providers.list())
                elif parsed.path == '/api/provider':
                    self.reply(200,providers.get(query.get('id',[''])[0]))
                elif parsed.path == '/api/facets':
                    self.reply(200, manager.facets(query.get('id',[''])[0], query.get('view',['hits'])[0],query.get('provider',[''])[0],query.get('favorites',[''])[0]=='1'))
                elif parsed.path == '/api/compare':
                    self.reply(200, manager.compare(query.get('old',[''])[0], query.get('new',[''])[0], query.get('kind',['new'])[0]))
                elif parsed.path == '/api/export':
                    self.export(query.get('id', [''])[0], query.get('view', ['hits'])[0], query.get('region',[''])[0], query.get('colo',[''])[0], query.get('search',[''])[0],query.get('provider',[''])[0],query.get('favorites',[''])[0]=='1')
                else:
                    self.reply(404, {'error': '未找到'})
            except (ValueError, TypeError) as exc:
                self.reply(400, {'error': str(exc)})
            except (BrokenPipeError, ConnectionResetError):
                pass

        def export(self, ident, view, region='', colo='', search='',provider='',favorites=False):
            condition, args, sources = manager.selection_condition(ident,view,region,colo,search,provider,favorites)
            with connect(manager.path,favorites=favorites) as db:
                if ident!='*' and not db.execute('SELECT 1 FROM jobs WHERE id=?', (ident,)).fetchone():
                    self.reply(404, {'error': '任务不存在'})
                    return
                self.send_response(200)
                self.send_header('Content-Type', 'text/csv; charset=utf-8')
                self.send_header('Content-Disposition', csv_disposition(ident,sources,favorites))
                self.send_header('Cache-Control', 'no-store')
                self.send_header('X-Content-Type-Options', 'nosniff')
                self.end_headers()
                self.wfile.write(b'\xef\xbb\xbf')
                buf = io.StringIO()
                writer = csv.DictWriter(buf, fieldnames=FIELDS, extrasaction='ignore')
                writer.writeheader()
                self.wfile.write(buf.getvalue().encode())
                # Short paginated reads avoid holding a WAL snapshot during a slow download.
                cursor = -9223372036854775808 if favorites else 0
                maximum = db.execute(f'SELECT COALESCE(MAX(rowid),0) FROM results WHERE {condition}', args).fetchone()[0]
                while True:
                    rows = db.execute(f'SELECT rowid,job,data FROM results WHERE {condition} AND rowid>? AND rowid<=? ORDER BY rowid LIMIT 200', args + [cursor, maximum]).fetchall()
                    if not rows:
                        break
                    for row in rows:
                        data = json.loads(row['data'])
                        data.setdefault('request_ms', data.get('latency_ms',''))
                        data.update(job_id=row['job'],task_name=sources.get(row['job'],{}).get('task_name',data.get('task_name','')),provider_name=sources.get(row['job'],{}).get('provider_name',data.get('provider_name','未知来源')))
                        # Remote headers must not become spreadsheet formulas.
                        for key, value in data.items():
                            if isinstance(value, str) and value.lstrip().startswith(('=', '+', '-', '@')):
                                data[key] = "'" + value
                        buf.seek(0)
                        buf.truncate(0)
                        writer.writerow(data)
                        self.wfile.write(buf.getvalue().encode())
                    cursor = rows[-1]['rowid']

        def do_POST(self):
            if not self.authorized():
                return
            if self.headers.get('X-Requested-With') != 'CF-VPS' or self.headers.get('Sec-Fetch-Site') == 'cross-site':
                self.reply(403, {'error': '请求来源无效'})
                return
            if self.headers.get('Content-Type', '').split(';')[0] != 'application/json':
                self.reply(415, {'error': '需要 application/json'})
                return
            try:
                length = int(self.headers.get('Content-Length', '0'))
                if not 0 < length <= 70000:
                    raise ValueError('请求长度无效')
                raw = json.loads(self.rfile.read(length))
                if not isinstance(raw, dict):
                    raise ValueError('需要 JSON 对象')
                path = urlsplit(self.path).path
                if path == '/api/start':
                    if raw.get('provider'):
                        provider,networks=providers.resolve(raw['provider'],raw.get('prefixes'))
                        raw.update(targets='\n'.join(networks),provider_name=provider['name'],provider_asns=provider['asns'],provider_updated_at=provider['updated_at'],provider_country=provider.get('country',''))
                    self.reply(200, {'id': manager.start(raw)})
                elif path == '/api/provider-refresh':
                    providers.refresh(raw.get('id',''))
                    self.reply(200,{'ok':True})
                elif path == '/api/provider-add':
                    profile=providers.add(raw.get('name',''),raw.get('asns',''))
                    self.reply(200,profile)
                elif path == '/api/resume':
                    ident = raw.get('id')
                    if not isinstance(ident, str) or not ident:
                        raise ValueError('缺少任务 ID')
                    self.reply(200, {'id': manager.start(resume=ident)})
                elif path == '/api/retest':
                    ident = raw.get('id')
                    if not isinstance(ident,str) or not ident:
                        raise ValueError('缺少原任务 ID')
                    self.reply(200, {'id': manager.start(raw, retest=ident)})
                elif path == '/api/delete':
                    ident = raw.get('id')
                    if not isinstance(ident,str) or not ident:
                        raise ValueError('缺少任务 ID')
                    manager.delete(ident)
                    self.reply(200, {'ok': True})
                elif path == '/api/confirmed-import':
                    self.reply(200,manager.import_confirmed(raw.get('id'),raw.get('endpoints')))
                elif path == '/api/confirmed-delete':
                    self.reply(200,manager.delete_confirmed(raw.get('id'),raw.get('ip'),raw.get('port')))
                elif path == '/api/favorite':
                    self.reply(200,manager.favorite(raw.get('ip'),raw.get('port'),raw.get('enabled')))
                elif path == '/api/stop':
                    manager.stop()
                    self.reply(200, {'ok': True})
                else:
                    self.reply(404, {'error': '未找到'})
            except (ValueError, TypeError) as exc:
                self.reply(400, {'error': str(exc)})

        def setup(self):
            super().setup()
            self.connection.settimeout(15)

    return Handler


def main():
    password = os.environ.get('CFVPS_PASSWORD', '')
    if len(password) < 16:
        raise SystemExit('请设置至少 16 位的 CFVPS_PASSWORD')
    data = Path(os.environ.get('CFVPS_DATA', str(ROOT / 'data')))
    data.mkdir(parents=True, exist_ok=True)
    lock_file = (data / 'server.lock').open('a')
    try:
        fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        raise SystemExit('该数据目录已有一个面板实例正在运行')
    manager = Manager(data / 'scan.db')
    server = LimitedHTTPServer((os.environ.get('CFVPS_HOST', '0.0.0.0'), int(os.environ.get('CFVPS_PORT', '8787'))), make_handler(manager, password))
    def shutdown(*_):
        manager.stop()
        threading.Thread(target=server.shutdown, daemon=True).start()
    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    print(f'CF VPS dashboard listening on {server.server_address}', flush=True)
    try:
        server.serve_forever()
    finally:
        manager.stop()
        if manager.thread:
            manager.thread.join(timeout=100)
        server.server_close()


if __name__ == '__main__':
    main()
