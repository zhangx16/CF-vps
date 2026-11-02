#!/usr/bin/env python3
"""Authenticated, same-origin dashboard for a single local scan worker."""
import base64
import csv
import fcntl
import hmac
import io
import json
import os
import signal
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from engine import FIELDS, Manager, connect

ROOT = Path(__file__).resolve().parent


def make_handler(manager, password):
    expected = 'Basic ' + base64.b64encode(('admin:' + password).encode()).decode()

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
            self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
            for key, value in (extra or {}).items():
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(payload)

        def authorized(self):
            if not hmac.compare_digest(self.headers.get('Authorization', '').encode(), expected.encode()):
                self.reply(401, {'error': '请使用 admin 和安装时生成的密码登录'}, extra={'WWW-Authenticate': 'Basic realm="CF VPS"'})
                return False
            return True

        def do_GET(self):
            if not self.authorized():
                return
            parsed = urlsplit(self.path)
            query = parse_qs(parsed.query)
            try:
                if parsed.path in ('/', '/app.js', '/style.css'):
                    name, kind = {'/': ('index.html', 'text/html; charset=utf-8'), '/app.js': ('app.js', 'text/javascript; charset=utf-8'), '/style.css': ('style.css', 'text/css; charset=utf-8')}[parsed.path]
                    self.reply(200, (ROOT / 'static' / name).read_bytes(), kind)
                elif parsed.path == '/api/jobs':
                    self.reply(200, manager.jobs())
                elif parsed.path == '/api/results':
                    self.reply(200, manager.results(query.get('id', [''])[0], query.get('view', ['hits'])[0], query.get('page', ['1'])[0]))
                elif parsed.path == '/api/export':
                    self.export(query.get('id', [''])[0], query.get('view', ['hits'])[0])
                else:
                    self.reply(404, {'error': '未找到'})
            except (ValueError, TypeError) as exc:
                self.reply(400, {'error': str(exc)})
            except (BrokenPipeError, ConnectionResetError):
                pass

        def export(self, ident, view):
            condition = 'job=?'
            if view != 'all':
                condition += " AND status='hit'"
            if view == 'verified':
                condition += " AND verified='1'"
            with connect(manager.path) as db:
                if not db.execute('SELECT 1 FROM jobs WHERE id=?', (ident,)).fetchone():
                    self.reply(404, {'error': '任务不存在'})
                    return
                self.send_response(200)
                self.send_header('Content-Type', 'text/csv; charset=utf-8')
                self.send_header('Content-Disposition', 'attachment; filename="results.csv"')
                self.send_header('Cache-Control', 'no-store')
                self.send_header('X-Content-Type-Options', 'nosniff')
                self.end_headers()
                self.wfile.write(b'\xef\xbb\xbf')
                buf = io.StringIO()
                writer = csv.DictWriter(buf, fieldnames=FIELDS, extrasaction='ignore')
                writer.writeheader()
                self.wfile.write(buf.getvalue().encode())
                # Short paginated reads avoid holding a WAL snapshot during a slow download.
                cursor = 0
                maximum = db.execute('SELECT COALESCE(MAX(rowid),0) FROM results WHERE job=?', (ident,)).fetchone()[0]
                while True:
                    rows = db.execute(f'SELECT rowid,data FROM results WHERE {condition} AND rowid>? AND rowid<=? ORDER BY rowid LIMIT 200', (ident, cursor, maximum)).fetchall()
                    if not rows:
                        break
                    for row in rows:
                        data = json.loads(row['data'])
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
                    self.reply(200, {'id': manager.start(raw)})
                elif path == '/api/resume':
                    ident = raw.get('id')
                    if not isinstance(ident, str) or not ident:
                        raise ValueError('缺少任务 ID')
                    self.reply(200, {'id': manager.start(resume=ident)})
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
    server = ThreadingHTTPServer((os.environ.get('CFVPS_HOST', '127.0.0.1'), int(os.environ.get('CFVPS_PORT', '8787'))), make_handler(manager, password))
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
