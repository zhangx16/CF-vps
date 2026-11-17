import base64
import contextlib
import fcntl
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from db import ConflictError, available, initialize_schema, connect
from engine import Manager
from server import make_handler


class RequestStream:
    """A mock connection drives the real HTTP parser without opening sockets."""
    def __init__(self, request):
        self.input = io.BytesIO(request)
        self.output = bytearray()
    def makefile(self, *args):
        return self.input
    def sendall(self, data):
        self.output.extend(data)
    def settimeout(self, timeout):
        pass


class HealthTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / 'scan.db'
        self.manager = Manager(self.path)

    def tearDown(self):
        self.manager.stop()
        self.manager.join(5)
        self.tmp.cleanup()

    def request(self, method, path, body=None, auth=True):
        payload = json.dumps(body).encode() if body is not None else b''
        headers = ['Host: localhost', 'Content-Type: application/json', 'X-Requested-With: CF-VPS', f'Content-Length: {len(payload)}']
        if auth:
            token = base64.b64encode(b'admin:fixture-password-1234').decode()
            headers.append('Authorization: Basic ' + token)
        stream = RequestStream((f'{method} {path} HTTP/1.0\r\n' + '\r\n'.join(headers) + '\r\n\r\n').encode() + payload)
        with contextlib.redirect_stdout(io.StringIO()) as log:
            make_handler(self.manager, 'fixture-password-1234')(stream, ('127.0.0.1', 1234), object())
        head, data = bytes(stream.output).split(b'\r\n\r\n', 1)
        return int(head.split()[1]), json.loads(data), log.getvalue()

    def test_health_auth_metrics_and_duration_log(self):
        self.assertEqual(self.request('GET', '/api/health', auth=False)[0], 401)
        status, metrics, log = self.request('GET', '/api/health?secret=never-log')
        self.assertEqual(status, 200)
        self.assertEqual((metrics['jobs'], metrics['hits'], metrics['running_jobs']), (0, 0, 0))
        self.assertEqual(metrics['runners'], [])
        self.assertGreater(metrics['page_count'], 0)
        self.assertEqual(metrics['used_bytes'], (metrics['page_count']-metrics['freelist_count'])*metrics['page_size'])
        self.assertTrue(metrics['rss_bytes'] is None or metrics['rss_bytes'] > 0)
        self.assertIn('"/api/health" 200 ', log)
        self.assertIn('ms', log)
        self.assertNotIn('secret', log)
        self.assertNotIn('password', log)
        self.assertNotIn('config', metrics)

    def test_compaction_returns_503_and_conflict_returns_409(self):
        with (self.path.parent / 'compact.lock').open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.assertEqual(self.request('GET', '/api/health')[0], 503)
            self.assertEqual(self.request('POST', '/api/start', {})[0], 503)
        with patch.object(self.manager, 'start', side_effect=ConflictError('running')):
            self.assertEqual(self.request('POST', '/api/resume', {'id': 'busy'})[0], 409)
        self.assertEqual(self.request('POST', '/api/resume', {})[0], 400)
        self.assertEqual(self.request('GET', '/does-not-exist')[0], 404)
        with available(self.path), (self.path.parent / 'compact.lock').open('a') as lock:
            with self.assertRaises(BlockingIOError):
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def test_empty_schema_is_repeatable_and_missing_columns_migrate(self):
        old = self.path.parent / 'old.db'
        with connect(old) as db:
            db.execute('CREATE TABLE results(job TEXT,ip TEXT,port INTEGER,status TEXT,verified TEXT,latency REAL,data TEXT,PRIMARY KEY(job,ip,port))')
            db.execute('INSERT INTO results VALUES (?,?,?,?,?,?,?)', ('old', '8.8.8.8', 443, 'hit', '1', 1, json.dumps(dict(ip='8.8.8.8', port=443, status='hit'))))
        initialize_schema(old)
        initialize_schema(old)
        with connect(old) as db:
            columns = {r['name'] for r in db.execute('PRAGMA table_info(results)')}
            self.assertTrue({'evidence','colo','loc','observed','ip_num'} <= columns)
            self.assertEqual(db.execute('SELECT evidence FROM results').fetchone()[0], 'legacy')
            self.assertEqual(db.execute('PRAGMA quick_check').fetchone()[0], 'ok')

    def test_unknown_prepare_fields_do_not_change_limits(self):
        from engine import prepare
        config = prepare(dict(targets='8.8.8.8', unexpected='ignored'))
        self.assertNotIn('unexpected', config)
        self.assertEqual(config['total'], 2)
