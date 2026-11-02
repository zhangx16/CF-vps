import asyncio
import base64
import http.client
import json
import ssl
import subprocess
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from engine import Manager
from scan_dmit_cf_fallback import probe_once
from server import make_handler


class DashboardTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.manager = Manager(Path(self.tmp.name) / 'scan.db')
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), make_handler(self.manager, 'test-password-12345678'))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.manager.stop()
        if self.manager.thread:
            self.manager.thread.join(5)
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.tmp.cleanup()

    def request(self, method, path, data=None, auth=True, csrf=True):
        conn = http.client.HTTPConnection(*self.server.server_address, timeout=5)
        headers = {}
        if auth:
            headers['Authorization'] = 'Basic ' + base64.b64encode(b'admin:test-password-12345678').decode()
        if csrf:
            headers['X-Requested-With'] = 'CF-VPS'
        if data is not None:
            headers['Content-Type'] = 'application/json'
        conn.request(method, path, json.dumps(data) if data is not None else None, headers)
        response = conn.getresponse()
        result = response.status, dict(response.getheaders()), response.read()
        conn.close()
        return result

    def test_auth_csrf_and_static(self):
        self.assertEqual(self.request('GET', '/api/jobs', auth=False)[0], 401)
        self.assertEqual(self.request('GET', '/app.js', auth=False)[0], 401)
        status, headers, html = self.request('GET', '/')
        self.assertEqual(status, 200)
        self.assertIn(b'/app.js', html)
        self.assertIn("script-src 'self'", headers['Content-Security-Policy'])
        self.assertEqual(self.request('POST', '/api/start', {}, csrf=False)[0], 403)
        self.assertEqual(self.request('POST', '/api/start', {'targets':'127.0.0.1'})[0], 400)
        self.assertEqual(self.request('POST', '/api/resume', {})[0], 400)

    def test_start_results_export_and_busy(self):
        async def fake(ip, port, *args, **kwargs):
            await asyncio.sleep(0.1)
            return dict(ip=ip,port=port,status='hit',verified='1',evidence='dual_verified',latency_ms=12,server='=FORMULA()')
        with patch('engine.probe', fake):
            status, _, body = self.request('POST', '/api/start', {'targets':'8.8.8.0/30','ports':'443','concurrency':1})
            self.assertEqual(status, 200)
            ident = json.loads(body)['id']
            self.assertEqual(self.request('POST', '/api/start', {'targets':'8.8.8.8'})[0], 400)
            self.manager.thread.join(5)
        result = self.request('GET', f'/api/results?id={ident}&view=verified')
        self.assertEqual(json.loads(result[2])['total'], 2)
        status, headers, body = self.request('GET', f'/api/export?id={ident}&view=all')
        self.assertEqual(status, 200)
        self.assertIn('attachment', headers['Content-Disposition'])
        self.assertIn(b"'=FORMULA()", body)
        self.assertEqual(self.request('GET', '/api/export?id=missing')[0], 404)


class ProbeTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cert = str(Path(cls.tmp.name) / 'cert.pem')
        key = str(Path(cls.tmp.name) / 'key.pem')
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',key,'-out',cert,'-days','1','-subj','/CN=localhost'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        cls.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        cls.context.load_cert_chain(cert, key)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    async def test_fragmented_chunked_tls_response(self):
        async def handle(reader, writer):
            try:
                await reader.readuntil(b'\r\n\r\n')
                # Header and trace body are deliberately split over multiple TLS records.
                for part in [b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n', b'\r\n', b'4\r\nfl=x\r\n', b'B\r\n\ncolo=SJC\n\n\r\n', b'0\r\n\r\n']:
                    writer.write(part)
                    await writer.drain()
                    await asyncio.sleep(0.01)
            finally:
                writer.close()
                await writer.wait_closed()
        server = await asyncio.start_server(handle, '127.0.0.1', 0, ssl=self.context)
        async with server:
            result = await probe_once('127.0.0.1', server.sockets[0].getsockname()[1], 'localhost', 1)
        self.assertTrue(result[0], result)
        self.assertEqual(result[3]['colo'], 'SJC')

    async def test_timeout_bounds_stalled_http(self):
        async def handle(reader, writer):
            try:
                await reader.readuntil(b'\r\n\r\n')
                await reader.read()
            finally:
                writer.close()
                await writer.wait_closed()
        server = await asyncio.start_server(handle, '127.0.0.1', 0, ssl=self.context)
        async with server:
            started = asyncio.get_running_loop().time()
            result = await probe_once('127.0.0.1', server.sockets[0].getsockname()[1], 'localhost', .1)
            elapsed = asyncio.get_running_loop().time() - started
        self.assertFalse(result[0])
        self.assertEqual(result[5], 'TimeoutError')
        self.assertLess(elapsed, .7)


class LoginGuardTests(unittest.TestCase):
    def test_failed_logins_expire_and_good_login_resets_counter(self):
        from server import LoginGuard
        guard=LoginGuard()
        with patch('server.time.monotonic',return_value=100):
            for _ in range(10):guard.record('192.0.2.1',False)
            self.assertTrue(guard.blocked('192.0.2.1'))
            self.assertFalse(guard.blocked('192.0.2.2'))
            guard.record('192.0.2.1',True)
            self.assertFalse(guard.blocked('192.0.2.1'))
            for _ in range(10):guard.record('192.0.2.1',False)
        with patch('server.time.monotonic',return_value=161):
            self.assertFalse(guard.blocked('192.0.2.1'))
