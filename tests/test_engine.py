import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from engine import Manager, connect, prepare, targets


class EngineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.manager = Manager(Path(self.tmp.name) / 'scan.db')

    def tearDown(self):
        self.manager.stop()
        if self.manager.thread:
            self.manager.thread.join(5)
        self.tmp.cleanup()

    def wait(self):
        self.manager.thread.join(5)
        self.assertFalse(self.manager.thread.is_alive())

    def test_validation_and_overlap(self):
        config = prepare({'targets': '8.8.8.0/30\n8.8.8.1/32', 'ports': '443,443'})
        self.assertEqual(config['total'], 2)
        self.assertEqual(list(targets(config)), [('8.8.8.1', 443), ('8.8.8.2', 443)])
        for raw in [{'targets':'127.0.0.1'}, {'targets':'8.8.8.8','timeout':'NaN'}, {'targets':'8.8.8.8','ports':'0'}, {'targets':'8.0.0.0/8'}, {'concurrency':0}]:
            with self.assertRaises(ValueError):
                prepare(raw)

    def test_stop_resume_skips_nonhits_and_recovers_restart(self):
        calls = []
        async def fake(ip, port, timeout, sem, **kwargs):
            calls.append((ip, port))
            # One completed result, then stop; all results must become checkpoints.
            self.manager.stop_event.set()
            return {'ip':ip,'port':port,'status':'open_not_cf','verified':'','latency_ms':1}
        with patch('engine.probe', fake):
            ident = self.manager.start({'targets':'8.8.8.0/30','ports':'443','concurrency':1,'provider':'retired_example','provider_name':'旧服务商快照'})
            self.wait()
        self.assertEqual(self.manager.jobs()[0]['status'], 'stopped')
        self.assertEqual(self.manager.results(ident, 'all')['total'], 1)
        self.assertEqual(self.manager.results(ident, 'hits')['total'], 0)
        with connect(self.manager.path) as db:
            db.execute("UPDATE jobs SET status='running' WHERE id=?", (ident,))
        self.manager = Manager(self.manager.path)
        self.assertEqual(self.manager.jobs()[0]['status'], 'interrupted')
        async def hit(ip, port, timeout, sem, **kwargs):
            calls.append((ip, port))
            return {'ip':ip,'port':port,'status':'hit','verified':'1','evidence':'dual_verified','latency_ms':2}
        with patch('engine.probe', hit):
            self.manager.start(resume=ident)
            self.wait()
        self.assertEqual(len(calls), len(set(calls)))
        self.assertEqual(self.manager.jobs()[0]['config']['provider'],'retired_example')
        self.assertEqual(self.manager.jobs()[0]['config']['concurrency'],1)
        job = self.manager.jobs()[0]
        self.assertEqual((job['status'],job['done'],job['hits']), ('completed',2,1))
        self.assertEqual(self.manager.results(ident, 'verified')['total'], 1)

    def test_favorites_across_ports_tasks_and_restart(self):
        async def hit(ip, port, timeout, sem, **kwargs):
            return dict(ip=ip,port=port,status='hit',verified='1',evidence='dual_verified',latency_ms=2)
        ids=[]
        with patch('engine.probe',hit):
            for _ in range(2):
                ids.append(self.manager.start({'targets':'8.8.8.8','ports':'443,8443'}))
                self.wait()
        self.manager.favorite('8.8.8.8',True)
        self.manager.favorite('8.8.8.8',True)
        self.manager=Manager(self.manager.path)
        rows=self.manager.results('*','all',favorites=True)
        self.assertEqual(rows['total'],4)
        self.assertTrue(all(r['favorite'] for r in rows['items']))
        self.assertEqual(sum(r['count'] for r in self.manager.facets('*','all',favorites=True)['regions']),4)
        self.manager.delete(ids[0])
        self.assertEqual(self.manager.results('*','all',favorites=True)['total'],2)
        self.manager.favorite('8.8.8.8',False)
        self.assertEqual(self.manager.results('*','all',favorites=True)['total'],0)
        self.assertTrue(all(not r['favorite'] for r in self.manager.results('*','all')['items']))
        for ip,enabled in [('127.0.0.1',True),('invalid',True),('8.8.8.8','true')]:
            with self.assertRaises(ValueError):
                self.manager.favorite(ip,enabled)

    def test_failure_is_visible(self):
        async def fail(*args, **kwargs):
            raise RuntimeError('simulated failure')
        with patch('engine.probe', fail):
            self.manager.start({'targets':'8.8.8.8','ports':'443'})
            self.wait()
        job = self.manager.jobs()[0]
        self.assertEqual(job['status'], 'failed')
        self.assertIn('simulated failure', job['error'])

    def test_retries(self):
        from probing import observe
        calls = []
        async def fake(ip, port, sni, timeout):
            calls.append(ip)
            return dict(is_cf=False,trace_valid=False,server='',cf_ray='',trace={},http_status=None,
                        err='TimeoutError',error_kind='connect_timeout',request_ms=10,connect_ms=None,tls_ms=None,ttfb_ms=None)
        with patch('probing.observe', fake):
            self.manager.start({'targets':'8.8.8.8','ports':'443','attempts':3})
            self.wait()
        self.assertEqual(len(calls), 3)
        self.assertEqual(self.manager.jobs()[0]['done'], 1)


if __name__ == '__main__':
    unittest.main()
