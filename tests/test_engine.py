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
        async def fake(ip, port, timeout, sem):
            calls.append((ip, port))
            # One completed result, then stop; all results must become checkpoints.
            self.manager.stop_event.set()
            return {'ip':ip,'port':port,'status':'open_not_cf','verified':'','latency_ms':1}
        with patch('engine.probe', fake):
            ident = self.manager.start({'targets':'8.8.8.0/30','ports':'443','concurrency':1})
            self.wait()
        self.assertEqual(self.manager.jobs()[0]['status'], 'stopped')
        self.assertEqual(self.manager.results(ident, 'all')['total'], 1)
        self.assertEqual(self.manager.results(ident, 'hits')['total'], 0)
        with connect(self.manager.path) as db:
            db.execute("UPDATE jobs SET status='running' WHERE id=?", (ident,))
        self.manager = Manager(self.manager.path)
        self.assertEqual(self.manager.jobs()[0]['status'], 'interrupted')
        async def hit(ip, port, timeout, sem):
            calls.append((ip, port))
            return {'ip':ip,'port':port,'status':'hit','verified':'1','latency_ms':2}
        with patch('engine.probe', hit):
            self.manager.start(resume=ident)
            self.wait()
        self.assertEqual(len(calls), len(set(calls)))
        job = self.manager.jobs()[0]
        self.assertEqual((job['status'],job['done'],job['hits']), ('completed',2,1))
        self.assertEqual(self.manager.results(ident, 'verified')['total'], 1)

    def test_failure_is_visible(self):
        async def fail(*args):
            raise RuntimeError('simulated failure')
        with patch('engine.probe', fail):
            self.manager.start({'targets':'8.8.8.8','ports':'443'})
            self.wait()
        job = self.manager.jobs()[0]
        self.assertEqual(job['status'], 'failed')
        self.assertIn('simulated failure', job['error'])

    def test_retries(self):
        calls = []
        async def fake(ip, port, *args):
            calls.append(ip)
            return {'ip':ip,'port':port,'status':'closed_or_error','verified':'','err':'TimeoutError'}
        with patch('engine.probe', fake):
            self.manager.start({'targets':'8.8.8.8','ports':'443','attempts':3})
            self.wait()
        self.assertEqual(len(calls), 3)
        self.assertEqual(self.manager.jobs()[0]['done'], 1)


if __name__ == '__main__':
    unittest.main()
