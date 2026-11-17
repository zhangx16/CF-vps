"""Query-count and task-count regressions use mock probes only."""
import asyncio
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from engine import Manager, connect


class ScanQueryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.manager = Manager(Path(self.tmp.name) / 'scan.db')

    def tearDown(self):
        self.manager.stop()
        self.manager.join(5)
        self.tmp.cleanup()

    def traced(self, statements):
        original = sqlite3.connect
        def traced_connect(*args, **kwargs):
            connection = original(*args, **kwargs)
            connection.set_trace_callback(statements.append)
            return connection
        return patch('sqlite3.connect', traced_connect)

    def test_large_ceiling_has_bounded_workers_and_one_checkpoint_read(self):
        statements, workers = [], set()
        async def fake(ip, port, timeout, sem, **kwargs):
            self.assertIsNone(sem)
            workers.add(asyncio.current_task())
            await asyncio.sleep(.001)
            return dict(ip=ip, port=port, status='miss')
        with self.traced(statements), patch('engine.probe', fake):
            ident = self.manager.start(dict(targets='8.8.0.0/21', ports='443', concurrency=1000000, adaptive=False))
            self.manager.join(10)
        self.assertEqual(self.manager.jobs()[0]['status'], 'completed')
        self.assertGreater(len(workers), 1)
        self.assertLessEqual(len(workers), 256)
        reads = [sql for sql in statements if sql.startswith('SELECT') and 'FROM scan_progress' in sql]
        self.assertEqual(len(reads), 1)
        with connect(self.manager.path) as db:
            self.assertEqual(db.execute('SELECT done FROM jobs WHERE id=?', (ident,)).fetchone()[0], 2046)

    def test_results_metadata_is_batched_and_config_cache_invalidates(self):
        async def fake(ip, port, *args, **kwargs):
            return dict(ip=ip, port=port, status='hit', evidence='dual_verified', request_ms=2)
        with patch('engine.probe', fake):
            ident = self.manager.start(dict(targets='8.8.8.0/26', ports='443'))
            self.manager.join(5)
        statements = []
        with self.traced(statements):
            result = self.manager.results(ident, limit=50)
        self.assertEqual(len(result['items']), 50)
        self.assertEqual(result['items'][0]['history']['checks'], 1)
        for table in ('observations', 'confirmed_nodes', 'endpoint_favorites'):
            self.assertEqual(len([s for s in statements if s.startswith('SELECT') and 'FROM '+table in s]), 1)
        self.manager.job_sources()
        with connect(self.manager.path) as db:
            config = json.loads(db.execute('SELECT config FROM jobs WHERE id=?', (ident,)).fetchone()[0])
            config['task_name'] = 'renamed'
            db.execute('UPDATE jobs SET config=? WHERE id=?', (json.dumps(config), ident))
        self.assertEqual(self.manager.job_sources()[ident]['task_name'], 'renamed')
        # jobs() must not mutate the cached original input.
        self.manager.jobs()
        self.assertEqual(self.manager.job_detail(ident)['target_text'], '8.8.8.0/26')
