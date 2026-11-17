import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from engine import Manager, connect, prune_retention
from retention import maintain
import manage


class VacuumTests(unittest.TestCase):
    def fixture(self, path):
        Manager(path)
        with connect(path) as db:
            db.executemany('INSERT INTO results(job,ip,port,status,data,observed) VALUES (?,?,?,?,?,?)',
                           [('fixture', str(i), 443, 'miss', 'x' * 4000, 0) for i in range(3500)])
        prune_retention(path)
        with connect(path) as db:
            return db.execute('PRAGMA freelist_count').fetchone()[0]

    def test_incremental_reclaims_and_running_job_skips(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'scan.db'
            before = self.fixture(path)
            with connect(path) as db:
                db.execute("INSERT INTO jobs(id,status) VALUES ('active','running')")
            maintain(path)
            with connect(path) as db:
                self.assertEqual(db.execute('PRAGMA freelist_count').fetchone()[0], before)
                db.execute("UPDATE jobs SET status='completed'")
            maintain(path)
            with connect(path) as db:
                after = db.execute('PRAGMA freelist_count').fetchone()[0]
                self.assertGreaterEqual(before - after, 1000)
                self.assertLessEqual(before - after, 2000)
                self.assertEqual(db.execute('PRAGMA cache_size').fetchone()[0], -8000)

    def test_compact_converts_legacy_preserves_rows_and_permissions(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / 'scan.db'
            with sqlite3.connect(path) as db:
                db.execute('CREATE TABLE payload(data BLOB)')
                db.executemany('INSERT INTO payload VALUES (?)', [(b'x' * 4000,)] * 3500)
                db.execute('DELETE FROM payload WHERE rowid>3')
            before = path.stat().st_size
            with patch.object(manage, 'require_install'), patch.object(manage, 'data_dir', return_value=root), patch.object(manage, 'backup', return_value='fixture-backup'), patch.object(manage, 'active', return_value=True), patch.object(manage, 'run') as run:
                manage.compact()
                self.assertEqual(run.call_args_list[-1].args, ('systemctl', 'start', 'cf-vps'))
            with sqlite3.connect(path) as db:
                self.assertEqual(db.execute('SELECT COUNT(*) FROM payload').fetchone()[0], 3)
                self.assertEqual(db.execute('PRAGMA auto_vacuum').fetchone()[0], 2)
            self.assertLess(path.stat().st_size, before // 10)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual((root / 'scan.db.bak').stat().st_size, before)

    def test_compact_low_space_preserves_source_and_restarts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / 'scan.db'
            self.fixture(path)
            with patch.object(manage, 'require_install'), patch.object(manage, 'data_dir', return_value=root), patch.object(manage, 'backup'), patch.object(manage, 'active', return_value=True), patch.object(manage, 'run') as run, patch.object(manage.shutil, 'disk_usage', return_value=type('Usage', (), {'free': 0})()):
                with self.assertRaisesRegex(ValueError, '可用空间不足'):
                    manage.compact()
                self.assertEqual(run.call_args_list[-1].args, ('systemctl', 'start', 'cf-vps'))
            self.assertFalse((root / 'scan.db.bak').exists())
            self.assertFalse(list(root.glob('.compact-*')))
