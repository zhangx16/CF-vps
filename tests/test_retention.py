import asyncio
import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch
from engine import Manager, connect, prune_retention

class RetentionTests(unittest.TestCase):
    def test_expiry_copies_and_networks(self):
        with tempfile.TemporaryDirectory() as tmp:
            m = Manager(Path(tmp)/'scan.db')
            now=time.time()
            with connect(m.path) as db:
                db.execute('INSERT INTO jobs(id,created,updated,status,config,total) VALUES (?,?,?,?,?,?)',('j',now-90000,now,'stopped',json.dumps({'networks':['8.8.8.0/24']}),3))
                for ip,status,observed in [('8.8.8.1','hit',now-86401),('8.8.8.2','miss',now),('8.8.8.3','hit',now)]:
                    db.execute('INSERT INTO results(job,ip,port,status,data,observed,evidence) VALUES (?,?,?,?,?,?,?)',('j',ip,443,status,'{}',observed,'suspected'))
                    db.execute('INSERT INTO observations VALUES (?,?,?,?,?,?)',('j',ip,443,observed,int(status=='hit'),0))
                    db.execute('INSERT INTO confirmed_nodes VALUES (?,?,?,?,?)',('j',ip,443,now,now))
                    db.execute('INSERT INTO endpoint_favorites VALUES (?,?,?)',(ip,443,now))
                db.execute('INSERT INTO favorite_snapshots SELECT rowid,* FROM results')
            prune_retention(m.path,now)
            with connect(m.path) as db:
                for table in ['results','observations','favorite_snapshots','confirmed_nodes','endpoint_favorites']:
                    self.assertEqual(db.execute(f'SELECT ip FROM {table}').fetchall()[0][0],'8.8.8.3')
                    self.assertEqual(db.execute(f'SELECT COUNT(*) FROM {table}').fetchone()[0],1)
                self.assertEqual(json.loads(db.execute('SELECT config FROM jobs').fetchone()[0])['networks'],['8.8.8.0/24'])
            with self.assertRaisesRegex(ValueError,'24小时'):
                m.start(resume='j')

    def test_nonhits_never_saved_and_resume(self):
        with tempfile.TemporaryDirectory() as tmp:
            m=Manager(Path(tmp)/'scan.db')
            async def miss(ip,port,*args,**kw):
                return dict(ip=ip,port=port,status='miss')
            with patch('engine.probe',miss):
                ident=m.start(dict(targets='8.8.8.0/30',ports='443',concurrency=1))
                m.join(5)
            with connect(m.path) as db:
                self.assertEqual(db.execute('SELECT COUNT(*) FROM results').fetchone()[0],0)
                self.assertEqual(db.execute('SELECT COUNT(*) FROM observations').fetchone()[0],0)
                self.assertEqual(db.execute('SELECT done FROM jobs').fetchone()[0],2)
                self.assertEqual(db.execute('SELECT COUNT(*) FROM scan_progress').fetchone()[0],0)

class ThroughputTests(unittest.TestCase):
    def test_high_rate_limiter_and_cancellation(self):
        from engine import RateLimiter
        async def run():
            limiter=RateLimiter(2000,lambda:False)
            start=time.monotonic()
            await asyncio.gather(*(limiter.wait() for _ in range(600)))
            elapsed=time.monotonic()-start
            self.assertGreaterEqual(elapsed,.27)
            self.assertLess(elapsed,.55)
            stopped=RateLimiter(2000,lambda:True)
            with self.assertRaises(asyncio.CancelledError):
                await stopped.wait()
        asyncio.run(run())
