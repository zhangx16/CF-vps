import asyncio
import json
import random
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from accuracy import compare_passes, sample_targets
from diagnostics import classify
from engine import Manager, connect, prune_retention
from adaptive import AdaptiveLimiter


class DiagnosticTests(unittest.TestCase):
    def test_failure_and_verification_are_separate(self):
        for cause in ['connection_refused','connect_timeout','tls_timeout','http_timeout','tls_error','http_error','connect_error']:
            self.assertEqual(dict(classify(dict(status='closed_or_error',error_kind=cause))),{cause:1})
        self.assertEqual(dict(classify(dict(status='open_not_cf'))),{'open_not_cf':1})
        self.assertEqual(dict(classify(dict(status='hit',verification='error',verify_error='tls_timeout'))),{'hit':1,'verify_tls_timeout':1})
        self.assertEqual(dict(classify(dict(status='hit',evidence='dual_verified',verification='confirmed'))),{'hit':1,'verify_confirmed':1})

    def test_aggregate_counts_resume_without_storing_failed_addresses(self):
        with tempfile.TemporaryDirectory() as tmp:
            manager=Manager(Path(tmp)/'scan.db')
            async def fail(ip,port,*args,**kw):
                manager.stop_event.set()
                return dict(ip=ip,port=port,status='closed_or_error',error_kind='connect_timeout')
            with patch('engine.probe',fail):
                ident=manager.start(dict(targets='8.8.8.0/30',ports='443',concurrency=1))
                manager.join(5)
            self.assertEqual(manager.jobs()[0]['diagnostics'],{'connect_timeout':1})
            manager=Manager(manager.path)
            async def hit(ip,port,*args,**kw):
                return dict(ip=ip,port=port,status='hit',evidence='dual_verified',verification='confirmed')
            with patch('engine.probe',hit):
                manager.start(resume=ident);manager.join(5)
            self.assertEqual(manager.jobs()[0]['diagnostics'],{'connect_timeout':1,'hit':1,'verify_confirmed':1})
            with connect(manager.path) as db:
                self.assertEqual(db.execute('SELECT COUNT(*) FROM results').fetchone()[0],1)
                self.assertEqual(db.execute('SELECT COUNT(*) FROM results WHERE status!=\'hit\'').fetchone()[0],0)


class AccuracyTests(unittest.TestCase):
    def test_sample_stays_in_scope_and_handles_small_networks(self):
        config=dict(networks=['8.8.8.0/30','1.1.1.0/31'],ports=[443,8443])
        samples=sample_targets(config,[('8.8.8.1',443)],64,random.Random(1))
        expected={(ip,p) for ip in ['8.8.8.1','8.8.8.2','1.1.1.0','1.1.1.1'] for p in [443,8443]}
        self.assertEqual(set(samples),expected)
        config.update(kind='retest',selected=[['8.8.8.1',443]])
        self.assertEqual(sample_targets(config,[],64),[('8.8.8.1',443)])

    def test_repeated_discrepancies_are_not_called_proven_misses(self):
        endpoints=[('8.8.8.1',443),('8.8.8.2',443)]
        passes=[dict(mode=mode,outcomes={endpoint:dict(hit=(mode=='low' and index==0),dual=False) for index,endpoint in enumerate(endpoints)}) for mode in ['low','high','high','low']]
        report=compare_passes(endpoints,passes)
        self.assertEqual(report['repeated_low_only'],1)
        self.assertEqual(len(report['discrepancies']),1)
        self.assertIn('不能直接认定',report['interpretation'])

    def make_manager(self,tmp):
        manager=Manager(Path(tmp)/'scan.db')
        config=dict(networks=['8.8.8.0/27'],ports=[443],concurrency=16000,timeout=.5,attempts=1,rps=2000)
        with connect(manager.path) as db:
            db.execute('INSERT INTO jobs(id,created,updated,status,config,total) VALUES (?,?,?,?,?,?)',('job',time.time(),time.time(),'completed',json.dumps(config),30))
        return manager

    def test_four_pass_report_survives_restart_and_expires(self):
        with tempfile.TemporaryDirectory() as tmp:
            manager=self.make_manager(tmp)
            calls=[]
            async def probe(ip,port,*args,**kwargs):
                calls.append((ip,port))
                return dict(ip=ip,port=port,status='closed_or_error',error_kind='connect_timeout')
            with patch('accuracy.probe',probe):
                manager.accuracy.start('job',16)
                manager.accuracy.thread.join(5)
            report=manager.accuracy.get('job')
            self.assertEqual(report['status'],'completed')
            self.assertEqual([p['mode'] for p in report['passes']],['low','high','high','low'])
            self.assertEqual(report['completed_checks'],64)
            self.assertEqual(len(set(calls)),16)
            manager=Manager(manager.path)
            self.assertEqual(manager.accuracy.get('job')['status'],'completed')
            self.assertNotIn('8.8.8.',json.dumps(manager.accuracy.get('job')))
            prune_retention(manager.path,time.time()+86401)
            self.assertIsNone(manager.accuracy.get('job'))

    def test_failed_audit_restores_background_limit(self):
        with tempfile.TemporaryDirectory() as tmp:
            manager=self.make_manager(tmp)
            async def make_controller():
                # Python 3.9 binds asyncio synchronization objects at construction.
                return AdaptiveLimiter(16000,enabled=False)
            controller=asyncio.run(make_controller())
            manager.runners['job']=dict(controller=controller)
            async def fail(*args,**kwargs):
                self.assertEqual(controller.audit_limit,4)
                raise RuntimeError('probe failed')
            with patch('accuracy.probe',fail):
                manager.accuracy.start('job',16)
                manager.accuracy.thread.join(5)
            self.assertEqual(manager.accuracy.get('job')['status'],'failed')
            self.assertIsNone(controller.audit_limit)
            manager.runners.clear()

    def test_audit_override_limits_gate_without_changing_ceiling(self):
        async def run():
            gate=AdaptiveLimiter(16000,enabled=False);gate.audit_limit=1
            entered=[]
            async def work(n):
                async with gate.slot(lambda:False):
                    entered.append(n);self.assertEqual(gate.active,1);await asyncio.sleep(.01)
            await asyncio.gather(work(1),work(2))
            self.assertEqual(entered,[1,2]);self.assertEqual(gate.ceiling,16000)
            self.assertEqual(gate.snapshot()['effective_concurrency'],1)
        asyncio.run(run())
