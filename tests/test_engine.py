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

    def test_concurrency_upper_bound(self):
        for value in [300,1000,1001,5000]:
            config=prepare({'targets':'8.8.8.8','concurrency':value,'min_concurrency':5000})
            self.assertEqual(config['concurrency'],value)
            self.assertEqual(config['min_concurrency'],value)
        for value in [0,5001]:
            with self.assertRaises(ValueError):prepare({'targets':'8.8.8.8','concurrency':value})

    def test_request_rate_upper_bound(self):
        for value in [1,1000,1001,2000]:
            self.assertEqual(prepare({'targets':'8.8.8.8','rps':value})['rps'],value)
        for value in [0,2001,float('inf'),float('nan')]:
            with self.assertRaises(ValueError):prepare({'targets':'8.8.8.8','rps':value})

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
        self.manager.favorite('8.8.8.8',443,True)
        self.manager.favorite('8.8.8.8',443,True)
        self.manager=Manager(self.manager.path)
        rows=self.manager.results('*','all',favorites=True)
        self.assertEqual(rows['total'],1)
        self.assertEqual(rows['items'][0]['port'],443)
        self.assertFalse(next(r for r in self.manager.results(ids[0],'all')['items'] if r['port']==8443)['favorite'])
        self.assertTrue(all(r['favorite'] for r in rows['items']))
        self.assertEqual(sum(r['count'] for r in self.manager.facets('*','all',favorites=True)['regions']),1)
        self.manager.delete(ids[0])
        self.assertEqual(self.manager.results('*','all',favorites=True)['total'],1)
        self.manager.delete(ids[1])
        self.assertEqual(self.manager.results('*','all',favorites=True)['total'],1)
        self.manager.favorite('8.8.8.8',443,False)
        self.assertEqual(self.manager.results('*','all',favorites=True)['total'],0)
        self.assertTrue(all(not r['favorite'] for r in self.manager.results('*','all')['items']))
        for ip,enabled in [('127.0.0.1',True),('invalid',True),('8.8.8.8','true')]:
            with self.assertRaises(ValueError):
                self.manager.favorite(ip,443,enabled)

    def test_named_task_persists_in_results_catalog_and_resume(self):
        async def hit(ip,port,timeout,sem,**kwargs):
            self.manager.stop_event.set()
            return dict(ip=ip,port=port,status='hit',verified='1',latency_ms=1)
        name='香港自选网段 · 晚间测试'
        with patch('engine.probe',hit):
            ident=self.manager.start({'targets':'8.8.8.0/30','ports':'443','concurrency':1,'task_name':'  '+name+'  '})
            self.wait()
        self.manager=Manager(self.manager.path)
        self.assertEqual(self.manager.jobs()[0]['config']['task_name'],name)
        self.assertEqual(self.manager.catalog()['jobs'][0]['task_name'],name)
        self.assertEqual(self.manager.results(ident,'all')['items'][0]['task_name'],name)
        with patch('engine.probe',hit):
            self.manager.start(resume=ident)
            self.wait()
        self.assertEqual(self.manager.jobs()[0]['config']['task_name'],name)
        self.assertEqual(prepare({'targets':'8.8.8.8'})['task_name'],'')
        for value in [None,{},'a'*61,'line\nname']:
            with self.assertRaises(ValueError):prepare({'targets':'8.8.8.8','task_name':value})

    def test_task_detail_preserves_original_targets_and_legacy_snapshot(self):
        text='8.8.8.0/30 # 测试网段\n8.8.8.1/32\n'
        async def hit(ip,port,*args,**kwargs):
            return dict(ip=ip,port=port,status='hit',verified='1',latency_ms=1)
        with patch('engine.probe',hit):
            ident=self.manager.start({'targets':text,'ports':'443','task_name':'输入快照'})
            self.wait()
        self.manager=Manager(self.manager.path)
        detail=self.manager.job_detail(ident)
        self.assertEqual(detail['target_text'],text)
        self.assertEqual(detail['target_kind'],'original')
        self.assertEqual(detail['networks'],['8.8.8.0/30'])
        self.assertEqual(detail['ports'],[443])
        self.assertNotIn('input_targets',self.manager.jobs()[0]['config'])
        with patch('engine.probe',hit):
            retest=self.manager.start(retest=ident)
            self.wait()
        self.assertEqual(self.manager.job_detail(retest)['kind'],'retest')
        self.assertEqual(self.manager.job_detail(retest)['target_text'],text)
        with connect(self.manager.path) as db:
            row=db.execute('SELECT config FROM jobs WHERE id=?',(ident,)).fetchone()
            config=json.loads(row['config']);config.pop('input_targets')
            db.execute('UPDATE jobs SET config=? WHERE id=?',(json.dumps(config),ident))
        self.assertEqual(self.manager.job_detail(ident)['target_kind'],'snapshot')
        self.assertEqual(self.manager.job_detail(ident)['target_text'],'8.8.8.0/30')
        with self.assertRaises(ValueError):self.manager.job_detail('missing')

    def test_completed_task_keeps_all_hit_levels_and_counters(self):
        levels=['dual_verified','trace_valid','suspected','legacy']
        async def result(ip,port,*args,**kwargs):
            index=int(ip.rsplit('.',1)[1])-1
            return dict(ip=ip,port=port,status='hit' if index<4 else 'closed_or_error',
                        evidence=levels[index] if index<4 else 'none',verified='',latency_ms=1)
        with patch('engine.probe',result):
            ident=self.manager.start({'targets':'8.8.8.0/29','ports':'443'})
            self.wait()
        job=self.manager.jobs()[0]
        self.assertEqual((job['status'],job['total'],job['done'],job['hits']),('completed',6,6,4))
        rows=self.manager.results(ident,'all')
        self.assertEqual(rows['total'],4)
        self.assertEqual({r['evidence'] for r in rows['items']},set(levels))
        with connect(self.manager.path) as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM observations WHERE job=? AND hit=0',(ident,)).fetchone()[0],0)
        self.manager=Manager(self.manager.path)
        self.assertEqual(self.manager.results(ident,'all')['total'],4)
        self.assertEqual(self.manager.jobs()[0]['done'],6)

    def test_startup_cleans_completed_only_and_preserves_paused_checkpoints(self):
        async def fail(ip,port,*args,**kwargs):
            return dict(ip=ip,port=port,status='closed_or_error',verified='',latency_ms=1)
        with patch('engine.probe',fail):
            completed=self.manager.start({'targets':'8.8.8.8','ports':'443'})
            self.wait()
        self.assertEqual(self.manager.results(completed,'all')['total'],0)
        def seed(db,job,ip):
            data=dict(ip=ip,port=443,status='open_not_cf')
            db.execute('INSERT INTO results(job,ip,port,status,data,evidence) VALUES (?,?,?,?,?,?)',(job,ip,443,'open_not_cf',json.dumps(data),'none'))
            db.execute('INSERT INTO observations VALUES (?,?,?,?,?,?)',(job,ip,443,1,0,0))
        with connect(self.manager.path) as db:
            seed(db,completed,'8.8.8.8')
            cfg=prepare({'targets':'1.1.1.0/30','ports':'443'})
            db.execute('INSERT INTO jobs(id,created,updated,status,config,total,done,hits) VALUES (?,?,?,?,?,?,?,?)',('paused',2,2,'stopped',json.dumps(cfg),2,1,0))
            seed(db,'paused','1.1.1.1')
        self.manager=Manager(self.manager.path)
        self.assertEqual(self.manager.results(completed,'all')['total'],0)
        self.assertEqual(self.manager.results('paused','all')['total'],1)
        calls=[]
        async def finish(ip,port,*args,**kwargs):
            calls.append(ip)
            return dict(ip=ip,port=port,status='closed_or_error',latency_ms=1)
        with patch('engine.probe',finish):
            self.manager.start(resume='paused')
            self.wait()
        self.assertEqual(calls,['1.1.1.2'])
        self.assertEqual(self.manager.results('paused','all')['total'],0)
        self.assertEqual(next(j for j in self.manager.jobs() if j['id']=='paused')['done'],2)

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
