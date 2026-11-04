import asyncio
import json
import sqlite3
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from engine import Manager, connect, RateLimiter
from probing import probe, valid_trace


def observation(valid=True, sni='www.cloudflare.com', error=''):
    return dict(is_cf=True,trace_valid=valid,server='cloudflare',cf_ray='abc-SJC',
                trace=dict(ip='8.8.8.8',fl='abc',colo='SJC',loc='US',h=sni),
                http_status=200,err=error,error_kind='http_timeout' if error else '',
                request_ms=12,connect_ms=1,tls_ms=3,ttfb_ms=9)


class ProbeEvidenceTests(unittest.IsolatedAsyncioTestCase):
    def test_trace_contract(self):
        trace=observation()['trace']
        self.assertTrue(valid_trace(200,trace,'www.cloudflare.com'))
        for field in ['h','ip','fl','colo','loc']:
            bad=dict(trace);bad[field]=''
            self.assertFalse(valid_trace(200,bad,'www.cloudflare.com'))
        self.assertFalse(valid_trace(403,trace,'www.cloudflare.com'))
        self.assertFalse(valid_trace(200,trace,'one.one.one.one'))

    async def test_secondary_retry_and_strict_confirmation(self):
        calls=[]
        async def fake(ip,port,sni,timeout):
            calls.append(sni)
            if len(calls)==2:
                return observation(error='TimeoutError')
            return observation(sni=sni)
        with patch('probing.observe',fake):
            result=await probe('8.8.8.8',443,1,asyncio.Semaphore(1),attempts=2)
        self.assertEqual(result['evidence'],'dual_verified')
        self.assertEqual(len(calls),3)

    async def test_header_only_is_not_confirmed(self):
        async def fake(ip,port,sni,timeout):
            return observation(valid=False,sni=sni)
        with patch('probing.observe',fake):
            result=await probe('8.8.8.8',443,1,asyncio.Semaphore(1))
        self.assertEqual(result['evidence'],'suspected')
        self.assertEqual(result['verified'],'0')

    async def test_secondary_timeout_is_distinct_from_negative(self):
        calls=[]
        async def fake(ip,port,sni,timeout):
            calls.append(sni)
            return observation(error='TimeoutError' if len(calls)>1 else '')
        with patch('probing.observe',fake):
            result=await probe('8.8.8.8',443,1,asyncio.Semaphore(1))
        self.assertEqual(result['verification'],'error')
        self.assertEqual(result['evidence'],'trace_valid')
        self.assertEqual(result['verified'],'')

    async def test_rate_gate_spacing(self):
        limiter=RateLimiter(20,lambda:False)
        times=[]
        async def request():
            await limiter.wait();times.append(time.monotonic())
        await asyncio.gather(*(request() for _ in range(4)))
        self.assertGreaterEqual(times[-1]-times[0],.145)


class HistoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.path=Path(self.tmp.name)/'scan.db'
        self.manager=Manager(self.path)

    def tearDown(self):
        self.manager.stop()
        if self.manager.thread:self.manager.thread.join(5)
        self.tmp.cleanup()

    def run_job(self, hits, raw=None):
        async def fake(ip,port,*args,**kwargs):
            last=int(ip.rsplit('.',1)[1])
            return dict(ip=ip,port=port,status='hit' if last in hits else 'closed_or_error',
                        evidence='dual_verified' if last in hits else 'none',verified='1' if last in hits else '',
                        request_ms=100-last,colo='NRT' if last%2 else 'SJC',loc='JP' if last%2 else 'US')
        with patch('engine.probe',fake):
            ident=self.manager.start(raw or {'targets':'8.8.8.0/29','ports':'443'})
            self.manager.thread.join(5)
        self.assertEqual(self.manager.jobs()[0]['status'],'completed')
        return ident

    def test_filter_sort_keyset_and_search(self):
        ident=self.run_job(set(range(1,7)))
        facets=self.manager.facets(ident)
        self.assertEqual({r['value']:r['count'] for r in facets['regions']},{'US':3,'JP':3})
        first=self.manager.results(ident,sort='latency_asc',limit=2)
        second=self.manager.results(ident,sort='latency_asc',limit=2,cursor=first['next_cursor'])
        self.assertEqual([r['ip'] for r in first['items']+second['items']],['8.8.8.6','8.8.8.5','8.8.8.4','8.8.8.3'])
        regional=self.manager.results(ident,region='JP',colo='NRT',sort='latency_asc')
        self.assertEqual([r['ip'] for r in regional['items']],['8.8.8.5','8.8.8.3','8.8.8.1'])
        self.assertEqual(self.manager.results(ident,search='8.8.8.1')['total'],1)
        with self.assertRaises(ValueError):self.manager.results(ident,sort='latency_asc;DELETE')
        with self.assertRaises(ValueError):self.manager.results(ident,cursor='invalid')

    def test_compare_retest_history_and_delete(self):
        old=self.run_job({1,2,3});new=self.run_job({2,3,4})
        result=self.manager.compare(old,new)
        self.assertEqual(result['counts'],{'new':1,'lost':1,'persistent':2})
        self.assertEqual(result['items'][0]['ip'],'8.8.8.4')
        self.assertEqual(self.manager.results(new,search='8.8.8.1',view='all')['total'],0)
        row=self.manager.results(old,search='8.8.8.1')['items'][0]
        self.assertEqual((row['history']['checks'],row['history']['successes']),(1,1))
        async def fake(ip,port,*args,**kwargs):
            return dict(ip=ip,port=port,status='hit',evidence='dual_verified',verified='1',request_ms=10)
        with patch('engine.probe',fake):
            ident=self.manager.start({'selected':[{'ip':'8.8.8.1','port':443}]},retest=old)
            self.manager.thread.join(5)
        row=self.manager.results(ident)['items'][0]
        self.assertEqual((row['history']['checks'],row['history']['successes']),(2,2))
        self.assertIsNotNone(row['history']['last_confirmed'])
        self.manager.delete(old)
        self.assertEqual(self.manager.results(old,view='all')['total'],0)
        self.assertEqual(len(self.manager.jobs()),2)

    def test_timer_commits_without_further_completed_requests(self):
        second_started=threading.Event()
        async def fake(ip,port,*args,**kwargs):
            if ip.endswith('.2'):
                second_started.set();await asyncio.sleep(1.2)
            return dict(ip=ip,port=port,status='open_not_cf',request_ms=1)
        with patch('engine.probe',fake):
            ident=self.manager.start({'targets':'8.8.8.0/30','ports':'443','concurrency':1})
            self.assertTrue(second_started.wait(2))
            time.sleep(.7)
            with connect(self.path) as db:
                self.assertEqual(db.execute('SELECT COUNT(*) FROM results WHERE job=?',(ident,)).fetchone()[0],1)
            self.manager.thread.join(5)

    def test_legacy_migration_does_not_claim_strict_confirmation(self):
        self.manager=None
        self.path.unlink()
        db=sqlite3.connect(self.path)
        db.executescript('CREATE TABLE results(job TEXT,ip TEXT,port INTEGER,status TEXT,verified TEXT,latency REAL,data TEXT,PRIMARY KEY(job,ip,port));')
        data=dict(ip='8.8.8.8',port=443,status='hit',verified='1',colo='SJC',loc='US')
        db.execute('INSERT INTO results VALUES (?,?,?,?,?,?,?)',('old','8.8.8.8',443,'hit','1',12,json.dumps(data)))
        db.commit();db.close()
        self.manager=Manager(self.path)
        self.assertEqual(self.manager.results('old','verified')['total'],0)
        self.assertEqual(self.manager.results('old','legacy')['total'],1)
        self.assertEqual(self.manager.facets('old')['regions'][0]['value'],'US')

    def test_connection_is_closed_on_exit(self):
        with connect(self.path) as db:db.execute('SELECT 1')
        with self.assertRaises(sqlite3.ProgrammingError):db.execute('SELECT 1')

    def test_cross_task_catalog_groups_and_searches_by_provider(self):
        first=self.run_job({1,2,3})
        second=self.run_job({1,2},{'targets':'8.8.8.0/30','ports':'443','provider':'vultr','provider_name':'Vultr','provider_asns':[20473]})
        self.assertEqual(self.manager.results('*',view='all')['total'],5)
        matches=self.manager.results('*',view='all',provider='vultr',search='8.8.8.1')
        self.assertEqual(matches['total'],1)
        self.assertEqual(matches['items'][0]['job_id'],second)
        self.assertEqual(matches['items'][0]['provider_name'],'Vultr')
        self.assertEqual(self.manager.results('*',view='all',search='8.8.8.1')['total'],2)
        groups={p['id']:p for p in self.manager.catalog()['providers']}
        self.assertEqual(groups['vultr']['records'],2)
        self.assertEqual(groups['custom_targets']['records'],6)
        self.assertEqual(self.manager.facets('*',view='all',provider='vultr')['regions'][0]['count'],1)
