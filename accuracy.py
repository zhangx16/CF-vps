"""Paired low/high concurrency checks with repeated, counterbalanced order."""
import asyncio
from collections import Counter
import ipaddress
import json
import random
import threading
import time
import uuid

from probing import probe
from diagnostics import classify


def sample_targets(config, hits, size, rng=None):
    rng = rng or random.SystemRandom()
    # Half known candidates, half uniformly sampled endpoints from the saved input.
    hits = list(dict.fromkeys((str(ip), int(port)) for ip, port in hits))
    chosen = rng.sample(hits, min(len(hits), size // 2))
    ranges = []
    total = 0
    for cidr in config.get('networks', []):
        net = ipaddress.ip_network(cidr)
        start = int(net.network_address) + (1 if net.prefixlen < 31 else 0)
        count = net.num_addresses - (2 if net.prefixlen < 31 else 0)
        ranges.append((total, start, count))
        total += count * len(config['ports'])
    if config.get('kind') == 'retest':
        # A retest can contain a subset of the saved networks; never expand its scope.
        pool = list(dict.fromkeys(tuple(x) for x in config.get('selected', hits)))
        remaining = [x for x in pool if x not in chosen]
        chosen += rng.sample(remaining, min(len(remaining), size-len(chosen)))
    elif total:
        for index in rng.sample(range(total), min(total, size * 4)):
            for offset, start, count in reversed(ranges):
                if index >= offset:
                    relative = index - offset
                    endpoint = (str(ipaddress.ip_address(start + relative // len(config['ports']))), config['ports'][relative % len(config['ports'])])
                    if endpoint not in chosen:
                        chosen.append(endpoint)
                    break
            if len(chosen) >= size:
                break
    rng.shuffle(chosen)
    return chosen[:size]


def compare_passes(samples, passes):
    low = [p for p in passes if p['mode'] == 'low']
    high = [p for p in passes if p['mode'] == 'high']
    discrepancies = []
    stable_low_only = 0
    for endpoint in samples:
        lh = sum(p['outcomes'][endpoint]['hit'] for p in low)
        hh = sum(p['outcomes'][endpoint]['hit'] for p in high)
        ld = sum(p['outcomes'][endpoint]['dual'] for p in low)
        hd = sum(p['outcomes'][endpoint]['dual'] for p in high)
        if lh != hh or ld != hd:
            # Only endpoints with at least one hit are included in persistent reports.
            discrepancies.append(dict(ip=endpoint[0], port=endpoint[1], low_hits=lh, high_hits=hh,
                                      low_confirmed=ld, high_confirmed=hd))
        stable_low_only += lh == len(low) and hh == 0
    return dict(discrepancies=discrepancies, repeated_low_only=stable_low_only,
                interpretation='低并发独有命中需复核；差异也可能来自网络或目标随时间变化，不能直接认定为高并发漏检。')


class AccuracyAudit:
    def __init__(self, manager):
        self.manager = manager
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.thread = None
        self.live = None
        self.controllers = []
        from engine import connect
        with connect(manager.path) as db:
            db.execute('CREATE TABLE IF NOT EXISTS accuracy_reports (id TEXT PRIMARY KEY, job TEXT, created REAL, updated REAL, status TEXT, report TEXT)')
            db.execute("UPDATE accuracy_reports SET status='interrupted' WHERE status='running'")

    def cancel(self):
        self.stop.set()

    def get(self, job):
        from engine import connect
        with self.lock:
            if self.live and self.live['job'] == job:
                return dict(self.live)
        with connect(self.manager.path) as db:
            row = db.execute('SELECT * FROM accuracy_reports WHERE job=? AND created>? ORDER BY created DESC LIMIT 1', (job,time.time()-86400)).fetchone()
        if not row:
            return None
        return {**json.loads(row['report']), 'id':row['id'], 'job':job, 'status':row['status']}

    def start(self, job, size=64):
        from engine import connect
        if type(size) is not int or not 16 <= size <= 256:
            raise ValueError('对照样本数量应为16–256')
        with self.lock:
            if self.thread and self.thread.is_alive():
                raise ValueError('已有并发对照正在运行，请等待完成')
            with connect(self.manager.path) as db:
                row = db.execute('SELECT config FROM jobs WHERE id=?',(job,)).fetchone()
                if not row:
                    raise ValueError('任务不存在')
                config = json.loads(row['config'])
                hits = [(r['ip'],r['port']) for r in db.execute("SELECT ip,port FROM results WHERE job=? AND status='hit' AND observed>?",(job,time.time()-86400))]
            samples = sample_targets(config,hits,size)
            if len(samples)<2:
                raise ValueError('对照至少需要两个不同端点')
            ident = uuid.uuid4().hex
            self.stop = threading.Event()
            self.live = dict(id=ident,job=job,status='running',sample_size=len(samples),known_hit_samples=sum(endpoint in set(hits) for endpoint in samples),completed_checks=0,total_checks=4*len(samples),passes=[])
            with connect(self.manager.path) as db:
                db.execute('INSERT INTO accuracy_reports VALUES (?,?,?,?,?,?)',(ident,job,time.time(),time.time(),'running',json.dumps(self.live)))
            self.thread = threading.Thread(target=self._run,args=(config,samples),daemon=True)
            self.thread.start()
            return dict(self.live)

    def _persist(self):
        from engine import connect
        with self.lock:
            report = dict(self.live)
        with connect(self.manager.path) as db:
            db.execute('UPDATE accuracy_reports SET updated=?,status=?,report=? WHERE id=?',(time.time(),report['status'],json.dumps(report),report['id']))

    def _run(self, config, samples):
        try:
            asyncio.run(self._compare(config,samples))
        except asyncio.CancelledError:
            with self.lock:
                self.live['status']='cancelled'
        except Exception as exc:
            with self.lock:
                self.live.update(status='failed',error=str(exc)[:500])
        finally:
            for controller, original in self.controllers:
                controller.audit_limit = original
            self._persist()

    async def _compare(self, config, samples):
        from engine import RateLimiter
        low = min(16, max(1, len(samples)//4))
        high = min(config['concurrency'],len(samples))
        if high <= low:
            low = max(1,high//2)
        passes = []
        with self.manager.lock:
            self.controllers = [(runtime['controller'],runtime['controller'].audit_limit) for runtime in self.manager.runners.values() if runtime.get('controller')]
            background = {job:dict(concurrency=runtime.get('controller').ceiling if runtime.get('controller') else None)
                          for job,runtime in self.manager.runners.items()}
        with self.lock:
            self.live.update(low_concurrency=low,high_concurrency=high,configured_concurrency=config['concurrency'],
                timeout=config['timeout'],attempts=config.get('attempts',1),rps=min(200,config.get('rps',100)),
                background_tasks=background,order=['low','high','high','low'],
                limitation='低负载轮短暂降低后台扫描并发，高负载轮恢复原并发；实际请求量取决于目标响应。此为混合抽样对照，非隔离压力实验，不能据此估算全网漏检率。')
        for mode in ['low','high','high','low']:
            with self.lock:
                self.live['phase'] = ('降低后台并发并等待在途探测结束' if mode=='low' else '恢复后台并发并等待负载建立')
            if self.stop.is_set():
                raise asyncio.CancelledError()
            for controller, original in self.controllers:
                controller.audit_limit = min(low,original) if mode=='low' and original is not None else low if mode=='low' else original
            # Drain in-flight work before measuring a low-load pass. Never discard checkpoints.
            deadline=time.monotonic()+60
            while mode=='low' and any(c.active>low for c,_ in self.controllers):
                if self.stop.is_set():
                    raise asyncio.CancelledError()
                if time.monotonic()>deadline:
                    raise RuntimeError('在途探测未及时降至低负载，对照停止并恢复原并发')
                await asyncio.sleep(.25)
            if mode=='high' and self.controllers:
                for _ in range(20):
                    if self.stop.is_set():
                        raise asyncio.CancelledError()
                    await asyncio.sleep(.25)
            concurrency = low if mode=='low' else high
            sem = asyncio.Semaphore(concurrency)
            limiter = RateLimiter(min(200,config.get('rps',100)),self.stop.is_set)
            counts=Counter();outcomes={}
            started=time.monotonic()
            with self.lock:
                self.live['phase'] = '低负载探测' if mode=='low' else '高负载探测'
            async def check(endpoint):
                async with sem:
                    if self.stop.is_set():
                        raise asyncio.CancelledError()
                    result=await probe(endpoint[0],endpoint[1],config['timeout'],asyncio.Semaphore(1),
                                       attempts=config.get('attempts',1),pace=limiter.wait,stopping=self.stop.is_set)
                    counts.update(classify(result))
                    outcomes[endpoint]=dict(hit=result['status']=='hit',dual=result.get('evidence')=='dual_verified')
                    with self.lock:
                        self.live['completed_checks']+=1
            await asyncio.gather(*(check(endpoint) for endpoint in samples))
            elapsed=round(time.monotonic()-started,3)
            summary=dict(mode=mode,concurrency=concurrency,elapsed=elapsed,counts=dict(counts),background=[dict(ceiling=c.ceiling,limit=min(c.limit,c.audit_limit) if c.audit_limit is not None else c.limit,inflight=c.active) for c,_ in self.controllers])
            passes.append(dict(summary,outcomes=outcomes))
            with self.lock:
                self.live['passes']=self.live['passes']+[summary]
            self._persist()
        comparison=compare_passes(samples,passes)
        with self.lock:
            self.live.update(status='completed',**comparison)
