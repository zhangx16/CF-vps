"""Bounded scan scheduling and checkpoint commits."""
import asyncio
from collections import Counter
import ipaddress
import json
import math
from pathlib import Path
import time
from adaptive import AdaptiveLimiter
from db import connect, open_db
from diagnostics import classify

ROOT = Path(__file__).resolve().parent


def prepare(raw):
    if not isinstance(raw, dict):
        raise ValueError('配置必须是 JSON 对象')
    task_name = raw.get('task_name', '')
    if not isinstance(task_name,str) or len(task_name)>60 or any(ord(c)<32 or ord(c)==127 for c in task_name):
        raise ValueError('任务名称应为最多 60 个字符的单行文本')
    task_name=task_name.strip()
    text = raw.get('targets', '')
    if not isinstance(text, str) or len(text.encode()) > 65536:
        raise ValueError('目标输入过长')
    input_targets = text
    builtin = not text.strip()
    if builtin:
        text = (ROOT / 'dmit_prefixes.txt').read_text()
    nets = []
    for line in text.replace(',', '\n').splitlines():
        line = line.split('#', 1)[0].strip()
        if not line:
            continue
        net = ipaddress.ip_network(line, strict=False)
        if net.version != 4 or not net.is_global:
            raise ValueError(f'请输入公网 IPv4 或 CIDR：{line}')
        nets.append(net)
    nets = list(ipaddress.collapse_addresses(nets))
    if not nets:
        raise ValueError('没有有效目标')
    ports = sorted(set(int(p.strip()) for p in str(raw.get('ports', '443,8443')).split(',')))
    if not ports or len(ports) > 16 or any(not 1 <= p <= 65535 for p in ports):
        raise ValueError('端口必须在 1–65535，最多 16 个')
    concurrency = int(raw.get('concurrency', 100))
    timeout = float(raw.get('timeout', 4))
    attempts = int(raw.get('attempts', 2))
    rps = float(raw.get('rps', 100))
    adaptive = raw.get('adaptive', True)
    if not isinstance(adaptive,bool):
        raise ValueError('自适应并发必须是布尔值')
    minimum = max(1,min(int(raw.get('min_concurrency',10)),concurrency))
    if concurrency < 1 or not math.isfinite(timeout) or not 0.5 <= timeout <= 30 or not 1 <= attempts <= 3:
        raise ValueError('并发为正整数，超时 0.5–30 秒，尝试次数 1–3')
    if not math.isfinite(rps) or not 1 <= rps <= 2000:
        raise ValueError('每秒请求上限应在 1–2000')
    total = sum(n.num_addresses if n.prefixlen >= 31 else n.num_addresses - 2 for n in nets) * len(ports)
    if total > 2_000_000:
        raise ValueError('单次任务最多 200 万个 IP:端口，请拆分网段')
    return dict(networks=[str(n) for n in nets], ports=ports, concurrency=concurrency,
                timeout=timeout, attempts=attempts, rps=rps, total=total, kind='scan',task_name=task_name,input_targets=input_targets,adaptive=adaptive,min_concurrency=minimum,provider=raw.get('provider','dmit' if builtin else ''),provider_name=raw.get('provider_name','DMIT（内置快照）' if builtin else '自定义目标'),provider_asns=raw.get('provider_asns',[]),provider_updated_at=raw.get('provider_updated_at'),provider_country=raw.get('provider_country',''))


def targets(config):
    for cidr in config['networks']:
        for ip in ipaddress.ip_network(cidr).hosts():
            for port in config['ports']:
                yield str(ip), port


class RateLimiter:
    """One shared, evenly spaced gate for all SNI requests and retries."""
    def __init__(self, rps, stop):
        self.interval = 1 / rps
        self.next = 0
        self.lock = asyncio.Lock()
        self.stop = stop
        self.capacity = max(1, rps * .01)
        self.tokens = self.capacity
        self.updated = time.monotonic()

    async def wait(self):
        # A 10ms bucket avoids serial sub-millisecond timer rounding at high rates.
        async with self.lock:
            while True:
                if self.stop():
                    raise asyncio.CancelledError()
                now = time.monotonic()
                self.tokens = min(self.capacity, self.tokens + (now-self.updated)/self.interval)
                self.updated = now
                if self.tokens >= 1:
                    self.tokens -= 1
                    return
                await asyncio.sleep(min(.1, (1-self.tokens)*self.interval))


class ScanMixin:
    def _run(self, ident, config, done, hits):
        try:
            asyncio.run(self._scan(ident, config, done, hits))
        except Exception as exc:
            with connect(self.path) as db:
                db.execute("UPDATE jobs SET status='failed', error=?, updated=? WHERE id=?", (str(exc)[:1000], time.time(), ident))
        finally:
            with self.lock:
                self.runners.pop(ident, None)
                if self.active == ident:
                    self.active = next(iter(self.runners), None)


    async def _scan(self, ident, config, done, hits):
        runtime = self.runners[ident]
        stop_event = runtime['stop']
        db = open_db(self.path)
        initial_done = done
        started = time.monotonic()
        source_db = open_db(self.path) if config.get('kind') == 'retest' and 'selected' not in config else None
        if config.get('kind') == 'retest':
            iterator = iter(config['selected']) if 'selected' in config else ((r['ip'],r['port']) for r in source_db.execute("SELECT ip,port FROM results WHERE job=? AND status='hit' ORDER BY rowid", (config['source_id'],)))
        else:
            iterator = targets(config)
        # Compact integer keys avoid millions of Python tuples and IP strings.
        completed = {(int(ipaddress.IPv4Address(row[0])) << 16) | row[1]
                     for row in db.execute('SELECT ip,port FROM scan_progress WHERE job=?', (ident,))}
        worker_count = min(config['concurrency'], 256, max(0, config['total'] - initial_done))
        limiter = RateLimiter(config.get('rps',100), stop_event.is_set)
        pending = 0
        writes = []
        diagnostics = Counter()
        finished = asyncio.Event()
        controller = AdaptiveLimiter(config['concurrency'],config.get('min_concurrency',10),config.get('adaptive',True))
        await controller.update()
        with self.lock:
            runtime['controller'] = controller
            runtime['workers'] = worker_count

        def save():
            nonlocal pending
            if pending:
                for sql, values in writes:
                    db.execute(sql, values)
                for category, count in diagnostics.items():
                    db.execute('INSERT INTO job_diagnostics VALUES (?,?,?,?) ON CONFLICT(job,category) DO UPDATE SET count=count+excluded.count,updated=excluded.updated', (ident,category,count,time.time()))
                db.execute('UPDATE jobs SET done=?, hits=?, updated=? WHERE id=?', (done,hits,time.time(),ident))
                db.commit()
                writes.clear()
                diagnostics.clear()
                pending = 0

        async def commit_timer():
            while not finished.is_set():
                try:
                    await asyncio.wait_for(finished.wait(), .5)
                except asyncio.TimeoutError:
                    save()

        async def resource_monitor():
            while not finished.is_set():
                try:
                    await asyncio.wait_for(finished.wait(),5)
                except asyncio.TimeoutError:
                    await controller.update()

        async def worker():
            nonlocal done, hits, pending
            for ip, port in iterator:
                if stop_event.is_set():
                    return
                if (int(ipaddress.IPv4Address(ip)) << 16) | port in completed:
                    continue
                try:
                    async with controller.slot(stop_event.is_set):
                        result = await self._probe(ip, port, config['timeout'], None,
                                             attempts=config.get('attempts',1), pace=limiter.wait,
                                             stopping=stop_event.is_set)
                except asyncio.CancelledError:
                    if stop_event.is_set():
                        return  # Incomplete observations are deliberately not checkpointed.
                    raise
                observed = time.time()
                result['observed_at'] = observed
                latency = result.get('request_ms', result.get('latency_ms'))
                if latency == '':
                    latency = None
                writes.append(('INSERT INTO scan_progress VALUES (?,?,?,?)', (ident,ip,port,observed)))
                if result['status'] == 'hit':
                    writes.append(('INSERT INTO results(job,ip,port,status,verified,latency,data,evidence,colo,loc,observed,ip_num) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)',
                               (ident,ip,port,result['status'],result.get('verified',''),latency,json.dumps(result),
                                result.get('evidence','suspected'),result.get('colo',''),result.get('loc',''),observed,int(ipaddress.ip_address(ip)))))
                    writes.append(('INSERT INTO observations VALUES (?,?,?,?,?,?)',
                               (ident,ip,port,observed,int(result['status']=='hit'),int(result.get('evidence')=='dual_verified'))))
                done += 1
                hits += result['status'] == 'hit'
                pending += 1
                diagnostics.update(classify(result))
                elapsed = max(time.monotonic()-started,.001)
                rate = (done-initial_done)/elapsed
                with self.lock:
                    runtime['live'] = dict(done=done,hits=hits,rate=round(rate,2),eta=round((config['total']-done)/rate) if rate else None)
                if pending >= 50:
                    save()
        tasks = [asyncio.create_task(worker()) for _ in range(worker_count)]
        timer = asyncio.create_task(commit_timer())
        resource_task = asyncio.create_task(resource_monitor())
        try:
            await asyncio.gather(*tasks)
            save()
            status = 'completed' if done == config['total'] else 'stopped'
            db.execute('UPDATE jobs SET status=?,updated=? WHERE id=?', (status,time.time(),ident))
            db.commit()
            if status == 'completed':
                with connect(self.path) as progress_db:
                    progress_db.execute('DELETE FROM scan_progress WHERE job=?', (ident,))
                self.prune_completed_nonhits(ident)
        except BaseException:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            save()
            raise
        finally:
            finished.set()
            try:
                await asyncio.gather(timer,resource_task)
            finally:
                db.close()
                if source_db:
                    source_db.close()


