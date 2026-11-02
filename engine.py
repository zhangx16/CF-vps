"""Persistent bounded-concurrency scanner and observation history."""
import asyncio
import base64
from contextlib import contextmanager
import ipaddress
import json
import math
import sqlite3
import threading
import time
import uuid
from pathlib import Path

from probing import probe
from adaptive import AdaptiveLimiter

ROOT = Path(__file__).resolve().parent
FIELDS = ['ip', 'port', 'status', 'evidence', 'verification', 'server', 'cf_ray', 'colo', 'loc',
          'trace_ip', 'verified', 'request_ms', 'connect_ms', 'tls_ms', 'ttfb_ms', 'http_status',
          'verify_cf_ray', 'verify_colo', 'verify_error', 'error_kind', 'err', 'observed_at']


def open_db(path):
    db = sqlite3.connect(path, timeout=15)
    db.row_factory = sqlite3.Row
    return db


@contextmanager
def connect(path):
    db = open_db(path)
    try:
        with db:
            yield db
    finally:
        db.close()


def prepare(raw):
    if not isinstance(raw, dict):
        raise ValueError('配置必须是 JSON 对象')
    text = raw.get('targets', '')
    if not isinstance(text, str) or len(text.encode()) > 65536:
        raise ValueError('目标输入过长')
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
    if not 1 <= concurrency <= 300 or not math.isfinite(timeout) or not 0.5 <= timeout <= 30 or not 1 <= attempts <= 3:
        raise ValueError('并发 1–300，超时 0.5–30 秒，尝试次数 1–3')
    if not math.isfinite(rps) or not 1 <= rps <= 1000:
        raise ValueError('每秒请求上限应在 1–1000')
    total = sum(n.num_addresses if n.prefixlen >= 31 else n.num_addresses - 2 for n in nets) * len(ports)
    if total > 2_000_000:
        raise ValueError('单次任务最多 200 万个 IP:端口，请拆分网段')
    return dict(networks=[str(n) for n in nets], ports=ports, concurrency=concurrency,
                timeout=timeout, attempts=attempts, rps=rps, total=total, kind='scan',adaptive=adaptive,min_concurrency=minimum,provider=raw.get('provider','dmit' if builtin else ''),provider_name=raw.get('provider_name','DMIT（内置快照）' if builtin else '自定义目标'),provider_asns=raw.get('provider_asns',[]),provider_updated_at=raw.get('provider_updated_at'))


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

    async def wait(self):
        async with self.lock:
            while time.monotonic() < self.next:
                if self.stop():
                    raise asyncio.CancelledError()
                await asyncio.sleep(min(.1, self.next - time.monotonic()))
            if self.stop():
                raise asyncio.CancelledError()
            self.next = time.monotonic() + self.interval


class Manager:
    def __init__(self, path):
        self.path = str(path)
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.Lock()
        self.thread = None
        self.stop_event = threading.Event()
        self.active = None
        self.live = {}
        self.controller = None
        with connect(self.path) as db:
            db.execute('PRAGMA journal_mode=WAL')
            db.executescript('''
                CREATE TABLE IF NOT EXISTS jobs (
                  id TEXT PRIMARY KEY, created REAL, updated REAL, status TEXT,
                  config TEXT, total INTEGER, done INTEGER DEFAULT 0,
                  hits INTEGER DEFAULT 0, error TEXT DEFAULT '');
                CREATE TABLE IF NOT EXISTS results (
                  job TEXT, ip TEXT, port INTEGER, status TEXT, verified TEXT,
                  latency REAL, data TEXT, PRIMARY KEY(job,ip,port));
                CREATE INDEX IF NOT EXISTS result_status ON results(job,status,verified);
                CREATE TABLE IF NOT EXISTS observations (
                  job TEXT, ip TEXT, port INTEGER, observed REAL, hit INTEGER, confirmed INTEGER,
                  PRIMARY KEY(job,ip,port));
                CREATE INDEX IF NOT EXISTS observation_endpoint ON observations(ip,port,observed);
            ''')
            columns = {r['name'] for r in db.execute('PRAGMA table_info(results)')}
            for name, kind in [('evidence','TEXT'), ('colo','TEXT'), ('loc','TEXT'), ('observed','REAL'), ('ip_num','INTEGER')]:
                if name not in columns:
                    db.execute(f'ALTER TABLE results ADD COLUMN {name} {kind}')
            # Old results keep their original meaning; do not relabel them as strict verification.
            reader = db.execute('SELECT rowid,ip,data FROM results WHERE evidence IS NULL')
            while True:
                rows = reader.fetchmany(500)
                if not rows:
                    break
                for row in rows:
                    data = json.loads(row['data'])
                    data['evidence'] = 'legacy'
                    db.execute('UPDATE results SET evidence=?,colo=?,loc=?,observed=0,ip_num=?,data=? WHERE rowid=?',
                               ('legacy', data.get('colo',''), data.get('loc',''), int(ipaddress.ip_address(row['ip'])), json.dumps(data), row['rowid']))
            db.executescript('''
                CREATE INDEX IF NOT EXISTS result_region ON results(job,loc);
                CREATE INDEX IF NOT EXISTS result_latency ON results(job,latency);
                CREATE INDEX IF NOT EXISTS result_job ON results(job);
            ''')
            db.execute("UPDATE jobs SET status='interrupted', updated=? WHERE status IN ('running','stopping')", (time.time(),))

    def jobs(self):
        with connect(self.path) as db:
            rows = [dict(r) for r in db.execute('SELECT * FROM jobs ORDER BY created DESC LIMIT 100')]
        with self.lock:
            for row in rows:
                row['config'] = json.loads(row['config'])
                if row['id'] == self.active:
                    row.update(self.live)
                    if self.controller:
                        row.update(self.controller.snapshot())
                    if self.stop_event.is_set():
                        row['status'] = 'stopping'
        return rows

    def start(self, raw=None, resume=None, retest=None):
        with self.lock:
            if self.thread and self.thread.is_alive():
                raise ValueError('已有任务正在运行，请先停止')
            now = time.time()
            with connect(self.path) as db:
                if resume:
                    row = db.execute('SELECT * FROM jobs WHERE id=?', (resume,)).fetchone()
                    if row is None or row['status'] == 'completed':
                        raise ValueError('任务不存在或已完成')
                    ident, config = resume, json.loads(row['config'])
                    done, hits = db.execute("SELECT COUNT(*), COALESCE(SUM(status='hit'),0) FROM results WHERE job=?", (ident,)).fetchone()
                    db.execute("UPDATE jobs SET status='running', error='', done=?, hits=?, updated=? WHERE id=?", (done, hits, now, ident))
                else:
                    if retest:
                        parent = db.execute('SELECT config FROM jobs WHERE id=?', (retest,)).fetchone()
                        if not parent:
                            raise ValueError('原任务不存在')
                        config = json.loads(parent['config'])
                        config.update(kind='retest', source_id=retest)
                        config.pop('selected', None)
                        selected = (raw or {}).get('selected')
                        if selected is not None:
                            if not isinstance(selected, list) or not 1 <= len(selected) <= 200:
                                raise ValueError('一次最多选择 200 个结果')
                            checked = []
                            for item in selected:
                                if not isinstance(item, dict):
                                    raise ValueError('复测目标格式错误')
                                ip, port = str(item.get('ip')), int(item.get('port',0))
                                if not db.execute('SELECT 1 FROM results WHERE job=? AND ip=? AND port=?', (retest,ip,port)).fetchone():
                                    raise ValueError('复测目标不在原任务中')
                                if [ip,port] not in checked:
                                    checked.append([ip,port])
                            config['selected'] = checked
                            config['total'] = len(checked)
                        else:
                            config['total'] = db.execute("SELECT COUNT(*) FROM results WHERE job=? AND status='hit'", (retest,)).fetchone()[0]
                        if not config['total']:
                            raise ValueError('没有可复测的目标')
                    else:
                        config = prepare(raw)
                    ident = uuid.uuid4().hex
                    done = hits = 0
                    db.execute('INSERT INTO jobs(id,created,updated,status,config,total) VALUES (?,?,?,?,?,?)',
                               (ident, now, now, 'running', json.dumps(config), config['total']))
            self.stop_event.clear()
            self.active = ident
            self.live = dict(done=done, hits=hits, rate=0, eta=None)
            self.thread = threading.Thread(target=self._run, args=(ident, config, done, hits), daemon=True)
            self.thread.start()
            return ident

    def stop(self):
        with self.lock:
            if self.thread and self.thread.is_alive():
                self.stop_event.set()

    def _run(self, ident, config, done, hits):
        try:
            asyncio.run(self._scan(ident, config, done, hits))
        except Exception as exc:
            with connect(self.path) as db:
                db.execute("UPDATE jobs SET status='failed', error=?, updated=? WHERE id=?", (str(exc)[:1000], time.time(), ident))
        finally:
            with self.lock:
                self.active = None
                self.live = {}
                self.controller = None

    async def _scan(self, ident, config, done, hits):
        db = open_db(self.path)
        initial_done = done
        started = time.monotonic()
        if config.get('kind') == 'retest':
            iterator = iter(config['selected']) if 'selected' in config else ((r['ip'],r['port']) for r in db.execute("SELECT ip,port FROM results WHERE job=? AND status='hit' ORDER BY rowid", (config['source_id'],)))
        else:
            iterator = targets(config)
        sem = asyncio.Semaphore(config['concurrency'])
        limiter = RateLimiter(config.get('rps',100), self.stop_event.is_set)
        pending = 0
        finished = asyncio.Event()
        controller = AdaptiveLimiter(config['concurrency'],config.get('min_concurrency',10),config.get('adaptive',True))
        await controller.update()
        with self.lock:
            self.controller = controller

        def save():
            nonlocal pending
            if pending:
                db.execute('UPDATE jobs SET done=?, hits=?, updated=? WHERE id=?', (done,hits,time.time(),ident))
                db.commit()
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
                if self.stop_event.is_set():
                    return
                if db.execute('SELECT 1 FROM results WHERE job=? AND ip=? AND port=?', (ident,ip,port)).fetchone():
                    continue
                try:
                    async with controller.slot(self.stop_event.is_set):
                        result = await probe(ip, port, config['timeout'], sem,
                                             attempts=config.get('attempts',1), pace=limiter.wait,
                                             stopping=self.stop_event.is_set)
                except asyncio.CancelledError:
                    if self.stop_event.is_set():
                        return  # Incomplete observations are deliberately not checkpointed.
                    raise
                observed = time.time()
                result['observed_at'] = observed
                latency = result.get('request_ms', result.get('latency_ms'))
                if latency == '':
                    latency = None
                db.execute('INSERT INTO results(job,ip,port,status,verified,latency,data,evidence,colo,loc,observed,ip_num) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)',
                           (ident,ip,port,result['status'],result.get('verified',''),latency,json.dumps(result),
                            result.get('evidence','suspected'),result.get('colo',''),result.get('loc',''),observed,int(ipaddress.ip_address(ip))))
                db.execute('INSERT INTO observations VALUES (?,?,?,?,?,?)',
                           (ident,ip,port,observed,int(result['status']=='hit'),int(result.get('evidence')=='dual_verified')))
                done += 1
                hits += result['status'] == 'hit'
                pending += 1
                elapsed = max(time.monotonic()-started,.001)
                rate = (done-initial_done)/elapsed
                with self.lock:
                    self.live = dict(done=done,hits=hits,rate=round(rate,2),eta=round((config['total']-done)/rate) if rate else None)
                if pending >= 50:
                    save()
        tasks = [asyncio.create_task(worker()) for _ in range(config['concurrency'])]
        timer = asyncio.create_task(commit_timer())
        resource_task = asyncio.create_task(resource_monitor())
        try:
            await asyncio.gather(*tasks)
            save()
            status = 'completed' if done == config['total'] else 'stopped'
            db.execute('UPDATE jobs SET status=?,updated=? WHERE id=?', (status,time.time(),ident))
            db.commit()
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

    @staticmethod
    def condition(ident, view='hits', region='', colo='', search=''):
        parts, args = ['job=?'], [ident]
        if view == 'hits':
            parts.append("status='hit'")
        elif view == 'verified':
            parts.append("evidence='dual_verified'")
        elif view in ('suspected','trace_valid','legacy'):
            parts.append('evidence=?'); args.append(view)
        elif view != 'all':
            raise ValueError('结果筛选无效')
        if region:
            parts.append("COALESCE(NULLIF(loc,''),'UNKNOWN')=?"); args.append(region)
        if colo:
            parts.append('colo=?'); args.append(colo)
        if search:
            parts.append("(ip LIKE ? ESCAPE '\\' OR CAST(port AS TEXT)=?)")
            args.extend([search.replace('\\','\\\\').replace('%','\\%').replace('_','\\_')+'%',search])
        return ' AND '.join(parts), args

    def facets(self, ident, view='hits'):
        condition, args = self.condition(ident,view)
        with connect(self.path) as db:
            regions = [dict(r) for r in db.execute(f"SELECT COALESCE(NULLIF(loc,''),'UNKNOWN') AS value,COUNT(*) AS count FROM results WHERE {condition} GROUP BY value ORDER BY count DESC",args)]
            colos = [dict(r) for r in db.execute(f"SELECT colo AS value,COUNT(*) AS count FROM results WHERE {condition} AND colo!='' GROUP BY colo ORDER BY count DESC",args)]
        return dict(regions=regions,colos=colos)

    def results(self, ident, view='hits', page=1, limit=100, region='', colo='', search='', sort='newest', cursor=''):
        page = max(1,min(int(page),100000))
        limit = max(1,min(int(limit),200))
        choices = {'newest':('rowid','DESC'),'latency_asc':('COALESCE(latency,1e30)','ASC'),
                   'latency_desc':('COALESCE(latency,-1)','DESC'),'ip':('ip_num','ASC'),
                   'region':("COALESCE(loc,'')",'ASC'),'colo':("COALESCE(colo,'')",'ASC')}
        if sort not in choices:
            raise ValueError('排序无效')
        key, direction = choices[sort]
        condition, args = self.condition(ident,view,region,colo,search)
        with connect(self.path) as db:
            total = db.execute(f'SELECT COUNT(*) FROM results WHERE {condition}',args).fetchone()[0]
            where, values = condition, list(args)
            if cursor:
                try:
                    if len(cursor)>1000:
                        raise ValueError()
                    token = json.loads(base64.urlsafe_b64decode(cursor))
                    if token['sort'] != sort or not isinstance(token['rowid'],int) or not isinstance(token['value'],(int,float,str)):
                        raise ValueError()
                except (ValueError,KeyError,TypeError,UnicodeError):
                    raise ValueError('分页游标无效')
                op = '<' if direction == 'DESC' else '>'
                where += f' AND ({key}{op}? OR ({key}=? AND rowid<?))'
                values.extend([token['value'],token['value'],token['rowid']])
            rows = db.execute(f'SELECT rowid,{key} AS sortkey,data FROM results WHERE {where} ORDER BY {key} {direction},rowid DESC LIMIT ?',values+[limit+1]).fetchall()
            more = len(rows)>limit
            rows = rows[:limit]
            items = []
            for row in rows:
                data = json.loads(row['data'])
                history = db.execute('SELECT MIN(CASE WHEN hit=1 THEN observed END) AS first_seen,MAX(CASE WHEN confirmed=1 THEN observed END) AS last_confirmed,COUNT(*) AS checks,COALESCE(SUM(hit),0) AS successes,COALESCE(SUM(confirmed),0) AS confirmations FROM observations WHERE ip=? AND port=?',(data['ip'],data['port'])).fetchone()
                data['history'] = dict(history)
                items.append(data)
            next_cursor = ''
            if more:
                last = rows[-1]
                next_cursor = base64.urlsafe_b64encode(json.dumps(dict(sort=sort,value=last['sortkey'],rowid=last['rowid'])).encode()).decode()
            return dict(total=total,page=page,items=items,next_cursor=next_cursor)

    def delete(self, ident):
        with self.lock:
            if self.thread and self.thread.is_alive():
                with connect(self.path) as db:
                    row = db.execute('SELECT config FROM jobs WHERE id=?',(self.active,)).fetchone()
                    if ident == self.active or row and json.loads(row['config']).get('source_id') == ident:
                        raise ValueError('请先停止相关任务')
            with connect(self.path) as db:
                db.execute('DELETE FROM observations WHERE job=?',(ident,))
                db.execute('DELETE FROM results WHERE job=?',(ident,))
                db.execute('DELETE FROM jobs WHERE id=?',(ident,))

    def compare(self, old, new, kind='new'):
        if old == new:
            raise ValueError('请选择两个不同任务')
        queries = {'new':(new,old,False),'lost':(old,new,False),'persistent':(new,old,True)}
        if kind not in queries:
            raise ValueError('对比类型无效')
        with connect(self.path) as db:
            if db.execute('SELECT COUNT(*) FROM jobs WHERE id IN (?,?)',(old,new)).fetchone()[0]!=2:
                raise ValueError('任务不存在')
            counts = {}
            for name,(a,b,present) in queries.items():
                exists = 'EXISTS' if present else 'NOT EXISTS'
                query = f"FROM results a WHERE a.job=? AND a.status='hit' AND {exists}(SELECT 1 FROM results b WHERE b.job=? AND b.ip=a.ip AND b.port=a.port AND b.status='hit')"
                counts[name] = db.execute('SELECT COUNT(*) '+query,(a,b)).fetchone()[0]
                if name == kind:
                    items = [json.loads(r[0]) for r in db.execute('SELECT a.data '+query+' ORDER BY a.ip_num,a.port LIMIT 200',(a,b))]
            statuses = [r['status'] for r in db.execute('SELECT status FROM jobs WHERE id IN (?,?)',(old,new))]
            return dict(counts=counts,items=items,kind=kind,provisional=any(s!='completed' for s in statuses))
