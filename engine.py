"""Persistent bounded-concurrency scanner; only Python standard library."""
import asyncio
import ipaddress
import json
import math
import sqlite3
import threading
import time
import uuid
from pathlib import Path

from scan_dmit_cf_fallback import probe

ROOT = Path(__file__).resolve().parent
FIELDS = ['ip', 'port', 'status', 'server', 'cf_ray', 'colo', 'loc', 'verified',
          'latency_ms', 'verify_cf_ray', 'verify_colo', 'err']


def connect(path):
    db = sqlite3.connect(path, timeout=15)
    db.row_factory = sqlite3.Row
    return db


def prepare(raw):
    if not isinstance(raw, dict):
        raise ValueError('配置必须是 JSON 对象')
    text = raw.get('targets', '')
    if not isinstance(text, str) or len(text) > 65536:
        raise ValueError('目标输入过长')
    if not text.strip():
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
    attempts = int(raw.get('attempts', 1))
    if not 1 <= concurrency <= 300 or not math.isfinite(timeout) or not 0.5 <= timeout <= 30 or not 1 <= attempts <= 3:
        raise ValueError('并发 1–300，超时 0.5–30 秒，尝试次数 1–3')
    total = sum(n.num_addresses if n.prefixlen >= 31 else n.num_addresses - 2 for n in nets) * len(ports)
    if total > 2_000_000:
        raise ValueError('单次任务最多 200 万个 IP:端口，请拆分网段')
    return dict(networks=[str(n) for n in nets], ports=ports, concurrency=concurrency,
                timeout=timeout, attempts=attempts, total=total)


def targets(config):
    for cidr in config['networks']:
        for ip in ipaddress.ip_network(cidr).hosts():
            for port in config['ports']:
                yield str(ip), port


class Manager:
    def __init__(self, path):
        self.path = str(path)
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.Lock()
        self.thread = None
        self.stop_event = threading.Event()
        self.active = None
        self.live = {}
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
                    if self.stop_event.is_set():
                        row['status'] = 'stopping'
        return rows

    def start(self, raw=None, resume=None):
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

    async def _scan(self, ident, config, done, hits):
        db = connect(self.path)
        initial_done = done
        started = last_save = time.monotonic()
        iterator = targets(config)
        sem = asyncio.Semaphore(config['concurrency'])

        def save():
            nonlocal last_save
            db.execute('UPDATE jobs SET done=?, hits=?, updated=? WHERE id=?', (done, hits, time.time(), ident))
            db.commit()
            last_save = time.monotonic()

        async def worker():
            nonlocal done, hits
            for ip, port in iterator:
                if self.stop_event.is_set():
                    return
                if db.execute('SELECT 1 FROM results WHERE job=? AND ip=? AND port=?', (ident, ip, port)).fetchone():
                    continue
                result = None
                for _ in range(config['attempts']):
                    result = await probe(ip, port, config['timeout'], sem)
                    if result['status'] != 'closed_or_error' or self.stop_event.is_set():
                        break
                db.execute('INSERT INTO results VALUES (?,?,?,?,?,?,?)',
                           (ident, ip, port, result['status'], result.get('verified', ''),
                            result.get('latency_ms') or None, json.dumps(result)))
                done += 1
                hits += result['status'] == 'hit'
                elapsed = max(time.monotonic() - started, 0.001)
                rate = (done - initial_done) / elapsed
                with self.lock:
                    self.live = dict(done=done, hits=hits, rate=round(rate, 2),
                                     eta=round((config['total'] - done) / rate) if rate else None)
                if time.monotonic() - last_save >= 0.5 or done % 50 == 0:
                    save()
        tasks = [asyncio.create_task(worker()) for _ in range(config['concurrency'])]
        try:
            await asyncio.gather(*tasks)
            save()
            status = 'completed' if done == config['total'] else 'stopped'
            db.execute('UPDATE jobs SET status=?, updated=? WHERE id=?', (status, time.time(), ident))
            db.commit()
        except BaseException:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            save()
            raise
        finally:
            db.close()

    def results(self, ident, view='hits', page=1, limit=100):
        page = max(1, min(int(page), 100000))
        limit = max(1, min(int(limit), 200))
        condition = 'job=?'
        if view == 'hits':
            condition += " AND status='hit'"
        elif view == 'verified':
            condition += " AND status='hit' AND verified='1'"
        with connect(self.path) as db:
            count = db.execute(f'SELECT COUNT(*) FROM results WHERE {condition}', (ident,)).fetchone()[0]
            rows = db.execute(f'SELECT data FROM results WHERE {condition} ORDER BY rowid DESC LIMIT ? OFFSET ?', (ident, limit, (page - 1) * limit))
            return dict(total=count, page=page, items=[json.loads(r[0]) for r in rows])
