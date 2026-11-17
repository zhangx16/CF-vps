"""SQLite connections, backwards-compatible schema migration and retention."""
from contextlib import contextmanager
import fcntl
import ipaddress
import json
from pathlib import Path
import sqlite3
import time


class ConflictError(ValueError):
    """A requested task mutation conflicts with an active operation."""


class MaintenanceError(ValueError):
    """Offline compaction is in progress."""


@contextmanager
def available(path):
    """Keep a request from racing the offline compactor."""
    with (Path(path).parent / 'compact.lock').open('a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_SH | fcntl.LOCK_NB)
        except BlockingIOError:
            raise MaintenanceError('数据库正在 compact，请稍后重试')
        yield


def open_db(path):
    db = sqlite3.connect(path, timeout=15)
    db.row_factory = sqlite3.Row
    # Changing this on an existing incremental database takes a writer lock.
    # Only initialize empty files; legacy conversion belongs to offline compact.
    if db.execute('PRAGMA page_count').fetchone()[0] == 0:
        db.execute('PRAGMA auto_vacuum=INCREMENTAL')
    db.execute('PRAGMA cache_size=-8000')
    db.execute('PRAGMA temp_store=MEMORY')
    db.execute('PRAGMA busy_timeout=15000')
    db.execute('PRAGMA wal_autocheckpoint=1000')
    return db


@contextmanager
def connect(path, favorites=False):
    db = open_db(path)
    try:
        if favorites:
            columns=[r['name'] for r in db.execute('PRAGMA main.table_info(results)')]
            names=','.join(columns)
            db.execute(f'CREATE TEMP VIEW results AS SELECT rowid,{names} FROM main.results UNION ALL SELECT -saved_rowid AS rowid,{names} FROM main.favorite_snapshots')
        with db:
            yield db
    finally:
        db.close()


def prune_retention(path, now=None, time_budget=None):
    """Keep only hits younger than 24h, including all independent result copies."""
    deadline = None if time_budget is None else time.monotonic() + time_budget
    cutoff = (time.time() if now is None else now) - 86400
    with connect(path) as db:
        db.execute('PRAGMA secure_delete=ON')
        db.execute('CREATE TABLE IF NOT EXISTS scan_progress (job TEXT, ip TEXT, port INTEGER, observed REAL, PRIMARY KEY(job,ip,port))')
        # Migrate only recent unfinished checkpoints before deleting failure payloads.
        db.execute("INSERT OR IGNORE INTO scan_progress SELECT job,ip,port,observed FROM results WHERE observed>? AND job IN (SELECT id FROM jobs WHERE status!='completed')", (cutoff,))
        for table, condition, args in [
            ('results', "status IS NOT 'hit' OR COALESCE(observed,0)<=?", (cutoff,)),
            ('observations', 'hit IS NOT 1 OR COALESCE(observed,0)<=?', (cutoff,)),
            ('favorite_snapshots', "status IS NOT 'hit' OR COALESCE(observed,0)<=?", (cutoff,)),
            ('scan_progress', "COALESCE(observed,0)<=? OR job IN (SELECT id FROM jobs WHERE status='completed')", (cutoff,)),
        ]:
            while True:
                if deadline is not None and time.monotonic() >= deadline:
                    return
                changed = db.execute(f'DELETE FROM {table} WHERE rowid IN (SELECT rowid FROM {table} WHERE {condition} LIMIT 2000)', args).rowcount
                db.commit()
                if changed < 2000:
                    break
        db.execute('DELETE FROM confirmed_nodes WHERE NOT EXISTS (SELECT 1 FROM results r WHERE r.job=confirmed_nodes.job AND r.ip=confirmed_nodes.ip AND r.port=confirmed_nodes.port)')
        db.execute('DELETE FROM endpoint_favorites WHERE NOT EXISTS (SELECT 1 FROM results r WHERE r.ip=endpoint_favorites.ip AND r.port=endpoint_favorites.port) AND NOT EXISTS (SELECT 1 FROM favorite_snapshots s WHERE s.ip=endpoint_favorites.ip AND s.port=endpoint_favorites.port)')
        db.execute('DELETE FROM favorites')
        db.execute('DELETE FROM accuracy_reports WHERE created<=?',(cutoff,))


def initialize_schema(path):
    with connect(path) as db:
        db.execute('PRAGMA journal_mode=WAL')
        db.executescript('''
            CREATE TABLE IF NOT EXISTS job_diagnostics (job TEXT, category TEXT, count INTEGER NOT NULL, updated REAL, PRIMARY KEY(job,category));
            CREATE TABLE IF NOT EXISTS confirmed_nodes (job TEXT, ip TEXT, port INTEGER, created REAL, updated REAL, PRIMARY KEY(job,ip,port));
            CREATE TABLE IF NOT EXISTS favorites (ip TEXT PRIMARY KEY, created REAL);
            CREATE TABLE IF NOT EXISTS endpoint_favorites (ip TEXT, port INTEGER, created REAL, PRIMARY KEY(ip,port));
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
        db.execute('CREATE TABLE IF NOT EXISTS favorite_snapshots AS SELECT rowid AS saved_rowid,* FROM results WHERE 0')
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
            CREATE INDEX IF NOT EXISTS result_endpoint ON results(ip,port);
            CREATE INDEX IF NOT EXISTS result_global_status ON results(status,loc);
        ''')
        db.execute("UPDATE jobs SET status='interrupted', updated=? WHERE status IN ('running','stopping')", (time.time(),))
