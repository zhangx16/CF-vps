"""Read-only SQLite and Linux process health metrics, without credentials."""
from contextlib import closing
from pathlib import Path
import sqlite3


def rss_bytes(pid='self'):
    try:
        for line in Path(f'/proc/{pid}/status').read_text().splitlines():
            if line.startswith('VmRSS:'):
                return int(line.split()[1]) * 1024
    except (OSError, ValueError):
        pass
    return None


def database_health(path):
    path = Path(path)
    with closing(sqlite3.connect(path.resolve().as_uri() + '?mode=ro', uri=True, timeout=15)) as db:
        page_count = db.execute('PRAGMA page_count').fetchone()[0]
        page_size = db.execute('PRAGMA page_size').fetchone()[0]
        free = db.execute('PRAGMA freelist_count').fetchone()[0]
        jobs = db.execute('SELECT COUNT(*) FROM jobs').fetchone()[0]
        hits = db.execute("SELECT COUNT(*) FROM results WHERE status='hit'").fetchone()[0]
        running = db.execute("SELECT COUNT(*) FROM jobs WHERE status IN ('running','stopping')").fetchone()[0]
    wal = Path(str(path) + '-wal')
    try:
        wal_bytes = wal.stat().st_size
    except FileNotFoundError:
        wal_bytes = 0
    return dict(db_bytes=path.stat().st_size, wal_bytes=wal_bytes, page_count=page_count,
                page_size=page_size, freelist_count=free, used_bytes=(page_count-free)*page_size,
                jobs=jobs, hits=hits, running_jobs=running)
