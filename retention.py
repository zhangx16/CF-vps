"""Periodic bounded retention and idle incremental page reclamation."""
import fcntl
import os
from pathlib import Path
from db import connect, prune_retention


def maintain(path):
    path = Path(path)
    with (path.parent / 'maintenance.lock').open('a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return
        prune_retention(path, time_budget=5)
        with connect(path) as db:
            # Reserve the writer lock so a task cannot start during reclamation.
            db.execute('BEGIN IMMEDIATE')
            if db.execute("SELECT 1 FROM jobs WHERE status IN ('running','stopping') LIMIT 1").fetchone():
                return
            free = db.execute('PRAGMA freelist_count').fetchone()[0]
            if free > 10000:
                (path.parent / 'vacuum.needed').touch(mode=0o600)
            if free > 1000 and db.execute('PRAGMA auto_vacuum').fetchone()[0] == 2:
                # Some SQLite builds reclaim only one page per invocation.
                for _ in range(min(2000, free)):
                    db.execute('PRAGMA incremental_vacuum(1)').fetchall()


if __name__ == '__main__':
    maintain(Path(os.environ.get('CFVPS_DATA', '/var/lib/cf-vps')) / 'scan.db')
