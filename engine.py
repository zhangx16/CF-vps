"""Stable Manager facade for the standard-library scanner."""
import threading
from pathlib import Path
from probing import probe
from providers import normalize
from db import connect, open_db, prune_retention, initialize_schema
from jobs import JobsMixin
from scan import ScanMixin, RateLimiter, prepare, targets
from query import QueryMixin
from favorites import FavoritesMixin
from confirmed import ConfirmedMixin
from health import database_health, rss_bytes

ROOT = Path(__file__).resolve().parent
FIELDS = ['ip', 'port', 'job_id', 'task_name', 'provider_name', 'status', 'evidence', 'verification', 'server', 'cf_ray', 'colo', 'loc',
          'trace_ip', 'verified', 'request_ms', 'connect_ms', 'tls_ms', 'ttfb_ms', 'http_status',
          'verify_cf_ray', 'verify_colo', 'verify_error', 'error_kind', 'err', 'observed_at']


class Manager(JobsMixin, ScanMixin, QueryMixin, FavoritesMixin, ConfirmedMixin):
    def __init__(self, path):
        self.path = str(path)
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.Lock()
        self.source_lock = threading.Lock()
        self.source_cache = {}
        self.thread = None
        self.stop_event = threading.Event()
        self.active = None
        self.live = {}
        self.controller = None
        self.runners = {}
        from accuracy import AccuracyAudit
        self.accuracy = AccuracyAudit(self)
        text=(ROOT/'dmit_prefixes.txt').read_text()
        self.builtin_networks=set(normalize([line.split('#',1)[0].strip() for line in text.splitlines() if line.split('#',1)[0].strip()]))
        initialize_schema(self.path)
        prune_retention(self.path, time_budget=5)


    async def _probe(self, *args, **kwargs):
        # Preserve the public engine.probe integration and mock hook.
        return await probe(*args, **kwargs)

    def health(self):
        metrics = database_health(self.path)
        with self.lock:
            metrics['runners'] = [dict(id=ident, workers=runtime.get('workers', 0),
                                       **(runtime['controller'].snapshot() if runtime.get('controller') else {}))
                                  for ident, runtime in self.runners.items()]
        metrics['rss_bytes'] = rss_bytes()
        return metrics
