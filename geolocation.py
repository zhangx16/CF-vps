"""Bounded, cached country enrichment for candidate IPs, never proxy credentials."""
from collections import deque
import csv
import io
import ipaddress
import json
import re
import threading
import time
import urllib.error
import urllib.request

from engine import connect
from providers import fetch_geofeed

FEEDS = {
    'gomami_hk': ('https://gomami.io/geofeed.txt', 'GoMami 官方 Geofeed'),
    'vmiss_us': ('https://geofeed.cogentco.com/geofeed.csv', 'Cogent 上游 Geofeed'),
    'isif_hk': ('https://isif.net/geofeed.csv', 'ISIF 官方 Geofeed'),
}
GEOIP_DAILY_LIMIT = 900  # Leave headroom below the public endpoint's quota.
CACHE_SECONDS = 30 * 86400
ERROR_SECONDS = 6 * 3600


def parse_geofeed(text):
    records = []
    for row in csv.reader(io.StringIO(text)):
        if len(row) < 2 or row[0].lstrip().startswith('#'):
            continue
        try:
            net = ipaddress.ip_network(row[0].strip(), strict=False)
        except ValueError:
            continue
        country = row[1].strip().upper()
        if country == 'CN' and len(row) > 2 and row[2].strip().upper() == 'CN-HK':
            country = 'HK'
        if net.version == 4 and net.is_global and re.fullmatch('[A-Z]{2}', country):
            records.append((int(net.network_address), int(net.broadcast_address), net.prefixlen, country))
    if not records:
        raise ValueError('Geofeed 没有有效的地区记录')
    return records


def feed_country(ip, records):
    value = int(ipaddress.ip_address(ip))
    matches = [(bits, country) for low, high, bits, country in records if low <= value <= high]
    if not matches:
        return ''
    longest = max(bits for bits, _ in matches)
    countries = {country for bits, country in matches if bits == longest}
    return next(iter(countries)) if len(countries) == 1 else 'UNKNOWN'


def lookup_geoip(ip):
    request = urllib.request.Request('https://ipwho.is/' + ip + '?fields=success,ip,country_code,message',
                                     headers={'User-Agent': 'CFVPS-Geolocation/1.0'})
    with urllib.request.urlopen(request, timeout=8) as response:
        body = response.read(65537)
    if len(body) > 65536:
        raise ValueError('GeoIP 响应过大')
    data = json.loads(body)
    country = data.get('country_code', '')
    if data.get('success') is not True or data.get('ip') != ip or not isinstance(country, str) or not re.fullmatch('[A-Z]{2}', country):
        raise ValueError('GeoIP 未返回有效的 IP 地区')
    return country


class GeoLocator:
    def __init__(self, manager):
        self.manager = manager
        self.path = manager.path
        self.lock = threading.Lock()
        self.queue = deque()
        self.pending = set()
        self.worker = None
        self.completed = 0
        self.error = ''
        self.feeds = {}
        self.next_query = 0
        self.cooldown = 0
        self.stopping = threading.Event()

    def status(self):
        with self.lock:
            pending, completed, error = len(self.pending), self.completed, self.error
        with connect(self.path) as db:
            row = db.execute('SELECT requests FROM geo_usage WHERE day=?', (time.strftime('%Y-%m-%d', time.gmtime()),)).fetchone()
        return dict(pending=pending, completed=completed, error=error,
                    geoip_remaining=max(0, GEOIP_DAILY_LIMIT - (row['requests'] if row else 0)))

    def enqueue(self, ips):
        if not isinstance(ips, list) or len(ips) > 200:
            raise ValueError('每次最多提交 200 个候选 IP')
        validated = []
        for value in ips:
            try:
                address = ipaddress.ip_address(value)
            except (ValueError, TypeError):
                raise ValueError('候选 IP 无效')
            if address.version != 4 or not address.is_global:
                raise ValueError('只支持已有结果中的公网 IPv4')
            validated.append(str(address))
        sources = self.manager.job_sources()
        work = []
        with connect(self.path) as db:
            for ip in dict.fromkeys(validated):
                cached = db.execute('SELECT expires FROM geo_cache WHERE ip=?', (ip,)).fetchone()
                if cached and cached['expires'] > time.time():
                    continue
                row = db.execute('SELECT job FROM results WHERE ip=? ORDER BY rowid DESC LIMIT 1', (ip,)).fetchone()
                if not row:
                    row = db.execute('SELECT job FROM favorite_snapshots WHERE ip=? LIMIT 1', (ip,)).fetchone()
                if not row:
                    raise ValueError('IP 不在已保存的探测结果中')
                work.append((ip, sources.get(row['job'], {}).get('provider', '')))
        with self.lock:
            for ip, provider in work:
                if ip not in self.pending and len(self.pending) < 1000:
                    self.pending.add(ip)
                    self.queue.append((ip, provider))
            if self.queue and self.worker is None:
                self.worker = threading.Thread(target=self._work, name='ip-country-enrichment', daemon=True)
                self.worker.start()
        return self.status()

    def _feed(self, provider):
        if provider not in FEEDS:
            return [], ''
        url, label = FEEDS[provider]
        if url in self.feeds and time.time()-self.feeds[url][0]<86400:
            return self.feeds[url][1:]
        with connect(self.path) as db:
            saved = db.execute('SELECT data,updated FROM geo_feeds WHERE url=?', (url,)).fetchone()
        records = json.loads(saved['data']) if saved else []
        if not saved or time.time() - saved['updated'] > 86400:
            try:
                records = parse_geofeed(fetch_geofeed(url))
                with connect(self.path) as db:
                    db.execute('INSERT OR REPLACE INTO geo_feeds VALUES (?,?,?)', (url, json.dumps(records), time.time()))
            except Exception:
                # Last-good records may be shown, explicitly marked as cached.
                label += '（缓存）' if records else '（不可用）'
        self.feeds[url] = (time.time(), records, label)
        return records, label

    def _lookup(self, ip, provider):
        records, source = self._feed(provider)
        country = feed_country(ip, records)
        if country:
            return country, source, ''
        if time.time() < self.cooldown:
            raise ValueError('GeoIP 服务限流，稍后自动重试')
        day = time.strftime('%Y-%m-%d', time.gmtime())
        with connect(self.path) as db:
            db.execute('INSERT OR IGNORE INTO geo_usage VALUES (?,0)', (day,))
            used = db.execute('SELECT requests FROM geo_usage WHERE day=?', (day,)).fetchone()['requests']
            if used >= GEOIP_DAILY_LIMIT:
                raise ValueError('今日 GeoIP 查询额度已用完，仍可多模板导出测试')
            db.execute('UPDATE geo_usage SET requests=requests+1 WHERE day=?', (day,))
        self.stopping.wait(max(0, self.next_query - time.monotonic()))
        self.next_query = time.monotonic() + 1.2
        try:
            return lookup_geoip(ip), 'ipwho.is GeoIP（估算）', ''
        except urllib.error.HTTPError as exc:
            if exc.code == 429:
                self.cooldown = time.time() + 3600
                raise ValueError('GeoIP 服务限流，稍后自动重试') from exc
            raise ValueError('GeoIP 服务暂时不可用') from exc

    def _work(self):
        while not self.stopping.is_set():
            with self.lock:
                if not self.queue:
                    self.worker = None
                    return
                ip, provider = self.queue.popleft()
            country, source, error = 'UNKNOWN', '', ''
            try:
                country, source, error = self._lookup(ip, provider)
            except Exception as exc:
                error = str(exc)[:180]
            try:
                now = time.time()
                with connect(self.path) as db:
                    db.execute('INSERT OR REPLACE INTO geo_cache VALUES (?,?,?,?,?,?)',
                               (ip, country, source, now, now + (ERROR_SECONDS if error else CACHE_SECONDS), error))
                with self.lock:
                    self.completed += 1
                    self.error = error
            except Exception:
                with self.lock:
                    self.error = '地区缓存写入失败，请稍后重试'
            finally:
                with self.lock:
                    self.pending.discard(ip)
