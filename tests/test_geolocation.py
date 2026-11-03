import json
import io
import tempfile
import time
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch

from engine import Manager, connect
from geolocation import GeoLocator, parse_geofeed, feed_country, lookup_geoip, GEOIP_DAILY_LIMIT


class CountryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.manager = Manager(Path(self.tmp.name)/'scan.db')
        self.geo = GeoLocator(self.manager)
        self.add('a','8.8.8.8',443,12)
        self.add('a','1.1.1.1',8443,8)

    def tearDown(self):
        self.geo.stopping.set()
        if self.geo.worker:
            self.geo.worker.join(5)
        self.tmp.cleanup()

    def add(self, job, ip, port, latency):
        import ipaddress
        with connect(self.manager.path) as db:
            db.execute('INSERT OR IGNORE INTO jobs VALUES (?,?,?,?,?,?,?,?,?)',
                       (job,1,1,'completed',json.dumps(dict(provider='dmit',provider_name='DMIT')),2,2,2,''))
            data=dict(ip=ip,port=port,status='hit',verified='1',latency_ms=latency,loc='CA')
            db.execute('INSERT INTO results(job,ip,port,status,verified,latency,data,evidence,loc,ip_num,colo) VALUES (?,?,?,?,?,?,?,?,?,?,?)',
                       (job,ip,port,'hit','1',latency,json.dumps(data),'dual_verified','CA',int(ipaddress.ip_address(ip)),''))

    def test_longest_feed_conflicts_and_invalid_data(self):
        records=parse_geofeed('8.8.8.0/24,US,,,\n8.8.8.0/25,HK,,,\n')
        self.assertEqual(feed_country('8.8.8.8',records),'HK')
        self.assertEqual(feed_country('8.8.8.200',records),'US')
        self.assertEqual(feed_country('1.1.1.1',records),'')
        records+=parse_geofeed('8.8.8.0/25,JP,,,\n')
        self.assertEqual(feed_country('8.8.8.8',records),'UNKNOWN')
        self.assertEqual(feed_country('8.8.8.8',parse_geofeed('8.8.8.0/24,CN,CN-HK,,\n')),'HK')
        with self.assertRaises(ValueError):parse_geofeed('<html>not csv</html>')

    def test_official_feed_before_geoip_and_persistent_feed_cache(self):
        with patch('geolocation.fetch_geofeed',return_value='8.8.8.0/24,HK,,,\n') as fetch,patch('geolocation.lookup_geoip') as lookup:
            self.assertEqual(self.geo._lookup('8.8.8.8','gomami_hk')[:2],('HK','GoMami 官方 Geofeed'))
            lookup.assert_not_called()
            fresh=GeoLocator(self.manager)
            self.assertEqual(fresh._lookup('8.8.8.8','gomami_hk')[0],'HK')
            fetch.assert_called_once()

    def test_stale_feed_failure_keeps_last_good_with_source_label(self):
        from geolocation import FEEDS
        records=parse_geofeed('8.8.8.0/24,HK,,,\n')
        with connect(self.manager.path) as db:
            db.execute('INSERT INTO geo_feeds VALUES (?,?,?)',(FEEDS['gomami_hk'][0],json.dumps(records),time.time()-90000))
        with patch('geolocation.fetch_geofeed',side_effect=ValueError('offline')),patch('geolocation.lookup_geoip') as lookup:
            first=self.geo._lookup('8.8.8.8','gomami_hk')
            second=self.geo._lookup('8.8.8.8','gomami_hk')
            self.assertEqual(first[0],'HK')
            self.assertIn('缓存',first[1])
            self.assertEqual(first,second)
            lookup.assert_not_called()

    def test_fallback_cache_dedup_and_saved_results_only(self):
        with patch('geolocation.lookup_geoip',return_value='US') as lookup:
            self.geo.enqueue(['8.8.8.8','8.8.8.8'])
            worker=self.geo.worker
            if worker:worker.join(5)
            self.geo.enqueue(['8.8.8.8'])
            lookup.assert_called_once_with('8.8.8.8')
        row=self.manager.results('a','all',search='8.8.8.8')['items'][0]
        self.assertEqual(row['ip_country'],'US')
        self.assertEqual(row['loc'],'CA')  # Never replace trace origin with candidate country.
        self.assertIn('估算',row['ip_country_source'])
        self.assertFalse(row['ip_country_retry'])
        self.assertEqual(GeoLocator(self.manager).status()['geoip_remaining'],GEOIP_DAILY_LIMIT-1)
        for values in [['127.0.0.1'],['9.9.9.9'],['bad'],None,['8.8.8.8']*201]:
            with self.assertRaises(ValueError):self.geo.enqueue(values)

    def test_filter_facets_sort_favorites_and_unknown(self):
        with connect(self.manager.path) as db:
            db.execute('INSERT INTO geo_cache VALUES (?,?,?,?,?,?)',('8.8.8.8','US','fixture',2,time.time()+10,''))
        self.assertEqual(self.manager.results('*','all',ip_country='US')['items'][0]['ip'],'8.8.8.8')
        self.assertEqual(self.manager.results('*','all',ip_country='UNKNOWN')['items'][0]['ip'],'1.1.1.1')
        self.assertEqual({r['value']:r['count'] for r in self.manager.facets('*','all')['ip_regions']},{'US':1,'UNKNOWN':1})
        self.assertEqual(self.manager.results('*','all',sort='ip_region',limit=1)['items'][0]['ip'],'1.1.1.1')
        first=self.manager.results('*','all',sort='ip_region',limit=1)
        self.assertEqual(self.manager.results('*','all',sort='ip_region',limit=1,cursor=first['next_cursor'])['items'][0]['ip'],'8.8.8.8')
        self.manager.favorite('8.8.8.8',443,True)
        self.manager.delete('a')
        self.assertEqual(self.manager.results('*','all',favorites=True,ip_country='US')['total'],1)
        with self.assertRaises(ValueError):self.manager.results('*','all',ip_country="US' OR 1=1")

    def test_outage_keeps_unknown_and_does_not_retry_on_poll(self):
        with patch('geolocation.lookup_geoip',side_effect=ValueError('offline')) as lookup:
            self.geo.enqueue(['8.8.8.8'])
            worker=self.geo.worker
            if worker:worker.join(5)
            self.geo.enqueue(['8.8.8.8'])
            lookup.assert_called_once()
        row=self.manager.results('a','all',search='8.8.8.8')['items'][0]
        self.assertEqual(row['ip_country'],'UNKNOWN')
        self.assertIn('offline',row['ip_country_error'])

    def test_geoip_response_validation(self):
        for body,valid in [(dict(success=True,ip='8.8.8.8',country_code='US'),True),
                           (dict(success=False,message='quota'),False),
                           (dict(success=True,ip='1.1.1.1',country_code='US'),False),
                           (dict(success=True,ip='8.8.8.8',country_code='bad'),False)]:
            with patch('geolocation.urllib.request.urlopen',return_value=io.BytesIO(json.dumps(body).encode())):
                if valid:self.assertEqual(lookup_geoip('8.8.8.8'),'US')
                else:
                    with self.assertRaises(ValueError):lookup_geoip('8.8.8.8')

    def test_persistent_daily_budget_and_429_backoff(self):
        day=time.strftime('%Y-%m-%d',time.gmtime())
        with connect(self.manager.path) as db:db.execute('INSERT INTO geo_usage VALUES (?,?)',(day,GEOIP_DAILY_LIMIT))
        with patch('geolocation.lookup_geoip') as lookup:
            with self.assertRaisesRegex(ValueError,'额度'):self.geo._lookup('8.8.8.8','dmit')
            lookup.assert_not_called()
        with connect(self.manager.path) as db:db.execute('DELETE FROM geo_usage')
        with patch('geolocation.lookup_geoip',side_effect=urllib.error.HTTPError('https://ipwho.is',429,'limit',{},None)) as lookup:
            with self.assertRaisesRegex(ValueError,'限流'):self.geo._lookup('8.8.8.8','dmit')
            with self.assertRaisesRegex(ValueError,'限流'):self.geo._lookup('1.1.1.1','dmit')
            self.assertEqual(lookup.call_count,1)
