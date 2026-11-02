import asyncio
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from adaptive import AdaptiveLimiter,ResourceSampler
from providers import ProviderStore,parse_asns,normalize
from engine import Manager


class AdaptiveTests(unittest.IsolatedAsyncioTestCase):
    def test_resource_decisions_preserve_ceiling_and_emergency_floor(self):
        limiter=AdaptiveLimiter(100,10)
        high=dict(cpu_percent=95,load_ratio=1.2,memory_available_mb=1000,memory_total_mb=2000,fd_used=20,fd_limit=4096)
        target,why=limiter.choose(high)
        self.assertEqual(target,75)
        self.assertIn('CPU',why)
        limiter.limit=75
        healthy=dict(high,cpu_percent=10,load_ratio=.1)
        self.assertEqual(limiter.choose(healthy)[0],75)
        self.assertEqual(limiter.choose(healthy)[0],85)
        emergency=dict(healthy,memory_available_mb=30)
        self.assertEqual(limiter.choose(emergency)[0],1)
        self.assertEqual(AdaptiveLimiter(40,10,False).choose(emergency)[0],40)
        fds=dict(healthy,fd_limit=128,fd_used=100)
        self.assertEqual(limiter.choose(fds)[0],1)

    async def test_reduction_does_not_cancel_inflight_probes(self):
        limiter=AdaptiveLimiter(3)
        gate=asyncio.Event();entered=[]
        async def worker(i):
            async with limiter.slot(lambda:False):
                entered.append(i)
                await gate.wait()
        tasks=[asyncio.create_task(worker(i)) for i in range(3)]
        await asyncio.sleep(.02)
        self.assertEqual(limiter.active,3)
        async with limiter.condition:limiter.limit=1
        fourth=asyncio.create_task(worker(4))
        await asyncio.sleep(.03)
        self.assertNotIn(4,entered)
        self.assertFalse(any(t.cancelled() for t in tasks))
        gate.set();await asyncio.gather(*tasks,fourth)
        self.assertIn(4,entered)
        self.assertEqual(limiter.active,0)

    def test_linux_sample_has_safe_numeric_fields(self):
        sample=ResourceSampler().sample()
        self.assertGreater(sample['cpu_capacity'],0)
        self.assertGreater(sample['fd_limit'],0)


class ProviderTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.store=ProviderStore(Path(self.tmp.name)/'providers.json')

    def tearDown(self):self.tmp.cleanup()

    def wait_refresh(self,key):
        for _ in range(200):
            if not self.store.get(key)['refreshing']:return
            time.sleep(.01)
        self.fail('refresh did not finish')

    def test_presets_and_strict_target_selection(self):
        self.assertEqual(len(self.store.list()),5)
        p,nets=self.store.resolve('dmit')
        self.assertTrue(nets)
        _,selected=self.store.resolve('dmit',nets[:2])
        self.assertEqual(selected,nets[:2])
        with self.assertRaises(ValueError):self.store.resolve('bwh')
        with self.assertRaises(ValueError):self.store.resolve('dmit',['8.8.8.0/24'])
        self.assertEqual(parse_asns('AS20473, 14061 AS20473'),[14061,20473])
        with self.assertRaises(ValueError):parse_asns('20473/../../etc/passwd')

    def test_refresh_failure_preserves_last_good_cache(self):
        with patch('providers.fetch_prefixes',return_value=['8.8.8.0/24']):
            self.store.refresh('bwh');self.wait_refresh('bwh')
        self.assertEqual(self.store.get('bwh')['networks'],['8.8.8.0/24'])
        with patch('providers.fetch_prefixes',side_effect=ValueError('source offline')):
            self.store.refresh('bwh');self.wait_refresh('bwh')
        cached=self.store.get('bwh')
        self.assertEqual(cached['networks'],['8.8.8.0/24'])
        self.assertIn('source offline',cached['error'])
        reloaded=ProviderStore(self.store.path)
        self.assertEqual(reloaded.get('bwh')['networks'],cached['networks'])

    def test_custom_provider_persists_and_refreshes(self):
        profile=self.store.add('Example provider','AS20473')
        with patch('providers.fetch_prefixes',return_value=['8.8.8.0/30']):
            self.store.refresh(profile['id']);self.wait_refresh(profile['id'])
        reloaded=ProviderStore(self.store.path)
        self.assertEqual(reloaded.get(profile['id'])['name'],'Example provider')
        self.assertEqual(reloaded.get(profile['id'])['ip_count'],2)

    def test_only_global_ipv4_prefixes_and_overlap_collapse(self):
        self.assertEqual(normalize(['8.8.8.0/25','8.8.8.128/25','127.0.0.0/8','2001:4860::/32']),['8.8.8.0/24'])


class RegionalProviderTests(unittest.TestCase):
    def test_only_requested_five_presets_are_available(self):
        from providers import PRESETS
        self.assertEqual({p['id'] for p in PRESETS},{'dmit','bwh','gomami_hk','vmiss_us','isif_hk'})
        self.assertEqual({p['id']:p.get('country') for p in PRESETS if p.get('country')},{'gomami_hk':'HK','vmiss_us':'US','isif_hk':'HK'})

    def test_longest_geofeed_prefix_overrides_broad_country(self):
        from providers import regional_prefixes
        feed='8.8.8.0/24,US,US-CA,Los Angeles,\n8.8.8.128/25,HK,,Hong Kong,\n1.1.1.0/24,US,,,\n'
        self.assertEqual(regional_prefixes(['8.8.8.0/24'],feed,'US'),['8.8.8.0/25'])
        self.assertEqual(regional_prefixes(['8.8.8.0/24'],feed,'HK'),['8.8.8.128/25'])

    def test_conflicting_and_missing_geography_never_fall_back_to_asn(self):
        from providers import regional_prefixes
        for feed in ['<html>unavailable</html>','8.8.8.0/24,US,,,\n8.8.8.0/24,HK,,,\n','1.1.1.0/24,HK,,,\n']:
            with self.assertRaises(ValueError):regional_prefixes(['8.8.8.0/24'],feed,'HK')

    def test_retired_caches_are_removed_but_kept_provider_cache_survives(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'providers.json'
            store=ProviderStore(path)
            store.state['cache']['vultr']=dict(networks=['1.1.1.0/24'])
            store.state['cache']['bwh']=dict(networks=['8.8.8.0/24'])
            store.save()
            reloaded=ProviderStore(path)
            self.assertNotIn('vultr',json.loads(path.read_text())['cache'])
            self.assertEqual(reloaded.get('bwh')['networks'],['8.8.8.0/24'])

    def test_regional_refresh_and_cache_scope_validation(self):
        with tempfile.TemporaryDirectory() as tmp:
            store=ProviderStore(Path(tmp)/'providers.json')
            store.state['cache']['gomami_hk']=dict(networks=['1.1.1.0/24'],source='unscoped ASN cache')
            with self.assertRaises(ValueError):store.resolve('gomami_hk')
            with patch('providers.fetch_prefixes',return_value=['8.8.8.0/24','1.1.1.0/24']),patch('providers.fetch_geofeed',return_value='8.8.8.0/24,HK,,,\n1.1.1.0/24,JP,,,\n'):
                store.refresh('gomami_hk')
                for _ in range(200):
                    if not store.get('gomami_hk')['refreshing']:break
                    time.sleep(.01)
            self.assertEqual(store.resolve('gomami_hk')[1],['8.8.8.0/24'])
            with patch('providers.fetch_prefixes',return_value=['8.8.8.0/24']),patch('providers.fetch_geofeed',side_effect=ValueError('geofeed offline')):
                store.refresh('gomami_hk')
                for _ in range(200):
                    if not store.get('gomami_hk')['refreshing']:break
                    time.sleep(.01)
            self.assertEqual(store.resolve('gomami_hk')[1],['8.8.8.0/24'])
            self.assertIn('geofeed offline',store.get('gomami_hk')['error'])
