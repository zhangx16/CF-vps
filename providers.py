"""Selectable provider ASN profiles with atomic, last-good prefix caches."""
import ipaddress
import csv
import io
import json
import os
from pathlib import Path
import re
import tempfile
import threading
import time
import urllib.request
import uuid

PRESETS=[
    dict(id='dmit',name='DMIT',asns=[906,132110,32519]),
    dict(id='bwh',name='BWH / 搬瓦工（IT7）',asns=[25820],notes='IT7 主网 ASN 公告，不保证覆盖所有机房、线路及租用网段。',reference='https://www.it7.net/'),
    dict(id='gomami_hk',name='GoMami · 香港',asns=[36002],country='HK',geofeed='https://gomami.io/geofeed.txt',
         notes='仅取 GoMami 官方 Geofeed 标注香港、且仍由 AS36002 公告的 IPv4；未标注地区的地址不纳入。',reference='https://docs.gomami.io/en/network/locations/'),
    dict(id='vmiss_us',name='VMISS · 美国',asns=[400464,967],country='US',geofeed='https://geofeed.cogentco.com/geofeed.csv',
         notes='仅取 VMISS ASN 公告与 Cogent 官方 Geofeed 美国标注的交集；不将整个 ASN 或注册地视为美国机房。',reference='https://www.vmiss.com/'),
    dict(id='isif_hk',name='ISIF Cloud · 香港',asns=[209554,154162],country='HK',geofeed='https://isif.net/geofeed.csv',
         notes='仅取 ISIF 官方 Geofeed 标注香港、且仍由所列 ASN 公告的 IPv4；日本、新加坡和美国网段排除。',reference='https://cloud.isif.net/'),
]

MAX_BYTES=8*1024*1024


def normalize(prefixes):
    nets=[]
    for value in prefixes:
        net=ipaddress.ip_network(value,strict=False)
        if net.version==4 and net.is_global:nets.append(net)
    return [str(n) for n in ipaddress.collapse_addresses(nets)]


def address_count(prefixes):
    return sum(n.num_addresses if n.prefixlen>=31 else n.num_addresses-2 for n in map(ipaddress.ip_network,prefixes))


def parse_asns(value):
    if not isinstance(value,str):raise ValueError('ASN 请用逗号分隔')
    parts=[s.strip().upper().removeprefix('AS') for s in re.split(r'[,，\s]+',value) if s.strip()]
    if not 1<=len(parts)<=5 or any(not s.isdigit() or not 1<=int(s)<=4294967295 for s in parts):
        raise ValueError('请输入 1–5 个有效 ASN，例如 AS20473,AS14061')
    return sorted(set(map(int,parts)))


def fetch_prefixes(asns):
    result=[]
    for asn in asns:
        url=f'https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{int(asn)}'
        request=urllib.request.Request(url,headers={'User-Agent':'cf-vps/2.0'})
        with urllib.request.urlopen(request,timeout=15) as response:
            body=response.read(MAX_BYTES+1)
        if len(body)>MAX_BYTES:raise ValueError('前缀响应过大')
        data=json.loads(body)
        if data.get('status') not in (None,'ok'):raise ValueError(f'AS{asn} 查询失败')
        prefixes=[p['prefix'] for p in data['data']['prefixes'] if ':' not in p.get('prefix','')]
        if not prefixes:raise ValueError(f'AS{asn} 没有可用 IPv4 公告前缀')
        result.extend(prefixes)
    networks=normalize(result)
    if not networks:raise ValueError('没有有效公网 IPv4 网段')
    return networks


def fetch_geofeed(url):
    # Public operators' text feeds sometimes reject Python's default User-Agent.
    request=urllib.request.Request(url,headers={'User-Agent':'Mozilla/5.0 (compatible; CFVPS-Prefix/2.0)','Accept':'text/csv,text/plain,*/*'})
    with urllib.request.urlopen(request,timeout=25) as response:
        body=response.read(MAX_BYTES+1)
    if len(body)>MAX_BYTES:raise ValueError('Geofeed 响应超过 8 MiB')
    return body.decode('utf-8-sig')


def regional_prefixes(announced,text,country):
    """Intersect routed space with geofeed using longest-prefix geography.

    A more-specific nonmatching country overrides a broad matching record.
    Conflicting equally specific records and unlabelled space are excluded.
    """
    records=[]
    for row in csv.reader(io.StringIO(text)):
        if len(row)<2 or row[0].lstrip().startswith('#'):continue
        try:net=ipaddress.ip_network(row[0].strip(),strict=False)
        except ValueError:continue
        if net.version!=4 or not net.is_global:continue
        cc=row[1].strip().upper()
        if cc=='CN' and len(row)>2 and row[2].strip().upper()=='CN-HK':cc='HK'
        if not re.fullmatch('[A-Z]{2}',cc):continue
        records.append((int(net.network_address),int(net.broadcast_address)+1,net.prefixlen,cc))
    if not records:raise ValueError('Geofeed 没有有效 IPv4 地区记录，拒绝回退到全 ASN')
    answer=[]
    for prefix in normalize(announced):
        net=ipaddress.ip_network(prefix);low=int(net.network_address);high=int(net.broadcast_address)+1
        overlaps=[(max(a,low),min(b,high),length,cc) for a,b,length,cc in records if a<high and b>low]
        edges=sorted({low,high}|{value for a,b,_,_ in overlaps for value in (a,b)})
        for a,b in zip(edges,edges[1:]):
            matches=[(length,cc) for start,end,length,cc in overlaps if start<=a<end]
            if not matches:continue
            longest=max(length for length,_ in matches)
            countries={cc for length,cc in matches if length==longest}
            if countries=={country}:
                answer.extend(map(str,ipaddress.summarize_address_range(ipaddress.IPv4Address(a),ipaddress.IPv4Address(b-1))))
    networks=normalize(answer)
    if not networks:raise ValueError(f'没有可确认属于 {country} 的公告 IPv4 网段，原缓存保持不变')
    return networks


def fetch_profile(profile):
    networks=fetch_prefixes(profile['asns'])
    if profile.get('country'):
        networks=regional_prefixes(networks,fetch_geofeed(profile['geofeed']),profile['country'])
    return networks


class ProviderStore:
    def __init__(self,path):
        self.path=Path(path)
        self.lock=threading.Lock()
        self.busy=set()
        self.errors={}
        self.state=dict(version=1,custom=[],cache={})
        if self.path.exists():
            if self.path.stat().st_size>MAX_BYTES:raise ValueError('服务商缓存文件过大')
            saved=json.loads(self.path.read_text())
            if saved.get('version')!=1:raise ValueError('不支持的服务商缓存版本')
            for profile in saved.get('custom',[]):
                if not isinstance(profile.get('id'),str) or not profile['id'].startswith('custom_'):
                    raise ValueError('自定义服务商标识无效')
                parse_asns(','.join(str(a) for a in profile['asns']))
            self.state=saved
            allowed={p['id'] for p in self.profiles()}
            retired=set(self.state['cache'])-allowed
            if retired:
                self.state['cache']={key:value for key,value in self.state['cache'].items() if key in allowed}
                self.save()
        if 'dmit' not in self.state['cache']:
            text=(Path(__file__).resolve().parent/'dmit_prefixes.txt').read_text()
            networks=normalize([line.split('#',1)[0].strip() for line in text.splitlines() if line.split('#',1)[0].strip()])
            self.state['cache']['dmit']=dict(networks=networks,updated_at=None,source='项目内置静态快照')

    def save(self):
        encoded=json.dumps(self.state,ensure_ascii=False).encode()
        if len(encoded)>MAX_BYTES:raise ValueError('服务商缓存总量超过 8 MiB，请减少自定义服务商')
        self.path.parent.mkdir(parents=True,exist_ok=True)
        fd,name=tempfile.mkstemp(prefix='.providers-',dir=self.path.parent)
        try:
            with os.fdopen(fd,'wb') as out:out.write(encoded)
            os.chmod(name,0o600)
            os.replace(name,self.path)
        finally:Path(name).unlink(missing_ok=True)

    def profiles(self):
        return PRESETS+self.state['custom']

    def summary(self,profile,full=False):
        key=profile['id'];cache=self.state['cache'].get(key,{})
        if profile.get('country') and (cache.get('country')!=profile['country'] or cache.get('geofeed')!=profile['geofeed'] or cache.get('asns')!=profile['asns']):
            cache={}
        networks=cache.get('networks',[])
        result=dict(profile,updated_at=cache.get('updated_at'),source=cache.get('source','尚未更新'),
                    prefix_count=len(networks),ip_count=address_count(networks),refreshing=key in self.busy,error=self.errors.get(key,''))
        if full:result['networks']=list(networks)
        return result

    def list(self):
        with self.lock:return [self.summary(p) for p in self.profiles()]

    def get(self,key):
        with self.lock:
            profile=next((p for p in self.profiles() if p['id']==key),None)
            if not profile:raise ValueError('服务商不存在')
            return self.summary(profile,True)

    def add(self,name,asns):
        if not isinstance(name,str) or not 1<=len(name.strip())<=60:raise ValueError('服务商名称应为 1–60 字')
        numbers=parse_asns(asns)
        with self.lock:
            if len(self.state['custom'])>=20:raise ValueError('最多添加 20 个自定义服务商')
            profile=dict(id='custom_'+uuid.uuid4().hex[:12],name=name.strip(),asns=numbers)
            self.state['custom'].append(profile)
            try:self.save()
            except BaseException:
                self.state['custom'].pop()
                raise
            return profile

    def refresh(self,key):
        profile=self.get(key)
        with self.lock:
            if self.busy:raise ValueError('已有服务商网段正在更新，请稍候')
            self.busy.add(key);self.errors.pop(key,None)
        def update():
            try:
                networks=fetch_profile(profile)
                with self.lock:
                    previous=self.state['cache'].get(key)
                    self.state['cache'][key]=dict(networks=networks,updated_at=time.time(),source=('RIPEstat 公告 ∩ '+profile['country']+' Geofeed') if profile.get('country') else 'RIPEstat ASN 公告前缀',country=profile.get('country'),geofeed=profile.get('geofeed'),asns=profile['asns'])
                    try:self.save()
                    except BaseException:
                        if previous is None:self.state['cache'].pop(key,None)
                        else:self.state['cache'][key]=previous
                        raise
            except Exception as exc:
                with self.lock:self.errors[key]=str(exc)[:500]
            finally:
                with self.lock:self.busy.discard(key)
        threading.Thread(target=update,name='provider-refresh',daemon=True).start()

    def resolve(self,key,selected=None):
        provider=self.get(key)
        if not provider['networks']:raise ValueError('此服务商尚无缓存网段，请先点击更新网段')
        networks=provider['networks']
        if selected is not None:
            if not isinstance(selected,list) or not selected or len(selected)>20000 or any(not isinstance(p,str) for p in selected):
                raise ValueError('请选择有效网段')
            if not set(selected)<=set(networks):raise ValueError('部分网段已更新，请重新选择')
            networks=list(dict.fromkeys(selected))
        return provider,networks
