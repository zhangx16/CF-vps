"""Selectable provider ASN profiles with atomic, last-good prefix caches."""
import ipaddress
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
    dict(id='vultr',name='Vultr',asns=[20473]),
    dict(id='digitalocean',name='DigitalOcean',asns=[14061]),
    dict(id='linode',name='Linode / Akamai',asns=[63949]),
    dict(id='hetzner',name='Hetzner',asns=[24940]),
    dict(id='ovh',name='OVHcloud',asns=[16276]),
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
                networks=fetch_prefixes(profile['asns'])
                with self.lock:
                    previous=self.state['cache'].get(key)
                    self.state['cache'][key]=dict(networks=networks,updated_at=time.time(),source='RIPEstat ASN 公告前缀')
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
