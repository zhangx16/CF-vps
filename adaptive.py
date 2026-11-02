"""Linux resource sampling and a non-disruptive adaptive concurrency gate."""
import asyncio
from contextlib import asynccontextmanager
import math
import os
from pathlib import Path
import resource
import time

MIB=1024*1024


class ResourceSampler:
    def __init__(self):
        self.previous=None

    @staticmethod
    def read(path):
        try:return Path(path).read_text().strip()
        except (OSError,ValueError):return ''

    def sample(self):
        now=time.monotonic()
        try:
            capacity=len(os.sched_getaffinity(0))
        except (AttributeError,OSError):capacity=os.cpu_count() or 1
        info={}
        for line in self.read('/proc/meminfo').splitlines():
            key,_,value=line.partition(':')
            if value.strip():info[key]=int(value.strip().split()[0])*1024
        total=info.get('MemTotal',0)
        available=info.get('MemAvailable',info.get('MemFree',0)+info.get('Cached',0))
        for maximum,current in [('/sys/fs/cgroup/memory.max','/sys/fs/cgroup/memory.current'),('/sys/fs/cgroup/memory/memory.limit_in_bytes','/sys/fs/cgroup/memory/memory.usage_in_bytes')]:
            limit,used=self.read(maximum),self.read(current)
            if limit.isdigit() and used.isdigit() and 0<int(limit)<total:
                total=int(limit);available=min(available,max(0,total-int(used)))
        quota=self.read('/sys/fs/cgroup/cpu.max').split()
        if len(quota)==2 and quota[0].isdigit():capacity=min(capacity,max(.1,int(quota[0])/int(quota[1])))
        else:
            q=self.read('/sys/fs/cgroup/cpu/cpu.cfs_quota_us');period=self.read('/sys/fs/cgroup/cpu/cpu.cfs_period_us')
            if q.isdigit() and period.isdigit() and int(q)>0:capacity=min(capacity,max(.1,int(q)/int(period)))
        first=self.read('/proc/stat').splitlines()
        values=[int(v) for v in first[0].split()[1:9]] if first and first[0].startswith('cpu ') else []
        ticks=sum(values);idle=sum(values[3:5]) if values else 0
        group={}
        for line in self.read('/sys/fs/cgroup/cpu.stat').splitlines():
            key,_,value=line.partition(' ')
            if value.isdigit():group[key]=int(value)
        usage=group.get('usage_usec')
        if usage is None:
            v=self.read('/sys/fs/cgroup/cpuacct/cpuacct.usage')
            if v.isdigit():usage=int(v)/1000
        cpu=None
        if self.previous:
            before,old_ticks,old_idle,old_usage=self.previous
            if ticks>old_ticks:cpu=max(0,min(100,100*(1-(idle-old_idle)/(ticks-old_ticks))))
            if usage is not None and old_usage is not None and now>before:
                group_cpu=max(0,min(100,(usage-old_usage)/(now-before)/1e6/capacity*100))
                cpu=max(cpu or 0,group_cpu)
        self.previous=(now,ticks,idle,usage)
        try:load=os.getloadavg()[0]/capacity
        except OSError:load=None
        try:fd_used=len(os.listdir('/proc/self/fd'))
        except OSError:fd_used=None
        fd_limit=resource.getrlimit(resource.RLIMIT_NOFILE)[0]
        if fd_limit==resource.RLIM_INFINITY:fd_limit=1_000_000
        return dict(cpu_percent=round(cpu,1) if cpu is not None else None,load_ratio=round(load,2) if load is not None else None,
                    cpu_capacity=round(capacity,2),memory_available_mb=round(available/MIB,1) if total else None,
                    memory_total_mb=round(total/MIB,1) if total else None,fd_used=fd_used,fd_limit=fd_limit)


class AdaptiveLimiter:
    def __init__(self, ceiling, minimum=10, enabled=True, sampler=None):
        self.ceiling=int(ceiling)
        self.minimum=max(1,min(int(minimum),self.ceiling))
        self.enabled=enabled
        self.limit=self.ceiling
        self.active=0
        self.reason='固定并发' if not enabled else '初始化资源评估'
        self.metrics={}
        self.healthy=0
        self.condition=asyncio.Condition()
        self.sampler=sampler or ResourceSampler()

    def choose(self, metrics):
        if not self.enabled:return self.ceiling,'固定并发'
        available,total=metrics.get('memory_available_mb'),metrics.get('memory_total_mb')
        cap=self.ceiling;reasons=[]
        if available is not None and total:
            reserve=max(64,total*.1)
            memory_cap=max(1,int((available-reserve)/1))
            if memory_cap<cap:cap=memory_cap;reasons.append('可用内存余量不足')
        used,limit=metrics.get('fd_used'),metrics.get('fd_limit')
        if used is not None and limit:
            fd_cap=max(1,int(limit*.8-used-32))
            if fd_cap<cap:cap=fd_cap;reasons.append('文件描述符余量不足')
        cpu,load=metrics.get('cpu_percent'),metrics.get('load_ratio')
        pressure=(cpu is not None and cpu>=85) or (load is not None and load>=.9)
        if cap<self.limit:
            self.healthy=0;return cap,'；'.join(reasons)
        if pressure:
            self.healthy=0
            return min(cap,max(min(self.minimum,cap),math.floor(self.limit*.75))),'CPU 使用率或系统负载偏高'
        healthy=(cpu is None or cpu<65) and (load is None or load<.65)
        if healthy:
            self.healthy+=1
            if self.healthy>=2 and self.limit<cap:
                self.healthy=0;return min(cap,self.limit+max(1,math.ceil(self.ceiling*.1))),'资源恢复，逐步增加并发'
        else:self.healthy=0
        return min(self.limit,cap),'资源正常' if healthy else '资源适中，保持当前并发'

    async def update(self):
        self.metrics=self.sampler.sample()
        target,reason=self.choose(self.metrics)
        async with self.condition:
            self.limit=target;self.reason=reason;self.condition.notify_all()

    def snapshot(self):
        return dict(adaptive=self.enabled,effective_concurrency=self.limit,concurrency_ceiling=self.ceiling,
                    inflight=self.active,concurrency_reason=self.reason,resources=dict(self.metrics))

    @asynccontextmanager
    async def slot(self, stopping):
        async with self.condition:
            while self.active>=self.limit:
                if stopping():raise asyncio.CancelledError()
                try:await asyncio.wait_for(self.condition.wait(),.25)
                except asyncio.TimeoutError:pass
            if stopping():raise asyncio.CancelledError()
            self.active+=1
        try:yield
        finally:
            async with self.condition:
                self.active-=1;self.condition.notify_all()
