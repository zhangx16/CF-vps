"""Task lifecycle and source catalog."""
import json
import threading
import time
import uuid
from db import connect, ConflictError
from scan import prepare


class JobsMixin:
    def prune_completed_nonhits(self, ident=None):
        """Remove failure payloads/checkpoints only after a task is complete."""
        with connect(self.path) as db:
            ids=[r['id'] for r in db.execute("SELECT id FROM jobs WHERE status='completed'"+(' AND id=?' if ident else ''), (ident,) if ident else ())]
        for job in ids:
            for table,condition in [('results',"status!='hit' OR status IS NULL"),('observations','hit=0')]:
                while True:
                    with connect(self.path) as db:
                        changed=db.execute(f'DELETE FROM {table} WHERE rowid IN (SELECT rowid FROM {table} WHERE job=? AND ({condition}) LIMIT 2000)',(job,)).rowcount
                    if changed<2000:
                        break


    def jobs(self):
        with connect(self.path) as db:
            rows = [dict(r) for r in db.execute('SELECT * FROM jobs ORDER BY created DESC LIMIT 100')]
            counts = {}
            ids = [row['id'] for row in rows]
            placeholders = ','.join('?' for _ in ids) or 'NULL'
            for r in db.execute(f'SELECT job,category,count FROM job_diagnostics WHERE job IN ({placeholders})', ids):
                counts.setdefault(r['job'], {})[r['category']] = r['count']
            for row in rows:
                row['diagnostics'] = counts.get(row['id'], {})
        with self.lock:
            for row in rows:
                row['config'] = self.cached_source_config(row['id'], row['config'])
                row['config'].pop('input_targets',None)
                runtime = self.runners.get(row['id'])
                if runtime:
                    row.update(runtime['live'])
                    if runtime.get('controller'):
                        row.update(runtime['controller'].snapshot())
                    if runtime['stop'].is_set():
                        row['status'] = 'stopping'
        return rows


    def job_detail(self, ident):
        with connect(self.path) as db:
            row=db.execute('SELECT * FROM jobs WHERE id=?',(ident,)).fetchone()
        if not row:
            raise ValueError('任务不存在')
        config=self.cached_source_config(row['id'], row['config'])
        original=config.get('input_targets')
        has_original=isinstance(original,str) and bool(original.strip())
        return dict(id=row['id'],created=row['created'],status=row['status'],total=row['total'],
                    task_name=config.get('task_name',''),provider_name=config.get('provider_name','自定义目标'),
                    target_text=original if has_original else '\n'.join(config.get('networks',[])),
                    target_kind='original' if has_original else 'snapshot',networks=config.get('networks',[]),
                    ports=config.get('ports',[]),kind=config.get('kind','scan'),source_id=config.get('source_id',''))


    def source_config(self,config):
        config=dict(config)
        if 'provider' not in config:
            if set(config.get('networks',[]))==self.builtin_networks:
                config.update(provider='dmit',provider_name='DMIT（目标匹配内置快照）')
            else:
                config.update(provider='',provider_name='自定义 / 旧任务')
        return config


    def cached_source_config(self, ident, raw):
        with self.source_lock:
            cached = self.source_cache.get(ident)
            if cached is None or cached[0] != raw:
                cached = (raw, self.source_config(json.loads(raw)))
                self.source_cache[ident] = cached
            return dict(cached[1])


    def job_sources(self):
        sources={}
        with connect(self.path) as db:
            for row in db.execute('SELECT id,created,status,config,done,hits FROM jobs ORDER BY created DESC'):
                config=self.cached_source_config(row['id'], row['config'])
                sources[row['id']]=dict(id=row['id'],created=row['created'],status=row['status'],done=row['done'],hits=row['hits'],
                    task_name=config.get('task_name',''),provider=config.get('provider') or 'custom_targets',provider_name=config.get('provider_name') or '自定义目标',kind=config.get('kind','scan'))
        return sources


    def catalog(self):
        jobs=list(self.job_sources().values())
        groups={}
        for job in jobs:
            key=job['provider']
            group=groups.setdefault(key,dict(id=key,name=job['provider_name'],records=0,hits=0,jobs=0))
            group['records']+=job['done'];group['hits']+=job['hits'];group['jobs']+=1
        return dict(jobs=jobs,providers=list(groups.values()))


    def start(self, raw=None, resume=None, retest=None):
        with self.lock:
            if resume in self.runners:
                raise ConflictError('该任务正在运行')
            now = time.time()
            with connect(self.path) as db:
                if resume:
                    row = db.execute('SELECT * FROM jobs WHERE id=?', (resume,)).fetchone()
                    if row is None or row['status'] == 'completed':
                        raise ValueError('任务不存在或已完成')
                    if row['created'] <= now - 86400:
                        raise ValueError('任务已超过24小时保留期，请使用原IP段新建测试')
                    ident, config = resume, json.loads(row['config'])
                    done, hits = row['done'], row['hits']
                    db.execute("UPDATE jobs SET status='running', error='', done=?, hits=?, updated=? WHERE id=?", (done, hits, now, ident))
                else:
                    if retest:
                        parent = db.execute('SELECT config FROM jobs WHERE id=?', (retest,)).fetchone()
                        if not parent:
                            raise ValueError('原任务不存在')
                        config = json.loads(parent['config'])
                        config.update(kind='retest', source_id=retest)
                        config.pop('selected', None)
                        selected = (raw or {}).get('selected')
                        if selected is not None:
                            if not isinstance(selected, list) or not 1 <= len(selected) <= 200:
                                raise ValueError('一次最多选择 200 个结果')
                            checked = []
                            for item in selected:
                                if not isinstance(item, dict):
                                    raise ValueError('复测目标格式错误')
                                ip, port = str(item.get('ip')), int(item.get('port',0))
                                if not db.execute('SELECT 1 FROM results WHERE job=? AND ip=? AND port=?', (retest,ip,port)).fetchone():
                                    raise ValueError('复测目标不在原任务中')
                                if [ip,port] not in checked:
                                    checked.append([ip,port])
                            config['selected'] = checked
                            config['total'] = len(checked)
                        else:
                            config['total'] = db.execute("SELECT COUNT(*) FROM results WHERE job=? AND status='hit'", (retest,)).fetchone()[0]
                        if not config['total']:
                            raise ValueError('没有可复测的目标')
                    else:
                        config = prepare(raw)
                    ident = uuid.uuid4().hex
                    done = hits = 0
                    db.execute('INSERT INTO jobs(id,created,updated,status,config,total) VALUES (?,?,?,?,?,?)',
                               (ident, now, now, 'running', json.dumps(config), config['total']))
            runtime = dict(stop=threading.Event(), live=dict(done=done, hits=hits, rate=0, eta=None),
                           controller=None, source_id=config.get('source_id'))
            self.runners[ident] = runtime
            self.stop_event = runtime['stop']
            self.active = ident
            self.thread = threading.Thread(target=self._run, args=(ident, config, done, hits), daemon=True)
            runtime['thread'] = self.thread
            self.thread.start()
            return ident


    def stop(self, ident=None):
        if ident is None:
            self.accuracy.cancel()
        with self.lock:
            if ident is not None and ident not in self.runners:
                raise ConflictError('该任务未在运行')
            for job, runtime in self.runners.items():
                if ident is None or job == ident:
                    runtime['stop'].set()


    def join(self, timeout=100):
        with self.lock:
            threads = [r['thread'] for r in self.runners.values()]
        if self.accuracy.thread:
            threads.append(self.accuracy.thread)
        deadline = time.monotonic() + timeout
        for thread in threads:
            thread.join(max(0, deadline - time.monotonic()))


    def delete(self, ident):
        with self.lock:
            if self.accuracy.thread and self.accuracy.thread.is_alive() and self.accuracy.live['job'] == ident:
                raise ConflictError('请先等待并发对照结束')
            if any(ident == job or runtime.get('source_id') == ident
                   for job, runtime in self.runners.items()):
                raise ConflictError('请先停止相关任务')
            # Release the SQLite writer lock between batches; the manager lock
            # keeps this task from resuming while its rows are removed.
            for table in ('confirmed_nodes', 'observations', 'results', 'scan_progress',
                          'job_diagnostics', 'accuracy_reports'):
                while True:
                    with connect(self.path) as db:
                        changed = db.execute(f'DELETE FROM {table} WHERE rowid IN (SELECT rowid FROM {table} WHERE job=? LIMIT 2000)', (ident,)).rowcount
                    if changed < 2000:
                        break
            with connect(self.path) as db:
                db.execute('DELETE FROM jobs WHERE id=?', (ident,))
            with self.source_lock:
                self.source_cache.pop(ident, None)
