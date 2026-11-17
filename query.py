"""Result filtering, pagination and comparisons."""
import base64
import json
from db import connect


class QueryMixin:
    def selection_condition(self,ident,view='hits',region='',colo='',search='',provider='',favorites=False):
        condition,args=self.condition(ident,view,region,colo,search)
        sources=self.job_sources()
        if provider:
            ids=[key for key,source in sources.items() if source['provider']==provider and (ident=='*' or key==ident)]
            scope='job IN ('+','.join('?' for _ in ids)+')' if ids else '0=1'
            condition=scope+condition[len('job=?'):];args=ids+args[1:]
        elif ident=='*':
            condition='1=1'+condition[len('job=?'):];args=args[1:]
        if favorites:
            condition += ' AND (ip,port) IN (SELECT ip,port FROM endpoint_favorites) AND rowid IN (SELECT MAX(rowid) FROM results GROUP BY ip,port)'
        return condition,args,sources


    @staticmethod
    def condition(ident, view='hits', region='', colo='', search=''):
        parts, args = ['job=?'], [ident]
        if view == 'hits':
            parts.append("status='hit'")
        elif view == 'local_confirmed':
            parts.append('(job,ip,port) IN (SELECT job,ip,port FROM confirmed_nodes)')
        elif view == 'verified':
            parts.append("evidence='dual_verified'")
        elif view in ('suspected','trace_valid','legacy'):
            parts.append('evidence=?'); args.append(view)
        elif view != 'all':
            raise ValueError('结果筛选无效')
        if region:
            parts.append("COALESCE(NULLIF(loc,''),'UNKNOWN')=?"); args.append(region)
        if colo:
            parts.append('colo=?'); args.append(colo)
        if search:
            parts.append("(ip LIKE ? ESCAPE '\\' OR CAST(port AS TEXT)=?)")
            args.extend([search.replace('\\','\\\\').replace('%','\\%').replace('_','\\_')+'%',search])
        return ' AND '.join(parts), args


    def facets(self, ident, view='hits',provider='',favorites=False):
        condition, args, _ = self.selection_condition(ident,view,provider=provider,favorites=favorites)
        with connect(self.path,favorites=favorites) as db:
            regions = [dict(r) for r in db.execute(f"SELECT COALESCE(NULLIF(loc,''),'UNKNOWN') AS value,COUNT(*) AS count FROM results WHERE {condition} GROUP BY value ORDER BY count DESC",args)]
            colos = [dict(r) for r in db.execute(f"SELECT colo AS value,COUNT(*) AS count FROM results WHERE {condition} AND colo!='' GROUP BY colo ORDER BY count DESC",args)]
        return dict(regions=regions,colos=colos)


    def results(self, ident, view='hits', page=1, limit=100, region='', colo='', search='', sort='newest', cursor='',provider='',favorites=False):
        page = max(1,min(int(page),100000))
        limit = max(1,min(int(limit),200))
        choices = {'newest':('rowid','DESC'),'latency_asc':('COALESCE(latency,1e30)','ASC'),
                   'latency_desc':('COALESCE(latency,-1)','DESC'),'ip':('ip_num','ASC'),
                   'region':("COALESCE(loc,'')",'ASC'),'colo':("COALESCE(colo,'')",'ASC')}
        if sort not in choices:
            raise ValueError('排序无效')
        key, direction = choices[sort]
        condition, args, sources = self.selection_condition(ident,view,region,colo,search,provider,favorites)
        with connect(self.path,favorites=favorites) as db:
            total = db.execute(f'SELECT COUNT(*) FROM results WHERE {condition}',args).fetchone()[0]
            where, values = condition, list(args)
            if cursor:
                try:
                    if len(cursor)>1000:
                        raise ValueError()
                    token = json.loads(base64.urlsafe_b64decode(cursor))
                    if token['sort'] != sort or not isinstance(token['rowid'],int) or not isinstance(token['value'],(int,float,str)):
                        raise ValueError()
                except (ValueError,KeyError,TypeError,UnicodeError):
                    raise ValueError('分页游标无效')
                op = '<' if direction == 'DESC' else '>'
                where += f' AND ({key}{op}? OR ({key}=? AND rowid<?))'
                values.extend([token['value'],token['value'],token['rowid']])
            rows = db.execute(f'SELECT rowid,job,{key} AS sortkey,data FROM results WHERE {where} ORDER BY {key} {direction},rowid DESC LIMIT ?',values+[limit+1]).fetchall()
            more = len(rows)>limit
            rows = rows[:limit]
            decoded = [json.loads(row['data']) for row in rows]
            endpoints = list({(data['ip'], data['port']) for data in decoded})
            history, confirmed, favorites_set = {}, set(), set()
            if endpoints:
                pairs = ','.join('(?,?)' for _ in endpoints)
                params = [value for endpoint in endpoints for value in endpoint]
                for r in db.execute(f'SELECT ip,port,MIN(CASE WHEN hit=1 THEN observed END) AS first_seen,MAX(CASE WHEN confirmed=1 THEN observed END) AS last_confirmed,COUNT(*) AS checks,COALESCE(SUM(hit),0) AS successes,COALESCE(SUM(confirmed),0) AS confirmations FROM observations WHERE (ip,port) IN (VALUES {pairs}) GROUP BY ip,port', params):
                    entry = dict(r)
                    endpoint = (entry.pop('ip'), entry.pop('port'))
                    history[endpoint] = entry
                triples = ','.join('(?,?,?)' for _ in rows)
                confirmed_params = [value for row, data in zip(rows, decoded) for value in (row['job'], data['ip'], data['port'])]
                confirmed = {tuple(r) for r in db.execute(f'SELECT job,ip,port FROM confirmed_nodes WHERE (job,ip,port) IN (VALUES {triples})', confirmed_params)}
                favorites_set = {tuple(r) for r in db.execute(f'SELECT ip,port FROM endpoint_favorites WHERE (ip,port) IN (VALUES {pairs})', params)}
            items = []
            for row, data in zip(rows, decoded):
                endpoint = (data['ip'], data['port'])
                data['history'] = history.get(endpoint, dict(first_seen=None, last_confirmed=None, checks=0, successes=0, confirmations=0))
                data['local_confirmed'] = (row['job'], *endpoint) in confirmed
                data['favorite'] = endpoint in favorites_set
                source=sources.get(row['job'],{})
                data.update(job_id=row['job'],task_name=source.get('task_name',data.get('task_name','')),provider_name=source.get('provider_name',data.get('provider_name','未知来源')),job_created=source.get('created',data.get('job_created')))
                items.append(data)
            next_cursor = ''
            if more:
                last = rows[-1]
                next_cursor = base64.urlsafe_b64encode(json.dumps(dict(sort=sort,value=last['sortkey'],rowid=last['rowid'])).encode()).decode()
            return dict(total=total,page=page,items=items,next_cursor=next_cursor)


    def compare(self, old, new, kind='new'):
        if old == new:
            raise ValueError('请选择两个不同任务')
        queries = {'new':(new,old,False),'lost':(old,new,False),'persistent':(new,old,True)}
        if kind not in queries:
            raise ValueError('对比类型无效')
        with connect(self.path) as db:
            if db.execute('SELECT COUNT(*) FROM jobs WHERE id IN (?,?)',(old,new)).fetchone()[0]!=2:
                raise ValueError('任务不存在')
            counts = {}
            for name,(a,b,present) in queries.items():
                exists = 'EXISTS' if present else 'NOT EXISTS'
                query = f"FROM results a WHERE a.job=? AND a.status='hit' AND {exists}(SELECT 1 FROM results b WHERE b.job=? AND b.ip=a.ip AND b.port=a.port AND b.status='hit')"
                counts[name] = db.execute('SELECT COUNT(*) '+query,(a,b)).fetchone()[0]
                if name == kind:
                    items = [json.loads(r[0]) for r in db.execute('SELECT a.data '+query+' ORDER BY a.ip_num,a.port LIMIT 200',(a,b))]
            statuses = [r['status'] for r in db.execute('SELECT status FROM jobs WHERE id IN (?,?)',(old,new))]
            return dict(counts=counts,items=items,kind=kind,provisional=any(s!='completed' for s in statuses))


