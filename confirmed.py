"""Endpoint validation imports and exports."""
import ipaddress
import time
from db import connect


class ConfirmedMixin:
    def import_confirmed(self,ident,endpoints):
        if not isinstance(ident,str) or not ident or len(ident)>128:raise ValueError('任务 ID 无效')
        if not isinstance(endpoints,list) or not 1<=len(endpoints)<=5000:
            raise ValueError('每次回填 1–5000 个 IP:端口')
        parsed=[];seen=set()
        for item in endpoints:
            if not isinstance(item,dict):raise ValueError('回填地址格式无效')
            try:ip=ipaddress.ip_address(item.get('ip',''))
            except (ValueError,TypeError):raise ValueError('仅支持公网 IPv4 节点')
            port=item.get('port')
            if ip.version!=4 or not ip.is_global or type(port) is not int or not 1<=port<=65535:
                raise ValueError('需要公网 IPv4 和有效端口')
            key=(str(ip),port)
            if key not in seen:seen.add(key);parsed.append(key)
        matched=[];unmatched=[];added=0;now=time.time()
        with connect(self.path) as db:
            if not db.execute('SELECT 1 FROM jobs WHERE id=?',(ident,)).fetchone():raise ValueError('任务不存在')
            for ip,port in parsed:
                if not db.execute("SELECT 1 FROM results WHERE job=? AND ip=? AND port=? AND status='hit'",(ident,ip,port)).fetchone():
                    unmatched.append(dict(ip=ip,port=port));continue
                exists=db.execute('SELECT 1 FROM confirmed_nodes WHERE job=? AND ip=? AND port=?',(ident,ip,port)).fetchone()
                if exists:db.execute('UPDATE confirmed_nodes SET updated=? WHERE job=? AND ip=? AND port=?',(now,ident,ip,port))
                else:db.execute('INSERT INTO confirmed_nodes VALUES (?,?,?,?,?)',(ident,ip,port,now,now));added+=1
                matched.append(dict(ip=ip,port=port))
        return dict(matched=matched,unmatched=unmatched,added=added,existing=len(matched)-added,duplicates=len(endpoints)-len(parsed))


    def confirmed(self,ident,limit=200):
        if not isinstance(ident,str) or not ident or len(ident)>128:raise ValueError('任务 ID 无效')
        with connect(self.path) as db:
            if not db.execute('SELECT 1 FROM jobs WHERE id=?',(ident,)).fetchone():raise ValueError('任务不存在')
            rows=[dict(r) for r in db.execute('SELECT ip,port,created,updated FROM confirmed_nodes WHERE job=? ORDER BY created DESC,ip,port LIMIT ?',(ident,max(1,min(int(limit),200))))]
            total=db.execute('SELECT COUNT(*) FROM confirmed_nodes WHERE job=?',(ident,)).fetchone()[0]
            ip_count=db.execute('SELECT COUNT(DISTINCT ip) FROM confirmed_nodes WHERE job=?',(ident,)).fetchone()[0]
        ips=list(dict.fromkeys(r['ip'] for r in rows))
        return dict(items=rows,total=total,ip_count=ip_count,ips='\n'.join(ips),endpoints='\n'.join(f"{r['ip']}:{r['port']}" for r in rows))


    def confirmed_text(self,ident,format='ips'):
        if not isinstance(ident,str) or not ident or len(ident)>128:raise ValueError('任务 ID 无效')
        with connect(self.path) as db:
            if not db.execute('SELECT 1 FROM jobs WHERE id=?',(ident,)).fetchone():raise ValueError('任务不存在')
            if format=='ips':return '\n'.join(r['ip'] for r in db.execute('SELECT DISTINCT ip FROM confirmed_nodes WHERE job=? ORDER BY ip',(ident,)))
            return '\n'.join(f"{r['ip']}:{r['port']}" for r in db.execute('SELECT ip,port FROM confirmed_nodes WHERE job=? ORDER BY ip,port',(ident,)))


    def delete_confirmed(self,ident,ip,port):
        if not isinstance(ident,str) or not isinstance(ip,str) or type(port) is not int:
            raise ValueError('需要任务、IP 和端口')
        with connect(self.path) as db:
            if not db.execute('SELECT 1 FROM jobs WHERE id=?',(ident,)).fetchone():
                raise ValueError('任务不存在')
            db.execute('DELETE FROM confirmed_nodes WHERE job=? AND ip=? AND port=?',(ident,ip,port))
        return dict(ok=True)


