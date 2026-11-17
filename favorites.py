"""Independent endpoint favorite snapshots."""
import ipaddress
import json
import time
from db import connect


class FavoritesMixin:
    def favorite(self, ip, port, enabled):
        try:
            address = ipaddress.ip_address(ip)
        except (ValueError, TypeError):
            raise ValueError('IP 无效')
        if address.version != 4 or not address.is_global or not isinstance(enabled, bool) or type(port) is not int or not 1<=port<=65535:
            raise ValueError('需要公网 IPv4、有效端口和布尔收藏状态')
        ip = str(address)
        with connect(self.path) as db:
            if enabled:
                db.execute('INSERT OR IGNORE INTO endpoint_favorites(ip,port,created) VALUES (?,?,?)',(ip,port,time.time()))
                db.execute('DELETE FROM favorite_snapshots WHERE ip=? AND port=?',(ip,port))
                db.execute('INSERT INTO favorite_snapshots SELECT rowid,* FROM results WHERE ip=? AND port=? ORDER BY rowid DESC LIMIT 1',(ip,port))
                snapshot=db.execute('SELECT saved_rowid,job,data FROM favorite_snapshots WHERE ip=? AND port=?',(ip,port)).fetchone()
                if snapshot:
                    data=json.loads(snapshot['data'])
                    source=self.job_sources().get(snapshot['job'],{})
                    data.update(task_name=source.get('task_name',data.get('task_name','')),provider_name=source.get('provider_name',data.get('provider_name','未知来源')),job_created=source.get('created',data.get('job_created')))
                    db.execute('UPDATE favorite_snapshots SET data=? WHERE saved_rowid=?',(json.dumps(data),snapshot['saved_rowid']))
            else:
                db.execute('DELETE FROM endpoint_favorites WHERE ip=? AND port=?',(ip,port))
                db.execute('DELETE FROM favorite_snapshots WHERE ip=? AND port=?',(ip,port))
        return dict(ip=ip,port=port,favorite=enabled)


