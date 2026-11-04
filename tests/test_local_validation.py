import base64
import http.client
import json
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from engine import Manager, connect, prepare
from server import make_handler

class LocalValidationTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.manager=Manager(Path(self.tmp.name)/'scan.db')
        with connect(self.manager.path) as db:
            for job in ['one','two']:
                config=prepare({'targets':'8.8.8.8','ports':'443,8443','task_name':'本地验证测试'})
                db.execute("INSERT INTO jobs(id,created,updated,status,config,total,done,hits) VALUES(?,1,1,'completed',?,2,2,2)",(job,json.dumps(config)))
                for port in [443,8443]:
                    data=dict(ip='8.8.8.8',port=port,status='hit',evidence='suspected',latency_ms=12)
                    db.execute('INSERT INTO results(job,ip,port,status,latency,data,ip_num) VALUES(?,?,?,?,?,?,?)',(job,'8.8.8.8',port,'hit',12,json.dumps(data),134744072))
        self.server=ThreadingHTTPServer(('127.0.0.1',0),make_handler(self.manager,'fixture-password-12345'))
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()
    def tearDown(self):
        self.server.shutdown();self.server.server_close();self.thread.join();self.tmp.cleanup()
    def request(self,method,path,data=None,auth=True,csrf=True):
        headers={}
        if auth:headers['Authorization']='Basic '+base64.b64encode(b'admin:fixture-password-12345').decode()
        if csrf:headers['X-Requested-With']='CF-VPS'
        if data is not None:headers['Content-Type']='application/json'
        c=http.client.HTTPConnection(*self.server.server_address,timeout=5);c.request(method,path,json.dumps(data) if data is not None else None,headers)
        r=c.getresponse();status=r.status;raw=r.read();c.close();return status,raw
    def test_exact_port_task_dedup_and_persistence(self):
        payload=dict(id='one',endpoints=[dict(ip='8.8.8.8',port=8443)]*2+[dict(ip='8.8.8.8',port=9443)])
        status,raw=self.request('POST','/api/confirmed-import',payload);d=json.loads(raw)
        self.assertEqual(status,200);self.assertEqual(d['added'],1);self.assertEqual(d['duplicates'],1);self.assertEqual(d['unmatched'],[dict(ip='8.8.8.8',port=9443)])
        self.assertEqual(self.manager.confirmed('two')['total'],0)
        self.assertEqual(self.manager.results('one',view='local_confirmed')['total'],1)
        self.assertEqual(self.manager.results('two',view='local_confirmed')['total'],0)
        data=self.manager.results('one')['items'];self.assertEqual({r['port']:r['local_confirmed'] for r in data},{443:False,8443:True})
        self.assertTrue(all(not r['favorite'] for r in data));self.assertTrue(all(r['evidence']=='suspected' for r in data))
        self.assertEqual(self.manager.import_confirmed('one',payload['endpoints'])['added'],0)
        reopened=Manager(self.manager.path);self.assertEqual(reopened.confirmed('one')['endpoints'],'8.8.8.8:8443')
        reopened.delete('one');self.assertEqual(reopened.confirmed('two')['total'],0)
        with connect(reopened.path) as db:self.assertEqual(db.execute('SELECT COUNT(*) FROM confirmed_nodes').fetchone()[0],0)
    def test_auth_csrf_export_and_remove(self):
        p=dict(id='one',endpoints=[dict(ip='8.8.8.8',port=443),dict(ip='8.8.8.8',port=8443)])
        self.assertEqual(self.request('POST','/api/confirmed-import',p,auth=False)[0],401)
        self.assertEqual(self.request('POST','/api/confirmed-import',p,csrf=False)[0],403)
        self.assertEqual(self.request('GET','/api/confirmed?id=one',auth=False)[0],401)
        self.assertEqual(self.request('GET','/api/confirmed-export?id=one',auth=False)[0],401)
        self.assertEqual(self.request('POST','/api/confirmed-import',p)[0],200)
        status,raw=self.request('GET','/api/confirmed-export?id=one&format=ips');self.assertEqual((status,raw),(200,b'8.8.8.8'))
        self.assertEqual(self.request('GET','/api/confirmed-export?id=one&format=endpoints')[1],b'8.8.8.8:443\n8.8.8.8:8443')
        self.assertEqual(self.request('POST','/api/confirmed-delete',dict(id='one',ip='8.8.8.8',port=443))[0],200)
        self.assertEqual(self.manager.confirmed('one')['endpoints'],'8.8.8.8:8443')
    def test_invalid_import_is_atomic_and_contains_no_credentials(self):
        for bad in [dict(ip='127.0.0.1',port=443),dict(ip='8.8.8.8',port=True),dict(ip='8.8.8.8',port='443'),dict(ip='vless://private',port=443)]:
            self.assertEqual(self.request('POST','/api/confirmed-import',dict(id='one',endpoints=[dict(ip='8.8.8.8',port=443),bad]))[0],400)
        self.assertEqual(self.manager.confirmed('one')['total'],0)
        for ident in [None,[],{},'missing']:
            self.assertEqual(self.request('POST','/api/confirmed-import',dict(id=ident,endpoints=[dict(ip='8.8.8.8',port=443)]))[0],400)
        self.assertNotIn(b'vless://',Path(self.manager.path).read_bytes())
