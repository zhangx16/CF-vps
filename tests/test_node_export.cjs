// Test the production export functions without a browser or third-party packages.
const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const text=fs.readFileSync('static/app.js','utf8');
const start=text.indexOf('function buildNodeLinks('),end=text.indexOf('function selectedExportTemplates(');
const context=vm.createContext({URL,Set});vm.runInContext(text.slice(start,end),context);
const a='vless://11111111-1111-4111-8111-111111111111@8.8.4.4:443?security=tls&type=ws&sni=one.example&host=one.example&path=%2Ftest%3Fed%3D2048#HK';
const b='vless://22222222-2222-4222-8222-222222222222@1.0.0.1:443?security=tls&type=ws&sni=two.example&host=two.example&path=%2Fother#US';
const candidates=[{ip:'8.8.8.8',port:443,ip_country:'HK'},{ip:'8.8.8.8',port:8443,ip_country:'UNKNOWN'},{ip:'8.8.8.8',port:443,ip_country:'HK'}];
const links=context.combineNodeTemplates([a,b],candidates,'candidate',500);
assert.equal(links.length,4);
for(let i=0;i<links.length;i++){
 const node=new URL(links[i]),template=new URL(i<2?a:b);
 assert.equal(node.username,template.username);assert.equal(node.search,template.search);assert.equal(node.hostname,'8.8.8.8');
 assert.equal(node.port,i%2?'8443':'443');
 assert.ok(decodeURIComponent(node.hash).includes(i%2?'IP地区:未知':'IP地区:HK'));
}
assert.equal(context.combineNodeTemplates([a,b],candidates,'template',500).length,2);
assert.equal(context.combineNodeTemplates([a,b],candidates,'candidate',1).length,2);
assert.equal(context.combineNodeTemplates([a,a],candidates,'candidate',500).length,2);
assert.throws(()=>context.combineNodeTemplates(Array(21).fill(a),candidates,'candidate',1));
assert.throws(()=>context.buildNodeLinks('invalid',candidates,'candidate',1));
const many=Array.from({length:5000},(_,i)=>({ip:`8.8.${Math.floor(i/256)}.${i%256}`,port:443}));
const templates=Array.from({length:5},(_,i)=>a+'-'+i);
assert.throws(()=>context.combineNodeTemplates(templates,many,'candidate',5000),/20000/);
console.log('Node export tests passed: multiple templates, unknown countries, exact ports, preserved credentials/transport, limits and dedup.');
