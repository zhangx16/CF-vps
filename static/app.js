const $ = id => document.getElementById(id);
const labels = {running:'扫描中',stopping:'正在停止',stopped:'已暂停 · 可继续',completed:'已完成',interrupted:'服务中断 · 可续扫',failed:'失败 · 可续扫',hit:'命中',open_not_cf:'开放 / 非 CF',closed_or_error:'请求失败'};
const levels = {none:'未命中',suspected:'疑似命中',trace_valid:'Trace 有效',dual_verified:'双域名确认',legacy:'旧版结果 · 待复测'};
const verifications = {not_run:'未执行',error:'验证失败 · 可复测',confirmed:'已确认',not_confirmed:'未确认'};
const errors = {connect_timeout:'连接超时',tls_timeout:'TLS 握手超时',http_timeout:'HTTP 读取超时',connection_refused:'连接拒绝',tls_error:'TLS 握手失败',http_error:'HTTP 响应错误',connect_error:'网络连接错误'};
const regionNames = typeof Intl.DisplayNames === 'function' ? new Intl.DisplayNames(['zh-CN'],{type:'region'}) : null;
let firstJobsRender=true;
let selected='', page=1, records=[], busy=false, polling=false, cursor='', nextCursor='', previous=[], epoch=0, visible=[], checked=new Map();
try{selected=localStorage.getItem('cfvps.selectedJob')||'';}catch{}
function rememberJob(){if(selected)try{localStorage.setItem('cfvps.selectedJob',selected);}catch{}}
function regionName(code) { if (!code || code==='UNKNOWN') return '未知地区'; try { return `${regionNames?.of(code)||code} (${code})`; } catch { return code; } }
function resetPage() { page=1; cursor=''; nextCursor=''; previous=[]; epoch++; }
function message(error) { const text=error ? error.message||error : ''; $('notice').textContent=text; if($('form-error'))$('form-error').textContent=text; }
async function api(path,data) {
  const res=await fetch(path,data===undefined?{}:{method:'POST',headers:{'Content-Type':'application/json','X-Requested-With':'CF-VPS'},body:JSON.stringify(data)});
  if(!res.ok) { let text=`请求失败 (${res.status})`; try { text=(await res.json()).error||text; } catch {} throw new Error(text); }
  return res.json();
}
function duration(seconds) { if(seconds==null)return '—'; return seconds<60?`${seconds} 秒`:`${Math.floor(seconds/3600)} 时 ${Math.floor(seconds%3600/60)} 分`; }
function timestamp(value) { return value?new Date(value*1000).toLocaleString('zh-CN'):'—'; }
function jobLabel(j) { return `${j.config.task_name?j.config.task_name+' · ':''}${timestamp(j.created)} · ${j.config.provider_name||'目标快照'} · ${j.config.kind==='retest'?'复测 · ':''}${labels[j.status]} · ${j.total.toLocaleString()} 次`; }
function options(select, values, title, formatter=v=>v) {
  const previousValue=select.value; select.replaceChildren();
  if(title) { const o=document.createElement('option'); o.value='';o.textContent=title;select.append(o); }
  for(const entry of values) { const o=document.createElement('option');o.value=entry.value;o.textContent=formatter(entry.value)+(entry.count==null?'':` · ${entry.count}`);select.append(o); }
  if([...select.options].some(o=>o.value===previousValue))select.value=previousValue;
}
function resultId(){return window.resultCenter?.active?$('catalog-job').value||'*':selected;}
function resultProvider(){return window.resultCenter?.active?$('catalog-provider').value:'';}
function selectionState() {
  const active=records.some(j=>['running','stopping'].includes(j.status));
  $('retest-selected').disabled=busy||active||!checked.size||resultId()==='*';
  const contextJob=records.find(j=>j.id===resultId())||window.resultCenter?.jobs.find(j=>j.id===resultId());
  $('retest-all').disabled=busy||active||!contextJob?.hits||resultId()==='*';
  document.body.classList.toggle('center-all',Boolean(window.resultCenter?.active&&resultId()==='*'));
  $('selection-count').textContent=`已选 ${checked.size} 个`;
  $('select-all').checked=visible.length>0&&visible.every(r=>checked.has(`${r.ip}:${r.port}`));
}
function renderJobs() {
  const unfinished=records.find(j=>['running','stopping'].includes(j.status))||records.find(j=>j.id===selected&&['stopped','interrupted','failed'].includes(j.status))||records.filter(j=>['stopped','interrupted','failed'].includes(j.status)).sort((a,b)=>b.updated-a.updated)[0];
  if(firstJobsRender&&records.length){if(unfinished)selected=unfinished.id;firstJobsRender=false;}
  if(!records.some(j=>j.id===selected)) { selected=records[0]?.id||'';resetPage();checked.clear(); }
  for(const id of ['jobs','compare-old','compare-new']) {
    const select=$(id), old=select.value; select.replaceChildren();
    for(const j of records) { const o=document.createElement('option');o.value=j.id;o.textContent=jobLabel(j);select.append(o); }
    if([...select.options].some(o=>o.value===old))select.value=old;
  }
  $('jobs').value=selected;rememberJob();
  const pending=records.find(j=>j.id===selected&&['stopped','interrupted','failed'].includes(j.status))||records.filter(j=>['stopped','interrupted','failed'].includes(j.status)).sort((a,b)=>b.updated-a.updated)[0];
  const hasActive=records.some(j=>['running','stopping'].includes(j.status));
  $('resume-notice').hidden=!pending||hasActive;
  if(pending){$('resume-notice-detail').textContent=`${pending.config.task_name?pending.config.task_name+' · ':''}${pending.config.provider_name||'目标快照'} · 已完成 ${pending.done.toLocaleString()} / ${pending.total.toLocaleString()} 次；保留原参数并跳过已完成目标。`;$('resume-last').dataset.id=pending.id;$('view-last').dataset.id=pending.id;}
  $('resume-last').disabled=busy||hasActive;
  if(!$('compare-old').dataset.initialized&&records.length>=2) { $('compare-old').value=records[1].id;$('compare-new').value=records[0].id;$('compare-old').dataset.initialized='1'; }
  const j=records.find(j=>j.id===selected),active=records.some(j=>['running','stopping'].includes(j.status));
  $('start').disabled=active||busy;$('stop').disabled=!active||busy;$('resume').disabled=active||!j||j.status==='completed'||busy;
  $('delete-job').disabled=active||!j||busy;
  selectionState();
  if(!j) { $('rows').replaceChildren();$('status').textContent='等待任务';$('percent').textContent='—';$('hits').textContent='0';$('progress').value=0;$('eta').textContent='—';$('rate').textContent='—';$('detail').textContent='创建任务后，进度每两秒更新。';$('error').textContent='';return; }
  const percent=j.total?j.done/j.total*100:0;
  $('status').textContent=labels[j.status];$('percent').textContent=`${percent.toFixed(1)}%`;$('hits').textContent=j.hits.toLocaleString();$('rate').textContent=j.rate??'—';$('progress').value=percent;
  $('eta').textContent=j.eta==null?'—':j.eta<60?`${j.eta}秒`:`${Math.floor(j.eta/3600)}时${Math.floor(j.eta%3600/60)}分`; $('eta').title=duration(j.eta);
  $('detail').textContent=`已完成 ${j.done.toLocaleString()} / ${j.total.toLocaleString()} 次 · 预计剩余 ${duration(j.eta)} · 请求上限 ${j.config.rps||100}/秒`;
  $('error').textContent=j.error||'';
  const resource=j.resources||{};
  $('runtime').textContent=j.effective_concurrency?`${j.adaptive?'自适应并发':'固定并发'} ${j.effective_concurrency} / ${j.concurrency_ceiling} · ${j.concurrency_reason} · CPU ${resource.cpu_percent??'—'}% · 可用内存 ${resource.memory_available_mb??'—'} MB · 句柄 ${resource.fd_used??'—'}/${resource.fd_limit??'—'}`:`并发上限 ${j.config.concurrency||100} · ${(j.config.adaptive??true)?'自适应调整':'固定模式'}`;
}
async function copyIP(ip) {
  try {
    if(navigator.clipboard&&window.isSecureContext)await navigator.clipboard.writeText(ip);
    else { const input=document.createElement('textarea');input.value=ip;input.className='clipboard-fallback';document.body.append(input);input.select();const ok=document.execCommand('copy');input.remove();if(!ok)throw new Error('复制失败，请手动复制 IP'); }
    $('toast').textContent=`已复制 IP：${ip}`;$('toast').classList.add('visible');clearTimeout(copyIP.timer);copyIP.timer=setTimeout(()=>$('toast').classList.remove('visible'),1800);
  } catch(e) { message(e); }
}
function ipButton(ip,port) { const b=document.createElement('button');b.className='copy-ip';b.type='button';b.textContent=`${ip}:${port}`;b.title=`复制 IP：${ip}`;b.onclick=()=>copyIP(ip);return b; }
function favoriteButton(r) {
  const b=document.createElement('button');b.type='button';b.className='favorite-ip';
  b.textContent=r.favorite?'★':'☆';b.setAttribute('aria-pressed',String(Boolean(r.favorite)));
  b.title=`${r.favorite?'取消收藏':'收藏'} ${r.ip}:${r.port}`;b.setAttribute('aria-label',b.title);
  b.onclick=async()=>{b.disabled=true;try{await api('/api/favorite',{ip:r.ip,port:r.port,enabled:!r.favorite});epoch++;await renderResults();}catch(e){message(e);}finally{b.disabled=false;}};
  return b;
}
function filterQuery() { return new URLSearchParams({id:resultId(),provider:resultProvider(),favorites:window.resultCenter?.favorites?'1':'',view:$('view').value,region:$('region').value,colo:$('colo').value,search:$('search').value.trim(),sort:$('sort').value,cursor}); }
async function renderResults() {
  if(!resultId())return;
  const current=resultId(), version=epoch;
  const data=await api('/api/results?'+filterQuery());
  if(current!==resultId()||version!==epoch)return;
  nextCursor=data.next_cursor;visible=data.items;
  const body=$('rows');body.replaceChildren();
  for(const r of visible) {
    const tr=document.createElement('tr'),tick=document.createElement('input');tick.type='checkbox';tick.setAttribute('aria-label',`选择 ${r.ip}:${r.port}`);const key=`${r.ip}:${r.port}`;tick.checked=checked.has(key);
    tick.onchange=()=>{if(tick.checked)checked.set(key,{ip:r.ip,port:r.port});else checked.delete(key);selectionState();};
    let td=document.createElement('td');td.append(tick);tr.append(td);td=document.createElement('td');td.append(favoriteButton(r),ipButton(r.ip,r.port));if(r.local_confirmed){const badge=document.createElement('span');badge.className='badge';badge.textContent='本地已验证';td.append(badge);}tr.append(td);td=document.createElement('td');td.className='catalog-column';td.textContent=r.provider_name||'未知来源';tr.append(td);
    const h=r.history||{},ms=r.request_ms??r.latency_ms;
    const values=[levels[r.evidence]||labels[r.status]||r.status,verifications[r.verification]||(r.verified==='1'?'旧版确认':'—'),ms===''||ms==null?'—':`${ms} ms`,r.colo||'—',regionName(r.loc),timestamp(h.first_seen),timestamp(h.last_confirmed),h.successes?`${h.successes} 次命中 / ${h.confirmations||0} 次双域名确认`:'—',errors[r.error_kind]||errors[r.verify_error]||r.err||r.server||'—'];
    for(const value of values){const cell=document.createElement('td');cell.textContent=value;tr.append(cell);}
    const jobCell=document.createElement('td');jobCell.className='catalog-column';jobCell.textContent=(r.task_name?r.task_name+' · ':'')+timestamp(r.job_created)+' · '+(r.job_id||'').slice(0,8);tr.append(jobCell);
    tr.children[5].title=`连接 ${r.connect_ms??'—'} ms / TLS ${r.tls_ms??'—'} ms / 首字节 ${r.ttfb_ms??'—'} ms（从请求开始计时）`;
    body.append(tr);
  }
  if(!visible.length){const tr=document.createElement('tr'),td=document.createElement('td');td.colSpan=13;td.className='empty';td.textContent='当前筛选下暂无结果';tr.append(td);body.append(tr);}
  $('page').textContent=`第 ${page} 页 · 共 ${data.total.toLocaleString()} 条`;$('prev').disabled=!previous.length;$('next').disabled=!nextCursor;
  const query=filterQuery();query.delete('cursor');$('export').href='/api/export?'+query;selectionState();await renderLocalConfirmed(current);
}
async function refresh() {
  if(polling)return;polling=true;
  try {
    records=await api('/api/jobs');renderJobs();
    if(window.resultCenter)await window.resultCenter.refreshMeta();
    if(resultId()) { const id=resultId(),view=$('view').value,provider=resultProvider();const facets=await api('/api/facets?'+new URLSearchParams({id,view,provider,favorites:window.resultCenter?.favorites?'1':''}));
      if(id===resultId()&&view===$('view').value){options($('region'),facets.regions,'全部地区',regionName);options($('colo'),facets.colos,'全部机房');if(window.resultCenter?.pendingRegion){$('region').value=window.resultCenter.pendingRegion;window.resultCenter.pendingRegion='';}} }
    await renderTaskTargets();
    await renderResults();
  } catch(e){message(e);}finally{polling=false;}
}
async function action(path,data) {
  if(busy)return;busy=true;renderJobs();message('');
  try { const result=await api(path,data);if(result.id){selected=result.id;resetPage();checked.clear();if(window.resultCenter?.active)window.resultCenter.pendingJob=result.id;if(path==='/api/start'){$('scan-dialog').close();$('task-name').value='';}} }
  catch(e){message(e);}finally{busy=false;await refresh();}
}
async function comparison() {
  try {
    const result=await api('/api/compare?'+new URLSearchParams({old:$('compare-old').value,new:$('compare-new').value,kind:$('compare-kind').value}));
    $('compare-summary').textContent=`新增 ${result.counts.new} · 本次未命中 ${result.counts.lost} · 持续命中 ${result.counts.persistent}${result.provisional?' · 含未完成任务，对比结果暂不完整':''}（最多展示 200 个）`;
    $('compare-items').replaceChildren();for(const r of result.items)$('compare-items').append(ipButton(r.ip,r.port));
  }catch(e){message(e);}
}
$('scan-form').onsubmit=e=>{e.preventDefault();action('/api/start',{task_name:$('task-name').value,targets:$('targets').value,ports:$('ports').value,concurrency:Number($('concurrency').value),timeout:Number($('timeout').value),attempts:Number($('attempts').value),rps:Number($('rps').value),adaptive:$('adaptive').checked,min_concurrency:Number($('min-concurrency').value),...(window.providerSelection?.targets===$('targets').value?{provider:window.providerSelection.id,prefixes:window.providerSelection.prefixes}:{})});};
function viewPending(id){if(window.resultCenter?.active)window.resultCenter.exit();selected=id;rememberJob();resetPage();checked.clear();renderJobs();refresh();$('overview').scrollIntoView();}
$('resume-last').onclick=()=>{const id=$('resume-last').dataset.id;viewPending(id);action('/api/resume',{id});};
$('view-last').onclick=()=>viewPending($('view-last').dataset.id);
$('stop').onclick=()=>action('/api/stop',{});$('resume').onclick=()=>action('/api/resume',{id:selected});
$('delete-job').onclick=()=>{if(confirm('删除此任务及其探测记录？此操作不能撤销。'))action('/api/delete',{id:selected});};
$('retest-selected').onclick=()=>action('/api/retest',{id:resultId(),selected:[...checked.values()]});$('retest-all').onclick=()=>action('/api/retest',{id:resultId()});
$('select-all').onchange=()=>{for(const r of visible){const key=`${r.ip}:${r.port}`;if($('select-all').checked)checked.set(key,{ip:r.ip,port:r.port});else checked.delete(key);}renderResults().catch(message);};
$('jobs').onchange=()=>{selected=$('jobs').value;resetPage();checked.clear();$('region').value='';$('colo').value='';renderJobs();refresh();};
for(const id of ['view','region','colo','sort'])$(id).onchange=()=>{resetPage();if(id==='view'){$('region').value='';$('colo').value='';}refresh();};
let searchTimer;$('search').oninput=()=>{clearTimeout(searchTimer);searchTimer=setTimeout(()=>{resetPage();refresh();},300);};
$('prev').onclick=()=>{cursor=previous.pop();page--;epoch++;renderResults().catch(message);};$('next').onclick=()=>{previous.push(cursor);cursor=nextCursor;page++;epoch++;renderResults().catch(message);};
$('compare').onclick=comparison;$('compare-kind').onchange=comparison;
$('file').onchange=async()=>{const file=$('file').files[0];if(!file)return;if(file.size>65536)return message('文件不能超过 64 KB');$('targets').value=await file.text();$('targets').dispatchEvent(new Event('input'));message('');};
function closeNavigation() { document.body.classList.remove('nav-open');$('nav-backdrop').hidden=true;$('nav-toggle').setAttribute('aria-expanded','false'); }
for(const trigger of document.querySelectorAll('[data-open-scan]'))trigger.onclick=()=>{closeNavigation();message('');$('scan-dialog').showModal();$('targets').focus();};
$('close-scan').onclick=$('cancel-scan').onclick=()=>$('scan-dialog').close();
$('nav-toggle').onclick=()=>{
  if(window.innerWidth<768){const open=document.body.classList.toggle('nav-open');$('nav-backdrop').hidden=!open;$('nav-toggle').setAttribute('aria-expanded',String(open));if(open)$('sidebar').querySelector('a').focus();}
  else {const collapsed=document.body.classList.toggle('sidebar-collapsed');$('nav-toggle').setAttribute('aria-expanded',String(!collapsed));}
};
$('nav-backdrop').onclick=()=>{closeNavigation();$('nav-toggle').focus();};
document.addEventListener('keydown',e=>{
  if(!document.body.classList.contains('nav-open'))return;
  if(e.key==='Escape'){closeNavigation();$('nav-toggle').focus();}
  if(e.key==='Tab'){const targets=[...$('sidebar').querySelectorAll('a,button')];const first=targets[0],last=targets.at(-1);if(e.shiftKey&&document.activeElement===first){last.focus();e.preventDefault();}else if(!e.shiftKey&&document.activeElement===last){first.focus();e.preventDefault();}}
});
for(const a of document.querySelectorAll('a[href^="#"]'))a.onclick=e=>{const id=a.getAttribute('href').slice(1),target=$(id);if(target){e.preventDefault();if(window.resultCenter?.active)window.resultCenter.exit();if(target.tagName==='DETAILS')target.open=true;target.scrollIntoView({behavior:matchMedia('(prefers-reduced-motion:reduce)').matches?'auto':'smooth'});for(const item of document.querySelectorAll('nav .nav-item'))item.classList.toggle('active',item===a);closeNavigation();}};
$('evidence-help').onclick=()=>{$('evidence').open=true;$('evidence').scrollIntoView();closeNavigation();};
$('sort-latency').onclick=()=>{$('sort').value=$('sort').value==='latency_asc'?'latency_desc':'latency_asc';resetPage();refresh();};
$('nav-toggle').setAttribute('aria-expanded',String(window.innerWidth>=768));
$('targets').addEventListener('input',()=>{window.providerSelection=null;$('scan-source').textContent='';});
refresh();setInterval(refresh,2000);

// Export locally: credentials never enter API requests. Saved templates are opt-in browser storage.
let nodeExportScope=null,nodeExportRun=0;
$('open-node-export').onclick=()=>{nodeExportScope={query:filterQuery(),selected:[...checked.values()],name:resultExportName()};$('node-port-mode').value='candidate';$('node-scope').value=checked.size?'selected':'filtered';$('node-export-status').textContent=`已锁定当前筛选范围；勾选 ${checked.size} 个候选。`;$('node-export-dialog').showModal();renderNodeTemplateOptions();$('node-template').focus();};
function clearNodeExport(){nodeExportRun++;$('node-template').value='';$('node-output').value='';$('copy-nodes').disabled=$('download-nodes').disabled=true;$('generate-nodes').disabled=false;}
$('close-node-export').onclick=()=>$('node-export-dialog').close();$('node-export-dialog').addEventListener('close',clearNodeExport);
function buildNodeLinks(template,candidates,portMode,limit){
 const value=template.trim();if(value.length>8192||/[\r\n]/.test(value))throw new Error('请输入单条 VLESS 分享链接');
 const url=new URL(value);if(url.protocol!=='vless:'||!url.username||!url.hostname||url.password)throw new Error('VLESS 模板格式无效');
 if(!/^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/i.test(decodeURIComponent(url.username)))throw new Error('模板 UUID 无效');
 const port=Number(url.port||443);if(!Number.isInteger(port)||port<1||port>65535)throw new Error('模板端口无效');
 let name;try{name=decodeURIComponent(url.hash.slice(1))||'CF-test';}catch{name='CF-test';}
 const seen=new Set(),links=[];
 for(const r of candidates){const p=portMode==='candidate'?Number(r.port):port;const key=`${r.ip}:${p}`;if(seen.has(key))continue;seen.add(key);const node=new URL(value);node.hostname=r.ip;node.port=String(p);node.hash=encodeURIComponent(`${name} · ${key}`);links.push(node.href);if(links.length>=limit)break;}
 return links;
}
$('node-export-form').onsubmit=async e=>{e.preventDefault();const run=++nodeExportRun;$('generate-nodes').disabled=true;$('copy-nodes').disabled=$('download-nodes').disabled=true;$('node-output').value='';
 try{let template=$('node-template').value;const saved=nodeTemplates.find(n=>n.id===$('node-saved-template').value);if(saved){const named=new URL(template);named.hash=encodeURIComponent(`${saved.region} · ${saved.name}`);template=named.href;}const mode=$('node-port-mode').value,limit=Number($('node-limit').value);if(!Number.isInteger(limit)||limit<1||limit>5000)throw new Error('导出数量应在 1–5000 之间');buildNodeLinks(template,[],mode,limit);
 let links=[];
 if($('node-scope').value==='selected'){links=buildNodeLinks(template,nodeExportScope.selected,mode,limit);}
 else{const query=new URLSearchParams(nodeExportScope.query);query.delete('cursor');let next='',candidates=[],seen=new Set(),pages=0;
 do{query.set('cursor',next);query.set('limit','200');const data=await api('/api/results?'+query);if(run!==nodeExportRun)return;for(const r of data.items){const key=`${r.ip}:${mode==='candidate'?r.port:'template'}`;if(!seen.has(key)){seen.add(key);candidates.push(r);}}next=data.next_cursor;pages++;$('node-export-status').textContent=`已提取 ${candidates.length} 个不同候选…`;if(pages>=500&&next&&candidates.length<limit)throw new Error('结果过多，请先缩小筛选范围');}while(next&&candidates.length<limit);
 links=buildNodeLinks(template,candidates,mode,limit);}
 if(run!==nodeExportRun)return;if(!links.length)throw new Error('当前范围没有可导出的候选');$('node-output').value=links.join('\n');$('node-export-status').textContent=`已生成 ${links.length} 个节点。请在本地 v2rayN 测试真连接延迟。`;$('copy-nodes').disabled=$('download-nodes').disabled=false;
 }catch(e){if(run===nodeExportRun)$('node-export-status').textContent=e.message;}finally{if(run===nodeExportRun)$('generate-nodes').disabled=false;}
};
$('copy-nodes').onclick=async()=>{try{await navigator.clipboard.writeText($('node-output').value);$('node-export-status').textContent='已复制，在 v2rayN 按 Ctrl+V 导入。';}catch{$('node-output').select();$('node-export-status').textContent='请按 Ctrl+C 复制选中的链接。';}};
$('download-nodes').onclick=()=>{const url=URL.createObjectURL(new Blob([$ ('node-output').value],{type:'text/plain;charset=utf-8'}));const a=document.createElement('a');a.href=url;a.download=safeTextFilename(nodeExportScope?.name);a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);};

const NODE_LIBRARY_KEY='cfvps.nodeTemplates.v1';let nodeTemplates=[];
try{const saved=JSON.parse(localStorage.getItem(NODE_LIBRARY_KEY)||'[]');if(Array.isArray(saved)&&saved.length<=200)nodeTemplates=saved.filter(n=>typeof n.id==='string'&&typeof n.name==='string'&&typeof n.region==='string'&&typeof n.link==='string'&&n.link.length<=8192);}catch{}
function persistNodeTemplates(next){try{localStorage.setItem(NODE_LIBRARY_KEY,JSON.stringify(next));}catch{throw new Error('浏览器无法保存模板，请检查存储权限或空间。');}nodeTemplates=next;renderNodeLibrary();renderNodeTemplateOptions();}
function invalidateNodeOutput(){nodeExportRun++;$('node-output').value='';$('copy-nodes').disabled=$('download-nodes').disabled=true;$('generate-nodes').disabled=false;}
function renderNodeTemplateOptions(){const region=$('node-region-filter').value,id=$('node-saved-template').value;$('node-region-filter').replaceChildren(new Option('全部地区',''));for(const r of [...new Set(nodeTemplates.map(n=>n.region))].sort())$('node-region-filter').add(new Option(r,r));if([...$('node-region-filter').options].some(o=>o.value===region))$('node-region-filter').value=region;$('node-saved-template').replaceChildren(new Option('临时粘贴链接',''));for(const n of nodeTemplates.filter(n=>!$('node-region-filter').value||n.region===$('node-region-filter').value))$('node-saved-template').add(new Option(`${n.region} · ${n.name}`,n.id));if([...$('node-saved-template').options].some(o=>o.value===id))$('node-saved-template').value=id;}
function renderNodeLibrary(){const list=$('library-list');list.replaceChildren();for(const n of nodeTemplates){const row=document.createElement('div');row.className='node-library-row';const text=document.createElement('span');text.textContent=`${n.region} · ${n.name}`;const edit=document.createElement('button');edit.type='button';edit.textContent='修改';edit.onclick=()=>{const name=prompt('节点名称',n.name);if(name===null)return;const region=prompt('节点地区',n.region);if(region===null)return;if(!name.trim()||name.length>60||!region.trim()||region.length>40){$('library-status').textContent='名称应为 1–60 字，地区应为 1–40 字。';return;}try{persistNodeTemplates(nodeTemplates.map(x=>x.id===n.id?{...x,name:name.trim(),region:region.trim()}:x));}catch(e){$('library-status').textContent=e.message;}};const del=document.createElement('button');del.type='button';del.textContent='删除';del.onclick=()=>{if(!confirm(`删除模板“${n.name}”？`))return;try{persistNodeTemplates(nodeTemplates.filter(x=>x.id!==n.id));if($('node-saved-template').value===n.id||$('node-template').value===n.link){$('node-template').value='';$('node-saved-template').value='';invalidateNodeOutput();}}catch(e){$('library-status').textContent=e.message;}};row.append(text,edit,del);list.append(row);}if(!nodeTemplates.length)list.textContent='暂无节点模板，请在上方导入。';}
function openNodeLibrary(){renderNodeLibrary();$('library-status').textContent=`已保存 ${nodeTemplates.length} 个模板。`;$('node-library-dialog').showModal();$('library-region').focus();closeNavigation();}
$('open-node-library').onclick=$('export-manage-nodes').onclick=openNodeLibrary;
$('close-node-library').onclick=()=>$('node-library-dialog').close();$('node-library-dialog').addEventListener('close',()=>{$('library-links').value='';$('library-file').value='';});
$('node-library-form').onsubmit=e=>{e.preventDefault();try{const region=$('library-region').value.trim(),prefix=$('library-name').value.trim(),text=$('library-links').value;if(!region||region.length>40||prefix.length>60||text.length>262144)throw new Error('请输入地区，名称最多 60 字，导入内容最多 256 KB');const lines=text.split(/\r?\n/).map(x=>x.trim()).filter(Boolean);if(!lines.length||lines.length>200)throw new Error('每次导入 1–200 条 VLESS 链接');const next=[...nodeTemplates];let added=0;for(let i=0;i<lines.length;i++){try{buildNodeLinks(lines[i],[],'template',1);}catch{throw new Error(`第 ${i+1} 行不是有效的 VLESS 节点，未保存本次导入。`);}if(next.some(n=>n.link===lines[i]))continue;const u=new URL(lines[i]);let alias;try{alias=decodeURIComponent(u.hash.slice(1));}catch{alias='';}const name=(prefix?(lines.length===1?prefix:`${prefix} · ${alias||i+1}`):alias||u.hostname).slice(0,60);next.push({id:crypto.randomUUID(),name,region,link:lines[i]});added++;}if(next.length>200)throw new Error('最多保存 200 个节点模板');persistNodeTemplates(next);$('library-links').value='';$('library-status').textContent=`已导入 ${added} 个，跳过 ${lines.length-added} 个重复链接；共 ${next.length} 个模板。`;}catch(e){$('library-status').textContent=e.message;}};
$('library-file').onchange=async()=>{const file=$('library-file').files[0];if(!file)return;if(file.size>262144){$('library-status').textContent='文件不能超过 256 KB';return;}$('library-links').value=await file.text();$('library-status').textContent='文件已读取，请选择地区后点击导入保存。';};
$('node-region-filter').onchange=()=>{$('node-saved-template').value='';$('node-template').value='';invalidateNodeOutput();renderNodeTemplateOptions();};
$('node-saved-template').onchange=()=>{const n=nodeTemplates.find(n=>n.id===$('node-saved-template').value);$('node-template').value=n?.link||'';invalidateNodeOutput();};
$('node-template').addEventListener('input',()=>{$('node-saved-template').value='';invalidateNodeOutput();});
$('node-export-dialog').addEventListener('close',()=>{$('node-saved-template').value='';});

let targetDetail=null,targetDetailId='',targetDetailVersion=0;
async function renderTaskTargets(){
 const id=resultId(),box=$('task-targets');if(!id||id==='*'){box.hidden=true;targetDetail=null;targetDetailId='';targetDetailVersion++;return;}
 box.hidden=false;if(targetDetailId===id)return;const version=++targetDetailVersion;targetDetailId=id;targetDetail=null;$('task-targets-text').value='';$('task-targets-meta').textContent='正在读取任务目标快照…';$('task-targets-status').textContent='';$('task-targets-note').textContent='';$('copy-task-targets').disabled=$('download-task-targets').disabled=true;
 try{const detail=await api('/api/job?'+new URLSearchParams({id}));if(version!==targetDetailVersion||id!==resultId()){if(targetDetailId===id)targetDetailId='';return;}targetDetail=detail;$('task-targets-text').value=detail.target_text;$('task-targets-meta').textContent=`${detail.task_name||detail.provider_name} · ${detail.networks.length} 个合并后网段 · 端口 ${detail.ports.join(', ')} · ${detail.total.toLocaleString()} 次目标探测`;
 $('task-targets-note').textContent=(detail.target_kind==='original'?'下方保留创建任务时输入或选定的网段文本，实际扫描会合并重叠网段。':'此任务未保存原始输入文本，下方显示创建时保存的网段快照。')+(detail.kind==='retest'?' 此任务为复测：这里展示继承的原任务网段，实际仅复测选中项或原任务命中项。':'');$('copy-task-targets').disabled=$('download-task-targets').disabled=!detail.target_text;
 }catch(e){if(version===targetDetailVersion){targetDetailId='';$('task-targets-meta').textContent='读取任务网段失败';$('task-targets-status').textContent=e.message;}}
}
$('copy-task-targets').onclick=async()=>{if(!targetDetail)return;try{await navigator.clipboard.writeText(targetDetail.target_text);$('task-targets-status').textContent='已复制任务网段。';}catch{$('task-targets-text').focus();$('task-targets-text').select();$('task-targets-status').textContent='请按 Ctrl+C 复制选中的网段。';}};
$('download-task-targets').onclick=()=>{if(!targetDetail)return;const name=(targetDetail.task_name||targetDetail.provider_name||'任务网段').replace(/[\x00-\x1f\x7f<>:"/\\|?*]/g,'_').replace(/^[ .]+|[ .]+$/g,'').slice(0,100)||'任务网段';const url=URL.createObjectURL(new Blob([targetDetail.target_text],{type:'text/plain;charset=utf-8'}));const link=document.createElement('a');link.href=url;link.download=name+'-网段.txt';link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);};

// Desktop returns endpoints only. Keep local verification separate from CF evidence.
let localConfirmedID='',localConfirmedAt=0;
async function renderLocalConfirmed(id,force=false){
 const panel=$('local-confirmed');if(!panel.open)return;
 if(id==='*'||!id){$('local-confirmed-status').textContent='请先选择左侧的具体测试任务。';$('local-confirmed-rows').replaceChildren();$('local-confirmed-ips').hidden=$('local-confirmed-endpoints').hidden=true;return;}
 if(!force&&id===localConfirmedID&&Date.now()-localConfirmedAt<10000)return;
 const d=await api('/api/confirmed?'+new URLSearchParams({id}));if(id!==resultId())return;localConfirmedID=id;localConfirmedAt=Date.now();
 $('local-confirmed-status').textContent=`已回填 ${d.total} 个 IP:端口，${d.ip_count} 个不同 IP。${d.total>200?'以下预览最近 200 条，导出包含全部通过记录。':''}`;
 for(const [key,format] of [['local-confirmed-ips','ips'],['local-confirmed-endpoints','endpoints']]){$(key).hidden=!d.total;$(key).href='/api/confirmed-export?'+new URLSearchParams({id,format});}
 const body=$('local-confirmed-rows');body.replaceChildren();for(const r of d.items){const tr=document.createElement('tr'),ip=document.createElement('td'),when=document.createElement('td'),action=document.createElement('td'),remove=document.createElement('button');ip.append(ipButton(r.ip,r.port));when.textContent=timestamp(r.updated);remove.textContent='移除标记';remove.onclick=async()=>{try{await api('/api/confirmed-delete',{id,ip:r.ip,port:r.port});epoch++;await renderLocalConfirmed(id,true);await renderResults();}catch(e){message(e)}};action.append(remove);tr.append(ip,when,action);body.append(tr);}
}
$('local-confirmed').addEventListener('toggle',()=>{if($('local-confirmed').open)renderLocalConfirmed(resultId(),true).catch(message);});

function resultExportName(){const id=resultId();if(id==='*')return window.resultCenter?.favorites?'收藏夹':'全部测试结果';const item=window.resultCenter?.jobs.find(j=>j.id===id);return item?.task_name||jobs.find(j=>j.id===id)?.config?.task_name||item?.provider_name||'测试结果';}
function safeTextFilename(name){return ([...(name||'测试结果').replace(/[\x00-\x1f\x7f<>:"/\\|?*]/g,'_').replace(/^[ .]+|[ .]+$/g,'')].slice(0,100).join('')||'测试结果')+'.txt';}
