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
function jobLabel(j) { return `${timestamp(j.created)} · ${j.config.provider_name||'目标快照'} · ${j.config.kind==='retest'?'复测 · ':''}${labels[j.status]} · ${j.total.toLocaleString()} 次`; }
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
  if(pending){$('resume-notice-detail').textContent=`${pending.config.provider_name||'目标快照'} · 已完成 ${pending.done.toLocaleString()} / ${pending.total.toLocaleString()} 次；保留原参数并跳过已完成目标。`;$('resume-last').dataset.id=pending.id;$('view-last').dataset.id=pending.id;}
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
  b.title=`${r.favorite?'取消收藏':'收藏'} ${r.ip}`;b.setAttribute('aria-label',b.title);
  b.onclick=async()=>{b.disabled=true;try{await api('/api/favorite',{ip:r.ip,enabled:!r.favorite});epoch++;await renderResults();}catch(e){message(e);}finally{b.disabled=false;}};
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
    let td=document.createElement('td');td.append(tick);tr.append(td);td=document.createElement('td');td.append(favoriteButton(r),ipButton(r.ip,r.port));tr.append(td);td=document.createElement('td');td.className='catalog-column';td.textContent=r.provider_name||'未知来源';tr.append(td);
    const h=r.history||{},ms=r.request_ms??r.latency_ms;
    const values=[levels[r.evidence]||labels[r.status]||r.status,verifications[r.verification]||(r.verified==='1'?'旧版确认':'—'),ms===''||ms==null?'—':`${ms} ms`,r.colo||'—',regionName(r.loc),timestamp(h.first_seen),timestamp(h.last_confirmed),h.checks?`${(h.successes/h.checks*100).toFixed(0)}% (${h.successes}/${h.checks})`:'—',errors[r.error_kind]||errors[r.verify_error]||r.err||r.server||'—'];
    for(const value of values){const cell=document.createElement('td');cell.textContent=value;tr.append(cell);}
    const jobCell=document.createElement('td');jobCell.className='catalog-column';jobCell.textContent=timestamp(r.job_created)+' · '+(r.job_id||'').slice(0,8);tr.append(jobCell);
    tr.children[5].title=`连接 ${r.connect_ms??'—'} ms / TLS ${r.tls_ms??'—'} ms / 首字节 ${r.ttfb_ms??'—'} ms（从请求开始计时）`;
    body.append(tr);
  }
  if(!visible.length){const tr=document.createElement('tr'),td=document.createElement('td');td.colSpan=13;td.className='empty';td.textContent='当前筛选下暂无结果';tr.append(td);body.append(tr);}
  $('page').textContent=`第 ${page} 页 · 共 ${data.total.toLocaleString()} 条`;$('prev').disabled=!previous.length;$('next').disabled=!nextCursor;
  const query=filterQuery();query.delete('cursor');$('export').href='/api/export?'+query;selectionState();
}
async function refresh() {
  if(polling)return;polling=true;
  try {
    records=await api('/api/jobs');renderJobs();
    if(window.resultCenter)await window.resultCenter.refreshMeta();
    if(resultId()) { const id=resultId(),view=$('view').value,provider=resultProvider();const facets=await api('/api/facets?'+new URLSearchParams({id,view,provider,favorites:window.resultCenter?.favorites?'1':''}));
      if(id===resultId()&&view===$('view').value){options($('region'),facets.regions,'全部地区',regionName);options($('colo'),facets.colos,'全部机房');if(window.resultCenter?.pendingRegion){$('region').value=window.resultCenter.pendingRegion;window.resultCenter.pendingRegion='';}} }
    await renderResults();
  } catch(e){message(e);}finally{polling=false;}
}
async function action(path,data) {
  if(busy)return;busy=true;renderJobs();message('');
  try { const result=await api(path,data);if(result.id){selected=result.id;resetPage();checked.clear();if(window.resultCenter?.active)window.resultCenter.pendingJob=result.id;if(path==='/api/start')$('scan-dialog').close();} }
  catch(e){message(e);}finally{busy=false;await refresh();}
}
async function comparison() {
  try {
    const result=await api('/api/compare?'+new URLSearchParams({old:$('compare-old').value,new:$('compare-new').value,kind:$('compare-kind').value}));
    $('compare-summary').textContent=`新增 ${result.counts.new} · 本次未命中 ${result.counts.lost} · 持续命中 ${result.counts.persistent}${result.provisional?' · 含未完成任务，对比结果暂不完整':''}（最多展示 200 个）`;
    $('compare-items').replaceChildren();for(const r of result.items)$('compare-items').append(ipButton(r.ip,r.port));
  }catch(e){message(e);}
}
$('scan-form').onsubmit=e=>{e.preventDefault();action('/api/start',{targets:$('targets').value,ports:$('ports').value,concurrency:Number($('concurrency').value),timeout:Number($('timeout').value),attempts:Number($('attempts').value),rps:Number($('rps').value),adaptive:$('adaptive').checked,min_concurrency:Number($('min-concurrency').value),...(window.providerSelection?.targets===$('targets').value?{provider:window.providerSelection.id,prefixes:window.providerSelection.prefixes}:{})});};
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
