const $ = id => document.getElementById(id);
const labels = {running:'扫描中',stopping:'正在停止',stopped:'已停止',completed:'已完成',interrupted:'服务中断 · 可续扫',failed:'失败 · 可续扫',hit:'命中',open_not_cf:'开放 / 非 CF',closed_or_error:'连接失败'};
let selected = '', page = 1, records = [], busy = false, polling = false;
async function api(path, data) {
  const res = await fetch(path, data === undefined ? {} : {method:'POST',headers:{'Content-Type':'application/json','X-Requested-With':'CF-VPS'},body:JSON.stringify(data)});
  if (!res.ok) { let message = `请求失败 (${res.status})`; try { message = (await res.json()).error || message; } catch {} throw new Error(message); }
  return res.json();
}
function message(error) { $('notice').textContent = error ? error.message || error : ''; }
function duration(seconds) { if (seconds == null) return '—'; return seconds < 60 ? `${seconds} 秒` : `${Math.floor(seconds/3600)} 时 ${Math.floor(seconds%3600/60)} 分`; }
function renderJobs() {
  const select = $('jobs');
  select.replaceChildren();
  if (!records.some(j => j.id === selected)) selected = records[0]?.id || '';
  for (const j of records) {
    const option = document.createElement('option'); option.value = j.id;
    option.textContent = `${new Date(j.created*1000).toLocaleString()} · ${labels[j.status]} · ${j.total.toLocaleString()} 次`;
    select.append(option);
  }
  select.value = selected;
  const j = records.find(j => j.id === selected);
  const active = records.some(j => ['running','stopping'].includes(j.status));
  $('start').disabled = active || busy;
  $('stop').disabled = !active || busy;
  $('resume').disabled = active || !j || j.status === 'completed' || busy;
  if (!j) return;
  const percent = j.total ? (j.done/j.total*100) : 0;
  $('status').textContent = labels[j.status];
  $('percent').textContent = `${percent.toFixed(1)}%`;
  $('hits').textContent = j.hits.toLocaleString();
  $('rate').textContent = j.rate ?? '—';
  $('progress').value = percent;
  $('detail').textContent = `已完成 ${j.done.toLocaleString()} / ${j.total.toLocaleString()} 次 · 预计剩余 ${duration(j.eta)} · 每次探测均保存，可断点续扫`;
  $('error').textContent = j.error || '';
}
async function renderResults() {
  if (!selected) return;
  const current = selected, currentPage = page, view = $('view').value;
  const data = await api(`/api/results?id=${encodeURIComponent(current)}&view=${view}&page=${currentPage}`);
  if (current !== selected || currentPage !== page || view !== $('view').value) return;
  const body = $('rows'); body.replaceChildren();
  for (const r of data.items) {
    const tr = document.createElement('tr');
    for (const value of [`${r.ip}:${r.port}`,labels[r.status]||r.status,r.verified === '1'?'已确认':r.verified === '0'?'未确认':'—',r.latency_ms === '' || r.latency_ms == null ? '—':`${r.latency_ms} ms`,r.colo||'—',r.loc||'—',r.err||r.server||'—']) {
      const td = document.createElement('td'); td.textContent = value; tr.append(td);
    }
    body.append(tr);
  }
  if (!data.items.length) { const tr = document.createElement('tr'), td = document.createElement('td'); td.colSpan = 7; td.className = 'empty'; td.textContent = '当前筛选下暂无结果'; tr.append(td); body.append(tr); }
  $('page').textContent = `第 ${page} 页 · 共 ${data.total.toLocaleString()} 条`;
  $('prev').disabled = page <= 1; $('next').disabled = page*100 >= data.total;
  $('export').href = `/api/export?id=${encodeURIComponent(selected)}&view=${view}`;
}
async function refresh() {
  if (polling) return;
  polling = true;
  try { records = await api('/api/jobs'); renderJobs(); await renderResults(); } catch(e) { message(e); }
  finally { polling = false; }
}
async function action(path, data) {
  if (busy) return;
  busy = true; renderJobs(); message('');
  try { const result = await api(path, data); if (result.id) { selected = result.id; page = 1; } }
  catch(e) { message(e); }
  finally { busy = false; await refresh(); }
}
$('scan-form').addEventListener('submit', e => { e.preventDefault(); action('/api/start',{targets:$('targets').value,ports:$('ports').value,concurrency:Number($('concurrency').value),timeout:Number($('timeout').value),attempts:Number($('attempts').value)}); });
$('stop').onclick = () => action('/api/stop',{});
$('resume').onclick = () => action('/api/resume',{id:selected});
$('jobs').onchange = () => { selected = $('jobs').value; page = 1; renderJobs(); renderResults().catch(message); };
$('view').onchange = () => { page = 1; renderResults().catch(message); };
$('prev').onclick = () => { page--; renderResults().catch(message); };
$('next').onclick = () => { page++; renderResults().catch(message); };
$('file').onchange = async () => { const file = $('file').files[0]; if (!file) return; if (file.size > 65536) return message('文件不能超过 64 KB'); $('targets').value = await file.text(); message(''); };
refresh(); setInterval(refresh,2000);
