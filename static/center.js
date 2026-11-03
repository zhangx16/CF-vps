/* Task-first result navigation; scanning continues in the background. */
(()=>{const get=id=>document.getElementById(id);let last=0,loading=false,navSignature='';const center=window.resultCenter={active:false,favorites:false,jobs:[],pendingJob:'',pendingRegion:'',
 async refreshMeta(){
  if(loading||Date.now()-last<5000&&!center.pendingJob)return;loading=true;
  try{const catalog=await api('/api/catalog');center.jobs=catalog.jobs;
   const provider=get('catalog-provider').value,job=center.pendingJob||get('catalog-job').value;
   get('catalog-provider').replaceChildren();const all=document.createElement('option');all.value='';all.textContent='全部服务商';get('catalog-provider').append(all);
   for(const p of catalog.providers){const option=document.createElement('option');option.value=p.id;option.textContent=`${p.name} · ${p.records.toLocaleString()} 条`;get('catalog-provider').append(option);}
   if([...get('catalog-provider').options].some(o=>o.value===provider))get('catalog-provider').value=provider;
   fillJobs(job);center.pendingJob='';renderTaskNav();updateContext();last=Date.now();
  }catch(e){message(e);}finally{loading=false;}
 },
 activate({job='*',view='all',favorites=false}={}){
  center.active=true;center.favorites=favorites;center.pendingRegion='';document.body.classList.add('center-mode');get('catalog-context').hidden=false;get('catalog-provider').value='';fillJobs(job);get('view').value=view;get('region').value='';get('colo').value='';get('search').value='';checked.clear();resetPage();updateContext();selectionState();refresh();get('results').scrollIntoView({behavior:'instant'});if(innerWidth<768){document.body.classList.remove('nav-open');get('nav-backdrop').hidden=true;get('nav-toggle').setAttribute('aria-expanded','false');}
 },
 exit(){center.active=false;center.favorites=false;center.pendingRegion='';document.body.classList.remove('center-mode','center-all');get('catalog-context').hidden=true;get('results-title').textContent='探测记录';get('results-hint').textContent='点击 IP:端口复制纯 IP。地区为 CF 观察到的出口地区。';get('region').value='';get('colo').value='';checked.clear();resetPage();updateContext();refresh();}
};
function taskName(j){return j.task_name||j.provider_name||'自定义目标';}
function renderTaskNav(){
 const signature=JSON.stringify(center.jobs.map(j=>[j.id,j.task_name,j.provider_name,j.status,j.done,j.hits]));
 get('result-task-count').textContent=center.jobs.length.toLocaleString();
 if(signature===navSignature)return;navSignature=signature;
 const parent=get('center-task-nav');parent.replaceChildren();
 for(const j of center.jobs){const button=document.createElement('button');button.type='button';button.className='nav-item task-result-button';button.dataset.job=j.id;button.title=`${taskName(j)} · ${timestamp(j.created)} · ${j.id}`;
 const name=document.createElement('span');name.className='task-result-name';name.textContent=taskName(j);
 const meta=document.createElement('span');meta.className='task-result-meta';meta.textContent=`${timestamp(j.created)} · ${labels[j.status]||j.status}`;
 const count=document.createElement('span');count.className='task-result-meta';count.textContent=`已测 ${j.done.toLocaleString()} · 命中 ${j.hits.toLocaleString()}`;
 button.append(name,meta,count);button.onclick=()=>center.activate({job:j.id});parent.append(button);}
 if(!center.jobs.length){const empty=document.createElement('p');empty.className='hint task-nav-empty';empty.textContent='暂无测试，新建扫描后会显示在这里。';parent.append(empty);}
}
function updateContext(){
 const id=get('catalog-job').value||'*',job=center.jobs.find(j=>j.id===id);
 get('delete-result-task').hidden=!center.active||center.favorites||!job;
 get('delete-result-task').disabled=Boolean(job&&['running','stopping'].includes(job.status));
 if(center.active){get('results-title').textContent=center.favorites?'收藏夹':job?taskName(job):'全部测试结果';get('results-hint').textContent=center.favorites?'按 IP:端口收藏；相同地址与端口只显示一条最新记录。':job?`${timestamp(job.created)} · ${job.provider_name} · ${labels[job.status]||job.status} · 已测 ${job.done.toLocaleString()} · 命中 ${job.hits.toLocaleString()}。点击 IP:端口复制 IP。`:'汇总所有测试记录；选择左侧某次测试可单独查看结果。';}
 for(const b of get('center-task-nav').querySelectorAll('button')){const active=center.active&&!center.favorites&&b.dataset.job===id;b.classList.toggle('active',active);if(active)b.setAttribute('aria-current','page');else b.removeAttribute('aria-current');}
 renderTaskTargets();
 get('center-all-nav').classList.toggle('active',center.active&&!center.favorites&&id==='*');get('center-favorites-nav').classList.toggle('active',center.active&&center.favorites);
}
function fillJobs(value){get('catalog-job').replaceChildren();const all=document.createElement('option');all.value='*';all.textContent='全部测试';get('catalog-job').append(all);for(const j of center.jobs){if(get('catalog-provider').value&&j.provider!==get('catalog-provider').value)continue;const o=document.createElement('option');o.value=j.id;o.textContent=`${taskName(j)} · ${timestamp(j.created)} · ${labels[j.status]}`;get('catalog-job').append(o);}if([...get('catalog-job').options].some(o=>o.value===value))get('catalog-job').value=value;}
get('delete-result-task').onclick=async()=>{const job=center.jobs.find(j=>j.id===get('catalog-job').value);if(!job||!confirm(`删除测试“${taskName(job)}”及其探测记录？此操作不能撤销。`))return;try{await api('/api/delete',{id:job.id});last=0;await center.refreshMeta();center.activate();}catch(e){message(e);}};
get('center-favorites-nav').onclick=()=>center.activate({favorites:true});get('center-all-nav').onclick=()=>center.activate();
get('catalog-provider').onchange=()=>{fillJobs('*');get('region').value='';get('colo').value='';checked.clear();resetPage();updateContext();refresh();};get('catalog-job').onchange=()=>{get('region').value='';get('colo').value='';checked.clear();resetPage();updateContext();refresh();};
center.refreshMeta();
})();
