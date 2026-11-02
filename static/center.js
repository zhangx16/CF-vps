/* Dedicated cross-task result catalog; scanning continues in the background. */
(()=>{const get=id=>document.getElementById(id);let last=0,loading=false;const center=window.resultCenter={active:false,jobs:[],pendingJob:'',pendingRegion:'',
 async refreshMeta(){
  if(loading||Date.now()-last<5000&&!center.pendingJob)return;loading=true;
  try{const [catalog,facets]=await Promise.all([api('/api/catalog'),api('/api/facets?id=*&view=hits')]);center.jobs=catalog.jobs;
   const provider=get('catalog-provider').value,job=center.pendingJob||get('catalog-job').value;
   get('catalog-provider').replaceChildren();const all=document.createElement('option');all.value='';all.textContent='全部服务商';get('catalog-provider').append(all);
   get('center-provider-nav').replaceChildren();for(const p of catalog.providers){const option=document.createElement('option');option.value=p.id;option.textContent=`${p.name} · ${p.records.toLocaleString()} 条`;get('catalog-provider').append(option);navButton(get('center-provider-nav'),p.name,p.hits,()=>center.activate({provider:p.id}));}
   if([...get('catalog-provider').options].some(o=>o.value===provider))get('catalog-provider').value=provider;
   fillJobs(job);center.pendingJob='';get('center-region-nav').replaceChildren();for(const r of facets.regions)navButton(get('center-region-nav'),regionName(r.value),r.count,()=>center.activate({region:r.value}));
   last=Date.now();
  }catch(e){message(e);}finally{loading=false;}
 },
 activate({provider='',region='',view='hits'}={}){
  center.active=true;center.pendingRegion=region;document.body.classList.add('center-mode');get('catalog-context').hidden=false;get('results-title').textContent='结果中心';get('results-hint').textContent='跨任务分类查看与查找；点击 IP:端口复制纯 IP。';get('catalog-provider').value=provider;fillJobs('*');get('view').value=view;get('region').value=region;get('colo').value='';checked.clear();resetPage();selectionState();refresh();get('results').scrollIntoView({behavior:'instant'});if(innerWidth<768){document.body.classList.remove('nav-open');get('nav-backdrop').hidden=true;get('nav-toggle').setAttribute('aria-expanded','false');}
 },
 exit(){center.active=false;center.pendingRegion='';document.body.classList.remove('center-mode','center-all');get('catalog-context').hidden=true;get('results-title').textContent='探测记录';get('results-hint').textContent='点击 IP:端口复制纯 IP。地区为 CF 观察到的出口地区。';get('region').value='';get('colo').value='';checked.clear();resetPage();refresh();}
};
function navButton(parent,label,count,click){const button=document.createElement('button');button.className='nav-item category-button';const text=document.createElement('span');text.textContent=label;text.title=label;const badge=document.createElement('span');badge.className='category-count';badge.textContent=count.toLocaleString();button.append(text,badge);button.onclick=click;parent.append(button);}
function fillJobs(value){get('catalog-job').replaceChildren();const all=document.createElement('option');all.value='*';all.textContent='全部历史任务';get('catalog-job').append(all);for(const j of center.jobs){if(get('catalog-provider').value&&j.provider!==get('catalog-provider').value)continue;const o=document.createElement('option');o.value=j.id;o.textContent=`${timestamp(j.created)} · ${j.provider_name} · ${labels[j.status]}`;get('catalog-job').append(o);}if([...get('catalog-job').options].some(o=>o.value===value))get('catalog-job').value=value;}
get('center-all-nav').onclick=()=>center.activate({view:'all'});get('center-verified-nav').onclick=()=>center.activate({view:'verified'});
get('catalog-provider').onchange=()=>{fillJobs('*');get('region').value='';get('colo').value='';checked.clear();resetPage();refresh();};get('catalog-job').onchange=()=>{checked.clear();resetPage();refresh();};
center.refreshMeta();
})();
