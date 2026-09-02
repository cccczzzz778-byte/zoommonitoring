(()=>{
  const ids=['key','meeting','pass','name','limit'];
  const save=()=>{for(const id of ids){const el=document.getElementById(id);if(el)sessionStorage.setItem(`zm_${id}`,el.value||'')}};
  const restore=()=>{for(const id of ids){const el=document.getElementById(id);const v=sessionStorage.getItem(`zm_${id}`);if(el&&v!==null&&v!=='')el.value=v}}
  restore();
  for(const id of ids){document.getElementById(id)?.addEventListener('input',save)}
  document.getElementById('zoomAuth')?.addEventListener('click',save,{capture:true});
  document.getElementById('start')?.addEventListener('click',save,{capture:true});
  const qs=new URLSearchParams(location.search);
  if(qs.get('zoom_auth')==='ok'){
    setTimeout(()=>{
      if(document.getElementById('key')?.value)document.getElementById('health')?.click();
    },400);
  }
})();
