import {tour, stopTour, needsIntroduction, markIntroduced} from "./onboarding.js";
import {sourceLines, sourceSelection, sourceWindowStart, reviewAdvice, reviewText} from "./evidence-ui.mjs";
"use strict";
const el = id => document.getElementById(id);
const token = document.querySelector('meta[name="evidence-token"]').content;
const kinds = {source_location:"源码引用", entry_point:"入口角色", critical_operation:"关键操作", trace:"调用链", fix_commit:"修复提交"};
const verdicts = {supported:"证据支持", contradicted:"与源码矛盾", uncertain:"证据不足"};
const phases = {repository:"查找本地代码与版本", advisory:"匹配公告", source:"读取源码证据", judge:"模型主审", critic:"反证复核", complete:"复核完成"};
const failureStates = new Set(["not_configured", "model_or_contract_failed", "context_budget_exceeded"]);
const clone = value => JSON.parse(JSON.stringify(value));
const topic = claim => claim.kind==="source_location"?"源码位置":/DNS|私网|重定向/.test(claim.text)?"网络防护":/URL\s*编码|点号/.test(claim.text)?"参数编码":claim.text.slice(0,18);
const chars = text => Array.from(text);
const identifier = prefix => prefix + "-" + Date.now() + "-" + (++serial);
let serial=0, view="import", busy=false, config=null, demo=null, repositoryState=null;
let context={case_id:"case-"+Date.now(), repo_url:"", reviewed_commit:"", vuln_ids:[], source_link:""};
let projectKind="project";
let candidates=[], selectedCandidate=0, candidatePage=0, extraction=null, selectedResult=0, resultPage=0;
let result=null, jobId=null, activeRequest=null, statusSequence=0, taskEpoch=0, toastTimer;
let presentation="live", savedDemo=null, selectedSource=null;
let tutorial=null;
const tutorialReturnKey="vulngym-evidence-tutorial-return-v1";
const tutorialStateKey="vulngym-evidence-tutorial-state-v1";
const draftKey="vulngym-evidence-draft-v3", historyKey="vulngym-evidence-recent-v2";
function node(tag, text, className) {const n=document.createElement(tag); if(text!==undefined)n.textContent=text; if(className)n.className=className; return n;}
function button(text, action, className="secondary") {const b=node("button",text,className); b.type="button"; b.onclick=action; return b;}
async function api(path, value) {
  const response=await fetch(path, value===undefined?{}:{method:"POST",headers:{"Content-Type":"application/json","X-Evidence-Token":token},body:JSON.stringify(value)});
  let body; try{body=await response.json();}catch{throw new Error("本地服务没有返回有效响应，请检查终端。");}
  if(!response.ok){const e=new Error(body.error||"请求未完成。");e.status=response.status;e.record=body;throw e;} return body;
}
function toast(text) {el("toast").textContent=text;el("toast").classList.remove("hidden");clearTimeout(toastTimer);toastTimer=setTimeout(()=>el("toast").classList.add("hidden"),5500);}
function message(text) {el("footer-tip").textContent=text;}

async function downloadPublicReport(event, format) {
  if(!config?.read_only_demo)return;
  event.preventDefault();
  const link=event.currentTarget;
  if(link.dataset.downloading==="true")return;
  const filename=format==="md"?"report.md":"result.json";
  const contentType=format==="md"?"text/plain":"application/json";
  link.dataset.downloading="true";
  try {
    // Read inside the authenticated Studio frame before asking Edge to save.
    // A native download request may lose the private frame's authentication.
    const response=await fetch("/demo-reports/"+filename,{credentials:"same-origin"});
    if(!response.ok)throw new Error("报告导出失败（HTTP "+response.status+"），请刷新空间后重试。");
    if(!response.headers.get("Content-Type")?.toLowerCase().startsWith(contentType))
      throw new Error("平台没有返回报告文件，请刷新空间后重试。");
    const text=await response.text();
    if(!text.trim())throw new Error("报告内容为空，请刷新空间后重试。");
    if(format==="json")JSON.parse(text);
    const url=URL.createObjectURL(new Blob([text],{type:contentType+";charset=utf-8"}));
    const save=document.createElement("a");
    save.href=url;save.download=filename;
    document.body.append(save);save.click();save.remove();
    setTimeout(()=>URL.revokeObjectURL(url),60000);
    toast("已交给浏览器保存 "+filename+"；如有提示，请在下载栏确认。");
  } catch(error) {
    toast(error.message||"报告导出失败，请刷新空间后重试。");
  } finally {
    delete link.dataset.downloading;
  }
}

// Each editor holds the complete text; pagination never changes the submitted content.
function pagedText(control, pager, editable=false, changed=()=>{}) {
  let text="", pages=[""], page=0, timer, rendering=false;
  const previous=button("上一页",()=>{commit();page--;paint();},""), next=button("下一页",()=>{commit();page++;paint();},"");
  const count=node("span","1 / 1"), controls=node("div",undefined,"pager-controls"); controls.append(previous,count,next);
  if(pager===el("report").nextElementSibling){el("previous-page").remove();el("next-page").remove();el("page-number").remove();pager.querySelector(".pager-controls").replaceWith(controls);}else pager.replaceChildren(node("span",""),controls);
  function commit(){if(editable&&!rendering){pages[page]=control.value;text=pages.join("");}}
  function paint(){rendering=true;control.value=pages[page];control.scrollTop=0;count.textContent=(page+1)+" / "+pages.length;pager.classList.toggle("hidden",pages.length===1);previous.disabled=page===0;next.disabled=page===pages.length-1;rendering=false;}
  function reflow(){
    if(!control.clientHeight||!control.clientWidth)return;
    commit();const offset=pages.slice(0,page).join("").length, rect=control.getBoundingClientRect(), measure=control.cloneNode();
    measure.removeAttribute("id");measure.tabIndex=-1;measure.setAttribute("aria-hidden","true");
    Object.assign(measure.style,{position:"fixed",left:"-20000px",top:"0",width:rect.width+"px",height:rect.height+"px",flex:"none",visibility:"hidden"});document.body.append(measure);
    const output=[];let start=0;
    while(start<text.length){let low=1,high=text.length-start,best=1;while(low<=high){const mid=Math.floor((low+high)/2);measure.value=text.slice(start,start+mid);if(measure.scrollHeight<=measure.clientHeight+1){best=mid;low=mid+1;}else high=mid-1;}if(best>1&&/[\uD800-\uDBFF]/.test(text[start+best-1]))best--;output.push(text.slice(start,start+best));start+=best;}
    measure.remove();pages=output.length?output:[""];page=0;let at=0;for(let i=0;i<pages.length;i++){if(offset<at+pages[i].length||i===pages.length-1){page=i;break;}at+=pages[i].length;}paint();
  }
  if(editable)control.addEventListener("input",()=>{commit();changed(text);if(control.scrollHeight>control.clientHeight+1)reflow();});
  new ResizeObserver(()=>{clearTimeout(timer);timer=setTimeout(reflow,40);}).observe(control);
  return {get:()=>{commit();return text;},set:value=>{text=value||"";pages=[text];page=0;paint();requestAnimationFrame(reflow);},reflow};
}
// The editable textarea always owns the complete report; Ctrl+A never selects only a preview page.
const report={get:()=>el("report").value,set:value=>{el("report").value=value||"";},reflow:()=>{}};
el("report").addEventListener("input",()=>{invalidateReport();saveDraft();});
const quote=pagedText(el("candidate-quote"),el("quote-pager"));
const reason=pagedText(el("result-reason"),el("reason-pager"));
const source={set:()=>el("code").replaceChildren(),reflow:()=>{}};
function invalidateReport(){candidates=[];extraction=null;candidatePage=0;result=null;jobId=null;activeRequest=null;clearJobURL();el("report-source").textContent="报告需包含文件位置与引用代码";updateActions();message("报告已更改，请重新提取核查内容。");}
function clearJobURL(){const url=new URL(location.href);url.searchParams.delete("job");url.searchParams.delete("demo");history.replaceState(null,"",url);}
function invalidateResult(){result=null;jobId=null;activeRequest=null;presentation="live";clearJobURL();updateActions();saveDraft();}
function setBusy(value){busy=value;document.querySelectorAll("main button, main input, main select, main textarea").forEach(n=>{n.disabled=value;});updateActions();if(!value){if(view==="confirm")renderCandidates();if(view==="results"&&result)renderResults();report.reflow();quote.reflow();reason.reflow();source.reflow();}}
function updateActions(){
  const preview=presentation==="demo", onlineDemo=Boolean(config?.read_only_demo);
  document.body.classList.toggle("public-demo",onlineDemo);

  el("advanced-options").classList.toggle("hidden",onlineDemo);
  el("model-settings").disabled=busy||onlineDemo;
  el("back-button").classList.toggle("hidden",view==="import"||preview);
  el("save-input").classList.toggle("hidden",view!=="confirm"||onlineDemo);
  el("new-task").classList.toggle("hidden",view!=="results"||busy||onlineDemo);
  el("new-task").textContent=preview?"亲自运行同一报告":"新报告";
  el("export-wrap").classList.toggle("hidden",view!=="results"||!result);
  el("next-button").classList.toggle("hidden",view==="results"||onlineDemo);
  const selected=candidates.filter(c=>c.selected), count=selected.length;
  const needsModel=selected.some(c=>!["source_location","fix_commit"].includes(c.claim.kind));
  const missingModel=view==="confirm"&&needsModel&&!config?.model_ready;
  const missingSource=!repositoryState?.ready;
  el("selected-count").textContent="已选 "+count+" / "+candidates.length+" 项";
  el("next-button").textContent=busy?(view==="import"?"正在提取…":"正在复核…"):
    view==="import"?(missingSource?"请先连接项目":!report.get().trim()?"请先导入报告":!config?.model_ready?"请先配置模型":"提取核查内容 →"):
    missingSource?"连接源码后复核":missingModel?"配置模型后复核":"确认并复核 "+count+" 项 →";
  el("next-button").disabled=busy||(view==="import"?
    !config?.model_ready||!repositoryState?.ready||!report.get().trim():
    !count||missingSource||missingModel||selected.some(c=>missing(c.claim).length));
  el("save-input").disabled=busy||!count||selected.some(c=>missing(c.claim).length);
  el("prepared-demo").classList.toggle("hidden",onlineDemo);
  el("history").classList.toggle("hidden",onlineDemo);
  el("repository-help").classList.toggle("hidden",onlineDemo);
  el("settings").classList.toggle("hidden",onlineDemo);
  el("prepared-demo").disabled=busy;
  el("view-demo").disabled=busy;
  el("setup-message").textContent=onlineDemo?"只读案例 · 无需 Key":!config?.model_ready?"AI 未配置":config.connection_state==="verified"?"AI 已配置 · 测试通过":config.connection_state==="failed"?"AI 已配置 · 上次测试失败":"AI 已配置 · 连接未测试";
  el("setup-card").classList.toggle("ready",config?.connection_state==="verified");
  for(const id of ["import-json","change-project","settings","load-demo","clear-report","report-file","import-report","other-examples"]){
    el(id).disabled=busy||onlineDemo;
  }
  el("report").disabled=busy;el("report").readOnly=onlineDemo;
  const modelLabel=config?.provider==="qwen"?"通义":"兼容接口";
  const connectionLabel=config?.connection_state==="verified"?"测试通过":config?.connection_state==="failed"?"测试失败":"未验证";
  el("mode").textContent=onlineDemo?"只读案例 · 无需 Key":config?.model_ready?
    modelLabel+" · "+(config.model_name||config.provider)+" · "+connectionLabel:"AI 未配置";
  document.querySelectorAll(".step").forEach(b=>{
    if(b.dataset.view===view)b.setAttribute("aria-current","step");else b.removeAttribute("aria-current");
    b.disabled=busy||(b.dataset.view==="confirm"&&(!candidates.length||preview||onlineDemo))||
      (b.dataset.view==="results"&&!result&&!jobId);
  });
  el("change-project").classList.toggle("primary",!context.repo_url);
  el("change-project").classList.toggle("secondary",Boolean(context.repo_url));
  document.body.classList.toggle("case-teaching",Boolean(tutorial));
  el("case-guide").classList.toggle("hidden",!tutorial);
  el("start-guide").disabled=busy;
  el("export-button").textContent=tutorial?"导出完整案例 ▾":"导出报告 ▾";
  if(tutorial){
    el("report").readOnly=true;
    for(const id of ["change-project","load-demo","import-report","clear-report","manual-claim","edit-candidate","remove-candidate","extraction-record","model-settings","usage-guide","history","view-demo","start-guide"]){el(id).disabled=true;}
    el("save-input").classList.add("hidden");el("new-task").classList.add("hidden");el("back-button").classList.toggle("hidden",view==="import");
    el("next-button").classList.toggle("hidden",view==="results");
    el("next-button").textContent=view==="import"?"查看案例核查项 →":"查看所选项的已有结果 →";
    el("next-button").disabled=view==="confirm"&&!count;
    document.querySelectorAll(".step").forEach(b=>{b.disabled=["import","confirm","results"].indexOf(b.dataset.view)>tutorial.progress;});
    el("guide-title").textContent={import:"1 / 3 · 先看报告",confirm:"2 / 3 · 确认要核对什么",results:"3 / 3 · 查看结论和源码依据"}[view];
    el("guide-text").textContent={import:"案例已准备好：左边是代码版本，右边是报告。读完后，点击右下“查看案例核查项”。",confirm:"点击右侧条目，对照左边原句；勾选本次要看的项，再点击右下按钮。",results:"点击左侧切换结论，阅读右侧理由和源码；可复制单条意见或导出完整案例。看完点击“完成教学”。"}[view];
    el("exit-guide").textContent=view==="results"?"完成教学":"退出教学";
    el("workflow-note").textContent="案例回放 · 已有记录 · 不调用模型";
  }else{el("workflow-note").textContent="对照代码，核对报告";}
}
function showView(next){if(busy)return;stopTour();
  if(tutorial&&next==="results"&&!result){showTutorialResults();return;}
  if(presentation==="demo"&&next!=="results"&&!tutorial){presentation="live";result=null;jobId=null;clearJobURL();}
  view=next;document.querySelectorAll(".view").forEach(n=>n.classList.toggle("active",n.id===view));document.querySelectorAll(".step").forEach(n=>n.classList.toggle("active",n.dataset.view===view));updateActions();if(view==="confirm")renderCandidates();if(view==="results"&&result)renderResults();if(tutorial){saveTutorial();const url=new URL(location.href);url.searchParams.set("tutorial",view);history.replaceState(null,"",url);message("案例回放：这里展示已有记录，不调用模型。");}else if(!busy){message(next==="import"?"连接项目并导入报告，再提取核查内容。":next==="confirm"?"对照原句，勾选本次需要复核的条目。":result?"已复核 "+result.results.length+" 项。点击左侧查看依据。":"正在读取任务…");}requestAnimationFrame(()=>{report.reflow();quote.reflow();reason.reflow();source.reflow();});}
function forceView(next){const was=busy;busy=false;showView(next);busy=was;updateActions();}
function openDialog(title, build){stopTour();el("detail-dialog").oncancel=null;el("dialog-body").classList.remove("welcome-content");el("detail-dialog").classList.toggle("model-dialog",title==="模型设置");el("close-dialog").disabled=false;el("dialog-title").textContent=title;el("detail-dialog").classList.toggle("wide-source",title==="源码与证据");el("detail-dialog").classList.toggle("repository-dialog",title==="连接本地源码");const body=el("dialog-body");body.replaceChildren();build(body);if(!el("detail-dialog").open)el("detail-dialog").showModal();}
function readDialog(title, text){openDialog(title,body=>{const area=node("textarea",undefined,"report-text dialog-reader");area.readOnly=true;area.value=text;area.setAttribute("aria-label",title);const pager=node("div",undefined,"pager");body.append(area,pager);const reader=pagedText(area,pager);reader.set(text);});}
function closeDialog(){stopTour();el("dialog-body").querySelectorAll('#setup-key,input[type="password"]').forEach(input=>{input.value="";});el("detail-dialog").close();}
function field(body,label,value="",multiline=false){const wrap=node("label",label),control=node(multiline?"textarea":"input",undefined,"field");control.value=value;control.spellcheck=false;wrap.append(control);body.append(wrap);return control;}
function links(body,items){items.forEach(([label,url])=>{const a=node("a",label,"secondary");a.href=url;a.download="";body.append(a);});}
function projectLabel(url){try{return new URL(url).pathname.replace(/^\//,"").replace(/\.git$/,"").replace("/"," / ");}catch{return url;}}
async function checkRepository(){
  const seq=++statusSequence;repositoryState=null;el("repository-state").textContent="正在检查本地源码…";
  try{const state=await api("/api/repository-status",{repo_url:context.repo_url,reviewed_commit:context.reviewed_commit});if(seq!==statusSequence)return;repositoryState=state;el("repository-state").textContent=state.message;updateActions();el("repository-state").classList.toggle("warning",!state.ready);}catch(e){if(seq!==statusSequence)return;el("repository-state").textContent=e.message;}
}
function renderProject(){
  const connected=Boolean(context.repo_url&&context.reviewed_commit);
  el("project-selection").classList.toggle("hidden",!connected);
  el("version-section").classList.toggle("hidden",!connected);
  el("change-project").textContent=connected?"更换项目":"连接我的项目";
  el("show-version").disabled=!connected;
  if(!connected){
    ++statusSequence;repositoryState=null;
    el("project-name").textContent="选择核对项目";el("project-icon").textContent="+";
    el("project-type").textContent="连接本地源码，固定版本";
    el("repo-name").textContent="";el("version-short").textContent="";
    el("repository-state").textContent="先选择项目，再导入对应报告。";
    el("repository-state").classList.remove("warning");updateActions();return;
  }
  const name=context.repo_url.split("/").filter(Boolean).at(-1).replace(/\.git$/,"");
  el("project-name").textContent=name;el("project-icon").textContent=name[0].toUpperCase();
  el("project-type").textContent=projectKind==="example"?"内置教学案例":"已连接的本地项目";
  el("repo-name").textContent=projectLabel(context.repo_url);
  el("version-short").textContent=context.reviewed_commit.slice(0,7)+"…"+context.reviewed_commit.slice(-7);
  if(tutorial){el("project-type").textContent="教学案例 · 已有记录";el("repository-state").textContent="固定版本案例回放，不连接或运行你的项目";repositoryState=null;updateActions();return;}
  if(config?.read_only_demo){el("project-type").textContent="只读教学案例";el("repository-state").textContent="固定公开源码；自己的报告请在本机运行";updateActions();return;}
  checkRepository();
}
function projectDialog(){
  if(config?.read_only_demo||busy)return;
  openDialog("连接本地源码",body=>{
    body.append(node("p","粘贴 Git 项目文件夹，选择版本，检查通过后使用。","subtle"));
    const localPath=field(body,"1. 本地 Git 文件夹",repositoryState?.repository?.path||"");
    localPath.placeholder=config?.path_style==="windows"?"例如 D:\\Projects\\my-project":"例如 /home/sam/my-project 或 /mnt/d/Projects/my-project";
    body.append(node("p",config?.path_style==="windows"?"在文件资源管理器打开项目文件夹，复制地址栏路径。":"服务运行在 WSL / Linux，请使用 /home/… 或 /mnt/… 路径。","subtle"));
    const projectFields=node("div",undefined,"connection-fields");body.append(projectFields);
    const commit=field(projectFields,"2. 代码版本",context.reviewed_commit);
    commit.placeholder="HEAD、分支名、标签或完整 Commit SHA";
    const repo=field(projectFields,"3. 仓库地址（留空则自动识别）",context.repo_url);
    let changedPath=false;
    localPath.addEventListener("input",()=>{if(!changedPath){changedPath=true;repo.value="";commit.value="HEAD";}});
    const status=node("div","检查包括：Git 仓库、来源地址、所选版本。","connection-status");
    status.setAttribute("role","status");body.append(status);
    const save=button("检查并使用",async()=>{
      save.disabled=true;[localPath,commit,repo].forEach(n=>{n.disabled=true;});
      status.className="connection-status";status.textContent="正在检查源码和版本…";
      try{
        let state;
        if(localPath.value.trim()){
          state=await api("/api/repository-connect",{local_path:localPath.value.trim(),revision:commit.value.trim(),repo_url:repo.value.trim()});
        }else{
          state=await api("/api/repository-status",{repo_url:repo.value.trim(),reviewed_commit:commit.value.trim().toLowerCase()});
          if(!state.ready)throw new Error(state.message+"；请填写本地 Git 文件夹。");
        }
        context={...context,repo_url:state.repo_url,reviewed_commit:state.reviewed_commit,case_id:identifier("case"),vuln_ids:[],source_link:""};projectKind="project";
        candidates=[];extraction=null;candidatePage=0;selectedCandidate=0;
        invalidateResult();el("project-type").textContent="指定版本的本地源码";renderProject();closeDialog();
        message("源码已连接，版本已固定为 "+state.reviewed_commit.slice(0,7)+"；请核对报告后重新提取。");
      }catch(e){status.className="connection-status warning";status.textContent=e.message;}
      finally{save.disabled=false;[localPath,commit,repo].forEach(n=>{n.disabled=false;});}
    },"primary");
    body.append(save,node("p","连接保留到本次服务关闭；重启后可再次连接。只读取提交中的源码，不切换分支。","subtle"));
  });
}
function repositoryHelp(){readDialog("源码接入说明","1. 使用 Git 克隆目标项目，保留 .git 和所需历史版本。\n2. 点击‘连接我的项目’，填写运行服务能访问的文件夹。\n3. 选择分支、标签或提交；应用将固定为完整 Commit SHA。\n4. 导入对应版本的报告。连接只读取源码，不执行目标代码。");}
function missing(claim){const out=[];if(!claim.text?.trim())out.push("具体声明");if(claim.kind==="fix_commit"){if(!/^[a-f0-9]{40}$/.test(claim.claimed_fix_commit||""))out.push("修复 SHA");}else{const nodes=claim.kind==="trace"?claim.nodes||[]:[claim.node||{}];if(claim.kind==="trace"&&(nodes.length<2||nodes.length>8))out.push("2–8 个节点");nodes.forEach(n=>{if(!n.file?.trim())out.push("文件路径");if(!/^[1-9]\d*(?:-[1-9]\d*)?$/.test(String(n.line||"")))out.push("行号");if(!n.code?.trim())out.push("引用代码");});}return [...new Set(out)];}
function paginateList(pager,page,length,onPage){const total=Math.max(1,Math.ceil(length/3));page=Math.min(page,total-1);pager.replaceChildren();pager.append(button("上一页",()=>onPage(page-1),""),node("span",(page+1)+" / "+total),button("下一页",()=>onPage(page+1),""));pager.firstChild.disabled=page===0;pager.lastChild.disabled=page===total-1;pager.classList.toggle("hidden",total===1);return page;}
function renderCandidates(){
  candidatePage=paginateList(el("candidate-pager"),candidatePage,candidates.length,p=>{candidatePage=p;selectedCandidate=p*3;renderCandidates();});
  el("candidate-list").replaceChildren();
  candidates.slice(candidatePage*3,candidatePage*3+3).forEach((item,offset)=>{
    const index=candidatePage*3+offset,card=node("div",undefined,"candidate"+(index===selectedCandidate?" active":""));
    card.setAttribute("role","group");card.setAttribute("aria-label","核查项 "+(index+1));
    card.onclick=e=>{if(!e.target.closest("input")){selectedCandidate=index;renderCandidates();}};
    const top=node("div",undefined,"candidate-top"),choose=button((index+1)+". "+topic(item.claim),()=>{selectedCandidate=index;renderCandidates();},"candidate-select"),check=node("input");check.type="checkbox";check.checked=item.selected;check.setAttribute("aria-label","复核第 "+(index+1)+" 项");check.onclick=e=>e.stopPropagation();check.onchange=()=>{item.selected=check.checked;if(tutorial){result=null;updateActions();saveTutorial();}else invalidateResult();};top.append(choose,check);
    card.append(top,node("div",item.claim.text,"candidate-line"));const n=item.claim.node;card.append(node("div",missing(item.claim).length?"待补："+missing(item.claim).join("、"):(n?n.file+":"+n.line:"字段完整"),"candidate-meta"));el("candidate-list").append(card);
  });
  const item=candidates[selectedCandidate]||candidates[0];if(item){quote.set(item.claim.origin?.quote||item.claim.text);el("candidate-location").textContent=item.claim.node?item.claim.node.file+":"+item.claim.node.line:kinds[item.claim.kind];el("candidate-warning").textContent=missing(item.claim).length?"字段不完整，编辑补齐后再复核。":item.claim.origin?"原句已定位。请确认这次要核查的范围。":"手动声明；尚未关联报告原句。";}else{quote.set("");el("candidate-warning").textContent="没有候选，可手动添加。";}
  el("edit-candidate").disabled=!item;el("remove-candidate").disabled=!item;el("extraction-record").disabled=!extraction;updateActions();
}
function editClaim(index=null){
  if(index===null&&candidates.length>=8){toast("每次最多 8 项，请拆分报告。");return;}
  const draft=index===null?{claim_id:identifier("claim"),kind:"source_location",text:"",node:{file:"",line:"",code:""}}:clone(candidates[index].claim);
  openDialog(index===null?"添加核查项":"编辑核查项",body=>{
    const label=node("label","核查类型"),type=node("select",undefined,"field");Object.entries(kinds).forEach(([key,text])=>{const option=node("option",text);option.value=key;type.append(option);});type.value=draft.kind;label.append(type);body.append(label);
    const text=field(body,"具体声明",draft.text,true),fields=node("div"),origin=node("div");body.append(fields,origin);let controls=[];
    function nodeFields(n={},label=""){if(label)fields.append(node("strong",label));return {file:field(fields,"仓库内文件",n.file||""),line:field(fields,"行号或行范围",n.line||""),code:field(fields,"报告引用的原始代码（保留缩进）",n.code||"",true),desc:field(fields,"说明（可选）",n.desc||"")};}
    function populate(){fields.replaceChildren();controls=[];if(type.value==="fix_commit")controls=[field(fields,"修复 Commit SHA",draft.claimed_fix_commit||"")];else if(type.value==="trace"){let rows=draft.nodes?.length?draft.nodes:[{},{}];rows.forEach((n,i)=>controls.push(nodeFields(n,"节点 "+(i+1))));fields.append(button("添加节点",()=>{if(controls.length>=8)return;const action=fields.lastChild;fields.removeChild(action);controls.push(nodeFields({},"节点 "+(controls.length+1)));fields.append(action);}));}else controls=[nodeFields(draft.node)];}
    type.onchange=populate;populate();
    const originText=field(origin,"对应报告原句（可选，须与原文完全一致）",draft.origin?.quote||"",true);origin.append(node("p","原句用于定位来源；核查类型和具体声明需要你确认。","subtle"));
    body.append(button("保存核查项",()=>{
      const value={claim_id:draft.claim_id,kind:type.value,text:text.value.trim()};
      if(originText.value.trim()){const raw=chars(report.get()),needle=chars(originText.value),full=raw.join(""),at=full.indexOf(originText.value);if(at<0||full.indexOf(originText.value,at+1)!==-1){toast("原句需要在报告中唯一、完整地出现。");return;}const start=chars(full.slice(0,at)).length;value.origin={quote:originText.value,start,end:start+needle.length};}
      const take=n=>{const line=n.line.value.trim(),v={file:n.file.value.trim(),line:/^\d+$/.test(line)?Number(line):line,code:n.code.value};if(n.desc.value.trim())v.desc=n.desc.value.trim();return v;};
      if(value.kind==="fix_commit")value.claimed_fix_commit=controls[0].value.trim().toLowerCase();else if(value.kind==="trace")value.nodes=controls.map(take);else value.node=take(controls[0]);
      if(missing(value).length){toast("请补齐："+missing(value).join("、"));return;}
      if(index===null){candidates.push({claim:value,selected:true});selectedCandidate=candidates.length-1;candidatePage=Math.floor(selectedCandidate/3);}else candidates[index]={...candidates[index],claim:value};
      invalidateResult();closeDialog();renderCandidates();saveDraft();message("核查项已保存，请确认本次复核范围。");
    },"primary"));
  });
}
function requestValue(){return {schema_version:"1.0",...clone(context),report_text:report.get(),claims:candidates.filter(c=>c.selected).map(c=>clone(c.claim))};}
function loadRequest(value, kind="project"){context={case_id:value.case_id,repo_url:value.repo_url,reviewed_commit:value.reviewed_commit,vuln_ids:value.vuln_ids,source_link:value.source_link};projectKind=kind;report.set(value.report_text);candidates=value.claims.map(claim=>({claim:clone(claim),selected:true}));selectedCandidate=0;candidatePage=0;extraction=null;renderProject();}
function chooseExample(prepared=false){
  if(!report.get().trim()&&!result){loadDemo(prepared);return;}
  openDialog("使用教学案例",body=>{
    body.append(node("p","将切换到 FastMCP 教学案例并替换当前输入。已完成的任务文件仍保留。"),
      button("使用案例并替换输入",()=>{closeDialog();loadDemo(prepared);},"primary"),button("保留当前输入",closeDialog));
  });
}
async function loadDemo(prepared=false){
  try{
    demo=demo||await api("/api/demo");presentation="live";
    loadRequest({...demo.request,case_id:identifier("demo")},"example");
    result=null;jobId=null;clearJobURL();
    el("project-type").textContent=config?.read_only_demo?"只读教学案例":"内置教学案例";
    el("report-source").textContent=config?.read_only_demo?"固定公开教学报告 · 只读":"教学报告 · 全文编辑，全选会替换整份";
    if(prepared){
      candidates=candidates.filter(c=>c.claim.kind==="source_location");
      const full=report.get(),start=full.indexOf("报告引用的源码位于"),end=full.indexOf("\n二、操作描述",start);
      if(start>=0&&end>start){const raw=full.slice(start,end).trimEnd(),offset=chars(full.slice(0,start)).length;
        candidates.forEach(c=>c.claim.origin={quote:raw,start:offset,end:offset+chars(raw).length});}
      showView("confirm");message("只核对一条源码引用，无需 Key；确认后读取固定版本源码。");
    }else{
      candidates=[];showView("import");
      message(config?.model_ready?"样例已载入，可提取核查内容。":"点击右上“模型设置”配置 AI 后，再提取核查内容。");
    }
    saveDraft();
  }catch(e){toast(e.message);}
}
async function examplesDialog(){
  if(config?.read_only_demo||busy)return;
  try{
    const catalog=await api("/api/examples");
    openDialog("其他教学样例",body=>{
      body.append(node("p","先加载报告，再提取核查内容。新任务需要模型 Key 和对应版本源码。","subtle"));
      catalog.examples.forEach(example=>body.append(button(example.title,()=>{
        presentation="live";loadRequest({...example.request,case_id:identifier("example")},"example");
        candidates=[];extraction=null;invalidateResult();showView("import");closeDialog();saveDraft();
        el("project-type").textContent="公开源码教学样例";
        el("report-source").textContent="教学报告 · 尚未提取或复核";
        message("样例已加载；确认源码可读后提取核查内容。缺源码时点“更换项目”。");
      })));
    });
  }catch(e){toast(e.message);}
}
async function viewDemo(){
  try{
    savedDemo=savedDemo||await api("/api/demo-result");
    taskEpoch++;presentation="demo";result=savedDemo.result;jobId=null;
    loadRequest(result.request,"example");selectedResult=0;resultPage=0;
    const url=new URL(location.href);url.searchParams.delete("job");url.searchParams.set("demo","1");history.replaceState(null,"",url);
    showView("results");renderResults();
    message("已保存的真实任务 · "+formatDate(result.created_at)+" · 本次没有调用模型");
  }catch(e){toast(e.message);}
}
async function startTutorial(stage="import",restoring=false){
  if(busy||tutorial)return;
  try{
    savedDemo=savedDemo||await api("/api/demo-result");
    if(tutorial||busy)return;
    const snapshot=restoring?null:{context:clone(context),projectKind,report:report.get(),reportSource:el("report-source").textContent,draftState:el("draft-state").textContent,candidates:clone(candidates),extraction,result,jobId,activeRequest,presentation,view,selectedCandidate,candidatePage,selectedResult,resultPage,url:location.href};
    if(!restoring){saveDraft();try{sessionStorage.setItem(tutorialReturnKey,location.href);}catch{}}
    ++statusSequence;taskEpoch++;tutorial={snapshot,record:clone(savedDemo.result),progress:{import:0,confirm:1,results:2}[stage]??0};
    presentation="demo";jobId=null;activeRequest=null;
    loadRequest(tutorial.record.request,"example");
    if(restoring){try{const state=JSON.parse(sessionStorage.getItem(tutorialStateKey)||"null");if(Array.isArray(state?.selected)){const ids=new Set(state.selected);candidates.forEach(c=>{c.selected=ids.has(c.claim.claim_id);});}if(Number.isInteger(state?.progress))tutorial.progress=Math.max(tutorial.progress,Math.min(2,state.progress));}catch{}}
    extraction=null;result=null;selectedCandidate=0;candidatePage=0;selectedResult=0;resultPage=0;
    const url=new URL(location.href);url.searchParams.delete("job");url.searchParams.delete("demo");history.replaceState(null,"",url);
    el("report-source").textContent="教学报告 · 已有任务回放";el("draft-state").textContent="当前任务已保留，退出教学后继续";
    if(stage==="results")showTutorialResults();else showView(stage==="confirm"?"confirm":"import");
  }catch(e){toast(e.message);}
}
function saveTutorial(){if(tutorial)try{sessionStorage.setItem(tutorialStateKey,JSON.stringify({selected:candidates.filter(c=>c.selected).map(c=>c.claim.claim_id),progress:tutorial.progress}));}catch{}}
function showTutorialResults(){
  if(!tutorial)return;
  const ids=new Set(candidates.filter(c=>c.selected).map(c=>c.claim.claim_id));
  const rows=tutorial.record.results.filter(row=>ids.has(row.claim_id));
  if(!rows.length){showView("confirm");toast("请至少选择一项，再查看案例结果。");return;}
  result=clone(tutorial.record);result.results=clone(rows);tutorial.progress=2;selectedResult=0;resultPage=0;showView("results");
}
function advanceTutorial(){
  if(!tutorial)return;
  if(view==="import"){tutorial.progress=Math.max(1,tutorial.progress);showView("confirm");}
  else if(view==="confirm")showTutorialResults();
}
function exitTutorial(){
  if(!tutorial)return;
  const snapshot=tutorial.snapshot;tutorial=null;markIntroduced("walkthrough");
  let returnURL=location.pathname;try{const stored=new URL(sessionStorage.getItem(tutorialReturnKey)||returnURL,location.href);if(stored.origin===location.origin&&!stored.searchParams.has("tutorial"))returnURL=stored.href;sessionStorage.removeItem(tutorialReturnKey);sessionStorage.removeItem(tutorialStateKey);}catch{}
  if(!snapshot){location.assign(returnURL);return;}
  ({context,projectKind,candidates,extraction,result,jobId,activeRequest,presentation,selectedCandidate,candidatePage,selectedResult,resultPage}=snapshot);
  report.set(snapshot.report);el("report-source").textContent=snapshot.reportSource;el("draft-state").textContent=snapshot.draftState;history.replaceState(null,"",snapshot.url);renderProject();showView(snapshot.view);saveDraft();
}
async function extract(){if(busy)return;const text=report.get();if(!text.trim()){toast("先粘贴报告或加载样例。");return;}try{setBusy(true);message("AI 正在整理待核查的内容…");const response=await api("/api/extract",{report_text:text});extraction=response;candidates=response.candidates.map(c=>{
    const claim={claim_id:identifier("claim"),kind:c.kind,text:c.text,origin:{quote:c.source_quote,start:c.source_span[0],end:c.source_span[1]}};
    if(c.kind==="fix_commit")claim.claimed_fix_commit=c.claimed_fix_commit;else if(c.kind==="trace")claim.nodes=[];else claim.node={file:c.file,line:/^\d+$/.test(c.line)?Number(c.line):c.line,code:c.code};return {claim,selected:!missing(claim).length};
  });selectedCandidate=0;candidatePage=0;result=null;jobId=null;clearJobURL();forceView("confirm");message("已提取 "+candidates.length+" 项；请确认原句和代码位置。");saveDraft();
  }catch(e){extraction=e.record?.extraction_id?e.record:null;toast(e.message);message("提取未完成，可查看记录或手动导入声明。");}finally{setBusy(false);if(view==="confirm")renderCandidates();}}
function resultState(row){const status=row.review_status||(row.verdict==="uncertain"&&failureStates.has(result.semantic_status)?result.semantic_status:"completed");return failureStates.has(status)?{label:"复核未完成",css:"failed"}:{label:row.kind==="source_location"&&row.verdict==="supported"?"引用一致":verdicts[row.verdict],css:row.verdict};}
function renderResults(){
  if(!result)return;
  resultPage=paginateList(el("result-pager"),resultPage,result.results.length,p=>{resultPage=p;selectedResult=p*3;renderResults();});
  el("result-list").replaceChildren();
  result.results.slice(resultPage*3,resultPage*3+3).forEach((row,offset)=>{
    const index=resultPage*3+offset,state=resultState(row);
    const b=button("",()=>{selectedResult=index;renderResults();},"result-item"+(index===selectedResult?" active":""));
    b.append(node("span",state.label,"pill "+state.css),node("strong",(index+1)+". "+topic(row)));el("result-list").append(b);
  });
  const row=result.results[selectedResult]||result.results[0],state=resultState(row);
  el("result-state").textContent=state.label;el("result-state").className="pill "+state.css;
  el("result-title").textContent=topic(row);el("result-quote").textContent=row.text;reason.set(row.reason);
  selectedSource=sourceSelection(row,result.evidence_packet.evidence);
  const src=selectedSource.evidence;
  el("code-block").classList.toggle("hidden",!src);el("gap-panel").classList.toggle("hidden",Boolean(src));
  if(src)renderSource(el("code"),selectedSource);
  el("code-file").textContent=src?src.file+" · 关键行 "+(selectedSource.highlighted.join("、")||src.declared_line):"未读取到源码";
  el("gap-panel").textContent=state.css==="failed"?"本条复核未完成，请打开运行记录检查材料或模型错误。":"未取得可读取的源码，请补充指定版本、文件或引用位置。";
  const advice=reviewAdvice(row),adviceBox=el("result-advice");adviceBox.replaceChildren(node("b",advice.title),node("span",advice.text));
  adviceBox.className="advice-row "+state.css;
  el("result-note").textContent="版本 "+result.request.reviewed_commit.slice(0,7)+" · 只评价本条说法";
  const counts={supported:0,contradicted:0,uncertain:0};
  result.results.forEach(r=>{if(r.verdict in counts)counts[r.verdict]++;});
  el("results-heading").textContent="核对结果";
  el("job-summary").textContent=(tutorial?"案例回放 · ":presentation==="demo"?"已保存真实任务 · ":"")+projectLabel(result.request.repo_url)+
    " · "+result.results.length+" 项 · "+result.elapsed_seconds.toFixed(2)+" 秒";
  ["md","html","json"].forEach(ext=>{
    el("download-"+ext).href=(presentation==="demo"?"/demo-reports/":"/reports/"+jobId+"/")+({md:"report.md",html:"report.html",json:"result.json"}[ext]);
  });
  el("copy-review").disabled=false;updateActions();
}
async function retrieveJob(restore=false){const epoch=taskEpoch;while(epoch===taskEpoch){const job=await api("/api/jobs/"+jobId);if(restore){loadRequest(job.request);activeRequest=clone(job.request);restore=false;}const event=job.events.at(-1);message(event?.message||(job.status==="queued"?"任务排队中…":"正在读取证据…"));if(job.status==="completed"){result=job.result;presentation="live";rememberJob();forceView("results");renderResults();message("已复核 "+result.results.length+" 项。点击左侧查看依据。");return;}if(job.status==="failed"){const e=new Error(job.error);e.jobFailed=true;throw e;}await new Promise(resolve=>setTimeout(resolve,1000));}}
function retrievalError(e){toast(e.message);el("recover").classList.toggle("hidden",Boolean(e.jobFailed||e.status===404));message(e.jobFailed?"运行失败，未生成完成报告。":e.status===404?"当前服务没有该任务；本地输出仍可保留。":"连接中断。任务可能仍在运行，请恢复任务，避免重复提交。");}
async function verify(){if(busy)return;let submitted=false;try{
  setBusy(true);message("正在检查声明与指定版本…");const request=await api("/api/validate",requestValue());const state=await api("/api/repository-status",{repo_url:request.repo_url,reviewed_commit:request.reviewed_commit});repositoryState=state;if(!state.ready)throw new Error(state.message+"。请先准备本地源码。");
  if(request.claims.some(c=>!["source_location","fix_commit"].includes(c.kind))&&!config?.model_ready)throw new Error("语义模型未配置。请配置模型，或只选择源码引用做确定性复核。");
  const reply=await api("/api/jobs",request);presentation="live";jobId=reply.job_id;activeRequest=clone(request);result=null;selectedResult=0;resultPage=0;submitted=true;
  const url=new URL(location.href);url.searchParams.set("job",jobId);history.replaceState(null,"",url);forceView("results");reason.set("任务已提交。正在读取源码并复核，请稍候。");source.set("");el("result-title").textContent="正在复核";el("result-quote").textContent=request.claims.map(c=>c.text).join("；");el("result-list").replaceChildren();el("code-block").classList.add("hidden");el("gap-panel").classList.add("hidden");el("result-state").textContent="进行中";el("result-state").className="pill pending";el("result-advice").replaceChildren();el("copy-review").disabled=true;await retrieveJob();
  }catch(e){if(submitted)retrievalError(e);else{toast(e.message);message(e.message);}}finally{setBusy(false);}}
async function resume(){if(busy||!jobId)return;try{setBusy(true);el("recover").classList.add("hidden");await retrieveJob(true);}catch(e){retrievalError(e);}finally{setBusy(false);}}
function auditDialog(){if(!extraction){toast("没有本次提取记录。");return;}openDialog("AI 提取记录",body=>{const usage=extraction.metadata?.usage;body.append(node("p",(extraction.cached?"复用缓存，本次没有新增模型调用。":"本次新增模型调用 "+extraction.additional_model_calls+" 次。")+"耗时 "+extraction.elapsed_seconds.toFixed(2)+" 秒。"),node("p","模型："+(extraction.metadata?.resolved_model||extraction.metadata?.requested_model||"未返回")+"；Token："+(usage?.total_tokens??"未返回")));links(body,[["下载完整提取记录",extraction.download_url]]);});}
function importDialog(){openDialog("导入声明 JSON / T1 材料",body=>{const upload=node("input");upload.type="file";upload.accept=".json,.jsonl";body.append(upload);const text=field(body,"粘贴单条材料","",true);text.classList.add("json-editor");upload.onchange=async()=>{const file=upload.files[0];if(!file)return;if(file.size>512000){toast("材料不能超过 500 KiB。");return;}text.value=await file.text();};body.append(button("导入并查看",async()=>{try{const value=JSON.parse(text.value.trim().replace(/^\uFEFF/,""));const request=await api(value.schema_version===undefined?"/api/import-t1":"/api/validate",value);loadRequest(request);jobId=null;result=null;clearJobURL();closeDialog();showView("confirm");message("材料已导入，尚未启动复核。");}catch(e){toast(e.message);}},"primary"));});}

function renderSource(container,selection){
  container.replaceChildren();
  if(container._sourceObserver)container._sourceObserver.disconnect();
  const rows=node("div",undefined,"source-rows"),pager=node("div",undefined,"source-pager");
  container.append(rows,pager);let start=0,capacity=0;
  function paint(){
    const nextCapacity=Math.max(3,Math.floor((container.clientHeight-34)/25));
    if(nextCapacity!==capacity){capacity=nextCapacity;start=sourceWindowStart(selection,capacity);}
    start=Math.min(start,Math.max(0,selection.lines.length-capacity));rows.replaceChildren();pager.replaceChildren();
    selection.lines.slice(start,start+capacity).forEach(line=>{
      const wrap=node("div",undefined,"code-line"+(selection.highlighted.includes(line.number)?" highlight":""));
      const number=node("span",String(line.number),"line-number"),code=node("code");
      const pattern=/("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|\b(?:return|if|for|in|def|class|from|import|None|True|False)\b)/g;
      let at=0;for(const match of line.text.matchAll(pattern)){
        code.append(document.createTextNode(line.text.slice(at,match.index)));
        code.append(node("span",match[0],/^["']/.test(match[0])?"syntax-string":"syntax-keyword"));at=match.index+match[0].length;
      }
      code.append(document.createTextNode(line.text.slice(at)));wrap.append(number,code);rows.append(wrap);
    });
    if(selection.lines.length>capacity){
      const previous=button("前文",()=>{start=Math.max(0,start-capacity);paint();},"text-button");
      const next=button("后文",()=>{start=Math.min(selection.lines.length-1,start+capacity);paint();},"text-button");
      previous.disabled=start===0;next.disabled=start+capacity>=selection.lines.length;
      pager.append(previous,node("span",selection.lines[start].number+"—"+selection.lines[Math.min(start+capacity-1,selection.lines.length-1)].number),next);
    }else pager.append(node("span","已显示全部 "+selection.lines.length+" 行"));
  }
  container._sourceObserver=new ResizeObserver(paint);container._sourceObserver.observe(container);requestAnimationFrame(paint);
}
function sourceDialog(){
  if(!result)return;
  const row=result.results[selectedResult],bound=result.evidence_packet.evidence.filter(e=>row.evidence_refs.includes(e.evidence_id));
  const readable=bound.filter(e=>sourceLines(e).length);
  openDialog("源码与证据",body=>{
    body.append(node("p","固定版本："+result.request.reviewed_commit,"subtle"));
    let current=selectedSource.evidence;
    const reader=node("div",undefined,"source-reader dialog-source");
    if(readable.length>1){
      const select=node("select",undefined,"field");select.setAttribute("aria-label","选择源码文件");
      readable.forEach((e,i)=>{const option=node("option",e.file+":"+e.context_range);option.value=i;select.append(option);});
      select.value=Math.max(0,readable.indexOf(current));
      select.onchange=()=>{current=readable[Number(select.value)];draw();};body.append(select);
    }
    const path=node("p",undefined,"source-path");body.append(path,reader);
    function draw(){
      if(!current){reader.textContent="没有可读取的源码";return;}
      path.textContent=current.file+":"+current.context_range;
      const selection=sourceSelection({...row,evidence_refs:[current.evidence_id]},[current]);renderSource(reader,selection);
    }
    draw();
    if(current&&/^https:\/\/github\.com\/[^/]+\/[^/]+$/.test(result.request.repo_url)){
      const a=node("a","打开同版本公开源码","text-button");
      a.href=result.request.repo_url+"/blob/"+result.request.reviewed_commit+"/"+current.file.split("/").map(encodeURIComponent).join("/")+
        "#L"+(selectedSource.highlighted[0]||current.declared_line||1);
      a.target="_blank";a.rel="noopener";body.append(a);
    }
  });
}
function detailDialog(){
  if(!result)return;
  const row=result.results[selectedResult];
  openDialog("复核详情",body=>{
    const parts=[["报告说",row.text],["复核结果",resultState(row).label],["理由",row.reason]];
    if(row.origin?.quote)parts.push(["报告原句",row.origin.quote]);
    const advice=reviewAdvice(row);parts.push([advice.title,advice.text],["代码版本",result.request.reviewed_commit]);
    parts.forEach(([title,text])=>{const section=node("section",undefined,"detail-section");section.append(node("h3",title),node("p",text));body.append(section);});
    const records=node("details");records.append(node("summary","技术记录（原始 JSON）"),
      node("p","置信度是模型自评，未校准为准确率。","subtle"),
      node("pre",JSON.stringify(row,null,2)));body.append(records);
  });
}
function formatDate(value){return value?new Date(value).toLocaleString("zh-CN",{hour12:false}):"日期见记录";}
function saveDraft(){
  if(presentation==="demo"||config?.read_only_demo)return;
  try{
    sessionStorage.setItem(draftKey,JSON.stringify({context,projectKind,report:report.get(),candidates,view:view==="confirm"?"confirm":"import"}));
    el("draft-state").textContent="草稿已保存 · 仅当前标签页";
  }catch{el("draft-state").textContent="草稿未保存，可复制报告备份";}
}
function restoreDraft(){
  try{
    const d=JSON.parse(sessionStorage.getItem(draftKey)||"null");
    if(!d||typeof d.report!=="string"||d.report.length>100000||!d.context||!Array.isArray(d.candidates)||d.candidates.length>8)return false;
    context=d.context;projectKind=d.projectKind==="example"?"example":"project";report.set(d.report);candidates=d.candidates;renderProject();
    showView(d.view==="confirm"&&candidates.length?"confirm":"import");
    message("已恢复当前标签页的草稿；尚未运行复核。");return true;
  }catch{return false;}
}
function rememberJob(){
  if(!jobId||!result)return;
  try{
    let list=JSON.parse(localStorage.getItem(historyKey)||"[]");if(!Array.isArray(list))list=[];
    list=[{id:jobId,date:result.created_at,project:projectLabel(result.request.repo_url),count:result.results.length},
      ...list.filter(x=>x.id!==jobId)].slice(0,6);localStorage.setItem(historyKey,JSON.stringify(list));
  }catch{}
}
function historyDialog(){
  openDialog("最近任务 · 本浏览器",body=>{
    let list=[];try{list=JSON.parse(localStorage.getItem(historyKey)||"[]");}catch{}
    if(!Array.isArray(list)||!list.length){body.append(node("p","完成一次复核后，任务会出现在这里。"));return;}
    list.filter(x=>/^[a-f0-9]{32}$/.test(x.id)).slice(0,6).forEach(item=>{
      body.append(button(item.project+" · "+item.count+" 项 · "+formatDate(item.date),()=>{
        taskEpoch++;presentation="live";jobId=item.id;result=null;selectedResult=0;resultPage=0;
        const url=new URL(location.href);url.searchParams.delete("demo");url.searchParams.set("job",jobId);history.replaceState(null,"",url);
        closeDialog();forceView("results");resume();
      },"history-item"));
    });
    body.append(node("p","任务保存在运行服务的输出目录；换服务或电脑后可能无法恢复。","subtle"));
  });
}
function infoControl(parent,text){
  const wrap=node("span",undefined,"info-wrap"),trigger=button("ⓘ",()=>{},"info-button"),content=node("span",text,"info-content hidden");
  trigger.setAttribute("aria-label","查看说明");trigger.setAttribute("aria-expanded","false");
  trigger.onclick=event=>{event.preventDefault();event.stopPropagation();const open=content.classList.contains("hidden");content.classList.toggle("hidden",!open);trigger.setAttribute("aria-expanded",String(open));};
  wrap.append(trigger,content);parent.append(wrap);return trigger;
}
function introduceCurrentPage(force=false){
  if(!force||tutorial||!config||busy||el("detail-dialog").open)return;
  if(view==="results"&&!result)return;
    const steps=view==="confirm"?[
    {target:"#candidate-list",title:"选择核查项",text:"点击卡片标题查看原句；右侧勾选框决定本次复核哪些项。"},
    {target:".original-card",title:"对照报告原句",text:"确认 AI 没有改变报告原意；需要时再编辑核查项。"},
    {target:"#next-button",title:"确认后开始",text:"确认所选内容，再点击这里读取源码并复核。"}
  ]:view==="results"?[
    {target:"#result-list",title:"逐条查看结果",text:"选择一项，右侧会显示它的结论、理由和源码依据。"},
    {target:"#code-block",title:"检查判断依据",text:"阅读带行号的代码，点击“展开上下文”查看更多邻近源码。"},
    {target:"#export-button",title:"带走复核成果",text:"导出审阅报告；也可复制单条意见，继续讨论或修订。"}
  ]:[
    {target:".project-entry",title:"选择源码",text:"连接自己的本地 Git 项目，或加载教学案例的报告和固定源码。"},
    {target:".report-card",title:"导入报告",text:"粘贴全文或导入文本；报告需要包含文件位置和引用代码。"},
    {target:"#model-settings",title:"准备运行 AI",text:"需要实际提取和复核时，在这里选择服务商、填写 Key 和模型。"}
  ];
  tour(view,steps,{force});
}
function welcome(){
  openDialog("欢迎使用",body=>{
    body.classList.add("welcome-content");
    body.append(node("h3","对照源码，核对漏洞报告"),node("p","把报告中的说法，与对应版本的代码逐条核对。"));
    const choices=node("div",undefined,"welcome-choices");
    const preview=button("",()=>{markIntroduced("welcome");closeDialog();startTutorial();},"welcome-choice featured");
    preview.append(node("strong","跟着案例走一遍 →"),node("span","从报告到结果，按实际按钮操作。无需 Key。"));
    const own=button("",()=>{markIntroduced("welcome");closeDialog();message("先点击左侧“连接我的项目”，再导入对应报告。");},"welcome-choice");
    own.append(node("strong","核对我的报告"),node("span","已有源码和报告？直接进入工作台。"));
    choices.append(preview,own);body.append(choices,button("跳过介绍，进入工作台",()=>{markIntroduced("welcome");markIntroduced("import");closeDialog();},"text-button"));
    el("detail-dialog").oncancel=()=>{markIntroduced("welcome");markIntroduced("import");};
  });
}
async function modelHelp(){
  if(busy)return;
  if(config?.read_only_demo||!config?.model_settings_available){readDialog("本机模型设置","下载源码并在本地运行后，点击‘模型设置’。公共空间只展示固定案例，不接收 Key 或私人报告。");return;}
  try{config=await api("/api/config");updateActions();}catch(e){toast(e.message);return;}
  openDialog("模型设置",body=>{
    const providerLabel=node("label","服务商"),provider=node("select",undefined,"field");provider.id="setup-provider";
    [["qwen","通义 DashScope"],["compatible","自定义兼容接口"]].forEach(([value,label])=>{const option=node("option",label);option.value=value;provider.append(option);});
    provider.value=config.provider==="compatible"?"compatible":"qwen";providerLabel.append(provider);body.append(providerLabel);
    const keyLabel=node("label","API Key"),keyRow=node("div",undefined,"secret-row"),key=node("input",undefined,"field");
    key.id="setup-key";key.type="password";key.autocomplete="off";key.spellcheck=false;
    key.placeholder=config.has_key?"已配置 · 留空沿用":"粘贴 API Key";
    const eye=button("显示",()=>{const hidden=key.type==="password";key.type=hidden?"text":"password";eye.textContent=hidden?"隐藏":"显示";},"text-button");
    eye.setAttribute("aria-label","显示或隐藏刚输入的 Key");keyRow.append(key,eye);keyLabel.append(keyRow);body.append(keyLabel);
    const modelLabel=node("label","模型"),model=node("select",undefined,"field");model.id="setup-model";
    modelLabel.append(model);body.append(modelLabel);
    const custom=field(body,"自定义模型 ID",config.model_name||"");custom.parentElement.classList.add("custom-model-row");
    function refreshModels(current=""){
      model.replaceChildren();if(provider.value==="qwen"){const option=node("option","qwen3.8-flash");option.value="qwen3.8-flash";model.append(option);}
      const option=node("option","自定义模型 ID…");option.value="custom";model.append(option);
      model.value=provider.value==="qwen"&&(!current||current==="qwen3.8-flash")?"qwen3.8-flash":"custom";
      custom.value=current&&current!=="qwen3.8-flash"?current:"";custom.parentElement.classList.toggle("hidden",model.value!=="custom");
    }
    refreshModels(config.model_name||"");model.onchange=()=>custom.parentElement.classList.toggle("hidden",model.value!=="custom");
    const rememberLabel=node("label",undefined,"check-row"),remember=node("input");remember.type="checkbox";remember.checked=Boolean(config.remember);remember.disabled=!config.credential_store_available;
    rememberLabel.append(remember,node("span","在这台电脑记住 Key"));
    infoControl(rememberLabel,config.credential_store_available?"勾选后使用系统凭据存储。未勾选只用于当前服务，不删除以前保存的配置；下次启动仍会载入旧配置。":"当前环境没有可用的系统凭据存储，可仅本次使用。");body.append(rememberLabel);
    const advanced=node("details",undefined,"model-advanced"),summary=node("summary","高级设置");advanced.append(summary);body.append(advanced);
    const base=field(advanced,"API 基地址",config.base_url||"https://dashscope.aliyuncs.com/compatible-mode/v1");
    infoControl(advanced,"预设服务地址自动填写。自定义接口需支持 Chat Completions 和 JSON Schema；这里填基地址，不填 /chat/completions。");
    const sourceLabel={saved:"系统已保存",session:"仅本次使用",environment:"来自启动环境",none:"未配置"};
    const source=node("div",sourceLabel[config.profile_source]||"未配置","settings-source");advanced.append(source);
    infoControl(source,"Key 不写入项目或浏览器存储。环境变量不会被应用修改；来自启动环境的 Key 在重启时仍可能被继承。");
    const limits=node("div","调用限制","settings-source");advanced.append(limits);
    infoControl(limits,"本次服务最多 10 次请求、100000 token 保守预约；测试和失败请求也计入，换模型不重置。费用以服务商账单为准。");
    let pending=false;const controls=[provider,key,eye,model,custom,remember,base];
    const status=node("div","","settings-status hidden");status.setAttribute("role","status");body.append(status);
    function say(text,error=false){status.textContent=text;status.classList.remove("hidden");status.classList.toggle("warning",error);}
    function activity(value){pending=value;[...controls,save,test,forget,restore,...advanced.querySelectorAll("button")].forEach(control=>{control.disabled=value;});remember.disabled=value||!config.credential_store_available;forget.disabled=value||!config.saved_profile_available;restore.disabled=value||!config.saved_profile_available;el("close-dialog").disabled=value;}
    const value=()=>({provider:provider.value,model:model.value==="custom"?custom.value:model.value,base_url:base.value,api_key:key.value,remember:remember.checked});
    async function submit(path){
      if(pending)return;stopTour();
      const data=["/api/model-forget","/api/model-restore"].includes(path)?{}:value();activity(true);
      say(path==="/api/model-test"?"正在测试连接…":"正在保存…");
      try{
        const response=await api(path,data);config=response;updateActions();
        if(path==="/api/model-test")say(response.tested_current_profile?"连接测试通过":"测试通过 · 点击保存后生效");
        else{key.value="";key.type="password";closeDialog();toast(path==="/api/model-forget"?"已忘记保存的 Key；当前服务可继续使用。":path==="/api/model-restore"?"已使用保存的配置。":"模型配置已保存。 ");}
      }catch(e){if(e.record?.configuration){config=e.record.configuration;updateActions();}say(e.message,true);}
      finally{activity(false);}
    }
    const confirm=node("div",undefined,"inline-confirm hidden");body.append(confirm);
    function confirmation(text,action,label){confirm.replaceChildren(node("p",text),button(label,()=>{confirm.classList.add("hidden");action();},"primary"),button("取消",()=>confirm.classList.add("hidden")));confirm.classList.remove("hidden");confirm.querySelector("button").focus();}
    const actions=node("div",undefined,"dialog-actions settings-actions");body.append(actions);
    const test=button("测试连接",()=>confirmation("发送一次短请求，可能产生费用。不会发送报告。",()=>submit("/api/model-test"),"发送测试"));
    const save=button("保存",()=>submit("/api/model-settings"),"primary");actions.append(test,save);
    const forget=button("忘记已保存的 Key",()=>confirmation("删除系统保存的配置？当前服务仍可继续使用。",()=>submit("/api/model-forget"),"确认忘记"),"danger-button");
    const restore=button("使用已保存配置",()=>submit("/api/model-restore"));forget.disabled=restore.disabled=!config.saved_profile_available;advanced.append(restore,forget);
    provider.onchange=()=>{key.value="";key.placeholder="填写此服务的 Key";base.value=provider.value==="qwen"?"https://dashscope.aliyuncs.com/compatible-mode/v1":"";refreshModels();if(provider.value==="compatible")advanced.open=true;};
    const extras=node("div",undefined,"settings-extras"),link=node("a","获取 Key");link.href="https://bailian.console.aliyun.com/?tab=model#/api-key";link.target="_blank";link.rel="noopener";
    link.classList.toggle("hidden",provider.value!=="qwen");provider.addEventListener("change",()=>link.classList.toggle("hidden",provider.value!=="qwen"));
    
    extras.append(link,button("查看引导",()=>tour("model",modelTour,{force:true,host:el("detail-dialog")}),"tour-skip"));body.append(extras);
    const modelTour=[{target:"#setup-provider",title:"选择服务商",text:"通义已填好默认接口地址；其他兼容服务在高级设置填写。"},{target:"#setup-key",title:"填写自己的 Key",text:"已有凭据可以留空沿用。默认仅本次使用；需要下次记住时勾选。"},{target:"#setup-model",title:"选择模型并保存",text:"选择预设或填写自定义模型 ID。保存不会联网；测试连接单独点击。"}];
    el("detail-dialog").oncancel=e=>{if(pending)e.preventDefault();};
  });
}

el("close-dialog").onclick=closeDialog;
el("next-button").onclick=()=>tutorial?advanceTutorial():view==="import"?extract():verify();el("back-button").onclick=()=>showView(view==="results"?"confirm":"import");
el("start-guide").onclick=()=>startTutorial();el("exit-guide").onclick=exitTutorial;
["md","json"].forEach(format=>{el("download-"+format).onclick=event=>downloadPublicReport(event,format);});
document.querySelectorAll("[data-view]").forEach(b=>b.onclick=()=>showView(b.dataset.view));
el("load-demo").onclick=()=>chooseExample();el("prepared-demo").onclick=()=>chooseExample(true);
el("change-project").onclick=projectDialog;el("show-version").onclick=()=>readDialog("固定代码版本",context.repo_url+"\n\n"+context.reviewed_commit);el("repository-help").onclick=repositoryHelp;
el("manual-claim").onclick=()=>editClaim();el("edit-candidate").onclick=()=>editClaim(selectedCandidate);
el("remove-candidate").onclick=()=>{candidates.splice(selectedCandidate,1);selectedCandidate=Math.max(0,selectedCandidate-1);invalidateResult();renderCandidates();};
el("whole-report").onclick=()=>readDialog("完整报告原文",report.get());el("extraction-record").onclick=auditDialog;
el("import-json").onclick=importDialog;el("source-detail").onclick=sourceDialog;
el("result-original").onclick=()=>{if(result)readDialog("报告声明与原文",result.results[selectedResult].text+"\n\n"+(result.results[selectedResult].origin?.quote||"未关联原文定位"));};
el("result-detail").onclick=detailDialog;
el("run-record").onclick=()=>{if(result)openDialog("运行记录",body=>{
  body.append(node("p",(presentation==="demo"?"已保存真实任务":"本次任务")+" · "+formatDate(result.created_at)),
    node("p","复核耗时 "+result.elapsed_seconds.toFixed(2)+" 秒；模型尝试 "+result.model_calls.length+" 次。"));
  const detail=node("details");detail.append(node("summary","查看原始运行记录"),
    node("pre",JSON.stringify({job_id:jobId,created_at:result.created_at,input_sha256:result.input_sha256,
      semantic_status:result.semantic_status,prompt_version:result.prompt_version,model_calls:result.model_calls},null,2)));body.append(detail);
});};
el("settings").onclick=()=>openDialog("更多设置",body=>{body.append(button("其他教学样例",examplesDialog));const ids=field(body,"CVE / GHSA（可选）",context.vuln_ids.join(", ")),link=field(body,"公告 HTTPS 链接（可选）",context.source_link);body.append(button("保存",()=>{context.vuln_ids=ids.value.split(/[,，\s]+/).filter(Boolean);context.source_link=link.value.trim();invalidateResult();saveDraft();closeDialog();},"primary"));});
el("save-input").onclick=async()=>{try{const value=await api("/api/inputs",requestValue());openDialog("输入已保存",body=>{body.append(node("p","没有启动复核。"));links(body,[["下载本次输入 JSON",value.download_url]]);});}catch(e){toast(e.message);}};
el("recover").onclick=resume;
el("new-task").onclick=()=>{if(presentation==="demo"){loadDemo();return;}taskEpoch++;context.case_id=identifier("case");jobId=null;result=null;candidates=[];extraction=null;report.set("");clearJobURL();showView("import");saveDraft();message("粘贴下一份报告。上一任务可从最近任务恢复。");};
el("about").onclick=()=>openDialog("VulnGym Evidence",body=>{body.append(node("p","帮助开发者对照指定版本的代码，逐条复核漏洞报告，并把源码依据带回结果。"),node("p","只评价你确认提交的声明。演示报告由项目作者根据公开源码编写。"),node("p",config?.model_message||"服务连接尚未检查。","subtle"));});
el("export-button").onclick=()=>{const menu=el("export-menu");menu.classList.toggle("hidden");el("export-button").setAttribute("aria-expanded",String(!menu.classList.contains("hidden")));};
document.addEventListener("click",e=>{if(!e.target.closest(".export-wrap")){el("export-menu").classList.add("hidden");el("export-button").setAttribute("aria-expanded","false");}});
el("view-demo").onclick=viewDemo;el("model-settings").onclick=modelHelp;el("history").onclick=historyDialog;
el("other-examples").onclick=examplesDialog;
el("import-report").onclick=()=>el("report-file").click();
el("usage-guide").onclick=()=>{
  openDialog("使用引导",body=>{
    body.append(node("p","建议第一次使用时跟着案例走完三个步骤。当前任务会保留。"),button("跟着案例走一遍 · 无需 Key",()=>{closeDialog();startTutorial();},"primary"));
    body.append(button("只介绍当前页面",()=>{closeDialog();requestAnimationFrame(()=>introduceCurrentPage(true));}));
  });
};
el("detail-dialog").addEventListener("close",()=>{stopTour();if(el("dialog-title").textContent==="欢迎使用")markIntroduced("welcome");el("dialog-body").querySelectorAll('#setup-key,input[type="password"]').forEach(input=>{input.value="";});});
el("clear-report").onclick=()=>{report.set("");invalidateReport();saveDraft();message("报告全文已清空。");};
el("report-file").onchange=async()=>{
  const file=el("report-file").files[0];if(!file)return;
  if(file.size>100000){toast("报告不能超过 100 KiB，请分段处理。");return;}
  report.set((await file.text()).replace(/^\uFEFF/,""));invalidateReport();saveDraft();el("report-source").textContent="已导入 "+file.name+" · 全文编辑";el("report-file").value="";
};
el("copy-review").onclick=async()=>{
  if(!result)return;const text=reviewText(result.results[selectedResult],result.request);
  try{await navigator.clipboard.writeText(text);toast("复核意见已复制。");}
  catch{readDialog("复核意见（可全选复制）",text);}
};
document.querySelectorAll(".step").forEach(b=>b.onclick=()=>{showView(b.dataset.view);saveDraft();});
el("report").addEventListener("blur",saveDraft);
api("/api/config").then(async value=>{
  config=value;renderProject();updateActions();
  const url=new URL(location.href),restoredJob=url.searchParams.get("job");
  if(["import","confirm","results"].includes(url.searchParams.get("tutorial"))){await startTutorial(url.searchParams.get("tutorial"),true);}
  else if(url.searchParams.get("demo")==="1"){await viewDemo();}
  else if(restoredJob&&/^[a-f0-9]{32}$/.test(restoredJob)){jobId=restoredJob;forceView("results");resume();}
  else if(value.read_only_demo){await loadDemo();updateActions();message("查看演示结果无需 Key；自己的报告请在本机运行。");}
  else if(!restoreDraft()){message("先选择项目，或跟着案例走一遍。");if(needsIntroduction("welcome"))welcome();}
}).catch(e=>{el("mode").textContent="服务连接失败";message(e.message);});
updateActions();
