"use strict";
const storageKey="vulngym-evidence-onboarding-v1";
const dismissed=new Set();
let active=null;
function seen(stage){try{return dismissed.has(stage)||Boolean(JSON.parse(localStorage.getItem(storageKey)||"{}")[stage]);}catch{return dismissed.has(stage);}}
export function markIntroduced(stage){dismissed.add(stage);try{const state=JSON.parse(localStorage.getItem(storageKey)||"{}");localStorage.setItem(storageKey,JSON.stringify({...state,[stage]:true}));}catch{}}
export function needsIntroduction(stage){return !seen(stage);}
export function stopTour(){if(active)active.finish(false);}
export function tour(stage,steps,{force=false,host=document.body}={}){
  if(active||(!force&&seen(stage)))return;
  const visible=steps.filter(step=>{const target=document.querySelector(step.target);return target&&target.getClientRects().length;});
  if(!visible.length)return;
  const previousFocus=document.activeElement;
  const overlay=document.createElement("div");overlay.className="tour-layer";
  const highlight=document.createElement("div");highlight.className="tour-highlight";highlight.setAttribute("aria-hidden","true");
  const panel=document.createElement("section");panel.className="tour-panel";panel.setAttribute("role","dialog");panel.setAttribute("aria-modal","true");panel.setAttribute("aria-label","使用引导");panel.tabIndex=-1;
  overlay.append(highlight,panel);host.append(overlay);
  let index=0,frame=0;
  function place(){
    frame=0;const target=document.querySelector(visible[index].target);if(!target?.getClientRects().length){finish(false);return;}
    const r=target.getBoundingClientRect(),margin=12,w=window.innerWidth,h=window.innerHeight;
    Object.assign(highlight.style,{left:Math.max(2,r.left-5)+"px",top:Math.max(2,r.top-5)+"px",width:Math.min(w-4,r.width+10)+"px",height:Math.min(h-4,r.height+10)+"px"});
    const width=Math.min(330,w-2*margin);panel.style.width=width+"px";
    const p=panel.getBoundingClientRect();let x=r.right+16,y=r.top;
    if(x+width>w-margin){x=r.left-width-16;}
    if(x<margin){x=Math.max(margin,Math.min(r.left,w-width-margin));y=r.bottom+16;if(y+p.height>h-margin)y=r.top-p.height-16;}
    Object.assign(panel.style,{left:Math.max(margin,Math.min(x,w-width-margin))+"px",top:Math.max(margin,Math.min(y,h-p.height-margin))+"px"});
  }
  function queue(){if(!frame)frame=requestAnimationFrame(place);}
  function makeButton(text,action,cls="secondary"){const b=document.createElement("button");b.type="button";b.textContent=text;b.className=cls;b.onclick=action;return b;}
  function paint(){
    const step=visible[index];panel.replaceChildren();
    const head=document.createElement("div");head.className="tour-heading";
    const count=document.createElement("span");count.textContent=`${index+1} / ${visible.length}`;
    head.append(count,makeButton("跳过",()=>finish(true),"tour-skip"));
    const title=document.createElement("h3");title.textContent=step.title;
    const description=document.createElement("p");description.textContent=step.text;
    const actions=document.createElement("div");actions.className="tour-actions";
    const back=makeButton("上一步",()=>{index--;paint();});back.disabled=index===0;
    actions.append(back,makeButton(index===visible.length-1?"开始使用":"下一步",()=>{if(index===visible.length-1)finish(true);else{index++;paint();}},"primary"));
    panel.append(head,title,description,actions);place();panel.focus({preventScroll:true});
  }
  function keydown(event){
    if(event.key==="Escape"){event.preventDefault();event.stopPropagation();finish(true);return;}
    if(event.key!=="Tab")return;
    const buttons=[...panel.querySelectorAll("button:not(:disabled)")];
    const first=buttons[0],last=buttons.at(-1);
    if(event.shiftKey&&(document.activeElement===first||document.activeElement===panel)){event.preventDefault();last.focus();}
    else if(!event.shiftKey&&(document.activeElement===last||document.activeElement===panel)){event.preventDefault();first.focus();}
  }
  function finish(remember){
    if(remember)markIntroduced(stage);overlay.remove();window.removeEventListener("resize",queue);document.removeEventListener("scroll",queue,true);document.removeEventListener("keydown",keydown,true);if(frame)cancelAnimationFrame(frame);active=null;if(previousFocus?.isConnected)previousFocus.focus({preventScroll:true});
  }
  active={finish};window.addEventListener("resize",queue);document.addEventListener("scroll",queue,true);document.addEventListener("keydown",keydown,true);paint();
}
