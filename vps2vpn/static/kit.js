
'use strict';
/* UI kit shared with the original admin console (legend ui_kit): design tokens live in style.css;
   this file holds the DOM helper, icons, formatting, theme, toast/modal and canvas charts. */
const KT_ZH={copied:'已复制 · ',manual:'请手动复制',manual_tip:'浏览器拒绝了剪贴板权限，可以长按或全选下方内容复制。',ok:'确定',cancel:'取消',confirm:'确认',
 now:'现在',min_ago:' 分钟前',min:' 分钟',no_usage:'暂无用量记录',total:'合计',net:'网络连接失败，请稍后重试',relogin:'登录已失效，正在返回登录页…',failed:'请求失败',
 s_ago:' 秒前',h_ago:' 小时前',d_ago:' 天前',locale:'zh-CN'};
const KT_EN={copied:'Copied · ',manual:'Copy it manually',manual_tip:'The browser blocked clipboard access; select the text below and copy it.',ok:'OK',cancel:'Cancel',confirm:'Confirm',
 now:'now',min_ago:' min ago',min:' min',no_usage:'No usage yet',total:'Total',net:'Network error, try again',relogin:'Session expired, reloading…',failed:'Request failed',
 s_ago:' s ago',h_ago:' h ago',d_ago:' d ago',locale:'en-US'};
let KT=KT_ZH;
const $=id=>document.getElementById(id);
function h(tag,attrs,...kids){const e=document.createElement(tag);if(attrs)for(const[k,v]of Object.entries(attrs)){if(v==null||v===false)continue;if(k==='class')e.className=v;else if(k==='text')e.textContent=v;else if(k.startsWith('on'))e.addEventListener(k.slice(2),v);else e.setAttribute(k,v===true?'':v);}for(const c of kids.flat())if(c!=null&&c!==false)e.append(c instanceof Node?c:document.createTextNode(String(c)));return e;}
const ICONS={
 home:'<path d="M3 11.5 12 4l9 7.5"/><path d="M5 10v10h14V10"/>',users:'<circle cx="9" cy="8" r="3.2"/><path d="M3 20c.6-3.4 3-5.4 6-5.4s5.4 2 6 5.4"/><path d="M16 4.6a3.2 3.2 0 0 1 0 6.3M18 14.8c1.7.7 2.8 2.4 3 5.2"/>',
 pulse:'<path d="M3 12h4l2.5-6 4 12 2.5-6H21"/>',inbox:'<path d="M3 13l2.5-8h13L21 13v6H3z"/><path d="M3 13h5l1.5 2.5h5L16 13h5"/>',
 server:'<rect x="3.5" y="4" width="17" height="7" rx="2"/><rect x="3.5" y="13" width="17" height="7" rx="2"/><path d="M7.5 7.5h.01M7.5 16.5h.01"/>',
 sliders:'<path d="M4 6h10M18 6h2M4 12h4M12 12h8M4 18h12M20 18h0"/><circle cx="16" cy="6" r="2"/><circle cx="10" cy="12" r="2"/><circle cx="18" cy="18" r="2"/>',
 refresh:'<path d="M20 11a8 8 0 1 0-2.3 5.7"/><path d="M20 5v6h-6"/>',out:'<path d="M15 4h4v16h-4"/><path d="M10 8l-4 4 4 4M6 12h10"/>',
 plus:'<path d="M12 5v14M5 12h14"/>',copy:'<rect x="8" y="8" width="12" height="12" rx="2.5"/><path d="M16 8V5.5A1.5 1.5 0 0 0 14.5 4h-9A1.5 1.5 0 0 0 4 5.5v9A1.5 1.5 0 0 0 5.5 16H8"/>',
 dots:'<circle cx="5" cy="12" r="1.3"/><circle cx="12" cy="12" r="1.3"/><circle cx="19" cy="12" r="1.3"/>',x:'<path d="M6 6l12 12M18 6 6 18"/>',
 search:'<circle cx="11" cy="11" r="6.5"/><path d="m20 20-4.2-4.2"/>',sun:'<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M2 12h2M20 12h2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/>',
 moon:'<path d="M20 14.5A8 8 0 0 1 9.5 4a8 8 0 1 0 10.5 10.5z"/>',auto:'<circle cx="12" cy="12" r="8"/><path d="M12 4v16" /><path d="M12 4a8 8 0 0 1 0 16z" fill="currentColor"/>',
 bolt:'<path d="M13 3 5 13h6l-1 8 8-10h-6z"/>',shield:'<path d="M12 3 4.5 6v6c0 4.4 3.2 7.8 7.5 9 4.3-1.2 7.5-4.6 7.5-9V6z"/>',key:'<circle cx="8" cy="15" r="4"/><path d="m11 12 9-9M17 6l3 3M15 8l2 2"/>',
 link:'<path d="M10 14a4.5 4.5 0 0 0 6.4 0l3-3a4.5 4.5 0 0 0-6.4-6.4l-1.2 1.2"/><path d="M14 10a4.5 4.5 0 0 0-6.4 0l-3 3a4.5 4.5 0 0 0 6.4 6.4l1.2-1.2"/>',
 pause:'<path d="M9 5v14M15 5v14"/>',play:'<path d="M7 5v14l12-7z"/>',edit:'<path d="M4 20h4L19 9l-4-4L4 16z"/><path d="m13.5 6.5 4 4"/>',gauge:'<path d="M4 17a8 8 0 1 1 16 0"/><path d="m12 17 4-5"/>',
 globe:'<circle cx="12" cy="12" r="8.5"/><path d="M3.5 12h17M12 3.5c2.5 2.6 3.6 5.4 3.6 8.5S14.5 17.9 12 20.5C9.5 17.9 8.4 15.1 8.4 12S9.5 6.1 12 3.5z"/>',
 check:'<path d="m5 12.5 4.5 4.5L19 7.5"/>',lock:'<rect x="5" y="10.5" width="14" height="10" rx="2.5"/><path d="M8 10.5V8a4 4 0 0 1 8 0v2.5"/>',
 chevron:'<path d="m9 6 6 6-6 6"/>',arrowUp:'<path d="M12 19V5M6 11l6-6 6 6"/>',arrowDown:'<path d="M12 5v14M6 13l6 6 6-6"/>',
 bell:'<path d="M6 16.5V11a6 6 0 0 1 12 0v5.5l1.5 2h-15z"/><path d="M10 20.5a2 2 0 0 0 4 0"/>',
 alert:'<path d="M12 4 21 19.5H3z"/><path d="M12 10v4.5M12 17.2v.3"/>',
 clock:'<circle cx="12" cy="12" r="8.5"/><path d="M12 7.5V12l3 2"/>'};
function icon(name,cls){const s=document.createElementNS('http://www.w3.org/2000/svg','svg');s.setAttribute('viewBox','0 0 24 24');s.setAttribute('class','i'+(cls?' '+cls:''));s.setAttribute('aria-hidden','true');s.innerHTML=ICONS[name]||'';return s;}
function hydrateIcons(root){for(const e of (root||document).querySelectorAll('[data-icon]')){e.prepend(icon(e.dataset.icon));e.removeAttribute('data-icon');}}

/* ---------- formatting ---------- */
const fmt={
 /* vps2vpn: binary units throughout, so shown sizes match the GB typed into quota fields (1 GB = 1024^3 B) */
 bytes(n,d){if(n==null||!isFinite(n))return '—';const a=Math.abs(n),G=1073741824;if(a>=G*1024)return (n/G/1024).toFixed(d??2)+' TB';if(a>=G)return (n/G).toFixed(d??(a>=100*G?0:a>=10*G?1:2))+' GB';if(a>=1048576)return (n/1048576).toFixed(d??0)+' MB';if(a>=1024)return (n/1024).toFixed(0)+' KB';return Math.round(n)+' B';},
 gb(n){return n==null?'—':(n/1073741824).toLocaleString(KT.locale,{maximumFractionDigits:n>=107374182400?0:n>=10737418240?1:2})+' GB';},
 mbps(v){if(v==null||!isFinite(v))return '—';return v>=100?v.toFixed(0):v>=10?v.toFixed(1):v.toFixed(2);},
 rate(bps){return fmt.mbps(bps*8/1e6);},
 pct(x){return x==null?'—':(x>=.1||x===0?Math.round(x*100):(x*100).toFixed(1))+'%';},
 date(s){return s||'—';},
 time(t){if(!t)return'—';const d=new Date(t*1000),y=d.getFullYear(),same=y===new Date().getFullYear(),hm=String(d.getHours()).padStart(2,'0')+':'+String(d.getMinutes()).padStart(2,'0');return KT===KT_ZH?(same?'':y+'年')+(d.getMonth()+1)+'月'+d.getDate()+'日 '+hm:['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'][d.getMonth()]+' '+d.getDate()+(same?'':', '+y)+', '+hm;},  // 11月26日 15:00 / Nov 26, 15:00; the year only when it is not this year
 ago(t){if(!t)return '—';const s=Math.max(0,Date.now()/1000-t);if(s<60)return Math.round(s)+KT.s_ago;if(s<3600)return Math.round(s/60)+KT.min_ago;if(s<86400)return Math.round(s/3600)+KT.h_ago;return Math.round(s/86400)+KT.d_ago;},
 daysUntil(iso){if(!iso)return null;const d=new Date(iso+'T23:59:59+08:00');return Math.ceil((d-Date.now())/864e5);},
};

/* ---------- theme ---------- */
const Theme={key:'v2v-theme',_mqlBound:false,get(){try{return localStorage.getItem(this.key)||'auto'}catch{return 'auto'}},
 set(v){try{localStorage.setItem(this.key,v)}catch{}this.apply(v);},
 apply(v){if(v==='auto')document.documentElement.removeAttribute('data-theme');else document.documentElement.setAttribute('data-theme',v);Palette.refresh();for(const b of document.querySelectorAll('[data-theme-btn]'))b.setAttribute('aria-pressed',String(b.dataset.themeBtn===v));},
 mount(){for(const b of document.querySelectorAll('[data-theme-btn]')){if(!b.dataset.themeBound){b.dataset.themeBound='1';b.addEventListener('click',()=>this.set(b.dataset.themeBtn));}}this.apply(this.get());if(!this._mqlBound){this._mqlBound=true;matchMedia('(prefers-color-scheme: dark)').addEventListener('change',()=>Palette.refresh());}}};
const Palette={v:{},mono:'monospace',refresh(){const cs=getComputedStyle(document.documentElement);this.mono=cs.getPropertyValue('--mono').trim()||'monospace';for(const k of ['text','text-2','muted','line','line-2','panel','panel-2','panel-3','down','up','sg','us','accent','ok','warn','danger'])this.v[k]=cs.getPropertyValue('--'+k).trim();Ticker.dirtyAll();}};
function alpha(color,a){const c=color.trim();if(c.startsWith('#')){let x=c.slice(1);if(x.length===3)x=[...x].map(ch=>ch+ch).join('');const n=parseInt(x,16);return `rgba(${n>>16&255},${n>>8&255},${n&255},${a})`;}return c;}
function placeTip(tip,x,y,w){tip.classList.remove('hide');const hw=Math.min(w/2,(tip.offsetWidth||120)/2+6);tip.style.left=Math.max(hw,Math.min(w-hw,x))+'px';tip.style.top=y+'px';}

/* ---------- toast + modal ---------- */
/* Server messages are English; show them in Chinese when the page is. Unknown ones pass through unchanged. */
const ERR_LBL={'quota (GB)':'额度（GB）','uses':'可用次数','code valid for (days)':'邀请码有效天数','account lifetime (days)':'账号有效天数','reset day':'重置日','extra quota (GB)':'增加的流量（GB）'};
const lbl=a=>ERR_LBL[a]||a;
const ERR_ZH=[
 [/^(.+) must be a number$/,(m,a)=>lbl(a)+'必须是数字'],[/^(.+) must be a whole number$/,(m,a)=>lbl(a)+'必须是整数'],
 [/^(.+) must be between (\S+) and (\S+)$/,(m,a,b,c)=>lbl(a)+'必须在 '+b+' 到 '+c+' 之间'],
 [/^note: at most/,'备注最多 100 个字'],[/^inviter not found/,'找不到邀请人'],[/^a paused or expired account cannot invite/,'已停用或已到期的账号不能邀请他人'],
 [/^unlimited accounts cannot share/,'不限量账号不能分出额度；如需邀请码，请联系管理员'],
 [/^not enough quota: (\d+) x (\S+) GB is more than the (\S+) GB/,(m,a,b,c)=>'额度不足：'+a+' × '+b+' GB 超过了你可分出的 '+c+' GB（自己至少保留 1 GB）'],
 [/^at most (\d+) unused codes/,(m,a)=>'最多同时保留 '+a+' 个未用完的邀请码，请先撤销一个'],
 [/^no such invite code/,'没有这个邀请码'],[/^this code is already used up or revoked/,'这个邀请码已用完或已撤销'],
 [/^name: 2-32/,'用户名 2–32 位，只能用字母、数字、汉字和 . _ -'],[/^that name is taken/,'这个名字已经有人用了，换一个吧'],[/^name already used/,'这个名字已经有人用了'],
 [/^name required/,'请填写名字'],[/^password: (\d+) to 128/,(m,a)=>'密码 '+a+'–128 位'],[/^password must be at least 8/,'密码至少 8 位'],
 [/^invite code is wrong, used up or expired/,'邀请码不对、已用完或已过期'],[/^the person who invited you can no longer invite/,'邀请你的人现在不能再邀请了，这个邀请码作废'],
 [/^the inviter's quota has run short/,'邀请人的额度不够了，这个邀请码作废'],[/^no such account/,'账号不存在'],[/^no such user/,'没有这个使用者'],
 [/^no such server/,'没有这台服务器'],[/^unknown line/,'不支持的协议'],[/^already set up/,'已经完成初始化'],[/^bad setup link/,'设置链接无效或已过期'],
 [/^date must look like/,'日期格式不对，请填类似 2026-12-31'],[/^version must look like/,'版本号格式不对，请填类似 1.2.3'],
 [/^download link must start with/,'下载链接必须以 http:// 或 https:// 开头'],[/^masquerade must be/,'伪装地址必须是公开的 https:// 链接'],
 [/^cannot reach api\.telegram\.org/,'无法连接 api.telegram.org，请检查服务器网络'],
 [/^you already have a request waiting/,'你已经有一个申请在等批准了，请等管理员处理'],[/^no pending request/,'这条申请已经处理过了'],
 [/^the account no longer exists/,'这个账号已经不存在'],[/^current password is wrong/,'当前密码不对'],
 [/^wrong (user)?name or password/,'用户名或密码错误'],[/^too many attempts/,'尝试太多次了，请 10 分钟后再试'],
 [/^not a vps2vpn join code/,'这不是 vps2vpn 的加入码'],[/^the join code is damaged/,'加入码不完整，请重新复制'],
 [/^that server is already added/,'这台服务器已经添加过了'],[/^cannot reach that server: (.*)$/,(m,a)=>'无法连接那台服务器：'+a],
 [/^this server already belongs to main server "(.*)"/,(m,a)=>'那台服务器已经归主服务器「'+a+'」管理；要换主服务器，先在那台的面板上点「换新加入码」'],
 [/^certificate (changed|does not match)/,'那台服务器的证书变了，请删掉后用新的加入码重新添加'],
 [/^invalid number/,'数字不对'],[/^invalid port|^port must be/,'端口必须是 1–65535'],[/^reset day must be 1-31/,'重置日必须是 1–31（0 = 不重置）'],[/^server reset day must be/,'服务器流量重置日必须是 1–31（小月没有这一天时按月底算）'],[/^unknown time zone/,'时区不认识（例如 UTC+8）'],
 [/^turn on at least one protocol/,'至少要开一种协议'],[/^Hysteria 2 and TUIC need different/,'Hysteria 2 和 TUIC 不能用同一个 UDP 端口'],
 [/must be outside the hopping range/,'这个端口不能落在端口跳跃范围里'],[/^the panel already uses that TCP port/,'面板已经占用了这个 TCP 端口'],
 [/^server address must be/,'服务器地址必须是 IP 或域名'],[/^invalid domain name/,'域名格式不对'],[/^invalid e-mail/,'邮箱格式不对'],
 [/^camouflage site must be/,'伪装网站必须是域名，比如 www.microsoft.com'],[/^restore failed: (.*)$/,(m,a)=>'恢复失败：'+a],
 [/^wrong 2FA code/,'验证码不对（看看手机时间准不准）'],[/^bad secret/,'密钥不对，请重新开启'],[/^device limit must be/,'设备上限必须是 0–100'],
 [/^a domain is set, so the server address is the domain/,'已经填了域名，服务器地址就是这个域名；想改用 IP，先把域名清空'],
 [/^the domain was cleared/,'域名已清空，请在「服务器地址」里填这台服务器的 IP'],
 [/^too long for a QR code/,'内容过长，无法生成二维码，请直接复制链接'],[/^this account has no traffic limit/,'你的账号不限流量，无需申请'],
 [/^managed by the main server/,'这个账号由主服务器管理，请到主服务器的面板上改'],
 [/^(speed limit|slow-down speed) must be 0-(\d+) Mbps/,(m,a,b)=>(a==='speed limit'?'限速':'降速后的速度')+'必须是 0–'+b+' Mbps'],
 [/^traffic rate must be/,'流量倍率必须是 0–100'],[/^update interval must be a whole number/,'更新间隔必须是整数小时'],
 [/^update interval must be 1-168/,'更新间隔必须是 1–168 小时'],[/^support link must start with/,'联系方式链接必须以 http://、https:// 或 tg:// 开头，一行，不能有空格'],
 [/^certificate renewal already in progress/,'证书正在续期，请稍等再试'],[/^disable existing 2FA before enrolling again/,'已经开着两步验证；要重新绑定，先关掉它'],
 [/^(login|sign-in) settings changed|^account credentials changed/,'设置刚被改过，请刷新页面再试一次'],
 [/^cannot resolve server address(?:: (.*))?$/,(m,a)=>'找不到这个服务器地址'+(a?'：'+a:'')+'（检查域名是否写对、是否已解析）'],
 [/^too many IDs/,'一次最多选 2000 个'],[/^expire_at is out of supported range/,'到期日期超出范围'],[/^text required/,'请填写内容'],
 [/^days must be/,'天数必须是 0–3650'],[/^prefix and a count/,'请填写名字前缀，数量 1–200'],[/^not a domain: (.*)$/,(m,a)=>'不是域名：'+a],
 [/^at most (\d+) domains/,(m,a)=>'每个列表最多 '+a+' 个域名'],[/^unknown action/,'不支持的操作'],
 [/^state must be ok, maintenance or congested/,'状态只能是正常、维护中或拥堵'],
 [/^until: expected/,'恢复时间的格式不对'],[/^until must be in the future/,'恢复时间要在现在之后、一年以内'],[/^note must be text/,'说明要填文字'],
 [/^too many reports, wait a moment/,'发送过于频繁，请 2 分钟后再试'],[/^too many reports today/,'今天已发送 5 条，请明天再试'],
 [/^feedback is turned off/,'管理员未开启反馈功能'],[/^devices are turned off/,'管理员未开启设备管理'],[/^no such device/,'没有这台设备'],
 [/^too many new links, wait an hour/,'1 小时内更换链接次数过多，请稍后再试'],[/^no such feedback/,'这条反馈已不存在'],[/^answer: at most/,'回复最多 500 字'],[/^text: at most/,'最多 1000 个字'],
 [/^internal error/,'服务器内部出错，请看日志'],[/^unknown endpoint/,'这个功能不可用（可能被管理员关掉了）'],[/^login required/,'请先登录']];
function errText(m){if(typeof KT==='undefined'||KT!==KT_ZH||!m)return m;for(const [re,f] of ERR_ZH){const x=String(m).match(re);if(x)return typeof f==='string'?f:f(...x);}return m;}
function toast(text,kind){if(kind==='err')text=errText(text);let box=$('toasts');if(!box){box=h('div',{id:'toasts','aria-live':'polite'});document.body.append(box);}const t=h('div',{class:'toast'+(kind==='err'?' err':''),role:'status'},text);const close=()=>{t.classList.add('out');setTimeout(()=>t.remove(),200);};t.onclick=close;box.append(t);setTimeout(close,kind==='err'?8000:4500);while(box.children.length>4)box.firstChild.remove();}
function modal({title,text,input,value,type,confirm,danger,cancel,placeholder,multiline,maxlength}){return new Promise(res=>{const d=h('dialog',{class:'modal'});const f=h('form',{method:'dialog'});let field=null;if(input){const a={placeholder:placeholder||''};if(maxlength>0)a.maxlength=String(maxlength);field=multiline?h('textarea',a):h('input',Object.assign({type:type||'text',autocomplete:'off'},a));field.value=value??'';if(type==='number'){field.step='any';field.min='0.001';}}
 const ok=h('button',{class:'btn '+(danger?'danger':'primary'),type:'submit'},confirm||KT.ok);const no=h('button',{class:'btn ghost',type:'button'},cancel||KT.cancel);
 f.append(...[h('h3',{text:title||KT.confirm}),text?h('p',{text}):null,field,h('div',{class:'acts'},no,ok)].filter(Boolean));d.append(f);document.body.append(d);
 let done=false;const finish=v=>{if(done)return;done=true;d.close();d.remove();res(v);};
 no.onclick=()=>finish(null);d.addEventListener('cancel',e=>{e.preventDefault();finish(null)});f.onsubmit=e=>{e.preventDefault();finish(field?field.value:true)};d.showModal();(field||ok).focus();if(field&&field.select)field.select();});}
const confirmBox=(title,text,o)=>modal(Object.assign({title,text},o||{})).then(v=>v===true);
async function copyText(text,label){const s=String(text??'');try{await navigator.clipboard.writeText(s);toast(KT.copied.replace(/ · $/,'')+(label?' · '+label:''));}catch{await modal({title:KT.manual,text:KT.manual_tip,input:true,value:s,multiline:s.includes('\n'),confirm:KT.ok});}}

/* ---------- animation loop ---------- */
const Ticker={items:new Set(),running:false,
 add(o){this.items.add(o);this.start();return o;},remove(o){this.items.delete(o);},
 dirtyAll(){for(const o of this.items)o.dirty=true;this.start();},
 start(){if(this.running)return;this.running=true;requestAnimationFrame(t=>this.frame(t));},
 frame(t){if(document.hidden){this.running=false;return;}let again=false;for(const o of this.items){if(o.el&&!o.el.isConnected){if(o.destroy)o.destroy();this.items.delete(o);continue;}if(o.el&&o.el.offsetParent===null&&o.el.getClientRects().length===0)continue;if(o.tick(t))again=true;}
  if(again)requestAnimationFrame(x=>this.frame(x));else this.running=false;}};
document.addEventListener('visibilitychange',()=>{if(!document.hidden)Ticker.dirtyAll();});

/* Number that glides to its new value instead of jumping. */
class Tween{constructor(el,format){this.el=el;this.format=format||(v=>String(Math.round(v)));this.from=0;this.to=null;this.v=null;this.t0=0;this.dur=700;Ticker.add(this);}
 set(v){if(v==null||!isFinite(v)){this.to=null;this.v=null;this.el.textContent=this.format(null);return;}if(this.v==null){this.v=this.to=v;this.el.textContent=this.format(v);return;}this.from=this.v;this.to=v;this.t0=performance.now();Ticker.start();}
 tick(t){if(this.to==null||this.v===this.to)return false;const k=Math.min(1,(t-this.t0)/this.dur),e=1-Math.pow(1-k,3);this.v=k>=1?this.to:this.from+(this.to-this.from)*e;this.el.textContent=this.format(this.v);return k<1;}}

function setupCanvas(cv){const r=cv.getBoundingClientRect(),dpr=Math.min(2,window.devicePixelRatio||1);const w=Math.max(1,Math.round(r.width*dpr)),hh=Math.max(1,Math.round(r.height*dpr));if(cv.width!==w||cv.height!==hh){cv.width=w;cv.height=hh;}const ctx=cv.getContext('2d');ctx.setTransform(dpr,0,0,dpr,0,0);return {ctx,w:r.width,h:r.height};}
function niceStep(max,count){const raw=max/count,mag=Math.pow(10,Math.floor(Math.log10(raw||1))),n=raw/mag;return (n<=1?1:n<=2?2:n<=2.5?2.5:n<=5?5:10)*mag;}
/* Monotone cubic through points in screen space: smooth, never overshoots. */
function traceMonotone(ctx,p,move){const n=p.length;if(!n)return;if(move)ctx.moveTo(p[0][0],p[0][1]);else ctx.lineTo(p[0][0],p[0][1]);if(n<3){for(let i=1;i<n;i++)ctx.lineTo(p[i][0],p[i][1]);return;}
 const d=[],m=new Array(n);for(let i=0;i<n-1;i++)d.push((p[i+1][1]-p[i][1])/((p[i+1][0]-p[i][0])||1e-6));m[0]=d[0];m[n-1]=d[n-2];for(let i=1;i<n-1;i++)m[i]=d[i-1]*d[i]<=0?0:(d[i-1]+d[i])/2;
 for(let i=0;i<n-1;i++){if(d[i]===0){m[i]=m[i+1]=0;continue;}const a=m[i]/d[i],b=m[i+1]/d[i],s=a*a+b*b;if(s>9){const k=3/Math.sqrt(s);m[i]=k*a*d[i];m[i+1]=k*b*d[i];}}
 for(let i=0;i<n-1;i++){const hx=(p[i+1][0]-p[i][0])/3;ctx.bezierCurveTo(p[i][0]+hx,p[i][1]+hx*m[i],p[i+1][0]-hx,p[i+1][1]-hx*m[i+1],p[i+1][0],p[i+1][1]);}}

/* Server clock estimate so the live window lines up with sample timestamps. */
const Clock={offset:null,seen(serverT){const o=serverT-Date.now()/1000;if(this.offset==null||Math.abs(o-this.offset)>5)this.offset=o;else this.offset+=0.25*(o-this.offset);},now(){return Date.now()/1000+(this.offset||0);}};

/* Streaming chart: the time axis glides continuously; rendering trails real time by
   ~1.5 sample intervals so the newest segment is always already known (no jumps). */
class LiveChart{
 constructor(el,o){this.el=el;this.o=Object.assign({span:180,delay:7.5,axis:true,series:[{key:'down',color:'down',fill:true},{key:'up',color:'up',fill:false}],min:0.2,pad:[10,8,18,8],head:true},o||{});
  this.cv=h('canvas');el.append(this.cv);this.pts=[];this.ymax=null;this.last=0;this.dirty=true;
  if(this.o.tooltip!==false&&this.o.axis){this.tip=h('div',{class:'tip hide'});el.append(this.tip);el.addEventListener('pointermove',e=>{this.hover=e.offsetX;this.dirty=true;Ticker.start();});el.addEventListener('pointerleave',()=>{this.hover=null;this.tip.classList.add('hide');});}
  this.ro=new ResizeObserver(()=>{this.dirty=true;Ticker.start();});this.ro.observe(el);Ticker.add(this);}
 destroy(){if(this.ro){this.ro.disconnect();this.ro=null;}Ticker.remove(this);}
 push(points){let changed=false;for(const p of points){const t=+p.t;if(!isFinite(t))continue;const i=this.pts.findIndex(q=>Math.abs(q.t-t)<1);if(i>=0){this.pts[i]=p;}else{this.pts.push(p);changed=true;}}if(changed)this.pts.sort((a,b)=>a.t-b.t);const cut=Clock.now()-this.o.span-this.o.delay-30;while(this.pts.length>2&&this.pts[1].t<cut)this.pts.shift();this.dirty=true;Ticker.start();}
 reset(){this.pts=[];this.ymax=null;this.dirty=true;}
 tick(t){const live=this.pts.length>1;if(!live&&!this.dirty)return false;this.dirty=false;this.draw(t);return live;}
 draw(t){const P=Palette.v,{ctx,w,h}=setupCanvas(this.cv),[pt,pr,pb,pl]=this.o.pad;ctx.clearRect(0,0,w,h);const right=Clock.now()-this.o.delay,left=right-this.o.span;const X=tt=>pl+(w-pl-pr)*(tt-left)/(right-left);
  const vis=this.pts.filter((p,i,a)=>(p.t>=left&&p.t<=right)||(a[i+1]&&a[i+1].t>=left&&p.t<left)||(a[i-1]&&a[i-1].t<=right&&p.t>right));
  let target=this.o.min;for(const p of vis)for(const s of this.o.series)target=Math.max(target,p[s.key]||0);target*=1.18;
  const dt=this.lastT?Math.min(.1,(t-this.lastT)/1000):0;this.lastT=t;this.ymax=this.ymax==null?target:this.ymax+(target-this.ymax)*Math.min(1,dt*2.5);
  const Y=v=>pt+(h-pt-pb)*(1-Math.max(0,v)/this.ymax);
  if(this.o.axis){const step=niceStep(this.ymax,3);ctx.font='10.5px '+Palette.mono;ctx.textBaseline='bottom';for(let v=step;v<this.ymax;v+=step){const y=Math.round(Y(v))+.5;ctx.strokeStyle=alpha(P.line||'#888',.9);ctx.setLineDash([3,5]);ctx.beginPath();ctx.moveTo(pl,y);ctx.lineTo(w-pr,y);ctx.stroke();ctx.setLineDash([]);ctx.fillStyle=P.muted;ctx.fillText(fmt.mbps(v)+' Mbps',pl+2,y-3);}
   ctx.strokeStyle=P.line;ctx.beginPath();ctx.moveTo(pl,h-pb+.5);ctx.lineTo(w-pr,h-pb+.5);ctx.stroke();ctx.fillStyle=P.muted;ctx.textBaseline='top';ctx.textAlign='right';ctx.fillText(KT.now,w-pr,h-pb+4);ctx.textAlign='left';ctx.fillText(Math.round(this.o.span/60*10)/10+KT.min_ago,pl,h-pb+4);ctx.textAlign='center';ctx.fillText(Math.round(this.o.span/120*10)/10+KT.min,pl+(w-pl-pr)/2,h-pb+4);ctx.textAlign='left';}
  ctx.save();ctx.beginPath();ctx.rect(pl,0,w-pl-pr,h);ctx.clip();
  for(const s of [...this.o.series].reverse()){if(vis.length<2)break;const pts=vis.map(p=>[X(p.t),Y(p[s.key]||0)]),col=P[s.color]||s.color;
   if(s.fill){const g=ctx.createLinearGradient(0,pt,0,h-pb);g.addColorStop(0,alpha(col,.32));g.addColorStop(1,alpha(col,0));ctx.beginPath();traceMonotone(ctx,pts,true);ctx.lineTo(pts[pts.length-1][0],h-pb);ctx.lineTo(pts[0][0],h-pb);ctx.closePath();ctx.fillStyle=g;ctx.fill();}
   ctx.beginPath();traceMonotone(ctx,pts,true);ctx.strokeStyle=col;ctx.lineWidth=s.fill?2:1.6;ctx.lineJoin='round';ctx.stroke();}
  ctx.restore();
  if(this.o.head&&vis.length>1){const s=this.o.series[0],col=P[s.color]||s.color;const last=vis[vis.length-1],prev=vis[vis.length-2];let hx,hy;if(last.t>right){const k=(right-prev.t)/((last.t-prev.t)||1);hx=X(right);hy=Y((prev[s.key]||0)+((last[s.key]||0)-(prev[s.key]||0))*k);}else{hx=X(last.t);hy=Y(last[s.key]||0);}
   const pulse=(Math.sin(t/300)+1)/2;ctx.fillStyle=alpha(col,.18+.12*pulse);ctx.beginPath();ctx.arc(hx,hy,6+3*pulse,0,7);ctx.fill();ctx.fillStyle=col;ctx.beginPath();ctx.arc(hx,hy,3,0,7);ctx.fill();}
  if(this.tip){if(this.hover!=null&&vis.length){const tt=left+(this.hover-pl)/(w-pl-pr)*(right-left);let best=null;for(const p of vis)if(!best||Math.abs(p.t-tt)<Math.abs(best.t-tt))best=p;if(best&&best.t>=left&&best.t<=right){const x=X(best.t);ctx.strokeStyle=alpha(P.text,.35);ctx.beginPath();ctx.moveTo(x+.5,pt);ctx.lineTo(x+.5,h-pb);ctx.stroke();this.tip.textContent=new Date((best.t-(Clock.offset||0))*1000).toLocaleTimeString(KT.locale,{hour12:false})+(KT===KT_ZH?'　':'  ')+'↓ '+fmt.mbps(best.down||0)+'  ↑ '+fmt.mbps(best.up||0)+' Mbps';placeTip(this.tip,x,Math.max(40,Y(best.down||0)),w);}else this.tip.classList.add('hide');}}}}

/* One device row, the same in the member center and the admin panel: the name (cut with an ellipsis, the full
   name on hover), then two fixed lines - platform · version · IP, and "last seen" with the date (never split; the
   relative time is its hover text) - with status and buttons on the right. A device without a name is called by
   its platform, so the platform is not repeated below it. */
const PLATFORM_NAMES={windows:'Windows',macos:'macOS',android:'Android',ios:'iOS',linux:'Linux'};
function deviceRow(x,seenLabel,acts){const pf=PLATFORM_NAMES[x.platform]||x.platform,name=x.name||pf;
 const info=[x.name?pf:'',x.version,x.ip].filter(Boolean).join(' · ');
 return h('div',{class:'tl-row dv-row'},h('div',{class:'dv-main'},h('b',{class:'dv-name',title:name},name),
  info?h('span',{class:'muted dv-meta'},info):null,
  x.last_seen?h('span',{class:'muted dv-meta nw',title:fmt.ago(x.last_seen)},seenLabel+' '+fmt.time(x.last_seen)):null),
  h('span',{class:'tl-acts'},...acts));}
/* history entries from the API -> chart points in Mbps */
const toPoints=hist=>(hist||[]).map(x=>({t:x.at,down:x.download_bps*8/1e6,up:x.upload_bps*8/1e6}));

/* Day-by-day stacked bars (download + upload), with hover tooltip. */
class DayBars{
 constructor(el,o){this.el=el;this.o=Object.assign({pad:[12,6,22,6],days:null},o||{});this.cv=h('canvas');this.tip=h('div',{class:'tip hide'});el.append(this.cv,this.tip);this.data=[];this.hover=null;this.grow=0;this.dirty=true;
  el.addEventListener('pointermove',e=>{this.hover=e.offsetX;this.dirty=true;Ticker.start();});el.addEventListener('pointerleave',()=>{this.hover=null;this.tip.classList.add('hide');this.dirty=true;Ticker.start();});
  this.ro=new ResizeObserver(()=>{this.dirty=true;Ticker.start();});this.ro.observe(el);Ticker.add(this);}
 destroy(){if(this.ro){this.ro.disconnect();this.ro=null;}Ticker.remove(this);}
 set(rows,days){this.data=rows||[];this.days=days||null;this.t0=performance.now();this.dirty=true;Ticker.start();}
 tick(t){const k=this.t0?Math.min(1,(t-this.t0)/700):1;if(!this.dirty&&k>=1)return false;this.dirty=false;this.draw(1-Math.pow(1-k,3));return k<1;}
 draw(k){const P=Palette.v,{ctx,w,h}=setupCanvas(this.cv),[pt,pr,pb,pl]=this.o.pad;ctx.clearRect(0,0,w,h);const rows=this.days?this.days.map(d=>this.data.find(r=>r.day===d)||{day:d,upload:0,download:0}):this.data;
  if(!rows.length){ctx.fillStyle=P.muted;ctx.font='12px sans-serif';ctx.textAlign='center';ctx.fillText(KT.no_usage,w/2,h/2);ctx.textAlign='left';return;}
  const max=Math.max(1,...rows.map(r=>r.upload+r.download))*1.1,n=rows.length,slot=(w-pl-pr)/n,bw=Math.max(2,Math.min(26,slot*.62));
  ctx.strokeStyle=P.line;ctx.beginPath();ctx.moveTo(pl,h-pb+.5);ctx.lineTo(w-pr,h-pb+.5);ctx.stroke();
  let hi=-1;if(this.hover!=null)hi=Math.max(0,Math.min(n-1,Math.floor((this.hover-pl)/slot)));
  rows.forEach((r,i)=>{const x=pl+slot*i+(slot-bw)/2,H=h-pt-pb,dh=H*r.download/max*k,uh=H*r.upload/max*k,y0=h-pb;const dim=hi>=0&&hi!==i;
   ctx.globalAlpha=dim?.4:1;ctx.fillStyle=P.down;rr(ctx,x,y0-dh,bw,dh,uh>1?0:3);ctx.fillStyle=P.up;rr(ctx,x,y0-dh-uh,bw,uh,3);ctx.globalAlpha=1;});
  ctx.fillStyle=P.muted;ctx.font='10.5px '+Palette.mono;ctx.textBaseline='top';const every=Math.ceil(n/(w/52));rows.forEach((r,i)=>{if(i!==n-1&&(i%every||n-1-i<every))return;ctx.textAlign='center';const lb=r.day.slice(5).replace('-','/'),tw=ctx.measureText(lb).width/2;ctx.fillText(lb,Math.min(w-tw,Math.max(tw,pl+slot*(i+.5))),h-pb+5);});ctx.textAlign='left';
  if(hi>=0){const r=rows[hi];this.tip.textContent=r.day+(KT===KT_ZH?'　':' · ')+KT.total+' '+fmt.bytes(r.upload+r.download)+'\n↓ '+fmt.bytes(r.download)+'  ↑ '+fmt.bytes(r.upload);placeTip(this.tip,pl+slot*(hi+.5),Math.max(44,(h-pb-(h-pt-pb)*(r.upload+r.download)/max)),w);}}}
function rr(ctx,x,y,w,h,r){if(h<=0)return;r=Math.min(r,h,w/2);ctx.beginPath();ctx.moveTo(x,y+h);ctx.lineTo(x,y+r);ctx.quadraticCurveTo(x,y,x+r,y);ctx.lineTo(x+w-r,y);ctx.quadraticCurveTo(x+w,y,x+w,y+r);ctx.lineTo(x+w,y+h);ctx.closePath();ctx.fill();}

/* Progress ring (canvas), animates between values. */
class Ring{constructor(el,o){this.el=el;this.o=Object.assign({width:12},o||{});this.cv=h('canvas');el.append(this.cv);this.v=0;this.to=0;this.from=0;this.t0=0;this.color='down';this.dirty=true;this.ro=new ResizeObserver(()=>{this.dirty=true;Ticker.start();});this.ro.observe(el);Ticker.add(this);}
 destroy(){if(this.ro){this.ro.disconnect();this.ro=null;}Ticker.remove(this);}
 set(v,color){this.from=this.v;this.to=Math.max(0,Math.min(1,v));this.color=color||'down';this.t0=performance.now();this.dirty=true;Ticker.start();}
 tick(t){const k=Math.min(1,(t-this.t0)/900);if(!this.dirty&&k>=1)return false;this.dirty=false;this.v=this.from+(this.to-this.from)*(1-Math.pow(1-k,3));const P=Palette.v,{ctx,w,h}=setupCanvas(this.cv),r=Math.min(w,h)/2-this.o.width/2-2,cx=w/2,cy=h/2;ctx.clearRect(0,0,w,h);ctx.lineCap='round';ctx.lineWidth=this.o.width;ctx.strokeStyle=P['panel-3'];ctx.beginPath();ctx.arc(cx,cy,r,0,7);ctx.stroke();
  if(this.v>0.001){const col=P[this.color]||this.color;const g=ctx.createConicGradient?ctx.createConicGradient(-Math.PI/2,cx,cy):null;if(g){g.addColorStop(0,alpha(col,.55));g.addColorStop(Math.max(.01,this.v),col);g.addColorStop(Math.min(1,this.v+.001),col);ctx.strokeStyle=g;}else ctx.strokeStyle=col;ctx.beginPath();ctx.arc(cx,cy,r,-Math.PI/2,-Math.PI/2+Math.PI*2*this.v);ctx.stroke();}return k<1;}}

/* API helper */
function makeApi(base,csrf){return async function api(path,method,data){const opt={method:method||'GET',credentials:'same-origin',cache:'no-store',headers:{'X-CSRF-Token':csrf}};if(data!==undefined){opt.headers['Content-Type']='application/json';opt.body=JSON.stringify(data);}
 let r;try{r=await fetch(base+path,opt);}catch{throw Error(KT.net);}let j={};try{j=await r.json();}catch{}if(!r.ok){if(r.status===401){toast(KT.relogin,'err');setTimeout(()=>location.reload(),1200);}throw Error(j.error||(KT.failed+' ('+r.status+')'));}return j;};}
