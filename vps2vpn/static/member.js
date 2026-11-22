'use strict';
/* vps2vpn member centre and personal subscription page. Same kit as the admin console.
   Two ways in: the person's own subscription link (/s/<token>/, the link is the key), or the member
   centre (/<member path>/) with a name and password, where invite codes also create new accounts. */
const T = {
  zh: {
    kicker: 'MEMBER', title: '我的 VPN', login: '登录', register: '用邀请码注册', name: '用户名', password: '密码',
    password_new: '设置密码（至少 8 位）', password2: '再输一次', code: '邀请码', have_code: '有邀请码？注册新账号', have_account: '已有账号？去登录',
    login_intro: '用管理员给你的用户名和密码登录。没有密码的话，打开管理员发你的订阅链接也能看到这一页。',
    reg_intro: '输入朋友或管理员给你的邀请码，起个名字、设个密码，马上就能用。',
    art_h: '你的专属线路，\n随时看用量。', art_p: '流量、到期、订阅导入、增加额度、邀请朋友，都在这里。',
    art_1: '三种协议随时切换', art_2: '一键导入 Clash / 小火箭', art_3: '用量透明，按天可查',
    logout: '退出', wrong: '用户名或密码错误', mismatch: '两次密码不一样',
    used: '已用', quota: '总额度', left: '剩余', unlimited: '不限量', expires: '到期', never: '永久', reset: '下次重置', none: '不重置',
    down: '下行', up_: '上行', status: '状态', ok: '正常', paused: '已停用', r_quota: '流量用完了', r_expired: '已到期', r_manual: '被管理员停用', r_remote: '被主服务器停用', r_devices: '同时在线设备超限',
    shared: '分给邀请的人', invited_by: '邀请人', online: '在线', online_now: '正在使用', devices: '个设备', offline: '当前未连接',
    import: '导入到 App', import_tip: '手机上直接点按钮；电脑上复制链接，在 App 里「从 URL 导入」。订阅会自动更新。', copy: '复制订阅链接',
    sr_full: '小火箭（完整配置：节点+分流+DNS）', sr_nodes: '小火箭（只导入节点）', scan: '手机扫码导入',
    apps: '装哪个 App', open_app: '在 vps2vpn 客户端中打开', get_app: '还没装 vps2vpn 客户端？点这里下载（免费）',
    apps_list: [['Windows', 'vps2vpn 客户端（免费，推荐），或 Clash Verge Rev、FlClash'], ['macOS', 'Clash Verge Rev 或 FlClash（免费）'], ['Android', 'FlClash 或 Hiddify（免费）'], ['iPhone / iPad', 'Shadowrocket 小火箭或 Stash（都要付费），免费的用 Karing']],
    apps_tip: '导入后打开 App 里的「系统代理」或「VPN / TUN 模式」开关就行。',
    history: '每日用量', history_sub: '近 30 天', more: '申请增加流量', more_tip: '流量不够用时，告诉管理员你需要多少、为什么。批准后立刻生效，只在本期有效，到下次重置日自动取消。',
    add_gb: '需要增加多少 GB', reason: '说明（可选）', send: '提交申请', sent: '已提交，等管理员批准',
    pending: '等待批准', approved: '已批准', rejected: '未批准', req_none: '还没有申请记录。',
    invites: '邀请朋友', invites_tip: '从你自己的额度里分一部分给朋友。朋友一注册，你每月的额度就立刻少掉分给他的那部分，直到他的账号到期或被删除；他用多少都只从这部分里扣。邀请码还没人用时可以随时撤销；已经注册的人要收回额度，需要找管理员。你自己至少保留 1 GB。',
    can_share: '还能分出', quota_each: '每人多少 GB', uses: '可用几次', valid: '邀请码有效几天', note: '备注（可选）', make: '生成邀请码',
    no_share: '不限量账号不能分额度；需要邀请码请找管理员。', inv_none: '还没有生成过邀请码。', revoke: '撤销', revoked: '已撤销',
    st_unused: '可用', st_used: '已用完', st_revoked: '已撤销', st_expired: '已过期', st_void: '已失效：你的额度不够了', reserved: '已预留给邀请码', used_by: '已注册', send_link: '复制注册链接',
    invitees: '你邀请的人', pw: '登录密码', pw_tip: '设置密码后，可以用用户名和密码登录会员中心（忘了订阅链接也不怕）。', pw_tip_link: '用你的专属链接打开这一页时，不用输入旧密码就能设新密码（链接本身就是钥匙）。', pw_set: '设置密码', pw_change: '修改密码', pw_old: '当前密码',
    saved: '已保存', member_link: '会员中心地址', link_mode: '这是你的专属页面，链接就是钥匙，不要发给别人。', days: '天',
    notice: '管理员公告', paused_quota: '这一期的流量用完了，所以暂时停用。', q_ask: '可以在下面「申请增加流量」。', q_wait: '到 {date} 重置后会自动恢复。', q_admin: '这个账号不会自动重置，请联系管理员。',
    extra: '本期临时加量', first_use: '首次使用后 {n} 天', inv_copied: '注册链接已复制，发给朋友打开就能注册', dev_limit: '（最多同时 {n} 台）',
    paused_expired: '账号已到期，请联系管理员续期。', paused_devices: '同时在线设备超过上限{lim}，已自动暂停 10 分钟。关掉多余的设备，稍后会自动恢复。', paused_other: '账号被暂停了，有问题请联系管理员。',
    expiring: '账号将在 {d} 天后到期（{date}），需要续期请联系管理员。', low: '流量快用完了：只剩 {left}。', slowed: '本期流量已用完，已降速到 {mbps} Mbps，下次重置或加流量后恢复。', capped: '这个账号限速 {mbps} Mbps。',
    security: '账号安全', rotate: '更换订阅链接', rotate_tip: '链接不小心发给了别人？换一个新的，旧链接立刻失效。换完后每台设备都要重新导入一次。',
    rotate_q: '更换后旧链接马上不能用了，所有设备都要重新导入。确定吗？', rotated: '已更换，请重新导入到 App',
    rotate_q_link: '更换后，你现在打开的这个页面地址也会失效。还没设密码的话，最好先在上面设一个；或者换完后一定要保存好新链接。确定更换吗？',
    new_link: '新的订阅链接', new_link_tip: '旧链接已经失效。请复制保存这个新链接，并在每台设备上重新导入。', copy_short: '复制', close: '关闭',
    wx: '在微信 / QQ 里打不开 App。请点右上角 ··· 选「在浏览器打开」，或点「复制订阅链接」到 App 里导入。'
  },
  en: {
    kicker: 'MEMBER', title: 'My VPN', login: 'Log in', register: 'Register with an invite code', name: 'Name', password: 'Password',
    password_new: 'Choose a password (8+ characters)', password2: 'Repeat it', code: 'Invite code', have_code: 'Have an invite code? Create an account', have_account: 'Already have an account? Log in',
    login_intro: 'Use the name and password you were given. No password? Opening your subscription link shows this page too.',
    reg_intro: 'Enter the invite code you were given, pick a name and a password, and you are ready.',
    art_h: 'Your own line,\nyour usage at a glance.', art_p: 'Usage, expiry, one-tap import, asking for more and inviting friends, all here.',
    art_1: 'Three protocols to switch between', art_2: 'One-tap import into Clash / Shadowrocket', art_3: 'Clear usage, day by day',
    logout: 'Log out', wrong: 'Wrong name or password', mismatch: 'Passwords do not match',
    used: 'Used', quota: 'Quota', left: 'Left', unlimited: 'unlimited', expires: 'Expires', never: 'never', reset: 'Next reset', none: 'never',
    down: 'down', up_: 'up', status: 'Status', ok: 'active', paused: 'paused', r_quota: 'quota used up', r_expired: 'expired', r_manual: 'paused by the admin', r_remote: 'paused by the main server', r_devices: 'too many devices',
    shared: 'Shared with invitees', invited_by: 'Invited by', online: 'Online', online_now: 'in use now', devices: 'device(s)', offline: 'not connected',
    import: 'Import into an app', import_tip: 'On a phone tap a button; on a computer copy the link and use "Import from URL". It updates itself.', copy: 'Copy subscription link',
    sr_full: 'Shadowrocket (full config: nodes + routing + DNS)', sr_nodes: 'Shadowrocket (nodes only)', scan: 'Scan with your phone',
    apps: 'Which app', open_app: 'Open in the vps2vpn app', get_app: 'No vps2vpn app yet? Download it here (free)',
    apps_list: [['Windows', 'the vps2vpn app (free, recommended), or Clash Verge Rev / FlClash'], ['macOS', 'Clash Verge Rev or FlClash (free)'], ['Android', 'FlClash or Hiddify (free)'], ['iPhone / iPad', 'Shadowrocket or Stash (both paid), or Karing (free)']],
    apps_tip: 'After importing, switch on "System proxy" or "VPN / TUN mode" in the app.',
    history: 'Daily usage', history_sub: 'last 30 days', more: 'Ask for more', more_tip: 'Running low? Tell the admin how much you need and why; it applies as soon as it is approved, for this period only (until the next reset).',
    add_gb: 'Extra GB', reason: 'Why (optional)', send: 'Send request', sent: 'Sent; waiting for the admin',
    pending: 'waiting', approved: 'approved', rejected: 'declined', req_none: 'No requests yet.',
    invites: 'Invite friends', invites_tip: 'Share part of your quota. As soon as a friend registers, your monthly quota drops by their share until their account expires or is deleted; what they use only comes out of that share. You can revoke a code nobody has used yet; taking a share back from someone who already registered needs the admin. You always keep at least 1 GB.',
    can_share: 'You can share', quota_each: 'GB per person', uses: 'Uses', valid: 'Code valid (days)', note: 'Note (optional)', make: 'Create code',
    no_share: 'Unlimited accounts cannot share quota; ask the admin for invite codes.', inv_none: 'No invite codes yet.', revoke: 'Revoke', revoked: 'Revoked',
    st_unused: 'usable', st_used: 'used up', st_revoked: 'revoked', st_expired: 'expired', st_void: 'void: not enough quota left', reserved: 'Kept for invite codes', used_by: 'Registered', send_link: 'Copy sign-up link',
    invitees: 'People you invited', pw: 'Password', pw_tip: 'With a password you can log in to the member centre by name (handy if you lose the link).', pw_tip_link: 'Opened from your personal link, you can set a new password without the old one (the link itself is the key).', pw_set: 'Set password', pw_change: 'Change password', pw_old: 'Current password',
    saved: 'Saved', member_link: 'Member centre', link_mode: 'This is your personal page. The link is the key: do not share it.', days: 'days',
    notice: 'Notice from the admin', paused_quota: 'This period\u2019s quota is used up, so the account is paused. ', q_ask: 'You can ask for more below. ', q_wait: 'It resumes by itself after the reset on {date}.', q_admin: 'This account does not reset by itself; ask the admin.',
    extra: 'Top-up this period', first_use: '{n} days after first use', inv_copied: 'Sign-up link copied; your friend just opens it', dev_limit: ' (at most {n} at once)',
    paused_expired: 'The account has expired; ask the admin to extend it.', paused_devices: 'Too many devices were online at once{lim}; the account is paused for 10 minutes. Close the extra ones and it resumes by itself.', paused_other: 'The account is paused; ask the admin if this is unexpected.',
    expiring: 'The account expires in {d} days ({date}); ask the admin to extend it.', low: 'Almost out of data: {left} left.', slowed: 'This period\'s data is used up: slowed down to {mbps} Mbps until the next reset or more data.', capped: 'This account is limited to {mbps} Mbps.',
    security: 'Account security', rotate: 'New subscription link', rotate_tip: 'Shared your link by mistake? Get a new one; the old link stops working at once. Re-import it on every device.',
    rotate_q: 'The old link stops working immediately and every device must re-import. Continue?', rotated: 'Done. Import the new link into your apps.',
    rotate_q_link: 'The address of this very page stops working too. Set a password above first if you have none, or make sure to save the new link. Continue?',
    new_link: 'Your new subscription link', new_link_tip: 'The old link no longer works. Copy and keep this one, and re-import it on every device.', copy_short: 'Copy', close: 'Close',
    wx: 'Apps cannot be opened from inside WeChat / QQ. Tap ··· at the top right and choose "Open in browser", or copy the subscription link into your app.'
  }
};
let L = (navigator.language || '').startsWith('zh') ? 'zh' : 'en';
const t = k => (T[L] && T[L][k]) || T.en[k] || k;
const GB = 1073741824;
const M = {hello: null, me: null};
function setLang(l) { L = l === 'en' ? 'en' : 'zh'; KT = L === 'en' ? KT_EN : KT_ZH; document.documentElement.lang = L === 'zh' ? 'zh-CN' : 'en'; }
const localDay = ms => { const d = new Date(ms); return d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0') + '-' + String(d.getDate()).padStart(2, '0'); };

async function api(path, body) {
  let r;
  try {
    r = await fetch('api/' + path, body === undefined ? {credentials: 'same-origin', cache: 'no-store'} : {
      method: 'POST', credentials: 'same-origin', headers: {'Content-Type': 'application/json', 'X-V2V': '1'}, body: JSON.stringify(body)});
  } catch (e) { throw Error(KT.net); }
  let j = {};
  try { j = await r.json(); } catch (e) { /* empty */ }
  if (r.status === 401 && path !== 'login') { renderLogin(); throw Error('login'); }
  if (!r.ok) throw Error(j.error || (KT.failed + ' (' + r.status + ')'));
  return j;
}
const err = e => { if (e.message !== 'login') toast(e.message, 'err'); };
const field = (label, input, hint) => h('label', {class: 'field'}, h('span', null, label), input, hint ? h('em', null, hint) : null);
const panel = (title, sub, right, ...body) => h('div', {class: 'panel'},
  h('div', {class: 'panel-h'}, h('h3', null, title), sub ? h('span', {class: 'sub'}, sub) : null, right ? h('div', {class: 'right'}, right) : null),
  h('div', {class: 'panel-b'}, ...body));
const chip = (kind, text) => h('span', {class: 'chip ' + kind}, text);
const brand = () => h('div', {class: 'brand'}, h('span', {class: 'seal'}, 'V'), h('div', null, h('b', null, M.hello ? M.hello.node_name : 'vps2vpn'), h('small', null, 'MEMBER')));
const dateStr = ts => ts ? new Date(ts * 1000).toLocaleDateString(KT.locale) : t('never');
// WeChat and QQ open links in their own browser, which cannot hand clash:// etc. to an app
const inChatApp = () => /MicroMessenger|QQ\//i.test(navigator.userAgent || '');
const onWindows = () => /Windows/i.test(navigator.userAgent || '') && !inChatApp();
const chatBanner = () => inChatApp() ? h('div', {class: 'alert warn', id: 'chat-app'}, icon('alert'), t('wx')) : null;

/* ---------- sign in / register (the split layout of the console) ---------- */
function frame(card) {
  const cv = h('canvas', {'aria-hidden': 'true'});
  const art = h('section', {class: 'login-art'}, brand(),
    h('div', null, h('h2', {style: 'white-space:pre-line'}, t('art_h')), h('p', null, t('art_p')),
      h('div', {class: 'points'}, h('span', null, icon('shield'), t('art_1')), h('span', null, icon('bolt'), t('art_2')), h('span', null, icon('gauge'), t('art_3')))), cv);
  document.body.replaceChildren(h('div', {class: 'login'}, art, h('section', {class: 'login-form'}, h('div', {class: 'login-card'}, card))));
  Ticker.add({el: cv, tick(tm) {
    const {ctx, w, h: hh} = setupCanvas(cv); ctx.clearRect(0, 0, w, hh);
    [['#3fe0c5', .62], ['#7b93ff', .74], ['#ff6b4a', .86]].forEach(([c, y0], k) => {
      const pts = []; for (let i = 0; i <= 40; i++) pts.push([i / 40 * w, hh * y0 + Math.sin(i / 6 + k * 2) * hh * .05]);
      ctx.strokeStyle = alpha(c, .35); ctx.lineWidth = 2; ctx.beginPath(); traceMonotone(ctx, pts, true); ctx.stroke();
      const p = ((tm / 9000 + k * .3) % 1), i = Math.floor(p * 40), a = pts[i], b = pts[Math.min(40, i + 1)], f = p * 40 - i;
      const x = a[0] + (b[0] - a[0]) * f, y = a[1] + (b[1] - a[1]) * f, g = ctx.createRadialGradient(x, y, 0, x, y, 14);
      g.addColorStop(0, alpha(c, .9)); g.addColorStop(1, alpha(c, 0)); ctx.fillStyle = g; ctx.beginPath(); ctx.arc(x, y, 14, 0, 7); ctx.fill();
    });
    return !matchMedia('(prefers-reduced-motion: reduce)').matches;
  }});
}
function renderLogin(code) {
  const reg = code !== undefined;
  const f = {name: h('input', {type: 'text', autocomplete: 'username', required: true, maxlength: '32'}),
    pw: h('input', {type: 'password', autocomplete: reg ? 'new-password' : 'current-password', required: true}),
    pw2: h('input', {type: 'password', autocomplete: 'new-password'}), code: h('input', {type: 'text', value: code || '', placeholder: 'XXXXX-XXXXX', autocomplete: 'off', required: reg})};
  const b = h('button', {class: 'btn primary', type: 'submit'}, reg ? t('register') : t('login'));
  const msg = h('div', {class: 'err', role: 'status'});
  const sw = h('button', {class: 'btn ghost', type: 'button', onclick: () => reg ? renderLogin() : renderLogin('')}, reg ? t('have_account') : t('have_code'));
  const form = h('form', {class: 'stack'}, chatBanner(), h('div', {class: 'kicker'}, t('kicker')), h('h1', null, reg ? t('register') : t('login')),
    h('p', {class: 'intro'}, reg ? t('reg_intro') : t('login_intro')),
    reg ? field(t('code'), f.code) : null, field(t('name'), f.name), field(reg ? t('password_new') : t('password'), f.pw),
    reg ? field(t('password2'), f.pw2) : null, b, msg, sw);
  form.onsubmit = async e => {
    e.preventDefault(); msg.textContent = '';
    if (reg && f.pw.value !== f.pw2.value) { msg.textContent = t('mismatch'); return; }
    b.disabled = true;
    try {
      await api(reg ? 'register' : 'login', reg ? {code: f.code.value, name: f.name.value.trim(), password: f.pw.value} : {name: f.name.value.trim(), password: f.pw.value});
      history.replaceState(null, '', location.pathname); await renderHome(); window.scrollTo(0, 0);
    } catch (er) { if (!reg) f.pw.value = ''; msg.textContent = er.message === 'wrong name or password' ? t('wrong') : errText(er.message); b.disabled = false; }
  };
  frame(form); (reg && !code ? f.code : f.name).focus();
}

/* ---------- the dashboard ---------- */
async function renderHome() {
  try { M.me = await api('me'); } catch (e) { if (e.message !== 'login') document.body.replaceChildren(h('div', {class: 'empty'}, e.message)); return; }
  const me = M.me, used = me.used_up + me.used_down, q = me.quota_gb ? Math.max(1, (me.quota_eff || 0) * GB) : 0;   // a capped plan that shared everything is not unlimited
  const reason = {quota: 'r_quota', expired: 'r_expired', manual: 'r_manual', remote: 'r_remote', devices: 'r_devices'}[me.disabled_reason] || 'r_manual';
  const logoutBtn = M.hello.mode === 'login' ? (() => {
    const b = h('button', {class: 'btn ghost'}, icon('out'), t('logout'));
    b.onclick = async () => { b.disabled = true; try { await api('logout', {}); renderLogin(); } catch (e) { err(e); b.disabled = false; } };
    return b;
  })() : null;
  const top = h('header', {class: 'm-top'}, brand(), h('div', {class: 'm-acts'},
    h('div', {class: 'seg', role: 'group'}, ['auto', 'light', 'dark'].map(v => h('button', {'data-theme-btn': v}, icon(v === 'auto' ? 'auto' : v === 'light' ? 'sun' : 'moon')))),
    logoutBtn));
  const ringBox = h('div', {class: 'ring-box'}, h('div', {class: 'chart'}), h('div', {class: 'lbl'}, h('b', null, q ? fmt.pct(used / q) : '∞'), h('small', null, t('used'))));
  const stat = (k, v) => h('div', null, h('small', null, k), h('b', null, v));
  const on = me.online;
  const dev = on ? (on.devices != null ? on.devices : on.ips.length) : 0;
  const hero = h('div', {class: 'panel m-hero'}, h('div', {class: 'panel-b'},
    h('div', {class: 'm-hello'}, h('div', null, h('div', {class: 'kicker'}, t('kicker')), h('h1', null, me.name)),
      me.enabled ? chip('ok', t('ok')) : chip(me.disabled_reason === 'devices' ? 'warn' : 'bad', t(reason)),
      on ? chip('info', t('online_now') + (dev ? ' · ' + dev + ' ' + t('devices') : '')) : chip('off', t('offline'))),
    h('div', {class: 'usage-hero'}, ringBox, h('div', {class: 'mini-stats m-stats'},
      stat(t('used'), fmt.bytes(used)), stat(t('quota'), q ? fmt.bytes(q) : t('unlimited')),
      stat(t('left'), q ? fmt.bytes(Math.max(0, q - used - (me.reserved_gb || 0) * GB)) : t('unlimited')),
      me.reserved_gb ? stat(t('reserved'), me.reserved_gb + ' GB') : null, stat(t('expires'), !me.expire_at && me.expire_after_days ? t('first_use').replace('{n}', me.expire_after_days) : dateStr(me.expire_at)),
      me.extra_gb ? stat(t('extra'), '+' + me.extra_gb + ' GB') : null,
      stat('↓ ' + t('down'), fmt.bytes(me.used_down)), stat('↑ ' + t('up_'), fmt.bytes(me.used_up)),
      stat(t('reset'), me.next_reset ? dateStr(me.next_reset) : t('none')),
      me.shared_gb ? stat(t('shared'), me.shared_gb + ' GB') : me.invited_by ? stat(t('invited_by'), me.invited_by) : stat(t('status'), me.enabled ? t('ok') : t('paused'))))));
  const days = h('div', {class: 'chart h160'});
  const im = me.import;
  const importP = panel(t('import'), null, null, h('div', {class: 'm-import'},
    h('div', null, h('p', {class: 'muted m-tip'}, t('import_tip')),
      h('div', {class: 'creds'}, me.sub_url),
      // on Windows the big button opens our own app and imports in one click
      onWindows() && im.vps2vpn ? h('div', {class: 'stack', style: 'margin:10px 0 0;gap:6px'},
        h('a', {class: 'btn primary', href: im.vps2vpn}, icon('bolt'), t('open_app')),
        h('a', {class: 'muted', style: 'font-size:12px', href: (me.client && ((me.client.files || {}).windows || me.client.url)) || 'https://github.com/xydadada/vps2vpn-client/releases/latest', target: '_blank', rel: 'noopener noreferrer'}, t('get_app'))) : null,
      h('div', {class: 'act-grid', style: 'margin:10px 0'}, h('button', {class: onWindows() && im.vps2vpn ? 'btn' : 'btn primary', onclick: () => copyText(me.sub_url, t('copy'))}, icon('copy'), t('copy')),
        h('a', {class: 'btn', href: im.clash}, 'Clash / FlClash')),
      h('div', {class: 'import-grid'},
        h('a', {class: 'btn', href: im.shadowrocket_conf}, t('sr_full')), h('a', {class: 'btn', href: im.shadowrocket}, t('sr_nodes')),
        h('a', {class: 'btn', href: im.hiddify}, 'Hiddify'), h('a', {class: 'btn', href: im.singbox}, 'sing-box'),
        h('a', {class: 'btn', href: im.stash}, 'Stash'), h('a', {class: 'btn', href: im.karing}, 'Karing'),
        h('a', {class: 'btn', href: im.v2rayng}, 'v2rayNG'))),
    h('div', {class: 'm-qr'}, h('img', {class: 'qr', alt: t('scan'), src: 'api/qr'}), h('small', {class: 'muted'}, t('scan')))));
  const apps = panel(t('apps'), null, null, h('ul', {class: 'm-apps'}, t('apps_list').map(([a, b]) => h('li', null, h('b', null, a), h('span', null, b)))),
    h('p', {class: 'muted m-tip'}, t('apps_tip')));
  const blocks = [];
  if (M.hello.requests && me.quota_gb) blocks.push(requestsPanel());   // unlimited: nothing to ask for
  if (M.hello.invites) blocks.push(invitesPanel());
  if (M.hello.member_url || M.hello.mode !== 'link') blocks.push(passwordPanel());   // no member centre: no login to use it on
  const colon = L === 'zh' ? '：' : ': ';
  document.body.replaceChildren(h('div', {class: 'm-wrap'}, top,
    h('section', {class: 'page'},
      chatBanner(),
      M.hello.notice ? h('div', {class: 'alert info', style: 'white-space:pre-line'}, icon('bell'), h('div', null, h('b', null, t('notice') + colon), M.hello.notice)) : null,
      ...statusAlerts(me, used, q),
      M.hello.mode === 'link' ? h('div', {class: 'alert'}, icon('lock'), t('link_mode')) : null,
      hero,
      h('div', {class: 'grid g-2-1'}, importP, apps),
      panel(t('history'), t('history_sub'), h('div', {class: 'legend'}, h('span', {style: '--c:var(--down)'}, t('down')), h('span', {style: '--c:var(--up)'}, t('up_'))), days),
      h('div', {class: 'grid g-2'}, ...blocks))));
  Theme.mount();
  new Ring(ringBox.firstChild).set(q ? used / q : 0, q && used / q > .9 ? 'danger' : 'down');
  const dl = []; for (let i = 29; i >= 0; i--) dl.push(localDay(Date.now() - i * 864e5));
  new DayBars(days).set(me.history.map(x => ({day: x.day, upload: x.up, download: x.down})), dl);
}

function statusAlerts(me, used, q) {
  const out = [], fill = (s, o) => s.replace(/\{(\w+)\}/g, (_, k) => o[k]);
  const r = me.disabled_reason;
  const msg = r === 'quota' ? t('paused_quota') + (M.hello.requests && me.quota_gb ? t('q_ask') : '') +
      (me.next_reset ? fill(t('q_wait'), {date: dateStr(me.next_reset)}) : t('q_admin'))
    : r === 'devices' ? fill(t('paused_devices'), {lim: me.max_ips ? fill(t('dev_limit'), {n: me.max_ips}) : ''})
    : t(r === 'expired' ? 'paused_expired' : 'paused_other');
  if (!me.enabled) out.push(h('div', {class: 'alert ' + (r === 'devices' ? 'warn' : 'bad')}, icon('alert'), msg));
  else {
    const d = me.expire_at ? Math.ceil((me.expire_at * 1000 - Date.now()) / 864e5) : 0;
    if (me.expire_at && d <= 7) out.push(h('div', {class: 'alert warn'}, icon('clock'), fill(t('expiring'), {d: Math.max(0, d), date: dateStr(me.expire_at)})));
    if (me.throttled) out.push(h('div', {class: 'alert warn'}, icon('alert'), fill(t('slowed'), {mbps: me.limit_mbps})));
    else if (q && used / q >= .9) out.push(h('div', {class: 'alert warn'}, icon('alert'), fill(t('low'), {left: fmt.bytes(Math.max(0, q - used))})));
    if (me.speed_mbps && !me.throttled) out.push(h('div', {class: 'alert'}, icon('alert'), fill(t('capped'), {mbps: me.speed_mbps})));
  }
  return out;
}

function requestsPanel() {
  const me = M.me, f = {gb: h('input', {type: 'number', min: '1', step: '1', value: '50'}), why: h('input', {type: 'text', maxlength: '300'})};
  const pend = me.requests.some(r => r.status === 'pending');
  const b = h('button', {class: 'btn primary', disabled: pend}, icon('plus'), t('send'));
  b.onclick = async () => { b.disabled = true; try { await api('request', {add_gb: Number(f.gb.value), reason: f.why.value}); toast(t('sent')); await renderHome(); } catch (e) { err(e); b.disabled = false; } };
  const list = me.requests.length ? h('div', {class: 'tl'}, me.requests.map(r => h('div', {class: 'tl-row'},
    h('b', {class: 'num'}, '+' + r.add_gb + ' GB'), h('span', {class: 'muted'}, fmt.time(r.created_at) + (r.reason ? ' · ' + r.reason : '') + (r.answer ? ' — ' + r.answer : '')),
    chip(r.status === 'approved' ? 'ok' : r.status === 'rejected' ? 'bad' : 'warn', t(r.status))))) : h('div', {class: 'muted m-tip'}, t('req_none'));
  return panel(t('more'), null, pend ? chip('warn', t('pending')) : null, h('div', {class: 'stack'},
    h('p', {class: 'muted m-tip'}, t('more_tip')), h('div', {class: 'form-grid'}, field(t('add_gb'), f.gb), field(t('reason'), f.why)), h('div', null, b), list));
}

function invitesPanel() {
  const me = M.me;
  if (me.capacity == null) return panel(t('invites'), null, null, h('p', {class: 'muted m-tip'}, t('no_share')), invList());
  const f = {gb: h('input', {type: 'number', min: '0.1', step: '0.5', value: String(Math.min(10, me.capacity >= 1 ? Math.floor(me.capacity) : me.capacity))}),
    uses: h('input', {type: 'number', min: '1', max: '20', value: '1'}), days: h('input', {type: 'number', min: '1', max: '30', value: '7'}),
    note: h('input', {type: 'text', maxlength: '100'})};
  const b = h('button', {class: 'btn primary'}, icon('key'), t('make'));
  b.onclick = async () => {
    b.disabled = true;
    try {
      const r = await api('invite', {quota_gb: Number(f.gb.value), max_uses: Number(f.uses.value), valid_days: Number(f.days.value), note: f.note.value});
      if (r.register_url) await copyText(r.register_url, t('inv_copied')); else await copyText(r.code, t('code'));
      await renderHome();
    } catch (e) { err(e); b.disabled = false; }
  };
  return panel(t('invites'), null, chip('info plain', t('can_share') + ' ' + me.capacity + ' GB'), h('div', {class: 'stack'},
    h('p', {class: 'muted m-tip'}, t('invites_tip')),
    h('div', {class: 'form-grid'}, field(t('quota_each'), f.gb), field(t('uses'), f.uses), field(t('valid'), f.days), field(t('note'), f.note)),
    h('div', null, b), invList()));
}
function invList() {
  const me = M.me;
  const rows = me.invites.map(i => {
    const revBtn = i.status === 'unused' ? (() => {
      const b = h('button', {class: 'btn sm'}, t('revoke'));
      b.onclick = async () => {
        if (!await confirmBox(t('revoke'), i.code)) return;
        b.disabled = true;
        try { await api('invite-revoke', {id: i.id}); toast(t('revoked')); await renderHome(); } catch (e) { err(e); b.disabled = false; }
      };
      return b;
    })() : null;
    return h('div', {class: 'tl-row'},
      h('code', {class: 'code-chip'}, i.code),
      h('span', {class: 'muted'}, i.quota_gb + ' GB · ' + i.uses + '/' + i.max_uses + (i.used_by.length ? ' · ' + t('used_by') + ' ' + i.used_by.join(', ') : '') + ' · ' + fmt.time(i.valid_until)),
      h('span', {class: 'tl-acts'}, i.void ? chip('bad', t('st_void')) : chip(i.status === 'unused' ? 'ok' : 'off', t('st_' + i.status)),
        i.status === 'unused' && i.register_url ? h('button', {class: 'btn sm', onclick: () => copyText(i.register_url, t('send_link'))}, icon('link')) : null,
        revBtn));
  });
  const sep = L === 'zh' ? '：' : ': ', joiner = L === 'zh' ? '，' : ', ';
  const who = me.invitees.length ? h('div', {class: 'muted m-tip'}, t('invitees') + sep + me.invitees.map(x => x.name + ' (' + x.quota_gb + ' GB' + (x.active ? '' : ', ' + t('paused')) + ')').join(joiner)) : null;
  return h('div', {class: 'stack'}, rows.length ? h('div', {class: 'tl'}, rows) : h('div', {class: 'muted m-tip'}, t('inv_none')), who);
}

function passwordPanel() {
  const me = M.me, f = {old: h('input', {type: 'password', autocomplete: 'current-password'}), nw: h('input', {type: 'password', autocomplete: 'new-password'})};
  const b = h('button', {class: 'btn'}, icon('lock'), me.has_login ? t('pw_change') : t('pw_set'));
  b.onclick = async () => { b.disabled = true; try { await api('password', {old: f.old.value, new: f.nw.value}); toast(t('saved')); await renderHome(); } catch (e) { err(e); b.disabled = false; } };
  const rot = h('button', {class: 'btn'}, icon('refresh'), t('rotate'));
  const byLink = M.hello.mode === 'link';
  rot.onclick = async () => {
    if (!await confirmBox(t('rotate'), t(byLink ? 'rotate_q_link' : 'rotate_q'))) return;
    rot.disabled = true;
    let r;
    try { r = await api('rotate', {}); } catch (e) { err(e); rot.disabled = false; return; }
    // Show the new link before anything else: in link mode this page's own address has just stopped working.
    const ok = await modal({title: t('new_link'), text: t('new_link_tip') + '\n\n' + r.sub_url.replace(/(.{24})/g, '$1​'), confirm: t('copy_short'), cancel: t('close')});
    if (ok) await copyText(r.sub_url, t('copy'));
    toast(t('rotated'));
    if (r.base) { location.replace(r.base); return; }
    await renderHome();
  };
  const sep = L === 'zh' ? '：' : ': ';
  return panel(t('security'), null, null, h('div', {class: 'stack'}, h('p', {class: 'muted m-tip'}, t('pw_tip') + (byLink && me.has_login ? ' ' + t('pw_tip_link') : '')),
    h('div', {class: 'form-grid'}, me.has_login && !byLink ? field(t('pw_old'), f.old) : null, field(t('password_new'), f.nw)), h('div', null, b),
    h('p', {class: 'muted m-tip', style: 'margin-top:8px'}, t('rotate_tip')), h('div', null, rot),
    M.hello.member_url ? h('div', {class: 'muted m-tip'}, t('member_link') + sep, h('a', {href: M.hello.member_url}, M.hello.member_url)) : null));
}

async function boot() {
  try { M.hello = await api('hello'); } catch (e) { document.body.replaceChildren(h('div', {class: 'empty'}, e.message)); return; }
  setLang(M.hello.language); Theme.apply(Theme.get());
  document.title = (M.hello.node_name || 'vps2vpn') + ' · ' + t('title');
  const reg = (location.hash.match(/register=([A-Z0-9-]+)/i) || [])[1];
  if (M.hello.mode === 'login' && reg !== undefined) return renderLogin(reg);
  if (!M.hello.logged_in) return renderLogin();
  renderHome();
}
boot();
