'use strict';
/* vps2vpn panel. Built on kit.js, the component kit of the original admin console. No framework, no external scripts. */
const T = {
  zh: {
    welcome: '欢迎使用 vps2vpn', welcome_sub: '三步把这台服务器变成你自己的 VPN，其他都已经自动设好。',
    art_h: '一台服务器，\n一个属于你的 VPN。', art_p: '三种协议随时切换，订阅一键导入 Clash 和小火箭，流量、到期、证书、告警全自动。',
    art_1: 'VLESS + REALITY · Hysteria 2 · TUIC v5', art_2: '自动证书、自动调优、自动备份', art_3: '一键体检，发现问题时给出修复方法',
    admin: '管理员账号', username: '用户名', password: '密码（至少 8 位）', password2: '再输一次密码',
    first_user: '第一个用户的名字', server_addr: '服务器地址（IP 或域名，已自动识别；修改后订阅链接也会改变，需要把新链接重新发给大家）',
    next: '下一步', back: '上一步', build: '开始搭建', building: '搭建中，大约 10 秒…',
    advanced: '高级选项（不了解时请保持默认）', lang: '语言 / Language',
    time_zone: '每月重置按哪个时区', tz_server: '服务器自己的时间',
    login: '登录', login_intro: '输入安装时设置的管理员账号。连续输错 8 次会锁定 10 分钟。', logout: '退出登录', wrong: '用户名或密码错误',
    nav_main: '运营', nav_infra: '服务器', nav_home: '总览', nav_users: '用户', nav_settings: '协议与设置', nav_system: '体检与维护',
    k_home: '管理面板', k_users: '管理面板', k_settings: '管理面板', k_system: '管理面板',
    live: '实时吞吐', down: '下行', up_: '上行', online: '在线连接', users_n: '个用户', active_n: '正常', paused_n: '停用',
    month: '近 30 天用户流量（计入额度）', today: '今日', avg7: '近 7 日均', server: '服务器', mem: '内存', load: '负载', uptime: '已运行',
    live_chart: '实时流量', live_sub: '服务器网卡 · 3 分钟', days_chart: '每日流量', days_sub: '近 30 天，全部用户',
    services: '服务状态', running: '运行中', stopped: '未运行', off: '已关闭', unknown: '未知',
    users: '用户', add_user: '添加用户', name: '名字', quota: '流量上限 (GB，0 = 不限)', expire: '到期日（留空 = 永久）',
    reset_day: '每月几号重置流量（0 = 不重置）', period_ends: '已保存。改了重置日：这一期用到 {d} 才重置（不会马上清零），之后每月按新的日子重置。', note: '备注', save: '保存', cancel: '取消', del: '删除',
    used: '已用', unlimited: '不限', never: '永久', status: '状态', expires: '到期', last_seen: '最近使用', sub_fetched: '最近拉取订阅', sub_never: '还没有 App 拉取过', sub_app: '拉取订阅的 App',
    enabled: '正常', r_quota: '流量用完', r_expired: '已到期', r_manual: '手动停用', r_remote: '主服务器停用', search: '搜索名字或备注',
    share: '订阅', share_tip: '把链接或二维码发给用户：手机扫码，或在 App 里「从 URL 导入」。',
    copy: '复制订阅链接', open_page: '打开导入页面', open_app: '在 vps2vpn 客户端中打开', rotate: '更换订阅链接', reset: '清零流量',
    confirm_del: '删除后该用户的链接立即失效，不能恢复。', confirm_rotate: '旧链接会立刻失效，需要把新链接重新发给该用户。',
    confirm_reset: '这个用户本期已用的流量会归零。', enable: '启用', disable: '停用', edit: '编辑', usage: '用量', actions: '操作',
    s_basic: '基本', s_proto: '协议（可同时开，App 里随时切换）', s_route: '分流', s_cert: '证书',
    node_name: '节点名字（显示在 App 里）', support_url: '客服 / 帮助链接（App 里显示，http(s):// 或 tg://，留空不显示）', sub_update_hours: '订阅自动更新间隔（小时，1–168；更换服务器或修改设置后，App 多久能获取到）', tune: '自动网络调优（BBR + 按内存调整缓冲区）',
    reality: 'VLESS + REALITY', reality_d: 'TCP + TLS。UDP 不通时可尝试；稳定性和可达性取决于实际线路。',
    reality_target: '伪装网站', reality_port: 'TCP 端口', test_targets: '自动挑最快的伪装网站',
    hy2: 'Hysteria 2', hy2_d: 'UDP + QUIC。可用于丢包线路；速度取决于实际网络，建议与 TCP 对比。', hy2_port: 'UDP 端口', hy2_hop: 'UDP 端口跳跃（单端口限速时可尝试，仍需 UDP）',
    hy2_hop_range: '跳跃端口范围', hy2_obfs: '混淆密码（可留空；QUIC 被过滤时可尝试，仍需 UDP）',
    tuic: 'TUIC v5', tuic_d: 'UDP + QUIC。另一种可选传输，需与 Hysteria 2 实测比较。', tuic_port: 'UDP 端口',
    block_ads: '屏蔽广告', block_bt: '禁止 BT 下载走服务器（防止机房投诉）', ai_group: '单独的「AI 服务」分组（ChatGPT、Claude、Gemini 等）',
    ipv6_nodes: '同时提供 IPv6 节点（IPv4 网络较慢时可以改用）',
    tcp_first: 'TCP 优先：订阅里先用 Reality，再用 Hysteria 2 / TUIC（适合 UDP 常被限速的网络）',
    cert_mode: '证书方式', cert_auto: '自动申请免费证书（Let\'s Encrypt，支持纯 IP）', cert_self: '只用自签名证书',
    domain: '域名（可选）', email: '邮箱（可选，证书快过期时提醒）', cert_now: '立即申请证书',
    cert_ok: '受信任证书', cert_self_s: '自签名证书', cert_self_tip: '代理连接仍然加密，但浏览器会提示不安全，订阅链接也会改用 HTTP：链接和其中的账号信息可能在传输途中被读取或篡改。建议放行 TCP 80，申请受信任证书。',
    cert_st_ok: '上次申请证书成功。', cert_st_failed: '上次申请证书失败。最常见的原因是云服务商的防火墙没有放行 TCP 80。点击查看原因。',
    saved: '已保存，生效中…', change_pw: '修改管理员密码', old_pw: '当前密码', new_pw: '新密码',
    backup: '备份与恢复', backup_tip: '每天自动备份一次（保留 14 天）。更换服务器时下载备份，在新服务器上恢复即可。',
    download_backup: '下载备份', restore: '从备份恢复', restore_ok: '已恢复', confirm_restore: '恢复会覆盖当前所有用户、邀请码和设置。', retry: '重试',
    ports: '防火墙端口', ports_tip: '需要在云服务商的防火墙 / 安全组里放行这些端口（服务器自己的防火墙已自动放行）。',
    logs: '最近日志', restart: '重启代理服务', rules_refresh: '立即更新分流规则', rules_age: '分流规则更新于', ago: '前', version: '版本',
    days: '天', hours: '小时', minutes: '分钟', bbr: 'BBR 加速', yes: '已开启', no: '未开启',
    setup_bad: '这个设置链接无效。请用安装完成时屏幕上显示的完整链接打开。',
    pw_mismatch: '两次密码不一样', pw_short: '密码至少 8 位', done_title: '完成！', done_sub: '下面是你的订阅，扫码或点击按钮导入到 App 即可使用。',
    import_to: '一键导入', apps_hint: 'Windows 推荐 vps2vpn 客户端（免费），也可以用 Clash Verge Rev / FlClash；Mac 用 Clash Verge Rev / FlClash，安卓用 FlClash / Hiddify，苹果手机用 Shadowrocket / Stash / Karing。',
    ai: 'AI 可用性', ai_tip: '从这台服务器测试能不能用 Claude、ChatGPT、Gemini。结果只作参考，封号还和支付方式、使用习惯有关。', ai_run: '重新检测', ai_never: '还没有检测过，请点击「重新检测」（约 10 秒）。', ai_where: '位置', ai_net: '网络', ai_kind: 'IP 类型', ai_at: '检测时间', ai_others: '其他服务器', ai_ok: '能用', ai_blocked: '地区不支持', ai_unreachable: '无法连接', ai_unknown: '不确定',
    doctor: '一键体检', doctor_tip: '无法连接或速度变慢时，先点击这里，它会逐项检查并告诉你如何修复。', doctor_run: '开始体检', doctor_ok: '全部正常', doctor_bad: '个问题',
    fix: '怎么修', tg: 'Telegram 告警', tg_tip: '流量快用完、有用户被停用、服务停止或 IP 变化时给你发消息。① 在 Telegram 找 @BotFather 发送 /newbot 创建一个机器人，把它给的 token 粘贴到下面；② 将下面的配对命令发给你与机器人的私聊；③ 点击「连接」。',
    tg_token: '机器人 token', tg_connect: '连接', tg_off: '关闭告警', tg_on: '告警已开启', tg_no_chat: '找不到匹配的私聊配对消息：发送下面的完整命令后，再点击「连接」。', tg_bad: 'token 不对，请从 @BotFather 重新复制。',
    tg_pair: '请把下面这行命令发送到与机器人的私聊（不要发送到群组）：',
    tg_repair: '旧版或从备份恢复的 Telegram 收件人尚未验证，告警和备份已暂停。请向原机器人私聊发送下面的配对命令，再点击「连接」；如果沿用原 token，可以留空。',
    refresh: '刷新', syncing: '同步中…', synced: '已同步', theme_auto: '跟随系统', theme_light: '浅色', theme_dark: '深色',
    no_users: '还没有用户，点击右上角添加。', proto_one: '至少要开一种协议',
    copy_btn: '复制', nav_members: '会员与邀请', nav_servers: '多服务器', nav_monitor: '监控与风控', k_members: '管理面板', k_servers: '管理面板', k_monitor: '管理面板',
    tab_home: '总览', tab_users: '用户', tab_members: '会员', tab_servers: '服务器', tab_monitor: '监控', tab_settings: '设置', tab_system: '体检',
    online_now: '在线', devices: '个设备', shared_out: '分给邀请的人', extra_now: '本期临时加量（下次重置或手动清零时取消）', extra_gone: '本期临时加量也会一起取消。', invited_by: '邀请人', eff_quota: '实际可用额度', plan: '套餐', history: '每日用量', history_sub: '近 30 天',
    member_login: '会员中心登录', member_login_tip: '设置密码后，该用户可以用用户名和密码登录会员中心（查看用量、申请流量、邀请朋友）。不设密码也能通过订阅链接看到同样的页面。',
    login_on: '已设置密码', login_off: '未设置密码', set_pw: '设置 / 重置密码', clear_pw: '取消密码登录', pw_cleared: '已取消', pw_ph: '新密码（至少 8 位）', pw_first: '先在左边输入新密码（至少 8 位），再点击「设置 / 重置密码」',
    requests: '流量申请', req_none: '没有待处理的申请。', approve: '批准', reject: '拒绝', approve_gb: '批准增加多少 GB', approve_tip: '留空 = 按申请的数量批准。只加到本期：下次重置日（或手动清零流量时）自动取消；没设重置日的账号会一直保留到手动清零。想长期提高，请在用户编辑里改「流量上限」。', answer: '回复（可选）', asked: '（申请了 {n} GB）',
    pending: '待处理', approved: '已批准', rejected: '已拒绝',
    invites: '邀请码', inv_tip: '管理员邀请码：自定义额度和有效期，不占用任何人的流量。会员也可以在会员中心用自己的额度生成邀请码。',
    inv_make: '生成邀请码', inv_quota: '每个账号的流量 (GB，0 = 不限)', inv_life: '账号有效期（天，0 = 永久）', inv_uses: '可使用次数', inv_valid: '邀请码几天内有效', inv_reset: '每月几号重置（0 = 不重置）',
    inv_none: '还没有邀请码。', inv_by: '生成者', inv_admin: '管理员', revoke: '撤销', copy_code: '复制邀请码', copy_link: '复制注册链接',
    st_unused: '可用', st_used: '已用完', st_revoked: '已撤销', st_expired: '已过期', used_by: '注册了',
    member_centre: '会员中心', member_url: '会员中心地址（发给会员，或附在邀请码后面）', member_enabled: '开启会员中心', member_invites: '允许会员用自己的额度邀请朋友', member_requests: '允许会员申请增加流量', member_notice: '给会员的公告（显示在会员中心顶部，留空则不显示）', save_notice: '保存公告',
    servers: '已加入的服务器', servers_tip: '只有一台服务器时，不需要设置这一页。有第二台（例如新加坡 + 美国）时：在另一台的面板复制它的「加入码」，粘贴到下面，点击「添加服务器」。之后每个人的订阅里会同时包含两台服务器的节点，流量计入同一个额度，用户只在这台服务器上管理。',
    join_code: '本机加入码', join_tip: '只在反过来、要让这台服务器被另一台管理时使用：把这串字符复制到另一台面板的「多服务器」页面。它相当于这台服务器的钥匙，请勿发给他人。', reset_key: '更换加入码',
    reset_key_tip: '旧加入码立即失效。主服务器需要先移除本机，再用新的加入码重新添加。', add_server: '添加服务器', paste_code: '粘贴子服务器的加入码', server_name: '显示名字（如「东京」）',
    no_servers: '还没有加入其他服务器。', sync_failed: '同步失败', sync_failed_why: '同步失败，点击查看原因', last_sync: '同步于', sync_now: '立即同步', remove: '移除', remove_tip: '移除后，订阅里不再有这台服务器的节点。面板会立即通知那台服务器删除从这里同步过去的账号，并记上它们最后用的流量。', remove_unreached: '已移除。那台服务器目前无法连接，面板会每隔几分钟再通知它，它一上线就会删除从这里同步过去的账号（最多等待 30 天）。', leaving: '等它上线', leaving_wait: '已移除，无法连接：等它上线后通知它删除从这里同步过去的账号（最多再等 {d} 天）', leaving_forget: '直接删除', leaving_forget_tip: '面板不再通知那台服务器。从这里同步过去的账号在那边会一直可用，流量也不再计入这里，除非在那台服务器面板的「多服务器」页点击「更换加入码」。',
    client_upd: 'vps2vpn 客户端更新', client_ver: '最新版本号（留空 = 按服务器上的安装包自动判断）', client_url: '下载链接（留空 = 用服务器上的安装包）', client_notes: '更新说明（可选，显示给用户）',
    client_tip: '面板会自动从 GitHub 获取最新的 vps2vpn 客户端（带签名的 Windows 安装包和安卓 APK），放进下面这个文件夹；使用 vps2vpn 客户端（1.0.9 及以上）的用户会在后台下载、校验签名，点击一次即可安装并重启。使用 Clash Verge、FlClash、小火箭等其他软件的用户不受影响，也收不到这个更新。也可以自己把安装包和同名 .sig 文件放进去，其他都不用填写。',
    client_auto_update: '自动从 GitHub 获取最新客户端（只要带发布签名的）',
    client_traffic_rank: '在客户端里显示「流量排行」（每个应用实时用了多少流量；仅 vps2vpn 客户端支持）',
    client_node_status: '向客户端公布服务器状态（维护中、拥堵；仅 vps2vpn 客户端支持）',
    node_status: '服务器状态', node_status_tip: '服务器需要维护或拥堵时，在这里标记。vps2vpn 客户端会把维护中的服务器标灰，自动选择节点时跳过，拥堵的排到后面；用户手动选择的节点仍然可以连接。其他软件看不到这些状态，只在「维护中」时在订阅公告里显示一句（Hiddify、Happ 等会显示），会员中心顶部也会显示。订阅里的节点名称不变；维护中的服务器不会被「自动选择」选中（所有软件都一样，但其他软件要等下次更新订阅才生效，所以请提前标记）。',
    st_state: '状态', st_ok: '正常', st_maint: '维护中', st_cong: '拥堵', st_note: '说明（可不填，最多 100 字）', st_until: '到这个时间自动恢复正常（可不填）',
    st_this: '（本机）',
    client_devices: '让客户端登记设备（会员能看到自己的设备、移除其中某一台；仅 vps2vpn 客户端支持）',
    dv: '设备', dv_tip: '这里列出用 vps2vpn 客户端（1.0.29 及以上）连接过的设备；其他软件的设备不在列表中，但计入「同时在线」。「移除」只对 vps2vpn 客户端有效；要让所有设备都无法连接，请使用下方的「更换订阅链接」。',
    dv_none: '还没有设备登记。', dv_revoke: '移除', dv_unrevoke: '恢复', dv_revoked: '已移除', dv_seen: '最后在线',
    client_feedback: '允许会员发反馈（vps2vpn 客户端带诊断和日志；会员中心网页只能写文字）',
    fb: '用户反馈', fb_tip: '会员在 vps2vpn 客户端里点击「反馈」，或在会员中心写几句话，就会出现在这里。日志和 IP 地址在发送前和保存前都已打码。保留 30 天，不进入备份。',
    fb_none: '还没有反馈。', fb_open: '待处理', fb_done: '已处理', fb_view: '详情', fb_hide: '收起', fb_answer: '回复并标为已处理', fb_answer_ph: '回复会员（会显示在该用户的客户端和会员中心里，最多 500 字）',
    fb_mark: '标为已处理', fb_reopen: '改回待处理', fb_del: '删除', fb_del_q: '删除这条反馈？', fb_diag: '诊断结果', fb_log: '日志', fb_copy: '复制日志', fb_replied: '已回复：',
    client_found: (v, p) => `服务器上找到安装包：版本 ${v}（${p}），只有订阅链接有效的人能下载。`, client_none: d => `服务器上还没有安装包。放进 ${d} 即可。`, client_unsigned: n => `缺少签名文件：${n}。App 只装带签名的安装包，请把 GitHub 发布页上同名的 .sig 文件一起放进来。`,
    renew: '服务器到期提醒', renew_at: '这台 VPS 哪天到期（续费日）', renew_note: '在哪里续费（例如 AWS Lightsail）',
    renew_tip: '填写后，到期前 7 天、3 天、1 天和当天会用 Telegram 提醒你，总览页也会提示。不填写则不提醒。如果按月付费，每次续费后改成下个月的日期。',
    renew_left: n => n > 0 ? `服务器还有 ${n} 天到期，请及时续费` : n === 0 ? '服务器今天到期，请马上续费' : `服务器已过期 ${-n} 天，请检查是否已续费`,
    renew_clear: '不提醒',
    line_down: (n, name) => `最近 24 小时有 ${n} 个用户的 vps2vpn 客户端报告「${name}」无法连接（使用其他软件的用户不会报告）`,
    line_far: '（属于其他服务器的节点，请到那台服务器的面板处理）',
    change_port: '更换端口', change_port_q: name => `把「${name}」更换到一个新的随机端口？`,
    change_port_tip: '端口被运营商封锁或限速时使用。更换后，大家的软件更新一次订阅即可使用（vps2vpn 客户端和多数软件会按「订阅自动更新间隔」自动更新，默认 12 小时；小火箭等未开启自动更新的软件需要手动更新）。云服务器自带防火墙的（如 AWS Lightsail、阿里云、腾讯云），还需要在云控制台放行新端口。',
    port_changed: p => `已更换到端口 ${p}。请让大家更新订阅；云防火墙也需要放行这个端口。`,
    managed_by: '本机正被主服务器管理：', remote_user: '这个账号来自主服务器「{m}」，由它统一管理：流量、到期、暂停和删除都请在主服务器的面板里改，这里改了也会被下次同步覆盖。', server_month: '本机本月流量', cap: '每月流量上限 (GB，0 = 不限)', cap_day: '每月几号开始计算', cap_tip: '很多 VPS 按月限流量。到 80% 和 100% 时 Telegram 提醒你（不会自动断网）。',
    monitor: '网站连通监控', monitor_tip: '服务器每 5 分钟自己访问一次这些网站，记录能不能打开、多快。用户说「某某网站打不开」时先看这里。', run_now: '立即检测',
    region: '网站看到的地区', chatgpt_ok: 'ChatGPT 可用', chatgpt_bad: 'ChatGPT 不支持这个地区', speed: '服务器下载速度', uptime24: '24 小时可用率', median: '中位延迟',
    no_data: '还没有数据，请点击「立即检测」。', monitor_enabled: '自动监控（每 5 分钟）',
    abuse: '风控观察', abuse_tip: '只观察、不自动封：发现有人短时间连几百个目标（像扫描/跳板）、很多 IP 同时用一个账号（链接被转发）、大量发邮件端口连接时，记下来并发 Telegram 提醒，由你决定要不要停用。',
    abuse_guard: '开启风控观察', scan_now: '立即扫描', streams: '连接', targets: '目标', ports_n: '端口', addrs: 'IP', flags: '信号', f_fanout: '大范围扫描', f_shared: '多人共用', f_mail: '发邮件',
    e_timeout: '超时', e_reset: '连接被重置', e_dns: '域名解析失败', e_tls: 'TLS 握手失败', e_other: '打不开', events: '最近记录', no_events: '还没有记录。', coverage: '覆盖', abuse_none: '当前没有在线连接。', ok_quiet: '正常',
    f_all: '全部', f_online: '在线', f_active: '正常', f_paused: '已停用', f_soon: '7 天内到期', f_low: '快用完',
    s_id: '按添加顺序', s_name: '按名字', s_used: '按用量', s_exp: '按到期日', s_seen: '按最近使用',
    selected: '已选', sel_all: '全选', clear_sel: '取消选择', b_reset: '清零流量', b_extend: '延期', b_addgb: '永久提高上限', b_rotate: '更换订阅链接',
    extend_days: '延长多少天（没有设置到期日的用户不受影响）', add_gb_q: '每个用户的流量上限永久提高多少 GB（每月都有效；不限量的用户不受影响）', bulk_done: '已处理', still_n: '其中 {n} 个已到期或流量用完，启用后马上又暂停了：请先延期或加流量。', still_expired: '已到期，启用后马上又暂停了：请先把到期日往后改。', still_quota: '流量已用完，启用后马上又暂停了：请先清零流量或调高上限。',
    confirm_bulk_del: '删除后，这些用户的链接立即失效，不能恢复。', confirm_bulk_rotate: '这些用户的旧链接立即失效，需要把新链接重新发给他们。',
    batch_add: '批量添加', export_csv: '导出表格', batch_prefix: '名字前缀（生成 前缀-01、前缀-02…）', batch_count: '数量（1–200）', batch_made: '已创建',
    max_ips: '同时在线上限（按同时连接的 IP 数计算：同一个 Wi‑Fi 下的多台设备算一台；0 = 不限）', speed_mbps: '限速 Mbps（0 = 不限）', throttle_mbps: '流量用完后降速到 Mbps（0 = 直接停用）',
    srv_pick: '可用服务器', srv_all: '全部服务器（以后加入的也算）', srv_none: '至少选一台服务器', limited_now: '限速中', slowed: '已降速',
    shaper_off: '这台服务器的内核不支持按账号限速（容器 VPS 常见），限速设置在这台上不生效。设了「用完后降速」的账号，流量用完后在这台上会停用，不会降速；如果它能用的其他服务器支持限速，会在那些服务器上降速继续用。',
    rate: '倍率', rate_tip: '这台服务器的流量按几倍计入额度（机场常见做法，如 ×2 表示 1 GB 记 2 GB；0 = 不计）', rate_this: '本机倍率', rate_set: '设置倍率',
    inv_limits: '限速与服务器', exp_mode: '到期方式', exp_never: '永久有效', exp_date: '指定日期', exp_first: '首次使用后开始计时', exp_days: '从今天起多少天',
    exp_first_days: '首次使用后多少天到期', exp_waiting: '首用后', r_devices: '设备超限', dev_limit: '设备上限', reset_on: '每月 {d} 号重置', srv_pause: '暂停这台（上面的账号全部停用）', srv_resume: '恢复这台', no_match: '没有符合条件的用户。',
    sec: '登录安全', totp: '两步验证（2FA）', totp_tip: '开启后，登录时除了密码，还要输入手机验证器 App（Google Authenticator、Microsoft Authenticator、1Password 等）里的 6 位数字。即使密码泄露，他人也无法登录。',
    totp_on: '已开启', totp_off: '未开启', totp_enable: '开启两步验证', totp_disable: '关闭两步验证', totp_scan: '① 用验证器 App 扫码（或手动输入下面的密钥）　② 填入 App 显示的 6 位数字',
    totp_code: '6 位验证码', totp_need: '请输入验证器 App 里的 6 位数字', totp_pw: '输入管理员密码确认关闭', totp_confirm: '确认开启',
    logins: '最近登录', login_ok: '登录成功', login_fail: '密码错误', login_fail2fa: '验证码错误', sessions: '已登录的设备', logout_others: '退出其他所有设备', no_logins: '还没有记录。',
    routing_custom: '自定义分流', routing_tip: '每行一个域名，自动包含子域名（写 example.com 就包括 www.example.com）。优先级：屏蔽 > 直连 > 走代理，都排在内置规则之前。保存后，App 下次更新订阅时生效。',
    c_direct: '直连（不走代理）', c_proxy: '走代理', c_block: '屏蔽（拒绝连接）', ip_limit_pause: '设备超过上限时暂停 10 分钟（关掉则只提醒）',
    tg_bot: '接受机器人命令', tg_backup: '每天把备份发到 Telegram', tg_cmds: '在 Telegram 里给机器人发：/status 服务器状态 · /users 每人用量 · /user 名字 · /doctor 体检 · /ai AI 可用性 · /expiring 快到期或流量快用完的人 · /backup 立即要一份备份。只回复你自己的聊天。',
    sys24: '服务器负载', sys24_sub: 'CPU、内存 · 24 小时', net24: '服务器网络', net24_sub: '24 小时 · 每分钟一个点', cpu: 'CPU', no_hist: '每分钟记录一次，稍后再来看。', dev_events: '设备超限记录',
    q_reset: '清零本期流量？', q_rotate: '更换订阅链接？', q_del: n => `删除「${n}」？`, q_bulk_del: n => `删除这 ${n} 个用户？`, q_bulk_rotate: n => `更换这 ${n} 个用户的订阅链接？`,
    q_bulk_extend: n => `给 ${n} 个用户延期`, q_bulk_addgb: n => `提高 ${n} 个用户的流量上限`,
    q_revoke: '撤销这个邀请码？', revoke_tip: c => `撤销后，${c} 不能再用来注册；已经注册的账号不受影响。`, fb_del_tip: '删除后不能恢复。',
    q_remove: n => `移除「${n}」？`, q_forget: n => `不再等待「${n}」？`, q_reset_key: '更换加入码？', q_restore: '从备份恢复？',
    q_restart: '重启代理服务？', restart_tip: '使用中的连接会断开几秒，之后自动重新连接。', restart_ok: '重启',
    brand_sub: '自建 VPN', console: '管理面板', live_pill: '实时'
  },
  en: {
    welcome: 'Welcome to vps2vpn', welcome_sub: 'Three steps turn this server into your own VPN. Everything else is set up for you.',
    art_h: 'One server,\nyour own VPN.', art_p: 'Three protocols you can switch between, one-click import into Clash and Shadowrocket, and quotas, expiry, certificates and alerts handled for you.',
    art_1: 'VLESS + REALITY · Hysteria 2 · TUIC v5', art_2: 'Automatic certificates, tuning and backups', art_3: 'One-click health check that tells you how to fix things',
    admin: 'Admin account', username: 'Username', password: 'Password (8+ characters)', password2: 'Repeat password',
    first_user: 'Name of the first user', server_addr: 'Server address (IP or domain, detected automatically; changing it changes every subscription link, so send everyone the new one)',
    next: 'Next', back: 'Back', build: 'Build my VPN', building: 'Building, about 10 seconds…',
    advanced: 'Advanced (safe to skip)', lang: 'Language / 语言',
    time_zone: 'Time zone for monthly resets', tz_server: "The server's own clock",
    login: 'Sign in', login_intro: 'Use the admin account you created during setup. 8 wrong tries lock sign-in for 10 minutes.', logout: 'Sign out', wrong: 'Wrong username or password',
    nav_main: 'Operate', nav_infra: 'Server', nav_home: 'Overview', nav_users: 'Users', nav_settings: 'Protocols & settings', nav_system: 'Health & upkeep',
    k_home: 'OVERVIEW', k_users: 'USERS', k_settings: 'SETTINGS', k_system: 'SYSTEM',
    live: 'Live throughput', down: 'down', up_: 'up', online: 'Online', users_n: 'users', users_n_1: 'user', active_n: 'active', paused_n: 'paused',
    month: 'User traffic, 30 days (as billed)', today: 'Today', avg7: '7-day avg', server: 'Server', mem: 'Memory', load: 'Load', uptime: 'Uptime',
    live_chart: 'Live traffic', live_sub: 'Server network · 3 minutes', days_chart: 'Daily traffic', days_sub: 'Last 30 days, all users',
    services: 'Services', running: 'running', stopped: 'stopped', off: 'off', unknown: 'unknown',
    users: 'Users', add_user: 'Add user', name: 'Name', quota: 'Quota (GB, 0 = unlimited)', expire: 'Expires (empty = never)',
    reset_day: 'Monthly reset day (0 = never)', period_ends: 'Saved. The reset day changed: this period runs until the reset on {d} (nothing is wiped now), then monthly on the new day.', note: 'Note', save: 'Save', cancel: 'Cancel', del: 'Delete',
    used: 'Used', unlimited: 'unlimited', never: 'never', status: 'Status', expires: 'Expires', last_seen: 'Last seen', sub_fetched: 'Subscription last fetched', sub_never: 'Not fetched by an app yet', sub_app: 'App that fetched it',
    enabled: 'active', r_quota: 'quota used', r_expired: 'expired', r_manual: 'paused', r_remote: 'paused by main server', search: 'Search name or note',
    share: 'Subscription', share_tip: 'Send this link or QR code to the user. Scan it, or use "Import from URL" in the app.',
    copy: 'Copy link', open_page: 'Open import page', open_app: 'Open in the vps2vpn app', rotate: 'New subscription link', reset: 'Reset usage',
    confirm_del: 'Their link stops working immediately. This cannot be undone.', confirm_rotate: 'The old link stops working immediately; send them the new one.',
    confirm_reset: 'This account\'s usage for the current period goes back to zero.', enable: 'Enable', disable: 'Pause', edit: 'Edit', usage: 'Usage', actions: 'Actions',
    s_basic: 'Basics', s_proto: 'Protocols (turn on several and switch in the app)', s_route: 'Routing', s_cert: 'Certificate',
    node_name: 'Node name (shown in apps)', support_url: 'Support link shown in apps (http(s):// or tg://, empty = none)', sub_update_hours: 'Subscription refresh interval (hours, 1-168: how soon apps pick up a change)', tune: 'Automatic network tuning (BBR + buffers sized to RAM)',
    reality: 'VLESS + REALITY', reality_d: 'TCP + TLS. An option when UDP is unavailable; reliability and reachability depend on the route.',
    reality_target: 'Camouflage site', reality_port: 'TCP port', test_targets: 'Pick the fastest camouflage site',
    hy2: 'Hysteria 2', hy2_d: 'UDP + QUIC. An option for lossy routes; compare with TCP on your network.', hy2_port: 'UDP port', hy2_hop: 'UDP port hopping (may help with per-port limits; needs UDP)',
    hy2_hop_range: 'Hopping range', hy2_obfs: 'Obfuscation password (optional; may help if QUIC is filtered, needs UDP)',
    tuic: 'TUIC v5', tuic_d: 'UDP + QUIC. Another transport to compare with Hysteria 2 on your network.', tuic_port: 'UDP port',
    block_ads: 'Block ads', block_bt: 'Block BitTorrent through the server (avoids abuse complaints)', ai_group: 'Separate "AI" group (ChatGPT, Claude, Gemini…)',
    ipv6_nodes: 'Also offer IPv6 entries (handy when the IPv4 route is slow)',
    tcp_first: 'TCP first: subscriptions try Reality before Hysteria 2 / TUIC (for networks that slow UDP down)',
    cert_mode: 'Certificate', cert_auto: 'Free certificate from Let\'s Encrypt (works with a bare IP)', cert_self: 'Self-signed only',
    domain: 'Domain (optional)', email: 'E-mail (optional, expiry notices)', cert_now: 'Get certificate now',
    cert_ok: 'Trusted certificate', cert_self_s: 'Self-signed', cert_self_tip: 'Proxy connections stay encrypted, but browsers show a warning and subscription links use plain HTTP, so a link and the account details in it can be read or changed on the way. Open TCP 80 and get a trusted certificate.',
    cert_st_ok: 'The last certificate request worked.', cert_st_failed: 'The last certificate request failed, most often because TCP 80 is closed in the provider firewall. Click for the reason.',
    saved: 'Saved, applying…', change_pw: 'Change admin password', old_pw: 'Current password', new_pw: 'New password',
    backup: 'Backup & restore', backup_tip: 'A backup is made every day (14 kept). To move servers, download one here and restore it on the new server.',
    download_backup: 'Download backup', restore: 'Restore from backup', restore_ok: 'Restored', confirm_restore: 'Restoring replaces all current users, invite codes and settings.', retry: 'Retry',
    ports: 'Firewall ports', ports_tip: 'Open these in your cloud provider\'s firewall / security group (the server\'s own firewall is already open).',
    logs: 'Recent log', restart: 'Restart proxy services', rules_refresh: 'Update routing rules now', rules_age: 'Routing rules updated', ago: 'ago', version: 'Version',
    days: 'd', hours: 'h', minutes: 'min', bbr: 'BBR', yes: 'on', no: 'off',
    setup_bad: 'This setup link is not valid. Open the full link shown when installation finished.',
    pw_mismatch: 'Passwords do not match', pw_short: 'Password needs 8+ characters', done_title: 'Done!', done_sub: 'Here is your subscription. Scan it or click a button to import it into an app.',
    import_to: 'Import', apps_hint: 'Windows: the vps2vpn app (free, recommended), or Clash Verge Rev / FlClash. Mac: Clash Verge Rev / FlClash. Android: FlClash / Hiddify. iPhone: Shadowrocket / Stash / Karing.',
    ai: 'AI availability', ai_tip: 'Tests from this server whether Claude, ChatGPT and Gemini work. For reference only: bans also depend on payment and usage.', ai_run: 'Check again', ai_never: 'Not checked yet. Click "Check again" (about 10 s).', ai_where: 'Location', ai_net: 'Network', ai_kind: 'IP type', ai_at: 'Checked', ai_others: 'Other servers', ai_ok: 'works', ai_blocked: 'region blocked', ai_unreachable: 'unreachable', ai_unknown: 'unsure',
    doctor: 'Health check', doctor_tip: 'Not connecting or slow? Run this first: it checks everything and tells you how to fix it.', doctor_run: 'Run check', doctor_ok: 'All good', doctor_bad: 'problems', doctor_bad_1: 'problem',
    fix: 'Fix', tg: 'Telegram alerts', tg_tip: 'Get a message when quota runs low, a user is paused, a service is down or the IP changes. 1) In Telegram, message @BotFather with /newbot and paste the token below. 2) Send the pairing command below to the bot in a private chat. 3) Click "Connect".',
    tg_token: 'Bot token', tg_connect: 'Connect', tg_off: 'Turn off', tg_on: 'Alerts are on', tg_no_chat: 'No matching private-chat pairing message: send the full command below, then click "Connect".', tg_bad: 'That token is not valid; copy it again from @BotFather.',
    tg_pair: 'Send this command to your bot in a private chat (not a group):',
    tg_repair: 'This legacy or restored Telegram recipient is unverified. Alerts and backups are paused. Send the pairing command below to your bot in a private chat, then reconnect. Leave the token blank to reuse the existing bot.',
    refresh: 'Refresh', syncing: 'Syncing…', synced: 'Synced', theme_auto: 'System', theme_light: 'Light', theme_dark: 'Dark',
    no_users: 'No users yet. Add one with the button above.', proto_one: 'Turn on at least one protocol',
    copy_btn: 'Copy', nav_members: 'Members & invites', nav_servers: 'Servers', nav_monitor: 'Monitor & abuse', k_members: 'MEMBERS', k_servers: 'SERVERS', k_monitor: 'MONITOR',
    tab_home: 'Home', tab_users: 'Users', tab_members: 'Members', tab_servers: 'Servers', tab_monitor: 'Monitor', tab_settings: 'Settings', tab_system: 'Health',
    online_now: 'online', devices: 'devices', devices_1: 'device', shared_out: 'Shared with invitees', extra_now: 'Top-up this period (ends at the next reset or manual reset)', extra_gone: 'The top-up for this period ends too.', invited_by: 'Invited by', eff_quota: 'Effective quota', plan: 'plan', history: 'Daily usage', history_sub: 'last 30 days',
    member_login: 'Member center sign-in', member_login_tip: 'With a password this user can sign in to the member center by name (usage, asking for more, inviting friends). Without one, their subscription link shows the same page.',
    login_on: 'password set', login_off: 'no password', set_pw: 'Set / reset password', clear_pw: 'Remove password sign-in', pw_cleared: 'Removed', pw_ph: 'New password (8+ characters)', pw_first: 'Type the new password first (8+ characters), then click "Set / reset password"',
    requests: 'Quota requests', req_none: 'No pending requests.', approve: 'Approve', reject: 'Decline', approve_gb: 'GB to add', approve_tip: 'Leave it empty to approve what was asked. For the current period only: it ends at the next reset day or a manual traffic reset (accounts without a reset day keep it until a manual reset). To raise the plan for good, change the quota under Edit.', answer: 'Reply (optional)', asked: ' (asked for {n} GB)',
    pending: 'pending', approved: 'approved', rejected: 'declined',
    invites: 'Invite codes', inv_tip: 'Admin codes: any quota and lifetime, nobody is charged. Members can also make codes from their own quota in the member center.',
    inv_make: 'Create code', inv_quota: 'Quota per account (GB, 0 = unlimited)', inv_life: 'Account lifetime (days, 0 = forever)', inv_uses: 'Uses', inv_valid: 'Code valid for (days)', inv_reset: 'Monthly reset day (0 = never)',
    inv_none: 'No invite codes yet.', inv_by: 'By', inv_admin: 'admin', revoke: 'Revoke', copy_code: 'Copy code', copy_link: 'Copy sign-up link',
    st_unused: 'usable', st_used: 'used up', st_revoked: 'revoked', st_expired: 'expired', used_by: 'registered',
    member_centre: 'Member center', member_url: 'Member center address (send it to members or with an invite code)', member_enabled: 'Member center on', member_invites: 'Members may invite friends from their own quota', member_requests: 'Members may ask for more quota', member_notice: 'Notice for members (shown at the top of the member center; empty = none)', save_notice: 'Save notice',
    servers: 'Joined servers', servers_tip: 'Only one server? You can ignore this page. With a second one (say Singapore + US): copy the other server\'s join code from its panel, paste it below and click "Add server". Every subscription then lists both servers, traffic counts against the same quota, and users are managed here only.',
    join_code: 'Join code of this server', join_tip: 'Only for the other way round, when another server should manage this one: paste this code into that server\'s Servers page. It is a key to this server: keep it private.', reset_key: 'New join code',
    reset_key_tip: 'The old code stops working at once; remove and re-add this server on the main server.', add_server: 'Add server', paste_code: 'Paste the other server\'s join code', server_name: 'Display name (e.g. "Tokyo")',
    no_servers: 'No other servers yet.', sync_failed: 'sync failed', sync_failed_why: 'Sync failed; click for the reason', last_sync: 'synced', sync_now: 'Sync now', remove: 'Remove', remove_tip: 'Its entries disappear from subscriptions. The panel tells that server at once to delete the accounts it got from here, and bills their last traffic.', remove_unreached: 'Removed. That server cannot be reached right now: the panel tells it again every few minutes and it deletes the accounts it got from here as soon as it answers (waiting up to 30 days).', leaving: 'Waiting for it', leaving_wait: 'Removed, unreachable: it is told to delete the accounts it got from here once it answers (up to {d} more days)', leaving_forget: 'Stop waiting', leaving_forget_tip: 'The panel stops telling that server. The accounts it got from here keep working there, unbilled, until "New join code" is clicked on its own panel (Servers page).',
    client_upd: 'vps2vpn app updates', client_ver: 'Latest version (empty = from the installers on the server)', client_url: 'Download link (empty = the installers on the server)', client_notes: 'What is new (shown to everyone, optional)',
    client_tip: 'The panel fetches the newest vps2vpn app from GitHub (the signed Windows setup and Android APK) into the folder below. From 1.0.9 the vps2vpn app downloads it in the background, checks its signature and installs it with one click; other apps (Clash Verge, FlClash, Shadowrocket...) are not affected and get nothing from here. You can also put installers and their .sig files there yourself and leave these empty.',
    client_auto_update: 'Fetch the newest app from GitHub (signed releases only)',
    client_traffic_rank: 'Show the traffic ranking in the app (live traffic per app; the vps2vpn app only)',
    client_node_status: 'Tell the app which servers are in maintenance or congested (the vps2vpn app only)',
    node_status: 'Server status', node_status_tip: 'Mark a server that is down for maintenance or congested. The vps2vpn app greys out one in maintenance and skips it when choosing automatically, and puts a congested one last; a node picked by hand still connects. Other apps see none of this, except a line in the subscription\'s announcement during maintenance (Hiddify, Happ and others show it); the member center shows it at the top. Node names in subscriptions never change for it; a server in maintenance is left out of "Auto" in every app (other apps only after their next subscription update, so mark it ahead of time).',
    st_state: 'Status', st_ok: 'Normal', st_maint: 'Maintenance', st_cong: 'Congested', st_note: 'Note (optional, up to 100 characters)', st_until: 'Back to normal at (optional)',
    st_this: ' (this server)',
    client_devices: 'Let the app register devices (members see theirs and can remove one; the vps2vpn app only)',
    dv: 'Devices', dv_tip: 'Devices that connected with the vps2vpn app (1.0.29 or later) are listed here; devices using other apps are not, but they count as online. "Remove" works on the vps2vpn app only; to cut off every device, use "New subscription link" below.',
    dv_none: 'No devices registered yet.', dv_revoke: 'Remove', dv_unrevoke: 'Restore', dv_revoked: 'removed', dv_seen: 'last seen',
    client_feedback: 'Members may send feedback (the vps2vpn app adds its diagnosis and log; the member center sends text only)',
    fb: 'Feedback', fb_tip: 'What members send with "Feedback" in the vps2vpn app, or write in the member center. Logs and IP addresses are redacted before sending and again before they are stored. Kept 30 days, not in backups.',
    fb_none: 'No feedback yet.', fb_open: 'open', fb_done: 'done', fb_view: 'Details', fb_hide: 'Hide', fb_answer: 'Reply and mark done', fb_answer_ph: 'Reply to the member (shown in their app and in the member center; up to 500 characters)',
    fb_mark: 'Mark done', fb_reopen: 'Reopen', fb_del: 'Delete', fb_del_q: 'Delete this feedback?', fb_diag: 'Diagnosis', fb_log: 'Log', fb_copy: 'Copy log', fb_replied: 'Replied: ',
    client_found: (v, p) => `Installers found on the server: version ${v} (${p}); only people with a valid subscription link can download them.`, client_none: d => `No installers on the server yet. Put them in ${d}.`, client_unsigned: n => `Signature missing: ${n}. The app only installs signed installers; put the matching .sig file from the GitHub release next to it.`,
    renew: 'Renewal reminder', renew_at: 'Date this VPS must be renewed', renew_note: 'Where to renew (e.g. AWS Lightsail)',
    renew_tip: 'You get a Telegram reminder 7, 3 and 1 days before and on the day, and a note on the overview. Leave empty for no reminder.',
    renew_left: n => n > 0 ? `The server must be renewed in ${n} ${n === 1 ? 'day' : 'days'}` : n === 0 ? 'The server must be renewed today' : `The renewal date passed ${-n} ${n === -1 ? 'day' : 'days'} ago`,
    renew_clear: 'No reminder',
    line_down: (n, name) => `In the last 24 hours the vps2vpn app of ${n} ${n === 1 ? 'account' : 'accounts'} reported that ${name} does not connect (other apps do not report)`,
    line_far: ' (a node of another server: fix it in that server\'s panel)',
    change_port: 'Change port', change_port_q: name => `Move ${name} to a new random port?`,
    change_port_tip: 'For a port that gets blocked or throttled. Everyone then updates the subscription (the vps2vpn app and most others do it by themselves at the subscription refresh interval, 12 hours by default; Shadowrocket and apps without auto-update need a manual update). With a cloud firewall (AWS Lightsail, Alibaba, Tencent...) also open the new port there.',
    port_changed: p => `Moved to port ${p}. Ask everyone to update the subscription and open the port in the cloud firewall.`,
    managed_by: 'This server is managed by main server: ', remote_user: 'This account comes from the main server "{m}", which manages it: change quota, expiry, pausing or deleting there. Changes made here are overwritten at the next sync.', server_month: 'This server, this month', cap: 'Monthly traffic cap (GB, 0 = none)', cap_day: 'Billing period starts on day', cap_tip: 'Many VPS plans cap monthly traffic. You get a Telegram alert at 80% and 100% (nothing is cut off).',
    monitor: 'Site reachability', monitor_tip: 'Every 5 minutes the server opens these sites itself and records whether and how fast they load. Check here first when someone says a site does not work.', run_now: 'Check now',
    region: 'Region sites see', chatgpt_ok: 'ChatGPT available', chatgpt_bad: 'ChatGPT does not serve this region', speed: 'Server download speed', uptime24: '24 h availability', median: 'median',
    no_data: 'No data yet. Click "Check now".', monitor_enabled: 'Automatic checks (every 5 minutes)',
    abuse: 'Abuse watch', abuse_tip: 'Observation only, never automatic bans: accounts that hit hundreds of targets at once (scanner/relay), are used from many addresses (shared link) or send lots of mail are logged and announced on Telegram; you decide.',
    abuse_guard: 'Abuse watch on', scan_now: 'Scan now', streams: 'Streams', targets: 'Targets', ports_n: 'Ports', addrs: 'IPs', flags: 'Signals', f_fanout: 'wide scan', f_shared: 'shared', f_mail: 'mail',
    e_timeout: 'timed out', e_reset: 'connection reset', e_dns: 'DNS failed', e_tls: 'TLS failed', e_other: 'failed', events: 'Recent events', no_events: 'Nothing recorded yet.', coverage: 'Coverage', abuse_none: 'No open connections right now.', ok_quiet: 'normal',
    f_all: 'All', f_online: 'Online', f_active: 'Active', f_paused: 'Paused', f_soon: 'Expiring in 7 days', f_low: 'Almost used up',
    s_id: 'Order added', s_name: 'Name', s_used: 'Usage', s_exp: 'Expiry', s_seen: 'Last seen',
    selected: 'Selected', sel_all: 'Select all', clear_sel: 'Clear', b_reset: 'Reset usage', b_extend: 'Extend', b_addgb: 'Raise quota', b_rotate: 'New subscription links',
    extend_days: 'Days to add (accounts without an expiry are unchanged)', add_gb_q: 'GB to add to each plan for good (every month; unlimited accounts are unchanged)', bulk_done: 'Done:', still_n: '{n} of them are expired or out of quota and were paused again at once: extend or add quota first.', still_expired: 'Expired, so it was paused again at once: move the expiry date first.', still_quota: 'Out of quota, so it was paused again at once: reset its traffic or raise the quota first.',
    confirm_bulk_del: 'Their links stop working immediately. This cannot be undone.', confirm_bulk_rotate: 'Their old links stop working at once; send them the new ones.',
    batch_add: 'Add many', export_csv: 'Export CSV', batch_prefix: 'Name prefix (makes prefix-01, prefix-02 …)', batch_count: 'How many (1–200)', batch_made: 'Created',
    max_ips: 'Devices online at once (counted by IP address: several on one Wi-Fi count as one; 0 = no limit)', speed_mbps: 'Speed limit, Mbps (0 = none)', throttle_mbps: 'When the quota is used up, slow down to Mbps (0 = stop)',
    srv_pick: 'Servers it may use', srv_all: 'All servers (including ones added later)', srv_none: 'Pick at least one server', limited_now: 'Limited', slowed: 'Slowed down',
    shaper_off: 'This server\'s kernel cannot limit single accounts (common on container VPSes): speed limits do not apply here. An account set to slow down once its quota is used up stops on this server instead; on other servers it may use that can limit speed, it keeps working, slowed down.',
    rate: 'Rate', rate_tip: 'How many times this server\'s traffic counts against quotas (2× means 1 GB counts as 2 GB; 0 = free)', rate_this: 'This server\'s rate', rate_set: 'Set rate',
    inv_limits: 'Speed and servers', exp_mode: 'Expiry', exp_never: 'Never expires', exp_date: 'On a date', exp_first: 'Counted from first use', exp_days: 'Days from today',
    exp_first_days: 'Days after first use', exp_waiting: 'after first use', r_devices: 'too many devices', dev_limit: 'Device limit', reset_on: 'resets on day {d}', srv_pause: 'Pause this server (every account on it is switched off)', srv_resume: 'Resume this server', no_match: 'No users match.',
    sec: 'Sign-in security', totp: 'Two-step verification (2FA)', totp_tip: 'When on, signing in also needs the 6-digit code from an authenticator app (Google Authenticator, Microsoft Authenticator, 1Password …). A leaked password alone is not enough.',
    totp_on: 'on', totp_off: 'off', totp_enable: 'Turn on 2FA', totp_disable: 'Turn off 2FA', totp_scan: '1) Scan with your authenticator app (or type the key below)  2) Enter the 6-digit code it shows',
    totp_code: '6-digit code', totp_need: 'Enter the 6-digit code from your authenticator app', totp_pw: 'Enter the admin password to turn it off', totp_confirm: 'Turn on',
    logins: 'Recent sign-ins', login_ok: 'signed in', login_fail: 'wrong password', login_fail2fa: 'wrong code', sessions: 'Signed-in devices', logout_others: 'Sign out all other devices', no_logins: 'Nothing recorded yet.',
    routing_custom: 'Custom routing', routing_tip: 'One domain per line; subdomains are included (example.com covers www.example.com). Block wins over direct, direct over proxy, and all of them come before the built-in rules. Apps pick changes up on their next subscription update.',
    c_direct: 'Direct (no proxy)', c_proxy: 'Through the proxy', c_block: 'Block', ip_limit_pause: 'Pause for 10 minutes when over the device limit (off = warn only)',
    tg_bot: 'Answer bot commands', tg_backup: 'Send the daily backup to Telegram', tg_cmds: 'Send your bot: /status server status · /users usage per person · /user NAME · /doctor health check · /ai AI availability · /expiring who ends or runs out soon · /backup a backup now. Only your own chat is answered.',
    sys24: 'Server load', sys24_sub: 'CPU, memory · 24 hours', net24: 'Server network', net24_sub: '24 hours · one point a minute', cpu: 'CPU', no_hist: 'Recorded once a minute; check back soon.', dev_events: 'Device limit events',
    q_reset: 'Reset usage?', q_rotate: 'Change the subscription link?', q_del: n => `Delete “${n}”?`, q_bulk_del: n => `Delete ${n} ${n === 1 ? 'user' : 'users'}?`, q_bulk_rotate: n => `Change the links of ${n} ${n === 1 ? 'user' : 'users'}?`,
    q_bulk_extend: n => `Extend ${n} ${n === 1 ? 'user' : 'users'}`, q_bulk_addgb: n => `Raise the quota of ${n} ${n === 1 ? 'user' : 'users'}`,
    q_revoke: 'Revoke this invite code?', revoke_tip: c => `${c} can no longer be used to sign up. Accounts already created stay.`, fb_del_tip: 'This cannot be undone.',
    q_remove: n => `Remove “${n}”?`, q_forget: n => `Stop waiting for “${n}”?`, q_reset_key: 'Change the join code?', q_restore: 'Restore from backup?',
    q_restart: 'Restart proxy services?', restart_tip: 'Connections in use drop for a few seconds, then reconnect by themselves.', restart_ok: 'Restart',
    brand_sub: 'Self-hosted VPN', console: 'Admin console', live_pill: 'Live'
  }
};
let L = (navigator.language || '').startsWith('zh') ? 'zh' : 'en';
const t = k => (T[L] && T[L][k]) || T.en[k] || k;
// a count's noun: English has a singular (key + '_1'), Chinese does not
const tn = (k, n) => (n === 1 && T[L] && T[L][k + '_1']) || t(k);
// protocol names as the rest of the panel writes them (the server reports its internal ids)
const PROTO = {reality: 'VLESS + REALITY', vless: 'VLESS + REALITY', hy2: 'Hysteria 2', hysteria2: 'Hysteria 2', tuic: 'TUIC v5'};
const protoNames = list => [...new Set((list || []).map(p => PROTO[p] || p))];
const S = {view: 'home', data: null, days: [], timer: null, charts: {}, q: '', f: 'all', sort: 'id', sel: new Set(), sys: [], sysAt: 0, viewSeq: 0, drawerSeq: 0, refreshSeq: 0, loadSeq: 0, daysSeq: 0, sysSeq: 0, sessionSeq: 0, refreshing: false};
const GB = 1073741824;

function setLang(l) {
  L = l === 'en' ? 'en' : 'zh'; KT = L === 'en' ? KT_EN : KT_ZH;
  document.documentElement.lang = L === 'zh' ? 'zh-CN' : 'en';
}
async function api(path, body, opts = {}) {
  const session = S.sessionSeq;
  let r;
  try {
    r = await fetch('api/' + path, body === undefined ? {credentials: 'same-origin', cache: 'no-store'} : {
      method: 'POST', credentials: 'same-origin', headers: {'Content-Type': 'application/json', 'X-V2V': '1'}, body: JSON.stringify(body)});
  } catch (e) { throw Error(KT.net); }
  let j = {};
  try { j = await r.json(); } catch (e) { /* empty */ }
  if (r.status === 401 && !opts.quiet) { if (session === S.sessionSeq) renderLogin(); throw Error('login'); }
  if (!r.ok) throw Error(j.error || (KT.failed + ' (' + r.status + ')'));
  return j;
}
const err = e => { if (e.message !== 'login') toast(e.message, 'err'); };
function dur(s) {
  if (s == null) return '—';
  const d = Math.floor(s / 86400), hh = Math.floor(s % 86400 / 3600), m = Math.floor(s % 3600 / 60);
  return d ? `${d} ${t('days')} ${hh} ${t('hours')}` : hh ? `${hh} ${t('hours')} ${m} ${t('minutes')}` : `${m} ${t('minutes')}`;
}
const pad2 = n => String(n).padStart(2, '0');
const localDate = d => `${d.getFullYear()}-${pad2(d.getMonth() + 1)}-${pad2(d.getDate())}`;
const last30 = () => { const d = []; for (let i = 29; i >= 0; i--) d.push(localDate(new Date(Date.now() - i * 864e5))); return d; };
const dateStr = ts => ts ? localDate(new Date(ts * 1000)) : t('never');
const localDay = ms => localDate(new Date(ms));
const field = (label, input, hint) => h('label', {class: 'field'}, h('span', null, label), input, hint ? h('em', null, hint) : null);
const check = (label, input) => h('label', {class: 'check'}, input, h('span', null, label));
const panel = (title, sub, right, ...body) => h('div', {class: 'panel'},
  h('div', {class: 'panel-h'}, h('h3', null, title), sub ? h('span', {class: 'sub'}, sub) : null, right ? h('div', {class: 'right'}, right) : null),
  h('div', {class: 'panel-b'}, ...body));
const tip = text => h('p', {class: 'muted m-tip', style: 'margin:0 0 12px'}, text);
const chip = (kind, text) => h('span', {class: 'chip ' + kind}, text);
const legend = () => h('div', {class: 'legend'}, h('span', {style: '--c:var(--down)'}, t('down')), h('span', {style: '--c:var(--up)'}, t('up_')));
// an empty number box is sent as null, not Number('') === 0: the server rejects it or uses its default
// (0 would quietly mean "not counted" for a traffic rate)
const numOrNull = v => (v === '' ? null : Number(v));
const brand = () => h('div', {class: 'brand'}, h('span', {class: 'seal'}, 'V'), h('div', null, h('b', null, 'vps2vpn'), h('small', null, t('brand_sub'))));
const AVA = ['#e5432a', '#3f5fe6', '#0b9e86', '#d4860f', '#8b5cf6', '#db2777', '#0891b2'];
// the note an invited sign-up gets (members.py); before 0.2.50 it was always English
const noteText = n => (n && L === 'zh' ? n.replace(/^invite ([A-Z0-9-]+)/, '邀请码 $1') : n || '');
const retryBox = (msg, fn) => h('div', {class: 'empty-state'}, h('p', null, errText(msg)), h('button', {class: 'btn sm', onclick: fn}, icon('refresh'), t('retry')));
// a joined server's error, in the panel's language when it is a known one (otherwise a plain "sync failed"),
// two lines at most; a click shows the whole text and the server's own words
// the last certificate request: '' (none yet), 'ok' or 'failed: <reason in English>'
const certStatus = st => !st ? null : st === 'ok' ? h('div', {class: 'muted', style: 'font-size:12.5px'}, t('cert_st_ok'))
  : xdetail(t('cert_st_failed'), st.replace(/^failed: /, ''), 'srv-err warn');
const srvErr = (e, kind) => { const zh = errText(e); return xdetail(L === 'zh' && zh === e ? t('sync_failed_why') : zh, e, 'srv-err' + (kind ? ' ' + kind : '')); };

/* ---------------- start ---------------- */
async function boot() {
  let hello;
  try { hello = await api('hello', undefined, {quiet: true}); } catch (e) { document.body.replaceChildren(retryBox(e.message, boot)); return; }
  setLang(hello.language);
  Theme.apply(Theme.get());
  if (!hello.setup_done) return renderSetup();
  if (!hello.logged_in) return renderLogin();
  try { await renderShell(); } catch (e) { if (e.message !== 'login') document.body.replaceChildren(retryBox(e.message, boot)); }
}

/* the split sign-in layout of the original console, used for setup and login */
function loginFrame(card) {
  const cv = h('canvas', {id: 'lineArt', 'aria-hidden': 'true'});
  const art = h('section', {class: 'login-art'}, brand(),
    h('div', null, h('h2', {style: 'white-space:pre-line'}, t('art_h')), h('p', null, t('art_p')),
      h('div', {class: 'points'}, h('span', null, icon('shield'), t('art_1')), h('span', null, icon('bolt'), t('art_2')), h('span', null, icon('check'), t('art_3')))), cv);
  document.body.replaceChildren(h('div', {class: 'login'}, art, h('section', {class: 'login-form'}, h('div', {class: 'login-card'}, card))));
  Ticker.add({el: cv, tick(tm) {
    const {ctx, w, h: hh} = setupCanvas(cv); ctx.clearRect(0, 0, w, hh);
    [['#ff6b4a', .62], ['#7b93ff', .74], ['#3fe0c5', .86]].forEach(([c, y0], k) => {
      const pts = []; for (let i = 0; i <= 40; i++) pts.push([i / 40 * w, hh * y0 + Math.sin(i / 6 + k * 2) * hh * .05]);
      ctx.strokeStyle = alpha(c, .35); ctx.lineWidth = 2; ctx.beginPath(); traceMonotone(ctx, pts, true); ctx.stroke();
      for (let j = 0; j < 5; j++) {
        const p = ((tm / 9000 + j / 5 + k * .13) % 1), i = Math.floor(p * 40), f = p * 40 - i, a = pts[i], b = pts[Math.min(40, i + 1)];
        const x = a[0] + (b[0] - a[0]) * f, y = a[1] + (b[1] - a[1]) * f, g = ctx.createRadialGradient(x, y, 0, x, y, 14);
        g.addColorStop(0, alpha(c, .9)); g.addColorStop(1, alpha(c, 0)); ctx.fillStyle = g; ctx.beginPath(); ctx.arc(x, y, 14, 0, 7); ctx.fill();
      }
    });
    return !matchMedia('(prefers-reduced-motion: reduce)').matches;
  }});
}

/* ---------------- setup wizard ---------------- */
async function renderSetup() {
  const token = new URLSearchParams(location.search).get('setup') || '';
  let info;
  try { info = await api('setup-info?token=' + encodeURIComponent(token), undefined, {quiet: true}); } catch (e) {
    loginFrame(h('div', null, h('div', {class: 'kicker'}, 'SETUP'), h('h1', null, 'vps2vpn'), h('p', {class: 'intro'}, t('setup_bad')))); return;
  }
  const w = {step: 0, username: 'admin', password: '', password2: '', first_user: L === 'zh' ? '我' : 'me', host: info.host,
    reality_target: info.target, hy2_enabled: true, tuic_enabled: true, block_ads: true};
  const draw = () => {
    const steps = h('div', {class: 'steps'}, [0, 1, 2].map(i => h('i', {class: i <= w.step ? 'on' : ''})));
    const kids = [h('div', {class: 'kicker'}, 'SETUP · ' + (w.step + 1) + ' / 3'), steps];
    const next = h('button', {class: 'btn primary', type: 'submit'}, t('next'));
    const back = h('button', {class: 'btn', type: 'button', onclick: () => { keep(); w.step--; draw(); }}, t('back'));
    const f = {};
    if (w.step === 0) {
      f.lang = h('select', null, h('option', {value: 'zh'}, '中文'), h('option', {value: 'en'}, 'English')); f.lang.value = L;
      f.lang.onchange = () => { setLang(f.lang.value); w.first_user = L === 'zh' ? '我' : 'me'; renderSetupAgain(); };
      kids.push(h('h1', null, t('welcome')), h('p', {class: 'intro'}, t('welcome_sub')), field(t('lang'), f.lang), next);
    } else if (w.step === 1) {
      f.user = h('input', {type: 'text', autocomplete: 'username', value: w.username});
      f.pw = h('input', {type: 'password', autocomplete: 'new-password'}); f.pw.value = w.password;
      f.pw2 = h('input', {type: 'password', autocomplete: 'new-password'}); f.pw2.value = w.password2;
      kids.push(h('h1', null, t('admin')), field(t('username'), f.user), field(t('password'), f.pw), field(t('password2'), f.pw2), h('div', {class: 'row'}, back, next));
    } else {
      f.first = h('input', {type: 'text', value: w.first_user, maxlength: '32'});
      f.host = h('input', {type: 'text', value: w.host}); f.target = h('input', {type: 'text', value: w.reality_target});
      f.hy2 = h('input', {type: 'checkbox', checked: w.hy2_enabled}); f.tuic = h('input', {type: 'checkbox', checked: w.tuic_enabled});
      f.ads = h('input', {type: 'checkbox', checked: w.block_ads});
      next.textContent = t('build');
      kids.push(h('h1', null, t('first_user')), field(t('name'), f.first),
        h('details', {class: 'more'}, h('summary', null, t('advanced')), h('div', null, field(t('server_addr'), f.host), field(t('reality_target'), f.target),
          check(t('hy2'), f.hy2), check(t('tuic'), f.tuic), check(t('block_ads'), f.ads))),
        h('div', {class: 'row'}, back, next));
    }
    const keep = () => {
      if (f.user) { w.username = f.user.value.trim(); w.password = f.pw.value; w.password2 = f.pw2.value; }
      if (f.first) { w.first_user = f.first.value.trim(); w.host = f.host.value.trim(); w.reality_target = f.target.value.trim();
        w.hy2_enabled = f.hy2.checked; w.tuic_enabled = f.tuic.checked; w.block_ads = f.ads.checked; }
    };
    const form = h('form', {class: 'stack'}, ...kids);
    form.onsubmit = async e => {
      e.preventDefault(); keep();
      if (w.step === 1 && w.password.length < 8) return toast(t('pw_short'), 'err');
      if (w.step === 1 && w.password !== w.password2) return toast(t('pw_mismatch'), 'err');
      if (w.step < 2) { w.step++; return draw(); }
      next.disabled = true; next.textContent = t('building');
      try {
        await api('setup', {token, username: w.username, password: w.password, first_user: w.first_user,
          settings: {language: L, public_host: w.host, reality_target: w.reality_target, hy2_enabled: w.hy2_enabled,
            tuic_enabled: w.tuic_enabled, block_ads: w.block_ads}});
        history.replaceState(null, '', location.pathname);
        await new Promise(r => setTimeout(r, 2500));
        S.view = 'users';
        await renderShell();
        const u = S.data.users[0];
        if (u) openUser(u.id, true);
      } catch (er) { err(er); next.disabled = false; next.textContent = t('build'); }
    };
    loginFrame(form);
    (form.querySelector('input,select') || next).focus();
  };
  const renderSetupAgain = draw;
  draw();
}

/* ---------------- login ---------------- */
function renderLogin() {
  clearInterval(S.timer);
  S.viewSeq++; S.drawerSeq++; S.refreshSeq++; S.refreshing = false;
  S.loadSeq++; S.daysSeq++; S.sysSeq++; S.sessionSeq++;
  document.body.style.overflow = '';
  const u = h('input', {type: 'text', autocomplete: 'username', required: true});
  const p = h('input', {type: 'password', autocomplete: 'current-password', required: true});
  const b = h('button', {class: 'btn primary', type: 'submit'}, t('login'));
  const msg = h('div', {class: 'err', role: 'status'});
  const code = h('input', {type: 'text', inputmode: 'numeric', autocomplete: 'one-time-code', maxlength: '12', class: 'otp'});
  const codeField = field(t('totp_code'), code); codeField.hidden = true;
  const f = h('form', null, h('div', {class: 'kicker'}, t('console')), h('h1', null, t('login')), h('p', {class: 'intro'}, t('login_intro')),
    field(t('username'), u), field(t('password').replace(/（.*|\(.*/, ''), p), codeField, b, msg);
  f.onsubmit = async e => {
    e.preventDefault(); b.disabled = true; msg.textContent = '';
    try { await api('login', {username: u.value, password: p.value, code: code.value.replace(/\s+/g, '')}, {quiet: true}); await renderShell(); }
    catch (er) {
      b.disabled = false;
      if (er.message === 'totp_required') { codeField.hidden = false; msg.textContent = t('totp_need'); code.focus(); return; }
      if (er.message === 'wrong 2FA code') { code.value = ''; msg.textContent = t('login_fail2fa'); code.focus(); return; }
      p.value = ''; code.value = ''; msg.textContent = er.message === 'wrong username or password' ? t('wrong') : errText(er.message); p.focus();
    }
  };
  loginFrame(f); u.focus();
}

/* ---------------- shell: sidebar + pages, same layout as the original console ---------------- */
const VIEWS = [['home', 'home', 'nav_home'], ['users', 'users', 'nav_users'], ['members', 'key', 'nav_members'],
  ['servers', 'server', 'nav_servers'], ['monitor', 'globe', 'nav_monitor'], ['settings', 'sliders', 'nav_settings'], ['system', 'pulse', 'nav_system']];
const waiting = () => S.data ? (S.data.pending_requests || 0) + (S.data.open_feedback || 0) : 0;
const badge = () => waiting() ? h('span', {class: 'badge', 'data-req-badge': '1'}, waiting()) : h('span', {'data-req-badge': '1', hidden: true});
function updateReqBadges() {
  const n = waiting();
  for (const rb of document.querySelectorAll('[data-req-badge]')) { rb.textContent = n || ''; rb.hidden = !n; rb.className = n ? 'badge' : ''; }
}
async function saveSettings(body, redraw) {
  const seq = S.viewSeq;
  try { await api('settings', body); toast(t('saved')); await load(); if (redraw && seq === S.viewSeq) redraw(); } catch (e) { err(e); }
}
async function load() {
  const seq = ++S.loadSeq, data = await api('state');
  if (seq !== S.loadSeq) return S.data;
  S.data = data; setLang(S.data.settings.language);
  Clock.seen(S.data.health.time || Date.now() / 1000);
  return S.data;
}
async function loadDays() {
  const seq = ++S.daysSeq;
  try { const days = (await api('traffic?days=30')).days || []; if (seq === S.daysSeq) S.days = days; }
  catch (e) { if (seq === S.daysSeq) S.days = []; }
}

async function renderShell() {
  const session = ++S.sessionSeq;
  await Promise.all([load(), loadDays()]);
  if (session !== S.sessionSeq) return;
  const doLogout = async btn => { btn.disabled = true; try { await api('logout', {}); location.reload(); } catch (e) { err(e); btn.disabled = false; } };
  const nav = v => h('button', {class: 'nav-item', 'data-view': v[0], onclick: () => go(v[0])}, icon(v[1]), t(v[2]), v[0] === 'members' ? badge() : null);
  const themeBtn = (v, ic, k) => h('button', {'data-theme-btn': v, title: t(k)}, icon(ic));
  const sideLogout = h('button', {class: 'btn ghost'}, icon('out'), t('logout'));
  sideLogout.onclick = () => doLogout(sideLogout);
  const side = h('aside', {class: 'side'}, brand(),
    h('nav', {class: 'nav'}, h('div', {class: 'nav-label'}, t('nav_main')), nav(VIEWS[0]), nav(VIEWS[1]), nav(VIEWS[2]),
      h('div', {class: 'nav-label'}, t('nav_infra')), nav(VIEWS[3]), nav(VIEWS[4]), nav(VIEWS[5]), nav(VIEWS[6])),
    h('div', {class: 'side-foot'}, h('div', {class: 'seg', role: 'group'}, themeBtn('auto', 'auto', 'theme_auto'), themeBtn('light', 'sun', 'theme_light'), themeBtn('dark', 'moon', 'theme_dark')),
      sideLogout, h('div', {class: 'ver'}, 'v' + S.data.version)));
  const mobTheme = h('button', {class: 'btn icon mob-only', title: t('theme_' + Theme.get())}, icon(Theme.get() === 'light' ? 'sun' : Theme.get() === 'dark' ? 'moon' : 'auto'));
  mobTheme.onclick = () => {
    const order = ['auto', 'light', 'dark'], next = order[(order.indexOf(Theme.get()) + 1) % 3];
    Theme.set(next); mobTheme.title = t('theme_' + next); mobTheme.replaceChildren(icon(next === 'light' ? 'sun' : next === 'dark' ? 'moon' : 'auto'));
  };
  const mobLogout = h('button', {class: 'btn icon mob-only', title: t('logout')}, icon('out'));
  mobLogout.onclick = () => doLogout(mobLogout);
  const top = h('header', {class: 'top'}, h('div', null, h('div', {class: 'kicker', id: 'viewKicker'}), h('h1', {id: 'viewTitle'})),
    h('div', {class: 'top-actions'}, h('span', {id: 'livePill', class: 'live-pill'}, t('live_pill')), h('span', {class: 'sync', id: 'syncInfo'}, t('synced')),
      mobTheme, mobLogout,
      h('button', {class: 'btn', onclick: () => refresh(true)}, icon('refresh'), t('refresh')),
      h('button', {class: 'btn primary', id: 'newBtn', onclick: () => editUser(null)}, icon('plus'), t('add_user'))));
  const tabbar = h('nav', {class: 'tabbar'}, VIEWS.map(v => h('button', {'data-view': v[0], onclick: () => go(v[0])}, icon(v[1]), t('tab_' + v[0]), v[0] === 'members' ? badge() : null)));
  const drawer = h('aside', {class: 'drawer', id: 'drawer', 'aria-hidden': 'true'});
  const scrim = h('div', {class: 'scrim', id: 'scrim', onclick: closeDrawer});
  document.body.replaceChildren(h('div', {class: 'app'}, side, h('main', {class: 'main'}, top, h('div', {id: 'view'}))), tabbar, scrim, drawer);
  Theme.mount();
  if (!S.escBound) {
    S.escBound = true;
    document.addEventListener('keydown', e => { if (e.key === 'Escape' && !document.querySelector('dialog.modal[open]')) closeDrawer(); });
  }
  // the page in the address (#users): a reload or a shared link opens it, and Back returns to the last page
  const hv = location.hash.slice(1);
  if (VIEWS.some(x => x[0] === hv)) S.view = hv;
  if (!S.popBound) {
    S.popBound = true;
    window.addEventListener('popstate', () => {
      if (S.backPending) {                                     // our own step back after closing the drawer
        S.backPending = false;
        if (S.hashAfterBack) { const hv = S.hashAfterBack; S.hashAfterBack = ''; try { history.pushState(null, '', '#' + hv); } catch (e) { /* no history */ } }
        if (S.pushAfterBack && $('drawer') && $('drawer').classList.contains('on')) { S.pushAfterBack = false; drawerPush(); }
        return;
      }
      if (S.drawerHist) { closeDrawer(true); return; }       // Back with the drawer open: just close it
      const v = location.hash.slice(1) || 'home';
      if ($('view') && v !== S.view && VIEWS.some(x => x[0] === v)) { closeDrawer(); go(v, 'none'); }
    });
  }
  go(S.view, 'replace');
  clearInterval(S.timer);
  S.timer = setInterval(() => { if (!document.hidden) refresh(false); }, 5000);
}

function go(v, how) {
  if (how !== 'none' && S.backPending) S.hashAfterBack = v;        // a drawer close is stepping back: set it after
  else if (how !== 'none' && location.hash !== '#' + v) {
    try { history[how === 'replace' || S.view === v ? 'replaceState' : 'pushState'](null, '', '#' + v); } catch (e) { /* sandboxed: no history */ }
  }
  S.view = v;
  S.viewSeq++;
  for (const ch of Object.values(S.charts)) if (ch && ch.destroy) ch.destroy();
  for (const b of document.querySelectorAll('[data-view]')) b.setAttribute('aria-current', b.dataset.view === v ? 'page' : 'false');
  const vv = VIEWS.find(x => x[0] === v);
  $('viewTitle').textContent = t(vv[2]); $('viewKicker').textContent = t('k_' + v);
  S.charts = {};
  S.fresh = true; setTimeout(() => { S.fresh = false; }, 400);     // only a page change fades in, not a refresh
  ({home: drawHome, users: drawUsers, members: drawMembers, servers: drawServers, monitor: drawMonitor, settings: drawSettings, system: drawSystem})[v]();
}

async function refresh(manual) {
  if (!$('view') || (S.refreshing && !manual)) return;
  S.refreshing = true;
  const seq = ++S.refreshSeq, startView = S.view;
  try {
    const si = $('syncInfo'); if (si) si.textContent = t('syncing');
    await load();
    if (seq !== S.refreshSeq) return;
    if (manual || S.view === 'home') await loadDays();
    if (seq !== S.refreshSeq) return;
    const lp = $('livePill'), si2 = $('syncInfo');
    if (lp) lp.classList.remove('stale');
    if (si2) si2.textContent = t('synced') + ' · ' + new Date().toLocaleTimeString(KT.locale, {hour12: false});
  } catch (e) {
    if (seq !== S.refreshSeq) return;
    const lp = $('livePill'), si = $('syncInfo');
    if (lp) lp.classList.add('stale');
    if (si) si.textContent = e.message;
    return;
  } finally {
    if (seq === S.refreshSeq) S.refreshing = false;
  }
  updateReqBadges();
  if (S.view === 'home') updateHome();
  else if (S.view === 'users' && (manual || !document.querySelector('#view select:focus, dialog.modal[open]'))) drawUsers();
  else if (manual && S.view === startView) go(S.view);
}

/* ---------------- overview ---------------- */
function drawHome() {
  const kpi = (cls, ic, label, id, unit, sub) => h('div', {class: 'panel kpi ' + cls}, h('div', {class: 'kpi-l'}, icon(ic), label),
    h('div', {class: 'kpi-v'}, h('span', {class: 'num', id}, '—'), h('small', {id: id + 'U'}, unit)), h('div', {class: 'kpi-s', id: id + 'S'}, sub || ''));
  const live = h('div', {class: 'chart h200'}), days = h('div', {class: 'chart h160'}), sysBox = h('div', {class: 'chart h160'}), netBox = h('div', {class: 'chart h160'});
  $('view').replaceChildren(h('section', {class: 'page'},
    h('div', {class: 'alerts', id: 'alerts'}),
    h('div', {class: 'kpis'},
      kpi('hero', 'bolt', t('live'), 'kDown', 'Mbps ' + t('down')),
      kpi('', 'users', t('online'), 'kOnline', ''),
      kpi('', 'gauge', t('month'), 'kMonth', 'GB'),
      kpi('', 'server', t('server'), 'kMem', '% ' + t('mem'))),
    h('div', {class: 'grid g-2-1'},
      panel(t('live_chart'), t('live_sub'), legend(), live),
      panel(t('services'), null, null, h('div', {id: 'svcList'}))),
    panel(t('days_chart'), t('days_sub'), legend(), days),
    h('div', {class: 'grid g-2'},
      panel(t('sys24'), t('sys24_sub'), h('div', {class: 'legend'}, h('span', {style: '--c:var(--accent)'}, t('cpu')), h('span', {style: '--c:var(--us)'}, t('mem'))), sysBox),
      panel(t('net24'), t('net24_sub'), legend(), netBox))));
  S.charts.live = new LiveChart(live, {span: 180, delay: 7.5});
  S.charts.days = new DayBars(days);
  S.charts.sys = new HistChart(sysBox, {max: 100, unit: v => Math.round(v) + '%',
    series: [{key: 'cpu', color: 'accent', label: t('cpu'), fill: true}, {key: 'mem', color: 'us', label: t('mem')}]});
  S.charts.net = new HistChart(netBox, {min: 1, unit: v => fmt.mbps(v) + ' Mbps',
    series: [{key: 'down', color: 'down', label: '↓', fill: true}, {key: 'up', color: 'up', label: '↑'}]});
  loadSys(true);
  S.charts.tw = {down: new Tween($('kDown'), v => fmt.mbps(v)), online: new Tween($('kOnline'), v => v == null ? '—' : String(Math.round(v))),
    month: new Tween($('kMonth'), v => v == null ? '—' : (v / GB).toFixed(v >= 100 * GB ? 0 : 1)), mem: new Tween($('kMem'), v => v == null ? '—' : String(Math.round(v)))};
  updateHome();
}
/* 24-hour history: lines over a fixed time axis, gaps where the panel was not running */
class HistChart {
  constructor(el, o) {
    this.el = el; this.o = Object.assign({pad: [12, 8, 20, 8]}, o); this.cv = h('canvas'); this.tip = h('div', {class: 'tip hide'}); el.append(this.cv, this.tip);
    this.pts = []; this.hover = null; this.dirty = true;
    el.addEventListener('pointermove', e => { this.hover = e.offsetX; this.dirty = true; Ticker.start(); });
    el.addEventListener('pointerleave', () => { this.hover = null; this.tip.classList.add('hide'); this.dirty = true; Ticker.start(); });
    this.ro = new ResizeObserver(() => { this.dirty = true; Ticker.start(); }); this.ro.observe(el); Ticker.add(this);
  }
  destroy() { if (this.ro) { this.ro.disconnect(); this.ro = null; } Ticker.remove(this); }
  set(pts) { this.pts = pts; this.dirty = true; Ticker.start(); }
  tick() { if (!this.dirty) return false; this.dirty = false; this.draw(); return false; }
  draw() {
    const P = Palette.v, {ctx, w, h: H} = setupCanvas(this.cv), [pt, pr, pb, pl] = this.o.pad, pts = this.pts;
    ctx.clearRect(0, 0, w, H);
    if (pts.length < 2) { ctx.fillStyle = P.muted; ctx.font = '12px sans-serif'; ctx.textAlign = 'center'; ctx.fillText(t('no_hist'), w / 2, H / 2); ctx.textAlign = 'left'; return; }
    const t1 = pts[pts.length - 1].t, t0 = Math.max(pts[0].t, t1 - 86400);
    let max = this.o.max;
    if (!max) { max = this.o.min || 1; for (const p of pts) for (const s of this.o.series) max = Math.max(max, p[s.key] || 0); max *= 1.15; }
    const X = tt => pl + (w - pl - pr) * (tt - t0) / Math.max(1, t1 - t0), Y = v => pt + (H - pt - pb) * (1 - Math.min(max, Math.max(0, v)) / max);
    ctx.font = '10.5px ' + Palette.mono; ctx.textBaseline = 'bottom';
    const step = niceStep(max, 3);
    for (let v = step; v < max * .999; v += step) {
      const y = Math.round(Y(v)) + .5; ctx.strokeStyle = alpha(P.line || '#888', .9); ctx.setLineDash([3, 5]); ctx.beginPath(); ctx.moveTo(pl, y); ctx.lineTo(w - pr, y); ctx.stroke(); ctx.setLineDash([]);
      ctx.fillStyle = P.muted; ctx.fillText(this.o.unit(v), pl + 2, y - 3);
    }
    ctx.strokeStyle = P.line; ctx.beginPath(); ctx.moveTo(pl, H - pb + .5); ctx.lineTo(w - pr, H - pb + .5); ctx.stroke();
    ctx.fillStyle = P.muted; ctx.textBaseline = 'top'; ctx.textAlign = 'center';
    const span = t1 - t0, every = span > 43200 ? 4 : span > 14400 ? 2 : span > 3600 ? 1 : 0;
    if (every) {
      const first = new Date(t0 * 1000); first.setMinutes(0, 0, 0);
      if (first.getTime() / 1000 < t0) first.setHours(first.getHours() + 1);
      for (let x = first.getTime() / 1000; x <= t1; x += 3600) {
        const d = new Date(x * 1000); if (d.getHours() % every) continue;
        const px = X(x); if (px < pl + 16 || px > w - pr - 16) continue; ctx.fillText(String(d.getHours()).padStart(2, '0') + ':00', px, H - pb + 5);
      }
    } else { ctx.textAlign = 'right'; ctx.fillText(new Date(t1 * 1000).toLocaleTimeString(KT.locale, {hour12: false, hour: '2-digit', minute: '2-digit'}), w - pr, H - pb + 5); }
    ctx.textAlign = 'left';
    const vis = pts.filter(p => p.t >= t0);
    for (const s of [...this.o.series].reverse()) {
      const col = P[s.color] || s.color, segs = [[]];
      vis.forEach((p, i) => { if (i && p.t - vis[i - 1].t > 900) segs.push([]); if (p[s.key] != null) segs[segs.length - 1].push([X(p.t), Y(p[s.key])]); });
      for (const seg of segs) {
        if (seg.length < 2) continue;
        if (s.fill) { const g = ctx.createLinearGradient(0, pt, 0, H - pb); g.addColorStop(0, alpha(col, .28)); g.addColorStop(1, alpha(col, 0));
          ctx.beginPath(); traceMonotone(ctx, seg, true); ctx.lineTo(seg[seg.length - 1][0], H - pb); ctx.lineTo(seg[0][0], H - pb); ctx.closePath(); ctx.fillStyle = g; ctx.fill(); }
        ctx.beginPath(); traceMonotone(ctx, seg, true); ctx.strokeStyle = col; ctx.lineWidth = s.fill ? 1.8 : 1.5; ctx.lineJoin = 'round'; ctx.stroke();
      }
    }
    if (this.hover != null) {
      const tt = t0 + (this.hover - pl) / (w - pl - pr) * (t1 - t0); let best = null;
      for (const p of vis) if (!best || Math.abs(p.t - tt) < Math.abs(best.t - tt)) best = p;
      if (best) {
        const x = X(best.t); ctx.strokeStyle = alpha(P.text, .35); ctx.beginPath(); ctx.moveTo(x + .5, pt); ctx.lineTo(x + .5, H - pb); ctx.stroke();
        for (const s of this.o.series) if (best[s.key] != null) { ctx.fillStyle = P[s.color] || s.color; ctx.beginPath(); ctx.arc(x, Y(best[s.key]), 3.5, 0, 7); ctx.fill(); }
        this.tip.textContent = new Date(best.t * 1000).toLocaleTimeString(KT.locale, {hour12: false, hour: '2-digit', minute: '2-digit'}) + (KT === KT_ZH ? '　' : '  ') +
          this.o.series.map(s => s.label + ' ' + (best[s.key] == null ? '—' : this.o.unit(best[s.key]))).join('  ');
        placeTip(this.tip, x, 44, w);
      }
    }
  }
}
async function loadSys(force) {
  if (!force && Date.now() - S.sysAt < 60000) return;
  const viewSeq = S.viewSeq, seq = ++S.sysSeq;
  try {
    const r = await api('sys-history');
    if (seq !== S.sysSeq) return;
    // 5-minute averages: one point a minute is too jagged to read at a glance
    const B = new Map();
    for (const [tt, cpu, mem, rx, tx] of r.points) {
      const k = Math.floor(tt / 300) * 300, b = B.get(k) || {t: k + 150, n: {}, s: {}};
      for (const [key, v] of [['cpu', cpu], ['mem', mem], ['down', tx == null ? null : tx * 8 / 1e6], ['up', rx == null ? null : rx * 8 / 1e6]])
        if (v != null) { b.s[key] = (b.s[key] || 0) + v; b.n[key] = (b.n[key] || 0) + 1; }
      B.set(k, b);
    }
    S.sys = [...B.values()].sort((a, b) => a.t - b.t).map(b => {
      const p = {t: b.t}; for (const k of ['cpu', 'mem', 'down', 'up']) p[k] = b.n[k] ? b.s[k] / b.n[k] : null; return p;
    });
    S.sysAt = Date.now();
  } catch (e) { return; }
  if (viewSeq === S.viewSeq && S.view === 'home' && S.charts.sys) { S.charts.sys.set(S.sys); S.charts.net.set(S.sys); }
}

function updateHome() {
  const d = S.data, hl = d.health || {}, s = d.settings, c = S.charts;
  if (!c.live) return;
  const now = hl.time || Clock.now();
  if (hl.tx_rate != null) c.live.push([{t: now, down: hl.tx_rate * 8 / 1e6, up: hl.rx_rate * 8 / 1e6}]);
  c.tw.down.set(hl.tx_rate != null ? hl.tx_rate * 8 / 1e6 : null);
  $('kDownS').replaceChildren(h('span', null, t('up_') + ' ', h('b', {class: 'num'}, fmt.mbps(hl.rx_rate != null ? hl.rx_rate * 8 / 1e6 : null)), ' Mbps'));
  const active = d.users.filter(u => u.enabled).length;
  c.tw.online.set(d.online);
  $('kOnlineU').textContent = '/ ' + d.users.length + ' ' + tn('users_n', d.users.length);
  $('kOnlineS').replaceChildren(h('span', null, t('active_n') + ' ', h('b', null, active)), h('span', null, t('paused_n') + ' ', h('b', null, d.users.length - active)));
  const rows = S.days.map(x => ({day: x.day, upload: x.up, download: x.down}));
  const days30 = last30(), d30 = new Set(days30), d7 = new Set(days30.slice(-7));
  const total = rows.filter(r => d30.has(r.day)).reduce((a, r) => a + r.upload + r.download, 0);   // the same 30 days as the chart
  const today = localDay(Date.now()), tr = rows.find(r => r.day === today);
  const last7 = rows.filter(r => d7.has(r.day)).reduce((a, r) => a + r.upload + r.download, 0) / 7;
  c.tw.month.set(total); $('kMonthU').textContent = 'GB';
  $('kMonthS').replaceChildren(h('span', null, t('today') + ' ', h('b', null, fmt.bytes(tr ? tr.upload + tr.download : 0))), h('span', null, t('avg7') + ' ', h('b', null, fmt.bytes(last7))));
  c.tw.mem.set(hl.mem_total ? hl.mem_used * 100 / hl.mem_total : null);
  $('kMemS').replaceChildren(h('span', null, t('load') + ' ', h('b', null, hl.load == null ? '—' : hl.load.toFixed(2))), h('span', null, (hl.cpus || '—') + ' CPU'), h('span', null, t('uptime') + ' ', h('b', null, dur(hl.uptime))));
  if (JSON.stringify(rows) !== c.daysKey) { c.daysKey = JSON.stringify(rows); c.days.set(rows, days30); }
  // services
  const svc = (name, on, active, detail) => h('div', {class: 'svc'}, h('b', null, name),
    !on ? chip('off', t('off')) : active === true ? chip('ok', t('running')) : active === false ? chip('bad', t('stopped')) : chip('off', t('unknown')), h('small', null, detail));
  $('svcList').replaceChildren(
    svc('VLESS + REALITY', s.reality_enabled, d.services.xray, 'TCP ' + s.reality_port + ' · ' + s.reality_target),
    svc('Hysteria 2', s.hy2_enabled, d.services.hysteria, 'UDP ' + s.hy2_port + (s.hy2_hop ? ' + ' + s.hy2_hop_range : '')),
    svc('TUIC v5', s.tuic_enabled, d.services.tuic, 'UDP ' + s.tuic_port),
    h('div', {class: 'svc'}, h('b', null, t('bbr')), hl.bbr ? chip('ok', t('yes')) : chip('warn', t('no')), h('small', null, hl.kernel || '')),
    h('div', {class: 'svc'}, h('b', null, t('cert_mode')), d.cert.trusted ? chip('ok', t('cert_ok')) : chip('warn', t('cert_self_s')), h('small', null, d.cert.names.join(', ') || s.public_host)));
  // alerts
  const al = [];
  for (const [k, on, a] of [['VLESS + REALITY', s.reality_enabled, d.services.xray], ['Hysteria 2', s.hy2_enabled, d.services.hysteria], ['TUIC v5', s.tuic_enabled, d.services.tuic]])
    if (on && a === false) al.push(h('div', {class: 'alert bad'}, icon('pulse'), k + ' · ' + t('stopped'), h('button', {class: 'btn sm', onclick: () => go('system')}, t('doctor'))));
  const quota = d.users.filter(u => !u.enabled && u.disabled_reason === 'quota').length;
  if (quota) al.push(h('div', {class: 'alert'}, icon('gauge'), quota + ' · ' + t('r_quota'), h('button', {class: 'btn sm', onclick: () => go('users')}, t('users'))));
  if (d.pending_requests) al.push(h('div', {class: 'alert'}, icon('inbox'), d.pending_requests + ' · ' + t('requests'), h('button', {class: 'btn sm', onclick: () => go('members')}, t('nav_members'))));
  if (d.open_feedback) al.push(h('div', {class: 'alert'}, icon('inbox'), d.open_feedback + ' · ' + t('fb'), h('button', {class: 'btn sm', onclick: () => go('members')}, t('nav_members'))));
  const sm = d.server_month || {}, cap = d.settings.server_cap_gb * GB, smu = (sm.rx || 0) + (sm.tx || 0);
  if (cap && smu >= cap * .8) al.push(h('div', {class: 'alert' + (smu >= cap ? ' bad' : '')}, icon('gauge'), t('server_month') + ' ' + fmt.bytes(smu) + ' / ' + fmt.bytes(cap), h('button', {class: 'btn sm', onclick: () => go('servers')}, t('nav_servers'))));
  for (const r of d.line_trouble || [])
    al.push(h('div', {class: 'alert bad'}, icon('alert'), t('line_down')(r.users, r.name) + (r.here ? '' : t('line_far')),
      r.here ? h('button', {class: 'btn sm', onclick: () => changePort(r.line, r.name, () => { if (S.view === 'home') updateHome(); })}, t('change_port')) : null));
  if (d.renew_days != null && d.renew_days <= 7)
    al.push(h('div', {class: 'alert' + (d.renew_days <= 1 ? ' bad' : '')}, icon('clock'), t('renew_left')(d.renew_days) + (s.vps_renew_note ? ' · ' + s.vps_renew_note : ''),
      h('button', {class: 'btn sm', onclick: () => go('servers')}, t('nav_servers'))));
  $('alerts').replaceChildren(...al);
  loadSys(false);
}

async function changePort(line, name, redraw) {
  if (!await confirmBox(t('change_port_q')(name), t('change_port_tip'), {confirm: t('change_port')})) return;
  try { const r = await api('change-port', {line}); toast(t('port_changed')(r.port)); await load(); if (redraw) redraw(); } catch (e) { err(e); }
}

/* ---------------- users ---------------- */
function userState(u) {
  if (u.enabled) return chip('ok', t('enabled'));
  if (u.disabled_reason === 'devices') return chip('warn', t('r_devices'));
  return chip(u.disabled_reason === 'manual' || !u.disabled_reason ? 'off' : 'bad', t({quota: 'r_quota', expired: 'r_expired', remote: 'r_remote'}[u.disabled_reason] || 'r_manual'));
}
// "12月5日" / "Dec 5" (the year only when it is not this one), like the member center
const dayLabel = iso => {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(iso || '');
  if (!m) return iso || '—';
  const y = +m[1], mo = +m[2], d = +m[3], same = y === new Date().getFullYear();
  return L === 'zh' ? (same ? '' : y + '年') + mo + '月' + d + '日'
    : ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'][mo - 1] + ' ' + d + (same ? '' : ', ' + y);
};
const expText = u => u.expire_at ? dayLabel(u.expire_day || dateStr(u.expire_at)) : u.expire_after_days ? u.expire_after_days + ' ' + t('days') + ' · ' + t('exp_waiting') : t('never');
// Bytes an account may use now. A capped plan whose share went to invitees is 'used up', never 'unlimited'.
const quotaBytes = u => u.quota_gb ? Math.max(1, (u.quota_eff != null ? u.quota_eff : u.quota_gb) * GB) : 0;
const FILTERS = {
  all: () => true, online: u => !!u.online, active: u => !!u.enabled, paused: u => !u.enabled,
  soon: u => u.enabled && u.expire_at && u.expire_at - Date.now() / 1000 < 7 * 86400,
  low: u => { const q = quotaBytes(u); return u.enabled && q && (u.used_up + u.used_down) / q >= .8; }
};
const SORTS = {
  id: (a, b) => a.id - b.id, name: (a, b) => a.name.localeCompare(b.name, L === 'zh' ? 'zh-CN' : 'en'),
  used: (a, b) => (b.used_up + b.used_down) - (a.used_up + a.used_down),
  exp: (a, b) => (a.expire_at || 9e12) - (b.expire_at || 9e12) || a.id - b.id,
  seen: (a, b) => (b.online ? 1 : 0) - (a.online ? 1 : 0) || b.last_seen - a.last_seen
};
async function bulk(action) {
  const ids = [...S.sel]; if (!ids.length) return;
  let value = 0;
  if (action === 'extend' || action === 'add_gb') {
    const v = await modal({title: t(action === 'extend' ? 'q_bulk_extend' : 'q_bulk_addgb')(ids.length), text: t(action === 'extend' ? 'extend_days' : 'add_gb_q'),
      input: true, type: 'number', value: action === 'extend' ? '30' : '50', confirm: t(action === 'extend' ? 'b_extend' : 'b_addgb')});
    if (v == null) return; value = Number(v);
  }
  if (action === 'delete' && !await confirmBox(t('q_bulk_del')(ids.length), t('confirm_bulk_del'), {danger: true, confirm: t('del')})) return;
  if (action === 'rotate' && !await confirmBox(t('q_bulk_rotate')(ids.length), t('confirm_bulk_rotate'), {confirm: t('b_rotate')})) return;
  try {
    const r = await api('users-bulk', {ids, action, value});
    toast(t('bulk_done') + ' ' + r.done);
    if (r.still_paused) toast(t('still_n').replace('{n}', r.still_paused), 'err');
    if (action === 'delete') S.sel.clear();
    await load(); drawUsers();
  } catch (e) { err(e); }
}
function usageBar(u) {
  const used = u.used_up + u.used_down, q = quotaBytes(u), p = q ? used / q : 0;
  return h('div', null, h('div', {class: 'use-top'}, h('b', null, fmt.bytes(used)), h('span', null, q ? fmt.bytes(q) : t('unlimited'))),
    h('div', {class: 'bar' + (p > .95 ? ' bad' : p > .8 ? ' warn' : '')}, h('i', {style: 'width:' + Math.min(100, p * 100) + '%'})));
}
function renderUsersList() {
  const body = $('uBody'); if (!body || !S.data) return;
  const us = S.data.users, q = S.q.toLowerCase();
  for (const id of [...S.sel]) if (!us.some(u => u.id === id)) S.sel.delete(id);
  const found = us.filter(u => !q || u.name.toLowerCase().includes(q) || (u.note || '').toLowerCase().includes(q));
  const list = found.filter(FILTERS[S.f] || FILTERS.all).sort(SORTS[S.sort] || SORTS.id);
  const chips = h('div', {class: 'chips'}, Object.keys(FILTERS).map(k => {
    const n = found.filter(FILTERS[k]).length;
    return k !== 'all' && !n && S.f !== k ? null : h('button', {class: 'filter-chip', 'aria-pressed': String(S.f === k), onclick: () => { S.f = k; renderUsersList(); }}, t('f_' + k), h('span', {class: 'n'}, n));
  }));
  const allSel = list.length > 0 && list.every(u => S.sel.has(u.id));
  const selAll = h('input', {type: 'checkbox', 'aria-label': t('sel_all'), checked: allSel});
  selAll.onchange = () => { for (const u of list) selAll.checked ? S.sel.add(u.id) : S.sel.delete(u.id); renderUsersList(); };
  const head = h('div', {class: 'acct-grid u-grid acct-head'}, h('div', {class: 'c-sel'}, selAll), h('div', null, t('name')), h('div', {class: 'c-use'}, t('usage')), h('div', {class: 'c-exp'}, t('expires')), h('div', {class: 'c-state'}, t('status')), h('div', {class: 'c-acts'}));
  const rows = list.map(u => {
    const box = h('input', {type: 'checkbox', checked: S.sel.has(u.id), 'aria-label': u.name});
    box.onchange = () => { box.checked ? S.sel.add(u.id) : S.sel.delete(u.id); renderUsersList(); };
    const dev = u.online ? (u.online.devices != null ? u.online.devices : u.online.ips.length) : 0;
    return h('div', {class: 'acct-grid u-grid acct-row' + (S.sel.has(u.id) ? ' sel' : ''), tabindex: '0',
        onclick: e => { if (!e.target.closest('button,input,label')) openUser(u.id); }, onkeydown: e => { if (e.key === 'Enter' && e.target === e.currentTarget) openUser(u.id); }},
      h('label', {class: 'c-sel'}, box),
      h('div', {class: 'who'}, h('span', {class: 'ava', style: 'background:' + AVA[u.id % AVA.length]}, (u.name[0] || '?').toUpperCase()),
        h('div', {style: 'min-width:0'}, h('b', null, u.online ? h('span', {class: 'on-dot', title: t('online_now')}) : null, u.name),
          h('small', null, u.online ? t('online_now') + (dev ? ' · ' + dev + (u.max_ips ? '/' + u.max_ips : '') + ' ' + tn('devices', dev) : '') + ' · ' + protoNames(u.online.protocols).join(' / ')
            : noteText(u.note) || (u.last_seen ? t('last_seen') + ' ' + fmt.ago(u.last_seen) : '—')))),
      h('div', {class: 'c-use'}, usageBar(u)),
      h('div', {class: 'c-exp'}, h('span', {class: 'num', style: FILTERS.soon(u) ? 'color:var(--warn);font-weight:600' : null}, expText(u)), u.reset_day || u.max_ips ? h('div', {class: 'cell-sub'},
        [u.reset_day ? t('reset_on').replace('{d}', u.reset_day) : '', u.max_ips ? t('dev_limit') + ' ' + u.max_ips : ''].filter(Boolean).join(' · ')) : null,
        u.limit_mbps ? h('div', {class: 'cell-sub'}, (u.throttled ? t('slowed') : t('limited_now')) + ' ' + u.limit_mbps + ' Mbps') : null),
      h('div', {class: 'c-state'}, userState(u)),
      h('div', {class: 'row-acts c-acts'}, h('button', {class: 'btn sm primary', onclick: () => openUser(u.id)}, icon('link'), t('share')),
        h('button', {class: 'btn sm icon', title: t('edit'), onclick: () => editUser(u)}, icon('edit'))));
  });
  const bb = (a, ic, k, cls) => h('button', {class: 'btn sm' + (cls ? ' ' + cls : ''), onclick: () => bulk(a)}, icon(ic), t(k));
  const bulkBar = S.sel.size ? h('div', {class: 'bulk-bar'}, h('b', null, t('selected') + ' ' + S.sel.size),
    h('div', {class: 'bulk-acts'}, bb('enable', 'play', 'enable'), bb('disable', 'pause', 'disable'), bb('extend', 'clock', 'b_extend'), bb('add_gb', 'plus', 'b_addgb'),
      bb('reset', 'refresh', 'b_reset'), bb('rotate', 'key', 'b_rotate'), bb('delete', 'x', 'del', 'danger')),
    h('button', {class: 'btn sm ghost', onclick: () => { S.sel.clear(); renderUsersList(); }}, t('clear_sel'))) : null;
  body.replaceChildren(chips, ...[bulkBar].filter(Boolean),
    h('div', {class: 'panel'}, head, ...(rows.length ? rows : [h('div', {class: 'empty'}, us.length ? t('no_match') : t('no_users'))])));
}
function drawUsers() {
  if ($('uBody')) { renderUsersList(); return; }
  const search = h('input', {id: 'uSearch', type: 'search', placeholder: t('search'), value: S.q});
  let composing = false;
  search.addEventListener('compositionstart', () => { composing = true; });
  search.addEventListener('compositionend', () => { composing = false; S.q = search.value; renderUsersList(); });
  search.oninput = e => { if (composing || e.isComposing) return; S.q = search.value; renderUsersList(); };
  const sort = h('select', {'aria-label': 'sort'}, Object.keys(SORTS).map(k => h('option', {value: k}, t('s_' + k)))); sort.value = S.sort;
  sort.onchange = () => { S.sort = sort.value; renderUsersList(); };
  const body = h('div', {id: 'uBody', class: 'stack'});
  $('view').replaceChildren(h('section', {class: 'page' + (S.fresh ? '' : ' still')},
    h('div', {class: 'toolbar'}, h('div', {class: 'search'}, icon('search'), search), sort,
      h('div', {class: 'tool-r'}, h('button', {class: 'btn', onclick: batchAdd}, icon('users'), t('batch_add')),
        h('a', {class: 'btn', href: 'api/users-export', download: ''}, icon('arrowDown'), t('export_csv')))),
    body));
  renderUsersList();
}

function batchAdd() {
  S.drawerSeq++;
  const f = {prefix: h('input', {type: 'text', maxlength: '24', value: L === 'zh' ? '用户' : 'user'}), count: h('input', {type: 'number', min: '1', max: '200', value: '10'}),
    quota: h('input', {type: 'number', min: '0', value: '100'}), reset: h('input', {type: 'number', min: '0', max: '31', value: '0'}),
    mode: h('select', null, h('option', {value: 'never'}, t('exp_never')), h('option', {value: 'days'}, t('exp_days')), h('option', {value: 'first'}, t('exp_first'))),
    days: h('input', {type: 'number', min: '1', max: '3650', value: '30'}), ips: h('input', {type: 'number', min: '0', max: '100', value: '0'}),
    note: h('input', {type: 'text', maxlength: '200'})};
  f.mode.value = 'first';
  const daysF = field(t('exp_first_days'), f.days);
  const sync = () => { daysF.hidden = f.mode.value === 'never'; f.days.disabled = daysF.hidden; daysF.firstChild.textContent = t(f.mode.value === 'first' ? 'exp_first_days' : 'exp_days'); };
  f.mode.onchange = sync; sync();
  const save = h('button', {class: 'btn primary', type: 'submit'}, icon('check'), t('batch_add'));
  const form = h('form', {class: 'stack'}, h('div', {class: 'form-grid'}, field(t('batch_prefix'), f.prefix), field(t('batch_count'), f.count),
      field(t('quota'), f.quota), field(t('reset_day'), f.reset), field(t('exp_mode'), f.mode), daysF, field(t('max_ips'), f.ips)), field(t('note'), f.note),
    h('div', {style: 'display:flex;gap:8px;justify-content:flex-end'}, h('button', {class: 'btn ghost', type: 'button', onclick: closeDrawer}, t('cancel')), save));
  form.onsubmit = async e => {
    e.preventDefault(); save.disabled = true;
    const days = Number(f.days.value || 0);
    try {
      const r = await api('users-batch', {prefix: f.prefix.value.trim(), count: Number(f.count.value), quota_gb: Number(f.quota.value || 0), reset_day: Number(f.reset.value || 0),
        max_ips: Number(f.ips.value || 0), note: f.note.value, expire_days: f.mode.value === 'days' ? days : 0, expire_after_days: f.mode.value === 'first' ? days : 0});
      toast(t('batch_made') + ' ' + r.ids.length); closeDrawer(); await load();
      S.sel = new Set(r.ids); S.f = 'all'; if (S.view === 'users') drawUsers(); else go('users');
    } catch (er) { err(er); save.disabled = false; }
  };
  $('drawer').replaceChildren(h('div', {class: 'dr-h'}, h('span', {class: 'ava', style: 'background:var(--accent)'}, icon('users')),
      h('div', null, h('b', null, t('batch_add'))), h('button', {class: 'btn ghost icon', onclick: closeDrawer}, icon('x'))),
    h('div', {class: 'dr-b'}, h('div', {class: 'dr-sec'}, form)));
  openDrawer(); setTimeout(() => f.prefix.focus(), 250);
}

// The drawer is one step in the history, so a phone's Back button closes it instead of leaving the page.
function drawerPush() {
  if (S.drawerHist) return;
  if (S.backPending) { S.pushAfterBack = true; return; }      // a close is still being undone: push after it
  try { history.pushState({drawer: 1}, '', location.hash); S.drawerHist = true; } catch (e) { /* no history */ }
}
function openDrawer() { drawerPush(); $('drawer').classList.add('on'); $('drawer').setAttribute('aria-hidden', 'false'); $('scrim').classList.add('on'); document.body.style.overflow = 'hidden'; }
function closeDrawer(fromBack) {
  S.pushAfterBack = false;
  if (S.drawerHist) {
    S.drawerHist = false;
    if (!fromBack) { S.backPending = true; try { history.back(); } catch (e) { S.backPending = false; } }
  }
  S.drawerSeq++; const d = $('drawer'); if (!d) return; d.classList.remove('on'); d.setAttribute('aria-hidden', 'true'); $('scrim').classList.remove('on'); document.body.style.overflow = ''; }

async function openUser(id, first) {
  const u = S.data.users.find(x => x.id === id); if (!u) return;
  const seq = ++S.drawerSeq;
  let links;
  try { links = await api('user-links?id=' + id); } catch (e) { if (seq === S.drawerSeq) err(e); return; }
  if (seq !== S.drawerSeq || !$('drawer')) return;
  const used = u.used_up + u.used_down, q = quotaBytes(u);
  const histBox = h('div', {class: 'chart h160'});
  const devBox = h('div');
  const pwIn = h('input', {type: 'password', autocomplete: 'new-password', placeholder: t('pw_ph'), 'aria-label': t('pw_ph')});
  const ringBox = h('div', {class: 'ring-box'}, h('div', {class: 'chart'}), h('div', {class: 'lbl'}, h('b', null, q ? fmt.pct(used / q) : '∞'), h('small', null, t('used'))));
  const act = async (btn, fn, ok) => {
    if (btn) btn.disabled = true;
    try { const r = await fn(); if (r && r.still_paused) toast(t('still_' + r.still_paused), 'err'); else toast(ok || t('saved')); await load(); closeDrawer(); if (S.view === 'users') drawUsers(); }
    catch (e) { err(e); if (btn) btn.disabled = false; }
  };
  const actBtn = (cls, ic, label, onClick) => { const b = h('button', {class: cls}, ...(ic ? [icon(ic)] : []), label); b.onclick = () => onClick(b); return b; };
  const imp = links.import;
  const sep = L === 'zh' ? '：' : ': ';
  $('drawer').replaceChildren(
    h('div', {class: 'dr-h'}, h('span', {class: 'ava', style: 'background:' + AVA[u.id % AVA.length]}, (u.name[0] || '?').toUpperCase()),
      h('div', null, h('b', null, first ? t('done_title') : u.name), h('small', null, first ? t('done_sub') : (noteText(u.note) || ('#' + u.id)))),
      h('button', {class: 'btn ghost icon', onclick: closeDrawer, title: KT.cancel}, icon('x'))),
    h('div', {class: 'dr-b'},
      h('div', {class: 'dr-sec'}, h('h4', null, t('share')), h('img', {class: 'qr', alt: 'QR', src: 'api/qr?text=' + encodeURIComponent(links.sub)}),
        h('p', {class: 'muted', style: 'font-size:12.5px;margin:0 0 10px'}, t('share_tip')),
        h('div', {class: 'creds'}, links.sub),
        h('div', {class: 'act-grid'}, h('button', {class: 'btn primary', onclick: () => copyText(links.sub, t('share'))}, icon('copy'), t('copy')),
          h('a', {class: 'btn', href: links.sub, target: '_blank', rel: 'noopener'}, icon('globe'), t('open_page'))),
        // on Windows our own app takes the subscription in one click (vps2vpn://install-config), like the member page
        imp.vps2vpn && /Windows/i.test(navigator.userAgent || '') ?
          h('a', {class: 'btn', href: imp.vps2vpn, style: 'margin-top:8px;width:100%'}, icon('bolt'), t('open_app')) : null,
        h('div', {class: 'import-grid', style: 'margin-top:8px'}, [['Clash', imp.clash], [L === 'zh' ? '小火箭' : 'Shadowrocket', imp.shadowrocket], ['Hiddify', imp.hiddify], ['sing-box', imp.singbox]].map(([n, href]) =>
          h('a', {class: 'btn', href}, t('import_to') + ' ' + n))),
        h('p', {class: 'muted', style: 'font-size:12px;margin:10px 0 0'}, t('apps_hint'))),
      h('div', {class: 'dr-sec'}, h('h4', null, t('usage'), h('span', {class: 'right'}, userState(u))),
        h('div', {class: 'usage-hero'}, ringBox, h('div', {class: 'mini-stats'},
          h('div', null, h('small', null, t('used')), h('b', null, fmt.bytes(used))), h('div', null, h('small', null, q && u.quota_eff != null && u.quota_eff !== u.quota_gb ? t('eff_quota') : t('quota').split(/[（(]/)[0]), h('b', null, q ? fmt.bytes(q) : t('unlimited'), q && u.quota_eff != null && u.quota_eff !== u.quota_gb ? h('small', {class: 'muted'}, ' (' + t('plan') + ' ' + u.quota_gb + ' GB)') : null)),
          h('div', null, h('small', null, '↓ ' + t('down')), h('b', null, fmt.bytes(u.used_down))), h('div', null, h('small', null, '↑ ' + t('up_')), h('b', null, fmt.bytes(u.used_up))),
          h('div', null, h('small', null, t('expires')), h('b', null, expText(u))), h('div', null, h('small', null, t('last_seen')), h('b', null, u.online ? t('online_now') : fmt.ago(u.last_seen))),
          h('div', null, h('small', null, t('sub_fetched')), h('b', null, u.sub_fetched_at ? fmt.ago(u.sub_fetched_at) : t('sub_never'))),
          u.sub_ua ? h('div', {style: 'grid-column:1/-1'}, h('small', null, t('sub_app')), h('b', {style: 'font-size:12px;word-break:break-all'}, u.sub_ua)) : null,
          u.max_ips ? h('div', null, h('small', null, t('dev_limit')), h('b', null, (u.online ? (u.online.devices ?? u.online.ips.length) + ' / ' : '') + u.max_ips)) : null,
          u.shared_gb ? h('div', null, h('small', null, t('shared_out')), h('b', null, u.shared_gb + ' GB')) : null,
          u.extra_gb ? h('div', null, h('small', null, t('extra_now')), h('b', null, '+' + u.extra_gb + ' GB')) : null,
          u.invited_by_name ? h('div', null, h('small', null, t('invited_by')), h('b', null, u.invited_by_name)) : null,
          u.online && u.online.ips.length ? h('div', {style: 'grid-column:1/-1'}, h('small', null, t('online_now') + ' · ' + u.online.ips.length + ' ' + tn('devices', u.online.ips.length)), h('b', {style: 'font-size:12px'}, u.online.ips.join('  '))) : null))),
      h('div', {class: 'dr-sec'}, h('h4', null, t('history'), h('span', {class: 'right muted', style: 'font-weight:500'}, t('history_sub'))), histBox),
      devBox,
      u.remote_id ? null : h('div', {class: 'dr-sec'}, h('h4', null, t('member_login'), h('span', {class: 'right'}, u.has_login ? chip('ok', t('login_on')) : chip('off', t('login_off')))),
        h('p', {class: 'muted', style: 'font-size:12.5px;margin:0 0 10px;line-height:1.7'}, t('member_login_tip')),
        h('div', {style: 'display:flex;gap:8px;flex-wrap:wrap'}, pwIn,
          // An empty box would send password '' - which removes the sign-in - while the page said "saved".
          actBtn('btn', 'lock', t('set_pw'), b => { if (!pwIn.value) { toast(t('pw_first'), 'err'); pwIn.focus(); return; }
            act(b, () => api(`users/${u.id}/login`, {password: pwIn.value})); }),
          u.has_login ? actBtn('btn ghost', null, t('clear_pw'), b => act(b, () => api(`users/${u.id}/login`, {password: ''}), t('pw_cleared'))) : null),
        S.data.member_url ? h('div', {class: 'muted', style: 'font-size:12px;margin-top:8px;word-break:break-all'}, t('member_centre') + sep + S.data.member_url) : null),
      u.remote_id && S.data.node_master ? h('div', {class: 'dr-sec'}, h('div', {class: 'alert'}, icon('server'), t('remote_user').replace('{m}', S.data.node_master))) :
      h('div', {class: 'dr-sec'}, h('h4', null, t('actions')), h('div', {class: 'act-grid'},
        h('button', {class: 'btn', onclick: () => { closeDrawer(); editUser(u); }}, icon('edit'), t('edit')),
        actBtn('btn', u.enabled ? 'pause' : 'play', u.enabled ? t('disable') : t('enable'), b => act(b, () => api(`users/${u.id}/save`, {enabled: !u.enabled}))),
        actBtn('btn', 'refresh', t('reset'), async b => { if (await confirmBox(t('q_reset'), t('confirm_reset') + (u.extra_gb ? ' ' + t('extra_gone') : ''), {confirm: t('reset')})) await act(b, () => api(`users/${u.id}/reset`, {})); }),
        actBtn('btn', 'key', t('rotate'), async b => { if (await confirmBox(t('q_rotate'), t('confirm_rotate'), {confirm: t('rotate')})) await act(b, () => api(`users/${u.id}/rotate`, {})); }),
        actBtn('btn danger', 'x', t('del'), async b => { if (await confirmBox(t('q_del')(u.name), t('confirm_del'), {danger: true, confirm: t('del')})) await act(b, () => api(`users/${u.id}/delete`, {})); })))));
  openDrawer();
  new Ring(ringBox.firstChild).set(q ? used / q : 0, q && used / q > .9 ? 'danger' : 'down');
  const drawDevices = () => api('users/' + u.id + '/devices').then(r => {
    if (seq !== S.drawerSeq || !devBox.isConnected || !r.on) return;
    const flip = async (x, b) => { b.disabled = true; try { await api(`users/${u.id}/devices/${x.device_id}/${x.revoked ? 'unrevoke' : 'revoke'}`, {}); toast(t('saved')); drawDevices(); } catch (e) { err(e); b.disabled = false; } };
    devBox.replaceChildren(h('div', {class: 'dr-sec'}, h('h4', null, t('dv'), h('span', {class: 'right muted', style: 'font-weight:500'}, String(r.devices.length))),
      h('p', {class: 'muted', style: 'font-size:12.5px;margin:0 0 10px;line-height:1.7'}, t('dv_tip')),
      h('div', {class: 'tl'}, ...(r.devices.length ? r.devices.map(x => { const b = h('button', {class: 'btn sm' + (x.revoked ? '' : ' danger')}, t(x.revoked ? 'dv_unrevoke' : 'dv_revoke')); b.onclick = () => flip(x, b);
        return deviceRow(x, t('dv_seen'), [x.revoked ? chip('bad', t('dv_revoked')) : null, b]); }) : [h('div', {class: 'empty', style: 'padding:12px'}, t('dv_none'))]))));
  }).catch(() => {});
  if (!u.remote_id) drawDevices();
  api('users/' + u.id + '/history?days=30').then(r => {
    if (seq === S.drawerSeq && histBox.isConnected) new DayBars(histBox).set(r.days.map(x => ({day: x.day, upload: x.up, download: x.down})), last30());
  }).catch(() => {});
}

function serverChoices() {
  return [{id: 'main', name: (S.data.settings.node_name || 'vps2vpn') + (S.data.settings.traffic_rate !== 1 ? ' ×' + S.data.settings.traffic_rate : '')}]
    .concat((S.data.servers || []).map(x => ({id: x.id, name: x.name + (x.rate !== 1 ? ' ×' + x.rate : '')})));
}

function serverPicker(selected) {
  const all = h('input', {type: 'checkbox', checked: !selected || !selected.length});
  const boxes = serverChoices().map(x => ({id: x.id, el: h('input', {type: 'checkbox', checked: !selected || !selected.length || selected.includes(x.id)}), name: x.name}));
  const sync = () => boxes.forEach(b => { b.el.disabled = all.checked; if (all.checked) b.el.checked = true; });
  all.onchange = sync; sync();
  const el = h('div', {class: 'full stack', style: 'gap:6px'}, h('small', {class: 'muted'}, t('srv_pick')), check(t('srv_all'), all),
    h('div', {style: 'display:flex;flex-wrap:wrap;gap:4px 14px'}, ...boxes.map(b => check(b.name, b.el))));
  // one server and no others: nothing to choose
  if (boxes.length < 2) el.hidden = true;
  return {el, value() {
    if (all.checked || boxes.length < 2) return '';
    const ids = boxes.filter(b => b.el.checked).map(b => b.id);
    if (!ids.length) throw new Error(t('srv_none'));
    return ids;
  }};
}

function shaperNote() {
  const sh = S.data.shaper;
  return sh && !sh.active ? h('div', {class: 'full muted', style: 'font-size:12px'}, t('shaper_off')) : null;
}

function editUser(u) {
  S.drawerSeq++;
  const isNew = !u; u = u || {name: '', quota_gb: 0, expire_at: 0, reset_day: 0, note: '', max_ips: 0, expire_after_days: 0, speed_mbps: 0, throttle_mbps: 0, servers: null};
  const f = {name: h('input', {type: 'text', value: u.name, maxlength: '32'}), quota: h('input', {type: 'number', min: '0', step: 'any', value: u.quota_gb || 0}),
    exp: h('input', {type: 'date', value: u.expire_at ? (u.expire_day || dateStr(u.expire_at)) : ''}), reset: h('input', {type: 'number', min: '0', max: '31', value: u.reset_day || 0}),
    note: h('input', {type: 'text', value: u.note || '', maxlength: '200'}), ips: h('input', {type: 'number', min: '0', max: '100', value: u.max_ips || 0}),
    mode: h('select', null, h('option', {value: 'never'}, t('exp_never')), h('option', {value: 'date'}, t('exp_date')), h('option', {value: 'first'}, t('exp_first'))),
    first: h('input', {type: 'number', min: '1', max: '3650', value: u.expire_after_days || 30}),
    speed: h('input', {type: 'number', min: '0', step: 'any', value: u.speed_mbps || 0}), slow: h('input', {type: 'number', min: '0', step: 'any', value: u.throttle_mbps || 0})};
  const pick = serverPicker(u.servers);
  f.mode.value = u.expire_at ? 'date' : u.expire_after_days ? 'first' : 'never';
  const expF = field(t('expire').split(/[（(]/)[0], f.exp), firstF = field(t('exp_first_days'), f.first);
  const sync = () => { expF.hidden = f.mode.value !== 'date'; firstF.hidden = f.mode.value !== 'first'; f.exp.disabled = expF.hidden; f.first.disabled = firstF.hidden; };
  f.mode.onchange = () => { sync(); if (f.mode.value === 'date' && !f.exp.value) f.exp.value = localDay(Date.now() + 30 * 864e5); };
  sync();
  const save = h('button', {class: 'btn primary', type: 'submit'}, icon('check'), t('save'));
  const form = h('form', {class: 'stack'}, field(t('name'), f.name), h('div', {class: 'form-grid'}, field(t('quota'), f.quota), field(t('reset_day'), f.reset),
      field(t('exp_mode'), f.mode), h('div', null, expF, firstF), h('div', {class: 'full'}, field(t('max_ips'), f.ips)),
      field(t('speed_mbps'), f.speed), field(t('throttle_mbps'), f.slow), shaperNote(), pick.el),
    field(t('note'), f.note), h('div', {class: 'acts', style: 'display:flex;gap:8px;justify-content:flex-end'},
      h('button', {class: 'btn ghost', type: 'button', onclick: closeDrawer}, t('cancel')), save));
  form.onsubmit = async e => {
    e.preventDefault();
    let servers;
    try { servers = pick.value(); } catch (er) { return err(er); }
    save.disabled = true;
    const exp = f.mode.value === 'date' ? f.exp.value : '';
    const body = {name: f.name.value.trim(), quota_gb: Number(f.quota.value || 0), reset_day: Number(f.reset.value || 0), note: f.note.value,
      // the day, not a moment: the server ends it at 23:59:59 in the panel's time zone (Settings), whatever this
      // browser's is. An unchanged day is not sent, so saving other fields never moves the expiry.
      ...(exp ? (exp !== (u.expire_day || '') || isNew ? {expire_date: exp} : {}) : {expire_at: 0}), max_ips: Number(f.ips.value || 0),
      expire_after_days: f.mode.value === 'first' ? Number(f.first.value || 0) : 0,
      speed_mbps: Number(f.speed.value || 0), throttle_mbps: Number(f.slow.value || 0), servers};
    try {
      const r = isNew ? await api('users', body) : await api(`users/${u.id}/save`, body);
      await load(); toast(r && r.period_ends ? t('period_ends').replace('{d}', r.period_ends) : t('saved')); closeDrawer();
      if (S.view === 'users') drawUsers();
      if (isNew && r.id) openUser(r.id);
    } catch (er) { err(er); save.disabled = false; }
  };
  $('drawer').replaceChildren(h('div', {class: 'dr-h'}, h('span', {class: 'ava', style: 'background:var(--accent)'}, icon(isNew ? 'plus' : 'edit')),
      h('div', null, h('b', null, isNew ? t('add_user') : u.name), h('small', null, isNew ? '' : '#' + u.id)),
      h('button', {class: 'btn ghost icon', onclick: closeDrawer}, icon('x'))),
    h('div', {class: 'dr-b'}, h('div', {class: 'dr-sec'}, form)));
  openDrawer(); setTimeout(() => f.name.focus(), 250);
}


/* ---------------- members: requests, invite codes, member center ---------------- */
async function drawMembers() {
  const s = S.data.settings, view = $('view'), seq = S.viewSeq;
  view.replaceChildren(h('div', {class: 'skeleton', style: 'height:200px'}));
  let inv, req, fb;
  try { [inv, req, fb] = await Promise.all([api('invites'), api('requests'), api('feedback').catch(() => null)]); }
  catch (e) { if (seq === S.viewSeq && S.view === 'members') view.replaceChildren(retryBox(e.message, drawMembers)); return err(e); }
  if (seq !== S.viewSeq || S.view !== 'members') return;
  const pend = req.requests.filter(r => r.status === 'pending'), done = req.requests.filter(r => r.status !== 'pending').slice(0, 10);
  const decide = async (r, ok) => {
    let body = {};
    if (ok) {
      const gb = await modal({title: t('approve') + ' · ' + r.name, text: (r.reason ? r.reason + ' · ' : '') + t('approve_tip'), input: true, type: 'number', value: String(r.add_gb), confirm: t('approve')});
      if (gb == null) return; body = {add_gb: numOrNull(gb.trim())};
    } else {
      const ans = await modal({title: t('reject') + ' · ' + r.name, input: true, placeholder: t('answer'), confirm: t('reject'), danger: true});
      if (ans == null) return; body = {answer: ans};
    }
    try { await api(`requests/${r.id}/${ok ? 'approve' : 'reject'}`, body); toast(t('saved')); await load(); updateReqBadges(); drawMembers(); } catch (e) { err(e); }
  };
  const reqRows = pend.map(r => h('div', {class: 'tl-row'}, h('b', null, r.name), h('b', {class: 'num'}, '+' + r.add_gb + ' GB'),
    h('span', {class: 'muted'}, fmt.time(r.created_at) + (r.reason ? ' · ' + r.reason : '')),
    h('span', {class: 'tl-acts'}, h('button', {class: 'btn sm primary', onclick: () => decide(r, true)}, icon('check'), t('approve')),
      h('button', {class: 'btn sm', onclick: () => decide(r, false)}, t('reject')))));
  const histRows = done.map(r => h('div', {class: 'tl-row'}, h('b', null, r.name), h('span', {class: 'num'}, '+' + r.add_gb + ' GB' + (r.asked_gb ? t('asked').replace('{n}', r.asked_gb) : '')),
    h('span', {class: 'muted'}, fmt.time(r.decided_at) + (r.answer ? ' · ' + r.answer : '')), h('span', {class: 'tl-acts'}, chip(r.status === 'approved' ? 'ok' : 'off', t(r.status)))));
  const f = {quota: h('input', {type: 'number', min: '0', step: 'any', value: '100'}), life: h('input', {type: 'number', min: '0', value: '30'}),
    uses: h('input', {type: 'number', min: '1', max: '1000', value: '1'}), valid: h('input', {type: 'number', min: '1', max: '90', value: '7'}),
    reset: h('input', {type: 'number', min: '0', max: '31', value: '0'}), note: h('input', {type: 'text', maxlength: '100'}),
    speed: h('input', {type: 'number', min: '0', step: 'any', value: '0'}), slow: h('input', {type: 'number', min: '0', step: 'any', value: '0'})};
  const pick = serverPicker(null);
  const mk = h('button', {class: 'btn primary'}, icon('key'), t('inv_make'));
  mk.onclick = async () => {
    let servers;
    try { servers = pick.value(); } catch (er) { return err(er); }
    mk.disabled = true;
    try {
      // a cleared box is not 0 (that means unlimited / forever here): the server asks for a number instead
      const r = await api('invites', {kind: 'admin', quota_gb: numOrNull(f.quota.value), expire_days: numOrNull(f.life.value), max_uses: numOrNull(f.uses.value),
        valid_days: numOrNull(f.valid.value), reset_day: numOrNull(f.reset.value), note: f.note.value,
        speed_mbps: Number(f.speed.value || 0), throttle_mbps: Number(f.slow.value || 0), servers});
      await copyText(r.invite.code + (r.invite.register_url ? '\n' + r.invite.register_url : ''), t('copy_code')); drawMembers();
    } catch (e) { err(e); mk.disabled = false; }
  };
  const invRows = inv.invites.map(i => h('div', {class: 'tl-row'}, h('code', {class: 'code-chip'}, i.code),
    h('span', {class: 'muted'}, (i.kind === 'admin' ? t('inv_admin') : i.inviter_name) + ' · ' + (i.quota_gb ? i.quota_gb + ' GB' : t('unlimited')) +
      (i.kind === 'admin' && i.expire_days ? ' · ' + i.expire_days + ' ' + t('days') : '') + ' · ' + i.uses + '/' + i.max_uses +
      (i.used_by.length ? ' · ' + t('used_by') + ' ' + i.used_by.join(', ') : '') + (i.note ? ' · ' + i.note : '') +
      (i.speed_mbps ? ' · ⏬ ' + i.speed_mbps + ' Mbps' : '') + (i.throttle_mbps ? ' · ' + t('slowed') + ' ' + i.throttle_mbps + ' Mbps' : '') +
      (i.servers && i.servers.length ? ' · ' + i.servers.map(id => (serverChoices().find(x => x.id === id) || {name: id}).name).join('/') : '') +
      ' · ' + fmt.time(i.valid_until)),
    h('span', {class: 'tl-acts'}, chip(i.status === 'unused' ? 'ok' : 'off', t('st_' + i.status)),
      i.status === 'unused' ? h('button', {class: 'btn sm', title: t('copy_link'), onclick: () => copyText(i.register_url || i.code, t('copy_link'))}, icon('link')) : null,
      i.status === 'unused' ? h('button', {class: 'btn sm', onclick: async e => { const b = e.currentTarget; if (await confirmBox(t('q_revoke'), t('revoke_tip')(i.code), {danger: true, confirm: t('revoke')})) { b.disabled = true; try { await api(`invites/${i.id}/revoke`, {}); drawMembers(); } catch (er) { err(er); b.disabled = false; } } }}, t('revoke')) : null)));
  const cb = k => { const e = h('input', {type: 'checkbox', checked: !!s[k]}); e.onchange = () => saveSettings({[k]: e.checked}); return check(t(k), e); };
  const fbAct = async (x, a, body) => { try { await api(`feedback/${x.id}/${a}`, body || {}); toast(t('saved')); await load(); updateReqBadges(); drawMembers(); } catch (e) { err(e); } };
  const fbDetail = async (x, box, btn) => {
    if (box.firstChild) { box.replaceChildren(); btn.textContent = t('fb_view'); return; }
    let d; try { d = await api('feedback/' + x.id); } catch (e) { return err(e); }
    btn.textContent = t('fb_hide');
    const steps = (d.diagnosis && Array.isArray(d.diagnosis.steps)) ? d.diagnosis.steps : [];
    const ans = h('textarea', {rows: '2', maxlength: '500', style: 'width:100%;resize:vertical', placeholder: t('fb_answer_ph')});
    box.replaceChildren(h('div', {class: 'stack', style: 'gap:8px;padding:8px 0 4px'},
      d.text ? h('div', {style: 'white-space:pre-wrap;overflow-wrap:anywhere'}, d.text) : null,
      h('small', {class: 'muted', style: 'overflow-wrap:anywhere'}, Object.entries(d.client || {}).map(([k, v]) => k + ': ' + v).join(' · ')),
      steps.length ? h('div', null, h('b', null, t('fb_diag')), h('div', {style: 'display:flex;flex-wrap:wrap;gap:6px;margin-top:6px'},
        ...steps.map(st => chip(st.ok ? 'ok' : 'bad', String(st.id || '?') + (st.detail ? ' · ' + String(st.detail).slice(0, 80) : ''))))) :
        (d.diagnosis && Object.keys(d.diagnosis).length ? h('pre', {class: 'mono', style: 'white-space:pre-wrap;overflow-wrap:anywhere;max-height:200px;overflow:auto;font-size:12px'}, JSON.stringify(d.diagnosis, null, 1)) : null),
      d.log ? h('details', null, h('summary', null, t('fb_log') + ' (' + Math.max(1, Math.ceil(d.log.length / 1024)) + ' KB)'),
        h('pre', {class: 'mono', style: 'white-space:pre-wrap;overflow-wrap:anywhere;max-height:320px;overflow:auto;font-size:12px'}, d.log),
        h('button', {class: 'btn sm', onclick: () => copyText(d.log, t('fb_log'))}, icon('copy'), t('fb_copy'))) : null,
      d.answer ? h('div', {class: 'muted'}, t('fb_replied') + d.answer) : null,
      ans, h('div', {class: 'act-grid'},
        h('button', {class: 'btn sm primary', onclick: () => fbAct(x, 'answer', {answer: ans.value})}, icon('check'), t('fb_answer')),
        x.status === 'open' ? h('button', {class: 'btn sm', onclick: () => fbAct(x, 'done')}, t('fb_mark')) : h('button', {class: 'btn sm', onclick: () => fbAct(x, 'reopen')}, t('fb_reopen')),
        h('button', {class: 'btn sm danger', onclick: async () => { if (await confirmBox(t('fb_del_q'), t('fb_del_tip'), {danger: true, confirm: t('fb_del')})) fbAct(x, 'delete'); }}, icon('x'), t('fb_del')))));
  };
  const fbRows = fb ? fb.items.map(x => {
    const box = h('div'), btn = h('button', {class: 'btn sm'}, t('fb_view'));
    btn.onclick = () => fbDetail(x, box, btn);
    const c = x.client || {};
    return h('div', null, h('div', {class: 'tl-row'}, h('b', null, x.name),
      h('span', {class: 'muted', style: 'overflow-wrap:anywhere'}, fmt.time(x.created_at) + ' · ' + [PLATFORM_NAMES[c.platform] || c.platform, c.version].filter(Boolean).join(' ') + (x.text ? ' · ' + x.text : '')),
      h('span', {class: 'tl-acts'}, chip(x.status === 'open' ? 'warn' : 'ok', t(x.status === 'open' ? 'fb_open' : 'fb_done')), btn)), box);
  }) : [];
  const fbOpen = fb ? fb.items.filter(x => x.status === 'open').length : 0;
  const fbPanel = fb ? panel(t('fb'), null, fbOpen ? chip('warn', fbOpen + ' ' + t('fb_open')) : null, tip(t('fb_tip')), h('div', {class: 'stack'},
    cb('client_feedback'),
    h('div', {class: 'tl'}, ...(fbRows.length ? fbRows : [h('div', {class: 'empty', style: 'padding:18px'}, t('fb_none'))])))) : null;
  view.replaceChildren(h('section', {class: 'page'},
    fbPanel,
    h('div', {class: 'grid g-2-1'},
      panel(t('requests'), null, pend.length ? chip('warn', pend.length + ' ' + t('pending')) : null,
        h('div', {class: 'tl'}, ...(reqRows.length ? reqRows : [h('div', {class: 'empty', style: 'padding:18px'}, t('req_none'))])),
        histRows.length ? h('div', {class: 'tl', style: 'margin-top:14px;opacity:.8'}, ...histRows) : null),
      panel(t('member_centre'), null, null, h('div', {class: 'stack'}, cb('member_enabled'), cb('member_invites'), cb('member_requests'),
        (() => { const ta = h('textarea', {rows: '3', maxlength: '500', style: 'width:100%;resize:vertical'}, s.member_notice || '');
          return h('div', null, field(t('member_notice'), ta), h('button', {class: 'btn sm', style: 'margin-top:8px', onclick: () => saveSettings({member_notice: ta.value})}, t('save_notice'))); })(),
        S.data.member_url ? h('div', null, h('div', {class: 'muted', style: 'font-size:12px;margin-bottom:6px'}, t('member_url')), h('div', {class: 'creds'}, S.data.member_url),
          h('button', {class: 'btn sm', style: 'margin-top:8px', onclick: () => copyText(S.data.member_url, t('member_centre'))}, icon('copy'), t('copy_btn'))) : null))),
    panel(t('invites'), null, null, tip(t('inv_tip')), h('div', {class: 'stack'},
      h('div', {class: 'form-grid g3'}, field(t('inv_quota'), f.quota), field(t('inv_life'), f.life), field(t('inv_uses'), f.uses), field(t('inv_valid'), f.valid),
        field(t('inv_reset'), f.reset), field(t('note'), f.note), field(t('speed_mbps'), f.speed), field(t('throttle_mbps'), f.slow), shaperNote(), pick.el),
      h('div', null, mk),
      h('div', {class: 'tl'}, ...(invRows.length ? invRows : [h('div', {class: 'empty', style: 'padding:18px'}, t('inv_none'))]))))));
}

/* ---------------- servers: join code, joined servers, monthly traffic ---------------- */
async function drawServers() {
  const s = S.data.settings, view = $('view'), seq = S.viewSeq;
  view.replaceChildren(h('div', {class: 'skeleton', style: 'height:200px'}));
  let sv;
  try { sv = await api('servers'); }
  catch (e) { if (seq === S.viewSeq && S.view === 'servers') view.replaceChildren(retryBox(e.message, drawServers)); return err(e); }
  // a panel too old to have it, or a joined server (its own status is set on the main server): no status panel
  const ns = sv.node_master ? null : await api('node-status').catch(() => null);
  if (seq !== S.viewSeq || S.view !== 'servers') return;
  const code = h('input', {type: 'text', placeholder: 'v2v1.…', autocomplete: 'off'}), name = h('input', {type: 'text', maxlength: '24'});
  const add = h('button', {class: 'btn primary'}, icon('plus'), t('add_server'));
  add.onclick = async () => { add.disabled = true; try { await api('servers', {code: code.value.trim(), name: name.value.trim()}); toast(t('saved')); await load(); drawServers(); } catch (e) { err(e); add.disabled = false; } };
  const act = async (btn, id, a, body) => { if (btn) btn.disabled = true; try { const r = await api(`servers/${id}/${a}`, body || {}); if (r && r.released === false) toast(t('remove_unreached')); await load(); drawServers(); } catch (e) { err(e); if (btn) btn.disabled = false; } };
  const rows = sv.servers.map(x => h('div', {class: 'tl-row'},
    h('b', null, x.name), h('span', {class: 'muted'}, x.host + ' · ' + protoNames(x.protocols).join(' / ') + ' · ' + x.users + ' ' + tn('users_n', x.users) +
      (x.health && x.health.mem_total ? ' · ' + t('mem') + ' ' + Math.round(x.health.mem_used * 100 / x.health.mem_total) + '%' : '') +
      (x.last_ok ? ' · ' + t('last_sync') + ' ' + fmt.ago(x.last_ok) : '') + (x.version ? ' · v' + x.version : '') + ' · ' + t('rate') + ' ×' + x.rate),
    h('span', {class: 'tl-acts'}, x.error ? chip('bad', t('sync_failed')) : x.enabled ? chip('ok', t('running')) : chip('off', t('off')),
      h('button', {class: 'btn sm', title: t('rate_set'), onclick: async e => { const b = e.currentTarget;
        const v = await modal({title: t('rate_set') + ' · ' + x.name, text: t('rate_tip'), input: true, type: 'number', value: String(x.rate), confirm: t('save')});
        if (v != null) act(b, x.id, 'save', {rate: Number(v)}); }}, '×' + x.rate),
      h('button', {class: 'btn sm', title: t('sync_now'), 'aria-label': t('sync_now'), onclick: e => act(e.currentTarget, x.id, 'sync')}, icon('refresh')),
      h('button', {class: 'btn sm', title: t(x.enabled ? 'srv_pause' : 'srv_resume'), 'aria-label': t(x.enabled ? 'srv_pause' : 'srv_resume'), onclick: e => act(e.currentTarget, x.id, 'save', {enabled: !x.enabled})}, icon(x.enabled ? 'pause' : 'play')),
      h('button', {class: 'btn sm danger', onclick: async e => { const b = e.currentTarget; if (await confirmBox(t('q_remove')(x.name), t('remove_tip'), {danger: true, confirm: t('remove')})) act(b, x.id, 'remove'); }}, icon('x'))),
    x.error ? srvErr(x.error) : null));
  rows.push(...(sv.leaving || []).map(x => h('div', {class: 'tl-row'},
    h('b', null, x.name), h('span', {class: 'muted'}, x.host + ' · ' + t('leaving_wait').replace('{d}', x.days_left)),
    h('span', {class: 'tl-acts'}, chip('warn', t('leaving')),
      h('button', {class: 'btn sm danger', onclick: async e => { const b = e.currentTarget; if (await confirmBox(t('q_forget')(x.name), t('leaving_forget_tip'), {danger: true, confirm: t('leaving_forget')})) act(b, x.id, 'forget'); }}, t('leaving_forget'))),
    x.error ? srvErr(x.error, 'warn') : null)));
  const stRow = x => {
    const st = h('select', null, ...[['ok', t('st_ok')], ['maintenance', t('st_maint')], ['congested', t('st_cong')]].map(([v, l]) => h('option', {value: v}, l)));
    const note = h('input', {type: 'text', maxlength: '100', value: x.note || ''}), until = h('input', {type: 'datetime-local', value: x.until_local || ''});
    st.value = x.state;
    const sync = () => { note.disabled = until.disabled = st.value === 'ok'; }; st.onchange = sync; sync();
    const b = h('button', {class: 'btn sm'}, icon('check'), t('save'));
    b.onclick = async () => { b.disabled = true;
      try { await api('node-status', {id: x.id, state: st.value, note: note.value, until_local: st.value === 'ok' ? '' : until.value}); toast(t('saved')); drawServers(); }
      catch (e) { err(e); b.disabled = false; } };
    return h('div', {class: 'stack', style: 'gap:6px'}, h('b', null, x.name + (x.id === 'main' ? t('st_this') : '')),
      h('div', {class: 'form-grid g3'}, field(t('st_state'), st), field(t('st_note'), note), field(t('st_until'), until)), h('div', null, b));
  };
  const statusPanel = ns ? panel(t('node_status'), null, null, tip(t('node_status_tip')), h('div', {class: 'stack'},
    (() => { const e = h('input', {type: 'checkbox'}); e.checked = !!ns.on; e.onchange = () => saveSettings({client_node_status: e.checked}, drawServers); return check(t('client_node_status'), e); })(),
    ...(ns.on ? ns.servers.map(stRow) : []))) : null;
  const sm = S.data.server_month || {}, used = (sm.rx || 0) + (sm.tx || 0), cap = s.server_cap_gb * GB;
  const capIn = h('input', {type: 'number', min: '0', value: s.server_cap_gb || 0}), dayIn = h('input', {type: 'number', min: '1', max: '31', value: s.server_reset_day || 1});
  const ring = h('div', {class: 'ring-box'}, h('div', {class: 'chart'}), h('div', {class: 'lbl'}, h('b', null, cap ? fmt.pct(used / cap) : '∞'), h('small', null, sm.period || '')));
  const resetKeyBtn = h('button', {class: 'btn'}, icon('key'), t('reset_key'));
  resetKeyBtn.onclick = async () => {
    if (!await confirmBox(t('q_reset_key'), t('reset_key_tip'), {danger: true, confirm: t('reset_key')})) return;
    resetKeyBtn.disabled = true;
    try { await api('node-key', {}); await load(); drawServers(); } catch (e) { err(e); resetKeyBtn.disabled = false; }
  };
  view.replaceChildren(h('section', {class: 'page'},
    sv.node_master ? h('div', {class: 'alert'}, icon('server'), t('managed_by') + sv.node_master) : null,
    panel(t('servers'), null, null, tip(t('servers_tip')), h('div', {class: 'stack'},
      h('div', {class: 'tl'}, ...(rows.length ? rows : [h('div', {class: 'empty', style: 'padding:18px'}, t('no_servers'))])),
      h('div', {class: 'form-grid'}, field(t('paste_code'), code), field(t('server_name'), name)), h('div', null, add),
      (() => { const r = h('input', {type: 'number', min: '0', max: '100', step: '0.1', value: s.traffic_rate ?? 1});
        return h('div', {class: 'form-grid'}, field(t('rate_this'), r), h('div', {style: 'display:flex;align-items:flex-end;gap:8px'},
          h('button', {class: 'btn', onclick: () => saveSettings({traffic_rate: numOrNull(r.value)}, drawServers)}, icon('check'), t('save')),
          h('small', {class: 'muted'}, t('rate_tip')))); })())),
    statusPanel,
    h('div', {class: 'grid g-2'},
      panel(t('server_month'), null, null, tip(t('cap_tip')), h('div', {class: 'usage-hero'}, ring, h('div', {class: 'stack'},
        h('div', {class: 'mini-stats'}, h('div', null, h('small', null, '↓ ' + t('down')), h('b', null, fmt.bytes(sm.tx || 0))), h('div', null, h('small', null, '↑ ' + t('up_')), h('b', null, fmt.bytes(sm.rx || 0)))),
        h('div', {class: 'form-grid'}, field(t('cap'), capIn), field(t('cap_day'), dayIn)),
        h('div', null, h('button', {class: 'btn', onclick: () => saveSettings({server_cap_gb: numOrNull(capIn.value), server_reset_day: numOrNull(dayIn.value)}, drawServers)}, icon('check'), t('save')))))),
      panel(t('join_code'), null, null, tip(t('join_tip')), h('div', {class: 'stack'}, h('div', {class: 'creds', style: 'max-height:90px;overflow:auto'}, sv.join_code),
        h('div', {class: 'act-grid'}, h('button', {class: 'btn primary', onclick: () => copyText(sv.join_code, t('join_code'))}, icon('copy'), t('copy_btn')), resetKeyBtn))))));
  const renewIn = h('input', {type: 'date', value: s.vps_renew_at || ''}), noteIn = h('input', {type: 'text', maxlength: '40', value: s.vps_renew_note || ''});
  const left = S.data.renew_days;
  view.firstChild.append(panel(t('renew'), left != null ? t('renew_left')(left) : null, null, tip(t('renew_tip')), h('div', {class: 'stack'},
    h('div', {class: 'form-grid'}, field(t('renew_at'), renewIn), field(t('renew_note'), noteIn)),
    h('div', {style: 'display:flex;gap:8px;flex-wrap:wrap'},
      h('button', {class: 'btn', onclick: () => saveSettings({vps_renew_at: renewIn.value, vps_renew_note: noteIn.value}, drawServers)}, icon('check'), t('save')),
      s.vps_renew_at ? h('button', {class: 'btn', onclick: () => saveSettings({vps_renew_at: '', vps_renew_note: ''}, drawServers)}, t('renew_clear')) : null))));
  new Ring(ring.firstChild).set(cap ? used / cap : 0, cap && used / cap > .9 ? 'danger' : 'down');
}

/* ---------------- monitor: site reachability + abuse watch ---------------- */
function spark(cv, vals) {
  Ticker.add({el: cv, tick() {
    const {ctx, w, h: hh} = setupCanvas(cv), P = Palette.v; ctx.clearRect(0, 0, w, hh);
    const ok = vals.filter(v => v != null), max = Math.max(200, ...ok) * 1.15, n = Math.max(1, vals.length - 1);
    vals.forEach((v, i) => { if (v == null) { ctx.fillStyle = alpha(P.danger || '#e5432a', .7); ctx.fillRect(i / n * w - 1, 0, 2, hh); } });
    const pts = vals.map((v, i) => v == null ? null : [i / n * w, hh - 2 - v / max * (hh - 4)]).filter(Boolean);
    if (pts.length > 1) { ctx.strokeStyle = P.down; ctx.lineWidth = 1.6; ctx.beginPath(); traceMonotone(ctx, pts, true); ctx.stroke(); }
    return false;
  }});
  Ticker.start();
}
function probeErr(r) {
  if (r.status) return 'HTTP ' + r.status;
  const e = r.error || '';
  return t(/Timeout|timed out/i.test(e) ? 'e_timeout' : /Refused|Reset|Aborted/i.test(e) ? 'e_reset' : /gaierror|getaddrinfo|Name or service/i.test(e) ? 'e_dns'
    : /SSL|certificate/i.test(e) ? 'e_tls' : 'e_other');
}
async function drawMonitor() {
  const s = S.data.settings, view = $('view'), seq = S.viewSeq;
  view.replaceChildren(h('div', {class: 'skeleton', style: 'height:200px'}));
  let mo, ab;
  try { [mo, ab] = await Promise.all([api('monitor'), api('abuse')]); }
  catch (e) { if (seq === S.viewSeq && S.view === 'monitor') view.replaceChildren(retryBox(e.message, drawMonitor)); return err(e); }
  if (seq !== S.viewSeq || S.view !== 'monitor') return;
  const run = h('button', {class: 'btn primary'}, icon('refresh'), t('run_now'));
  run.onclick = async () => {
    run.disabled = true;
    try { await api('monitor', {}); toast('…'); setTimeout(() => { if (seq === S.viewSeq && S.view === 'monitor') drawMonitor(); }, 9000); }
    catch (e) { err(e); run.disabled = false; }
  };
  const lt = mo.latest;
  const sites = (mo.sites || []).map(x => {
    const cvs = [], fam = ['v4', 'v6'].filter(k => x[k]);
    const box = h('div', {class: 'site'}, h('div', {class: 'site-h'}, h('b', null, x.label),
        x.v4 && x.v4.now ? (x.v4.now.ok ? chip('ok', Math.round(x.v4.now.total) + ' ms') : chip('bad', probeErr(x.v4.now))) : chip('off', '—')),
      ...fam.map(k => { const cv = h('canvas', {class: 'spark'}); cvs.push([cv, x[k].spark]);
        return h('div', null, h('small', null, (k === 'v4' ? 'IPv4' : 'IPv6') + ' · ' + t('uptime24') + ' ' + fmt.pct(x[k].uptime) + ' · ' + t('median') + ' ' + (x[k].median_ms == null ? '—' : Math.round(x[k].median_ms) + ' ms')), cv); }));
    box._cvs = cvs; return box;
  });
  const flag = f => chip(f === 'shared' ? 'warn' : 'bad', t('f_' + f));
  const accs = ab.accounts.filter(a => a.streams || a.ips || a.flags.length);
  const acb = k => { const e = h('input', {type: 'checkbox', checked: !!s[k]}); e.onchange = () => saveSettings({[k]: e.checked}); return check(t(k), e); };
  const scan = h('button', {class: 'btn'}, icon('shield'), t('scan_now'));
  scan.onclick = async () => { scan.disabled = true; try { await api('abuse', {}); drawMonitor(); } catch (e) { err(e); scan.disabled = false; } };
  const sep = L === 'zh' ? '：' : ': ';
  view.replaceChildren(h('section', {class: 'page'},
    panel(t('monitor'), null, run, tip(t('monitor_tip')), !lt ? h('div', {class: 'empty'}, t('no_data')) : h('div', {class: 'stack'},
      h('div', {class: 'port-list'}, chip('info plain', fmt.time(lt.at)), lt.region ? chip('info plain', t('region') + ' ' + lt.region) : null,
        lt.chatgpt_region_ok === true ? chip('ok', t('chatgpt_ok')) : lt.chatgpt_region_ok === false ? chip('bad', t('chatgpt_bad')) : null,
        lt.speed && lt.speed.ok ? chip('ok', t('speed') + ' ' + lt.speed.mbps + ' Mbps') : null, chip(lt.v6 ? 'ok' : 'off', 'IPv6 ' + (lt.v6 ? t('yes') : t('no')))),
      h('div', {class: 'site-grid'}, ...sites), acb('monitor_enabled'))),
    panel(t('abuse'), null, scan, tip(t('abuse_tip')), h('div', {class: 'stack'}, acb('abuse_guard'),
      h('div', {class: 'muted', style: 'font-size:12px'}, t('coverage') + sep + (ab.coverage.join(', ') || '—') + (ab.at ? ' · ' + fmt.time(ab.at) : '')),
      accs.length ? h('div', {class: 'tl'}, accs.map(a => h('div', {class: 'tl-row'}, h('b', null, a.name),
        h('span', {class: 'muted num'}, `${t('streams')} ${a.streams} · ${t('targets')} ${a.targets} · ${t('ports_n')} ${a.ports} · ${t('addrs')} ${a.ips}`),
        h('span', {class: 'tl-acts'}, ...(a.flags.length ? a.flags.map(flag) : [chip('ok', t('ok_quiet'))]))))) : h('div', {class: 'muted', style: 'font-size:12.5px'}, t('abuse_none')),
      h('h4', {style: 'margin:8px 0 0'}, t('events')),
      ab.events.length ? h('div', {class: 'tl'}, ab.events.map(e => h('div', {class: 'tl-row'}, h('span', {class: 'num muted'}, fmt.time(e.at)), h('span', null, e.text)))) : h('div', {class: 'muted', style: 'font-size:12.5px'}, t('no_events'))))));
  for (const b of sites) for (const [cv, vals] of b._cvs) spark(cv, vals);
}

/* ---------------- settings ---------------- */
function drawSettings() {
  const s = S.data.settings, inputs = [], seq = S.viewSeq;
  const bind = (k, el) => { el.dataset.k = k; inputs.push(el); return el; };
  const cb = k => bind(k, h('input', {type: 'checkbox', checked: !!s[k]}));
  const inp = (k, type) => bind(k, h('input', {type: type || 'text', value: s[k] == null ? '' : s[k]}));
  const sel = (k, opts) => { const e = bind(k, h('select', null, opts.map(([v, n]) => h('option', {value: v}, n)))); e.value = s[k]; return e; };
  const timeZones = [['', t('tz_server')], ['UTC+8', 'UTC+8 · 北京 / 新加坡 / 台北'], ['UTC+9', 'UTC+9 · 东京 / 首尔'],
    ['UTC+7', 'UTC+7 · 曼谷'], ['UTC', 'UTC'], ['UTC-5', 'UTC-5'], ['UTC-8', 'UTC-8']];
  if (s.time_zone && !timeZones.some(([value]) => value === s.time_zone)) timeZones.push([s.time_zone, s.time_zone]);
  const pickRes = h('div', {class: 'muted', style: 'font-size:12px'});
  const target = inp('reality_target');
  const pick = h('button', {class: 'btn sm', type: 'button'}, icon('bolt'), t('test_targets'));
  pick.onclick = async () => {
    pick.disabled = true; pickRes.textContent = '…';
    try { const r = await api('check-targets'); target.value = r.best; pickRes.textContent = r.results.map(x => `${x.host}: ${x.ok ? x.ms + ' ms ✓' : '✗'}`).join(' · '); }
    catch (e) { err(e); pickRes.textContent = ''; }
    pick.disabled = false;
  };
  const proto = (k, title, desc, ...grid) => h('div', {class: 'proto'}, check(title, cb(k)), h('em', null, desc), h('div', {class: 'form-grid'}, ...grid));
  const portBtn = (line, name) => s[line === 'reality' ? 'reality_enabled' : line + '_enabled'] ?
    h('div', {class: 'full'}, h('button', {class: 'btn sm', type: 'button', title: t('change_port_tip'), onclick: () => changePort(line, name, drawSettings)}, icon('refresh'), t('change_port'))) : null;
  const certBtn = h('button', {class: 'btn sm', type: 'button'}, icon('lock'), t('cert_now'));
  certBtn.onclick = async () => { certBtn.disabled = true; try { await api('cert', {}); toast('…'); } catch (e) { err(e); } finally { certBtn.disabled = false; } };
  const saveBtn = h('button', {class: 'btn primary'}, icon('check'), t('save'));
  saveBtn.onclick = async () => {
    const body = {};
    for (const el of inputs) body[el.dataset.k] = el.type === 'checkbox' ? el.checked : el.type === 'number' ? numOrNull(el.value) : el.value;
    if (!body.reality_enabled && !body.hy2_enabled && !body.tuic_enabled) return toast(t('proto_one'), 'err');
    const prevLang = L;
    saveBtn.disabled = true;
    try { await api('settings', body); toast(t('saved')); await load(); if (seq !== S.viewSeq) return; if (L !== prevLang) await renderShell(); else drawSettings(); }
    catch (e) { err(e); saveBtn.disabled = false; }
  };
  $('view').replaceChildren(h('section', {class: 'page'},
    panel(t('s_proto'), null, null, h('div', null,
      proto('reality_enabled', t('reality'), t('reality_d'), field(t('reality_target'), target), field(t('reality_port'), inp('reality_port', 'number')),
        h('div', {class: 'full'}, pick, pickRes), portBtn('reality', 'VLESS + REALITY')),
      proto('hy2_enabled', t('hy2'), t('hy2_d'), field(t('hy2_port'), inp('hy2_port', 'number')), field(t('hy2_hop_range'), inp('hy2_hop_range')),
        h('div', {class: 'full'}, check(t('hy2_hop'), cb('hy2_hop'))), h('div', {class: 'full'}, field(t('hy2_obfs'), inp('hy2_obfs'))), portBtn('hy2', 'Hysteria 2')),
      proto('tuic_enabled', t('tuic'), t('tuic_d'), field(t('tuic_port'), inp('tuic_port', 'number')), portBtn('tuic', 'TUIC v5')))),
    h('div', {class: 'grid g-2'},
      panel(t('s_basic'), null, null, h('div', {class: 'stack'},
        field(t('lang'), sel('language', [['zh', '中文'], ['en', 'English']])),
        field(t('time_zone'), sel('time_zone', timeZones)), field(t('node_name'), inp('node_name')), field(t('server_addr'), inp('public_host')),
        field(t('support_url'), inp('support_url', 'url')), field(t('sub_update_hours'), inp('sub_update_hours', 'number')),
        check(t('tune'), cb('tune_network')), s.public_ipv6 ? check(t('ipv6_nodes') + ' · ' + s.public_ipv6, cb('ipv6_nodes')) : null,
        check(t('ip_limit_pause'), cb('ip_limit_pause')))),
      panel(t('s_route'), null, null, h('div', {class: 'stack'}, check(t('tcp_first'), cb('tcp_first')), check(t('block_ads'), cb('block_ads')), check(t('ai_group'), cb('ai_group')), check(t('block_bt'), cb('block_bt'))))),
    panel(t('routing_custom'), null, null, tip(t('routing_tip')), h('div', {class: 'grid g-3'},
      ...[['custom_direct', 'c_direct', 'ok'], ['custom_proxy', 'c_proxy', 'info'], ['custom_block', 'c_block', 'bad']].map(([k, lk, c]) => {
        const ta = bind(k, h('textarea', {rows: '6', spellcheck: 'false', class: 'mono', placeholder: k === 'custom_direct' ? 'example.cn\nmy-nas.com' : k === 'custom_proxy' ? 'example.com' : 'ads.example.com'}));
        ta.value = (s[k] || []).join('\n');
        return h('label', {class: 'field'}, h('span', null, chip(c, t(lk)), h('small', {class: 'muted', style: 'margin-left:6px'}, (s[k] || []).length || '')), ta);
      }))),
    panel(t('s_cert'), null, S.data.cert.trusted ? chip('ok', t('cert_ok')) : chip('warn', t('cert_self_s')), h('div', {class: 'stack'},
      h('div', {class: 'form-grid'}, field(t('cert_mode'), sel('cert_mode', [['auto', t('cert_auto')], ['self', t('cert_self')]])), field(t('domain'), inp('domain')),
        field(t('email'), inp('acme_email', 'email'))),
      S.data.cert.trusted ? null : h('div', {class: 'muted', style: 'font-size:12.5px'}, t('cert_self_tip')),
      certStatus(S.data.cert.status), h('div', null, certBtn))),
    clientPanel(s, inp),
    h('div', {class: 'save-bar'}, saveBtn)));
}
function clientPanel(s, inp) {
  const c = S.data.client || {}, f = c.found;
  const found = f ? t('client_found')(f.version, Object.keys(f.files).join(' / ')) : t('client_none')(c.dir || '/var/lib/vps2vpn/client');
  return panel(t('client_upd'), null, f || s.client_version ? chip('ok', 'v' + (s.client_version || f.version)) : chip('off', t('off')),
    tip(t('client_tip')), h('div', {class: 'stack'},
      // a folder path or long installer names must wrap, or they widen the whole page on a phone
      h('div', {class: 'muted', style: 'font-size:12.5px;overflow-wrap:anywhere'}, found),
      f && f.unsigned && f.unsigned.length ? h('div', {class: 'alert warn', style: 'overflow-wrap:anywhere'}, icon('alert'), t('client_unsigned')(f.unsigned.join(', '))) : null,
      (() => { const e = h('input', {type: 'checkbox', checked: s.client_auto_update !== false}); e.onchange = () => saveSettings({client_auto_update: e.checked}); return check(t('client_auto_update'), e); })(),
      (() => { const e = h('input', {type: 'checkbox', checked: !!s.client_traffic_rank}); e.onchange = () => saveSettings({client_traffic_rank: e.checked}); return check(t('client_traffic_rank'), e); })(),
      (() => { const e = h('input', {type: 'checkbox', checked: !!s.client_node_status}); e.onchange = () => saveSettings({client_node_status: e.checked}); return check(t('client_node_status'), e); })(),
      (() => { const e = h('input', {type: 'checkbox', checked: !!s.client_feedback}); e.onchange = () => saveSettings({client_feedback: e.checked}); return check(t('client_feedback'), e); })(),
      (() => { const e = h('input', {type: 'checkbox', checked: !!s.client_devices}); e.onchange = () => saveSettings({client_devices: e.checked}); return check(t('client_devices'), e); })(),
      h('div', {class: 'form-grid'}, field(t('client_ver'), inp('client_version')), field(t('client_url'), inp('client_url'))),
      field(t('client_notes'), inp('client_notes'))));
}

/* ---------------- health check + maintenance ---------------- */
async function runDoctor(btn, box) {
  btn.disabled = true; box.replaceChildren(h('div', {class: 'skeleton', style: 'height:120px'}));
  try {
    const r = (await api('doctor', {})).results, bad = r.filter(x => x.ok === false).length;
    const sep = L === 'zh' ? '：' : ': ';
    box.replaceChildren(h('div', {style: 'margin-bottom:6px'}, bad ? chip('bad', bad + ' ' + tn('doctor_bad', bad)) : chip('ok', t('doctor_ok'))),
      // name, detail and fix come in the panel's language; `orig` is the server's English detail (hover / click)
      ...r.map(x => h('div', {class: 'doc-row'}, h('span', {class: 'dot ' + (x.ok === true ? 'ok' : x.ok === false ? 'bad' : '')}),
        h('div', null, h('b', null, x.name || x.id), x.detail ? xdetail(x.detail, x.orig, 'doc-detail') : null,
          x.fix ? h('div', {class: 'fix'}, h('b', null, t('fix') + sep), x.fix) : null))));
  } catch (e) { box.replaceChildren(retryBox(e.message, () => runDoctor(btn, box))); }
  btn.disabled = false;
}
const AI_KIND = {hosting: ['机房 IP（数据中心）', 'Data-center IP'], residential: ['家庭宽带 IP', 'Home broadband IP'], mobile: ['手机网络 IP', 'Mobile IP']};
const AI_SITES = [['claude', 'Claude'], ['claude_api', 'Claude API'], ['chatgpt', 'ChatGPT'], ['gemini', 'Gemini']];
function aiPanel() {
  const seq = S.viewSeq, box = h('div', {class: 'skeleton', style: 'height:120px'}), btn = h('button', {class: 'btn sm'}, icon('pulse'), t('ai_run'));
  const draw = r => {
    if (seq !== S.viewSeq || !box.isConnected) return;
    box.className = ''; box.style.height = '';
    const res = r.result;
    if (!res) return box.replaceChildren(h('p', {class: 'muted', style: 'margin:0;font-size:12.5px'}, t('ai_never')));
    const ip = res.ip || {}, kind = AI_KIND[ip.kind], zh = L === 'zh';
    const tone = st => st === 'ok' ? 'ok' : st === 'blocked' ? 'bad' : st === 'unreachable' ? 'warn' : 'off';
    const row = (k, v) => v ? h('div', {style: 'display:flex;gap:12px;font-size:13px;padding:3px 0'}, h('span', {class: 'muted', style: 'flex:none;width:64px'}, k), h('span', null, v)) : null;
    box.replaceChildren(...[
      h('div', {style: 'display:flex;flex-wrap:wrap;gap:6px;margin-bottom:10px'},
        AI_SITES.map(([k, n]) => { const x = res.sites[k] || {}; return h('span', {title: x.note || ''}, chip(tone(x.status), n + ' · ' + t('ai_' + (x.status || 'unknown')))); })),
      row(t('ai_where'), [ip.city, ip.region, res.country].filter(Boolean).join(', ')),
      row(t('ai_net'), ip.org || ip.isp),
      row(t('ai_kind'), kind ? kind[zh ? 0 : 1] : ''),
      ...AI_SITES.filter(([k]) => (res.sites[k] || {}).note && zh).map(([k, n]) => h('p', {class: 'muted', style: 'margin:4px 0 0;font-size:12px'}, n + '：' + res.sites[k].note)),
      ...(zh ? res.advice || [] : []).map(a => h('div', {class: 'fix', style: 'margin-top:8px;font-size:12.5px'}, a)),
      r.servers && r.servers.length ? h('div', {style: 'margin-top:12px'}, h('h4', {style: 'margin:0 0 6px'}, t('ai_others')),
        r.servers.map(x => h('div', {class: 'muted', style: 'font-size:12.5px'}, h('b', null, x.name), '  ', x.summary || '—'))) : null,
      h('p', {class: 'muted num', style: 'margin:10px 0 0;font-size:11.5px'}, t('ai_at') + ' ' + fmt.time(res.at))].filter(Boolean));
  };
  const get = async body => { try { draw(await api('aicheck', body)); } catch (e) { if (seq === S.viewSeq && box.isConnected) { box.className = ''; box.style.height = ''; box.replaceChildren(retryBox(e.message, () => get(body))); } } };
  btn.onclick = async () => { btn.disabled = true; box.className = 'skeleton'; box.style.height = '120px'; await get({}); btn.disabled = false; };
  get();
  return panel(t('ai'), t('ai_tip'), btn, box);
}
function securityPanel() {
  const seq = S.viewSeq, totpBox = h('div', {class: 'stack'}), histBox = h('div', {class: 'skeleton', style: 'height:120px'}), sessBox = h('div');
  const fill = async () => {
    let r;
    try { r = await api('security'); }
    catch (e) { if (seq === S.viewSeq && histBox.isConnected) { histBox.className = ''; histBox.style.height = ''; histBox.replaceChildren(retryBox(e.message, fill)); } return; }
    if (seq !== S.viewSeq || !histBox.isConnected) return;
    // two-step verification
    const on = r.totp;
    const enable = async btn => {
      btn.disabled = true;
      let g; try { g = await api('totp'); } catch (e) { btn.disabled = false; return err(e); }
      if (seq !== S.viewSeq || !totpBox.isConnected) return;
      const code = h('input', {type: 'text', inputmode: 'numeric', autocomplete: 'one-time-code', maxlength: '12', class: 'otp', placeholder: '000000'});
      const ok = h('button', {class: 'btn primary'}, icon('check'), t('totp_confirm'));
      ok.onclick = async () => { ok.disabled = true; try { await api('totp', {secret: g.secret, code: code.value.replace(/\s+/g, '')}); toast(t('totp_on')); await load(); fill(); } catch (e) { err(e); ok.disabled = false; code.select(); } };
      code.onkeydown = e => { if (e.key === 'Enter') ok.click(); };
      totpBox.replaceChildren(h('p', {class: 'muted', style: 'margin:0;font-size:12.5px;line-height:1.8'}, t('totp_scan')),
        h('div', {class: 'totp-setup'}, h('img', {class: 'qr', alt: 'QR', src: 'api/qr?text=' + encodeURIComponent(g.uri)}),
          h('div', {class: 'stack'}, h('div', {class: 'creds', style: 'letter-spacing:.12em'}, g.secret.replace(/(.{4})/g, '$1 ').trim()),
            field(t('totp_code'), code), h('div', {style: 'display:flex;gap:8px'}, ok, h('button', {class: 'btn ghost', onclick: fill}, t('cancel'))))));
      code.focus();
    };
    const tb = h('button', {class: 'btn' + (on ? '' : ' primary')}, icon('shield'), t(on ? 'totp_disable' : 'totp_enable'));
    tb.onclick = async () => {
      if (!on) return enable(tb);
      const pw = await modal({title: t('totp_disable'), text: t('totp_pw'), input: true, type: 'password', confirm: t('totp_disable'), danger: true});
      if (pw == null) return;
      tb.disabled = true;
      try { await api('totp', {off: true, password: pw}); toast(t('saved')); await load(); fill(); } catch (e) { err(e); tb.disabled = false; }
    };
    totpBox.replaceChildren(h('div', {class: 'sec-row'}, h('div', {class: 'sec-ic' + (on ? ' on' : '')}, icon('shield')),
      h('div', {style: 'flex:1;min-width:0'}, h('b', null, t('totp'), ' ', chip(on ? 'ok' : 'off', t(on ? 'totp_on' : 'totp_off'))), h('p', {class: 'muted'}, t('totp_tip'))), tb));
    // sessions
    const lo = h('button', {class: 'btn sm'}, icon('out'), t('logout_others'));
    lo.onclick = async () => { lo.disabled = true; try { await api('security', {logout_others: true}); toast(t('saved')); fill(); } catch (e) { err(e); lo.disabled = false; } };
    sessBox.replaceChildren(h('div', {class: 'sec-row'}, h('div', {class: 'sec-ic'}, icon('users')),
      h('div', {style: 'flex:1'}, h('b', null, t('sessions')), h('p', {class: 'muted'}, h('b', {class: 'num'}, r.sessions))), r.sessions > 1 ? lo : null));
    // sign-in history
    const ua = s => /iPhone|iPad/.test(s) ? 'iOS' : /Android/.test(s) ? 'Android' : /Mac OS/.test(s) ? 'macOS' : /Windows/.test(s) ? 'Windows' : /Linux/.test(s) ? 'Linux' : (s || '').slice(0, 24);
    const br = s => /Edg\//.test(s) ? 'Edge' : /Chrome\//.test(s) ? 'Chrome' : /Firefox\//.test(s) ? 'Firefox' : /Safari\//.test(s) ? 'Safari' : '';
    histBox.className = ''; histBox.style.height = '';
    histBox.replaceChildren(...[r.logins.length ? h('div', {class: 'tl'}, r.logins.slice(0, 12).map(x => h('div', {class: 'tl-row'},
      h('span', {class: 'num muted', style: 'min-width:92px;flex:none'}, fmt.time(x.at)), h('code', {class: 'code-chip'}, x.ip || '—'),
      h('span', {class: 'muted'}, [ua(x.ua), br(x.ua)].filter(Boolean).join(' · ')),
      h('span', {class: 'tl-acts'}, chip(x.ok ? 'ok' : 'bad', t(x.ok ? 'login_ok' : x.kind === 'fail2fa' ? 'login_fail2fa' : 'login_fail')))))) :
      h('div', {class: 'muted', style: 'font-size:12.5px'}, t('no_logins')),
      r.devices.length ? h('h4', {style: 'margin:16px 0 6px'}, t('dev_events')) : null,
      r.devices.length ? h('div', {class: 'tl'}, r.devices.slice(0, 8).map(e => h('div', {class: 'tl-row'}, h('span', {class: 'num muted', style: 'flex:none'}, fmt.time(e.at)), h('span', null, e.detail)))) : null].filter(Boolean));
  };
  fill();
  return h('div', {class: 'grid g-2'}, panel(t('sec'), null, null, h('div', {class: 'stack'}, totpBox, sessBox)), panel(t('logins'), null, null, histBox));
}

function drawSystem() {
  const d = S.data, tg = d.settings.tg_ready;
  const docBox = h('div', null, h('div', {class: 'empty-state'}, h('span', {class: 'es-ic'}, icon('pulse')), h('p', null, t('doctor_tip')))),
    docBtn = h('button', {class: 'btn primary'}, icon('pulse'), t('doctor_run'));
  docBtn.onclick = () => runDoctor(docBtn, docBox);
  const tgTok = h('input', {type: 'password', placeholder: '123456789:AA…', autocomplete: 'off'});
  // One code per visit: a refresh or a redraw must not change the command the owner already sent to the bot.
  const tgPairCode = S.tgPairCode || (S.tgPairCode = Array.from(crypto.getRandomValues(new Uint8Array(16)), b => b.toString(16).padStart(2, '0')).join(''));
  const tgPairCommand = '/bind ' + tgPairCode;
  const tgIntro = d.settings.tg_repair_needed ? t('tg_repair') : t('tg_tip');
  const tgCb = k => { const e = h('input', {type: 'checkbox', checked: !!d.settings[k]}); e.onchange = () => saveSettings({[k]: e.checked}); return check(t(k), e); };
  const tgOffBtn = h('button', {class: 'btn sm'}, t('tg_off'));
  tgOffBtn.onclick = async () => { tgOffBtn.disabled = true; try { await api('telegram', {off: true}); await load(); drawSystem(); } catch (e) { err(e); tgOffBtn.disabled = false; } };
  const tgConnBtn = h('button', {class: 'btn'}, t('tg_connect'));
  tgConnBtn.onclick = async () => {
    tgConnBtn.disabled = true;
    try { await api('telegram', {token: tgTok.value.trim(), challenge: tgPairCode}); S.tgPairCode = null; toast(t('tg_on')); await load(); drawSystem(); }
    catch (e) { toast(e.message === 'no_chat' ? t('tg_no_chat') : e.message === 'bad_token' ? t('tg_bad') : e.message, 'err'); tgConnBtn.disabled = false; }
  };
  const tgBody = tg ? h('div', {class: 'stack'}, h('div', null, chip('ok', t('tg_on'))), h('p', {class: 'muted', style: 'margin:0;font-size:12.5px;line-height:1.8'}, t('tg_cmds')),
      tgCb('tg_bot'), tgCb('tg_backup'), h('div', null, tgOffBtn))
    : h('div', {class: 'stack'}, h('p', {class: 'muted', style: 'margin:0;font-size:12.5px;line-height:1.8'}, tgIntro), field(t('tg_token'), tgTok),
      h('p', {class: 'muted', style: 'margin:0;font-size:12.5px;line-height:1.8'}, t('tg_pair')),
      h('code', {style: 'display:block;padding:12px;overflow-wrap:anywhere;user-select:all'}, tgPairCommand),
      h('div', null, tgConnBtn));
  const pw = {user: h('input', {type: 'text', value: d.settings.admin_user}), old: h('input', {type: 'password', autocomplete: 'current-password'}), nw: h('input', {type: 'password', autocomplete: 'new-password'})};
  const pwBtn = h('button', {class: 'btn'}, icon('lock'), t('save'));
  pwBtn.onclick = async () => {
    pwBtn.disabled = true;
    try { await api('password', {username: pw.user.value, old: pw.old.value, new: pw.nw.value}); toast(t('saved')); pw.old.value = pw.nw.value = ''; }
    catch (e) { err(e); } finally { pwBtn.disabled = false; }
  };
  const restore = h('input', {type: 'file', accept: '.json', hidden: true});
  restore.onchange = async () => {
    const f = restore.files[0]; if (!f) return;
    try {
      if (!await confirmBox(t('q_restore'), t('confirm_restore'), {danger: true, confirm: t('restore')})) return;
      await api('restore', JSON.parse(await f.text())); toast(t('restore_ok')); await renderShell();
    } catch (er) { err(er); }
    finally { restore.value = ''; }
  };
  const rulesBtn = h('button', {class: 'btn sm'}, icon('refresh'), t('rules_refresh'));
  rulesBtn.onclick = async () => { rulesBtn.disabled = true; try { await api('rules-refresh', {}); toast('…'); } catch (e) { err(e); } finally { rulesBtn.disabled = false; } };
  const restartBtn = h('button', {class: 'btn sm'}, icon('bolt'), t('restart'));
  restartBtn.onclick = async () => {
    if (!await confirmBox(t('q_restart'), t('restart_tip'), {confirm: t('restart_ok')})) return;
    restartBtn.disabled = true;
    try { await api('restart', {}); toast(t('saved')); } catch (e) { err(e); } finally { restartBtn.disabled = false; }
  };
  $('view').replaceChildren(h('section', {class: 'page'},
    h('div', {class: 'grid g-2-1'},
      panel(t('doctor'), null, docBtn, docBox),
      h('div', {class: 'stack'},
        panel(t('ports'), null, null, h('p', {class: 'muted', style: 'margin:0 0 10px;font-size:12.5px'}, t('ports_tip')),
          h('div', {class: 'port-list'}, d.ports.map(([p, n]) => chip('info plain', p.toUpperCase() + ' ' + n)))),
        panel(t('tg'), null, null, tgBody))),
    aiPanel(),
    securityPanel(),
    h('div', {class: 'grid g-2'},
      panel(t('change_pw'), null, null, h('div', {class: 'stack'}, field(t('username'), pw.user), field(t('old_pw'), pw.old), field(t('new_pw'), pw.nw),
        h('div', null, pwBtn))),
      panel(t('backup'), null, null, h('p', {class: 'muted', style: 'margin:0 0 12px;font-size:12.5px;line-height:1.8'}, t('backup_tip')),
        h('div', {class: 'act-grid'}, h('a', {class: 'btn', href: 'api/backup'}, icon('arrowDown'), t('download_backup')),
          h('label', {class: 'btn'}, icon('arrowUp'), t('restore'), restore)))),
    panel(t('logs'), [t('rules_age') + ' ' + (d.rules_age == null ? '—' : dur(d.rules_age) + (L === 'zh' ? '' : ' ') + t('ago')), t('version') + ' ' + d.version, d.os].filter(Boolean).join(' · '),
      h('div', {style: 'display:flex;flex-wrap:wrap;gap:8px'}, rulesBtn, restartBtn),   // the English labels need two rows on a phone
      h('div', {class: 'log'}, d.log.join('\n') || '—'))));
}

boot();
