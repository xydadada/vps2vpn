"""Background work inside the panel process: traffic accounting, limits, certificates, rule mirror,
service watchdog, IP-change follow-up, daily backups, server monthly traffic, site monitor, abuse guard,
multi-server sync and alerts."""
import ipaddress
import json
import os
import random
import threading
import time
import traceback

from . import abuse, aicheck, certs, cluster, cores, db, members, monitor, notify, paths, rules, system

LOG = []          # recent events shown in the panel
_report_lock = threading.Lock()


def log(msg):
    line = time.strftime('%m-%d %H:%M:%S ') + str(msg)
    LOG.append(line)
    del LOG[:-200]
    print(line, flush=True)


def over_limit(u, now=None, quota=None):
    """quota: effective GB (after what the user shares with people they invited); defaults to quota_gb."""
    now = time.time() if now is None else now
    quota = u['quota_gb'] if quota is None else quota
    if u['expire_at'] and now >= u['expire_at']:
        return 'expired'
    if u['quota_gb'] and u['used_up'] + u['used_down'] >= quota * (1 << 30):
        return 'quota'
    return ''


def monthly_reset(u, now=None):
    """Reset usage on the user's reset day, once per month."""
    t = time.localtime(time.time() if now is None else now)
    month = time.strftime('%Y-%m', t)
    return bool(u['reset_day']) and t.tm_mday >= u['reset_day'] and u['last_reset'] != month, month


def _quota_order(users):
    """Children before inviters, independent of restored IDs; iterate to avoid recursion depth limits."""
    children = {}
    for u in users:
        if u.get('invited_by'):
            children.setdefault(u['invited_by'], []).append(u)
    done, visiting, ordered = set(), set(), []
    for root in users:
        stack = [(root, False)]
        while stack:
            u, expanded = stack.pop()
            uid = u['id']
            if uid in done:
                continue
            if expanded:
                visiting.discard(uid)
                done.add(uid)
                ordered.append(u)
            elif uid not in visiting:
                visiting.add(uid)
                stack.append((u, True))
                stack.extend((child, False) for child in reversed(children.get(uid, [])))
            # An imported cycle has no topological order. Visit it once; the quota ledger
            # conservatively charges cyclic grants instead of recursing indefinitely.
    return ordered


def enforce(now=None):
    """Atomically reset/evaluate limits. Send alerts only after committing the decisions."""
    changed, messages, alerts = False, [], []
    t_now = time.time() if now is None else now
    month = time.strftime('%Y-%m', time.localtime(t_now))
    with db.transaction():
        users = db.users()
        for u in users:
            if u['remote_id']:
                continue                 # an account of a main server: it decides about limits
            if u['expire_after_days'] and not u['expire_at'] and u['used_up'] + u['used_down'] > 0:
                days = u['expire_after_days']
                u.update(expire_at=int(t_now + days * 86400), expire_after_days=0)
                db.update_user(u['id'], expire_at=u['expire_at'], expire_after_days=0)
                messages.append('%s used the account for the first time; expires in %d days' % (u['name'], days))
            if not u['enabled'] and u['disabled_reason'] == 'devices' and t_now >= u['paused_until']:
                db.update_user(u['id'], enabled=1, disabled_reason='', paused_until=0)
                u.update(enabled=1, disabled_reason='', paused_until=0)
                messages.append('device pause over: %s' % u['name'])
                changed = True
            due, reset_month = monthly_reset(u, t_now)
            if due:
                db.update_user(u['id'], used_up=0, used_down=0, last_reset=reset_month)
                u.update(used_up=0, used_down=0, last_reset=reset_month)
                messages.append('monthly reset: %s' % u['name'])
        # Every reset is visible before any parent is checked. Follow the actual inviter edges:
        # restored backups are not required to assign larger IDs to descendants.
        for u in _quota_order(users):
            if u['remote_id']:
                continue
            quota = members.effective_quota(u, users, t_now)
            reason = over_limit(u, t_now, quota)
            if u['quota_gb'] and u['enabled'] and not reason and \
                    u['used_up'] + u['used_down'] >= 0.8 * quota * (1 << 30):
                alerts.append(('%s has used 80%% of %g GB / %s 已用掉 80%% 流量' % (u['name'], quota, u['name']),
                               {'key': 'q80-%d-%s' % (u['id'], month), 'every': 40 * 86400}))
            if u['enabled'] and reason:
                db.update_user(u['id'], enabled=0, disabled_reason=reason)
                u.update(enabled=0, disabled_reason=reason)
                messages.append('disabled %s (%s)' % (u['name'], reason))
                alerts.append(('%s paused: %s / %s 已停用（%s）' % (u['name'], reason, u['name'],
                               '流量用完' if reason == 'quota' else '已到期'),
                               {'key': 'off-%d-%s' % (u['id'], reason), 'every': 86400}))
                changed = True
            elif not u['enabled'] and u['disabled_reason'] in ('quota', 'expired') and not reason:
                db.update_user(u['id'], enabled=1, disabled_reason='')
                u.update(enabled=1, disabled_reason='')
                messages.append('re-enabled %s' % u['name'])
                changed = True
    for message in messages:
        log(message)
    for text, kwargs in alerts:
        notify.send(text, **kwargs)
    return changed


def collect():
    s = db.settings()
    known = {u['id'] for u in db.users()}
    for uid, (up, down) in cores.collect_traffic(s).items():
        if uid in known and (up or down):
            db.add_traffic(uid, up, down)


def period_of(now, reset_day):
    """Billing period label (its first day, YYYY-MM-DD) for a reset on `reset_day` of each month."""
    t = time.localtime(now)
    y, m = t.tm_year, t.tm_mon
    if t.tm_mday < reset_day:
        y, m = (y - 1, 12) if m == 1 else (y, m - 1)
    return '%04d-%02d-%02d' % (y, m, reset_day)


def server_month(s, health=None, now=None):
    """Add the server's network traffic since the last look to this billing period. Returns the record."""
    now = now or time.time()
    h = health or system.health()
    if 'rx_total' not in h:
        return s['server_month']
    rec = dict(s['server_month'] or {})
    period = period_of(now, max(1, min(28, int(s['server_reset_day'] or 1))))
    if rec.get('period') != period:
        if rec.get('period'):
            log('server traffic %s: %.1f GB' % (rec['period'], (rec.get('rx', 0) + rec.get('tx', 0)) / (1 << 30)))
        rec = {'period': period, 'rx': 0, 'tx': 0, 'last_rx': rec.get('last_rx'), 'last_tx': rec.get('last_tx')}
    for k in ('rx', 'tx'):
        cur, last = h[k + '_total'], rec.get('last_' + k)
        if last is not None:
            rec[k] += cur - last if cur >= last else cur       # counters restart from zero after a reboot
        rec['last_' + k] = cur
    rec['at'] = int(now)
    db.set_settings(server_month=rec)
    cap = s['server_cap_gb'] * (1 << 30)
    if cap:
        used = rec['rx'] + rec['tx']
        for pct in (100, 80):
            if used >= cap * pct / 100:
                notify.send('server traffic %d%% of %g GB this month / 服务器本月流量已用 %d%%（%g GB 上限）' % (
                    pct, s['server_cap_gb'], pct, s['server_cap_gb']), key='cap%d-%s' % (pct, period), every=40 * 86400)
                break
    return rec



# --- VPS renewal date --------------------------------------------------------------------------
def renew_days_left(s, now=None):
    """Whole days until the VPS plan must be renewed (negative once past), or None when no date is set."""
    if not s.get('vps_renew_at'):
        return None
    try:
        due = time.mktime(time.strptime(s['vps_renew_at'], '%Y-%m-%d'))
    except ValueError:
        return None
    today = time.localtime(now or time.time())
    start = time.mktime((today.tm_year, today.tm_mon, today.tm_mday, 0, 0, 0, 0, 0, -1))
    return int(round((due - start) / 86400))


def renew_reminder(s, now=None):
    """Telegram reminder 7, 3 and 1 days before the renewal date, and on the day."""
    left = renew_days_left(s, now)
    if left is None or left > 7 or left < 0:
        return None
    step = 0 if left == 0 else 1 if left <= 1 else 3 if left <= 3 else 7
    where = (' (%s)' % s['vps_renew_note']) if s.get('vps_renew_note') else ''
    notify.send('VPS renewal due in %d day(s) on %s%s / 服务器 %d 天后到期（%s）%s，记得续费，过期会被删机' % (
        left, s['vps_renew_at'], where, left, s['vps_renew_at'], where),
        key='renew%d-%s' % (step, s['vps_renew_at']), every=40 * 86400)
    return step


# --- lines the apps cannot reach ---------------------------------------------------------------
LINES = {'reality': ('reality_port', 'tcp', 'VLESS + REALITY'),
         'hy2': ('hy2_port', 'udp', 'Hysteria 2'),
         'tuic': ('tuic_port', 'udp', 'TUIC v5')}
REPORT_TTL = 24 * 3600


def report_line(uid, line, ok, host='', now=None):
    """An app says it could (not) connect over one line. One entry per account and line, so one person cannot
    make it look like many; a later success from the same account clears it."""
    if line not in LINES:
        raise ValueError('unknown line')
    now = int(now or time.time())
    with _report_lock:
        reps = {k: dict(v) for k, v in (db.settings()['line_reports'] or {}).items()}
        mine = reps.setdefault(line, {})
        if ok:
            mine.pop(str(uid), None)
        else:
            first = str(uid) not in mine
            mine[str(uid)] = [now, str(host)[:64]]
        db.set_settings(line_reports=_prune(reps, now))
    if not ok and first:
        n = len(line_trouble(db.settings(), now).get(line, {}).get('users', []))
        if n >= 2:
            notify.send('%d accounts cannot connect over %s / %d 个使用者报告 %s 连不上，可在面板一键换端口' % (
                n, LINES[line][2], n, LINES[line][2]), key='line-' + line, every=6 * 3600)


def _prune(reps, now):
    return {k: {u: v for u, v in m.items() if now - v[0] < REPORT_TTL} for k, m in reps.items()
            if any(now - v[0] < REPORT_TTL for v in m.values())}


def line_trouble(s, now=None):
    """{'hy2': {'users': [ids], 'hosts': [...], 'last': time}} for lines reported down in the last 24 hours."""
    now = now or time.time()
    out = {}
    for line, m in _prune(s['line_reports'] or {}, now).items():
        out[line] = {'users': sorted(int(u) for u in m), 'hosts': sorted({v[1] for v in m.values() if v[1]}),
                     'last': max(v[0] for v in m.values())}
    return out


def change_port(line):
    """Move one line to a fresh random port (as when a port gets blocked) and open it in the firewall.
    Returns the new port; the apps pick it up at their next subscription update."""
    if line not in LINES:
        raise ValueError('unknown line')
    key, proto, name = LINES[line]
    s = db.settings()
    taken = {s['panel_port'], s['reality_port'] if proto == 'tcp' else 0,
             s['hy2_port'] if proto == 'udp' else 0, s['tuic_port'] if proto == 'udp' else 0, 80, 443}
    lo, hi = system.parse_range(s['hy2_hop_range']) if proto == 'udp' and s['hy2_hop'] else (0, -1)
    for _ in range(200):
        p = random.randint(10000, 60000)
        if p in taken or lo <= p <= hi or not system.port_free(proto, p):
            continue
        db.set_settings(**{key: p})
        with _report_lock:
            reps = dict(db.settings()['line_reports'] or {})
            reps.pop(line, None)
            db.set_settings(line_reports=reps)
        system.open_firewall(db.settings())
        log('%s moved from port %s to %d' % (name, s[key], p))
        return p
    raise RuntimeError('no free port found')


def backup(keep=14):
    """One JSON file per day in /var/lib/vps2vpn/backups, newest `keep` kept."""
    os.makedirs(paths.BACKUPS, exist_ok=True)
    name = os.path.join(paths.BACKUPS, 'vps2vpn-%s.json' % time.strftime('%Y%m%d'))
    paths.write_atomic(name, json.dumps(db.export_all(), ensure_ascii=False), 0o600)
    files = sorted(f for f in os.listdir(paths.BACKUPS) if f.startswith('vps2vpn-') and f.endswith('.json'))
    for f in files[:-keep]:
        os.unlink(os.path.join(paths.BACKUPS, f))
    return name


def watchdog(s):
    """Restart a proxy core that died and tell the owner (systemd also restarts, this catches the rest)."""
    for unit, on in ((cores.XRAY_UNIT, s['reality_enabled']), (cores.HY2_UNIT, s['hy2_enabled']),
                     (cores.TUIC_UNIT, s['tuic_enabled'])):
        if on and system.unit_active(unit) is False:
            log('%s is down, restarting' % unit)
            system.systemctl('restart', unit)
            time.sleep(2)
            ok = system.unit_active(unit)
            notify.send('%s was down; restart %s / %s 挂了，已%s' % (unit, 'worked' if ok else 'FAILED', unit,
                                                                 '自动重启' if ok else '重启失败，请登录面板体检'),
                        key='down-' + unit, every=3600)


DEVICE_PAUSE = 600


def device_limits(s, online=None, now=None):
    """Users over their device limit: a 10-minute pause (or only a warning). Returns True if cores need configs."""
    online = cores.online_detail(s) if online is None else online
    if not online:
        return False
    now = now or time.time()
    changed = False
    for u in db.users():
        d = online.get(u['id'])
        if not d or not u['max_ips'] or u['remote_id'] or not u['enabled']:
            continue
        n = d.get('devices', len(d.get('ips', [])))
        if n <= u['max_ips']:
            continue
        db.add_event('devices', u['id'], '%s: %d devices online, limit %d (%s)' % (
            u['name'], n, u['max_ips'], ', '.join(d.get('ips', [])[:8])))
        if s['ip_limit_pause']:
            db.update_user(u['id'], enabled=0, disabled_reason='devices', paused_until=int(now + DEVICE_PAUSE))
            log('paused %s for 10 minutes: %d devices, limit %d' % (u['name'], n, u['max_ips']))
            changed = True
        notify.send('%s: %d devices online (limit %d)%s / %s 同时在线 %d 台设备（上限 %d）%s' % (
            u['name'], n, u['max_ips'], ', paused 10 min' if s['ip_limit_pause'] else '',
            u['name'], n, u['max_ips'], '，暂停 10 分钟' if s['ip_limit_pause'] else ''),
            key='dev-%d' % u['id'], every=3600)
    return changed


class History:
    """Server CPU, memory and network, one point a minute for 24 hours (kept across restarts)."""

    KEEP = 1440

    def __init__(self, path=None):
        self.path = path or os.path.join(paths.VAR, 'history.json')
        self.points, self.cpu_last, self.saved = [], None, 0
        try:
            with open(self.path) as f:
                self.points = [p for p in json.load(f) if isinstance(p, list) and len(p) == 5][-self.KEEP:]
        except (OSError, ValueError):
            pass

    @staticmethod
    def _cpu_times():
        with open('/proc/stat') as f:
            v = [int(x) for x in f.readline().split()[1:]]
        idle = v[3] + (v[4] if len(v) > 4 else 0)
        return sum(v), idle

    def sample(self, health=None, now=None):
        now = int(now or time.time())
        h = health or system.health()
        cpu = None
        try:
            total, idle = self._cpu_times()
            if self.cpu_last and total > self.cpu_last[0]:
                cpu = round(100 * (1 - (idle - self.cpu_last[1]) / (total - self.cpu_last[0])), 1)
            self.cpu_last = (total, idle)
        except (OSError, ValueError, IndexError):
            pass
        mem = round(h['mem_used'] * 100 / h['mem_total'], 1) if h.get('mem_total') else None
        self.points.append([now, cpu, mem, h.get('rx_rate'), h.get('tx_rate')])
        del self.points[:-self.KEEP]
        if now - self.saved >= 600:
            self.save()
            self.saved = now

    def save(self):
        try:
            paths.write_atomic(self.path, json.dumps(self.points), 0o600)
        except OSError:
            pass


HISTORY = History.__new__(History)      # replaced with a loaded one when the scheduler starts
HISTORY.points = []


def tg_status(s):
    zh = s['language'] != 'en'
    h = system.health()
    on = cores.online_detail(s) or {}
    users = db.users()
    svc = []
    for name, unit, enabled in (('REALITY', cores.XRAY_UNIT, s['reality_enabled']), ('Hysteria 2', cores.HY2_UNIT, s['hy2_enabled']),
                                ('TUIC', cores.TUIC_UNIT, s['tuic_enabled'])):
        if enabled:
            svc.append('%s %s' % ('✅' if system.unit_active(unit) else '❌', name))
    sm = s['server_month'] or {}
    used = (sm.get('rx', 0) + sm.get('tx', 0)) / (1 << 30)
    lines = [
        ' · '.join(svc),
        ('在线 %d 人 / 共 %d 个使用者（停用 %d）' if zh else 'Online %d / %d users (%d paused)') % (
            len(on), len(users), sum(1 for u in users if not u['enabled'])),
        ('内存 %d%% · 负载 %.2f · 已运行 %d 天' if zh else 'Memory %d%% · load %.2f · up %d days') % (
            h['mem_used'] * 100 / h['mem_total'] if h.get('mem_total') else 0, h.get('load') or 0, (h.get('uptime') or 0) // 86400),
        ('本月服务器流量 %.1f GB%s' if zh else 'Server traffic this month %.1f GB%s') % (
            used, (' / %g GB' % s['server_cap_gb']) if s['server_cap_gb'] else ''),
    ]
    return '\n'.join(lines)


def tg_users(s, name=''):
    zh = s['language'] != 'en'
    users = db.users()
    on = cores.online_detail(s) or {}
    if name:
        u = next((x for x in users if x['name'].lower() == name.lower()), None)
        if not u:
            return '没有这个使用者' if zh else 'No such user'
        users = [u]
    users.sort(key=lambda u: -(u['used_up'] + u['used_down']))
    out = []
    for u in users[:25]:
        used = (u['used_up'] + u['used_down']) / (1 << 30)
        state = '🟢' if u['id'] in on else ('⚪' if u['enabled'] else '⛔')
        quota = ('%g GB' % u['quota_gb']) if u['quota_gb'] else ('不限' if zh else 'unlimited')
        exp = time.strftime('%Y-%m-%d', time.localtime(u['expire_at'])) if u['expire_at'] else ('永久' if zh else 'never')
        out.append('%s %s  %.2f GB / %s  %s %s' % (state, u['name'], used, quota, '到期' if zh else 'until', exp))
    return '\n'.join(out) or ('还没有使用者' if zh else 'No users yet')


def tg_command(text):
    s = db.settings()
    zh = s['language'] != 'en'
    cmd, _, arg = text.partition(' ')
    cmd = cmd.split('@')[0].lower()
    if cmd == '/status':
        return tg_status(s)
    if cmd == '/users':
        return tg_users(s)
    if cmd == '/user':
        return tg_users(s, arg.strip()) if arg.strip() else ('用法：/user 名字' if zh else 'Usage: /user NAME')
    if cmd == '/backup':
        data = json.dumps(db.export_all(), ensure_ascii=False).encode()
        return ('file', 'vps2vpn-%s.json' % time.strftime('%Y%m%d-%H%M'), data,
                '备份（含密钥，请妥善保存）' if zh else 'Backup (contains keys, keep it private)')
    if cmd == '/doctor':
        from . import doctor
        bad = [r for r in doctor.run_all() if r.get('ok') is False]
        if not bad:
            return '✅ 体检全部正常' if zh else '✅ Health check: all good'
        return '\n'.join('❌ %s: %s' % (r['id'], r.get('fix') or r.get('detail', '')) for r in bad)
    if cmd == '/ai':
        return ai_text(aicheck.run())
    return ('可用命令：\n/status 服务器状态\n/users 使用者用量\n/user 名字 某个人的详情\n/doctor 一键体检\n/ai AI 可用性检测\n/backup 发送备份' if zh else
            'Commands:\n/status server status\n/users usage per user\n/user NAME one user\n/doctor health check\n/ai AI availability\n/backup send a backup')


def ai_text(res):
    ip = res.get('ip') or {}
    where = ' '.join(x for x in (res.get('country', ''), ip.get('city', ''), ip.get('org', '')) if x)
    lines = ['AI 可用性：' + aicheck.summary(res), '位置：' + where]
    if ip.get('kind'):
        lines.append('类型：' + aicheck.KIND_TEXT.get(ip['kind'], ip['kind']))
    for k in aicheck.SITES:
        if res['sites'][k].get('note'):
            lines.append('%s：%s' % (aicheck.LABEL[k], res['sites'][k]['note']))
    return '\n'.join(lines + res.get('advice', []))


def ai_recheck(s, log=print):
    """Daily AI check; a change (e.g. Claude stops working here) is sent to Telegram."""
    old = aicheck.latest()
    new = aicheck.run()
    diff = aicheck.changed(old, new)
    if diff:
        log('AI availability changed: ' + '; '.join(diff))
        notify.send('AI 可用性有变化 / AI availability changed\n' + '\n'.join(diff) + '\n' + aicheck.summary(new),
                    key='aicheck', every=3600, s=s)
    return new


LOCAL_NETS = [ipaddress.ip_network(n) for n in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '100.64.0.0/10',
                                                 '127.0.0.0/8', '169.254.0.0/16', '::1/128', 'fc00::/7', 'fe80::/10')]


def _local(host):
    ip = ipaddress.ip_address(host)
    return any(ip.version == n.version and ip in n for n in LOCAL_NETS)


class IpWatch:
    """Cloud servers sometimes get a new public IP (stop/start, plan change). Follow it automatically."""

    CONFIRM_AFTER = 600

    def __init__(self):
        self.seen, self.seen_at = None, 0

    def check(self, s):
        if self.seen and time.time() - self.seen_at < self.CONFIRM_AFTER:
            return None                   # wait before looking again, so a brief glitch is not acted on
        host = s['public_host']
        if not certs.is_ip(host) or s['domain'] or _local(host):
            return None                   # a domain, or an internal address the owner set on purpose
        now = system.public_ip(v6=':' in host)
        if not now or now == host:
            self.seen = None
            return None
        if self.seen != now:              # must be seen twice, 10 minutes apart, before we act
            self.seen, self.seen_at = now, time.time()
            return None
        db.set_settings(public_host=now)
        certs.ensure_self_signed(now)
        cores.apply(force=True)
        log('public IP changed %s -> %s; subscriptions now use the new address' % (host, now))
        notify.send('IP changed %s -> %s. Apps pick it up on their next subscription update. / 服务器 IP 变了，'
                    '订阅已自动改成新地址。' % (host, now), key='ip-' + now, every=86400)
        self.seen = None
        return now


class Scheduler:
    def __init__(self):
        self.last = {}
        self.cert_backoff_until = 0
        self.stop = threading.Event()
        self.ipwatch = IpWatch()

    def due(self, name, every):
        if time.time() - self.last.get(name, 0) >= every:
            self.last[name] = time.time()
            return True
        return False

    def tick(self):
        s = db.settings()
        if not s['setup_done']:
            return
        if self.due('traffic', 60):
            collect()
            changed = enforce()
            if paths.LIVE and device_limits(s):
                changed = True
            if changed:
                cores.apply()
                cluster.sync_soon()
            health = system.health()
            server_month(s, health)
            HISTORY.sample(health)
        if s['abuse_guard'] and self.due('abuse', 60) and paths.LIVE:
            abuse.check(s, log)
        if s['monitor_enabled'] and paths.LIVE and self.due('monitor', 300):
            monitor.run_in_background(log)
        if paths.LIVE and self.due('cert', 3600) and time.time() >= self.cert_backoff_until:
            before = certs.current(s['public_host'])
            res = certs.renew_if_needed(s, log=log)
            if res and res != 'ok':
                self.cert_backoff_until = time.time() + 6 * 3600    # stay well under Let's Encrypt's failure limits
                db.set_settings(cert_status='failed: ' + res[:200])
                if certs.trusted(s['public_host']) and not certs.acme_valid(36):
                    notify.send('certificate renewal failing: %s / 证书续期失败' % res[:200], key='cert', every=12 * 3600)
            elif res == 'ok':
                db.set_settings(cert_status='ok')
            if certs.current(s['public_host']) != before:
                cores.apply()
            elif res == 'ok':
                # Same file, new certificate: the QUIC servers hold the old one in memory until restarted.
                # (IP certificates are renewed every few days, so without this they would expire in use.)
                for unit, on in ((cores.HY2_UNIT, s['hy2_enabled']), (cores.TUIC_UNIT, s['tuic_enabled'])):
                    if on:
                        system.systemctl('restart', unit)
                log('certificate renewed, QUIC servers reloaded')
        if self.due('rules', 86400) or (rules.mirror_age() is None and self.due('rules-missing', 600)):
            rules.refresh_in_background(log)
        if self.due('renew', 3600):
            renew_reminder(s)
        if self.due('watchdog', 300) and paths.LIVE:
            watchdog(s)
        if self.due('ip', 6 * 3600) or self.ipwatch.seen:
            self.ipwatch.check(s)
        if paths.LIVE and self.due('aicheck', 86400):
            threading.Thread(target=ai_recheck, args=(s, log), daemon=True, name='aicheck').start()
        if self.due('backup', 86400):
            name = backup()
            if s['tg_backup'] and s['tg_token'] and s['tg_chat']:
                with open(name, 'rb') as f:
                    notify.send_file(os.path.basename(name), f.read(),
                                     'daily backup / 每日备份（含密钥，请妥善保存）', s=s)

    def run(self):
        while not self.stop.wait(10):
            try:
                self.tick()
            except Exception:        # keep the loop alive no matter what
                log('job error: ' + traceback.format_exc(limit=3))

    def tuic_sampler(self):
        """TUIC per-user accounting needs frequent looks at open connections (see cores.TuicMeter)."""
        while not self.stop.wait(2):
            try:
                s = db.settings()
                if s['setup_done'] and s['tuic_enabled']:
                    cores._tuic.sample(s, users={u['id'] for u in cores.active_users()})
            except Exception:
                pass

    def start(self):
        global HISTORY
        HISTORY = History()
        threading.Thread(target=notify.bot_loop, args=(self.stop, tg_command, log), daemon=True, name='tg-bot').start()
        threading.Thread(target=self.run, daemon=True, name='jobs').start()
        threading.Thread(target=self.tuic_sampler, daemon=True, name='tuic-meter').start()
        threading.Thread(target=cluster.loop, args=(self.stop, log), daemon=True, name='servers').start()
