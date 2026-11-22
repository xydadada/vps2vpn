"""Background work inside the panel process: traffic accounting, limits, certificates, rule mirror,
service watchdog, IP-change follow-up, daily backups, server monthly traffic, site monitor, abuse guard,
multi-server sync and alerts."""
import ipaddress
import json
import math
import os
import random
import shutil
import threading
import time
import traceback

from . import abuse, aicheck, certs, clientsync, cluster, cores, db, members, monitor, notify, paths, rules, system

LOG = []          # recent events shown in the panel
_log_lock = threading.Lock()
_report_lock = threading.Lock()
_enforce_lock = threading.Lock()
_port_lock = threading.Lock()


def log(msg):
    line = time.strftime('%m-%d %H:%M:%S ') + str(msg)
    with _log_lock:
        LOG.append(line)
        del LOG[:-200]
    print(line, flush=True)


def recent_logs(n=60):
    with _log_lock:
        return list(LOG[-n:]) if n else []


def over_limit(u, now=None, quota=None):
    """quota: effective GB (after what the user shares with people they invited); defaults to quota_gb."""
    now = now or time.time()
    quota = u['quota_gb'] if quota is None else quota
    if u['expire_at'] and now >= u['expire_at']:
        return 'expired'
    if u['quota_gb'] and u['used_up'] + u['used_down'] >= quota * (1 << 30):
        return 'quota'
    return ''


def monthly_reset(u, now=None):
    """Reset usage on the user's reset day, once per month."""
    t = time.localtime(now or time.time())
    month = time.strftime('%Y-%m', t)
    return bool(u['reset_day']) and t.tm_mday >= u['reset_day'] and u['last_reset'] != month, month


def quota_alert_key(u, quota, now):
    """One 80% warning per billing period and quota. The period follows the account's own reset day (an
    account without one has a single period), so a reset on the 15th re-arms it and the 1st of a month does
    not; raising the quota re-arms it too. A manual traffic reset forgets it (see forget_quota_alerts)."""
    period = period_of(now, u['reset_day']) if u['reset_day'] else 'total'
    return 'q80-%d-%s-%g' % (u['id'], period, quota)


def forget_quota_alerts(uid):
    """After a manual traffic reset the account may warn and pause again in the same period."""
    notify.forget('q80-%d-' % uid)
    notify.forget('off-%d-quota' % uid)


def enforce(now=None):
    """Turn users off/on according to quota, expiry and reset day. Returns True if cores need new configs."""
    with _enforce_lock:
        changed = False
        users = db.users()
        by_id = {u['id']: u for u in users}
        invitees = members.invitee_index(users)       # once: per-user rebuilding was O(n^2)
        t_now = now or time.time()
        for _pass in range(2):
            pass_changed = False
            for u in users:
                if u['remote_id']:
                    # an account of a main server: it decides about limits. Only expiry is applied here as well,
                    # so an expired account stops even while the main server is unreachable.
                    if u['enabled'] and u['expire_at'] and t_now >= u['expire_at']:
                        db.update_user(u['id'], enabled=0, disabled_reason='expired')
                        u.update(enabled=0, disabled_reason='expired')
                        log('disabled %s (expired; main server account)' % u['name'])
                        pass_changed = True
                    continue
                if u['expire_after_days'] and not u['expire_at'] and u['used_up'] + u['used_down'] > 0:
                    # "N days from first use": the clock starts with the first traffic
                    days = u['expire_after_days']
                    u['expire_at'] = int(t_now + days * 86400)
                    u['expire_after_days'] = 0
                    db.update_user(u['id'], expire_at=u['expire_at'], expire_after_days=0)
                    for cid in members.propagate_lifetime(u['id'], u['expire_at']):
                        if cid in by_id:
                            by_id[cid]['expire_at'] = u['expire_at']
                            by_id[cid]['expire_after_days'] = 0
                    log('%s used the account for the first time; expires in %d days' % (u['name'], days))
                device_due = not u['enabled'] and u['disabled_reason'] == 'devices' and t_now >= u['paused_until']
                due, month = monthly_reset(u, now)
                if due:
                    db.update_user(u['id'], used_up=0, used_down=0, last_reset=month)
                    u.update(used_up=0, used_down=0, last_reset=month)
                    log('monthly reset: %s' % u['name'])
                quota = members.effective_quota(u, now=now, index=invitees)
                reason = over_limit(u, now, quota)
                if device_due:
                    if reason:
                        db.update_user(u['id'], enabled=0, disabled_reason=reason, paused_until=0)
                        u.update(enabled=0, disabled_reason=reason, paused_until=0)
                        log('device pause over: %s (now disabled: %s)' % (u['name'], reason))
                    else:
                        db.update_user(u['id'], enabled=1, disabled_reason='', paused_until=0)
                        u.update(enabled=1, disabled_reason='', paused_until=0)
                        log('device pause over: %s' % u['name'])
                        pass_changed = True
                    continue
                if u['quota_gb'] and u['enabled'] and not reason and \
                        u['used_up'] + u['used_down'] >= 0.8 * quota * (1 << 30):
                    notify.send('%s has used 80%% of %g GB / %s 已用掉 80%% 流量' % (u['name'], quota, u['name']),
                                key=quota_alert_key(u, quota, t_now), every=40 * 86400)
                if u['enabled'] and reason:
                    db.update_user(u['id'], enabled=0, disabled_reason=reason)
                    u.update(enabled=0, disabled_reason=reason)
                    log('disabled %s (%s)' % (u['name'], reason))
                    notify.send('%s paused: %s / %s 已停用（%s）' % (u['name'], reason, u['name'],
                                                                 '流量用完' if reason == 'quota' else '已到期'),
                                key='off-%d-%s' % (u['id'], reason), every=86400)
                    pass_changed = True
                elif not u['enabled'] and u['disabled_reason'] in ('quota', 'expired') and not reason:
                    db.update_user(u['id'], enabled=1, disabled_reason='')
                    u.update(enabled=1, disabled_reason='')
                    log('re-enabled %s' % u['name'])
                    pass_changed = True
            if pass_changed:
                changed = True
            else:
                break
        return changed


COLLECT_EVERY = 20     # seconds between traffic readings (cores.apply also reads right before a restart)


def client_sync(s):
    """The newest signed client release from GitHub into the members' download folder."""
    try:
        clientsync.sync(s, log=log)
    except Exception as e:           # GitHub unreachable, disk full: try again at the next round
        log('client update from GitHub failed: %s' % e)


def collect():
    cores.save_traffic(db.settings())


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
        rec = {'period': period, 'rx': 0, 'tx': 0, 'last_rx': rec.get('last_rx'), 'last_tx': rec.get('last_tx'),
               'last_if': rec.get('last_if')}
    ifaces = h.get('net_ifaces')
    if isinstance(ifaces, dict):
        # Per interface: one that goes away (a VPN or container link) must not make the sum drop and look like
        # a reboot, which would count everything since boot a second time.
        last_if = rec.get('last_if') if isinstance(rec.get('last_if'), dict) else None
        if last_if is not None:
            for name, (rx, tx) in ifaces.items():
                prev = last_if.get(name)
                if not prev:
                    rec['rx'] += rx                              # a new interface: what it carried so far
                    rec['tx'] += tx
                    continue
                for i, k in ((0, 'rx'), (1, 'tx')):
                    cur, last = (rx, tx)[i], prev[i]
                    rec[k] += cur - last if cur >= last else cur  # counters restart from zero after a reboot
        elif rec.get('last_rx') is not None and rec.get('last_tx') is not None:
            # first look since the per-interface record: continue from the old totals
            rec['rx'] += max(0, h['rx_total'] - rec['last_rx'])
            rec['tx'] += max(0, h['tx_total'] - rec['last_tx'])
        rec['last_if'] = {name: [int(rx), int(tx)] for name, (rx, tx) in ifaces.items()}
        rec['last_rx'], rec['last_tx'] = h['rx_total'], h['tx_total']
    else:
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


# --- accounts about to expire ---------------------------------------------------------------------
ACCOUNT_REMIND_DAYS = (3, 1)        # Telegram heads-up to the owner this many days before an account ends


def _days_until(ts, now):
    """Whole calendar days from today to the day of `ts` (local time): 0 = today, 1 = tomorrow."""
    a, b = time.localtime(now), time.localtime(ts)
    start = time.mktime((a.tm_year, a.tm_mon, a.tm_mday, 0, 0, 0, 0, 0, -1))
    end = time.mktime((b.tm_year, b.tm_mon, b.tm_mday, 0, 0, 0, 0, 0, -1))
    return int(round((end - start) / 86400))


def expiry_reminders(now=None):
    """Tell the owner (Telegram) about working accounts that end within 3 days, and again the day before.

    Accounts of a main server are left to it, paused ones were already reported, and "N days from first
    use" accounts have no date yet. The key names the expiry date, so an account that is extended and
    later runs out again is reminded again. Returns [(user name, step)] for the reminders due."""
    now = now or time.time()
    out = []
    for u in db.users():
        exp = u['expire_at']
        if u['remote_id'] or not u['enabled'] or not exp or exp <= now:
            continue
        left = _days_until(exp, now)
        step = next((d for d in sorted(ACCOUNT_REMIND_DAYS) if left <= d), None)
        if step is None:
            continue
        date = time.strftime('%Y-%m-%d %H:%M', time.localtime(exp))
        when = 'today' if left <= 0 else 'tomorrow' if left == 1 else 'in %d days' % left
        when_zh = '今天' if left <= 0 else '明天' if left == 1 else '%d 天后' % left
        notify.send('%s expires %s (%s) / %s %s到期（%s），需要续期请在面板里延长' % (
            u['name'], when, date, u['name'], when_zh, date), key='uexp%d-%d-%d' % (step, u['id'], exp), every=40 * 86400)
        out.append((u['name'], step))
    return out


def tg_expiring(s, now=None, days=7):
    """/expiring: working accounts that end within `days` days or have used 80% of their quota."""
    zh = s['language'] != 'en'
    now = now or time.time()
    users = db.users()
    invitees = members.invitee_index(users)
    soon, low = [], []
    for u in users:
        if u['remote_id'] or not u['enabled']:
            continue
        if u['expire_at'] and now < u['expire_at'] <= now + days * 86400:
            soon.append(u)
        quota = members.effective_quota(u, now=now, index=invitees)
        if u['quota_gb'] and u['used_up'] + u['used_down'] >= 0.8 * quota * (1 << 30):
            low.append((u, quota))
    lines = []
    if soon:
        lines.append(('%d 天内到期：' if zh else 'Ending within %d days:') % days)
        for u in sorted(soon, key=lambda u: u['expire_at']):
            lines.append('⏳ %s  %s' % (u['name'], time.strftime('%Y-%m-%d %H:%M', time.localtime(u['expire_at']))))
    if low:
        lines.append('流量快用完（≥80%）：' if zh else 'Almost out of data (80% or more):')
        for u, quota in sorted(low, key=lambda x: -(x[0]['used_up'] + x[0]['used_down']) / max(x[1], 1e-9)):
            used = (u['used_up'] + u['used_down']) / (1 << 30)
            lines.append('📉 %s  %.2f / %g GB' % (u['name'], used, quota))
    if not lines:
        return ('%d 天内没有要到期或快用完流量的账号' if zh else 'Nothing ends or runs out within %d days') % days
    return '\n'.join(lines)


# --- lines the apps cannot reach ---------------------------------------------------------------
LINES = {'reality': ('reality_port', 'tcp', 'VLESS + REALITY'),
         'hy2': ('hy2_port', 'udp', 'Hysteria 2'),
         'tuic': ('tuic_port', 'udp', 'TUIC v5')}
REPORT_TTL = 24 * 3600
MAX_REPORTED_HOSTS = 64


def _norm_host(host):
    if host is None:
        return ''
    h = str(host).strip().lower()
    if h.startswith('[') and h.endswith(']'):
        h = h[1:-1]
    h = h.rstrip('.')
    if h:
        try:
            h = str(ipaddress.ip_address(h))
        except ValueError:
            pass
    return h


def _local_hosts(s):
    return {_norm_host(h) for h in (s.get('public_host'), s.get('domain'), s.get('public_ipv6')) if h} - {''}


def report_line(uid, line, ok, host='', now=None):
    """Keep endpoint state separate; alert counts distinct accounts per (line, host)."""
    if line not in LINES:
        raise ValueError('unknown line')
    now = int(now or time.time())
    if host is not None and len(str(host)) > 512:
        raise ValueError('host too long')
    host = _norm_host(host)
    if len(host) > 253:
        raise ValueError('host too long')
    if any(ord(c) < 33 or ord(c) == 127 for c in host):
        # A member sends it, and it is quoted in the admin's alert: no line breaks or spaces to fake text with.
        raise ValueError('host must be a host name or address')
    owner = str(uid)
    first = False
    with _report_lock:
        reps = _prune(db.settings()['line_reports'] or {}, now)
        raw = reps.get(line) or {}
        mine = {}
        for k, v in raw.items():
            if not isinstance(v, (list, tuple)) or len(v) < 2:
                continue
            vh = _norm_host(v[1])
            if '@' in k:
                u_part, h_part = k.split('@', 1)
                nk = '%s@%s' % (u_part, _norm_host(h_part))
            else:
                nk = '%s@%s' % (k, vh)
            nv = [v[0], vh]
            if nk not in mine or nv[0] > mine[nk][0]:
                mine[nk] = nv
        reps[line] = mine
        key = '%s@%s' % (owner, host)
        owned = [k for k in mine if k.split('@', 1)[0] == owner]
        if ok:
            if not host and key not in mine:
                if len(owned) > 1:
                    raise ValueError('host required for multiple reported servers')
                if owned:
                    key = owned[0]
            mine.pop(key, None)
        else:
            first = key not in mine
            if first and len(owned) >= MAX_REPORTED_HOSTS:
                raise ValueError('too many reported hosts')
            mine[key] = [now, host]
        db.set_settings(line_reports=_prune(reps, now))
    if not ok and first:
        s_now = db.settings()
        cur = _prune(s_now['line_reports'] or {}, now).get(line) or {}
        n = len({k.split('@', 1)[0] for k, v in cur.items() if _norm_host(v[1]) == host})
        if n >= 2:
            is_local = (not host) or (host in _local_hosts(s_now))
            where = (' (%s)' % host) if host else ''
            hint = '，可在面板一键换端口' if is_local else ''
            notify.send('%d accounts cannot connect over %s%s / %d 个使用者报告 %s%s 连不上%s' % (
                n, LINES[line][2], where, n, LINES[line][2], where, hint), key='line-' + line, every=6 * 3600)


def _prune(reps, now):
    return {k: {u: v for u, v in m.items() if now - v[0] < REPORT_TTL} for k, m in reps.items()
            if any(now - v[0] < REPORT_TTL for v in m.values())}


def line_trouble(s, now=None):
    """{'hy2': {'users': [ids], 'hosts': [...], 'last': time}} for lines reported down in the last 24 hours."""
    now = now or time.time()
    out = {}
    for line, m in _prune(s['line_reports'] or {}, now).items():
        hosts = {_norm_host(v[1]) for v in m.values()} - {''}
        out[line] = {'users': sorted({int(u.split('@', 1)[0]) for u in m}),
                     'hosts': sorted(hosts),
                     'last': max(v[0] for v in m.values())}
    return out


def change_port(line):
    """Move one line to a fresh random port (as when a port gets blocked) and open it in the firewall.
    Returns the new port; the apps pick it up at their next subscription update."""
    if line not in LINES:
        raise ValueError('unknown line')
    key, proto, name = LINES[line]
    with _port_lock:
        s = db.settings()
        taken = {s['panel_port'], s['reality_port'] if proto == 'tcp' else 0,
                 s['hy2_port'] if proto == 'udp' else 0, s['tuic_port'] if proto == 'udp' else 0,
                 s.get('traffic_api_port', 10085), s.get('hy2_stats_port', 10086), s.get('tuic_api_port', 10087),
                 80, 443}
        lo, hi = system.parse_range(s['hy2_hop_range']) if proto == 'udp' and s['hy2_hop'] else (0, -1)
        for _ in range(200):
            p = random.randint(10000, 60000)
            if p in taken or lo <= p <= hi or not system.port_free(proto, p):
                continue
            db.set_settings(**{key: p})
            with _report_lock:
                cur_s = db.settings()
                local_h = _local_hosts(cur_s)
                reps = dict(cur_s['line_reports'] or {})
                if line in reps and isinstance(reps[line], dict):
                    kept = {k: v for k, v in reps[line].items()
                            if _norm_host(v[1]) and _norm_host(v[1]) not in local_h}
                    if kept:
                        reps[line] = kept
                    else:
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
            # No traffic collection first: the core is not running, its counters are already gone.
            log('%s is down, restarting' % unit)
            system.systemctl('restart', unit)
            time.sleep(2)
            ok = system.unit_active(unit)
            notify.send('%s was down; restart %s / %s 挂了，已%s' % (unit, 'worked' if ok else 'FAILED', unit,
                                                                 '自动重启' if ok else '重启失败，请登录面板体检'),
                        key='down-' + unit, every=3600)
    if paths.LIVE and s['hy2_enabled'] and s['hy2_hop'] and shutil.which('nft'):
        if system.run(['nft', 'list', 'table', 'inet', system.NFT_TABLE]).returncode != 0:
            res = system.port_hopping(s)
            log('port hopping table missing; restored (%s)' % res)


DEVICE_PAUSE = 600
DEVICE_EVENT_EVERY = 3600
_device_events = {}       # user id -> when its last "too many devices" event was recorded


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
        # With warnings only, an account stays over its limit check after check; one event an hour is
        # enough, and the event log keeps only the latest 1000 rows (registrations and requests included).
        if s['ip_limit_pause'] or now - _device_events.get(u['id'], 0) >= DEVICE_EVENT_EVERY:
            _device_events[u['id']] = now
            db.add_event('devices', u['id'], '%s: %d devices online, limit %d (%s)' % (
                u['name'], n, u['max_ips'], ', '.join(d.get('ips', [])[:8])))
        if s['ip_limit_pause']:
            if not db.pause_for_devices(u['id'], now + DEVICE_PAUSE):
                continue                        # turned off meanwhile (by an admin, say): leave it so
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

    @staticmethod
    def _valid_point(point):
        # Length alone is not a schema: malformed values in history.json can
        # otherwise reach the browser's CPU/memory/network plots.
        if not isinstance(point, list) or len(point) != 5 or type(point[0]) is not int:
            return False
        if not 0 <= point[0] <= 253402300799:  # JavaScript Date/SQLite-safe epoch
            return False
        for index in range(1, 5):
            value = point[index]
            if value is None:
                continue
            if type(value) not in (int, float):
                return False
            # math.isfinite() converts ints to float; a huge JSON integer
            # would itself raise OverflowError and re-break cache startup.
            if type(value) is float and not math.isfinite(value):
                return False
            if value is not None and index in (1, 2) and not 0 <= value <= 100:
                return False
            if index in (3, 4) and not 0 <= value < (1 << 63):
                return False
        return True

    def __init__(self, path=None, load=True):
        self.path = path or os.path.join(paths.VAR, 'history.json')
        self._lock = threading.Lock()
        self.points, self.cpu_last, self.saved = [], None, 0
        if load:
            try:
                with open(self.path) as f:
                    saved = json.load(f)
                if not isinstance(saved, list):
                    raise ValueError('history cache must be a list')
                self.points = [p for p in saved if self._valid_point(p)][-self.KEEP:]
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
        mem = round(h['mem_used'] * 100 / h['mem_total'], 1) if h.get('mem_total') else None
        should_save = False
        with self._lock:
            try:
                total, idle = self._cpu_times()
                if self.cpu_last and total > self.cpu_last[0]:
                    cpu = round(100 * (1 - (idle - self.cpu_last[1]) / (total - self.cpu_last[0])), 1)
                self.cpu_last = (total, idle)
            except (OSError, ValueError, IndexError):
                pass
            self.points.append([now, cpu, mem, h.get('rx_rate'), h.get('tx_rate')])
            del self.points[:-self.KEEP]
            if now - self.saved >= 600:
                self.saved = now
                should_save = True
        if should_save:
            self.save()

    def snapshot(self, n=None):
        with self._lock:
            return list(self.points[-n:]) if n is not None else list(self.points)

    def save(self):
        with self._lock:
            data = json.dumps(self.points)
        try:
            paths.write_atomic(self.path, data, 0o600)
        except OSError:
            pass


HISTORY = History(load=False)           # replaced with a loaded one when the scheduler starts


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
    invitees = members.invitee_index(users)       # before a name narrows the list: shares count all of it
    on = cores.online_detail(s) or {}
    if name:
        u = next((x for x in users if x['name'].lower() == name.lower()), None)
        if not u:
            return '没有这个使用者' if zh else 'No such user'
        users = [u]
    now = time.time()
    users.sort(key=lambda u: -(u['used_up'] + u['used_down']))
    out = []
    for u in users[:25]:
        used = (u['used_up'] + u['used_down']) / (1 << 30)
        state = '🟢' if u['id'] in on else ('⚪' if u['enabled'] else '⛔')
        # What the account may really use after sharing with invitees, as the quota pass and the app see it.
        if u['quota_gb']:
            quota = '%g GB' % round(members.effective_quota(u, now=now, index=invitees), 2)
        else:
            quota = '不限' if zh else 'unlimited'
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
    if cmd == '/expiring':
        return tg_expiring(s)
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
    return ('可用命令：\n/status 服务器状态\n/users 使用者用量\n/user 名字 某个人的详情\n/expiring 快到期或快用完的账号\n/doctor 一键体检\n/ai AI 可用性检测\n/backup 发送备份' if zh else
            'Commands:\n/status server status\n/users usage per user\n/user NAME one user\n/expiring accounts ending or running out soon\n/doctor health check\n/ai AI availability\n/backup send a backup')


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
        self.seen, self.seen_at = None, 0.0

    def check(self, s):
        if self.seen and time.monotonic() - self.seen_at < self.CONFIRM_AFTER:
            return None                   # wait before looking again, so a brief glitch is not acted on
        host = s['public_host']
        if not certs.is_ip(host) or s['domain'] or _local(host):
            return None                   # a domain, or an internal address the owner set on purpose
        now = system.public_ip(v6=':' in host)
        if not now or now == host:
            self.seen = None
            return None
        if self.seen != now:              # must be seen twice, 10 minutes apart, before we act
            self.seen, self.seen_at = now, time.monotonic()
            return None
        db.set_settings(public_host=now)
        certs.ensure_self_signed(now)
        cores.apply(force=True)
        log('public IP changed %s -> %s; subscriptions now use the new address' % (host, now))
        notify.send('IP changed %s -> %s. Apps pick it up on their next subscription update. / 服务器 IP 变了，'
                    '订阅已自动改成新地址。' % (host, now), key='ip-' + now, every=86400)
        self.seen = None
        return now


def send_backup(name, s):
    with open(name, 'rb') as f:
        notify.send_file(os.path.basename(name), f.read(), 'daily backup / 每日备份（含密钥，请妥善保存）', s=s)


class Scheduler:
    def __init__(self):
        self.last = {}
        self.cert_backoff_until = 0.0
        self.apply_owed, self.apply_wait, self.apply_at = False, 0, 0.0   # a failed apply, tried again later
        self.stop = threading.Event()
        self.ipwatch = IpWatch()
        self._threads = []
        self._slow = {}

    def in_background(self, name, fn, *args):
        """Run a slow network job (ACME renewal, a Telegram upload) beside the scheduler, one at a time per
        name: a server that does not answer must not hold up the 20-second quota and expiry pass (#112).
        Returns False while the previous one is still running."""
        t = self._slow.get(name)
        if t is not None and t.is_alive():
            return False

        def run():
            try:
                fn(*args)
            except Exception as e:
                log('%s failed: %s' % (name, e))

        t = threading.Thread(target=run, daemon=True, name=name)
        self._slow[name] = t
        t.start()
        return True

    def due(self, name, every):
        now = time.monotonic()
        if name not in self.last or now - self.last[name] >= every:
            self.last[name] = now
            return True
        return False

    def tick(self):
        s = db.settings()
        if not s['setup_done']:
            return
        changed = False
        if self.due('collect', COLLECT_EVERY):
            # Often, and cheap (one counter read per core): less is lost if a core dies, and quotas cut in sooner.
            try:
                collect()
            except Exception as e:     # what was read is kept and billed with the next reading
                log('traffic collection failed: %s' % e)
            # Expiry and quotas are enforced even when this reading failed.
            changed = enforce()
        if self.due('traffic', 60):
            if paths.LIVE and device_limits(s):
                changed = True
            health = system.health()
            server_month(s, health)
            HISTORY.sample(health)
        if changed:
            cluster.sync_soon()
        if changed or (self.apply_owed and time.monotonic() >= self.apply_at):
            # The database already says who may connect; until the cores have loaded it, an account that was
            # just stopped (quota, expiry) still gets in. A failed apply is tried again with backoff
            # (1, 2, 4 ... 15 min), not only at the next unrelated change, which may never come.
            try:
                cores.apply()
                self.apply_owed, self.apply_wait = False, 0
            except Exception as e:
                self.apply_owed = True
                self.apply_wait = min(self.apply_wait * 2 or 60, 900)
                self.apply_at = time.monotonic() + self.apply_wait
                log('apply failed, retrying in %d s: %s' % (self.apply_wait, e))
        if s['abuse_guard'] and self.due('abuse', 60) and paths.LIVE:
            abuse.check(s, log)
        if s['monitor_enabled'] and paths.LIVE and self.due('monitor', 300):
            with_speed = self.due('monitor_speed', 3600)
            if not monitor.run_in_background(log, with_speed=with_speed):
                # A previous round still owns the monitor worker. Retry at
                # the next scheduler tick, including any hourly speed refresh.
                self.last.pop('monitor', None)
                if with_speed:
                    self.last.pop('monitor_speed', None)
        if paths.LIVE and self.due('cert', 3600) and time.monotonic() >= self.cert_backoff_until:
            self.in_background('cert-renewal', self.renew_cert, s)
        if paths.LIVE and s.get('client_auto_update', True) and self.due('client', 6 * 3600):
            threading.Thread(target=client_sync, args=(s,), daemon=True, name='clientsync').start()
        if self.due('rules', 86400) or (rules.mirror_age() is None and self.due('rules-missing', 600)):
            rules.refresh_in_background(log)
        if self.due('renew', 3600):
            renew_reminder(s)
            expiry_reminders()
        if self.due('watchdog', 300) and paths.LIVE:
            watchdog(s)
        if self.due('ip', 6 * 3600) or self.ipwatch.seen:
            # Asks outside servers for our address, which can take several timeouts: beside the quota pass.
            # One at a time, so IpWatch's state has a single writer; cores.apply takes its own lock.
            self.in_background('ipwatch', self.ipwatch.check, s)
        if paths.LIVE and self.due('aicheck', 86400):
            threading.Thread(target=ai_recheck, args=(s, log), daemon=True, name='aicheck').start()
        if self.due('backup', 86400):
            name = backup()
            if s['tg_backup'] and s['tg_token'] and s['tg_chat']:
                self.in_background('tg-backup', send_backup, name, s)

    def renew_cert(self, s):
        """Renew the certificate when due and hand it to the cores."""
        cert_host = s['domain'] or s['public_host']
        before = certs.current(cert_host)
        res = certs.renew_if_needed(s, log=log)
        if res and res != 'ok':
            self.cert_backoff_until = time.monotonic() + 6 * 3600    # stay well under Let's Encrypt's failure limits
            db.set_settings(cert_status='failed: ' + res[:200])
            if certs.trusted(cert_host) and not certs.acme_valid(36):
                notify.send('certificate renewal failing: %s / 证书续期失败' % res[:200], key='cert', every=12 * 3600)
        elif res == 'ok':
            db.set_settings(cert_status='ok')
        if certs.current(cert_host) != before:
            cores.apply()            # other files: the configs change and the cores restart
        elif res == 'ok':
            # Same files, new certificate: both QUIC servers pick it up by themselves, no restart (which
            # would drop every connection). Checked for the pinned versions:
            # - Hysteria app/v2.14.0 serves through tls.Config.GetCertificate = LocalCertificateLoader, which
            #   stats cert and key on every handshake and reloads them when a modification time changes
            #   (app/cmd/server.go, app/internal/utils/certloader.go).
            # - sing-box v1.14.4 watches certificate_path / key_path (fsnotify on the directory, so the
            #   atomic rename in paths.write_atomic is seen) and swaps in a new tls.Config that
            #   GetConfigForClient hands to each new handshake, QUIC included (common/tls/std_server.go).
            log('certificate renewed; Hysteria and TUIC load it on their next handshakes')

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
        self._threads = [
            threading.Thread(target=notify.bot_loop, args=(self.stop, tg_command, log), daemon=True, name='tg-bot'),
            threading.Thread(target=self.run, daemon=True, name='jobs'),
            threading.Thread(target=self.tuic_sampler, daemon=True, name='tuic-meter'),
            threading.Thread(target=cluster.loop, args=(self.stop, log), daemon=True, name='servers'),
        ]
        for t in self._threads:
            t.start()

    def stop_all(self, timeout=5):
        self.stop.set()
        cluster.sync_soon()
        deadline = time.monotonic() + timeout
        for t in self._threads:
            rem = max(0.0, deadline - time.monotonic())
            t.join(rem)
        HISTORY.save()
