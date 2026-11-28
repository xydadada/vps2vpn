#!/usr/bin/env python3
"""Move the accounts (and, if you want, the routing rules) of an old "legend" panel into vps2vpn.

    python tools/legend_import.py --base vps2vpn-backup.json --settings settings.json \\
        --usage usage.sqlite3 [--template template.json] [--lines config.json] -o merged-backup.json

--base      a backup downloaded from the NEW vps2vpn panel (Settings -> Backup). Its admin password, panel
            address and settings are kept; the old accounts are added to the accounts already in it.
--settings  the old panel's settings.json (normally /etc/legend-sub/settings.json), a copy.
--usage     the old panel's usage.sqlite3 (normally /var/lib/legend-sub/usage.sqlite3), a copy: this
            period's traffic so far, so nobody gets a fresh quota on moving day.
--template  optional: the old subscription template (template.json); its "rules" become the panel's own
            direct / proxy / block lists.
--lines     optional: the old proxy's sing-box config (/etc/legend-tiered/config.json): keep its Reality key,
            short id, handshake site and public ports, so old Reality links keep working without a refresh.

Only copies are read, and nothing is sent anywhere. Restore the result on the new panel (Settings -> Restore).
Each account keeps its subscription token, its Reality UUID and Hysteria 2 password, its quota, this period's
usage and any top-up, its expiry, who invited it, and its member-centre password. What cannot be carried over
exactly is listed at the end; nothing is dropped without being listed.
"""
import argparse
import base64
import calendar
import datetime as dt
import json
import math
import os
import re
import sqlite3
import sys
import tempfile
import urllib.request

GIB = 1 << 30                       # vps2vpn counts a GB as 2^30 bytes; the old panel stored bytes
SG = dt.timezone(dt.timedelta(hours=8), 'Asia/Singapore')   # the old panel's billing clock (no DST there)
NAME_RE = re.compile(r'^[\w.\-一-鿿]{2,32}$')       # vps2vpn members.NAME_RE
HOST_RE = re.compile(r'^(?=.{1,253}$)([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$')
MAX_PBKDF2_ROUNDS = 5_000_000       # vps2vpn secure.MAX_PBKDF2_ROUNDS
MAX_MBPS = 100000
PANEL_LIST_MAX = 10000              # what the panel's settings page accepts per list (web.CUSTOM_LIST_MAX)

# Old policy-group names -> vps2vpn list. "ai" is left to vps2vpn's own AI group.
TARGETS = {
    '节点选择': 'proxy', '海外影音': 'proxy', 'Steam商店': 'proxy', 'OneDrive': 'proxy', '学术网站': 'proxy',
    'Cloudflare': 'proxy', 'PROXY': 'proxy',
    '国内服务': 'direct', '国内影音': 'direct', 'Steam下载': 'direct', 'DIRECT': 'direct',
    '广告过滤': 'block', 'REJECT': 'block', 'REJECT-DROP': 'block',
    'Claude': 'ai',
}
LIST_KEY = {'block': 'custom_block', 'direct': 'custom_direct', 'proxy': 'custom_proxy'}
ORDER = ('block', 'direct', 'proxy')          # the order vps2vpn puts the three lists in (rules.route_plan)
AI_SUFFIX = ('anthropic.com', 'claude.ai', 'claude.com', 'claudeusercontent.com', 'clau.de', 'openai.com',
             'chatgpt.com', 'oaistatic.com', 'oaiusercontent.com', 'sora.com', 'gemini.google.com',
             'aistudio.google.com', 'generativelanguage.googleapis.com', 'notebooklm.google.com',
             'alkalimakersuite-pa.clients6.google.com', 'proactivebackend-pa.googleapis.com',
             'ai.google.dev', 'deepmind.google', 'x.ai', 'grok.com', 'perplexity.ai')   # = vps2vpn rules.AI_SUFFIX
UUID_RE = re.compile(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')
# what Hysteria 2 (user:password), TUIC and the Shadowrocket lines can carry as they are written
HY2_PASS_RE = re.compile(r'^[A-Za-z0-9._~!@#$%^&*+=:;?/|-]{6,128}$')
_OFFSET = re.compile(r'UTC(?:([+-])(\d{1,2})(?::([0-5]\d))?)?')       # vps2vpn clock.parse


class Problem(ValueError):
    pass


# What this tool reads from the old settings.json. Anything else is named in the report, never dropped silently.
USER_KEYS = {'id', 'remark', 'token', 'uuid', 'hy_password', 'tuic_uuid', 'tuic_password', 'total', 'expire',
             'enabled', 'cycle_day', 'quota_overrun', 'created_at', 'quota_bonus', 'member_login', 'speed_policy',
             'invited_by', 'invite_deduct', 'nodes'}
TOP_KEYS = {'users', 'legacy', 'nodes', 'relays', 'base_url', 'settings'}
RATE_SUFFIX = re.compile(r'\s*[·・•]\s*\d+(\.\d+)?\s*[x×]\s*$', re.I)     # "Taiwan · 5.0x" -> "Taiwan"


def _old_nodes(legend):
    """[(id, name, multiplier or None, bad value or None)] of the old panel's nodes (other servers). They are not
    imported: each one joins the new panel on its own. Read from settings.json "nodes" (an object keyed by id, or
    a list), also when it sits under a "settings" object."""
    holders = [legend] + ([legend['settings']] if isinstance(legend.get('settings'), dict) else [])
    out = []
    for h in holders:
        nodes = h.get('nodes')
        items = (nodes.items() if isinstance(nodes, dict)
                 else ((n.get('id'), n) for n in nodes if isinstance(n, dict)) if isinstance(nodes, list) else ())
        for nid, n in items:
            n = n if isinstance(n, dict) else {}
            name = RATE_SUFFIX.sub('', str(n.get('name') or n.get('remark') or nid or '?')).strip()
            m, bad = n.get('billing_multiplier'), None
            if m is not None:
                if type(m) in (int, float) and 0 <= m <= 100:
                    m = float(m)
                else:
                    m, bad = None, n.get('billing_multiplier')
            out.append((str(nid), name, m, bad))
    return out


def _old_relays(legend):
    holders = [legend] + ([legend['settings']] if isinstance(legend.get('settings'), dict) else [])
    n = 0
    for h in holders:
        r = h.get('relays')
        n += len(r) if isinstance(r, (list, dict)) else (1 if r else 0)
    return n


def _whole(u, key, default=0):
    """A count, byte total or time from the old panel: a whole number >= 0. A missing key or JSON null is
    `default`; true/false, fractions and negative numbers are refused (they would be quietly turned into 1 or 0)."""
    v = u.get(key) if isinstance(u, dict) else None
    if v is None:
        return default
    if type(v) is float and math.isfinite(v) and v >= 0:
        return int(v)                   # a time written by time.time()
    if type(v) is not int or v < 0:
        raise Problem('旧账号 %s 的 %s 不是非负整数：%r' % (u.get('id', '?'), key, v))
    return v


def _record(v):
    return v if isinstance(v, dict) else {}


def _parse_tz(name):
    """tzinfo for the new panel's time_zone setting, as vps2vpn clock.parse reads it (None = not set)."""
    name = str(name or '').strip()
    if not name:
        return None
    m = _OFFSET.fullmatch(name)
    if m:
        if not m.group(1):
            return dt.timezone.utc
        hours, minutes = int(m.group(2)), int(m.group(3) or 0)
        if hours > 14 or (hours == 14 and minutes):
            raise Problem('新面板的重置时区 %s 看不懂' % name)
        delta = dt.timedelta(hours=hours, minutes=minutes)
        return dt.timezone(-delta if m.group(1) == '-' else delta, name)
    try:
        from zoneinfo import ZoneInfo
        return ZoneInfo(name)
    except Exception:
        raise Problem('新面板的重置时区 %s 在这台电脑上找不到；先在面板里改成 UTC+8 这样的写法' % name) from None


# --- the old panel's own arithmetic (legend_sub.py), kept identical -----------------------------------------
def cycle_key(cycle_day, ts):
    local = dt.datetime.fromtimestamp(ts, SG)
    day = 20 if cycle_day is None else cycle_day
    if type(day) is not int or not 1 <= day <= 31:
        raise Problem('cycle_day outside 1..31')
    year, month = local.year, local.month
    if local.day < min(day, calendar.monthrange(year, month)[1]):
        month -= 1
        if not month:
            year, month = year - 1, 12
    return dt.date(year, month, min(day, calendar.monthrange(year, month)[1])).isoformat()


def legend_deducting(u, now):
    return (bool(u.get('invited_by')) and _whole(u, 'invite_deduct') > 0 and u.get('enabled', True)
            and not (_whole(u, 'expire') and _whole(u, 'expire') <= now))


def legend_quota(u, users, now):
    """Bytes the old panel allowed this period (0 = unlimited): legend_sub.quota_total with invites.annotate."""
    base = _whole(u, 'total')
    if not base:
        return 0
    bonus = _record(u.get('quota_bonus'))
    extra = _whole(bonus, 'bytes') if bonus.get('cycle') == cycle_key(u.get('cycle_day'), now) else 0
    out = sum(_whole(c, 'invite_deduct') for c in users if c.get('invited_by') == u['id'] and legend_deducting(c, now))
    return max(1, base + extra - out)


# --- reading the old panel's files --------------------------------------------------------------------------
def read_json(path, what):
    try:
        with open(path, encoding='utf-8-sig') as f:
            return json.load(f)
    except OSError as e:
        raise Problem('读不到%s：%s' % (what, e))
    except ValueError as e:
        raise Problem('%s不是有效的 JSON：%s' % (what, e))


def read_usage(path, users, now):
    """{old id: (upload, download)} for each account's current period, as the old panel sums it."""
    if not os.path.isfile(path):
        raise Problem('找不到流量记录文件：%s' % path)
    uri = 'file:%s?mode=ro&immutable=1' % urllib.request.pathname2url(os.path.abspath(path))
    db = sqlite3.connect(uri, uri=True)
    try:
        out = {}
        for u in users:
            row = db.execute('SELECT COALESCE(SUM(upload),0), COALESCE(SUM(download),0) FROM daily '
                             'WHERE user_id=? AND cycle=?', (u['id'], cycle_key(u.get('cycle_day'), now))).fetchone()
            if not all(type(n) is int and n >= 0 for n in row):
                raise Problem('流量记录里账号 %s 的用量不是非负整数' % u['id'])
            out[u['id']] = (row[0], row[1])
        return out
    except sqlite3.DatabaseError as e:
        raise Problem('流量记录文件读不了（%s）：是 usage.sqlite3 吗？' % e)
    finally:
        db.close()


def convert_login(login):
    """The old member-centre credential as a vps2vpn login_hash ('' = no password sign-in)."""
    if not isinstance(login, dict) or not login.get('enabled', True) or not login.get('password_hash'):
        return ''
    try:
        salt, digest, rounds = bytes.fromhex(login['salt']), bytes.fromhex(login['password_hash']), int(login['iterations'])
    except (KeyError, TypeError, ValueError):
        return ''
    if len(salt) < 8 or len(digest) != 32 or not 1 <= rounds <= MAX_PBKDF2_ROUNDS:
        return ''
    b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b'=').decode()
    return 'pbkdf2_sha256$%d$%s$%s' % (rounds, b64(salt), b64(digest))


def _clean_name(text):
    text = re.sub(r'[^\w.\-一-鿿]', '', str(text or ''))[:32]
    return text if NAME_RE.match(text) else ''


def pick_name(u, taken):
    """Account name in vps2vpn: the member-centre user name when it has one (members sign in with it), else
    the remark, else the old id. Made unique (case-insensitively) against `taken`."""
    login = u.get('member_login') if isinstance(u.get('member_login'), dict) else {}
    for cand in (login.get('username'), u.get('remark'), u['id']):
        name = _clean_name(cand)
        if name and name.casefold() not in taken:
            return name
    base = _clean_name(u['id']) or 'user'
    base = (base + '-x') if len(base) < 2 else base[:28]
    n = 2
    while ('%s-%d' % (base, n)).casefold() in taken:
        n += 1
    return '%s-%d' % (base, n)


def _speed(u, quota, report):
    """throttle_mbps for vps2vpn (0 = stop when the quota is used up)."""
    if not quota or u.get('quota_overrun') != 'throttle':
        return 0
    p = _record(u.get('speed_policy'))
    if p.get('exempt'):
        report['exempt'].append(u['id'])
        return MAX_MBPS
    speeds = []
    for key, default in (('download_mbps', 50.0), ('upload_mbps', 5.0)):
        v = p.get(key)
        if v is None:
            v = default
        try:                            # the old panel wrote numbers, sometimes as text ("50")
            f = float(v) if type(v) in (int, float, str) else float('nan')
        except ValueError:
            f = float('nan')
        if not math.isfinite(f) or f <= 0:          # NaN would become "no limit", true would become 1 Mbps
            raise Problem('旧账号 %s 的降速速度 %s 不对：%r' % (u['id'], key, v))
        speeds.append(f)
    down, up = speeds
    if p and p.get('follow_quota') is False:
        report['free_gb'].append(u['id'])
    if up != down:
        report['updown'].append((u['id'], up, down))
    return max(1.0, min(MAX_MBPS, down))


def import_users(base, legend, usage, now):
    """Return (merged backup, report). `base` is a vps2vpn backup; nothing in it is changed except users."""
    if not isinstance(base, dict) or base.get('format') != 'vps2vpn-backup-1' or not isinstance(base.get('users'), list):
        raise Problem('--base 不是 vps2vpn 面板导出的备份文件')
    old = legend.get('users') if isinstance(legend, dict) else None
    if not isinstance(old, list):
        raise Problem('--settings 里没有 users：是旧面板的 settings.json 吗？')
    report = {'renamed': [], 'login_renamed': [], 'exempt': [], 'free_gb': [], 'updown': [],
              'nodes': [], 'orphans': [], 'chain': [], 'no_login': [], 'legacy': bool(legend.get('legacy')),
              'count': 0}
    users = [dict(u) for u in base['users']]
    base_settings = _record(base.get('settings'))
    panel_tz = _parse_tz(base_settings.get('time_zone')) or SG
    taken = {str(u.get('name', '')).casefold() for u in users}
    seen = {k: {u.get(k) for u in users} for k in ('sub_token', 'uuid', 'hy2_pass')}
    next_id = max([int(u.get('id') or 0) for u in users] + [0]) + 1
    ids = {}
    for u in old:
        if not isinstance(u, dict) or not isinstance(u.get('id'), str) or u['id'] in ids:
            raise Problem('旧面板账号列表有问题（缺 id 或 id 重复）')
        ids[u['id']] = next_id
        next_id += 1
    new = []
    for u in old:
        for k_old, k_new in (('token', 'sub_token'), ('uuid', 'uuid'), ('hy_password', 'hy2_pass')):
            v = u.get(k_old)
            if not isinstance(v, str) or not v:
                raise Problem('旧账号 %s 缺少 %s' % (u['id'], k_old))
            if v in seen[k_new]:
                raise Problem('旧账号 %s 的 %s 和新面板里已有的账号重复：先在新面板删掉那个测试账号' % (u['id'], k_old))
            seen[k_new].add(v)
        if not re.fullmatch(r'[A-Za-z0-9_-]{16,64}', u['token']):
            raise Problem('旧账号 %s 的订阅 token 格式 vps2vpn 不认' % u['id'])
        for k in ('total', 'expire', 'invite_deduct', 'created_at'):
            _whole(u, k)                                      # every count, whether or not it is used below
        if not UUID_RE.fullmatch(u['uuid']):
            raise Problem('旧账号 %s 的 uuid 不是 UUID：恢复后 Xray 会起不来' % u['id'])
        if not HY2_PASS_RE.fullmatch(u['hy_password']):
            raise Problem('旧账号 %s 的 Hysteria 密码里有空格、逗号或别的字符，订阅里写不进去' % u['id'])
        name = pick_name(u, taken)
        taken.add(name.casefold())
        login = u.get('member_login') if isinstance(u.get('member_login'), dict) else {}
        login_hash = convert_login(login)
        wanted = login.get('username') or u.get('remark') or u['id']
        if login.get('username') and login_hash and name != login['username']:
            report['login_renamed'].append((u['id'], login['username'], name))
        elif name != wanted:
            report['renamed'].append((u['id'], wanted, name))
        if login.get('password_hash') and login.get('enabled', True) and not login_hash:
            report['no_login'].append(u['id'])
        day = 20 if u.get('cycle_day') is None else u['cycle_day']
        cycle_key(day, now)                                   # rejects an impossible day
        reset_day = day                                       # 29-31 fall on a short month's last day, as before
        # the month as the new panel will see it: in its own time zone (UTC+8, the old panel's, if none is set),
        # or its first reset check would think a month had passed and clear this month's usage
        here = dt.datetime.fromtimestamp(now, panel_tz)
        prev = (here.year - 1, 12) if here.month == 1 else (here.year, here.month - 1)
        this_month = min(day, calendar.monthrange(here.year, here.month)[1])
        last_reset = '%04d-%02d' % ((here.year, here.month) if here.day >= this_month else prev)
        total = _whole(u, 'total')
        bonus = _record(u.get('quota_bonus'))
        extra = _whole(bonus, 'bytes') if total and bonus.get('cycle') == cycle_key(day, now) else 0
        up, down = usage.get(u['id'], (0, 0))
        inviter = u.get('invited_by') or ''
        if inviter and inviter not in ids:
            report['orphans'].append(u['id'])
        if u.get('nodes'):
            report['nodes'].append(u['id'])
        note = ('旧系统 %s' % u['id']) + ((' · ' + str(u['remark'])) if u.get('remark') and u['remark'] != name else '')
        new.append({
            'id': ids[u['id']], 'name': name, 'uuid': u['uuid'], 'hy2_pass': u['hy_password'],
            'sub_token': u['token'], 'quota_gb': total / GIB, 'extra_gb': extra / GIB,
            'expire_at': _whole(u, 'expire'), 'reset_day': reset_day, 'last_reset': last_reset,
            'used_up': up, 'used_down': down,
            'enabled': 1 if u.get('enabled', True) else 0, 'disabled_reason': '' if u.get('enabled', True) else 'manual',
            'note': note[:200], 'created_at': _whole(u, 'created_at'), 'login_hash': login_hash,
            'invited_by': ids.get(inviter, 0), 'invite_deduct': _whole(u, 'invite_deduct') / GIB if inviter in ids else 0,
            'throttle_mbps': _speed(u, total, report), 'speed_mbps': 0, 'throttled': 0,
        })
    # vps2vpn also charges an inviter for what an inactive invitee passed on to its own invitees; the old
    # panel did not. Name the accounts where that changes the quota.
    by_inviter = {}
    for u in old:
        by_inviter.setdefault(u.get('invited_by'), []).append(u)
    for u in old:
        if u.get('invited_by') and not legend_deducting(u, now) and _whole(u, 'invite_deduct') > 0:
            if any(legend_deducting(c, now) for c in by_inviter.get(u['id'], ())):
                report['chain'].append(u['invited_by'])
    report['count'] = len(new)
    report['old_nodes'] = _old_nodes(legend)
    report['relays'] = _old_relays(legend)
    report['base_url'] = legend.get('base_url') if isinstance(legend.get('base_url'), str) else ''
    report['top_unknown'] = sorted(k for k in legend if k not in TOP_KEYS)
    if isinstance(legend.get('settings'), dict):
        report['top_unknown'] += sorted('settings.' + k for k in legend['settings'] if k not in ('nodes', 'relays'))
    unknown = {}
    for u in old:
        for k in u:
            if k not in USER_KEYS:
                unknown[k] = unknown.get(k, 0) + 1
    report['user_unknown'] = sorted(unknown.items())
    out = dict(base)
    out['users'] = users + new
    # the old panel changed months at midnight Singapore time; keep that unless the new panel already chose a zone
    s = dict(base_settings)
    report['time_zone'] = s.get('time_zone') or ''
    if not report['time_zone']:
        s['time_zone'] = 'UTC+8'
        out['settings'] = s
    return out, report


# --- routing rules ------------------------------------------------------------------------------------------
def _domain(value):
    d = re.sub(r'^(\+\.|\*\.|\.)', '', value.strip().lower().rstrip('.'))
    return d if HOST_RE.match(d) or re.fullmatch(r'[a-z0-9-]{1,63}', d) else ''


def _ancestors(d):
    parts = d.split('.')
    return ['.'.join(parts[i:]) for i in range(len(parts))]


def convert_rules(rules, targets=TARGETS):
    """Old Clash rules -> ({'proxy': [...], 'direct': [...], 'block': [...]}, report).

    First match wins in the old file too, so a rule under a domain an earlier rule already matched is dead
    there and is skipped here. vps2vpn puts its lists block -> direct -> proxy; an entry a broader entry of an
    earlier list would catch first is reported (it would not work as before)."""
    if not isinstance(rules, list):
        raise Problem('template.json 里没有 rules 列表')
    lists = {k: [] for k in ORDER}
    where = {}                                    # domain -> lists it went to
    exact, suffix = set(), set()
    rep = {'total': len(rules), 'by_type': {}, 'keyword': 0, 'ip': 0, 'other': 0, 'unknown_target': {},
           'ai': 0, 'exact': 0, 'dead': 0, 'bad': 0, 'shadowed': []}
    for r in rules:
        parts = [p.strip() for p in str(r).split(',')]
        kind = parts[0].upper() if parts else ''
        rep['by_type'][kind] = rep['by_type'].get(kind, 0) + 1
        if kind in ('DOMAIN-KEYWORD',):
            rep['keyword'] += 1
            continue
        if kind in ('IP-CIDR', 'IP-CIDR6', 'GEOIP', 'IP-ASN', 'SRC-IP-CIDR'):
            rep['ip'] += 1
            continue
        if kind not in ('DOMAIN-SUFFIX', 'DOMAIN') or len(parts) < 3:
            rep['other'] += 1
            continue
        to = targets.get(parts[2])
        if to is None:
            rep['unknown_target'][parts[2]] = rep['unknown_target'].get(parts[2], 0) + 1
            continue
        d = _domain(parts[1])
        if not d:
            rep['bad'] += 1
            continue
        if any(a in suffix for a in _ancestors(d)) or (kind == 'DOMAIN' and d in exact):
            rep['dead'] += 1                      # an earlier rule already decides this name
            continue
        (exact if kind == 'DOMAIN' else suffix).add(d)
        if to == 'ai' or (to == 'proxy' and any(a in AI_SUFFIX for a in _ancestors(d))):
            rep['ai'] += 1                        # vps2vpn's AI group routes these itself
            continue
        if kind == 'DOMAIN':
            rep['exact'] += 1                     # vps2vpn lists are suffixes: this now covers subdomains too
        if to not in where.setdefault(d, set()):
            lists[to].append(d)
            where[d].add(to)
    for to in ORDER:
        earlier = ORDER[:ORDER.index(to)]
        for d in lists[to]:
            for a in _ancestors(d):
                shadow = next((target for target in earlier if target in where.get(a, ())), None)
                if shadow:
                    rep['shadowed'].append((d, to, a, shadow))
                    break
    return lists, rep


def merge_rules(backup, lists):
    s = dict(backup.get('settings') or {})
    for to, key in LIST_KEY.items():
        have = [d for d in (s.get(key) or []) if isinstance(d, str)]
        s[key] = have + [d for d in lists[to] if d not in have]
    out = dict(backup)
    out['settings'] = s
    return out


# --- the old server's lines ---------------------------------------------------------------------------------
OLD_REALITY_PORT = 443          # legend-tiered listens on 26443/28443; nft sends the public 443/8443 there
OLD_TUIC_PORT = 8443
OLD_HOP_RANGE = '20000-25999'


def _panel(name):
    """A module of the panel next to this tool (vps2vpn.secure, vps2vpn.db)."""
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    try:
        return __import__('vps2vpn.' + name, fromlist=[name])
    finally:
        sys.path.pop(0)


def _reality_public(private):
    try:
        return _panel('secure').reality_public_key(private)
    except Exception:                   # 43 characters that are still no X25519 key: say so, no traceback
        raise Problem('旧线路设置里的 Reality 私钥无效')


OBFS_RE = re.compile(r'[^\s\x00-\x1f\x7f]{1,64}')     # at most 64 like the panel; no spaces or control characters


def _hy2_obfs(hy2):
    """The old server's salamander password, '' for none. Hysteria 2 has no other kind of obfuscation."""
    obfs = hy2.get('obfs')
    if not obfs:
        return ''
    if not isinstance(obfs, dict) or str(obfs.get('type') or '').lower() != 'salamander':
        raise Problem('旧线路设置里 Hysteria 2 的混淆方式不是 salamander，新面板不支持')
    password = obfs.get('password')
    if not isinstance(password, str) or not OBFS_RE.fullmatch(password):
        raise Problem('旧线路设置里 Hysteria 2 的混淆密码格式不对（要 1–64 个字符，不能有空格）')
    return password


def convert_lines(cfg):
    """Settings that keep every old Reality link working unchanged: the same private key (so the public key in
    everyone's client still matches), the same short id, the same handshake site and the same public ports.
    Hysteria 2 keeps its port and hop range; its passwords already move with the accounts."""
    if not isinstance(cfg, dict) or not isinstance(cfg.get('inbounds'), list):
        raise Problem('旧线路设置（config.json）里没有 inbounds 列表')
    by_type = {}
    for ib in cfg['inbounds']:
        if isinstance(ib, dict):
            by_type.setdefault(ib.get('type'), ib)
    vless = by_type.get('vless') or {}
    tls = vless.get('tls') if isinstance(vless.get('tls'), dict) else {}
    reality = tls.get('reality') if isinstance(tls.get('reality'), dict) else {}
    private = reality.get('private_key')
    if not reality.get('enabled') or not isinstance(private, str) or not re.fullmatch(r'[A-Za-z0-9_-]{43}', private):
        raise Problem('旧线路设置里找不到 Reality 私钥')
    sids = reality.get('short_id')
    sid = sids[0] if isinstance(sids, list) and sids else sids
    # hex digits in pairs (bytes), at most 8 bytes; upper case is the same id
    if not isinstance(sid, str) or not re.fullmatch(r'(?:[0-9A-Fa-f]{2}){0,8}', sid):
        raise Problem('旧线路设置里的 Reality short_id 格式不对')
    sid = sid.lower()
    hs = reality.get('handshake') if isinstance(reality.get('handshake'), dict) else {}
    target = str(hs.get('server') or tls.get('server_name') or '').strip().lower()
    if not HOST_RE.match(target):
        raise Problem('旧线路设置里的 Reality 伪装网站格式不对')
    out = {'reality_enabled': True, 'reality_port': OLD_REALITY_PORT, 'reality_target': target,
           'reality_private_key': private, 'reality_public_key': _reality_public(private), 'reality_short_id': sid}
    hy2 = by_type.get('hysteria2')
    if hy2:
        out.update({'hy2_enabled': True, 'hy2_port': OLD_REALITY_PORT, 'hy2_hop': True, 'hy2_hop_range': OLD_HOP_RANGE,
                    'hy2_obfs': _hy2_obfs(hy2)})
    if by_type.get('tuic'):
        out.update({'tuic_enabled': True, 'tuic_port': OLD_TUIC_PORT})
    return out


def merge_lines(backup, lines):
    """The old lines over the new panel's settings, refused when they would collide with what the new panel
    already uses (the panel itself refuses the same settings in its settings page)."""
    out = dict(backup)
    out['settings'] = dict(backup.get('settings') or {}, **lines)
    s = dict(_panel('db').DEFAULTS, **out['settings'])
    if s['reality_enabled'] and s['panel_port'] == s['reality_port']:
        raise Problem('新面板自己用的是 TCP %d 端口，和旧线路的 Reality 端口冲突；先在新面板里把面板端口改掉'
                      % s['panel_port'])
    if s['hy2_enabled'] and s['tuic_enabled'] and s['hy2_port'] == s['tuic_port']:
        raise Problem('Hysteria 2 和 TUIC 会用同一个 UDP 端口 %d' % s['tuic_port'])
    if s['hy2_enabled'] and s['hy2_hop']:
        try:
            a, b = _panel('system').parse_range(str(s['hy2_hop_range']))
        except ValueError:
            raise Problem('跳端口范围格式不对：%s' % s['hy2_hop_range'])
        for name, port in (('Hysteria 2', s['hy2_port']), ('TUIC', s['tuic_port'] if s['tuic_enabled'] else 0)):
            if a <= port <= b:
                raise Problem('%s 的端口 %d 落在跳端口范围 %d-%d 里' % (name, port, a, b))
    return out


# --- report -------------------------------------------------------------------------------------------------
def describe(report, rules_report, settings):
    lines = ['导入了 %d 个旧账号。' % report['count']]
    for oid, old, new in report['renamed']:
        lines.append('  · %s 的名字 “%s” vps2vpn 不支持或已被占用，改叫 “%s”。' % (oid, old, new))
    for oid, old, new in report['login_renamed']:
        lines.append('  · %s 以前用 “%s” 登录成员中心，以后要用 “%s” 登录（密码不变），请告诉对方。' % (oid, old, new))
    for oid in report['no_login']:
        lines.append('  · %s 的成员中心密码格式不认，导入后只能用订阅链接打开成员中心，需要时请重设密码。' % oid)
    for oid in report['exempt']:
        lines.append('  · %s 以前“始终不限速”：流量用完后按 %d Mbps（等于不限速）继续用。' % (oid, MAX_MBPS))
    for oid in report['free_gb']:
        lines.append('  · %s 以前在“门槛流量”后降速：vps2vpn 只能在套餐流量用完后降速。' % oid)
    if report['updown']:
        lines.append('  · %d 个账号以前上传、下载降速不一样（例如上传 %g / 下载 %g Mbps）：vps2vpn 用一个速度，取下载速度。'
                     % (len(report['updown']), report['updown'][0][1], report['updown'][0][2]))
    if report['nodes']:
        lines.append('  · %d 个账号以前只能用部分节点（%s）：导入后能用这台服务器，其他服务器请在面板里给他们勾选。'
                     % (len(report['nodes']), '、'.join(report['nodes'][:5])))
    for oid in report['orphans']:
        lines.append('  · %s 的邀请人在旧系统里已经不存在：导入后不再从别人那里扣流量。' % oid)
    for oid in sorted(set(report['chain'])):
        lines.append('  · %s：它邀请的人已停用，但那人又邀请了别人；vps2vpn 会继续从 %s 扣这部分流量，旧系统不扣。' % (oid, oid))
    if report['legacy']:
        lines.append('  · 旧系统里还有一个公用的 legacy Hysteria 账号，它没有订阅链接，不会导入。')
    nodes = report.get('old_nodes') or []
    if nodes:
        lines.append('  · 旧系统有 %d 个节点（%s）：节点不会导入。每台装好 vps2vpn 后，在新面板「多服务器」页用它的加入码加入，'
                     '再给需要的账号勾选。' % (len(nodes), '、'.join('%s「%s」' % (i, n) for i, n, _, _ in nodes[:8])
                                                + ('等' if len(nodes) > 8 else '')))
        for nid, name, m, bad in nodes:
            if m is not None and m != 1:
                lines.append('    - 节点 %s「%s」以前按 %g 倍计流量：加入后在「多服务器」页点它的「×1」按钮改成 %g。'
                             '（「自动选择」不会切到倍率大于 1 的服务器，名字后面会带 ×%g。）' % (nid, name, m, m, m))
            elif bad is not None:
                lines.append('    - 节点 %s「%s」的计费倍率 %r 看不懂（vps2vpn 要 0 到 100 的数）：加入后请手动设。' % (nid, name, bad))
    if report.get('relays'):
        lines.append('  · 旧系统有 %d 条中转（relays）：vps2vpn 还不支持中转，没有导入。走中转的人导入后直接连目标服务器，'
                     '移动网络下可能变慢（以后的计划见 docs/phase2-api.md 第 6.1 节）。' % report['relays'])
    if report.get('base_url'):
        lines.append('  · 旧订阅链接的地址是 %s：要让大家手里的旧链接继续能用，这个地址必须指向新服务器（域名就改解析；'
                     '如果是 IP，旧链接就没法继续用了，只能把新链接发给每个人）。' % report['base_url'])
    if report.get('top_unknown'):
        lines.append('  · 旧 settings.json 里这些设置没有导入：%s。' % '、'.join(report['top_unknown'][:20]))
    if report.get('user_unknown'):
        lines.append('  · 旧账号里这些字段没有导入：%s。' % '、'.join('%s（%d 个账号）' % kv for kv in report['user_unknown'][:20]))
    if report.get('time_zone'):
        lines.append('  · 新面板已经设了重置时区 %s，保留不动；旧系统按 UTC+8（新加坡时间）零点换月。' % report['time_zone'])
    else:
        lines.append('  · 面板的「每月重置按哪个时区」设成了 UTC+8，和旧系统一样按新加坡时间零点换月。')
    if report.get('lines'):
        ln = report['lines']
        lines.append('  · 沿用旧服务器的 Reality 私钥、short_id 和伪装网站 %s，端口 %d：旧链接里的 Reality 不用更新就能连。'
                     % (ln['reality_target'], ln['reality_port']))
        if ln.get('hy2_enabled'):
            lines.append('  · Hysteria 2 沿用端口 %d 和跳端口 %s。' % (ln['hy2_port'], ln['hy2_hop_range']))
    lines.append('  · TUIC 改用每个人的 Reality UUID 和 Hysteria 2 密码：用订阅的人更新一次订阅就好，手填 TUIC 的要重新填。')
    if rules_report:
        r = rules_report
        n = sum(len(settings.get(k) or []) for k in LIST_KEY.values())
        lines.append('分流规则：旧模板 %d 条，写进了自定义名单（直连 %d / 代理 %d / 拦截 %d，共 %d 条）。'
                     % (r['total'], len(settings.get('custom_direct') or []), len(settings.get('custom_proxy') or []),
                        len(settings.get('custom_block') or []), n))
        if r['ai']:
            lines.append('  · %d 条 AI 网站规则交给 vps2vpn 自带的 “AI” 分组，不写进名单。' % r['ai'])
        if r['dead']:
            lines.append('  · %d 条在旧模板里被更早的规则盖住、从来没生效过，跳过。' % r['dead'])
        if r['exact']:
            lines.append('  · %d 条 DOMAIN（只管一个域名）在 vps2vpn 里会连它的子域名一起管。' % r['exact'])
        if r['keyword']:
            lines.append('  · %d 条 DOMAIN-KEYWORD 规则 vps2vpn 名单不支持，没有导入。' % r['keyword'])
        if r['ip']:
            lines.append('  · %d 条 IP 规则（IP-CIDR 等）vps2vpn 名单不支持，没有导入。' % r['ip'])
        if r['other'] or r['bad']:
            lines.append('  · %d 条其他类型或格式不对的规则没有导入。' % (r['other'] + r['bad']))
        for target, count in sorted(r['unknown_target'].items()):
            lines.append('  · %d 条规则走 “%s” 分组，不知道该放进哪个名单，没有导入（可用 --map %s=proxy|direct|block 指定）。'
                         % (count, target, target))
        for d, to, a, ato in r['shadowed'][:20]:
            lines.append('  · %s 放在%s名单，但它的上级域名 %s 在%s名单里，vps2vpn 会先按 %s 处理。'
                         % (d, NAMES[to], a, NAMES[ato], NAMES[ato]))
        if len(r['shadowed']) > 20:
            lines.append('  · 还有 %d 条同样的情况。' % (len(r['shadowed']) - 20))
        big = [NAMES[k] for k, key in LIST_KEY.items() if len(settings.get(key) or []) > PANEL_LIST_MAX]
        if big:
            lines.append('  · 注意：%s名单超过 %d 条。恢复备份没问题，但现在的面板设置页保存时会拒绝这么长的名单。'
                         % ('、'.join(big), PANEL_LIST_MAX))
    return '\n'.join(lines)


NAMES = {'block': '拦截', 'direct': '直连', 'proxy': '代理'}


def write_private(path, data):
    """The merged backup holds every account's UUID, passwords and subscription token: readable by its owner
    only (0600), written whole or not at all."""
    # a new file of its own (0600, a name nobody else holds) next to the output, renamed over it at the end
    fd, tmp = tempfile.mkstemp(prefix=os.path.basename(path) + '.', suffix='.tmp',
                               dir=os.path.dirname(os.path.abspath(path)))
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            if hasattr(os, 'fchmod'):
                os.fchmod(f.fileno(), 0o600)        # whatever the umask
            json.dump(data, f, ensure_ascii=False, indent=1)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def main(argv=None):
    ap = argparse.ArgumentParser(description='把旧 legend 面板的账号（和分流规则）合并进 vps2vpn 备份文件。')
    ap.add_argument('--base', required=True, help='新 vps2vpn 面板导出的备份 JSON')
    ap.add_argument('--settings', required=True, help='旧面板 settings.json 的副本')
    ap.add_argument('--usage', required=True, help='旧面板 usage.sqlite3 的副本')
    ap.add_argument('--template', help='旧面板 template.json 的副本（导入分流规则时才需要）')
    ap.add_argument('--map', action='append', default=[], metavar='分组=proxy|direct|block',
                    help='旧模板里其他分组名该放进哪个名单')
    ap.add_argument('--lines', help='旧线路设置的副本（/etc/legend-tiered/config.json）：沿用 Reality 私钥和端口，旧链接不断')
    ap.add_argument('-o', '--output', required=True, help='写出的新备份文件（不能和输入同名）')
    ap.add_argument('--now', type=int, help=argparse.SUPPRESS)
    a = ap.parse_args(argv)
    now = a.now if a.now is not None else int(dt.datetime.now(dt.timezone.utc).timestamp())
    try:
        inputs = (a.base, a.settings, a.usage, a.template, a.lines)
        # A symlink in a parent directory can make different spellings replace the same input.
        ins = {os.path.normcase(os.path.realpath(p)) for p in inputs if p}
        if os.path.normcase(os.path.realpath(a.output)) in ins:
            raise Problem('-o 不能覆盖输入文件')
        targets = dict(TARGETS)
        for m in a.map:
            k, _, v = m.partition('=')
            if v not in ('proxy', 'direct', 'block') or not k:
                raise Problem('--map 要写成 分组名=proxy、direct 或 block')
            targets[k] = v
        base = read_json(a.base, '新面板备份')
        legend = read_json(a.settings, '旧面板 settings.json')
        users = [u for u in (legend.get('users') or []) if isinstance(u, dict) and 'id' in u] if isinstance(legend, dict) else []
        out, report = import_users(base, legend, read_usage(a.usage, users, now), now)
        rules_report = None
        if a.template:
            template = read_json(a.template, '旧模板 template.json')
            if not isinstance(template, dict):
                raise Problem('旧模板 template.json 不是对象')
            lists, rules_report = convert_rules(template.get('rules'), targets)
            out = merge_rules(out, lists)
        if a.lines:
            report['lines'] = convert_lines(read_json(a.lines, '旧线路设置 config.json'))
            out = merge_lines(out, report['lines'])
        write_private(a.output, out)
    except Problem as e:
        print('没有写出文件：%s' % e, file=sys.stderr)
        return 2
    print(describe(report, rules_report, out.get('settings') or {}))
    print('已写出 %s。在新面板 设置 → 恢复备份 里选这个文件。' % a.output)
    return 0


if __name__ == '__main__':
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    sys.exit(main())
