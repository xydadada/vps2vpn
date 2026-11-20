"""Abuse guard: notice accounts that behave like a scanner, a botnet relay or a link shared with strangers.

Observation only - it never pauses anyone by itself. It reads what the cores already expose:
  * Hysteria 2  /dump/streams       - every open TCP stream with its user and destination
  * TUIC        Clash API connections - user, destination and client address of each connection
  * Xray/TUIC   online IP lists     - how many different client addresses use one account
Short-lived connections and Xray destinations are invisible here, so a quiet result is not proof of
innocence and a flag is a reason to look, not a verdict. Flags go to the event log and Telegram.
"""
import json
import threading
import time
import urllib.request

from . import cores, db, notify

FANOUT_TARGETS = 100       # distinct destinations...
FANOUT_PORTS = 20          # ...on many different ports...
FANOUT_STREAMS = 200       # ...with many streams at once: looks like scanning or a proxy for a botnet
SHARED_IPS = 8             # this many client addresses on one account at once: the link has probably spread
MAIL_PORTS = {25, 465, 587}

_last = {'at': 0, 'accounts': {}, 'coverage': []}
_last_lock = threading.Lock()
_check_lock = threading.Lock()     # two overlapping rounds must not both log/announce the same flag


def _hy2_streams(s):
    req = urllib.request.Request('http://127.0.0.1:%d/dump/streams' % s['hy2_stats_port'],
                                 headers={'Authorization': s['stats_secret']})
    with urllib.request.urlopen(req, timeout=4) as r:
        return json.loads(r.read()).get('streams') or []


def aggregate(flows, online=None):
    """flows: iterable of (uid, host, port). online: {uid: {'ips': [...], 'devices': n}}. Returns {uid: report}."""
    acc = {}
    for uid, host, port in flows:
        a = acc.setdefault(uid, {'streams': 0, 'targets': set(), 'ports': set(), 'mail': 0})
        a['streams'] += 1
        a['targets'].add((host or '').lower())
        a['ports'].add(port)
        if port in MAIL_PORTS:
            a['mail'] += 1
    for uid in (online or {}):
        acc.setdefault(uid, {'streams': 0, 'targets': set(), 'ports': set(), 'mail': 0})
    out = {}
    for uid, a in acc.items():
        info = (online or {}).get(uid, {})
        ips = len(info.get('ips', []))
        devices = max(ips, int(info.get('devices', 0) or 0))
        flags = []
        if len(a['targets']) >= FANOUT_TARGETS and len(a['ports']) >= FANOUT_PORTS and a['streams'] >= FANOUT_STREAMS:
            flags.append('fanout')
        if devices >= SHARED_IPS:
            flags.append('shared')
        if a['mail'] >= 20:
            flags.append('mail')
        out[uid] = {'streams': a['streams'], 'targets': len(a['targets']), 'ports': len(a['ports']),
                    'mail': a['mail'], 'ips': ips, 'devices': devices, 'flags': flags}
    return out


def split_addr(addr):
    """'host:port' or '[v6]:port' -> (host, port); anything else (bare v6, no/invalid port) -> None."""
    addr = str(addr or '').strip()
    if addr.startswith('['):
        host, sep, port = addr[1:].partition(']:')
    else:
        if addr.count(':') != 1:
            return None
        host, sep, port = addr.partition(':')
    # A remote stream address is telemetry, not a trusted integer. Reject
    # Unicode numeric characters and enormous decimal strings before int().
    if (not sep or not host or not 1 <= len(port) <= 5
            or not port.isascii() or not port.isdecimal()):
        return None
    number = int(port)
    return (host, number) if 1 <= number <= 65535 else None


def scan(s=None):
    s = s or db.settings()
    flows, coverage = [], []
    if s['hy2_enabled']:
        try:
            for st in _hy2_streams(s):
                if not isinstance(st, dict):
                    continue
                auth = st.get('auth')
                hp = split_addr(st.get('req_addr'))
                if not isinstance(auth, str) or not auth.startswith('u') or not hp:
                    continue
                digits = auth[1:]
                if not digits or len(digits) > 19 or not digits.isascii() or not digits.isdecimal():
                    continue
                uid = int(digits)
                if 0 < uid <= 9223372036854775807:
                    flows.append((uid, hp[0], hp[1]))
            coverage.append('hy2')
        except (OSError, ValueError):
            pass
    if s['tuic_enabled']:
        try:
            for c in cores.TuicMeter.poll(s, 3).get('connections') or []:
                if not isinstance(c, dict):
                    continue
                m = c.get('metadata')
                if not isinstance(m, dict):
                    continue
                port = str(m.get('destinationPort', ''))
                if not port or len(port) > 5 or not port.isascii() or not port.isdecimal():
                    continue
                port_num = int(port)
                if not 1 <= port_num <= 65535:
                    continue
                try:
                    uid = cores.TuicMeter.owner(c)
                except (TypeError, ValueError, AttributeError):
                    # One malformed connection must not discard the whole snapshot.
                    continue
                if uid is not None:
                    flows.append((uid, m.get('host') or m.get('destinationIP') or '', port_num))
            coverage.append('tuic')
        except (OSError, ValueError):
            pass
    online = cores.online_detail(s, max_age=0) or {}
    if s['reality_enabled']:
        coverage.append('reality-ips')
    rep = aggregate(flows, online)
    with _last_lock:
        _last.update(at=int(time.time()), accounts=rep, coverage=coverage)
    return rep


def check(s=None, log=print):
    """One round: scan, and record/announce newly flagged accounts (once a day per account and kind)."""
    with _check_lock:
        s = s or db.settings()
        if not s.get('abuse_guard', True):
            return {}
        rep = scan(s)
        names = {u['id']: u['name'] for u in db.users()}
        words = {'fanout': ('connects to hundreds of targets on many ports (scanner or relay?)', '短时间连了几百个目标和端口（像扫描或被当跳板）'),
                 'shared': ('used from many addresses at once (link shared?)', '同时有很多个 IP 在用（链接可能被转发了）'),
                 'mail': ('sends lots of mail traffic (spam?)', '大量发邮件端口连接（可能在发垃圾邮件）')}
        day = time.strftime('%Y-%m-%d')
        for uid, r in rep.items():
            for f in r['flags']:
                key = 'abuse-%s-%d-%s' % (f, uid, day)
                if db.q('SELECT 1 FROM events WHERE kind=? AND detail LIKE ?', ('abuse', key + '%')):
                    continue
                name = names.get(uid, '#%d' % uid)
                db.add_event('abuse', uid, '%s | %s: %s | streams %d, targets %d, ports %d, devices %d' % (
                    key, name, words[f][0], r['streams'], r['targets'], r['ports'], r['devices']))
                log('abuse guard: %s %s' % (name, words[f][0]))
                notify.send('%s: %s / %s：%s（不会自动停用，请到面板查看）' % (name, words[f][0], name, words[f][1]),
                            key=key, every=86400)
        return rep


def latest():
    names = {u['id']: u['name'] for u in db.users()}
    with _last_lock:
        snap = dict(_last)
        accounts = dict(snap['accounts'])
        coverage = list(snap['coverage'])
    rows = [dict(r, id=uid, name=names.get(uid, '#%d' % uid)) for uid, r in accounts.items()]
    rows.sort(key=lambda r: (-len(r['flags']), -r['streams']))
    events = []
    for e in db.events('abuse', 50):
        _, _, text = e['detail'].partition(' | ')
        events.append({'at': e['at'], 'user_id': e['user_id'], 'text': text})
    return {'at': snap['at'], 'coverage': coverage, 'accounts': rows, 'events': events,
            'thresholds': {'targets': FANOUT_TARGETS, 'ports': FANOUT_PORTS, 'streams': FANOUT_STREAMS, 'ips': SHARED_IPS}}
