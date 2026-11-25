"""Server status the admin announces: maintenance or congested, with a note and an optional end (docs/phase2-api.md
section 3). This server's own is the setting `node_status`; a joined server's is `status` in its `servers` entry.
Both look like {"state": "maintenance", "note": "...", "until": 1795012200}; until 0 = until changed by hand.

Sent to our app in api/me (`nodes`) when the owner turns on `client_node_status`. The subscription files never
change because of it (third-party apps keep their node list); a server in maintenance is named in the
subscription's Announce header and on the member page."""
import datetime as dt
import re
import time

from . import clock, db

STATES = ('ok', 'maintenance', 'congested')
NOTE_MAX = 100
UNTIL_MAX_DAYS = 366
OK = {'state': 'ok', 'note': '', 'until': 0}


def _note(text):
    """One line, no control characters, at most NOTE_MAX characters."""
    text = ''.join(' ' if c in '\r\n\t' else c for c in str(text or '') if c in '\r\n\t' or ord(c) >= 32)
    text = re.sub(r'[​-‏ -‮⁠-⁯﻿]', '', text)
    return re.sub(r' {2,}', ' ', text).strip()[:NOTE_MAX]


def until_of(text):
    """'YYYY-MM-DDTHH:MM' (or with a space) in the owner's time zone -> seconds since the epoch."""
    m = re.fullmatch(r'\s*(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2})(?::\d{2})?\s*', str(text))
    if not m:
        raise ValueError('until: expected YYYY-MM-DD HH:MM')
    y, mo, d, hh, mm = (int(x) for x in m.groups())
    dt.date(y, mo, d)                                   # ValueError for 2026-02-30
    if hh > 23 or mm > 59:
        raise ValueError('until: expected YYYY-MM-DD HH:MM')
    return clock.midnight(y, mo, d) + hh * 3600 + mm * 60


def clean(d, now=None):
    """A status from the panel -> what is stored. Raises ValueError with an English reason."""
    if not isinstance(d, dict):
        raise ValueError('status: expected an object')
    now = int(now or time.time())
    state = d.get('state', 'ok')
    if state not in STATES:
        raise ValueError('state must be ok, maintenance or congested')
    if state == 'ok':
        return dict(OK)
    note = d.get('note', '')
    if not isinstance(note, str):
        raise ValueError('note must be text')
    until = 0
    if d.get('until_local'):
        until = until_of(d['until_local'])
    elif d.get('until'):
        if type(d['until']) is not int:
            raise ValueError('until: expected a time')
        until = d['until']
    if until and not now < until <= now + UNTIL_MAX_DAYS * 86400:
        raise ValueError('until must be in the future (within a year)')
    return {'state': state, 'note': _note(note), 'until': until}


def current(st, now=None):
    """The status in force: anything unreadable (a hand-edited backup) or past its end is "ok"."""
    if not isinstance(st, dict) or st.get('state') not in STATES or st.get('state') == 'ok':
        return dict(OK)
    until = st.get('until') or 0
    if type(until) is not int or until < 0:
        return dict(OK)
    if until and until <= (now or time.time()):
        return dict(OK)
    note = st.get('note') if isinstance(st.get('note'), str) else ''
    return {'state': st['state'], 'note': note[:NOTE_MAX], 'until': until}


def of(s, sid, now=None):
    if sid == db.MAIN_SERVER:
        return current(s.get('node_status'), now)
    x = next((x for x in s.get('servers') or [] if x.get('id') == sid), None)
    return current((x or {}).get('status'), now)


def on(s):
    return s.get('client_node_status') is True          # a hand-edited backup's "false" stays off


def view(st):
    """For the panel: adds the end as the owner's local time for a datetime-local input."""
    return dict(st, until_local=clock.strftime('%Y-%m-%dT%H:%M', st['until']) if st['until'] else '')


def panel_list(s, now=None):
    """[{id, name, state, note, until, until_local}] this server first, for the panel's Servers page."""
    out = [dict(view(of(s, db.MAIN_SERVER, now)), id=db.MAIN_SERVER, name=s.get('node_name') or 'vps2vpn')]
    for x in s.get('servers') or []:
        out.append(dict(view(current(x.get('status'), now)), id=x['id'], name=x['name']))
    return out


def set_status(sid, d):
    """Save a status from the panel. Returns the stored value; ValueError for bad input or an unknown server."""
    from . import cluster
    st = clean(d)
    if sid == db.MAIN_SERVER:
        db.set_settings(node_status=st)
        return st
    with cluster._lock:
        servers = db.settings()['servers']
        x = next((x for x in servers if x['id'] == sid), None)
        if x is None:
            raise LookupError('no such server')
        x['status'] = st
        db.set_settings(servers=servers)
    return st


def for_member(s, u, now=None):
    """api/me "nodes": the servers this account gets, in subscription order, with the exact group and entry names
    of its Clash / sing-box subscription, so the app matches a status to its nodes without guessing."""
    from . import subscription
    ns = subscription.nodes(s, u)
    sid_of = {}
    for n in ns:
        sid_of.setdefault(n['group'], n.get('server_id', db.MAIN_SERVER))
    out = []
    for group, names in subscription.server_groups(ns):
        sid = sid_of[group]
        out.append(dict(of(s, sid, now), id=sid, group=group, names=names))
    return out


def maintenance_text(s, u, now=None):
    """'Tokyo: tonight 23:00-23:30' lines for the servers this account can use that are in maintenance ('' if
    none): the Announce header (Hiddify, Happ...) and the member page. Cheap: no node list is built."""
    items = []
    if db.allowed_on(u, db.MAIN_SERVER):
        items.append((s.get('node_name') or 'vps2vpn', of(s, db.MAIN_SERVER, now)))
    for x in s.get('servers') or []:
        if (x.get('enabled', True) and x.get('info') and str(u['id']) in (x.get('idmap') or {})
                and db.allowed_on(u, x['id'])):
            items.append((x['name'], current(x.get('status'), now)))
    parts = ['%s%s' % (name, ('：' + st['note']) if st['note'] else '') for name, st in items
             if st['state'] == 'maintenance']
    return '；'.join(parts[:3]) + ('…' if len(parts) > 3 else '')
