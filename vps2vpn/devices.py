"""Devices the vps2vpn app reports, and the soft kick (docs/phase2-api.md section 2).

The app makes a random device id on first run and reports it (with a name, platform and version) when it
connects and every 30 minutes. The member and the admin see the list; "revoke" marks one device, and our app
then disconnects and shows it as removed the next time it reports (it keeps the subscription, so "Restore"
needs no re-import). Every device of an account shares the same proxy credentials, so a revoked device that
ignores this (another app, a modified one) still connects: only a new subscription link (the hard kick) stops
everything.

The list is for seeing, never for enforcing: the device limit (`max_ips`) keeps counting the addresses the cores
report, because a device list sent by the app can be made up. Not in backups; gone with the account; a device
not seen for 90 days is forgotten."""
import re
import time

from . import db, feedback

PLATFORMS = ('windows', 'android', 'macos', 'linux', 'ios')
NAME_MAX = 40
VERSION_MAX = 32
PER_USER = 50
REPORT_GAP = 60                   # one report a minute per device
KEEP_DAYS = 90
KICK_MAX = 3                      # new links per account and hour, from the app
UUID_RE = feedback.UUID_RE

_kicks = {}                       # user id -> [times]


class Refused(feedback.Refused):
    pass


def on(s):
    return s.get('client_devices') is True


def _line(v, name, limit):
    if not isinstance(v, str):
        raise Refused('%s must be text' % name)
    v = ''.join(c for c in v if ord(c) >= 32 and ord(c) != 127)
    v = re.sub(r'[​-‏ -‮⁠-⁯﻿]', '', v).strip()
    if len(v) > limit:
        raise Refused('%s: at most %d characters' % (name, limit))
    return v


def device_id(v):
    if not (isinstance(v, str) and UUID_RE.fullmatch(v)):
        raise Refused('device_id must be a lowercase UUID')
    return v


def report(u, d, ip, now=None):
    """The app's report. Returns True when this device has been revoked. Raises Refused (429 within a minute)."""
    did = device_id(d.get('device_id'))
    name = _line(d.get('name', ''), 'name', NAME_MAX)
    platform = d.get('platform', '')
    if platform not in PLATFORMS:
        raise Refused('platform must be one of ' + ', '.join(PLATFORMS))
    version = _line(d.get('version', ''), 'version', VERSION_MAX)
    now = int(now or time.time())
    masked = feedback.mask_ips(ip or '')
    with db.transaction() as c:
        row = c.execute('SELECT last_seen, revoked FROM devices WHERE user_id=? AND device_id=?', (u['id'], did)).fetchone()
        if row:
            if 0 <= now - row['last_seen'] < REPORT_GAP:
                raise Refused('reported less than a minute ago', 'rate_limited', 429, REPORT_GAP - (now - row['last_seen']))
            c.execute('UPDATE devices SET name=?, platform=?, version=?, last_seen=?, ip=? WHERE user_id=? AND device_id=?',
                      (name, platform, version, now, masked, u['id'], did))
            return bool(row['revoked'])
        c.execute('INSERT INTO devices(user_id, device_id, name, platform, version, first_seen, last_seen, ip) '
                  'VALUES(?,?,?,?,?,?,?,?)', (u['id'], did, name, platform, version, now, now, masked))
        c.execute('DELETE FROM devices WHERE user_id=? AND device_id NOT IN (SELECT device_id FROM devices '
                  'WHERE user_id=? ORDER BY last_seen DESC LIMIT ?)', (u['id'], u['id'], PER_USER))
    return False


def listing(uid, this=''):
    rows = db.q('SELECT device_id, name, platform, version, first_seen, last_seen, ip, revoked FROM devices '
                'WHERE user_id=? ORDER BY last_seen DESC', (uid,))
    return [dict(r, revoked=bool(r['revoked']), this_device=bool(this) and r['device_id'] == this) for r in rows]


def set_revoked(uid, did, revoked):
    """False when the account has no such device."""
    with db.transaction() as c:
        return c.execute('UPDATE devices SET revoked=? WHERE user_id=? AND device_id=?',
                         (1 if revoked else 0, uid, did)).rowcount > 0


def forget_others(uid, keep=''):
    """After a new subscription link: every other device has to import it again, so they are forgotten."""
    with db.transaction() as c:
        c.execute('DELETE FROM devices WHERE user_id=? AND device_id!=?', (uid, keep or ''))


def kick_allowed(uid, now=None):
    """At most KICK_MAX new links an hour from the app. Returns seconds to wait (0 = go ahead, and counted)."""
    now = now or time.time()
    times = [t for t in _kicks.get(uid, []) if now - t < 3600]
    if len(times) >= KICK_MAX:
        _kicks[uid] = times
        return max(1, int(times[0] + 3600 - now))
    _kicks[uid] = times + [now]
    return 0


def recent_names(uid, now=None, within=3600):
    """Names of the devices that reported within the last hour (for the device-limit notice)."""
    since = int(now or time.time()) - within
    return [r[0] or '?' for r in db.q('SELECT name FROM devices WHERE user_id=? AND last_seen>=? '
                                       'ORDER BY last_seen DESC LIMIT 8', (uid, since))]


def prune(now=None):
    with db.transaction() as c:
        return c.execute('DELETE FROM devices WHERE last_seen<?', (int(now or time.time()) - KEEP_DAYS * 86400,)).rowcount
