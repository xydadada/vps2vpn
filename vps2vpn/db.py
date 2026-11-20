"""SQLite storage: settings, users, sessions, daily traffic, invite codes, quota requests and events."""
import contextlib
import itertools
import json
import math
import os
import re
import sqlite3
import threading
import time

from . import paths, secure

_lock = threading.RLock()
_conn = None
_savepoints = itertools.count()

SCHEMA = """
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    uuid TEXT NOT NULL,
    hy2_pass TEXT NOT NULL,
    sub_token TEXT NOT NULL UNIQUE,
    quota_gb REAL NOT NULL DEFAULT 0,
    expire_at INTEGER NOT NULL DEFAULT 0,
    reset_day INTEGER NOT NULL DEFAULT 0,
    used_up INTEGER NOT NULL DEFAULT 0,
    used_down INTEGER NOT NULL DEFAULT 0,
    enabled INTEGER NOT NULL DEFAULT 1,
    disabled_reason TEXT NOT NULL DEFAULT '',
    note TEXT NOT NULL DEFAULT '',
    last_seen INTEGER NOT NULL DEFAULT 0,
    last_reset TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS traffic (
    day TEXT NOT NULL, user_id INTEGER NOT NULL, up INTEGER NOT NULL DEFAULT 0, down INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (day, user_id));
CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS member_sessions (token TEXT PRIMARY KEY, user_id INTEGER NOT NULL, expires INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS invites (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT NOT NULL UNIQUE,
    kind TEXT NOT NULL,                       -- 'admin' or 'member'
    inviter INTEGER NOT NULL DEFAULT 0,       -- member codes: the user whose quota is shared
    quota_gb REAL NOT NULL DEFAULT 0,         -- what each new account gets
    expire_days INTEGER NOT NULL DEFAULT 0,   -- admin codes: account lifetime (0 = never expires)
    reset_day INTEGER NOT NULL DEFAULT 0,
    max_uses INTEGER NOT NULL DEFAULT 1,
    uses INTEGER NOT NULL DEFAULT 0,
    used_by TEXT NOT NULL DEFAULT '',         -- comma-separated user ids
    valid_until INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'unused',    -- unused | used | revoked
    note TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, add_gb REAL NOT NULL, reason TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'pending', answer TEXT NOT NULL DEFAULT '', created_at INTEGER NOT NULL,
    decided_at INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT, at INTEGER NOT NULL, kind TEXT NOT NULL, user_id INTEGER NOT NULL DEFAULT 0,
    detail TEXT NOT NULL DEFAULT '');
"""

# Columns added after the first release; created on start-up when missing.
MIGRATIONS = {
    'users': [('login_hash', "TEXT NOT NULL DEFAULT ''"),        # member-centre password (empty = link only)
              ('invited_by', 'INTEGER NOT NULL DEFAULT 0'),
              ('invite_deduct', 'REAL NOT NULL DEFAULT 0'),        # GB carved out of the inviter's quota
              ('remote_id', 'INTEGER NOT NULL DEFAULT 0'),         # set on a joined node: the main server's user id
              ('traffic_epoch', 'INTEGER NOT NULL DEFAULT 0'),
              ('max_ips', 'INTEGER NOT NULL DEFAULT 0'),           # device limit (0 = none)
              ('paused_until', 'INTEGER NOT NULL DEFAULT 0'),      # end of a short pause for too many devices
              ('expire_after_days', 'INTEGER NOT NULL DEFAULT 0')],  # lifetime that starts on first use
}

# Everything the panel can be configured with, and the defaults a fresh install starts from.
DEFAULTS = {
    'setup_done': False,
    'language': 'zh',
    'admin_user': 'admin',
    'admin_hash': '',
    'admin_totp': '',           # base32 TOTP secret; empty = no second factor
    'ip_limit_pause': True,     # over a user's device limit: pause 10 minutes (False = only warn)
    'panel_port': 0,            # chosen at install time
    'panel_path': '',           # secret URL prefix for the admin panel
    'public_host': '',          # IP or domain written into subscriptions
    'public_ipv6': '',
    'node_name': 'vps2vpn',
    # VLESS + REALITY (TCP)
    'reality_enabled': True,
    'reality_port': 443,
    'reality_target': 'www.amd.com',
    'reality_private_key': '',
    'reality_public_key': '',
    'reality_short_id': '',
    # Hysteria 2 (UDP)
    'hy2_enabled': True,
    'hy2_port': 443,
    'hy2_hop': True,            # UDP port hopping: clients spread over a port range
    'hy2_hop_range': '20000-40000',
    'hy2_obfs': '',             # salamander password; empty = off (faster, looks like HTTP/3)
    'hy2_masquerade': 'https://www.bing.com',
    # TUIC v5 (UDP, served by sing-box): a second QUIC protocol to switch to when Hysteria is throttled
    'tuic_enabled': True,
    'tuic_port': 8443,
    # Certificates: 'auto' = Let's Encrypt (domain or IP), falls back to self-signed
    'cert_mode': 'auto',
    'domain': '',
    'acme_email': '',
    'cert_status': '',
    # Routing in client subscriptions
    'block_ads': True,
    'block_bt': True,           # stop BitTorrent through the server (abuse complaints)
    'ai_group': True,
    'custom_direct': [],        # owner's own domain lists, ahead of every built-in rule
    'custom_proxy': [],
    'custom_block': [],
    # Server tuning
    'tune_network': True,
    'ipv6_nodes': False,        # also list IPv6 entries (when the server has public IPv6)
    # Telegram alerts
    'tg_token': '',
    'tg_chat': '',
    'tg_backup': True,          # send the daily backup to the Telegram chat as well
    'tg_bot': True,             # answer /status, /users, /backup ... from the owner's chat
    'stats_secret': '',
    'traffic_api_port': 10085,
    'hy2_stats_port': 10086,
    'tuic_api_port': 10087,
    # Member centre: people log in with their own name and password, see usage, ask for more, invite friends
    'member_path': '',          # secret URL prefix of the member centre (separate from the admin panel)
    'member_enabled': True,
    'member_invites': True,     # members may share part of their quota through invite codes
    'member_requests': True,    # members may ask the admin for more quota
    'member_notice': '',        # short message from the admin shown at the top of every member page
    # Server-wide monthly traffic (many providers bill or cap it)
    'server_cap_gb': 0,         # 0 = no cap; alerts at 80% and 100%
    'server_reset_day': 1,
    'server_month': {},
    'vps_renew_at': '',         # 'YYYY-MM-DD' the VPS plan must be renewed (reminders 7, 3 and 1 days before)
    'vps_renew_note': '',       # where to renew, e.g. 'AWS Lightsail' (shown in the reminder)
    'line_reports': {},
    # vps2vpn app updates: set by hand, or found in /var/lib/vps2vpn/client (newest file wins when no version is set)
    'client_version': '',
    'client_url': '',
    'client_notes': '',         # {'hy2': {'<user id>': [time, host]}} lines the apps say they cannot reach         # {'period': 'YYYY-MM', 'rx': bytes, 'tx': bytes, 'last_rx':..., 'last_tx':...}
    # Watching
    'monitor_enabled': True,    # probe GitHub/YouTube/ChatGPT/Google/X from the server every 5 minutes
    'abuse_guard': True,        # flag (never ban) accounts that fan out to hundreds of targets and ports
    # Several servers, one subscription. On a node: the key the main server uses. On the main server: the node list.
    'node_key': '',
    'node_master': '',          # set on a node once a main server has synced with it (its name)
    'node_master_id': '',       # ...and its identity: a second, different main server is refused
    'install_id': '',           # random identity of this install (sent to nodes as the main server's id)
    'servers': [],              # main server: [{id, name, url, key, pin, info, idmap, last_ok, error}]
}

_DEFAULT_SNAPSHOT = json.dumps(DEFAULTS)


def connect():
    global _conn
    with _lock:
        if _conn is None:
            paths.ensure_dirs()
            _conn = sqlite3.connect(paths.DB, check_same_thread=False, isolation_level=None)
            _conn.row_factory = sqlite3.Row
            _conn.execute('PRAGMA journal_mode=WAL')
            # Keys and password hashes live here: owner-only, even inside the owner-only data directory.
            # (SQLite gives the -wal/-shm files the same mode as the database.)
            for f in (paths.DB, paths.DB + '-wal', paths.DB + '-shm'):
                try:
                    os.chmod(f, 0o600)
                except OSError:
                    pass
            _conn.executescript(SCHEMA)
            for table, cols in MIGRATIONS.items():
                have = {r[1] for r in _conn.execute('PRAGMA table_info(%s)' % table)}
                for name, decl in cols:
                    if name not in have:
                        _conn.execute('ALTER TABLE %s ADD COLUMN %s %s' % (table, name, decl))
        return _conn


def close():
    global _conn
    with _lock:
        if _conn is not None:
            _conn.close()
            _conn = None


def q(sql, args=()):
    with _lock:
        return connect().execute(sql, args).fetchall()


def x(sql, args=()):
    with _lock:
        cur = connect().execute(sql, args)
        return cur.lastrowid


@contextlib.contextmanager
def transaction():
    """Keep multi-step mutations atomic, including calls to other database helpers."""
    with _lock:
        c = connect()
        savepoint = 'v2v_%d' % next(_savepoints) if c.in_transaction else None
        c.execute('SAVEPOINT ' + savepoint if savepoint else 'BEGIN IMMEDIATE')
        try:
            yield c
            c.execute('RELEASE ' + savepoint if savepoint else 'COMMIT')
        except BaseException:
            if c.in_transaction:
                if savepoint:
                    c.execute('ROLLBACK TO ' + savepoint)
                    c.execute('RELEASE ' + savepoint)
                else:
                    c.execute('ROLLBACK')
            raise


# --- settings -----------------------------------------------------------------
def settings():
    out = json.loads(_DEFAULT_SNAPSHOT)
    for row in q('SELECT key, value FROM settings'):
        out[row['key']] = json.loads(row['value'])
    return out


def set_settings(**kv):
    with transaction() as c:
        for k, v in kv.items():
            if k not in DEFAULTS:
                raise KeyError(k)
            c.execute('INSERT INTO settings(key, value) VALUES(?, ?) '
                      'ON CONFLICT(key) DO UPDATE SET value=excluded.value', (k, json.dumps(v, allow_nan=False)))


def ensure_secrets():
    """Fill in keys a fresh install needs. Never overwrites existing ones."""
    with transaction():
        return _ensure_secrets()


def _ensure_secrets():
    s = settings()
    new = {}
    if not s['reality_private_key']:
        new['reality_private_key'], new['reality_public_key'] = secure.reality_keypair()
    if not s['reality_short_id']:
        new['reality_short_id'] = secure.short_id()
    if not s['stats_secret']:
        new['stats_secret'] = secure.token(18)
    if not s['panel_path']:
        new['panel_path'] = secure.token(9).replace('-', 'x').replace('_', 'y')
    if not s['member_path']:
        new['member_path'] = secure.token(6).replace('-', 'x').replace('_', 'y')
    if not s['node_key']:
        new['node_key'] = secure.token(24)
    if not s['install_id']:
        new['install_id'] = secure.token(12)
    if new:
        set_settings(**new)
    return settings()


# --- users --------------------------------------------------------------------
USER_FIELDS = ('name', 'quota_gb', 'expire_at', 'reset_day', 'enabled', 'note', 'max_ips', 'expire_after_days')


def users():
    return [dict(r) for r in q('SELECT * FROM users ORDER BY id')]


def user(uid):
    rows = q('SELECT * FROM users WHERE id=?', (uid,))
    return dict(rows[0]) if rows else None


def user_by_token(token):
    rows = q('SELECT * FROM users WHERE sub_token=?', (token,))
    return dict(rows[0]) if rows else None


def add_user(name, quota_gb=0, expire_at=0, reset_day=0, note='', **extra):
    with transaction():
        if user_by_name(name):
            raise ValueError('that user name already exists')
        uid = x('INSERT INTO users(name, uuid, hy2_pass, sub_token, quota_gb, expire_at, reset_day, note, created_at) '
                'VALUES(?,?,?,?,?,?,?,?,?)',
                (name, secure.new_uuid(), secure.token(18), secure.token(18), float(quota_gb), int(expire_at),
                 int(reset_day), note, int(time.time())))
        if extra:
            update_user(uid, **extra)
    return uid


def user_by_name(name):
    rows = q('SELECT * FROM users WHERE name=? COLLATE NOCASE', (name,))
    return dict(rows[0]) if rows else None


def user_traffic(uid, days=30):
    since = time.strftime('%Y-%m-%d', time.localtime(time.time() - days * 86400))
    return [dict(r) for r in q('SELECT day, up, down FROM traffic WHERE user_id=? AND day>=? ORDER BY day', (uid, since))]


def traffic_by_user(days=30):
    since = time.strftime('%Y-%m-%d', time.localtime(time.time() - days * 86400))
    return {r['user_id']: (r['up'], r['down']) for r in
            q('SELECT user_id, SUM(up) up, SUM(down) down FROM traffic WHERE day>=? GROUP BY user_id', (since,))}


def update_user(uid, **kv):
    sets, args = [], []
    for k, v in kv.items():
        if k not in USER_FIELDS + ('disabled_reason', 'used_up', 'used_down', 'last_reset', 'last_seen', 'login_hash',
                                   'invited_by', 'invite_deduct', 'remote_id', 'uuid', 'hy2_pass', 'paused_until'):
            raise KeyError(k)
        sets.append(k + '=?')
        args.append(v)
    if sets:
        if 'used_up' in kv or 'used_down' in kv:
            sets.append('traffic_epoch=traffic_epoch+1')
        with transaction():
            if 'name' in kv:
                existing = user_by_name(kv['name'])
                if existing and existing['id'] != uid:
                    raise ValueError('name already used')
            x('UPDATE users SET %s WHERE id=?' % ','.join(sets), args + [uid])


def rotate_user(uid):
    """New credentials and link, e.g. after a link leaked."""
    x('UPDATE users SET uuid=?, hy2_pass=?, sub_token=? WHERE id=?',
      (secure.new_uuid(), secure.token(18), secure.token(18), uid))


def delete_user(uid):
    from . import members
    with transaction():
        u = user(uid)
        if u and u.get('invited_by') and u.get('invite_deduct', 0) > 0:
            # Keep consumed quota charged after the child account disappears. Do not
            # duplicate it in daily traffic: those bytes have already been measured.
            debt = min(int(u['invite_deduct'] * (1 << 30)), members.spent_bytes(u))
            x('UPDATE users SET used_down=used_down+? WHERE id=?', (debt, u['invited_by']))
        x('DELETE FROM users WHERE id=?', (uid,))
        x('DELETE FROM traffic WHERE user_id=?', (uid,))
        x('DELETE FROM member_sessions WHERE user_id=?', (uid,))
        x('DELETE FROM requests WHERE user_id=?', (uid,))
        x("UPDATE invites SET status='revoked' WHERE inviter=? AND status='unused'", (uid,))
        x('UPDATE users SET invited_by=0, invite_deduct=0 WHERE invited_by=?', (uid,))


def add_traffic(uid, up, down, now=None):
    if any(type(n) is not int or n < 0 or n > (1 << 63) - 1 for n in (up, down)):
        raise ValueError('traffic counters must be nonnegative integers')
    now = time.time() if now is None else now
    day = time.strftime('%Y-%m-%d', time.localtime(now))
    with transaction() as c:
        changed = c.execute('UPDATE users SET used_up=used_up+?, used_down=used_down+?, last_seen=? WHERE id=?',
                            (up, down, int(now), uid)).rowcount
        if not changed:
            return
        c.execute('INSERT INTO traffic(day, user_id, up, down) VALUES(?,?,?,?) ON CONFLICT(day, user_id) '
                  'DO UPDATE SET up=up+excluded.up, down=down+excluded.down', (day, uid, up, down))


def traffic_days(days=30):
    since = time.strftime('%Y-%m-%d', time.localtime(time.time() - days * 86400))
    return [dict(r) for r in q('SELECT day, SUM(up) up, SUM(down) down FROM traffic WHERE day>=? '
                                'GROUP BY day ORDER BY day', (since,))]


# --- sessions -----------------------------------------------------------------
def new_session(ttl=7 * 86400):
    tok = secure.token(32)
    now = int(time.time())
    x('DELETE FROM sessions WHERE expires<?', (now,))
    x('INSERT INTO sessions(token, expires) VALUES(?,?)', (tok, now + ttl))
    return tok


def session_ok(tok):
    return bool(tok) and bool(q('SELECT 1 FROM sessions WHERE token=? AND expires>?', (tok, int(time.time()))))


def end_session(tok):
    x('DELETE FROM sessions WHERE token=?', (tok,))


def end_all_sessions():
    x('DELETE FROM sessions')


def new_member_session(uid, ttl=8 * 3600):
    tok = secure.token(32)
    now = int(time.time())
    with transaction():
        if not user(uid):
            raise ValueError('no such user')
        x('DELETE FROM member_sessions WHERE expires<?', (now,))
        x('INSERT INTO member_sessions(token, user_id, expires) VALUES(?,?,?)', (tok, uid, now + ttl))
    return tok


def member_session(tok):
    if not tok:
        return None
    rows = q('SELECT user_id FROM member_sessions WHERE token=? AND expires>?', (tok, int(time.time())))
    return rows[0]['user_id'] if rows else None


def end_member_session(tok, uid=None):
    if uid is not None:
        x('DELETE FROM member_sessions WHERE user_id=?', (uid,))
    else:
        x('DELETE FROM member_sessions WHERE token=?', (tok,))


# --- invites, requests, events ---------------------------------------------------
def invites(inviter=None):
    if inviter is None:
        return [dict(r) for r in q('SELECT * FROM invites ORDER BY id DESC LIMIT 500')]
    return [dict(r) for r in q('SELECT * FROM invites WHERE inviter=? ORDER BY id DESC LIMIT 100', (inviter,))]


def invite(iid):
    rows = q('SELECT * FROM invites WHERE id=?', (iid,))
    return dict(rows[0]) if rows else None


def invite_by_code(code):
    rows = q('SELECT * FROM invites WHERE code=?', (code,))
    return dict(rows[0]) if rows else None


def add_invite(**kv):
    kv.setdefault('created_at', int(time.time()))
    cols = list(kv)
    return x('INSERT INTO invites(%s) VALUES(%s)' % (','.join(cols), ','.join('?' * len(cols))), [kv[c] for c in cols])


def update_invite(iid, **kv):
    if kv:
        x('UPDATE invites SET %s WHERE id=?' % ','.join(k + '=?' for k in kv), list(kv.values()) + [iid])


def requests(user_id=None, status=None):
    sql, args = 'SELECT * FROM requests WHERE 1=1', []
    if user_id is not None:
        sql += ' AND user_id=?'
        args.append(user_id)
    if status:
        sql += ' AND status=?'
        args.append(status)
    return [dict(r) for r in q(sql + ' ORDER BY id DESC LIMIT 200', args)]


def add_request(user_id, add_gb, reason):
    return x('INSERT INTO requests(user_id, add_gb, reason, created_at) VALUES(?,?,?,?)',
             (user_id, float(add_gb), reason, int(time.time())))


def decide_request(rid, status, answer='', add_gb=None):
    x('UPDATE requests SET status=?, answer=?, decided_at=?%s WHERE id=?' % (', add_gb=?' if add_gb is not None else ''),
      [status, answer, int(time.time())] + ([float(add_gb)] if add_gb is not None else []) + [rid])


def add_event(kind, user_id=0, detail=''):
    x('INSERT INTO events(at, kind, user_id, detail) VALUES(?,?,?,?)', (int(time.time()), kind, user_id, detail[:500]))
    x('DELETE FROM events WHERE id <= (SELECT MAX(id) - 1000 FROM events)')


def end_other_sessions(keep):
    x('DELETE FROM sessions WHERE token<>?', (keep or '',))


def session_count():
    return q('SELECT COUNT(*) n FROM sessions WHERE expires>?', (int(time.time()),))[0]['n']


def events(kind=None, limit=100):
    if kind:
        return [dict(r) for r in q('SELECT * FROM events WHERE kind=? ORDER BY id DESC LIMIT ?', (kind, limit))]
    return [dict(r) for r in q('SELECT * FROM events ORDER BY id DESC LIMIT ?', (limit,))]


# --- backup -------------------------------------------------------------------
def export_all():
    with transaction():
        return {'format': 'vps2vpn-backup-1', 'settings': settings(), 'users': users(),
                'invites': [dict(r) for r in q('SELECT * FROM invites')],
                'requests': [dict(r) for r in q('SELECT * FROM requests')],
                'traffic': [dict(r) for r in q('SELECT * FROM traffic')]}


IMPORT_DEFAULTS = {'enabled': 1, 'note': '', 'disabled_reason': '', 'last_reset': '', 'login_hash': ''}


def _backup_id(value):
    return type(value) is int and 0 < value < (1 << 63)


def _backup_counter(value):
    return type(value) is int and 0 <= value < (1 << 63)


def _backup_time(value):
    return type(value) is int and 0 <= value <= 253402300799


def _check_backup_settings(settings):
    """Check nested persistent state before a restore can publish it."""
    from . import cluster

    for key in ('custom_direct', 'custom_proxy', 'custom_block'):
        if any(not isinstance(item, str) or len(item) > 253 or any(ord(c) < 32 for c in item)
               for item in settings.get(key, [])):
            raise ValueError('invalid domain list: ' + key)
    seen_ids, seen_urls = set(), set()
    for server in settings.get('servers', []):
        if not isinstance(server, dict) or any(
                not isinstance(server.get(key), str) or not server[key] for key in ('id', 'name', 'url', 'key')):
            raise ValueError('invalid server record')
        if server['id'] in seen_ids or server['url'] in seen_urls:
            raise ValueError('duplicate server identity')
        seen_ids.add(server['id'])
        seen_urls.add(server['url'])
        cluster.parse_join_code('v2v1.' + secure.b64url(json.dumps(
            {'u': server['url'], 'k': server['key'], 'p': server.get('pin', ''), 'n': server['name']}).encode()))
        if 'enabled' in server and (type(server['enabled']) not in (bool, int) or server['enabled'] not in (0, 1)):
            raise ValueError('invalid server enabled flag')
        for key in ('info', 'health', 'idmap', 'seen', 'seen_epochs'):
            if key in server and not isinstance(server[key], dict):
                raise ValueError('invalid server field: ' + key)
        for key in ('idmap', 'seen', 'seen_epochs'):
            for uid, value in server.get(key, {}).items():
                if (not isinstance(uid, str) or not re.fullmatch(r'[0-9]{1,19}', uid)
                        or not _backup_id(int(uid))):
                    raise ValueError('invalid server account ID')
                if key == 'seen':
                    valid = isinstance(value, (list, tuple)) and len(value) == 2 and all(_backup_counter(n) for n in value)
                else:
                    valid = _backup_id(value) if key == 'idmap' else _backup_counter(value)
                if not valid:
                    raise ValueError('invalid server checkpoint: ' + key)
        for key in ('last_ok', 'added_at'):
            if key in server and not _backup_time(server[key]):
                raise ValueError('invalid server timestamp')
        if 'fail_count' in server and not _backup_counter(server['fail_count']):
            raise ValueError('invalid server failure count')
        for key in ('version', 'error'):
            if key in server and not isinstance(server[key], str):
                raise ValueError('invalid server text field')
        info = server.get('info', {})
        if info:
            required = ('public_host', 'reality_enabled', 'reality_port', 'reality_target', 'reality_public_key',
                        'reality_short_id', 'hy2_enabled', 'hy2_port', 'hy2_hop', 'hy2_hop_range', 'hy2_obfs')
            if any(key not in info for key in required):
                raise ValueError('incomplete server protocol information')
            for key in required + ('tuic_enabled', 'tuic_port', 'public_ipv6', 'ipv6_nodes', 'node_name'):
                if key not in info:
                    continue
                value, expected = info[key], DEFAULTS[key]
                if isinstance(expected, bool):
                    valid = type(value) in (bool, int) and value in (0, 1)
                else:
                    valid = type(value) is type(expected)
                if not valid:
                    raise ValueError('invalid server protocol field: ' + key)
            for key in ('reality_port', 'hy2_port', 'tuic_port'):
                if key in info and not 1 <= info[key] <= 65535:
                    raise ValueError('invalid server protocol port')
            tls = info.get('tls', {})
            if not isinstance(tls, dict) or any(not isinstance(v, str) for v in tls.values()):
                raise ValueError('invalid server TLS information')
            if tls.get('pin') and not re.fullmatch(r'[0-9a-fA-F]{64}', tls['pin']):
                raise ValueError('invalid server certificate fingerprint')
            if 'ai_score' in info and (type(info['ai_score']) not in (int, float)
                                       or not math.isfinite(info['ai_score'])):
                raise ValueError('invalid server score')
            if 'ai' in info and not isinstance(info['ai'], str):
                raise ValueError('invalid server AI summary')
    month = settings.get('server_month', {})
    for key in ('rx', 'tx', 'last_rx', 'last_tx'):
        if key in month and not (key.startswith('last_') and month[key] is None) and not _backup_counter(month[key]):
            raise ValueError('invalid server monthly counter')
    if month and any(key not in month for key in ('rx', 'tx')):
        raise ValueError('incomplete server monthly counters')
    if month and (not isinstance(month.get('period'), str) or not re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}', month['period'])):
        raise ValueError('invalid server billing period')
    if 'at' in month and not _backup_time(month['at']):
        raise ValueError('invalid server monthly timestamp')
    for line, reports in settings.get('line_reports', {}).items():
        if line not in ('reality', 'hy2', 'tuic'):
            raise ValueError('invalid reported protocol')
        if not isinstance(reports, dict):
            raise ValueError('invalid line reports')
        for entry, report in reports.items():
            if not isinstance(entry, str):
                raise ValueError('invalid line report key')
            uid, separator, host = entry.partition('@')
            if (not re.fullmatch(r'[0-9]{1,19}', uid) or not _backup_id(int(uid))
                    or not isinstance(report, (list, tuple)) or len(report) != 2
                    or type(report[0]) not in (int, float) or not math.isfinite(report[0])
                    or not 0 <= report[0] <= 253402300799 or not isinstance(report[1], str)
                    or len(report[1]) > 253 or any(ord(c) < 32 for c in report[1])
                    or (separator and host != report[1].strip().lower().rstrip('.'))):
                raise ValueError('invalid line report')


def _check_backup_tables(tables):
    users = tables['users']
    ids = set()
    for user in users:
        if 'id' in user:
            if not _backup_id(user['id']) or user['id'] in ids:
                raise ValueError('invalid or duplicate user ID')
            ids.add(user['id'])
    # The original backup format may omit IDs. Allocate deterministic fresh IDs only for those rows.
    candidate = 1
    for user in users:
        if 'id' not in user:
            while candidate in ids:
                candidate += 1
            user['id'] = candidate
            ids.add(candidate)
    names, uuids, remote_ids = set(), set(), set()
    fold_ascii = str.maketrans('ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')
    for user in users:
        name = user.get('name', '')
        uuid = user.get('uuid', '')
        if not name.strip() or len(name) > 128 or any(ord(c) < 32 or ord(c) == 127 for c in name):
            raise ValueError('invalid user name')
        if not re.fullmatch(r'[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}', uuid):
            raise ValueError('invalid user UUID')
        if name.translate(fold_ascii) in names or uuid.lower() in uuids:
            raise ValueError('duplicate user identity')
        names.add(name.translate(fold_ascii))
        uuids.add(uuid.lower())
        if not re.fullmatch(r'[!-~]{6,128}', user.get('hy2_pass', '')):
            raise ValueError('invalid user protocol password')
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,256}', user.get('sub_token', '')):
            raise ValueError('invalid subscription token')
        for key, maximum in (('reset_day', 28), ('max_ips', 100), ('expire_after_days', 3650), ('enabled', 1)):
            if not 0 <= user.get(key, IMPORT_DEFAULTS.get(key, 0)) <= maximum:
                raise ValueError('invalid user field: ' + key)
        for key in ('expire_at', 'last_seen', 'created_at', 'paused_until'):
            if key in user and not _backup_time(user[key]):
                raise ValueError('invalid user timestamp: ' + key)
        for key in ('quota_gb', 'invite_deduct'):
            if user.get(key, 0) > ((1 << 63) - 1) / (1 << 30):
                raise ValueError('user quota exceeds supported counters')
        remote = user.get('remote_id', 0)
        if remote and remote in remote_ids:
            raise ValueError('duplicate remote user identity')
        if remote:
            remote_ids.add(remote)
        parent = user.get('invited_by', 0)
        if parent and (parent not in ids or parent == user['id']):
            raise ValueError('invalid inviter reference')
        if user.get('invite_deduct', 0) and not parent:
            raise ValueError('quota deduction has no inviter')
        if user.get('last_reset') and not re.fullmatch(r'[0-9]{4}-(?:0[1-9]|1[0-2])', user['last_reset']):
            raise ValueError('invalid last reset month')
    parents = {u['id']: u.get('invited_by', 0) for u in users}
    complete = set()
    for uid in parents:
        trail = set()
        while uid and uid not in complete:
            if uid in trail:
                raise ValueError('cyclic inviter references')
            trail.add(uid)
            uid = parents[uid]
        complete.update(trail)
    for table in ('invites', 'requests', 'traffic'):
        for row in tables[table]:
            if 'id' in row and not _backup_id(row['id']):
                raise ValueError('invalid record ID: ' + table)
            for key in ('created_at', 'decided_at', 'valid_until'):
                if key in row and not _backup_time(row[key]):
                    raise ValueError('invalid record timestamp: ' + table)
            if table in ('requests', 'traffic') and row.get('user_id') not in ids:
                raise ValueError('orphan record: ' + table)
            if table == 'requests':
                if row.get('status', 'pending') not in ('pending', 'approved', 'rejected') or row.get('add_gb', 0) <= 0:
                    raise ValueError('invalid quota request')
            elif table == 'traffic':
                try:
                    time.strptime(row.get('day', ''), '%Y-%m-%d')
                except ValueError as exc:
                    raise ValueError('invalid traffic day') from exc
            else:
                kind, status = row.get('kind'), row.get('status', 'unused')
                if kind not in ('admin', 'member') or status not in ('unused', 'used', 'revoked'):
                    raise ValueError('invalid invite kind or status')
                if (not re.fullmatch(r'[A-Z2-9]{5}-[A-Z2-9]{5}', row.get('code', ''))
                        or not 0 <= row.get('reset_day', 0) <= 28 or not 0 <= row.get('expire_days', 0) <= 3650
                        or not 1 <= row.get('max_uses', 1) <= 1000 or row.get('uses', 0) > row.get('max_uses', 1)):
                    raise ValueError('invalid invite limits')
                # Revoked/used codes and their used_by list deliberately retain deleted users as history.
                if kind == 'member' and status == 'unused' and row.get('inviter') not in ids:
                    raise ValueError('live invite has no inviter')
                if row.get('used_by') and any(not re.fullmatch(r'[0-9]{1,19}', value) or not _backup_id(int(value))
                                              for value in row['used_by'].split(',')):
                    raise ValueError('invalid invite history')


def import_all(data):
    if not isinstance(data, dict) or data.get('format') != 'vps2vpn-backup-1':
        raise ValueError('not a vps2vpn backup file')
    if not isinstance(data.get('settings'), dict) or not isinstance(data.get('users'), list):
        raise ValueError('backup must contain settings and a user list')
    keep = {k: v for k, v in data['settings'].items() if k in DEFAULTS}
    for k, v in keep.items():
        default = DEFAULTS[k]
        if isinstance(default, bool) and type(v) is int and v in (0, 1):
            keep[k] = bool(v)  # Older JSON backups may encode SQLite-style booleans as 0/1.
        elif type(v) is not type(default):
            if not (k == 'server_cap_gb' and type(v) is float and math.isfinite(v)):
                raise ValueError('invalid setting: ' + k)
        json.dumps(v, allow_nan=False)
    _check_backup_settings(keep)
    cols = ('id', 'name', 'uuid', 'hy2_pass', 'sub_token', 'quota_gb', 'expire_at', 'reset_day', 'used_up',
            'used_down', 'enabled', 'disabled_reason', 'note', 'last_seen', 'last_reset', 'created_at',
            'login_hash', 'invited_by', 'invite_deduct', 'remote_id', 'max_ips', 'paused_until', 'expire_after_days',
            'traffic_epoch')
    try:
        with transaction() as c:
            tables = {}
            for table in ('users', 'invites', 'requests', 'traffic'):
                rows = data.get(table, [])
                if not isinstance(rows, list):
                    raise ValueError('invalid backup table: ' + table)
                schema = {r[1]: r[2] for r in c.execute('PRAGMA table_info(%s)' % table)}
                for row in rows:
                    if not isinstance(row, dict) or not row or not set(row) <= schema.keys():
                        raise ValueError('unknown or invalid columns in ' + table)
                    for k, v in row.items():
                        if schema[k] == 'TEXT':
                            if not isinstance(v, str):
                                raise ValueError('invalid text field: %s.%s' % (table, k))
                        elif schema[k] == 'INTEGER':
                            is_flag = table == 'users' and k == 'enabled' and type(v) is bool
                            if (type(v) is not int and not is_flag) or not 0 <= v <= (1 << 63) - 1:
                                raise ValueError('invalid integer field: %s.%s' % (table, k))
                        elif schema[k] == 'REAL':
                            if type(v) not in (int, float) or not math.isfinite(v) or v < 0:
                                raise ValueError('invalid number field: %s.%s' % (table, k))
                tables[table] = [dict(row) for row in rows]
            _check_backup_tables(tables)
            for table in ('sessions', 'member_sessions', 'traffic', 'invites', 'requests', 'events'):
                c.execute('DELETE FROM ' + table)
            c.execute('DELETE FROM users')
            for u in tables['users']:
                if any(not u.get(k) for k in ('name', 'uuid', 'hy2_pass', 'sub_token')):
                    raise ValueError('backup user is missing its identity or credentials')
                vals = [u.get(k, IMPORT_DEFAULTS.get(k, 0)) for k in cols]
                if 'id' not in u:
                    vals[0] = None
                c.execute('INSERT INTO users(%s) VALUES(%s)' % (','.join(cols), ','.join('?' * len(cols))), vals)
            for table in ('invites', 'requests', 'traffic'):
                for row in tables[table]:
                    ks = list(row)
                    c.execute('INSERT INTO %s(%s) VALUES(%s)' % (table, ','.join(ks), ','.join('?' * len(ks))),
                              [row[k] for k in ks])
            c.execute('DELETE FROM settings')
            for k, v in keep.items():
                c.execute('INSERT INTO settings(key, value) VALUES(?, ?) '
                          'ON CONFLICT(key) DO UPDATE SET value=excluded.value', (k, json.dumps(v, allow_nan=False)))
    except (sqlite3.DatabaseError, OverflowError) as e:
        raise ValueError('invalid backup records: %s' % e) from e
