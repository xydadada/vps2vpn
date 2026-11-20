"""SQLite storage: settings, users, sessions, daily traffic, invite codes, quota requests and events."""
import contextlib
import itertools
import json
import os
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
            _conn.execute('PRAGMA busy_timeout=15000')
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
    """Serialise compound writes, with savepoints for nested database helpers."""
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
        x('UPDATE users SET %s WHERE id=?' % ','.join(sets), args + [uid])


def rotate_user(uid):
    """New credentials and link, e.g. after a link leaked."""
    x('UPDATE users SET uuid=?, hy2_pass=?, sub_token=? WHERE id=?',
      (secure.new_uuid(), secure.token(18), secure.token(18), uid))


def delete_user(uid):
    with transaction() as c:
        c.execute('DELETE FROM users WHERE id=?', (uid,))
        c.execute('DELETE FROM traffic WHERE user_id=?', (uid,))
        c.execute('DELETE FROM member_sessions WHERE user_id=?', (uid,))
        c.execute('DELETE FROM requests WHERE user_id=?', (uid,))
        c.execute("UPDATE invites SET status='revoked' WHERE inviter=? AND status='unused'", (uid,))
        c.execute('UPDATE users SET invited_by=0, invite_deduct=0 WHERE invited_by=?', (uid,))

def add_traffic(uid, up, down, now=None):
    day = time.strftime('%Y-%m-%d', time.localtime(now or time.time()))
    with transaction() as c:
        c.execute('UPDATE users SET used_up=used_up+?, used_down=used_down+?, last_seen=? WHERE id=?',
                  (up, down, int(now or time.time()), uid))
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


def end_other_member_sessions(uid, keep):
    x('DELETE FROM member_sessions WHERE user_id=? AND token<>?', (uid, keep or ''))


def end_all_member_sessions():
    x('DELETE FROM member_sessions')


# --- invites, requests, events ---------------------------------------------------
INVITE_COLS = ('id', 'code', 'kind', 'inviter', 'quota_gb', 'expire_days', 'reset_day',
               'max_uses', 'uses', 'used_by', 'valid_until', 'status', 'note', 'created_at')
REQUEST_COLS = ('id', 'user_id', 'add_gb', 'reason', 'status', 'answer', 'created_at', 'decided_at')


def invites(inviter=None):
    if inviter is None:
        return [dict(r) for r in q('SELECT * FROM invites ORDER BY id DESC LIMIT 500')]
    return [dict(r) for r in q('SELECT * FROM invites WHERE inviter=? ORDER BY id DESC LIMIT 100', (inviter,))]


def member_live_invites(inviter, now=None):
    """All unused, unexpired invite codes created by `inviter` (without the display LIMIT)."""
    now = int(time.time()) if now is None else int(now)
    return [dict(r) for r in q(
        "SELECT * FROM invites WHERE inviter=? AND status='unused' AND valid_until>? AND uses<max_uses",
        (inviter, now))]


def invite(iid):
    rows = q('SELECT * FROM invites WHERE id=?', (iid,))
    return dict(rows[0]) if rows else None


def invite_by_code(code):
    rows = q('SELECT * FROM invites WHERE code=?', (code,))
    return dict(rows[0]) if rows else None


def add_invite(**kv):
    kv.setdefault('created_at', int(time.time()))
    cols = list(kv)
    bad = [c for c in cols if c not in INVITE_COLS]
    if bad:
        raise KeyError(bad[0])
    return x('INSERT INTO invites(%s) VALUES(%s)' % (','.join(cols), ','.join('?' * len(cols))), [kv[c] for c in cols])


def update_invite(iid, **kv):
    if kv:
        bad = [k for k in kv if k not in INVITE_COLS or k == 'id']
        if bad:
            raise KeyError(bad[0])
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


def request_by_id(rid):
    rows = q('SELECT * FROM requests WHERE id=?', (rid,))
    return dict(rows[0]) if rows else None


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
    return {'format': 'vps2vpn-backup-1', 'settings': settings(), 'users': users(),
            'invites': [dict(r) for r in q('SELECT * FROM invites')],
            'requests': [dict(r) for r in q('SELECT * FROM requests')]}


IMPORT_DEFAULTS = {'enabled': 1, 'note': '', 'disabled_reason': '', 'last_reset': '', 'login_hash': ''}


def import_all(data):
    if data.get('format') != 'vps2vpn-backup-1':
        raise ValueError('not a vps2vpn backup file')
    keep = {k: v for k, v in data['settings'].items() if k in DEFAULTS}
    cols = ('id', 'name', 'uuid', 'hy2_pass', 'sub_token', 'quota_gb', 'expire_at', 'reset_day', 'used_up',
            'used_down', 'enabled', 'disabled_reason', 'note', 'last_seen', 'last_reset', 'created_at',
            'login_hash', 'invited_by', 'invite_deduct', 'remote_id', 'max_ips', 'paused_until', 'expire_after_days')
    table_cols = {'invites': INVITE_COLS, 'requests': REQUEST_COLS}
    with _lock:
        c = connect()
        c.execute('BEGIN')
        try:
            c.execute('DELETE FROM users')
            for u in data['users']:
                vals = [u.get(k, IMPORT_DEFAULTS.get(k, 0)) for k in cols]
                if 'id' not in u:
                    vals[0] = None                     # backups from before ids were kept
                c.execute('INSERT INTO users(%s) VALUES(%s)' % (','.join(cols), ','.join('?' * len(cols))), vals)
            for table, allowed in table_cols.items():
                if table in data:
                    c.execute('DELETE FROM ' + table)
                    for row in data[table]:
                        ks = [k for k in row if k in allowed]
                        if not ks:
                            continue
                        c.execute('INSERT INTO %s(%s) VALUES(%s)' % (table, ','.join(ks), ','.join('?' * len(ks))),
                                  [row[k] for k in ks])
            for k, v in keep.items():
                c.execute('INSERT INTO settings(key, value) VALUES(?, ?) '
                          'ON CONFLICT(key) DO UPDATE SET value=excluded.value', (k, json.dumps(v)))
            c.execute('COMMIT')
        except BaseException:
            c.execute('ROLLBACK')
            raise
