"""SQLite storage: settings, users, sessions, daily traffic, invite codes, quota requests and events."""
import contextlib
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
_tx_depth = 0

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
CREATE TABLE IF NOT EXISTS alerts_sent (key TEXT PRIMARY KEY, at INTEGER NOT NULL);
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
CREATE INDEX IF NOT EXISTS idx_traffic_user_day ON traffic(user_id, day);
CREATE INDEX IF NOT EXISTS idx_events_kind_id ON events(kind, id);
CREATE INDEX IF NOT EXISTS idx_invites_inviter_status ON invites(inviter, status, valid_until);
CREATE INDEX IF NOT EXISTS idx_requests_user_status ON requests(user_id, status);
CREATE INDEX IF NOT EXISTS idx_requests_status_id ON requests(status, id);
CREATE INDEX IF NOT EXISTS idx_member_sessions_expires ON member_sessions(expires);
CREATE INDEX IF NOT EXISTS idx_member_sessions_user ON member_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires);
CREATE INDEX IF NOT EXISTS idx_users_name_nocase ON users(name COLLATE NOCASE);
"""

# Columns added after the first release; created on start-up when missing.
MIGRATIONS = {
    'users': [('login_hash', "TEXT NOT NULL DEFAULT ''"),        # member-centre password (empty = link only)
              ('invited_by', 'INTEGER NOT NULL DEFAULT 0'),
              ('invite_deduct', 'REAL NOT NULL DEFAULT 0'),        # GB carved out of the inviter's quota
              ('remote_id', 'INTEGER NOT NULL DEFAULT 0'),         # set on a joined node: the main server's user id
              ('max_ips', 'INTEGER NOT NULL DEFAULT 0'),           # device limit (0 = none)
              ('paused_until', 'INTEGER NOT NULL DEFAULT 0'),      # end of a short pause for too many devices
              ('expire_after_days', 'INTEGER NOT NULL DEFAULT 0'),   # lifetime that starts on first use
              ('sub_fetched_at', 'INTEGER NOT NULL DEFAULT 0'),      # last time an app downloaded the subscription
              ('sub_ua', "TEXT NOT NULL DEFAULT ''")],               # ...and its User-Agent (sanitised, short)
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
    'tg_verified': False,       # old bindings are untrusted until an admin completes a fresh /bind
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
    'sub_update_hours': 12,     # Profile-Update-Interval: how often apps refresh the subscription (1-168 h)
    'support_url': '',          # http(s):// or tg:// link apps show as "support" (Support-Url header); empty = none
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
    'client_auto_update': True,  # fetch the newest signed client from GitHub into the client folder
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
            _conn.execute('PRAGMA synchronous=NORMAL')
            _conn.execute('PRAGMA wal_autocheckpoint=1000')
            _conn.execute('PRAGMA journal_size_limit=16777216')
            _conn.execute('PRAGMA temp_store=MEMORY')
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
            _conn.execute('CREATE INDEX IF NOT EXISTS idx_users_invited_by ON users(invited_by)')
            _conn.execute('CREATE INDEX IF NOT EXISTS idx_users_remote_id ON users(remote_id)')
        return _conn


def close():
    global _conn, _tx_depth
    with _lock:
        if _conn is not None:
            try:
                _conn.execute('PRAGMA wal_checkpoint(TRUNCATE)')
                _conn.execute('PRAGMA optimize')
            except sqlite3.Error:
                pass
            _conn.close()
            _conn = None
            _tx_depth = 0


@contextlib.contextmanager
def transaction():
    """Re-entrant SQLite write transaction using BEGIN IMMEDIATE (or SAVEPOINT when nested)."""
    global _tx_depth
    with _lock:
        c = connect()
        nested = _tx_depth > 0 or c.in_transaction
        if nested:
            sp = 'sp_%d' % _tx_depth
            c.execute('SAVEPOINT ' + sp)
        else:
            c.execute('BEGIN IMMEDIATE')
        _tx_depth += 1
        try:
            yield c
            if nested:
                c.execute('RELEASE SAVEPOINT ' + sp)
            elif c.in_transaction:
                c.execute('COMMIT')
        except BaseException:
            if nested:
                try:
                    if c.in_transaction:
                        c.execute('ROLLBACK TO SAVEPOINT ' + sp)
                        c.execute('RELEASE SAVEPOINT ' + sp)
                except sqlite3.Error:
                    pass
            elif c.in_transaction:
                c.execute('ROLLBACK')
            raise
        finally:
            _tx_depth -= 1


def q(sql, args=()):
    with _lock:
        return connect().execute(sql, args).fetchall()


def x(sql, args=()):
    with _lock:
        cur = connect().execute(sql, args)
        return cur.lastrowid


# --- alerts that must not repeat after a restart ------------------------------
ALERT_KEEP = 90 * 86400


def alert_sent_at(key):
    """Wall-clock time a long-window alert with this key was last delivered, or None."""
    rows = q('SELECT at FROM alerts_sent WHERE key=?', (key,))
    return rows[0]['at'] if rows else None


def forget_alerts(prefix):
    """Stored keys are '<bot>:<chat>:<key>'; forget every recipient's record of keys starting with prefix."""
    with transaction() as c:
        for row in c.execute('SELECT key FROM alerts_sent').fetchall():
            if row['key'].split(':', 2)[-1].startswith(prefix):
                c.execute('DELETE FROM alerts_sent WHERE key=?', (row['key'],))


def mark_alert_sent(key, at=None):
    at = int(at if at is not None else time.time())
    with transaction() as c:
        c.execute('INSERT INTO alerts_sent(key, at) VALUES(?, ?) '
                  'ON CONFLICT(key) DO UPDATE SET at=excluded.at', (key, at))
        c.execute('DELETE FROM alerts_sent WHERE at<?', (at - ALERT_KEEP,))


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
                      'ON CONFLICT(key) DO UPDATE SET value=excluded.value', (k, json.dumps(v)))


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


def user_ids():
    """Set of all user ids (cheaper than users() when only membership is needed)."""
    return {r[0] for r in q('SELECT id FROM users')}


def user_names():
    """{user id: name} for every user."""
    return {r[0]: r[1] for r in q('SELECT id, name FROM users')}


def users_invited_by(uid):
    """Accounts `uid` invited directly, by id."""
    return [dict(r) for r in q('SELECT * FROM users WHERE invited_by=? ORDER BY id', (uid,))]


def invite_tree(uid):
    """Every account below `uid` in the invite chain (children, their children, ...), by id.

    Enough to work out what `uid` shares with invitees without loading every user. UNION (not UNION ALL)
    stops on a damaged chain that loops back on itself."""
    return [dict(r) for r in q(
        'WITH RECURSIVE tree(id) AS (SELECT id FROM users WHERE invited_by=? '
        'UNION SELECT u.id FROM users u JOIN tree t ON u.invited_by=t.id) '
        'SELECT * FROM users WHERE id IN (SELECT id FROM tree) ORDER BY id', (uid,))]


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


def pause_for_devices(uid, until):
    """Pause an account over its device limit, but only while it is still on: the device check works
    from a reading that takes seconds, and an admin who turned the account off meanwhile must not have
    that replaced by a pause that ends by itself. Returns True when it was paused."""
    with _lock:
        cur = connect().execute("UPDATE users SET enabled=0, disabled_reason='devices', paused_until=? "
                                "WHERE id=? AND enabled=1", (int(until), uid))
        return cur.rowcount == 1


SUB_UA_MAX = 120
SUB_FETCH_QUIET = 300           # the same app fetching again within 5 minutes is not written down again


def clean_ua(ua):
    """A User-Agent safe to store and show: printable ASCII only, at most SUB_UA_MAX characters."""
    return ''.join(c for c in str(ua or '') if 32 <= ord(c) < 127).strip()[:SUB_UA_MAX]


def record_sub_fetch(u, ua, now=None):
    """Note that `u` (a user row) downloaded its subscription. Returns True when a row was written."""
    now = int(now if now is not None else time.time())
    ua = clean_ua(ua)
    if u.get('sub_ua', '') == ua and 0 <= now - int(u.get('sub_fetched_at') or 0) < SUB_FETCH_QUIET:
        return False
    x('UPDATE users SET sub_fetched_at=?, sub_ua=? WHERE id=?', (now, ua, u['id']))
    return True


def rotate_user(uid):
    """Rotate account secrets and revoke all old member sessions atomically.

    A stolen subscription token grants access to the link-based member area,
    including password setup and login. Rotating only the URL/proxy keys
    must not leave an already-issued member cookie usable for eight hours.
    """
    with transaction() as c:
        c.execute('UPDATE users SET uuid=?, hy2_pass=?, sub_token=? WHERE id=?',
                  (secure.new_uuid(), secure.token(18), secure.token(18), uid))
        c.execute('DELETE FROM member_sessions WHERE user_id=?', (uid,))


def delete_user(uid):
    with transaction() as c:
        row = c.execute('SELECT invited_by, invite_deduct FROM users WHERE id=?', (uid,)).fetchone()
        c.execute('DELETE FROM users WHERE id=?', (uid,))
        c.execute('DELETE FROM traffic WHERE user_id=?', (uid,))
        c.execute('DELETE FROM member_sessions WHERE user_id=?', (uid,))
        c.execute('DELETE FROM requests WHERE user_id=?', (uid,))
        c.execute("UPDATE invites SET status='revoked' WHERE inviter=? AND status='unused'", (uid,))
        parent = row['invited_by'] if row else 0
        if parent and c.execute('SELECT 1 FROM users WHERE id=?', (parent,)).fetchone():
            rem = max(0.0, float(row['invite_deduct'] or 0))
            now = time.time()
            children = c.execute('SELECT id, invite_deduct, expire_at, enabled, disabled_reason FROM users '
                                 'WHERE invited_by=? ORDER BY id', (uid,)).fetchall()

            def charged(ch):
                # As members.deducting: what is left to hand on goes first to accounts that still count,
                # or an expired one would take it and leave a live one charged to nobody.
                live = not (ch['expire_at'] and ch['expire_at'] <= now)
                return live and (bool(ch['enabled']) or ch['disabled_reason'] in ('quota', 'devices'))
            for ch in sorted(children, key=lambda ch: not charged(ch)):
                ded = min(max(0.0, float(ch['invite_deduct'] or 0)), rem)
                rem = max(0.0, rem - ded)
                if ded > 0:
                    c.execute('UPDATE users SET invited_by=?, invite_deduct=? WHERE id=?', (parent, ded, ch['id']))
                else:
                    c.execute('UPDATE users SET invited_by=0, invite_deduct=0 WHERE id=?', (ch['id'],))
        else:
            c.execute('UPDATE users SET invited_by=0, invite_deduct=0 WHERE invited_by=?', (uid,))
        rep_row = c.execute("SELECT value FROM settings WHERE key='line_reports'").fetchone()
        if rep_row:
            try:
                reps = json.loads(rep_row['value']) or {}
            except ValueError:
                reps = {}
            if isinstance(reps, dict):
                owner = str(uid)
                new_reps = {}
                changed = False
                for line, m in reps.items():
                    if not isinstance(m, dict):
                        continue
                    kept = {k: v for k, v in m.items() if k.split('@', 1)[0] != owner}
                    if len(kept) != len(m):
                        changed = True
                    if kept:
                        new_reps[line] = kept
                if changed:
                    c.execute("INSERT INTO settings(key, value) VALUES('line_reports', ?) "
                              "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (json.dumps(new_reps),))


MAX_SQLITE_INT = (1 << 63) - 1


def add_traffic(uid, up, down, now=None):
    add_traffic_many([(uid, up, down)], now)


def add_traffic_many(deltas, now=None):
    """Bill non-negative byte deltas atomically without overflowing SQLite INTEGER."""
    ts = now or time.time()
    day = time.strftime('%Y-%m-%d', time.localtime(ts))
    deltas = list(deltas)
    if not deltas:
        return
    if any(type(up) is not int or type(down) is not int or
           not (0 <= up <= MAX_SQLITE_INT and 0 <= down <= MAX_SQLITE_INT)
           for _, up, down in deltas):
        raise ValueError('invalid traffic delta')
    with transaction() as c:
        # A user may have been deleted while core counters were being read.
        # Ignore their stale deltas rather than losing other users' usage.
        deltas = [(uid, up, down) for uid, up, down in deltas
                  if c.execute('SELECT 1 FROM users WHERE id=?', (uid,)).fetchone()]
        if not deltas:
            return
        # SQLite promotes overflowing INTEGER addition to REAL. The bounded
        # UPDATE/UPSERT and row counts keep every batch exact and atomic.
        updated = c.executemany(
            'UPDATE users SET used_up=used_up+?, used_down=used_down+?, last_seen=? '
            "WHERE id=? AND typeof(used_up)='integer' AND used_up BETWEEN 0 AND ? "
            "AND typeof(used_down)='integer' AND used_down BETWEEN 0 AND ?",
            [(up, down, int(ts), uid, MAX_SQLITE_INT - up, MAX_SQLITE_INT - down)
             for uid, up, down in deltas])
        if updated.rowcount != len(deltas):
            raise OverflowError('account traffic exceeds SQLite INTEGER range')
        history = c.executemany(
            'INSERT INTO traffic(day, user_id, up, down) VALUES(?,?,?,?) '
            'ON CONFLICT(day, user_id) DO UPDATE SET up=up+excluded.up, down=down+excluded.down '
            "WHERE typeof(traffic.up)='integer' AND traffic.up BETWEEN 0 AND ? "
            "AND typeof(traffic.down)='integer' AND traffic.down BETWEEN 0 AND ?",
            [(day, uid, up, down, MAX_SQLITE_INT - up, MAX_SQLITE_INT - down)
             for uid, up, down in deltas])
        if history.rowcount != len(deltas):
            raise OverflowError('daily traffic exceeds SQLite INTEGER range')


def traffic_days(days=30):
    since = time.strftime('%Y-%m-%d', time.localtime(time.time() - days * 86400))
    return [dict(r) for r in q('SELECT day, SUM(up) up, SUM(down) down FROM traffic WHERE day>=? '
                                'GROUP BY day ORDER BY day', (since,))]


# --- sessions -----------------------------------------------------------------
def new_session(ttl=7 * 86400):
    tok = secure.token(32)
    now = int(time.time())
    with transaction() as c:
        c.execute('DELETE FROM sessions WHERE expires<?', (now,))
        c.execute('INSERT INTO sessions(token, expires) VALUES(?,?)', (tok, now + ttl))
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
    with transaction() as c:
        c.execute('DELETE FROM member_sessions WHERE expires<?', (now,))
        c.execute('INSERT INTO member_sessions(token, user_id, expires) VALUES(?,?,?)', (tok, uid, now + ttl))
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
    now = time.time() if now is None else now
    return [dict(r) for r in q(
        "SELECT * FROM invites WHERE inviter=? AND status='unused' AND valid_until>? AND uses<max_uses ORDER BY id DESC",
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
    with transaction() as c:
        c.execute('INSERT INTO events(at, kind, user_id, detail) VALUES(?,?,?,?)',
                  (int(time.time()), kind, user_id, detail[:500]))
        c.execute('DELETE FROM events WHERE id <= (SELECT MAX(id) - 1000 FROM events)')


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


IMPORT_DEFAULTS = {'enabled': 1, 'note': '', 'disabled_reason': '', 'last_reset': '', 'login_hash': '', 'sub_ua': ''}
_IMPORT_INT = ('expire_at', 'reset_day', 'used_up', 'used_down', 'enabled', 'last_seen', 'created_at', 'invited_by',
               'remote_id', 'max_ips', 'paused_until', 'expire_after_days', 'sub_fetched_at')
_IMPORT_REAL = ('quota_gb', 'invite_deduct')
_IMPORT_TEXT = ('name', 'uuid', 'hy2_pass', 'sub_token', 'disabled_reason', 'note', 'last_reset', 'login_hash',
                'sub_ua')
_SQLITE_MAX = (1 << 63) - 1


def _usable_password_hash(h):
    """A hash secure.check_password can verify a password against (an unusable one locks the owner out)."""
    parts = h.split('$') if isinstance(h, str) else []
    if len(parts) != 4 or parts[0] != 'pbkdf2_sha256' or not re.fullmatch(r'[1-9][0-9]{0,9}', parts[1]):
        return False
    if not 1 <= int(parts[1]) <= secure.MAX_PBKDF2_ROUNDS:
        return False
    try:
        salt, digest = secure.b64url_decode(parts[2]), secure.b64url_decode(parts[3])
    except ValueError:
        return False
    return len(salt) >= 8 and len(digest) == 32 and all(re.fullmatch(r'[A-Za-z0-9_-]+', x) for x in parts[2:])


def _check_import_sign_in(keep):
    """The admin must still be able to sign in after the restore (#109)."""
    user = keep.get('admin_user', DEFAULTS['admin_user'])
    if not isinstance(user, str) or not 1 <= len(user) <= 32 or re.search(r'[\x00-\x1f\x7f]', user):
        raise ValueError('invalid admin_user in backup')
    h = keep.get('admin_hash', DEFAULTS['admin_hash'])
    configured = keep.get('setup_done', DEFAULTS['setup_done'])
    if not isinstance(h, str) or ((h or configured) and not _usable_password_hash(h)):
        raise ValueError('invalid admin_hash in backup')
    totp = keep.get('admin_totp', DEFAULTS['admin_totp'])
    if not isinstance(totp, str) or (totp and not re.fullmatch(r'[A-Z2-7]{16,64}', totp)):
        raise ValueError('invalid admin_totp in backup')


def _check_import_request(r, i):
    """Rows the admin list formats and approval adds to a quota (#107)."""
    if not isinstance(r, dict):
        raise ValueError('request %d: not an object' % i)
    for k in ('id', 'user_id'):
        if k in r and (type(r[k]) is not int or not 0 < r[k] <= MAX_SQLITE_INT):
            raise ValueError('request %d: invalid %s' % (i, k))
    if type(r.get('user_id')) is not int:
        raise ValueError('request %d: invalid user_id' % i)
    gb = r.get('add_gb')
    if type(gb) not in (int, float) or not 0 <= gb <= 1e9 or not math.isfinite(gb):
        raise ValueError('request %d: invalid add_gb' % i)
    for k in ('created_at', 'decided_at'):
        if k in r and (type(r[k]) is not int or not 0 <= r[k] <= MAX_SQLITE_INT):
            raise ValueError('request %d: invalid %s' % (i, k))
    if type(r.get('created_at')) is not int:
        raise ValueError('request %d: invalid created_at' % i)
    for k in ('reason', 'status', 'answer'):
        if k in r and not isinstance(r[k], str):
            raise ValueError('request %d: invalid %s' % (i, k))


def _check_import_servers(servers):
    """Joined servers as subscriptions read them: the same checks a sync makes before saving (#111)."""
    from . import cluster              # cluster imports db
    if not isinstance(servers, list):
        raise ValueError('backup servers must be a list')
    ids = set()
    for i, x in enumerate(servers, 1):
        if (not isinstance(x, dict) or not isinstance(x.get('id'), str) or not x['id'] or x['id'] in ids
                or not isinstance(x.get('name'), str) or not x['name'] or not isinstance(x.get('url'), str)
                or not x['url'].startswith('https://')):
            raise ValueError('server %d: invalid entry' % i)
        ids.add(x['id'])
        if 'enabled' in x and type(x['enabled']) is not bool:
            raise ValueError('server %d: invalid enabled' % i)
        info, idmap = x.get('info') or {}, x.get('idmap') or {}
        try:
            cluster._validate_sync_answer({'ok': True, 'info': info, 'idmap': idmap, 'traffic': {}})
        except cluster.SyncError as e:
            raise ValueError('server %d: %s' % (i, e))


def _check_import_user(u, i):
    """A backup's user row, before anything is deleted. SQLite would store "abc" in an INTEGER column as text,
    and that account's subscription would then fail on every request."""
    if not isinstance(u, dict):
        raise ValueError('user %d in the backup is not a record' % i)
    for k in _IMPORT_TEXT:
        if k in u and not isinstance(u[k], str):
            raise ValueError('user %d: %s must be text' % (i, k))
    for k in ('name', 'uuid', 'hy2_pass', 'sub_token'):
        if not isinstance(u.get(k), str) or not u[k]:
            raise ValueError('user %d: %s is missing' % (i, k))
    for k in _IMPORT_INT:
        v = u.get(k, 0)
        if type(v) is bool:
            v = int(v)
        if type(v) is not int or not 0 <= v <= _SQLITE_MAX:
            raise ValueError('user %d: %s must be a whole number' % (i, k))
    if 'id' in u and u['id'] is not None and (type(u['id']) is not int or not 0 < u['id'] <= _SQLITE_MAX):
        raise ValueError('user %d: invalid id' % i)
    for k in _IMPORT_REAL:
        v = u.get(k, 0)
        if type(v) not in (int, float) or not 0 <= v <= 1e9 or not math.isfinite(v):
            raise ValueError('user %d: %s must be a number' % (i, k))
    if u.get('enabled', 1) not in (0, 1) or not 0 <= u.get('reset_day', 0) <= 28:
        raise ValueError('user %d: invalid enabled or reset day' % i)


def import_all(data):
    if not isinstance(data, dict) or data.get('format') != 'vps2vpn-backup-1':
        raise ValueError('not a vps2vpn backup file')
    if not isinstance(data.get('settings'), dict) or not isinstance(data.get('users'), list):
        raise ValueError('not a vps2vpn backup file')
    keep = {k: v for k, v in data['settings'].items() if k in DEFAULTS}
    # Route prefixes from a damaged/edited backup must not poison every future
    # HTTP request. The panel concatenates these values as strings on *all*
    # requests, and an empty or colliding admin path can lock out the owner.
    # Validate before deleting any existing rows so restore failures are atomic.
    for flag in ('setup_done', 'member_enabled'):
        if flag in keep and type(keep[flag]) is not bool:
            raise ValueError('invalid %s in backup' % flag)
    for key in ('panel_path', 'member_path'):
        value = keep.get(key, DEFAULTS[key])
        if not isinstance(value, str) or (value and not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', value)):
            raise ValueError('invalid %s in backup' % key)
    panel_path = keep.get('panel_path', DEFAULTS['panel_path'])
    member_path = keep.get('member_path', DEFAULTS['member_path'])
    if keep.get('setup_done', DEFAULTS['setup_done']) and not panel_path:
        raise ValueError('a configured backup needs a panel_path')
    if panel_path and panel_path == member_path:
        raise ValueError('panel_path and member_path must differ')
    for i, u in enumerate(data['users'], 1):
        _check_import_user(u, i)
    _check_import_sign_in(keep)
    if 'servers' in keep:
        _check_import_servers(keep['servers'])
    if 'requests' in data and not isinstance(data['requests'], list):
        raise ValueError('backup requests must be a list')
    for i, r in enumerate(data.get('requests', []), 1):
        _check_import_request(r, i)
    if 'invites' in data and not isinstance(data['invites'], list):
        raise ValueError('backup invites must be a list')
    for i, invite in enumerate(data.get('invites', []), 1):
        used_by = invite.get('used_by', '') if isinstance(invite, dict) else None
        if not isinstance(used_by, str) or not re.fullmatch(
                r'(?:[1-9][0-9]{0,18}(?:,[1-9][0-9]{0,18})*)?', used_by):
            raise ValueError('invite %d: invalid usage history' % i)
    # A backup can be old, copied from another install, or edited: it is never
    # evidence that this bot/chat was verified on the restored installation.
    keep['tg_verified'] = False
    cols = ('id', 'name', 'uuid', 'hy2_pass', 'sub_token', 'quota_gb', 'expire_at', 'reset_day', 'used_up',
            'used_down', 'enabled', 'disabled_reason', 'note', 'last_seen', 'last_reset', 'created_at',
            'login_hash', 'invited_by', 'invite_deduct', 'remote_id', 'max_ips', 'paused_until', 'expire_after_days',
            'sub_fetched_at', 'sub_ua')
    table_cols = {'invites': INVITE_COLS, 'requests': REQUEST_COLS}
    with transaction() as c:
        c.execute('DELETE FROM settings')
        c.execute('DELETE FROM traffic')
        c.execute('DELETE FROM events')
        c.execute('DELETE FROM member_sessions')
        c.execute('DELETE FROM invites')
        c.execute('DELETE FROM requests')
        c.execute('DELETE FROM users')
        for u in data['users']:
            vals = [u.get(k, IMPORT_DEFAULTS.get(k, 0)) for k in cols]
            if 'id' not in u:
                vals[0] = None                     # backups from before ids were kept
            c.execute('INSERT INTO users(%s) VALUES(%s)' % (','.join(cols), ','.join('?' * len(cols))), vals)
        for table, allowed in table_cols.items():
            if table in data:
                for row in data[table]:
                    ks = [k for k in allowed if k in row]
                    if not ks:
                        continue
                    c.execute('INSERT INTO %s(%s) VALUES(%s)' % (table, ','.join(ks), ','.join('?' * len(ks))),
                              [row[k] for k in ks])
        for k, v in keep.items():
            c.execute('INSERT INTO settings(key, value) VALUES(?, ?) '
                      'ON CONFLICT(key) DO UPDATE SET value=excluded.value', (k, json.dumps(v)))
