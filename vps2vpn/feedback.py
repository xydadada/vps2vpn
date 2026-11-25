"""One-tap feedback from the vps2vpn app and the member page (docs/phase2-api.md section 1).

A member sends what went wrong (their words, the app's diagnosis, a redacted log); the admin reads it on the
Members page and may answer. The app redacts before sending; this module redacts again before anything is
stored (the account's own secrets, every full IP address), so the database never holds the original.

Kept 30 days, at most 20 per account and 500 in all; not in backups; deleted with the account."""
import ipaddress
import json
import re
import time

from . import db

PLATFORMS = ('windows', 'android', 'macos', 'linux', 'ios', 'web')
TEXT_MAX = 1000                   # characters
DIAG_MAX = 32 << 10               # bytes of JSON
LOG_MAX = 64 << 10                # bytes of UTF-8
BODY_MAX = 128 << 10
CLIENT_MAX = 64                   # characters per client value
ANSWER_MAX = 500
PER_USER_KEEP = 20
TOTAL_KEEP = 500
KEEP_DAYS = 30
GAP = 120                         # one per 2 minutes per account
DAY_MAX = 5                       # and 5 per 24 hours
UUID_RE = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}')
HIDDEN = '<hidden>'


class Refused(ValueError):
    """`code` and `status` as docs/phase2-api.md section 0; `retry` seconds for rate_limited."""
    def __init__(self, msg, code='bad_request', status=400, retry=0):
        super().__init__(msg)
        self.code, self.status, self.retry = code, status, retry


def on(s):
    return s.get('client_feedback') is True


# --- redaction -----------------------------------------------------------------------------------------------
_V4 = re.compile(r'(?<![\d.])(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?![\d.]*\d)')
_V6 = re.compile(r'(?<![0-9A-Za-z:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Za-z:])')


def _v4(m):
    if all(int(x) <= 255 for x in m.groups()):
        return '%s.%s.x.x' % (m.group(1), m.group(2))
    return m.group(0)


def _v6(m):
    text = m.group(0)
    try:
        ipaddress.IPv6Address(text)
    except ValueError:
        return text                                    # "12:30:45", a MAC address...
    head = text.split(':')[:2]
    return ':'.join(head) + ':x:x:...'


def mask_ips(text):
    """203.0.113.7 -> 203.0.x.x; 2001:db8::1 -> 2001:db8:x:x:..."""
    return _V6.sub(_v6, _V4.sub(_v4, text))


def redact(text, u):
    for secret in (u.get('sub_token'), u.get('uuid'), u.get('hy2_pass')):
        if secret and len(secret) >= 6:
            text = text.replace(secret, HIDDEN)
    return mask_ips(text)


def _redact_json(v, u):
    if isinstance(v, str):
        return redact(v, u)
    if isinstance(v, list):
        return [_redact_json(x, u) for x in v]
    if isinstance(v, dict):
        return {redact(str(k), u): _redact_json(x, u) for k, x in v.items()}
    return v


def _text(v, name, limit, newlines=True):
    if not isinstance(v, str):
        raise Refused('%s must be text' % name)
    v = ''.join(c for c in v if (newlines and c == '\n') or c == '\t' or ord(c) >= 32 and ord(c) != 127)
    return v.strip()


# --- checking what arrives ------------------------------------------------------------------------------------
def clean(d, u):
    """The request body -> the row to store (already redacted). Raises Refused."""
    client = d.get('client')
    if not isinstance(client, dict) or not client or len(client) > 12:
        raise Refused('client: expected an object with version and platform')
    c = {}
    for k, v in client.items():
        if not isinstance(k, str) or not re.fullmatch(r'[a-z_]{1,24}', k):
            raise Refused('client: unknown key')
        v = _text(v, 'client.' + k, CLIENT_MAX, newlines=False)
        if len(v) > CLIENT_MAX:
            raise Refused('client.%s: at most %d characters' % (k, CLIENT_MAX))
        c[k] = v
    if c.get('platform') not in PLATFORMS:
        raise Refused('client.platform must be one of ' + ', '.join(PLATFORMS))
    text = _text(d.get('text', ''), 'text', TEXT_MAX)
    if len(text) > TEXT_MAX:
        raise Refused('text: at most %d characters' % TEXT_MAX)
    diag = d.get('diagnosis', {})
    if diag in (None, ''):
        diag = {}
    if not isinstance(diag, dict):
        raise Refused('diagnosis must be an object')
    diag_json = json.dumps(diag, ensure_ascii=False, separators=(',', ':'))
    if len(diag_json.encode()) > DIAG_MAX:
        raise Refused('diagnosis: at most 32 KB', 'too_large', 413)
    log = d.get('log', '')
    log = _text(log if log is not None else '', 'log', LOG_MAX)
    if len(log.encode()) > LOG_MAX:
        raise Refused('log: at most 64 KB', 'too_large', 413)
    device = d.get('device_id', '')
    if device not in ('', None) and not (isinstance(device, str) and UUID_RE.fullmatch(device)):
        raise Refused('device_id must be a lowercase UUID')
    if not (text or diag or log):
        raise Refused('text, diagnosis or log required')
    return {'client': json.dumps(_redact_json(c, u), ensure_ascii=False), 'text': redact(text, u),
            'diagnosis': json.dumps(_redact_json(diag, u), ensure_ascii=False) if diag else '{}',
            'log': redact(log, u), 'device_id': device or ''}


# --- storing ---------------------------------------------------------------------------------------------------
def add(u, d, now=None):
    """Store one; returns its id. Raises Refused (bad input, or 429 too often)."""
    row = clean(d, u)
    now = int(now or time.time())
    with db.transaction() as c:
        times = [r[0] for r in c.execute('SELECT created_at FROM feedback WHERE user_id=? AND created_at>? '
                                         'ORDER BY created_at', (u['id'], now - 86400))]
        if times and now - times[-1] < GAP:
            raise Refused('too many reports, wait a moment', 'rate_limited', 429, GAP - (now - times[-1]))
        if len(times) >= DAY_MAX:
            raise Refused('too many reports today', 'rate_limited', 429, max(1, times[-DAY_MAX] + 86400 - now))
        cur = c.execute('INSERT INTO feedback(user_id, created_at, device_id, client, text, diagnosis, log) '
                        'VALUES(?,?,?,?,?,?,?)', (u['id'], now, row['device_id'], row['client'], row['text'],
                                                  row['diagnosis'], row['log']))
        fid = cur.lastrowid
        c.execute('DELETE FROM feedback WHERE user_id=? AND id NOT IN '
                  '(SELECT id FROM feedback WHERE user_id=? ORDER BY id DESC LIMIT ?)', (u['id'], u['id'], PER_USER_KEEP))
        c.execute('DELETE FROM feedback WHERE id NOT IN (SELECT id FROM feedback ORDER BY id DESC LIMIT ?)', (TOTAL_KEEP,))
    return fid


def prune(now=None):
    """Daily: older than 30 days goes, answered or not."""
    with db.transaction() as c:
        return c.execute('DELETE FROM feedback WHERE created_at<?', (int(now or time.time()) - KEEP_DAYS * 86400,)).rowcount


# --- what the member sees -----------------------------------------------------------------------------------------
def for_member(uid, mark_seen=True):
    """Last 10, without logs. Reading them is what clears `feedback_unread`."""
    rows = db.q('SELECT id, created_at, text, status, answer, answered_at FROM feedback WHERE user_id=? '
                'ORDER BY id DESC LIMIT 10', (uid,))
    if mark_seen and rows:
        with db.transaction() as c:
            c.execute('UPDATE feedback SET seen=1 WHERE user_id=? AND seen=0', (uid,))
    return [dict(r, text=r['text'][:200]) for r in rows]


def unread(uid):
    return db.q('SELECT COUNT(*) FROM feedback WHERE user_id=? AND seen=0', (uid,))[0][0]


# --- the admin's side --------------------------------------------------------------------------------------------
def open_count():
    return db.q("SELECT COUNT(*) FROM feedback WHERE status='open'")[0][0]


def _client(text):
    try:
        v = json.loads(text)
        return v if isinstance(v, dict) else {}
    except ValueError:
        return {}


def admin_list():
    names = db.user_names()
    rows = db.q('SELECT id, user_id, created_at, client, substr(text, 1, 80) AS text, status, answer, answered_at, '
                "length(log) AS log_len, diagnosis != '{}' AS has_diag FROM feedback ORDER BY id DESC")
    return [dict(r, client=_client(r['client']), name=names.get(r['user_id'], '?'), has_diag=bool(r['has_diag']))
            for r in rows]


def admin_get(fid):
    rows = db.q('SELECT * FROM feedback WHERE id=?', (fid,))
    if not rows:
        return None
    r = dict(rows[0])
    try:
        r['diagnosis'] = json.loads(r['diagnosis'])
    except ValueError:
        r['diagnosis'] = {}
    r['client'] = _client(r['client'])
    r['name'] = db.user_names().get(r['user_id'], '?')
    return r


def admin_act(fid, action, answer=''):
    """'answer' (done, with a reply the member sees), 'done', 'reopen', 'delete'. False when there is no such."""
    with db.transaction() as c:
        if not c.execute('SELECT 1 FROM feedback WHERE id=?', (fid,)).fetchone():
            return False
        if action == 'delete':
            c.execute('DELETE FROM feedback WHERE id=?', (fid,))
        elif action == 'answer':
            text = ''.join(ch for ch in str(answer) if ch == '\n' or ord(ch) >= 32).strip()
            if not text:
                raise Refused('text required')
            if len(text) > ANSWER_MAX:
                raise Refused('answer: at most %d characters' % ANSWER_MAX)
            c.execute("UPDATE feedback SET status='done', answer=?, answered_at=?, seen=0 WHERE id=?",
                      (text, int(time.time()), fid))
        elif action == 'done':
            c.execute("UPDATE feedback SET status='done' WHERE id=?", (fid,))
        elif action == 'reopen':
            c.execute("UPDATE feedback SET status='open' WHERE id=?", (fid,))
        else:
            raise Refused('unknown action')
    return True
