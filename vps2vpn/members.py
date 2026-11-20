"""Member centre rules: invite codes, self-registration, shared quota and quota requests.

Two kinds of invite codes, each usable `max_uses` times before it runs out:

* admin  - made by the admin with any quota and account lifetime; nobody is charged.
* member - made by a member. Each new account's quota is carved out of the inviter's: active
           invitees reserve their grant; inactive ones retain their consumed share and downstream
           commitments, so only unused quota returns to the inviter. An inviter always
           keeps at least 1 GB, unlimited accounts cannot carve, and a member may have at most 5 live codes.
"""
import functools
import math
import re
import secrets
import time

from . import db, secure

ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789'   # no 0/O, 1/I/L
MIN_KEEP_GB = 1.0
MEMBER_PENDING_MAX = 5
MEMBER_VALID_DAYS = (1, 30)
ADMIN_VALID_DAYS = (1, 90)
MEMBER_MAX_USES = 20
ADMIN_MAX_USES = 1000
NAME_RE = re.compile(r'^[\w.\-一-鿿]{2,32}$')
MIN_PASSWORD = 8


def _serial(fn):
    """Check-then-write steps (quota room, uses left) must not interleave between web threads."""
    @functools.wraps(fn)
    def run(*a, **kw):
        with db.transaction():
            return fn(*a, **kw)
    return run


class Refused(ValueError):
    """A rule said no; the message is shown to the person."""


def new_code():
    pick = lambda: ''.join(secrets.choice(ALPHABET) for _ in range(5))
    return pick() + '-' + pick()


def normalize(code):
    if not isinstance(code, str) or len(code) > 32:
        return ''
    c = ''.join(ch for ch in code.upper() if ch in ALPHABET)
    return c[:5] + '-' + c[5:] if len(c) == 10 else ''


def _active(u, now):
    return bool(u['enabled']) and not (u['expire_at'] and u['expire_at'] <= now)


def deducting(u, now=None):
    """Does this account reserve its full grant from the inviter right now?"""
    return bool(u.get('invited_by')) and u.get('invite_deduct', 0) > 0 and _active(u, now or time.time())


def _invite_children(rows):
    children = {}
    for child in rows:
        if child.get('invited_by') and child.get('invite_deduct', 0) > 0:
            children.setdefault(child['invited_by'], []).append(child)
    return children

def _subtree_charge(account, children, now=None, allocate=False, ancestors=()):
    """Walk the invitation tree without depending on Python's recursion limit."""
    visiting = set(ancestors)

    def grant(u):
        return int(u.get('invite_deduct', 0) * (1 << 30))

    if account['id'] in visiting or (allocate and _active(account, now)):
        return grant(account)
    visiting.add(account['id'])
    stack = [[account, iter(children.get(account['id'], [])),
              account['used_up'] + account['used_down']]]
    while stack:
        frame = stack[-1]
        try:
            child = next(frame[1])
        except StopIteration:
            u, _, used = stack.pop()
            visiting.remove(u['id'])
            if not stack:
                return used
            stack[-1][2] += min(grant(u), used)
            continue
        if child['id'] in visiting or (allocate and _active(child, now)):
            frame[2] += grant(child)
        else:
            visiting.add(child['id'])
            stack.append([child, iter(children.get(child['id'], [])),
                          child['used_up'] + child['used_down']])

def spent_bytes(u, users=None):
    """Actual consumed bytes in an invite subtree, capped by each child's grant."""
    children = _invite_children(users if users is not None else db.users())
    return _subtree_charge(u, children)


def given_away(uid, users=None, now=None):
    """Allocated or already consumed GB; disabling an invitee never refunds traffic."""
    now = time.time() if now is None else now
    children = _invite_children(users if users is not None else db.users())
    return sum(min(int(u['invite_deduct'] * (1 << 30)),
                   _subtree_charge(u, children, now, True, (uid,)))
               for u in children.get(uid, [])) / (1 << 30)


def effective_quota(u, users=None, now=None):
    """Quota in GB after what the user shares with invitees (0 = unlimited)."""
    if not u['quota_gb']:
        return 0
    return max(0.0, u['quota_gb'] - given_away(u['id'], users, now))


def _live(inv, now):
    return inv['status'] == 'unused' and inv['valid_until'] > now and inv['uses'] < inv['max_uses']


def reserved(uid, now=None):
    """GB promised by this member's still-usable codes (quota x remaining uses)."""
    now = time.time() if now is None else now
    return db.q("SELECT COALESCE(SUM(quota_gb*(max_uses-uses)), 0) AS total FROM invites "
                "WHERE inviter=? AND kind='member' AND status='unused' AND valid_until>? AND uses<max_uses",
                (uid, now))[0]['total']


def _room(u, now):
    if not u['quota_gb']:
        return None
    # Bytes the inviter already consumed cannot be promised to another account. Preserve the
    # existing minimum *total* personal quota while never reducing it below recorded usage.
    retained = max(MIN_KEEP_GB, (u['used_up'] + u['used_down']) / (1 << 30))
    return u['quota_gb'] - given_away(u['id'], None, now) - reserved(u['id'], now) - retained


def capacity(u, now=None):
    """Largest total GB this member may still share; None = not allowed (unlimited account)."""
    room = _room(u, now or time.time())
    return None if room is None else math.floor(max(0.0, room) * 1000) / 1000


def _num(v, low, high, label, integer=False):
    try:
        n = int(v) if integer else float(v)
    except (TypeError, ValueError, OverflowError):
        raise Refused('%s must be a number' % label)
    if integer and isinstance(v, float) and v != int(v):
        raise Refused('%s must be a whole number' % label)
    if not low <= n <= high:
        raise Refused('%s must be between %s and %s' % (label, low, high))
    return n


@_serial
def create_invite(kind, quota_gb, valid_days, max_uses=1, inviter=0, expire_days=0, reset_day=0, note='',
                  by_member=False, now=None):
    now = now or time.time()
    note = str(note or '').strip()
    if len(note) > 100 or any(ord(c) < 32 for c in note):
        raise Refused('note: at most 100 characters')
    rec = {'code': new_code(), 'kind': kind, 'note': note, 'created_at': int(now)}
    if kind == 'member':
        u = db.user(inviter)
        if not u:
            raise Refused('inviter not found')
        if not _active(u, now):
            raise Refused('a paused or expired account cannot invite')
        low, high = MEMBER_VALID_DAYS if by_member else ADMIN_VALID_DAYS
        grant = _num(quota_gb, 0.1, 100000, 'quota (GB)')
        times = _num(max_uses, 1, MEMBER_MAX_USES, 'uses', True)
        room = capacity(u, now)
        if room is None:
            raise Refused('unlimited accounts cannot share quota; ask the admin for an invite code')
        if grant * times > room + 1e-9:
            raise Refused('not enough quota: %d x %g GB is more than the %.2f GB you can share '
                          '(you always keep at least 1 GB)' % (times, grant, room))
        live_codes = db.q("SELECT COUNT(*) AS total FROM invites WHERE inviter=? AND status='unused' "
                          "AND valid_until>? AND uses<max_uses", (inviter, now))[0]['total']
        if by_member and live_codes >= MEMBER_PENDING_MAX:
            raise Refused('at most %d unused codes; use or revoke one first' % MEMBER_PENDING_MAX)
        rec.update(inviter=inviter, quota_gb=grant, max_uses=times, reset_day=u['reset_day'])
    elif kind == 'admin':
        low, high = ADMIN_VALID_DAYS
        rec.update(quota_gb=_num(quota_gb, 0, 100000, 'quota (GB)'),
                   expire_days=_num(expire_days, 0, 3650, 'account lifetime (days)', True),
                   reset_day=_num(reset_day, 0, 28, 'reset day', True),
                   max_uses=_num(max_uses, 1, ADMIN_MAX_USES, 'uses', True))
    else:
        raise Refused('unknown invite kind')
    rec['valid_until'] = int(now + _num(valid_days, low, high, 'code valid for (days)', True) * 86400)
    while db.invite_by_code(rec['code']):
        rec['code'] = new_code()
    rec['id'] = db.add_invite(**rec)
    return rec


@_serial
def revoke_invite(iid, by_member=None):
    inv = db.invite(iid)
    if not inv or (by_member is not None and inv['inviter'] != by_member):
        raise Refused('no such invite code')
    if inv['status'] != 'unused':
        raise Refused('this code is already used up or revoked')
    db.update_invite(iid, status='revoked')


def check_name(name):
    name = str(name or '').strip()
    if not NAME_RE.match(name):
        raise Refused('name: 2-32 letters, digits, Chinese characters, "." "_" or "-"')
    if db.user_by_name(name):
        raise Refused('that name is taken, pick another')
    return name


def check_password(pw):
    pw = str(pw or '')
    if len(pw) < MIN_PASSWORD or len(pw) > 128:
        raise Refused('password: %d to 128 characters' % MIN_PASSWORD)
    return pw


@_serial
def register(code, name, password, now=None):
    """Use an invite code to create an account with a member-centre login. Returns the new user id."""
    now = now or time.time()
    inv = db.invite_by_code(normalize(code))
    if not inv or not _live(inv, now):
        raise Refused('invite code is wrong, used up or expired')
    name = check_name(name)
    password = check_password(password)
    fields = {'login_hash': secure.hash_password(password)}
    if inv['kind'] == 'member':
        inviter = db.user(inv['inviter'])
        if not inviter or not _active(inviter, now):
            raise Refused('the person who invited you can no longer invite; the code is void')
        # This use is already counted in `reserved`; turning it into a deduction is neutral, so the books
        # still balance unless the inviter's quota was lowered in the meantime.
        room = _room(inviter, now)
        if room is None or room < -1e-9:
            raise Refused("the inviter's quota has run short; the code is void")
        fields.update(invited_by=inviter['id'], invite_deduct=inv['quota_gb'])
        expire_at = inviter['expire_at']
    else:
        expire_at = int(now + inv['expire_days'] * 86400) if inv['expire_days'] else 0
    note = 'invite %s' % inv['code'] + (' · ' + inv['note'] if inv['note'] else '')
    uid = db.add_user(name, inv['quota_gb'], expire_at, inv['reset_day'], note[:200], **fields)
    used = [x for x in inv['used_by'].split(',') if x] + [str(uid)]
    db.update_invite(inv['id'], uses=inv['uses'] + 1, used_by=','.join(used),
                     status='used' if inv['uses'] + 1 >= inv['max_uses'] else 'unused')
    db.add_event('register', uid, '%s via %s' % (name, inv['code']))
    return uid


def invite_view(inv, names, register_url=''):
    now = time.time()
    status = 'expired' if inv['status'] == 'unused' and inv['valid_until'] <= now else inv['status']
    used = [int(x) for x in inv['used_by'].split(',') if x]
    return {'id': inv['id'], 'code': inv['code'], 'kind': inv['kind'], 'status': status, 'quota_gb': inv['quota_gb'],
            'inviter': inv['inviter'], 'inviter_name': names.get(inv['inviter'], ''), 'uses': inv['uses'],
            'max_uses': inv['max_uses'], 'used_by': [names.get(u, '#%d' % u) for u in used],
            'expire_days': inv['expire_days'], 'reset_day': inv['reset_day'], 'valid_until': inv['valid_until'],
            'created_at': inv['created_at'], 'note': inv['note'],
            'register_url': register_url + '#register=' + inv['code'] if register_url else ''}


@_serial
def request_more(uid, add_gb, reason):
    u = db.user(uid)
    if not u:
        raise Refused('no such account')
    add_gb = _num(add_gb, 1, 10000, 'extra quota (GB)')
    reason = str(reason or '').strip()[:300]
    if any(r['status'] == 'pending' for r in db.requests(uid)):
        raise Refused('you already have a request waiting; the admin will answer it first')
    rid = db.add_request(uid, add_gb, reason)
    db.add_event('request', uid, '%s asks for +%g GB' % (u['name'], add_gb))
    return rid


@_serial
def decide(rid, approve, add_gb=None, answer=''):
    r = next((x for x in db.requests() if x['id'] == rid), None)
    if not r or r['status'] != 'pending':
        raise Refused('no pending request with that id')
    u = db.user(r['user_id'])
    if not u:
        raise Refused('the account no longer exists')
    answer = str(answer or '')[:200]
    if not approve:
        db.decide_request(rid, 'rejected', answer)
        return
    gb = r['add_gb'] if add_gb in (None, '') else _num(add_gb, 0.1, 100000, 'extra quota (GB)')
    if u['quota_gb']:                         # unlimited stays unlimited
        db.update_user(u['id'], quota_gb=u['quota_gb'] + gb)
    if u['disabled_reason'] == 'quota':
        db.update_user(u['id'], enabled=1, disabled_reason='')
    db.decide_request(rid, 'approved', answer, gb)
