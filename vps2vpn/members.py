"""Member centre rules: invite codes, self-registration, shared quota and quota requests.

Two kinds of invite codes, each usable `max_uses` times before it runs out:

* admin  - made by the admin with any quota and account lifetime; nobody is charged.
* member - made by a member. Each new account's quota is carved out of the inviter's: while the
           invitee is active, the inviter's effective quota shrinks by that amount. An inviter always
           keeps at least 1 GB, unlimited accounts cannot carve, and a member may have at most 5 live codes.
"""
import functools
import re
import secrets
import threading
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


_lock = threading.Lock()


def _serial(fn):
    """Check-then-write steps (quota room, uses left) must not interleave between web threads."""
    @functools.wraps(fn)
    def run(*a, **kw):
        with _lock:
            return fn(*a, **kw)
    return run


class Refused(ValueError):
    """A rule said no; the message is shown to the person."""


class CodeRefused(Refused):
    """The invite code itself is wrong, used up or expired: the only sign-up error that counts as a guess."""


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
    """Is this account currently charged to the person who invited it?"""
    now = time.time() if now is None else now
    if not u.get('invited_by') or u.get('invite_deduct', 0) <= 0:
        return False
    if u['expire_at'] and u['expire_at'] <= now:
        return False
    # Keep quota-exhausted and device-paused invitees charged so their quota cannot be recycled.
    return bool(u['enabled']) or u.get('disabled_reason') in ('quota', 'devices')


def _given_away(uid, by_inviter, now, seen):
    """What `uid` has handed out through invites. An invitee who no longer deducts (paused, expired) still passes
    on what it handed out itself, up to its own deduction. A loop with its own stack, not recursion: a chain of
    invites over ~1000 deep would end in RecursionError. Same order and same `seen` rule as the recursive form."""
    if uid in seen:
        return 0.0
    seen.add(uid)
    # frame: [user id, its invitees still to look at, total so far, deduction of the invitee being walked]
    stack = [[uid, iter(by_inviter.get(uid, ())), 0.0, 0.0]]
    while True:
        frame = stack[-1]
        for u in frame[1]:
            ded = u.get('invite_deduct', 0)
            if ded <= 0:
                continue
            if deducting(u, now):
                frame[2] += ded
            elif u['id'] not in seen:                # one already walked hands out nothing more here
                seen.add(u['id'])
                frame[3] = ded
                stack.append([u['id'], iter(by_inviter.get(u['id'], ())), 0.0, 0.0])
                break
        else:
            stack.pop()
            if not stack:
                return frame[2]
            parent = stack[-1]
            if frame[2] > 0:
                parent[2] += min(parent[3], frame[2])


def invitee_index(users):
    """{inviter id: [invited user rows]} for given_away / effective_quota.

    Build it once when working through many users: each call without it walks the whole list again,
    which turns a loop over all users into O(n^2). The rows are shared, not copied, so in-place updates
    to them (enabled, expire_at ...) are seen; a change to `invited_by` needs a new index."""
    by_inviter = {}
    for u in users:
        if u.get('invited_by'):
            by_inviter.setdefault(u['invited_by'], []).append(u)
    return by_inviter


def given_away(uid, users=None, now=None, index=None):
    """GB this user currently shares with accounts they invited.

    `index` (from invitee_index) or `users` (all users) may be passed by callers that already have them;
    otherwise only this user's invite chain is read from the database."""
    now = time.time() if now is None else now
    if index is None:
        index = invitee_index(users if users is not None else db.invite_tree(uid))
    return _given_away(uid, index, now, set())


def effective_quota(u, users=None, now=None, index=None):
    """Quota in GB after what the user shares with invitees (0 = unlimited)."""
    if not u['quota_gb']:
        return 0
    return max(0.0, u['quota_gb'] + extra(u) - given_away(u['id'], users, now, index))


def extra(u):
    """GB added by approved requests for the current period (cleared at the next traffic reset)."""
    try:
        return max(0.0, float(u.get('extra_gb') or 0))
    except (TypeError, ValueError, AttributeError):
        return 0.0


def _live(inv, now):
    return inv['status'] == 'unused' and inv['valid_until'] > now and inv['uses'] < inv['max_uses']


def reserved(uid, now=None):
    """GB promised by this member's still-usable codes (quota x remaining uses)."""
    now = time.time() if now is None else now
    return sum(i['quota_gb'] * (i['max_uses'] - i['uses'])
               for i in db.member_live_invites(uid, now) if i['kind'] == 'member')


def _room(u, now, keep=MIN_KEEP_GB):
    """GB left after shares, live reservations, traffic already used and `keep` GB of headroom.

    New grants use keep=MIN_KEEP_GB (the inviter keeps 1 GB usable on top of what they used).
    Redeeming an already-reserved code uses keep=0: spending the kept 1 GB must not void it;
    only an inviter who is actually over quota (or whose quota was lowered) voids codes.
    """
    if not u['quota_gb']:
        return None
    used_gb = (u.get('used_up', 0) + u.get('used_down', 0)) / (1 << 30)
    # This period's top-up (approved requests) is used first: what it covers takes nothing from the room.
    # The top-up itself is never room to share: it ends at the next reset, a share would outlive it.
    used_from_base = max(0.0, used_gb - extra(u))
    return u['quota_gb'] - given_away(u['id'], None, now) - reserved(u['id'], now) - used_from_base - keep


def capacity(u, now=None):
    """Largest total GB this member may still share; None = not allowed (unlimited account)."""
    room = _room(u, time.time() if now is None else now)
    return None if room is None else max(0.0, round(room, 3))


def propagate_lifetime(uid, new_expire_at, new_reset_day=None):
    """Propagate expiry (and optionally reset_day) to all descendants carved from uid."""
    fields = {}
    if new_expire_at is not None:
        fields['expire_at'] = int(new_expire_at)
        if int(new_expire_at):
            fields['expire_after_days'] = 0
    if new_reset_day is not None:
        fields['reset_day'] = int(new_reset_day)
    if not fields:
        return []
    updated = []
    with db.transaction():
        by_inviter = invitee_index(db.invite_tree(uid))
        queue = [uid]
        visited = {uid}
        while queue:
            cur = queue.pop(0)
            for child in by_inviter.get(cur, ()):
                cid = child['id']
                if cid in visited:
                    continue
                visited.add(cid)
                if child.get('invite_deduct', 0) > 0:
                    db.update_user(cid, **fields)
                    updated.append(cid)
                    queue.append(cid)
    return updated


def _num(v, low, high, label, integer=False):
    if isinstance(v, bool):                       # JSON true is no amount
        raise Refused('%s must be a number' % label)
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
                  by_member=False, now=None, servers='', speed_mbps=0, throttle_mbps=0):
    now = time.time() if now is None else now
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
        if by_member and len(db.member_live_invites(inviter, now)) >= MEMBER_PENDING_MAX:
            raise Refused('at most %d unused codes; use or revoke one first' % MEMBER_PENDING_MAX)
        # what the inviter may use is all the invitee may use: same servers, same speed rules
        rec.update(inviter=inviter, quota_gb=grant, max_uses=times, reset_day=u['reset_day'],
                   servers=u['servers'] or '', speed_mbps=u['speed_mbps'] or 0, throttle_mbps=u['throttle_mbps'] or 0)
    elif kind == 'admin':
        low, high = ADMIN_VALID_DAYS
        rec.update(quota_gb=_num(quota_gb, 0, 100000, 'quota (GB)'),
                   expire_days=_num(expire_days, 0, 3650, 'account lifetime (days)', True),
                   reset_day=_num(reset_day, 0, 31, 'reset day', True),
                   max_uses=_num(max_uses, 1, ADMIN_MAX_USES, 'uses', True),
                   speed_mbps=_num(speed_mbps or 0, 0, db.MAX_MBPS, 'speed limit (Mbps)'),
                   throttle_mbps=_num(throttle_mbps or 0, 0, db.MAX_MBPS, 'slow-down speed (Mbps)'))
        try:
            rec['servers'] = db.clean_servers(servers)
        except ValueError as e:
            raise Refused(str(e))
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
    now = time.time() if now is None else now
    inv = db.invite_by_code(normalize(code))
    if not inv or not _live(inv, now):
        raise CodeRefused('invite code is wrong, used up or expired')
    name = check_name(name)
    password = check_password(password)
    fields = {'login_hash': secure.hash_password(password)}
    if inv['kind'] == 'member':
        inviter = db.user(inv['inviter'])
        if not inviter or not _active(inviter, now):
            raise Refused('the person who invited you can no longer invite; the code is void')
        # This use is already counted in `reserved`; turning it into a deduction is neutral, so the books
        # still balance unless the inviter's quota was lowered or burned past their kept allowance.
        room = _room(inviter, now, keep=0.0)
        if room is None or room < -1e-9:
            raise Refused("the inviter's quota has run short; the code is void")
        fields.update(invited_by=inviter['id'], invite_deduct=inv['quota_gb'])
        expire_at = inviter['expire_at']
        if not expire_at and inviter.get('expire_after_days'):
            # The inviter's "N days from first use" has not started. Without this the invitee would have no
            # end at all while the inviter never connects; it gets the same N days from its own first use,
            # and the inviter's date replaces it once the inviter's clock starts (propagate_lifetime).
            fields['expire_after_days'] = inviter['expire_after_days']
    else:
        expire_at = int(now + inv['expire_days'] * 86400) if inv['expire_days'] else 0
    src = inviter if inv['kind'] == 'member' else inv     # the inviter's limits now: the admin may have tightened them
    fields.update(servers=src['servers'] or '', speed_mbps=src['speed_mbps'] or 0, throttle_mbps=src['throttle_mbps'] or 0)
    # in the panel's language (the panel shows a pre-0.2.50 English one in Chinese too)
    note = ('invite %s' if db.settings()['language'] == 'en' else '邀请码 %s') % inv['code'] + (
        ' · ' + inv['note'] if inv['note'] else '')
    with db.transaction():
        uid = db.add_user(name, inv['quota_gb'], expire_at, inv['reset_day'], note[:200], **fields)
        used = [x for x in inv['used_by'].split(',') if x] + [str(uid)]
        db.update_invite(inv['id'], uses=inv['uses'] + 1, used_by=','.join(used),
                         status='used' if inv['uses'] + 1 >= inv['max_uses'] else 'unused')
        db.add_event('register', uid, '%s via %s' % (name, inv['code']))
    return uid


def void_code(inv, now=None):
    """A usable member code that would be refused now: the inviter has no room left to honour it."""
    now = time.time() if now is None else now
    if inv['kind'] != 'member' or not _live(inv, now):
        return False
    inviter = db.user(inv['inviter'])
    if not inviter or not _active(inviter, now):
        return True
    room = _room(inviter, now, keep=0.0)
    return room is not None and room < -1e-9


def invite_view(inv, names, register_url=''):
    now = time.time()
    status = 'expired' if inv['status'] == 'unused' and inv['valid_until'] <= now else inv['status']
    used = [int(x) for x in inv['used_by'].split(',') if x]
    return {'id': inv['id'], 'code': inv['code'], 'kind': inv['kind'], 'status': status, 'quota_gb': inv['quota_gb'],
            'inviter': inv['inviter'], 'inviter_name': names.get(inv['inviter'], ''), 'uses': inv['uses'],
            'max_uses': inv['max_uses'], 'used_by': [names.get(u, '#%d' % u) for u in used],
            'expire_days': inv['expire_days'], 'reset_day': inv['reset_day'], 'valid_until': inv['valid_until'],
            'created_at': inv['created_at'], 'note': inv['note'], 'servers': db.server_list(inv),
            'speed_mbps': inv['speed_mbps'] or 0, 'throttle_mbps': inv['throttle_mbps'] or 0,
            'register_url': register_url + '#register=' + inv['code'] if register_url else '',
            'void': void_code(inv, now)}


@_serial
def request_more(uid, add_gb, reason):
    u = db.user(uid)
    if not u:
        raise Refused('no such account')
    if not u['quota_gb']:
        raise Refused('this account has no traffic limit')
    add_gb = _num(add_gb, 1, 10000, 'extra quota (GB)')
    reason = str(reason or '').strip()[:300]
    if any(r['status'] == 'pending' for r in db.requests(uid)):
        raise Refused('you already have a request waiting; the admin will answer it first')
    rid = db.add_request(uid, add_gb, reason)
    db.add_event('request', uid, '%s asks for +%g GB' % (u['name'], add_gb))
    return rid


@_serial
def decide(rid, approve, add_gb=None, answer=''):
    r = db.request_by_id(rid)
    if not r or r['status'] != 'pending':
        raise Refused('no pending request with that id')
    u = db.user(r['user_id'])
    if not u:
        raise Refused('the account no longer exists')
    answer = str(answer or '')[:200]
    if not approve:
        with db.transaction():
            db.decide_request(rid, 'rejected', answer)
        return
    gb = r['add_gb'] if add_gb in (None, '') else _num(add_gb, 0.1, 100000, 'extra quota (GB)')
    with db.transaction():
        if u['quota_gb']:                         # unlimited stays unlimited
            # A request is "more for now" ("exams this month"): a top-up for the current period, dropped at the
            # account's next traffic reset. Raising the plan itself is the owner's edit, not an approval.
            db.update_user(u['id'], extra_gb=extra(u) + gb)
        if u['disabled_reason'] == 'quota' or u['throttled']:
            # Switch it back on (or back to full speed) only if the new quota really covers what was used;
            # otherwise the next enforce pass would pause it again and tell the owner a second time.
            fresh = db.user(u['id'])
            now = time.time()
            quota = effective_quota(fresh, None, now)
            expired = bool(fresh['expire_at']) and fresh['expire_at'] <= now
            if not expired and (not fresh['quota_gb'] or fresh['used_up'] + fresh['used_down'] < quota * (1 << 30)):
                upd = {'throttled': 0}
                if u['disabled_reason'] == 'quota':
                    upd.update(enabled=1, disabled_reason='')
                db.update_user(u['id'], **upd)
        db.decide_request(rid, 'approved', answer, gb)
