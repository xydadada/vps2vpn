"""Secrets, password hashing and REALITY (X25519) keys - standard library only."""
import base64
import hashlib
import hmac
import json
import math
import os
import secrets
import uuid

PBKDF2_ROUNDS = 240_000
JSON_MAX_DEPTH = 64          # the deepest real body (cluster sync, settings) is under 10 levels
JSON_MAX_INT_DIGITS = 4300   # Python 3.11's own limit; 3.8 would convert a 4 MB number in quadratic time


class BadJson(ValueError):
    """`kind` is 'unicode' for a lone surrogate (valid JSON, not text), else 'json'."""
    def __init__(self, why, kind='json'):
        super().__init__(why)
        self.kind = kind


def _json_object(pairs):
    out = {}
    for k, v in pairs:
        if k in out:     # {"a": 1, "a": 2}: two readers of one request could disagree on what it says
            raise BadJson('duplicate key')
        out[k] = v
    return out


def _json_float(text):
    v = float(text)
    if not math.isfinite(v):        # 1e999 becomes inf without ever reaching parse_constant
        raise BadJson('number out of range')
    return v


def _json_int(text):
    if len(text.lstrip('-')) > JSON_MAX_INT_DIGITS:
        raise BadJson('number out of range')
    return int(text)


def _json_constant(name):
    raise BadJson('NaN and Infinity are not JSON')


def loads_json(data, max_depth=JSON_MAX_DEPTH):
    """json.loads for data from the network: no duplicate keys, NaN / Infinity / overflowing numbers, nesting past
    `max_depth` (very deep input would otherwise end in RecursionError, not ValueError), or lone surrogates.
    Every refusal is a BadJson, which is a ValueError, so existing `except ValueError` handlers keep working."""
    try:
        obj = json.loads(data, object_pairs_hook=_json_object, parse_float=_json_float, parse_int=_json_int,
                         parse_constant=_json_constant)
    except RecursionError:
        raise BadJson('nested too deeply')
    except BadJson:
        raise
    except (ValueError, TypeError) as e:
        raise BadJson(str(e))
    stack = [(obj, 0)]                       # a loop, not recursion, for the same reason
    while stack:
        v, depth = stack.pop()
        if isinstance(v, str):
            if any(0xd800 <= ord(c) <= 0xdfff for c in v):
                raise BadJson('invalid unicode', 'unicode')
        elif isinstance(v, (dict, list)):
            if depth >= max_depth:
                raise BadJson('nested too deeply')
            if isinstance(v, dict):
                stack.extend((k, depth + 1) for k in v)
                v = v.values()
            stack.extend((x, depth + 1) for x in v)
    return obj
MAX_PBKDF2_ROUNDS = 5_000_000


def token(nbytes=24):
    return secrets.token_urlsafe(nbytes)


def new_uuid():
    return str(uuid.uuid4())


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


def b64url_decode(text):
    return base64.urlsafe_b64decode(text + '=' * (-len(text) % 4))


def _utf8(text):
    # 'surrogatepass': a lone surrogate (a password typed on a non-UTF-8 terminal, say) is still bytes, the
    # same bytes every time, instead of an exception halfway through a sign-in.
    return text.encode('utf-8', 'surrogatepass')


def hash_password(password):
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac('sha256', _utf8(password), salt, PBKDF2_ROUNDS)
    return 'pbkdf2_sha256$%d$%s$%s' % (PBKDF2_ROUNDS, b64url(salt), b64url(digest))


def check_password(password, stored):
    try:
        if not isinstance(password, str) or not isinstance(stored, str):
            return False
        algo, rounds, salt, digest = stored.split('$')
        if algo != 'pbkdf2_sha256':
            return False
        n = int(rounds)
        if not 1 <= n <= MAX_PBKDF2_ROUNDS:
            return False
        calc = hashlib.pbkdf2_hmac('sha256', _utf8(password), b64url_decode(salt), n)
        return hmac.compare_digest(calc, b64url_decode(digest))
    except (ValueError, AttributeError):
        return False


# --- X25519 (RFC 7748), used for REALITY keys -------------------------------
_P = 2 ** 255 - 19
_A24 = 121665


def _clamp(k):
    b = bytearray(k)
    b[0] &= 248
    b[31] &= 127
    b[31] |= 64
    return bytes(b)


def x25519(scalar, u_point):
    if len(scalar) != 32 or len(u_point) != 32:
        raise ValueError('X25519 inputs must be 32 bytes')
    k = int.from_bytes(_clamp(scalar), 'little')
    u = bytearray(u_point)
    u[31] &= 127
    x1 = int.from_bytes(u, 'little') % _P
    x2, z2, x3, z3, swap = 1, 0, x1, 1, 0
    for t in range(254, -1, -1):
        bit = (k >> t) & 1
        swap ^= bit
        if swap:
            x2, x3, z2, z3 = x3, x2, z3, z2
        swap = bit
        a = (x2 + z2) % _P
        aa = a * a % _P
        b = (x2 - z2) % _P
        bb = b * b % _P
        e = (aa - bb) % _P
        c = (x3 + z3) % _P
        d = (x3 - z3) % _P
        da = d * a % _P
        cb = c * b % _P
        x3 = (da + cb) ** 2 % _P
        z3 = x1 * (da - cb) ** 2 % _P
        x2 = aa * bb % _P
        z2 = e * (aa + _A24 * e) % _P
    if swap:
        x2, x3, z2, z3 = x3, x2, z3, z2
    return (x2 * pow(z2, _P - 2, _P) % _P).to_bytes(32, 'little')


def reality_public_key(private_key):
    return b64url(x25519(b64url_decode(private_key), (9).to_bytes(32, 'little')))


def reality_keypair():
    """Same format as `xray x25519`: base64url without padding."""
    private = b64url(_clamp(os.urandom(32)))
    return private, reality_public_key(private)


def short_id():
    return secrets.token_hex(8)


def hmac_eq(a, b):
    """Constant-time string compare; non-strings or an empty expected value never match."""
    if not isinstance(a, str) or not isinstance(b, str) or not b:
        return False
    return hmac.compare_digest(_utf8(a), _utf8(b))


# --- TOTP (RFC 6238) for the admin's optional second factor ---------------------
def totp_secret():
    return base64.b32encode(os.urandom(20)).decode().rstrip('=')


def totp(secret, at=None, step=30, digits=6):
    import struct
    import time
    key = base64.b32decode(secret.upper() + '=' * (-len(secret) % 8))
    counter = int((time.time() if at is None else at) // step)
    mac = hmac.new(key, struct.pack('>Q', counter), hashlib.sha1).digest()
    off = mac[-1] & 15
    return '%0*d' % (digits, (int.from_bytes(mac[off:off + 4], 'big') & 0x7fffffff) % 10 ** digits)


def totp_check(secret, code, at=None, window=1):
    """Accept the current code and one step either side (clock drift)."""
    import time
    code = ''.join(c for c in str(code or '') if c.isdigit())
    if not isinstance(secret, str) or not secret or len(code) != 6:
        return False
    now = time.time() if at is None else at
    try:
        return any(hmac.compare_digest(totp(secret, now + k * 30), code) for k in range(-window, window + 1))
    except (ValueError, TypeError, AttributeError):
        return False
