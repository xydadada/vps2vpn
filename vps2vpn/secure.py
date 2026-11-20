"""Secrets, password hashing and REALITY (X25519) keys - standard library only."""
import base64
import hashlib
import hmac
import os
import secrets
import uuid

PBKDF2_ROUNDS = 240_000
MAX_PBKDF2_ROUNDS = 5_000_000


def token(nbytes=24):
    return secrets.token_urlsafe(nbytes)


def new_uuid():
    return str(uuid.uuid4())


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


def b64url_decode(text):
    return base64.urlsafe_b64decode(text + '=' * (-len(text) % 4))


def hash_password(password):
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, PBKDF2_ROUNDS)
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
        calc = hashlib.pbkdf2_hmac('sha256', password.encode(), b64url_decode(salt), n)
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
    return hmac.compare_digest(a.encode(), b.encode())


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
