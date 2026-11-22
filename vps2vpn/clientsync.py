"""Keeps the app installers members download (paths.CLIENT) at the newest vps2vpn client release.

Every few hours the panel asks GitHub for the latest release of the client. When it is newer than what
the client folder holds, the installer each platform updates itself from (the Windows setup program,
an Android APK) is downloaded with its `.sig`, and published only when that is the release key's
signature for it, the same check the app makes before it installs anything. Older copies this module
downloaded itself are then removed; files the owner put there by hand are never touched.
"""
import hashlib
import json
import os
import re
import tempfile
import threading
import urllib.request

from . import paths

RELEASE_API = 'https://api.github.com/repos/xydadada/vps2vpn-client/releases/latest'
# The client's update key (lib/vps2vpn/update_signing.dart in the client).
PUBLIC_KEY = bytes.fromhex('39f3a52a75eaf2175a8e3c7f8e0d3c2b2a6dcea45a6e97a878864a61d9e7f7b5')
MAX_INSTALLER = 512 << 20
MAX_SIG = 4096
MANIFEST = '.vps2vpn-auto.json'        # names this module downloaded, so only those are ever removed
# What an app installs by itself; a portable zip would only add a big file nobody updates from.
SELF_UPDATING = re.compile(r'vps2vpn-v?(\d+(?:\.\d+){1,3})-(?:windows-[a-z0-9]+-setup\.exe|android-[a-z0-9]+\.apk)')

_lock = threading.Lock()


# --- Ed25519 verification (RFC 8032), the standard library has none ------------------------------
_P = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_I = pow(2, (_P - 1) // 4, _P)


def _add(a, b):
    x1, y1, z1, t1 = a
    x2, y2, z2, t2 = b
    A = (y1 - x1) * (y2 - x2) % _P
    B = (y1 + x1) * (y2 + x2) % _P
    C = 2 * t1 * t2 * _D % _P
    D = 2 * z1 * z2 % _P
    E, F, G, H = B - A, D - C, D + C, B + A
    return (E * F % _P, G * H % _P, F * G % _P, E * H % _P)


def _mul(s, p):
    q = (0, 1, 1, 0)
    while s:
        if s & 1:
            q = _add(q, p)
        p = _add(p, p)
        s >>= 1
    return q


def _equal(a, b):
    return (a[0] * b[2] - b[0] * a[2]) % _P == 0 and (a[1] * b[2] - b[1] * a[2]) % _P == 0


def _decompress(s):
    if len(s) != 32:
        return None
    y = int.from_bytes(s, 'little')
    sign = y >> 255
    y &= (1 << 255) - 1
    if y >= _P:
        return None
    x2 = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    if x2 == 0:
        if sign:
            return None
        x = 0
    else:
        x = pow(x2, (_P + 3) // 8, _P)
        if (x * x - x2) % _P:
            x = x * _I % _P
        if (x * x - x2) % _P:
            return None
        if x & 1 != sign:
            x = _P - x
    return (x, y, 1, x * y % _P)


_G = _decompress(bytes.fromhex('5866666666666666666666666666666666666666666666666666666666666666'))


def ed25519_verify(public, message, signature):
    if len(public) != 32 or len(signature) != 64:
        return False
    a = _decompress(public)
    r = _decompress(signature[:32])
    s = int.from_bytes(signature[32:], 'little')
    if a is None or r is None or s >= _L:
        return False
    h = int.from_bytes(hashlib.sha512(signature[:32] + public + message).digest(), 'little') % _L
    return _equal(_mul(s, _G), _add(r, _mul(h, a)))


def statement(name, sha256_hex, size):
    """What the release key signs for one installer (as the app checks it)."""
    return ('vps2vpn-update-v1\n%s\n%s\n%d\n' % (name, sha256_hex, size)).encode()


def signature_ok(name, sha256_hex, size, sig_text, public=None):
    import base64
    import binascii
    public = public or PUBLIC_KEY
    try:
        sig = base64.b64decode(sig_text.strip(), validate=True)
    except (binascii.Error, ValueError):
        return False
    return ed25519_verify(public, statement(name, sha256_hex, size), sig)


# --- syncing --------------------------------------------------------------------------------------
def _version(v):
    return tuple(int(x) for x in v.split('.'))


def _get(url, limit, timeout=30):
    req = urllib.request.Request(url, headers={'User-Agent': 'vps2vpn-panel', 'Accept': 'application/vnd.github+json'})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        data = r.read(limit + 1)
    if len(data) > limit:
        raise ValueError('%s is larger than expected' % url)
    return data


def _download(url, dest_dir, name, timeout=60):
    """Stream `url` into a private temp file in dest_dir. Returns (path, sha256 hex, size)."""
    fd, tmp = tempfile.mkstemp(prefix='.vps2vpn-', suffix='.part', dir=dest_dir)
    digest, size = hashlib.sha256(), 0
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'vps2vpn-panel', 'Accept': 'application/octet-stream'})
        with os.fdopen(fd, 'wb') as out, urllib.request.urlopen(req, timeout=timeout) as r:
            while True:
                chunk = r.read(1 << 16)
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_INSTALLER:
                    raise ValueError('%s is larger than %d MB' % (name, MAX_INSTALLER >> 20))
                digest.update(chunk)
                out.write(chunk)
        if not size:
            raise ValueError('%s is empty' % name)
        return tmp, digest.hexdigest(), size
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _manifest(folder):
    try:
        with open(os.path.join(folder, MANIFEST), encoding='utf-8') as f:
            names = json.load(f)
        return [n for n in names if isinstance(n, str)] if isinstance(names, list) else []
    except (OSError, ValueError):
        return []


def _save_manifest(folder, names):
    paths.write_atomic(os.path.join(folder, MANIFEST), json.dumps(sorted(set(names))))


def held_version(folder):
    """Newest version among the self-updating installers in `folder` that carry a signature."""
    best = None
    try:
        names = os.listdir(folder)
    except OSError:
        return None
    for n in names:
        m = SELF_UPDATING.fullmatch(n)
        if m and os.path.isfile(os.path.join(folder, n + '.sig')):
            v = _version(m.group(1))
            best = v if best is None or v > best else best
    return best


def sync(s, log=print, folder=None, api=RELEASE_API):
    """Fetch the latest client release when it is newer than the folder's. Returns the new version or None."""
    if not s.get('client_auto_update', True):
        return None
    folder = folder or paths.CLIENT
    if not _lock.acquire(blocking=False):
        return None
    try:
        release = json.loads(_get(api, 1 << 20, timeout=20))
        if not isinstance(release, dict) or release.get('draft') or release.get('prerelease'):
            return None
        assets = {a.get('name'): a.get('browser_download_url') for a in release.get('assets') or []
                  if isinstance(a, dict) and isinstance(a.get('name'), str)
                  and str(a.get('browser_download_url') or '').startswith('https://')}
        wanted = {}
        for name in assets:
            m = SELF_UPDATING.fullmatch(name)
            if m and name + '.sig' in assets:
                wanted[name] = _version(m.group(1))
        if not wanted:
            return None
        newest = max(wanted.values())
        held = held_version(folder)
        if held is not None and held > newest:
            return None
        # One platform's installer at newest does not mean its siblings arrived.
        missing = {name for name, v in wanted.items() if v == newest and
                   (not os.path.isfile(os.path.join(folder, name)) or
                    not os.path.isfile(os.path.join(folder, name + '.sig')))}
        if not missing:
            return None
        os.makedirs(folder, exist_ok=True)
        published = []
        failed = False
        for name in sorted(missing):
            # Each platform on its own: one that fails must neither hold back the others nor leave what was
            # already published out of the manifest (which is what later syncs clean up by).
            try:
                sig = _get(assets[name + '.sig'], MAX_SIG).decode('ascii', 'replace')
                tmp, sha, size = _download(assets[name], folder, name)
            except (OSError, ValueError) as e:
                failed = True
                log('client update %s: download failed (%s); tried again later' % (name, e))
                continue
            if not signature_ok(name, sha, size, sig):
                os.unlink(tmp)
                log('client update %s: the signature does not match; not published' % name)
                continue
            # Private like the rest of /var/lib/vps2vpn (the panel serves them as root): 0600, not the umask's.
            paths.write_atomic(os.path.join(folder, name + '.sig.tmp'), sig.strip() + '\n')
            os.chmod(tmp, 0o600)
            os.replace(tmp, os.path.join(folder, name))
            os.replace(os.path.join(folder, name + '.sig.tmp'), os.path.join(folder, name + '.sig'))
            published.append(name)
        if not published:
            if failed:
                raise OSError('no client installer could be downloaded')
            return None
        # Remove only what an earlier sync brought in and this one superseded.
        mine = _manifest(folder)
        keep = []
        for n in mine:
            m = SELF_UPDATING.fullmatch(n)
            if n in published or not m or _version(m.group(1)) >= newest:
                keep.append(n)
                continue
            for p in (n, n + '.sig'):
                try:
                    os.unlink(os.path.join(folder, p))
                except OSError:
                    pass
        _save_manifest(folder, keep + published)
        version = '.'.join(map(str, newest))
        log('client %s from GitHub is now offered to members (%s)' % (version, ', '.join(published)))
        return version
    finally:
        _lock.release()
