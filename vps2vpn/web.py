"""The web panel and subscription server.

One port serves both HTTPS and plain HTTP: the first byte of a connection tells them apart.
Plain HTTP only serves subscriptions and rule files (for clients that refuse a self-signed
certificate); the admin panel and the member centre always require HTTPS.

URL map (paths are secret random prefixes chosen at install time):
  /s/<token>                 subscription (apps) or the person's own page (browsers)
  /s/<token>/api/...         that page's API, authorised by the token in the path
  /rules/<set>.mrs|srs|list  routing rule sets for Clash / sing-box / Shadowrocket
  /<member_path>/            member centre: sign in with name + password, or register with an invite code
  /<panel_path>/             admin panel (and /api/node/sync for a main server, authorised by the node key)
"""
import hmac
import html
import http.server
import ipaddress
import json
import math
import mimetypes
import os
import re
import signal
import socket
import sqlite3
import ssl
import stat
import threading
import time
import urllib.error
import urllib.parse

from . import (VERSION, abuse, aicheck, certs, cluster, cores, db, doctor, jobs, members, monitor, notify, paths, qr, rules,
               secure, shaper, subscription, system)

SETUP_TOKEN_FILE = paths.ETC + '/setup-token'
_fails = {}                    # rate-limit bucket -> [monotonic timestamps] of failed attempts
_fails_lock = threading.Lock()
_FAIL_CAP = 2000
_totp_lock = threading.Lock()
_totp_last_step = {}           # secret -> last accepted 30s time-step (prevents replay)
_apply_lock = threading.Lock()
_apply_pending = False
_apply_force = False
_apply_running = False
_cert_lock = threading.Lock()
_SVG_CSP = "default-src 'none'; style-src 'none'; sandbox"


class _BadRequest(ValueError):
    """Malformed HTTP request framing, JSON body, or query parameter (answered with 400)."""


def _has_surrogate(v):
    if isinstance(v, str):
        return any(0xd800 <= ord(c) <= 0xdfff for c in v)
    if isinstance(v, list):
        return any(_has_surrogate(x) for x in v)
    if isinstance(v, dict):
        return any(_has_surrogate(k) or _has_surrogate(x) for k, x in v.items())
    return False


def _rate_key(ip):
    """Aggregate IPv6 clients to /64 so a single host cannot rotate IIDs to bypass rate limits."""
    try:
        addr = ipaddress.ip_address(ip.split('%', 1)[0])
        # A dual-stack listener brings IPv4 clients as ::ffff:a.b.c.d, which would all fall into one /64.
        if addr.version == 6 and addr.ipv4_mapped is not None:
            addr = addr.ipv4_mapped
        if addr.version == 6:
            return str(ipaddress.ip_network((addr, 64), strict=False))
        return str(addr)
    except ValueError:
        return ip


def _totp_consume(secret, code):
    """Verify a TOTP code and reject replaying the same or an older 30 s time-step."""
    digits = ''.join(c for c in str(code or '') if c.isdigit())
    if not isinstance(secret, str) or not secret or len(digits) != 6:
        return False
    cur = int(time.time() // 30)
    matched = None
    try:
        for k in (-1, 0, 1):
            if hmac.compare_digest(secure.totp(secret, (cur + k) * 30), digits):
                matched = cur + k
                break
    except (ValueError, TypeError, AttributeError):
        return False
    if matched is None:
        return False
    with _totp_lock:
        if matched <= _totp_last_step.get(secret, -1):
            return False
        if len(_totp_last_step) > 64:
            _totp_last_step.clear()
        _totp_last_step[secret] = matched
    return True


def _norm_host(host):
    if hasattr(certs, '_norm_host'):
        return certs._norm_host(host)
    h = str(host or '').strip()
    if not h:
        return ''
    try:
        return str(ipaddress.ip_address(h.strip('[]')))
    except ValueError:
        return h.lower().rstrip('.')


def _is_private_ip(addr):
    if addr.version == 6:
        # An IPv4 address carried inside IPv6 (mapped, NAT64, 6to4, Teredo) is judged as that IPv4 address.
        # (NAT64's 64:ff9b::/96 is already reserved.)
        inner = addr.ipv4_mapped or addr.sixtofour or (addr.teredo[1] if addr.teredo else None)
        if inner is not None and _is_private_ip(inner):
            return True
    return (addr.is_private or addr.is_loopback or addr.is_link_local
            or addr.is_multicast or addr.is_reserved or addr.is_unspecified)



def _is_private_host(host):
    h = (host or '').strip().strip('[]').lower()
    if not h or h == 'localhost' or h.endswith('.localhost') or h.endswith('.local'):
        return True
    try:
        return _is_private_ip(ipaddress.ip_address(h))
    except ValueError:
        pass
    if paths.LIVE:
        try:
            infos = socket.getaddrinfo(h, 443, type=socket.SOCK_STREAM)
        except OSError:
            return False
        for info in infos:
            try:
                if _is_private_ip(ipaddress.ip_address(info[4][0].split('%', 1)[0])):
                    return True
            except ValueError:
                continue
    return False


def _propagate_lifetime(uid, old_expire, new_expire=None, old_reset=None, new_reset=None):
    """Propagate expiry and reset_day recursively to accounts carved from this user's quota."""
    if hasattr(members, 'propagate_lifetime'):
        updated = members.propagate_lifetime(uid, new_expire, new_reset)
        if updated and new_reset and not old_reset:
            t_now = time.localtime()
            if t_now.tm_mday >= new_reset:
                month = time.strftime('%Y-%m', t_now)
                for cid in updated:
                    child = db.user(cid)
                    if child and not child['last_reset']:
                        db.update_user(cid, last_reset=month)
        return
    by_inviter = {}
    for x in db.users():
        if x['invited_by'] and x['invite_deduct']:
            by_inviter.setdefault(x['invited_by'], []).append(x)
    queue = [uid]
    seen = {uid}
    t_now = time.localtime()
    month = time.strftime('%Y-%m', t_now)
    while queue:
        cur = queue.pop(0)
        for child in by_inviter.get(cur, ()):
            cid = child['id']
            if cid in seen:
                continue
            seen.add(cid)
            upd = {}
            if new_expire is not None:
                upd['expire_at'] = int(new_expire)
                if int(new_expire):
                    upd['expire_after_days'] = 0
            if new_reset is not None:
                upd['reset_day'] = int(new_reset)
                if new_reset > 0 and child['reset_day'] == 0 and not child['last_reset'] and t_now.tm_mday >= new_reset:
                    upd['last_reset'] = month
            if upd:
                db.update_user(cid, **upd)
            queue.append(cid)


def _csv_cell(v):
    """Neutralize spreadsheet formula prefixes in exported CSV cells."""
    if isinstance(v, (int, float)) and v >= 0:
        return v
    s = str(v)
    if s and (s[0] in ('=', '+', '-', '@', '\t', '\r') or s.lstrip()[:1] in ('=', '+', '-', '@')):
        return "'" + s
    return s


def setup_token():
    try:
        with open(SETUP_TOKEN_FILE, encoding='utf-8') as f:
            return f.read().strip()
    except OSError:
        return ''


def ai_view(res):
    """The last AI check, for the member page and the app: {'summary': 'Claude ✓ ...', 'sites': {'claude': 'ok'}}."""
    if not res or not res.get('sites'):
        return None
    return {'summary': aicheck.summary(res), 'place': aicheck.place_name(res), 'at': res.get('at', 0),
            'sites': {k: res['sites'][k]['status'] for k in aicheck.SITES if k in res['sites']}}


CLIENT_FILE = re.compile(r'vps2vpn-v?(\d+(?:\.\d+){0,3})-([a-z0-9]+)[a-z0-9._-]*\.(exe|msi|apk|dmg|zip|AppImage|deb)')
# Matches client lib/common/release_asset.dart's current releaseAssetName().
# The legacy numeric-first naming above remains valid for older installers.
CLIENT_FILE_RELEASE = re.compile(
    r'vps2vpn-(dev|rs)-(\d+\.\d+\.\d+(?:-[A-Za-z0-9.]+)?)-'
    r'(windows|macos|linux|android)-(amd64|arm64|armv7|universal)'
    r'(?:-(setup|portable))?\.(exe|msi|apk|dmg|zip|AppImage|deb)')


def _ver(v):
    core, _, prerelease = v.partition('-')
    numbers = tuple(int(x) for x in core.split('.'))
    # SemVer: a normal release outranks a prerelease of the same core.
    # Compare numeric prerelease identifiers numerically (rs.10 > rs.2).
    pre = tuple((0, int(p)) if p.isdigit() else (1, p) for p in prerelease.split('.')) if prerelease else ()
    return (numbers + (0,) * (4 - len(numbers)), int(not bool(prerelease)), pre)


def _client_asset(name):
    """(version, platform, preference) for a legacy or current client artifact."""
    modern = CLIENT_FILE_RELEASE.fullmatch(name)
    if modern:
        line, version, platform, arch, form, ext = modern.groups()
        # The member API exposes one download per OS. Prefer common builds
        # and a Windows installer when several architectures/forms coexist.
        ranks = {
            'windows': ('amd64', 'arm64', 'universal', 'armv7'),
            'android': ('arm64', 'armv7', 'amd64', 'universal'),
            'macos': ('universal', 'arm64', 'amd64', 'armv7'),
            'linux': ('amd64', 'arm64', 'universal', 'armv7'),
        }
        arch_score = 4 - ranks[platform].index(arch)
        return version, platform, (2, arch_score, int(form == 'setup'), int(line == 'rs'), name)
    legacy = CLIENT_FILE.fullmatch(name)
    if legacy:
        return legacy.group(1), legacy.group(2), (1, 0, 0, 0, name)
    return None


def client_files():
    """Newest recognized client release and a deterministic default download for each OS."""
    try:
        names = os.listdir(paths.CLIENT)
    except OSError:
        return None
    best = {}
    for name in names:
        asset = _client_asset(name)
        if not asset or not os.path.isfile(os.path.join(paths.CLIENT, name)):
            continue
        version, platform, preference = asset
        current = best.setdefault(version, {}).get(platform)
        if current is None or preference > current[0]:
            best[version][platform] = (preference, name)
    if not best:
        return None
    v = max(best, key=_ver)
    files = {platform: entry[1] for platform, entry in best[v].items()}
    # The app refuses an installer without its signature (<installer>.sig from the same GitHub release).
    unsigned = sorted(n for n in files.values() if not os.path.isfile(os.path.join(paths.CLIENT, n + '.sig')))
    return {'version': v, 'files': files, 'unsigned': unsigned}


def client_info(s, link):
    """What the app shows as "new version": {'version', 'url', 'notes', 'files'} or None.
    `link` is the member's /s/<token> URL; installers in paths.CLIENT are downloaded through it."""
    found = client_files()
    files = {k: '%s/download/%s' % (link, n) for k, n in (found or {}).get('files', {}).items()}
    held = (found or {}).get('version', '')
    manual = (s['client_version'] or '').strip().lstrip('vV')
    version, link_ok = held or manual, True
    if manual and held and manual != held:
        try:
            newer = _ver(manual) > _ver(held)
        except ValueError:          # not a version number: the files here decide
            newer = False
        if newer:
            # Newer than the installers here: those would be refused as "not newer", so only the link is offered.
            version, files = manual, {}
        else:
            # A version typed in long ago must not hide the newer release synced since, nor its link.
            link_ok = False
    url = (s['client_url'] if link_ok else '') or files.get('windows') or next(iter(files.values()), '')
    if not version or not url:
        return None
    return {'version': version, 'url': url, 'notes': s['client_notes'], 'files': files}


_apply_retry = [0]          # seconds until the next retry after a failed apply (0 = last apply worked)


def apply_async(force=False):
    """Restarting cores can take a second; coalesce bursts and never block the HTTP response on it."""
    global _apply_pending, _apply_force, _apply_running
    start = False
    with _apply_lock:
        _apply_pending = True
        _apply_force = _apply_force or bool(force)
        if not _apply_running:
            _apply_running = True
            start = True
    if start:
        def go():
            global _apply_pending, _apply_force, _apply_running
            while True:
                with _apply_lock:
                    if not _apply_pending:
                        _apply_running = False
                        return
                    f = _apply_force
                    _apply_pending = False
                    _apply_force = False
                try:
                    cores.apply(force=f)
                    jobs.log('configs applied')
                    _apply_retry[0] = 0
                except Exception as e:
                    # The database already says who may connect; until a core has loaded that, a disabled
                    # account could still get in. Try again with backoff (1, 2, 4 … 15 min) instead of waiting
                    # for the next unrelated change.
                    _apply_retry[0] = min(_apply_retry[0] * 2 or 60, 900)
                    jobs.log('apply failed, retrying in %d s: %s' % (_apply_retry[0], e))
                    t = threading.Timer(_apply_retry[0], apply_async, kwargs={'force': f})
                    t.daemon = True
                    t.start()
        threading.Thread(target=go, daemon=True, name='apply').start()
    cluster.sync_soon()          # joined servers learn about user changes within seconds


class TLSContext:
    """Reloads the certificate when the files change (Let's Encrypt IP certs renew every few days)."""

    def __init__(self):
        self.ctx, self.key, self.checked = None, None, 0.0
        self.lock = threading.Lock()

    def get(self):
        with self.lock:
            now = time.monotonic()
            if self.ctx is not None and now - self.checked < 5.0:
                return self.ctx
            s = db.settings()
            host = s['domain'] or s['public_host']
            crt, key = certs.current(host)
            try:
                sc, sk = os.stat(crt), os.stat(key)
            except OSError:
                certs.ensure_self_signed(host or 'vps2vpn.local')
                crt, key = certs.current(host)
                sc, sk = os.stat(crt), os.stat(key)
            stamp = (crt, key, sc.st_ino, sc.st_mtime_ns, sc.st_size,
                     sk.st_ino, sk.st_mtime_ns, sk.st_size)
            if stamp != self.key:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ctx.minimum_version = ssl.TLSVersion.TLSv1_2
                try:
                    ctx.load_cert_chain(crt, key)
                except (ssl.SSLError, OSError):
                    if self.ctx is not None:
                        return self.ctx
                    raise
                ctx.set_alpn_protocols(['http/1.1'])
                self.ctx, self.key = ctx, stamp
            self.checked = now
            return self.ctx


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 128

    PER_CLIENT = 16          # open connections one address (an IPv6 /64) may hold at once

    def __init__(self, addr, handler, tls):
        self.tls = tls
        self._sem = threading.BoundedSemaphore(128)
        # Without a per-address share, one client opening 128 idle connections (each may wait 20 s for its
        # request) takes every worker and locks everyone else out of the panel and the subscriptions.
        self._per_client = {}
        self._per_client_lock = threading.Lock()
        if ':' in addr[0]:
            self.address_family = socket.AF_INET6
        super().__init__(addr, handler)

    def server_bind(self):
        if self.address_family == socket.AF_INET6:
            try:
                self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            except OSError:
                pass
        super().server_bind()

    def _client_slot(self, client_address, take):
        host = client_address[0] if client_address else ''
        try:
            ip = ipaddress.ip_address(host.split('%', 1)[0])
            loopback = ip.is_loopback or (ip.version == 6 and ip.ipv4_mapped is not None and ip.ipv4_mapped.is_loopback)
        except ValueError:
            loopback = False
        if loopback:
            # A reverse proxy on this machine (Caddy, nginx) brings every visitor from 127.0.0.1; a per-address
            # share would then cap the whole panel at PER_CLIENT. The global 128 still applies.
            return True
        key = _rate_key(host)
        with self._per_client_lock:
            n = self._per_client.get(key, 0)
            if take:
                if n >= self.PER_CLIENT:
                    return False
                self._per_client[key] = n + 1
            elif n <= 1:
                self._per_client.pop(key, None)
            else:
                self._per_client[key] = n - 1
        return True

    def process_request(self, request, client_address):
        if not self._client_slot(client_address, True):
            self.shutdown_request(request)
            return
        if not self._sem.acquire(blocking=False):
            self._client_slot(client_address, False)
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._sem.release()
            self._client_slot(client_address, False)
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._sem.release()
            self._client_slot(client_address, False)

    def finish_request(self, request, client_address):
        request.settimeout(20)
        try:
            first = request.recv(1, socket.MSG_PEEK)
        except OSError:
            return
        if not first:
            return
        is_tls = first == b'\x16'
        if is_tls:
            try:
                request = self.tls.get().wrap_socket(request, server_side=True)
            except (ssl.SSLError, OSError):
                return
        h = self.RequestHandlerClass.__new__(self.RequestHandlerClass)
        h.is_tls = is_tls
        try:
            h.__init__(request, client_address, self)
        finally:
            if is_tls:
                try:
                    request.close()
                except OSError:
                    pass

    def handle_error(self, request, client_address):
        pass          # scanners hammer every public port; don't fill the journal


def fmt_bytes(n):
    n = float(n or 0)
    for unit in ('B', 'KB', 'MB', 'GB', 'TB'):
        if n < 1024 or unit == 'TB':
            return ('%.0f %s' if unit in ('B', 'KB') else '%.2f %s') % (n, unit)
        n /= 1024


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = 'nginx'
    sys_version = ''
    protocol_version = 'HTTP/1.1'
    is_tls = False

    def log_message(self, *a):
        pass

    # --- helpers ----------------------------------------------------------------
    def send(self, code, body=b'', ctype='text/plain; charset=utf-8', headers=None):
        if isinstance(body, str):
            body = body.encode()
        if getattr(self, '_raw', b'') is None:
            # Read what the client sent even if the endpoint did not need it: replying with unread request
            # data still in the socket makes the kernel reset the connection, and the reply is lost on real
            # networks (seen with "check now" buttons that POST an empty JSON body). Only a small body,
            # though: endpoints that take a large one read it themselves, and buffering megabytes for any
            # request (a subscription URL is public) would let a few clients use up the memory. A larger
            # or chunked one closes the connection instead.
            te_vals = self.headers.get_all('Transfer-Encoding') or []
            cl_vals = self.headers.get_all('Content-Length') or []
            if (not te_vals and len(cl_vals) == 1
                    and re.fullmatch(r'\d{1,6}', cl_vals[0].strip())
                    and int(cl_vals[0].strip()) <= 65536):
                try:
                    self._read_body(65536)
                except (_BadRequest, ValueError, OSError):
                    self.close_connection = True
            elif te_vals or cl_vals:
                self.close_connection = True
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(body)))
        if self.close_connection and not any(k.lower() == 'connection' for k in (headers or {})):
            self.send_header('Connection', 'close')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        # No Strict-Transport-Security: if the certificate ever lapses (a failed renewal, a removed domain) the
        # panel falls back to a self-signed one, and HSTS would leave the admin no way to click through.
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(body)

    def json(self, obj, code=200, headers=None):
        self.send(code, json.dumps(obj, ensure_ascii=False), 'application/json; charset=utf-8',
                  dict({'Cache-Control': 'no-store'}, **(headers or {})))

    def not_found(self):
        self.send(404, '<html><head><title>404 Not Found</title></head><body><center><h1>404 Not Found</h1>'
                       '</center><hr><center>nginx</center></body></html>', 'text/html')

    def _read_body(self, limit):
        if getattr(self, '_raw', b'') is not None:
            return                       # already read (or nothing to read)
        te_vals = self.headers.get_all('Transfer-Encoding') or []
        cl_vals = self.headers.get_all('Content-Length') or []
        if te_vals and cl_vals:
            self._raw = b''
            self.close_connection = True
            raise _BadRequest('conflicting length headers')
        if te_vals:
            te = ','.join(te_vals).strip().lower()
            if te != 'chunked':
                self._raw = b''
                self.close_connection = True
                raise _BadRequest('unsupported transfer-encoding')
            self._raw = self._read_chunked(limit)    # some HTTP libraries (Dart, Go) send bodies this way
            return
        if len(cl_vals) > 1:
            self._raw = b''
            self.close_connection = True
            raise _BadRequest('duplicate content-length')
        if cl_vals:
            raw_len = cl_vals[0].strip()
            if not re.fullmatch(r'\d{1,12}', raw_len):
                self._raw = b''
                self.close_connection = True
                raise _BadRequest('bad Content-Length')
            n = int(raw_len)
        else:
            n = 0
        if n > limit:
            self._raw = b''
            self.close_connection = True
            raise _BadRequest('request too large')
        data = self.rfile.read(n) if n > 0 else b''
        if len(data) != n:
            self._raw = b''
            self.close_connection = True
            raise _BadRequest('incomplete request body')
        self._raw = data

    def _read_chunked(self, limit):
        out = bytearray()
        while True:
            line = self.rfile.readline(64)
            if not line or not line.endswith(b'\n'):
                self._raw = b''
                self.close_connection = True
                raise _BadRequest('incomplete chunked body')
            raw_size = line.split(b';', 1)[0].strip()
            if not re.fullmatch(rb'[0-9a-fA-F]{1,8}', raw_size):
                self._raw = b''
                self.close_connection = True
                raise _BadRequest('bad chunked body')
            size = int(raw_size, 16)
            if size == 0:
                for _ in range(33):
                    tr = self.rfile.readline(1024)
                    if tr in (b'\r\n', b'\n'):
                        return bytes(out)
                    if not tr or not tr.endswith(b'\n'):
                        self._raw = b''
                        self.close_connection = True
                        raise _BadRequest('bad chunked body')
                self._raw = b''
                self.close_connection = True
                raise _BadRequest('too many trailers')
            if len(out) + size > limit:
                self._raw = b''
                self.close_connection = True
                raise _BadRequest('request too large')
            chunk = self.rfile.read(size)
            if len(chunk) != size:
                self._raw = b''
                self.close_connection = True
                raise _BadRequest('incomplete chunked body')
            out += chunk
            crlf = self.rfile.readline(4)       # CRLF after each chunk
            if crlf not in (b'\r\n', b'\n'):
                self._raw = b''
                self.close_connection = True
                raise _BadRequest('bad chunked body')

    def body_json(self, limit=4 << 20):
        self._read_body(limit)
        try:
            obj = json.loads(self._raw or b'{}')
        except ValueError:
            raise _BadRequest('invalid json')
        if not isinstance(obj, dict):
            raise _BadRequest('json object required')
        if _has_surrogate(obj):          # a lone surrogate escape is valid JSON but not text: later a 500
            raise _BadRequest('invalid unicode')
        return obj

    def client_ip(self):
        ip = self.client_address[0]
        return ip[7:] if ip.startswith('::ffff:') else ip

    def _local_host(self):
        try:
            ip = self.connection.getsockname()[0]
            if ip.startswith('::ffff:'):
                ip = ip[7:]
            if ip and ip not in ('0.0.0.0', '::'):
                return ip
        except (AttributeError, OSError, IndexError):
            pass
        return '127.0.0.1'

    def cookie(self, name):
        for part in (self.headers.get('Cookie') or '').split(';'):
            k, _, v = part.strip().partition('=')
            if k == name:
                return v
        return ''

    def base_url(self, s):
        host = s['domain'] or s['public_host'] or self._local_host()
        scheme = 'https' if certs.trusted(host) else 'http'
        h = '[%s]' % host if ':' in host and not host.startswith('[') else host
        return '%s://%s:%d' % (scheme, h, s['panel_port'])

    def _https_location(self, s):
        """Safe HTTPS redirect URL using configured host or local socket address (never Host header)."""
        host = s['domain'] or s['public_host'] or self._local_host()
        h = '[%s]' % host if ':' in host and not host.startswith('[') else host
        url = urllib.parse.urlsplit(self.path)
        safe_path = '/' + url.path.lstrip('/')
        if url.query:
            safe_path += '?' + url.query
        safe_path = safe_path.replace('\r', '').replace('\n', '')
        return 'https://%s:%d%s' % (h, s['panel_port'], safe_path)

    # --- routing ----------------------------------------------------------------
    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        self.route('GET')

    def do_POST(self):
        self.route('POST')

    def route(self, method):
        self._raw = None                 # request body not read yet (one handler serves a keep-alive connection)
        self._s = None
        self._rl_slot = None             # sign-in attempt reserved by rate_limited()
        try:
            return self._route(method)
        finally:
            self._release_attempt()

    def _route(self, method):
        try:
            url = urllib.parse.urlsplit(self.path)
            path = url.path
            self.query = dict(urllib.parse.parse_qsl(url.query))
            s = db.settings()
            self._s = s
            m = re.fullmatch(r'/s/([A-Za-z0-9_-]{16,64})(?:/(qr\.svg))?', path)
            if m and method == 'GET':
                return self.subscription(s, m.group(1), m.group(2))
            m = re.fullmatch(r'/s/([A-Za-z0-9_-]{16,64})(/.*)', path)
            if m:
                u = db.user_by_token(m.group(1))
                # The app may hold a plain-http subscription link; tell it to use https instead of a bare 404
                # (which it would read as "link changed"). Only for a valid token: probes keep seeing nginx's 404.
                if (u and s['setup_done']
                        and (m.group(2) in ('/api/me', '/api/report') or m.group(2).startswith('/download/'))
                        and not self.secure_ok()):
                    return self.json({'service': 'vps2vpn', 'error': 'https_required'}, 426, {'Upgrade': 'TLS/1.2'})
                if not u or not s['setup_done'] or not self.secure_ok():
                    return self.not_found()
                return self.member_area(method, m.group(2), s, u, '/s/%s/' % m.group(1))
            m = re.fullmatch(r'/rules/([a-z0-9-]{2,32})\.(mrs|srs|list)', path)
            if m and method == 'GET':
                return self.rule_file(m.group(1), m.group(2))
            mp = '/' + s['member_path']
            if s['member_path'] and s['member_enabled'] and s['setup_done'] and (path == mp or path.startswith(mp + '/')):
                if not self.secure_ok():
                    loc = self._https_location(s)
                    return self.send(301, '', headers={'Location': loc}) if loc else self.not_found()
                if path == mp:
                    return self.send(301, '', headers={'Location': mp + '/'})
                uid = db.member_session(self.cookie('v2vm'))
                return self.member_area(method, path[len(mp):], s, db.user(uid) if uid else None, mp + '/')
            pp = '/' + s['panel_path']
            if s['panel_path'] and (path == pp or path.startswith(pp + '/')):
                if not self.secure_ok():
                    loc = self._https_location(s)
                    return self.send(301, '', headers={'Location': loc}) if loc else self.not_found()
                if path == pp and method in ('GET', 'HEAD'):
                    # The page's relative links (api/..., assets) only resolve under the trailing slash.
                    url = urllib.parse.urlsplit(self.path)
                    return self.send(301, '', headers={'Location': pp + '/' + ('?' + url.query if url.query else '')})
                return self.panel(method, path[len(pp):] or '/', s)
            return self.not_found()
        except _BadRequest as e:
            try:
                self.json({'error': str(e)[:120]}, 400)
            except OSError:
                pass
        except (ConnectionError, socket.timeout, ssl.SSLError):
            self.close_connection = True
            return
        except Exception as e:   # never leak a traceback to the network
            import traceback
            self.close_connection = True     # part of a reply may be out already: no second one on this connection
            jobs.log('http error %s %s: %r %s' % (method, self._log_path(), e,
                                                 traceback.format_exc(limit=-2).replace(chr(10), ' | ')[-300:]))
            try:
                self.json({'error': 'internal error'}, 500)
            except OSError:
                pass

    def _log_path(self):
        """The request path for the journal, without the secrets it carries: a subscription token is the
        account's credentials, and the panel and member-centre paths are meant to stay unguessable."""
        path = self.path.split('?')[0]
        path = re.sub(r'^/s/[^/]*', '/s/<token>', path)
        s = self._s or {}
        for key, label in (('panel_path', '/<panel>'), ('member_path', '/<member>')):
            prefix = '/' + str(s.get(key) or '')
            if len(prefix) > 1 and (path == prefix or path.startswith(prefix + '/')):
                path = label + path[len(prefix):]
                break
        return path[-60:]

    def secure_ok(self):
        """HTTPS, or plain HTTP from this machine in development mode."""
        return self.is_tls or (paths.DEV and self.client_ip() in ('127.0.0.1', '::1'))

    # --- public: subscriptions ------------------------------------------------------
    def subscription(self, s, token, qr_svg):
        u = db.user_by_token(token)
        if not u or not s['setup_done']:
            return self.not_found()
        base = self.base_url(s)
        if base.startswith('https://') and not self.is_tls:
            # A trusted certificate exists, so every app can use HTTPS: never send the account's proxy
            # credentials in clear text. Old http:// links keep working through the redirect (apps follow it).
            # Only a self-signed panel still serves plain HTTP, which most apps need there.
            return self.send(308, '', headers={'Location': self._https_location(s), 'Cache-Control': 'no-store'})
        sub_url = '%s/s/%s' % (base, token)
        if qr_svg:
            target = self.query.get('t', 'sub')
            text = sub_url
            if target == 'links':
                nodes = subscription.nodes(s, u) if u['enabled'] else []
                text = subscription.share_link(nodes[0]) if nodes else sub_url
            try:          # a cut-off link would scan "fine" and then not work: refuse instead
                image = qr.svg(text, scale=5)
            except ValueError:
                return self.json({'error': 'too long for a QR code; copy the link instead'}, 413)
            return self.send(200, image, 'image/svg+xml',
                             {'Cache-Control': 'no-store', 'Content-Security-Policy': _SVG_CSP})
        ua = self.headers.get('User-Agent')
        fmt = subscription.detect_format(ua, self.query.get('format', ''), self.headers.get('Accept') or '')
        if not fmt:
            if self.secure_ok():          # the person's own page (usage, import buttons, requests, invites)
                return self.member_page('/s/%s/' % token)
            return self.send(200, landing_page(s, u, sub_url), 'text/html; charset=utf-8',
                             {'Cache-Control': 'no-store', 'X-Frame-Options': 'DENY', 'Content-Security-Policy':
                              "default-src 'none'; img-src 'self' data:; style-src 'unsafe-inline'; "
                              "script-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"})
        if not u['enabled']:
            s = dict(s, reality_enabled=False, hy2_enabled=False, tuic_enabled=False, servers=[])   # usage header still sent
        try:
            quota_eff = members.effective_quota(u)   # also when paused: the app's usage bar must match the page
        except Exception as e:          # only for the heads-up text: never fail the subscription over it
            jobs.log('could not work out the effective quota: %r' % e)
            quota_eff = None
        ctype, body, headers = subscription.render(fmt, s, u, base, quota_eff)
        if self.command == 'GET':
            try:
                db.record_sub_fetch(u, ua)
            except Exception as e:      # bookkeeping only: never fail the subscription itself over it
                jobs.log('could not record a subscription fetch: %r' % e)
        return self.send(200, body, ctype, headers)

    def rule_file(self, name, ext):
        if name not in rules.SETS:
            return self.not_found()
        fmt = {'mrs': 'clash', 'srs': 'singbox', 'list': 'shadowrocket'}[ext]
        f = rules.local_file(name, fmt)
        if not os.path.exists(f):
            if fmt == 'shadowrocket':     # needs converting, so it cannot be a redirect: fetch it now
                # Do not park every public HTTP worker behind a slow upstream
                # fetch. The first cold request owns the refresh; all other
                # callers either use its completed atomic cache or fail fast.
                if not rules._refresh_lock.acquire(blocking=False):
                    if not os.path.exists(f):
                        return self.send(503, 'rule set not available yet')
                else:
                    try:
                        if not os.path.exists(f):
                            try:
                                converted = rules.fetch_converted(name, fmt)
                                # A successful HTTP response can still contain no
                                # convertible rules (e.g. a CDN's HTML error page).
                                # Do not make this empty result a persistent 200
                                # cache entry on the first anonymous request.
                                rows = converted.splitlines()
                                prefixes = (b'DOMAIN,', b'DOMAIN-SUFFIX,', b'IP-CIDR,', b'IP-CIDR6,')
                                if not rows or any(not row.startswith(prefixes) or row.endswith(b',') for row in rows):
                                    return self.send(503, 'rule set not available yet')
                                paths.write_atomic(f, converted, 0o644)
                            except OSError:
                                return self.send(503, 'rule set not available yet')
                    finally:
                        rules._refresh_lock.release()
            else:
                return self.send(302, '', headers={'Location': rules.upstream_url(name, fmt, cdn=True)})
        with open(f, 'rb') as fh:
            data = fh.read()
        return self.send(200, data, 'application/octet-stream', {'Cache-Control': 'public, max-age=3600'})

    # --- admin panel ------------------------------------------------------------------
    def panel(self, method, sub, s):
        if method == 'GET' and sub in ('/', '/index.html'):
            return self.static('index.html')
        m = re.fullmatch(r'/static/([a-z0-9_.-]+)', sub)
        if method == 'GET' and m:
            return self.static(m.group(1))
        if not sub.startswith('/api/'):
            return self.not_found()
        api = sub[5:]
        if method == 'POST' and self.headers.get('X-V2V') != '1':
            return self.json({'error': 'missing header'}, 403)     # blocks cross-site form posts
        # endpoints that work without a session
        if api == 'hello':
            if method != 'GET':
                return self.json({'error': 'GET only'}, 405)
            return self.json({'setup_done': s['setup_done'], 'language': s['language'], 'version': VERSION,
                              'logged_in': db.session_ok(self.cookie('v2v'))})
        if api == 'setup':
            return self.api_setup(s) if method == 'POST' else self.json({'error': 'POST only'}, 405)
        if api == 'setup-info':
            return self.api_setup_info(s) if method == 'GET' else self.json({'error': 'GET only'}, 405)
        if api == 'login':
            return self.api_login(s) if method == 'POST' else self.json({'error': 'POST only'}, 405)
        if api == 'node/sync':
            if method != 'POST':
                return self.json({'error': 'POST only'}, 405)
            auth = self.headers.get('Authorization', '')
            if not s['setup_done'] or not secure.hmac_eq(auth[7:] if auth.startswith('Bearer ') else '', s['node_key']):
                time.sleep(0.5)
                return self.json({'error': 'bad node key'}, 403)
            try:
                res = cluster.handle_sync(s, self.body_json(8 << 20))
            except ValueError as e:      # a damaged account list is refused whole, nothing is changed
                return self.json({'error': 'sync refused: %s' % str(e)[:200]}, 400)
            return self.json(res, 409 if res.get('conflict') else 200)
        if not s['setup_done'] or not db.session_ok(self.cookie('v2v')):
            return self.json({'error': 'login required'}, 401)
        m = re.fullmatch(r'users/(\d+)/(save|delete|rotate|reset|login)', api)
        if m:
            return self.api_user_action(int(m.group(1)), m.group(2)) if method == 'POST' else self.json({'error': 'POST only'}, 405)
        m = re.fullmatch(r'users/(\d+)/history', api)
        if m:
            if method != 'GET':
                return self.json({'error': 'GET only'}, 405)
            try:
                days = max(1, min(400, int(self.query.get('days', 30))))
            except ValueError:
                days = 30
            return self.json({'days': db.user_traffic(int(m.group(1)), days)})
        m = re.fullmatch(r'invites/(\d+)/revoke', api)
        if m:
            return self.refused(lambda: members.revoke_invite(int(m.group(1)))) if method == 'POST' else self.json({'error': 'POST only'}, 405)
        m = re.fullmatch(r'requests/(\d+)/(approve|reject)', api)
        if m:
            if method != 'POST':
                return self.json({'error': 'POST only'}, 405)
            d = self.body_json()
            return self.refused(lambda: members.decide(int(m.group(1)), m.group(2) == 'approve', d.get('add_gb'),
                                                       d.get('answer', '')), after=lambda: (jobs.enforce(), apply_async()))
        m = re.fullmatch(r'servers/([0-9a-f]{8})/(remove|save|sync)', api)
        if m:
            return self.api_server_action(m.group(1), m.group(2)) if method == 'POST' else self.json({'error': 'POST only'}, 405)
        routes = {
            'security': (('GET', 'POST'), self.api_security),
            'totp': (('GET', 'POST'), self.api_totp),
            'sys-history': (('GET',), self.api_sys_history),
            'aicheck': (('GET', 'POST'), self.api_aicheck),
            'logout': (('POST',), self.api_logout),
            'state': (('GET',), self.api_state),
            'change-port': (('POST',), self.api_change_port),
            'traffic': (('GET',), self.api_traffic),
            'settings': (('POST',), self.api_settings),
            'users': (('GET', 'POST'), self.api_users),
            'users-batch': (('POST',), self.api_users_batch),
            'users-bulk': (('POST',), self.api_users_bulk),
            'users-export': (('GET',), self.api_users_export),
            'invites': (('GET', 'POST'), self.api_invites),
            'requests': (('GET',), self.api_requests),
            'monitor': (('GET', 'POST'), self.api_monitor),
            'abuse': (('GET', 'POST'), self.api_abuse),
            'servers': (('GET', 'POST'), self.api_servers),
            'node-key': (('POST',), self.api_node_key),
            'password': (('POST',), self.api_password),
            'check-targets': (('GET', 'POST'), self.api_check_targets),
            'cert': (('POST',), self.api_cert),
            'qr': (('GET',), self.api_qr),
            'user-links': (('GET',), self.api_user_links),
            'restart': (('POST',), self.api_restart),
            'rules-refresh': (('POST',), self.api_rules_refresh),
            'doctor': (('POST',), self.api_doctor),
            'telegram': (('POST',), self.api_telegram),
            'backup': (('GET',), self.api_backup),
            'restore': (('POST',), self.api_restore),
        }
        entry = routes.get(api)
        if entry is None:
            return self.json({'error': 'unknown endpoint'}, 404)
        allowed, fn = entry
        if method not in allowed:
            return self.json({'error': '%s only' % '/'.join(allowed)}, 405)
        return fn(method, s)

    def static(self, name):
        f = os.path.join(paths.STATIC, name)
        if not os.path.isfile(f):
            return self.not_found()
        ctype = mimetypes.guess_type(f)[0] or 'application/octet-stream'
        if ctype.startswith('text/') or ctype.endswith('javascript'):
            ctype += '; charset=utf-8'
        with open(f, 'rb') as fh:
            data = fh.read()
        return self.send(200, data, ctype, {
            'Cache-Control': 'no-cache',
            'Content-Security-Policy': "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
                                       "object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'",
            'X-Frame-Options': 'DENY'})

    def session_cookie(self, tok, max_age=7 * 86400):
        return 'v2v=%s; Path=/%s/; Max-Age=%d; HttpOnly; Secure; SameSite=Strict' % (
            tok, db.settings()['panel_path'], max_age)

    def rate_limited(self, scope='admin'):
        """Check the failure budget of this address and, when there is room, reserve one attempt in it.

        The reservation is taken under the lock, so parallel guesses cannot all pass the check before the
        first one is counted. It becomes a failure with _record_fail(); otherwise route() hands it back.
        Admin and member sign-ins count separately: a member's typos never lock the admin out, and
        signing in to an account the attacker owns never refills the budget for guessing someone else's."""
        now = time.monotonic()
        key = (scope, _rate_key(self.client_ip()))
        with _fails_lock:
            hits = [t for t in _fails.get(key, ()) if now - t < 600]
            if len(hits) >= 8:
                _fails[key] = hits
                return True
            hits.append(now)
            _fails[key] = hits
            self._rl_slot = (key, now)
            if len(_fails) > _FAIL_CAP:
                for k in list(_fails):
                    kept = [t for t in _fails[k] if now - t < 600]
                    if kept:
                        _fails[k] = kept
                    else:
                        _fails.pop(k, None)
                while len(_fails) > _FAIL_CAP:
                    _fails.pop(next(iter(_fails)))
            return False

    def _record_fail(self):
        """The reserved attempt failed: it stays counted for 10 minutes."""
        self._rl_slot = None

    def _release_attempt(self):
        """The reserved attempt was not a wrong guess (or the request ended without a verdict)."""
        slot, self._rl_slot = getattr(self, '_rl_slot', None), None
        if slot:
            key, stamp = slot
            with _fails_lock:
                hits = _fails.get(key)
                if hits and stamp in hits:
                    hits.remove(stamp)
                    if not hits:
                        _fails.pop(key, None)

    def _clear_fails(self):
        """The admin signed in: the admin budget of this address starts over. (Member sign-ins only hand back
        their own attempt: a member account proves nothing about any other password.)"""
        slot, self._rl_slot = getattr(self, '_rl_slot', None), None
        with _fails_lock:
            _fails.pop(slot[0] if slot else ('admin', _rate_key(self.client_ip())), None)

    # --- setup wizard ----------------------------------------------------------------
    def api_setup_info(self, s):
        if s['setup_done']:
            return self.json({'error': 'already set up'}, 409)
        if self.rate_limited():
            return self.json({'error': 'too many attempts, wait 10 minutes'}, 429)
        if not secure.hmac_eq(self.query.get('token', ''), setup_token()):
            self._record_fail()
            return self.json({'error': 'bad setup link'}, 403)
        host = s['domain'] or s['public_host'] or self._local_host()
        return self.json({'host': host, 'targets': system.GOOD_TARGETS,
                          'target': s['reality_target'], 'language': s['language']})

    def api_setup(self, s):
        if s['setup_done']:
            return self.json({'error': 'already set up'}, 409)
        if self.rate_limited():
            return self.json({'error': 'too many attempts, wait 10 minutes'}, 429)
        d = self.body_json()
        if not secure.hmac_eq(str(d.get('token', '')), setup_token()):
            self._record_fail()
            return self.json({'error': 'bad setup link'}, 403)
        pw = str(d.get('password', ''))
        if len(pw) < 8:
            return self.json({'error': 'password must be at least 8 characters'}, 400)
        if len(pw) > 128:
            return self.json({'error': 'password: 8 to 128 characters'}, 400)
        changes = validate_settings(d.get('settings', {}), s)
        if isinstance(changes, str):
            return self.json({'error': changes}, 400)
        admin_user = re.sub(r'[\x00-\x1f\x7f]', '', str(d.get('username') or 'admin')).strip()[:32] or 'admin'
        changes.update(admin_user=admin_user, admin_hash=secure.hash_password(pw))
        db.set_settings(**changes)
        first = re.sub(r'[\x00-\x1f\x7f]', '', str(d.get('first_user') or 'me')).strip()[:32] or 'me'
        if not db.users():
            db.add_user(first)
        s = db.settings()
        certs.ensure_self_signed(s['domain'] or s['public_host'] or 'vps2vpn.local')
        db.set_settings(setup_done=True)
        try:
            os.unlink(SETUP_TOKEN_FILE)
        except OSError:
            pass
        system.tune_network(s['tune_network'])
        system.open_firewall(s)
        apply_async(force=True)
        rules.refresh_in_background(jobs.log)
        self._clear_fails()
        tok = db.new_session()
        return self.json({'ok': True}, headers={'Set-Cookie': self.session_cookie(tok)})

    def api_login(self, s):
        if self.rate_limited():
            return self.json({'error': 'too many attempts, wait 10 minutes'}, 429)
        d = self.body_json()
        ua = re.sub(r'[\x00-\x1f\x7f]', '', self.headers.get('User-Agent', ''))[:120]
        pw = str(d.get('password', ''))
        ok = (len(pw) <= 128
              and (secure.hmac_eq(str(d.get('username', '')), s['admin_user'])
                   & secure.check_password(pw, s['admin_hash'])))
        if not ok:
            self._record_fail()
            db.add_event('login', 0, 'fail|%s|%s' % (self.client_ip(), ua))
            time.sleep(0.5)
            return self.json({'error': 'wrong username or password'}, 403)
        if s['admin_totp']:
            code = str(d.get('code') or '').strip()
            if not code:
                return self.json({'error': 'totp_required'}, 403)
            if not _totp_consume(s['admin_totp'], code):
                self._record_fail()
                db.add_event('login', 0, 'fail2fa|%s|%s' % (self.client_ip(), ua))
                time.sleep(0.5)
                return self.json({'error': 'wrong 2FA code'}, 403)
        # PBKDF2 and TOTP checks above use the snapshot from request entry.
        # Do not mint a session if 2FA, password or username changed meanwhile.
        # Reuse the DB transaction lock for the comparison and insert.
        with db.transaction():
            current = db.settings()
            stale = any(current[k] != s[k] for k in ('admin_user', 'admin_hash', 'admin_totp'))
            tok = None if stale else db.new_session()
        if stale:
            return self.json({'error': 'login settings changed; retry'}, 409)
        self._clear_fails()
        db.add_event('login', 0, 'ok|%s|%s' % (self.client_ip(), ua))
        return self.json({'ok': True}, headers={'Set-Cookie': self.session_cookie(tok)})

    def api_security(self, method, s):
        """Login history, open sessions, sign out everywhere else."""
        if method == 'POST':
            d = self.body_json()
            if d.get('logout_others'):
                db.end_other_sessions(self.cookie('v2v'))
            if 'ip_limit_pause' in d:
                try:
                    db.set_settings(ip_limit_pause=as_bool(d['ip_limit_pause']))
                except ValueError:
                    return self.json({'error': 'ip_limit_pause: expected true or false'}, 400)
            return self.json({'ok': True})
        hist = []
        for e in db.events('login', 40):
            kind, _, rest = e['detail'].partition('|')
            ip, _, ua = rest.partition('|')
            hist.append({'at': e['at'], 'ok': kind == 'ok', 'kind': kind, 'ip': ip, 'ua': ua})
        return self.json({'logins': hist, 'sessions': db.session_count(), 'totp': bool(s['admin_totp']),
                          'devices': [dict(e) for e in db.events('devices', 30)]})

    def api_totp(self, method, s):
        """GET: a fresh secret to scan. POST {secret, code}: turn on. POST {off, password}: turn off."""
        if method != 'POST':
            sec = secure.totp_secret()
            uri = 'otpauth://totp/%s:%s?secret=%s&issuer=%s' % (
                urllib.parse.quote(s['node_name'] or 'vps2vpn'), urllib.parse.quote(s['admin_user']), sec,
                urllib.parse.quote(s['node_name'] or 'vps2vpn'))
            return self.json({'secret': sec, 'uri': uri})
        d = self.body_json()
        if d.get('off'):
            if self.rate_limited():
                return self.json({'error': 'too many attempts, wait 10 minutes'}, 429)
            pw = str(d.get('password', ''))
            if len(pw) > 128 or not secure.check_password(pw, s['admin_hash']):
                self._record_fail()
                return self.json({'error': 'current password is wrong'}, 403)
            # Disable and enrollment must have one serialization point. A
            # concurrent enrollment must not report success only to have this
            # request overwrite its newly enrolled secret after releasing the lock.
            with _totp_lock:
                def off():
                    _totp_last_step.pop(s['admin_totp'], None)
                    db.set_settings(admin_totp='')
                return self._change_admin_sign_in(s, off)
        sec = str(d.get('secret', '')).strip().upper()
        if not re.fullmatch(r'[A-Z2-7]{16,64}', sec):
            return self.json({'error': 'bad secret'}, 400)
        if not secure.totp_check(sec, d.get('code')):
            return self.json({'error': 'wrong 2FA code'}, 400)
        # An authenticated session is not sufficient to replace an already
        # enrolled second factor. The normal UI first requires the password
        # to disable the old authenticator before enrolling a new one.
        # Check and write atomically: simultaneous enrollments must not win
        # against each other using stale request-level settings.
        with _totp_lock:
            if db.settings()['admin_totp']:
                return self.json({'error': 'disable existing 2FA before enrolling again'}, 409)

            def on():
                _totp_last_step.pop(sec, None)
                db.set_settings(admin_totp=sec)
            # Like turning it off: not from a session another change ended meanwhile.
            return self._change_admin_sign_in(s, on)

    def _change_admin_sign_in(self, s, change):
        """Apply `change` to how the admin signs in, then end every session and start one for this browser.

        The password check that allowed it ran against `s`, read when the request came in. If the user
        name, password or 2FA changed since then, or this session was ended meanwhile (another request
        changed them), the change would undo that one with credentials that no longer count: refuse.
        """
        with db.transaction():
            current = db.settings()
            if (any(current[k] != s[k] for k in ('admin_user', 'admin_hash', 'admin_totp'))
                    or not db.session_ok(self.cookie('v2v'))):
                stale = True
            else:
                stale = False
                change()
                db.end_all_sessions()
                tok = db.new_session()
        if stale:
            return self.json({'error': 'sign-in settings changed meanwhile; reload and try again'}, 409)
        return self.json({'ok': True}, headers={'Set-Cookie': self.session_cookie(tok)})

    def _new_admin_session(self):
        """After a change to how the admin signs in: every session ends (a stolen copy of this one too) and
        this browser goes on with a new one."""
        db.end_all_sessions()
        return self.json({'ok': True}, headers={'Set-Cookie': self.session_cookie(db.new_session())})

    def api_sys_history(self, method, s):
        return self.json({'points': jobs.HISTORY.points[-1440:]})

    def api_aicheck(self, method, s):
        """AI availability from this server (GET: last result; POST: check again now, ~10 s).
        Joined servers' summaries come from their last sync."""
        from . import aicheck
        res = jobs.ai_recheck(s, jobs.log) if method == 'POST' else aicheck.latest()
        others = [{'name': x['name'], 'summary': (x.get('info') or {}).get('ai', ''),
                   'score': (x.get('info') or {}).get('ai_score', -1)} for x in s.get('servers') or []]
        return self.json({'result': res, 'summary': aicheck.summary(res), 'servers': others})

    # --- logged-in API ----------------------------------------------------------------
    def api_logout(self, method, s):
        db.end_session(self.cookie('v2v'))
        return self.json({'ok': True}, headers={'Set-Cookie': self.session_cookie('', 0)})

    def api_state(self, method, s):
        base = self.base_url(s)
        users = []
        all_users = db.users()
        names = {u['id']: u['name'] for u in all_users}
        invitees = members.invitee_index(all_users)
        online = cores.online_detail(s)
        for u in all_users:
            sub = '%s/s/%s' % (base, u['sub_token'])
            row = {k: u[k] for k in ('id', 'name', 'quota_gb', 'expire_at', 'reset_day', 'used_up', 'used_down',
                                     'enabled', 'disabled_reason', 'note', 'last_seen', 'created_at', 'invited_by',
                                     'invite_deduct', 'remote_id', 'max_ips', 'paused_until', 'expire_after_days',
                                     'sub_fetched_at', 'sub_ua', 'speed_mbps', 'throttle_mbps', 'throttled', 'extra_gb')}
            row['servers'] = db.server_list(u)
            row['limit_mbps'] = db.limit_mbps(u)
            row['sub_url'] = sub
            row['quota_eff'] = members.effective_quota(u, index=invitees)
            row['shared_gb'] = members.given_away(u['id'], index=invitees)
            row['has_login'] = bool(u['login_hash'])
            row['invited_by_name'] = names.get(u['invited_by'], '')
            row['online'] = (online or {}).get(u['id'])
            users.append(row)
        public = {k: v for k, v in s.items() if k not in ('admin_hash', 'reality_private_key', 'stats_secret', 'tg_token',
                                                           'node_key', 'servers', 'server_month', 'admin_totp',
                                                           'line_reports')}
        public['totp_on'] = bool(s['admin_totp'])
        public['tg_ready'] = bool(s['tg_token'] and s['tg_chat'] and s.get('tg_verified') is True)
        public['tg_repair_needed'] = bool(s['tg_token'] and s['tg_chat'] and s.get('tg_verified') is not True)
        public['tg_token_set'] = bool(s['tg_token'])
        host = s['domain'] or s['public_host']
        return self.json({
            'settings': public, 'users': users, 'health': system.health(), 'version': VERSION,
            'services': {'xray': system.unit_active(cores.XRAY_UNIT), 'hysteria': system.unit_active(cores.HY2_UNIT),
                         'tuic': system.unit_active(cores.TUIC_UNIT)},
            'cert': {'trusted': certs.trusted(host), 'names': certs.acme_names(), 'status': s['cert_status']},
            'online': None if online is None else len(online), 'rules_age': rules.mirror_age(), 'log': jobs.LOG[-60:],
            'ports': system.needed_ports(s), 'os': system.os_info(), 'base_url': base,
            'member_url': '%s/%s/' % (base, s['member_path']) if s['member_enabled'] else '',
            'pending_requests': len(db.requests(status='pending')), 'servers': cluster.view(s),
            'server_month': {k: v for k, v in (s['server_month'] or {}).items() if not k.startswith('last_')},
            'renew_days': jobs.renew_days_left(s), 'line_trouble': self.trouble_view(s),
            'client': {'found': client_files(), 'dir': paths.CLIENT},
            'shaper': shaper.status(),
        })

    def trouble_view(self, s):
        mine = {_norm_host(s['public_host']), _norm_host(s['domain']), _norm_host(s.get('public_ipv6', ''))} - {''}
        out = []
        for line, r in jobs.line_trouble(s).items():
            hosts = {_norm_host(h) for h in r['hosts']} - {''}
            out.append({'line': line, 'name': jobs.LINES[line][2], 'users': len(r['users']), 'last': r['last'],
                        'hosts': r['hosts'], 'here': not hosts or bool(mine & hosts)})
        return out

    def api_change_port(self, method, s):
        """Move one line to a new random port (e.g. after the apps report it unreachable)."""
        if method != 'POST':
            return self.json({'error': 'POST only'}, 405)
        line = str(self.body_json().get('line', ''))
        if line not in jobs.LINES:
            return self.json({'error': 'unknown line'}, 400)
        try:
            port = jobs.change_port(line)
        except RuntimeError as e:
            return self.json({'error': str(e)}, 500)
        apply_async(force=True)
        cluster.sync_soon()
        return self.json({'ok': True, 'port': port})

    def api_traffic(self, method, s):
        try:
            days = max(1, min(400, int(self.query.get('days', 30))))
        except ValueError:
            days = 30
        return self.json({'days': db.traffic_days(days)})

    def api_settings(self, method, s):
        if method != 'POST':
            return self.json({'error': 'POST only'}, 405)
        changes = validate_settings(self.body_json(), s)
        if isinstance(changes, str):
            return self.json({'error': changes}, 400)
        db.set_settings(**changes)
        s2 = db.settings()
        if 'public_host' in changes or 'domain' in changes:
            certs.ensure_self_signed(s2['domain'] or s2['public_host'] or 'vps2vpn.local')
        if 'tune_network' in changes:
            system.tune_network(s2['tune_network'])
        system.open_firewall(s2)
        apply_async()
        return self.json({'ok': True})

    def api_users(self, method, s):
        if method != 'POST':
            secret_fields = {'login_hash', 'uuid', 'hy2_pass', 'sub_token'}
            clean = [{k: v for k, v in u.items() if k not in secret_fields} for u in db.users()]
            return self.json({'users': clean})
        d = self.body_json()
        name = re.sub(r'[\x00-\x1f\x7f]', '', str(d.get('name', ''))).strip()[:32]
        if not name:
            return self.json({'error': 'name required'}, 400)
        if db.user_by_name(name):
            return self.json({'error': 'name already used'}, 400)
        fields = user_fields(d)
        if isinstance(fields, str):
            return self.json({'error': fields}, 400)
        uid = db.add_user(name, fields.get('quota_gb', 0), fields.get('expire_at', 0), fields.get('reset_day', 0),
                          fields.get('note', ''), max_ips=fields.get('max_ips', 0),
                          expire_after_days=fields.get('expire_after_days', 0), **_limit_fields(fields))
        apply_async()
        return self.json({'ok': True, 'id': uid})

    def api_users_batch(self, method, s):
        """Create many accounts at once: prefix-01, prefix-02, ... with the same limits."""
        if method != 'POST':
            return self.json({'error': 'POST only'}, 405)
        d = self.body_json()
        prefix = re.sub(r'[\s\x00-\x1f\x7f]+', '', str(d.get('prefix', '')))[:24]
        try:
            count = int(d.get('count', 0))
        except (TypeError, ValueError, OverflowError):
            return self.json({'error': 'invalid number'}, 400)
        if not prefix or not 1 <= count <= 200:
            return self.json({'error': 'prefix and a count of 1-200 required'}, 400)
        fields = user_fields(d)
        if isinstance(fields, str):
            return self.json({'error': fields}, 400)
        width = max(2, len(str(count)))
        made, n = [], 1
        while len(made) < count and n < count + 1000:
            name = '%s-%0*d' % (prefix, width, n)
            n += 1
            if db.user_by_name(name):
                continue
            made.append(db.add_user(name, fields.get('quota_gb', 0), fields.get('expire_at', 0),
                                    fields.get('reset_day', 0), fields.get('note', ''),
                                    max_ips=fields.get('max_ips', 0),
                                    expire_after_days=fields.get('expire_after_days', 0), **_limit_fields(fields)))
        apply_async()
        return self.json({'ok': True, 'ids': made})

    def api_users_bulk(self, method, s):
        """One action on many users: enable, disable, reset, rotate, delete, extend (days), add_gb, set_quota."""
        if method != 'POST':
            return self.json({'error': 'POST only'}, 405)
        d = self.body_json()
        action = d.get('action')
        raw_ids = d.get('ids', [])
        if not isinstance(raw_ids, list):
            return self.json({'error': 'ids must be an array'}, 400)
        if len(raw_ids) > 2000:
            return self.json({'error': 'too many IDs (maximum 2000)'}, 400)
        def user_id(raw):
            # bool and fractional float are accepted by int() but do not
            # identify the account the caller intended.
            if type(raw) is int:
                uid = raw
            elif isinstance(raw, str) and re.fullmatch(r'[0-9]{1,19}', raw):
                uid = int(raw)
            else:
                raise ValueError('invalid user ID')
            if not 0 < uid < (1 << 63):
                raise ValueError('invalid user ID')
            return uid

        try:
            # A repeated account must not have its quota or expiry extended
            # twice. Preserve request order after de-duplication.
            ids = list(dict.fromkeys(user_id(i) for i in raw_ids))
            value = float(d.get('value') or 0)
        except (TypeError, ValueError, OverflowError):    # a 310-digit JSON integer overflows float()
            return self.json({'error': 'invalid number'}, 400)
        if not math.isfinite(value) or abs(value) > 1e6:
            return self.json({'error': 'invalid number'}, 400)
        if action not in ('enable', 'disable', 'reset', 'rotate', 'delete', 'extend', 'add_gb', 'set_quota'):
            return self.json({'error': 'unknown action'}, 400)
        if action in ('extend', 'add_gb') and value <= 0:
            return self.json({'error': 'invalid number'}, 400)
        now = int(time.time())
        if action == 'extend':
            # Verify the entire requested batch before changing the first
            # account. The single-user form's year-9999 bound applies here too.
            for uid in ids:
                user = db.user(uid)
                if (user and user['expire_at']
                        and int(max(user['expire_at'], now) + value * 86400) > MAX_ACCOUNT_EXPIRE_AT):
                    return self.json({'error': 'expire_at is out of supported range'}, 400)
        done = 0
        for uid in ids:
            u = db.user(uid)
            if not u:
                continue
            done += 1
            if action == 'enable':
                db.update_user(uid, enabled=1, disabled_reason='', paused_until=0)
            elif action == 'disable':
                db.update_user(uid, enabled=0, disabled_reason='manual')
            elif action == 'reset':
                db.update_user(uid, used_up=0, used_down=0, extra_gb=0)   # a new period: last one's top-up ends
                jobs.forget_quota_alerts(uid)
                if u['disabled_reason'] == 'quota':
                    db.update_user(uid, enabled=1, disabled_reason='')
            elif action == 'rotate':
                db.rotate_user(uid)
            elif action == 'delete':
                db.delete_user(uid)
            elif action == 'extend':
                if u['expire_at']:     # from the old date, or from today if it already passed
                    new_exp = int(max(u['expire_at'], now) + value * 86400)
                    db.update_user(uid, expire_at=new_exp)
                    _propagate_lifetime(uid, u['expire_at'], new_exp)
            elif action == 'add_gb':
                if u['quota_gb']:      # unlimited stays unlimited
                    db.update_user(uid, quota_gb=u['quota_gb'] + value)
            elif action == 'set_quota':
                db.update_user(uid, quota_gb=max(0.0, value))
        jobs.enforce()
        apply_async()
        still = 0
        if action == 'enable':
            still = sum(1 for uid in ids if (lambda x: x and not x['enabled'] and x['disabled_reason'] in ('expired', 'quota'))(db.user(uid)))
        return self.json({'ok': True, 'done': done, 'still_paused': still})

    def api_users_export(self, method, s):
        """All users as CSV (opens in Excel / Numbers). Contains subscription links: keep it private."""
        import csv
        import io
        base = self.base_url(s)
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(['id', 'name', 'status', 'used_gb', 'quota_gb', 'expires', 'reset_day', 'device_limit',
                    'last_seen', 'created', 'note', 'subscription'])
        day = lambda t: time.strftime('%Y-%m-%d', time.localtime(t)) if t else ''
        for u in db.users():
            row = [u['id'], u['name'], 'active' if u['enabled'] else (u['disabled_reason'] or 'paused'),
                   round((u['used_up'] + u['used_down']) / (1 << 30), 3), u['quota_gb'] or '',
                   day(u['expire_at']) or ('%d days from first use' % u['expire_after_days']
                                           if u['expire_after_days'] else ''),
                   u['reset_day'] or '', u['max_ips'] or '', day(u['last_seen']), day(u['created_at']), u['note'],
                   '%s/s/%s' % (base, u['sub_token'])]
            w.writerow([_csv_cell(c) for c in row])
        name = 'vps2vpn-users-%s.csv' % time.strftime('%Y%m%d')
        # BOM so Excel reads the UTF-8 names correctly
        return self.send(200, '﻿' + buf.getvalue(), 'text/csv; charset=utf-8',
                         {'Content-Disposition': 'attachment; filename=' + name, 'Cache-Control': 'no-store'})

    def api_user_action(self, uid, action):
        u = db.user(uid)
        fields = {}             # set by 'save' only
        if not u:
            return self.json({'error': 'no such user'}, 404)
        if action == 'delete':
            db.delete_user(uid)
        elif action == 'rotate':
            db.rotate_user(uid)
        elif action == 'reset':
            db.update_user(uid, used_up=0, used_down=0, extra_gb=0)   # a new period: last one's top-up ends
            jobs.forget_quota_alerts(uid)
            if u['disabled_reason'] == 'quota':
                db.update_user(uid, enabled=1, disabled_reason='')
        elif action == 'login':
            pw = str(self.body_json().get('password') or '')
            if pw:
                try:
                    members.check_password(pw)
                except members.Refused as e:
                    return self.json({'error': str(e)}, 400)
            db.update_user(uid, login_hash=secure.hash_password(pw) if pw else '')
            db.end_member_session(None, uid)
            return self.json({'ok': True})
        else:
            fields = user_fields(self.body_json())
            if isinstance(fields, str):
                return self.json({'error': fields}, 400)
            if 'enabled' in fields:
                fields['disabled_reason'] = '' if fields['enabled'] else 'manual'
                if fields['enabled']:
                    fields['paused_until'] = 0
            if 'reset_day' in fields and fields['reset_day'] > 0 and u['reset_day'] == 0 and not u['last_reset']:
                t_now = time.localtime()
                if t_now.tm_mday >= fields['reset_day']:
                    fields['last_reset'] = time.strftime('%Y-%m', t_now)
            other = db.user_by_name(fields['name']) if 'name' in fields else None
            if other and other['id'] != uid:
                return self.json({'error': 'name already used'}, 400)
            db.update_user(uid, **fields)
            exp_changed = 'expire_at' in fields and fields['expire_at'] != u['expire_at']
            rst_changed = 'reset_day' in fields and fields['reset_day'] != u['reset_day']
            if exp_changed or rst_changed:
                # Accounts carved from this one's quota share its lifetime and reset schedule.
                _propagate_lifetime(uid, u['expire_at'], fields['expire_at'] if exp_changed else None,
                                    u['reset_day'], fields['reset_day'] if rst_changed else None)
        jobs.enforce()
        apply_async()
        after = db.user(uid)
        if after and fields.get('enabled') and not after['enabled'] and after['disabled_reason'] in ('expired', 'quota'):
            # Switched on, but still expired or out of quota: enforce paused it again at once. Say so.
            return self.json({'ok': True, 'still_paused': after['disabled_reason']})
        return self.json({'ok': True})

    def refused(self, fn, after=None):
        """Run a members.* action; a refusal becomes a 400 with its message."""
        try:
            out = fn()
        except members.Refused as e:
            return self.json({'error': str(e)}, 400)
        if after:
            after()
        return self.json(dict({'ok': True}, **(out if isinstance(out, dict) else {})))

    def api_invites(self, method, s):
        names = db.user_names()
        reg = '%s/%s/' % (self.base_url(s), s['member_path'])
        if method != 'POST':
            return self.json({'invites': [members.invite_view(i, names, reg) for i in db.invites()]})
        d = self.body_json()
        try:
            inviter = int(d.get('inviter') or 0)
        except (TypeError, ValueError, OverflowError):
            return self.json({'error': 'invalid inviter'}, 400)
        rec = lambda: {'invite': members.invite_view(db.invite(members.create_invite(
            d.get('kind', 'admin'), d.get('quota_gb', 0), d.get('valid_days', 7), d.get('max_uses', 1),
            inviter=inviter, expire_days=d.get('expire_days', 0), reset_day=d.get('reset_day', 0),
            note=d.get('note', ''), servers=d.get('servers', ''), speed_mbps=d.get('speed_mbps', 0),
            throttle_mbps=d.get('throttle_mbps', 0))['id']), names, reg)}
        return self.refused(rec)

    def api_requests(self, method, s):
        names = db.user_names()
        return self.json({'requests': [dict(r, name=names.get(r['user_id'], '#%d' % r['user_id'])) for r in db.requests()]})

    def api_monitor(self, method, s):
        if method == 'POST':
            monitor.run_in_background(jobs.log)
            return self.json({'ok': True})
        return self.json(monitor.summary())

    def api_abuse(self, method, s):
        if method == 'POST':
            abuse.check(s, jobs.log)
        return self.json(abuse.latest())

    def api_servers(self, method, s):
        if method != 'POST':
            return self.json({'servers': cluster.view(s), 'join_code': cluster.join_code(s, self.base_url(s)),
                              'node_master': s['node_master']})
        d = self.body_json()
        try:
            x = cluster.add_server(str(d.get('code', '')), str(d.get('name', '')).strip())
        except ValueError as e:
            return self.json({'error': str(e)}, 400)
        jobs.log('server added: %s' % x['name'])
        return self.json({'ok': True, 'id': x['id']})

    def api_server_action(self, sid, action):
        if not any(x['id'] == sid for x in db.settings()['servers']):
            return self.json({'error': 'no such server'}, 404)
        if action == 'remove':
            cluster.remove_server(sid)
        elif action == 'save':
            d = self.body_json()
            fields = {k: d[k] for k in ('name', 'enabled', 'rate') if k in d}
            if 'enabled' in fields:
                try:
                    fields['enabled'] = as_bool(fields['enabled'])
                except ValueError:
                    return self.json({'error': 'enabled: expected true or false'}, 400)
            if 'rate' in fields:
                try:
                    fields['rate'] = float(fields['rate'])
                except (TypeError, ValueError, OverflowError):
                    return self.json({'error': 'traffic rate must be 0-100'}, 400)
            try:
                cluster.update_server(sid, **fields)
            except ValueError as e:
                return self.json({'error': str(e)}, 400)
        else:
            cluster.sync_all(jobs.log)
        return self.json({'ok': True, 'servers': cluster.view(db.settings())})

    def api_node_key(self, method, s):
        """New node key (the old join code stops working; re-add this server on the main server)."""
        if method != 'POST':
            return self.json({'error': 'POST only'}, 405)
        db.set_settings(node_key=secure.token(24), node_master='', node_master_id='')
        removed = False
        for u in db.users():
            if u['remote_id']:
                db.delete_user(u['id'])
                removed = True
        if removed:
            apply_async()
        return self.json({'ok': True, 'join_code': cluster.join_code(db.settings(), self.base_url(s))})

    # --- member centre ---------------------------------------------------------------------------
    def member_page(self, base):
        with open(os.path.join(paths.STATIC, 'member.html'), encoding='utf-8') as f:
            page = f.read().replace('{{BASE}}', html.escape(base, quote=True))
        return self.send(200, page, 'text/html; charset=utf-8', {
            'Cache-Control': 'no-store', 'X-Frame-Options': 'DENY',
            'Content-Security-Policy': "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
                                       "object-src 'none'; base-uri 'self'; form-action 'self'; "
                                       "frame-ancestors 'none'"})

    def member_cookie(self, tok, max_age=8 * 3600):
        return 'v2vm=%s; Path=/%s/; Max-Age=%d; HttpOnly; Secure; SameSite=Strict' % (
            tok, db.settings()['member_path'], max_age)

    def member_area(self, method, sub, s, u, base):
        """Shared by the link page (/s/<token>/, `u` from the token) and the member centre (`u` from the login)."""
        by_link = base.startswith('/s/')
        if method == 'GET' and sub in ('/', '/index.html'):
            return self.member_page(base)
        m = re.fullmatch(r'/static/(kit\.js|style\.css|member\.js)', sub)
        if method == 'GET' and m:
            return self.static(m.group(1))
        m = re.fullmatch(r'/download/([A-Za-z0-9._-]{5,120})', sub)
        if method in ('GET', 'HEAD') and m and u is not None:
            return self.download(m.group(1))
        if not sub.startswith('/api/'):
            return self.not_found()
        api = sub[5:]
        if method == 'POST' and self.headers.get('X-V2V') != '1':
            return self.json({'error': 'missing header'}, 403)
        if api == 'hello':
            return self.json({'mode': 'link' if by_link else 'login', 'logged_in': u is not None,
                              'language': s['language'], 'node_name': s['node_name'],
                              'invites': s['member_invites'] and s['member_enabled'], 'requests': s['member_requests'],
                              'notice': s['member_notice'] if u is not None else '',
                              'member_url': '%s/%s/' % (self.base_url(s), s['member_path']) if s['member_enabled'] else ''})
        if not by_link and method == 'POST' and api in ('login', 'register'):
            if self.rate_limited('member'):
                return self.json({'error': 'too many attempts, wait 10 minutes'}, 429)
            d = self.body_json()
            if api == 'login':
                cand = db.user_by_name(str(d.get('name', '')).strip())
                good = secure.check_password(str(d.get('password', '')),
                                             cand['login_hash'] if cand and cand['login_hash'] else _dummy_hash())
                if not cand or not cand['login_hash'] or not good:
                    self._record_fail()
                    time.sleep(0.5)
                    return self.json({'error': 'wrong name or password'}, 403)
                uid = cand['id']
            else:
                try:
                    uid = members.register(d.get('code', ''), d.get('name', ''), d.get('password', ''))
                except members.Refused as e:
                    self._record_fail()
                    return self.json({'error': str(e)}, 400)
                jobs.log('new account from an invite code: %s' % db.user(uid)['name'])
                notify.send('new account %s (invite code) / 新用户 %s 通过邀请码注册' % (db.user(uid)['name'], db.user(uid)['name']),
                            key='reg-%d' % uid)
                apply_async()
            # Password or subscription-token rotation may have revoked sessions
            # while PBKDF2 ran. Recheck the account and mint the cookie atomically.
            with db.transaction():
                current = db.user(uid)
                stale = current is None or (api == 'login' and any(
                    current[k] != cand[k] for k in ('name', 'login_hash', 'sub_token', 'uuid')))
                session = None if stale else db.new_member_session(uid)
            if stale:
                return self.json({'error': 'account credentials changed; retry'}, 409)
            self._release_attempt()
            return self.json({'ok': True}, headers={'Set-Cookie': self.member_cookie(session)})
        if u is None:
            return self.json({'error': 'login required'}, 401)
        if api == 'logout' and not by_link:
            if method != 'POST':
                return self.json({'error': 'POST only'}, 405)
            db.end_member_session(self.cookie('v2vm'))
            return self.json({'ok': True}, headers={'Set-Cookie': self.member_cookie('', 0)})
        if api == 'me':
            return self.json(self.member_view(s, u, by_link))
        if api == 'qr':
            return self.send(200, qr.svg('%s/s/%s' % (self.base_url(s), u['sub_token']), scale=5), 'image/svg+xml',
                             {'Cache-Control': 'no-store'})
        if method != 'POST':
            return self.json({'error': 'unknown endpoint'}, 404)
        d = self.body_json()
        if api == 'password':
            if u['login_hash']:
                # The link or a session must not become an unlimited guesser of the login password.
                if self.rate_limited('member'):
                    return self.json({'error': 'too many attempts, wait 10 minutes'}, 429)
                if not secure.check_password(str(d.get('old', '')), u['login_hash']):
                    self._record_fail()
                    return self.json({'error': 'current password is wrong'}, 403)
            fresh = {}

            def set_pw():
                db.update_user(u['id'], login_hash=secure.hash_password(members.check_password(d.get('new'))))
                # Every session ends, this one included: a stolen copy of this very cookie must stop working.
                # The member who changed it from the member centre goes on with a new session.
                db.end_member_session(None, u['id'])
                if not by_link:
                    fresh['Set-Cookie'] = self.member_cookie(db.new_member_session(u['id']))
            try:
                set_pw()
            except members.Refused as e:
                return self.json({'error': str(e)}, 400)
            return self.json({'ok': True}, headers=fresh or None)
        if api == 'request' and s['member_requests']:
            def ask():
                members.request_more(u['id'], d.get('add_gb'), d.get('reason', ''))
                notify.send('%s asks for +%s GB / %s 申请增加 %s GB 流量' % (u['name'], d.get('add_gb'), u['name'], d.get('add_gb')),
                            key='req-%d' % u['id'], every=600)
            return self.refused(ask)
        if api == 'invite' and s['member_invites'] and s['member_enabled']:   # a code needs a sign-up page
            def make():
                code = members.create_invite('member', d.get('quota_gb'), d.get('valid_days', 7), d.get('max_uses', 1), inviter=u['id'], note=d.get('note', ''), by_member=True)['code']
                # The friend needs somewhere to type the code: hand back the ready sign-up link too.
                return {'code': code, 'register_url': '%s/%s/#register=%s' % (self.base_url(s), s['member_path'], code)}
            return self.refused(make)
        if api == 'rotate':
            # New link and credentials (the old link stops working at once), e.g. after it leaked.
            db.rotate_user(u['id'])
            apply_async()
            nu = db.user(u['id'])
            jobs.log('%s changed their own subscription link' % nu['name'])
            # Rotation ends every member session (a leaked link may have opened one). The member who
            # rotated from the member centre keeps going with a fresh session instead of being logged out.
            headers = None if by_link else {'Set-Cookie': self.member_cookie(db.new_member_session(u['id']))}
            return self.json({'ok': True, 'sub_url': '%s/s/%s' % (self.base_url(s), nu['sub_token']),
                              'base': '/s/%s/' % nu['sub_token'] if by_link else ''}, headers=headers)
        if api == 'report':
            # Sent by the vps2vpn app when a line keeps failing (or works again); shown to the admin.
            try:
                host = d.get('host', '')
                if not isinstance(host, str):
                    raise ValueError('host must be text')
                jobs.report_line(u['id'], str(d.get('line', '')), as_bool(d.get('ok', False)), host)
            except ValueError as e:
                return self.json({'error': str(e)}, 400)
            return self.json({'ok': True})
        if api == 'invite-revoke' and s['member_invites']:
            try:
                iid = int(d.get('id', 0))
            except (TypeError, ValueError, OverflowError):
                return self.json({'error': 'invalid invite id'}, 400)
            return self.refused(lambda: members.revoke_invite(iid, by_member=u['id']))
        return self.json({'error': 'unknown endpoint'}, 404)

    def download(self, name):
        """Stream an app installer from paths.CLIENT (only names the update check would offer), or its
        detached update signature `<installer>.sig`, which the app checks before it offers the file."""
        sig = name.endswith('.sig')
        if not _client_asset(name[:-4] if sig else name):
            return self.not_found()
        # Opened once, and the size taken from that open file: a client sync may swap in a new installer at
        # any moment, and a size read from one file with bytes sent from another breaks Content-Length (and
        # the next request on the connection). Not through a symlink.
        try:
            fd = os.open(os.path.join(paths.CLIENT, name), os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) |
                         getattr(os, 'O_BINARY', 0))
        except OSError:
            return self.not_found()
        with os.fdopen(fd, 'rb') as fh:
            st = os.fstat(fh.fileno())
            size = st.st_size
            if not stat.S_ISREG(st.st_mode) or (sig and size > 4096):
                return self.not_found()
            self.send_response(200)
            for k, v in (('Content-Type', 'application/octet-stream'), ('Content-Length', str(size)),
                         ('Content-Disposition', 'attachment; filename="%s"' % name), ('Cache-Control', 'no-store'),
                         ('X-Content-Type-Options', 'nosniff')):
                self.send_header(k, v)
            self.end_headers()
            if self.command == 'HEAD':
                return
            left = size
            while left:
                chunk = fh.read(min(left, 1 << 16))
                if not chunk:                    # shorter than it said: the client must not wait for the rest
                    self.close_connection = True
                    return
                self.wfile.write(chunk)
                left -= len(chunk)

    def member_view(self, s, u, by_link):
        base = self.base_url(s)
        sub_url = '%s/s/%s' % (base, u['sub_token'])
        # Installer downloads are only served over TLS (route() requires secure_ok), so never emit http:// here.
        dl_url = 'https://' + sub_url[7:] if sub_url.startswith('http://') else sub_url
        names = db.user_names()
        invitees = members.invitee_index(db.invite_tree(u['id']))    # this account's invite chain only
        nxt = 0
        if u['reset_day']:
            t = time.localtime()
            y, mth = (t.tm_year, t.tm_mon) if t.tm_mday < u['reset_day'] else \
                ((t.tm_year + 1, 1) if t.tm_mon == 12 else (t.tm_year, t.tm_mon + 1))
            nxt = int(time.mktime((y, mth, u['reset_day'], 0, 0, 0, 0, 0, -1)))
        reg = '%s/%s/' % (base, s['member_path'])
        online = (cores.online_detail(s) or {}).get(u['id'])
        return {
            'name': u['name'], 'enabled': bool(u['enabled']), 'disabled_reason': u['disabled_reason'],
            'used_up': u['used_up'], 'used_down': u['used_down'], 'quota_gb': u['quota_gb'],
            'extra_gb': members.extra(u), 'expire_after_days': u['expire_after_days'], 'max_ips': u['max_ips'],
            'quota_eff': members.effective_quota(u, index=invitees),
            'shared_gb': round(members.given_away(u['id'], index=invitees), 2),
            'capacity': members.capacity(u) if s['member_invites'] else None,
            'expire_at': u['expire_at'], 'reset_day': u['reset_day'], 'next_reset': nxt, 'created_at': u['created_at'],
            'invited_by': names.get(u['invited_by'], ''), 'has_login': bool(u['login_hash']),
            'sub_url': sub_url, 'import': subscription.import_links(sub_url, s['node_name'] or 'vps2vpn'),
            'history': db.user_traffic(u['id'], 30),
            'requests': db.requests(u['id'])[:10] if s['member_requests'] else [],
            'invites': [members.invite_view(i, names, reg) for i in db.invites(u['id'])][:20] if s['member_invites'] else [],
            'invitees': [{'name': x['name'], 'quota_gb': x['invite_deduct'], 'active': members.deducting(x)}
                         for x in invitees.get(u['id'], ())],
            'online': online, 'servers': 1 + len([x for x in s['servers'] if x.get('info')]),
            'speed_mbps': u['speed_mbps'] or 0, 'throttle_mbps': u['throttle_mbps'] or 0, 'throttled': bool(u['throttled']),
            'limit_mbps': db.limit_mbps(u),
            'ai': ai_view(aicheck.latest()),
            'client': client_info(s, dl_url),
        }

    def api_password(self, method, s):
        d = self.body_json()
        if self.rate_limited():          # a session must not become an unlimited guesser of the password
            return self.json({'error': 'too many attempts, wait 10 minutes'}, 429)
        old = str(d.get('old', ''))
        if len(old) > 128 or not secure.check_password(old, s['admin_hash']):
            self._record_fail()
            return self.json({'error': 'current password is wrong'}, 403)
        new = str(d.get('new', ''))
        if len(new) < 8:
            return self.json({'error': 'password must be at least 8 characters'}, 400)
        if len(new) > 128:               # sign-in refuses longer passwords: it would lock the admin out
            return self.json({'error': 'password: 8 to 128 characters'}, 400)
        new_hash = secure.hash_password(new)     # slow: before the transaction, not inside it
        user = str(d.get('username') or s['admin_user']).strip()[:32]
        if not user or any(ord(c) < 32 or ord(c) == 127 for c in user):
            return self.json({'error': 'invalid username'}, 400)
        return self._change_admin_sign_in(s, lambda: db.set_settings(admin_hash=new_hash, admin_user=user))

    def api_check_targets(self, method, s):
        best, res = system.best_target()
        return self.json({'best': best, 'results': res})

    def api_cert(self, method, s):
        if method != 'POST':
            return self.json({'error': 'POST only'}, 405)
        host = s['domain'] or s['public_host']
        if not _cert_lock.acquire(blocking=False):
            return self.json({'error': 'certificate renewal already in progress'}, 409)

        def go():
            try:
                certs.issue(host, s['acme_email'], log=jobs.log)
                db.set_settings(cert_status='ok')
                apply_async(force=True)
            except Exception as e:
                db.set_settings(cert_status='failed: %s' % str(e)[:200])
                jobs.log('certificate failed: %s' % e)
            finally:
                _cert_lock.release()
        threading.Thread(target=go, daemon=True).start()
        return self.json({'ok': True, 'started': host})

    def api_qr(self, method, s):
        text = self.query.get('text', '')
        if not text:
            return self.json({'error': 'text required'}, 400)
        try:
            image = qr.svg(text, scale=5)
        except ValueError:
            return self.json({'error': 'too long for a QR code; copy the link instead'}, 413)
        return self.send(200, image, 'image/svg+xml', {'Cache-Control': 'no-store', 'Content-Security-Policy': _SVG_CSP})

    def api_user_links(self, method, s):
        try:
            uid = int(self.query.get('id', 0))
        except ValueError:
            return self.json({'error': 'invalid user id'}, 400)
        u = db.user(uid)
        if not u:
            return self.json({'error': 'no such user'}, 404)
        sub = '%s/s/%s' % (self.base_url(s), u['sub_token'])
        return self.json({'sub': sub, 'import': subscription.import_links(sub, s['node_name'] or 'vps2vpn'),
                          'nodes': [subscription.share_link(n) for n in subscription.nodes(s, u)]})

    def api_restart(self, method, s):
        apply_async(force=True)
        return self.json({'ok': True})

    def api_rules_refresh(self, method, s):
        rules.refresh_in_background(jobs.log)
        return self.json({'ok': True})

    def api_doctor(self, method, s):
        if method != 'POST':
            return self.json({'error': 'POST only'}, 405)
        return self.json({'results': doctor.run_all()})

    def api_telegram(self, method, s):
        """POST {token?, challenge} -> verify a private chat pairing code before saving."""
        if method != 'POST':
            return self.json({'error': 'POST only'}, 405)
        d = self.body_json()
        if d.get('off'):
            db.set_settings(tg_token='', tg_chat='', tg_verified=False)
            return self.json({'ok': True})
        token = str(d.get('token') or s['tg_token']).strip()
        if not re.fullmatch(r'\d{5,15}:[A-Za-z0-9_-]{30,64}', token):
            return self.json({'error': 'bad_token'}, 400)
        challenge = str(d.get('challenge') or '').strip()
        if not re.fullmatch(r'[0-9a-f]{32}', challenge):
            return self.json({'error': 'pairing_required'}, 400)
        try:
            chat, who = notify.find_chat(token, challenge)
        except urllib.error.HTTPError as e:
            return self.json({'error': 'bad_token' if e.code in (401, 404) else 'telegram %d' % e.code}, 400)
        except OSError as e:
            return self.json({'error': 'cannot reach api.telegram.org: %s' % e}, 502)
        if not chat:
            return self.json({'error': 'no_chat'}, 400)
        # Only this authenticated panel flow confirms ownership of a chat.
        db.set_settings(tg_token=token, tg_chat=chat, tg_verified=True)
        ok = notify.send('alerts are on / 告警已开启', s=db.settings())
        return self.json({'ok': ok, 'who': who})

    def api_backup(self, method, s):
        data = json.dumps(db.export_all(), ensure_ascii=False, indent=1)
        name = 'vps2vpn-backup-%s.json' % time.strftime('%Y%m%d-%H%M')
        return self.send(200, data, 'application/json', {'Content-Disposition': 'attachment; filename=' + name,
                                                         'Cache-Control': 'no-store'})

    def api_restore(self, method, s):
        if method != 'POST':
            return self.json({'error': 'POST only'}, 405)
        try:
            body = self.body_json(limit=32 << 20)
            with cores.replacing_accounts(s), cluster.restoring():
                db.import_all(body)
        except (ValueError, KeyError, TypeError, sqlite3.Error) as e:
            return self.json({'error': 'restore failed: %s' % e}, 400)
        db.end_all_sessions()
        db.end_all_member_sessions()
        s2 = db.ensure_secrets()    # a backup without some keys (older, or made by hand) gets them now, not at restart
        certs.ensure_self_signed(s2['domain'] or s2['public_host'])
        apply_async(force=True)
        return self.json({'ok': True}, headers={'Set-Cookie': self.session_cookie(db.new_session())})


_DUMMY = []


def _dummy_hash():
    if not _DUMMY:
        _DUMMY.append(secure.hash_password(secure.token(12)))
    return _DUMMY[0]


# Latest supported account expiry is 9999-12-31 23:59:59 UTC.
# Keep values representable in SQLite and in client calendar/date APIs.
MAX_ACCOUNT_EXPIRE_AT = 253402300799


def _limit_fields(fields):
    return {k: fields[k] for k in ('servers', 'speed_mbps', 'throttle_mbps') if k in fields}


def user_fields(d):
    out = {}
    try:
        if 'quota_gb' in d:
            q = float(d['quota_gb'] or 0)
            if not math.isfinite(q) or q > 1e6:     # max(0, nan) would quietly mean "unlimited"
                return 'invalid number'
            out['quota_gb'] = max(0.0, q)
        if 'expire_at' in d:
            expiry = int(d['expire_at'] or 0)
            if expiry > MAX_ACCOUNT_EXPIRE_AT:
                return 'expire_at is out of supported range'
            out['expire_at'] = max(0, expiry)
        if 'reset_day' in d:
            out['reset_day'] = int(d['reset_day'] or 0)
            if not 0 <= out['reset_day'] <= 28:
                return 'reset day must be 1-28 (0 = never)'
        if 'enabled' in d:
            try:
                out['enabled'] = int(as_bool(d['enabled']))
            except ValueError:
                return 'enabled: expected true or false'
        if 'max_ips' in d:
            out['max_ips'] = int(d['max_ips'] or 0)
            if not 0 <= out['max_ips'] <= 100:
                return 'device limit must be 0-100'
        if 'expire_after_days' in d:
            out['expire_after_days'] = int(d['expire_after_days'] or 0)
            if not 0 <= out['expire_after_days'] <= 3650:
                return 'days must be 0-3650'
        if 'expire_days' in d and int(d['expire_days'] or 0):      # batch creation: lifetime from today
            days = int(d['expire_days'])
            if not 0 < days <= 3650:
                return 'days must be 0-3650'
            out['expire_at'] = int(time.time() + days * 86400)
        if 'note' in d:
            out['note'] = str(d['note'])[:200]
        for k, label in (('speed_mbps', 'speed limit'), ('throttle_mbps', 'slow-down speed')):
            if k in d:
                v = float(d[k] or 0)
                if not math.isfinite(v) or not 0 <= v <= db.MAX_MBPS:
                    return '%s must be 0-%d Mbps' % (label, db.MAX_MBPS)
                out[k] = v
        if 'servers' in d:
            try:
                out['servers'] = db.clean_servers(d['servers'])
            except ValueError as e:
                return str(e)
        if 'name' in d and str(d['name']).strip():
            out['name'] = str(d['name']).strip()[:32]
    except (TypeError, ValueError, OverflowError):
        return 'invalid number'
    return out


HOST_RE = re.compile(r'^(?=.{1,253}$)([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$')


def as_bool(v):
    """A switch from JSON. bool('false') is True, so strings and numbers are read the way they are meant;
    anything else (lists, objects, 'maybe') is refused rather than guessed."""
    if isinstance(v, bool):
        return v
    if isinstance(v, int) and v in (0, 1):
        return bool(v)
    if isinstance(v, str) and v.strip().lower() in ('true', '1', 'on', 'yes'):
        return True
    if isinstance(v, str) and v.strip().lower() in ('false', '0', 'off', 'no', ''):
        return False
    raise ValueError('expected true or false')


def validate_settings(d, s):
    """Check and normalise settings from the panel. Returns a dict of changes or an error string."""
    out = {}
    bools = ('reality_enabled', 'hy2_enabled', 'tuic_enabled', 'hy2_hop', 'block_ads', 'block_bt', 'ai_group',
             'tune_network', 'ipv6_nodes', 'member_enabled', 'member_invites', 'member_requests', 'monitor_enabled',
             'abuse_guard', 'tg_backup', 'tg_bot', 'ip_limit_pause', 'client_auto_update')
    for k in bools:
        if k in d:
            try:
                out[k] = as_bool(d[k])
            except ValueError:
                return '%s: expected true or false' % k
    for k in ('custom_direct', 'custom_proxy', 'custom_block'):
        if k in d:
            v = d[k]
            items = re.split(r'[\s,;]+', v) if isinstance(v, str) else [str(i) for i in (v or [])]
            clean = []
            for item in items:
                item = re.sub(r'^(https?://)?(\+\.|\*\.|\.)?', '', item.strip().lower()).split('/')[0]
                if not item:
                    continue
                if not (HOST_RE.match(item) or re.fullmatch(r'[a-z0-9-]{1,63}', item)):
                    return 'not a domain: %s' % item[:60]
                if item not in clean:
                    clean.append(item)
            if len(clean) > 500:
                return 'at most 500 domains per list'
            out[k] = clean
    if 'traffic_rate' in d:
        try:
            rate = float(d['traffic_rate'])
        except (TypeError, ValueError, OverflowError):
            return 'traffic rate must be 0-100'
        if not db.valid_rate(rate):
            return 'traffic rate must be 0-100'
        out['traffic_rate'] = rate
    if 'language' in d:
        out['language'] = 'en' if d['language'] == 'en' else 'zh'
    if 'member_notice' in d:
        out['member_notice'] = ''.join(c for c in str(d['member_notice']) if c == '\n' or ord(c) >= 32).strip()[:500]
    if 'node_name' in d:
        out['node_name'] = re.sub(r'[\r\n#]', '', str(d['node_name']))[:40] or 'vps2vpn'
    if 'public_host' in d:
        h = str(d['public_host']).strip().strip('[]')
        if not (certs.is_ip(h) or HOST_RE.match(h)):
            return 'server address must be an IP address or a domain name'
        out['public_host'] = h
    if 'domain' in d:
        h = str(d['domain']).strip().lower()
        if h and not HOST_RE.match(h):
            return 'invalid domain name'
        out['domain'] = h
        if h:
            out['public_host'] = h
    if 'acme_email' in d:
        e = str(d['acme_email']).strip()
        if e and not re.fullmatch(r'[^@\s]+@[^@\s]+\.[^@\s]+', e):
            return 'invalid e-mail address'
        out['acme_email'] = e
    if 'cert_mode' in d:
        out['cert_mode'] = 'self' if d['cert_mode'] == 'self' else 'auto'
    if 'reality_target' in d:
        t = str(d['reality_target']).strip().lower()
        if not HOST_RE.match(t):
            return 'camouflage site must be a domain name like www.microsoft.com'
        if t != s.get('reality_target') and _is_private_host(t):
            # REALITY hands every non-client connection to this site; a local one would expose this machine.
            return 'camouflage site must be a public website, not this machine or a private network'
        out['reality_target'] = t
    for k in ('reality_port', 'hy2_port', 'tuic_port'):
        if k in d:
            try:
                p = int(d[k])
            except (TypeError, ValueError, OverflowError):
                return 'invalid port'
            if not 1 <= p <= 65535:
                return 'port must be 1-65535'
            out[k] = p
    if 'server_cap_gb' in d:
        try:
            cap = float(d['server_cap_gb'] or 0)
        except (TypeError, ValueError, OverflowError):
            return 'invalid number'
        if not math.isfinite(cap) or cap > 1e7:
            return 'invalid number'
        out['server_cap_gb'] = max(0.0, cap)
    if 'server_reset_day' in d:
        try:
            out['server_reset_day'] = int(d['server_reset_day'] or 1)
        except (TypeError, ValueError, OverflowError):
            return 'invalid number'
        if not 1 <= out['server_reset_day'] <= 28:
            return 'reset day must be 1-28'
    if 'vps_renew_at' in d:
        v = str(d['vps_renew_at'] or '').strip()
        if v:
            try:
                time.strptime(v, '%Y-%m-%d')
            except ValueError:
                return 'date must look like 2026-12-31'
        out['vps_renew_at'] = v
    if 'client_version' in d:
        v = str(d['client_version'] or '').strip().lstrip('vV')
        if v and not re.fullmatch(r'\d+(\.\d+){0,3}', v):
            return 'version must look like 1.2.3'
        out['client_version'] = v
    if 'client_url' in d:
        v = str(d['client_url'] or '').strip()
        if v and not re.fullmatch(r'https?://[^\s<>"]{3,500}', v):
            return 'download link must start with http:// or https://'
        out['client_url'] = v
    if 'client_notes' in d:
        out['client_notes'] = str(d['client_notes'] or '').strip()[:300]
    if 'support_url' in d:
        v = str(d['support_url'] or '').strip()
        if v and not re.fullmatch(subscription.SUPPORT_URL_RE, v):
            return 'support link must start with http://, https:// or tg:// (one line, no spaces)'
        out['support_url'] = v
    if 'sub_update_hours' in d:
        v = d['sub_update_hours']
        try:
            if isinstance(v, bool) or (isinstance(v, float) and not v.is_integer()):
                raise ValueError(v)
            h = int(v)
        except (TypeError, ValueError, OverflowError):
            return 'update interval must be a whole number of hours'
        if not 1 <= h <= 168:
            return 'update interval must be 1-168 hours'
        out['sub_update_hours'] = h
    if 'vps_renew_note' in d:
        out['vps_renew_note'] = str(d['vps_renew_note'] or '').strip()[:40]
    if 'hy2_hop_range' in d:
        try:
            a, b = system.parse_range(str(d['hy2_hop_range']))
        except ValueError as e:
            return str(e)
        out['hy2_hop_range'] = '%d-%d' % (a, b)
    if 'hy2_obfs' in d:
        v = str(d['hy2_obfs'])
        if v == 'random':
            v = secure.token(12)
        out['hy2_obfs'] = v[:64]
    if 'hy2_masquerade' in d:
        v = str(d['hy2_masquerade']).strip()
        if not re.fullmatch(r'https://[A-Za-z0-9.-]+(/\S*)?', v):
            return 'masquerade must be an https:// URL'
        if v != s.get('hy2_masquerade') and _is_private_host(urllib.parse.urlsplit(v).hostname):
            # Hysteria 2 proxies every visitor without the password to this URL.
            return 'masquerade must be a public website, not this machine or a private network'
        out['hy2_masquerade'] = v
    merged = dict(s, **out)
    if not (merged['reality_enabled'] or merged['hy2_enabled'] or merged['tuic_enabled']):
        return 'turn on at least one protocol'
    if merged['hy2_enabled'] and merged['tuic_enabled'] and merged['hy2_port'] == merged['tuic_port']:
        return 'Hysteria 2 and TUIC need different UDP ports'
    if merged['panel_port'] in (merged['reality_port'],) and merged['reality_enabled']:
        return 'the panel already uses that TCP port'
    if merged['hy2_hop'] and merged['hy2_enabled']:
        a, b = system.parse_range(merged['hy2_hop_range'])
        if a <= merged['hy2_port'] <= b:
            return 'Hysteria port must be outside the hopping range'
        if merged['tuic_enabled'] and a <= merged['tuic_port'] <= b:
            return 'TUIC port must be outside the hopping range'
    return out


# --- landing page for people who open their link in a browser ----------------------
LANDING = {
    'zh': {
        'title': '我的订阅', 'used': '已用', 'of': '共', 'unlimited': '不限量', 'expires': '到期', 'never': '永不过期',
        'disabled': '此订阅已停用（流量用完、已到期或被管理员关闭）', 'step1': '第 1 步：装一个 App',
        'step2': '第 2 步：一键导入', 'copy': '复制订阅链接', 'copied': '已复制', 'scan': '手机扫码导入',
        'apps': [('Windows / macOS', 'Clash Verge Rev 或 FlClash（免费）'), ('Android', 'FlClash 或 Hiddify（免费）'),
                 ('iPhone / iPad', 'Shadowrocket（小火箭，付费）、Stash 或 Karing（免费）')],
        'tip': '导入后打开 App 里的“系统代理”或“VPN/TUN 模式”开关即可。订阅会自动更新，不用重复导入。',
    },
    'en': {
        'title': 'My subscription', 'used': 'Used', 'of': 'of', 'unlimited': 'unlimited', 'expires': 'Expires',
        'never': 'never', 'disabled': 'This subscription is paused (quota used up, expired or turned off).',
        'step1': 'Step 1: install an app', 'step2': 'Step 2: import with one tap', 'copy': 'Copy link',
        'copied': 'Copied', 'scan': 'Scan with your phone',
        'apps': [('Windows / macOS', 'Clash Verge Rev or FlClash (free)'), ('Android', 'FlClash or Hiddify (free)'),
                 ('iPhone / iPad', 'Shadowrocket (paid), Stash or Karing (free)')],
        'tip': 'After importing, switch on "System proxy" or "VPN/TUN mode" in the app. The subscription updates itself.',
    },
}


def landing_page(s, u, sub_url):
    t = LANDING.get(s['language'], LANDING['zh'])
    e = html.escape
    used = u['used_up'] + u['used_down']
    quota = fmt_bytes(u['quota_gb'] * (1 << 30)) if u['quota_gb'] else t['unlimited']
    pct = min(100, int(used * 100 / (u['quota_gb'] * (1 << 30)))) if u['quota_gb'] else 0
    exp = time.strftime('%Y-%m-%d', time.localtime(u['expire_at'])) if u['expire_at'] else t['never']
    links = subscription.import_links(sub_url, s['node_name'] or 'vps2vpn')
    btns = [('Clash Verge / FlClash', links['clash']), ('Shadowrocket', links['shadowrocket']),
            ('Hiddify', links['hiddify']), ('sing-box', links['singbox']), ('v2rayNG', links['v2rayng'])]
    apps = ''.join('<li><b>%s</b>：%s</li>' % (e(a), e(b)) for a, b in t['apps'])
    buttons = ''.join('<a class="btn" href="%s">%s</a>' % (e(href), e(label)) for label, href in btns)
    warn = '<p class="warn">%s</p>' % e(t['disabled']) if not u['enabled'] else ''
    return '''<!doctype html><html lang="%(lang)s"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>%(title)s</title><style>
:root{--bg:#f6f7f9;--card:#fff;--fg:#1d2330;--mute:#667085;--acc:#2563eb;--line:#e5e7eb}
@media (prefers-color-scheme:dark){:root{--bg:#0f1218;--card:#171b23;--fg:#e8eaf0;--mute:#98a2b3;--acc:#5b8cff;--line:#2a3140}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.6 system-ui,-apple-system,"PingFang SC","Microsoft YaHei",sans-serif}
main{max-width:560px;margin:0 auto;padding:24px 16px}.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:18px;margin:14px 0}
h1{font-size:22px;margin:0 0 4px}h2{font-size:16px;margin:0 0 10px}.mute{color:var(--mute)}.bar{height:8px;border-radius:4px;background:var(--line);overflow:hidden}
.bar i{display:block;height:100%%;background:var(--acc)}.btn{display:block;text-align:center;padding:12px;border-radius:10px;background:var(--acc);color:#fff;text-decoration:none;margin:8px 0;font-weight:600}
button{width:100%%;padding:12px;border-radius:10px;border:1px solid var(--line);background:transparent;color:var(--fg);font:inherit;cursor:pointer}
.qr{display:block;margin:8px auto;width:220px;max-width:100%%;border-radius:8px}.warn{background:#fee4e2;color:#912018;padding:10px;border-radius:8px}
ul{padding-left:18px;margin:0}code{word-break:break-all;font-size:12px;color:var(--mute)}</style></head><body><main>
<h1>%(name)s</h1><div class="mute">%(node)s</div>%(warn)s
<div class="card"><div>%(used_l)s %(used)s %(of)s %(quota)s</div><div class="bar"><i style="width:%(pct)d%%"></i></div>
<div class="mute">%(exp_l)s：%(exp)s</div></div>
<div class="card"><h2>%(step1)s</h2><ul>%(apps)s</ul></div>
<div class="card"><h2>%(step2)s</h2>%(buttons)s
<button id="cp">%(copy)s</button><p><code id="u">%(sub)s</code></p></div>
<div class="card"><h2>%(scan)s</h2><img class="qr" alt="QR" src="%(qr)s"></div>
<p class="mute">%(tip)s</p></main>
<script>document.getElementById('cp').onclick=function(){var t=document.getElementById('u').textContent;
(navigator.clipboard?navigator.clipboard.writeText(t):Promise.reject()).catch(function(){var r=document.createRange();
r.selectNode(document.getElementById('u'));getSelection().removeAllRanges();getSelection().addRange(r);document.execCommand('copy')});
this.textContent='%(copied)s'}</script></body></html>''' % {
        'lang': 'zh-CN' if s['language'] == 'zh' else 'en', 'title': e(t['title']), 'name': e(u['name']),
        'node': e(s['node_name']), 'warn': warn, 'used_l': e(t['used']), 'used': fmt_bytes(used), 'of': e(t['of']),
        'quota': e(quota), 'pct': pct, 'exp_l': e(t['expires']), 'exp': e(exp), 'step1': e(t['step1']),
        'apps': apps, 'step2': e(t['step2']), 'buttons': buttons, 'copy': e(t['copy']), 'sub': e(sub_url),
        'scan': e(t['scan']), 'qr': e('/s/%s/qr.svg' % u['sub_token']), 'tip': e(t['tip']), 'copied': e(t['copied'])}


def serve(port=None, host='::'):
    paths.ensure_dirs()
    s = db.ensure_secrets()
    port = port or s['panel_port']
    if not s['public_host']:
        ip = system.public_ip()
        if ip:
            db.set_settings(public_host=ip)
    s = db.settings()
    certs.ensure_self_signed(s['domain'] or s['public_host'] or 'vps2vpn.local')
    if s['setup_done']:
        system.port_hopping(s)
    tls = TLSContext()
    tls.get()
    try:
        httpd = Server((host, port), Handler, tls)
    except OSError:
        httpd = Server(('0.0.0.0', port), Handler, tls)    # no IPv6 on this machine
    sched = jobs.Scheduler()
    sched.start()
    stopping = threading.Event()

    def _stop(signum=None, frame=None):
        if stopping.is_set():
            return
        stopping.set()
        sched.stop.set()
        threading.Thread(target=httpd.shutdown, daemon=True).start()

    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            signal.signal(sig, _stop)
        except (ValueError, OSError):
            pass
    jobs.log('vps2vpn %s panel on port %d' % (VERSION, port))
    try:
        httpd.serve_forever()
    finally:
        _stop()
        try:
            httpd.server_close()
        except OSError:
            pass
        try:
            if db.settings()['setup_done']:
                jobs.collect()      # flush traffic counted since the last minute tick
        except Exception:
            pass
        try:
            jobs.HISTORY.save()
        except Exception:
            pass
        db.close()
