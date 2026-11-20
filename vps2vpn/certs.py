"""TLS certificates: a self-signed fallback and a small ACME (Let's Encrypt) client.

Let's Encrypt issues certificates for bare IP addresses since January 2026 (profile
"shortlived", valid about 6 days, http-01 challenge on port 80). That lets the panel and
Hysteria 2 use a trusted certificate even when the owner has no domain name.
The client below uses only the standard library plus the `openssl` command.
"""
import base64
import hashlib
import http.server
import ipaddress
import json
import os
import re
import ssl
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request

from . import paths, secure

LE_DIRECTORY = 'https://acme-v02.api.letsencrypt.org/directory'
LE_STAGING = 'https://acme-staging-v02.api.letsencrypt.org/directory'


def _openssl(*args, data=None):
    r = subprocess.run(['openssl'] + list(args), input=data, capture_output=True, timeout=60)
    if r.returncode != 0:
        raise RuntimeError('openssl %s failed: %s' % (args[0], r.stderr.decode(errors='replace')[-300:]))
    return r.stdout


def _pem(path):
    """Read a PEM file with plain \n line endings (some openssl builds write \r\r\n, which Go rejects)."""
    with open(path, 'rb') as f:
        return f.read().replace(b'\r', b'')


def is_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _san(host):
    return ('IP:' if is_ip(host) else 'DNS:') + host


# --- self-signed ----------------------------------------------------------------
def ensure_self_signed(host):
    """Create (or recreate for a new host) a 10-year self-signed ECDSA certificate."""
    paths.ensure_dirs()
    marker = paths.SELF_CRT + '.host'
    if os.path.exists(paths.SELF_CRT) and os.path.exists(marker):
        with open(marker, encoding='utf-8') as f:
            if f.read() == host:
                return
    with tempfile.TemporaryDirectory() as d:
        key, crt = os.path.join(d, 'k'), os.path.join(d, 'c')
        _openssl('req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', '-nodes',
                 '-keyout', key, '-out', crt, '-days', '3650', '-subj', '/CN=' + host,
                 '-addext', 'subjectAltName=' + _san(host))
        paths.write_atomic(paths.SELF_KEY, _pem(key), 0o640, 'vps2vpn')
        paths.write_atomic(paths.SELF_CRT, _pem(crt), 0o644, 'vps2vpn')
    paths.write_atomic(marker, host, 0o644)


def acme_valid(min_hours=24):
    """True when a Let's Encrypt certificate exists and is good for at least `min_hours`."""
    if not (os.path.exists(paths.ACME_CRT) and os.path.exists(paths.ACME_KEY)):
        return False
    try:
        out = _openssl('x509', '-in', paths.ACME_CRT, '-noout', '-checkend', str(min_hours * 3600))
        return b'will not expire' in out
    except RuntimeError:
        return False


def acme_names():
    try:
        out = _openssl('x509', '-in', paths.ACME_CRT, '-noout', '-ext', 'subjectAltName').decode()
        return re.findall(r'(?:DNS:|IP Address:)([^,\s]+)', out)
    except (RuntimeError, FileNotFoundError):
        return []


_trust_cache = {}
_trust_lock = threading.Lock()


def _identity(host):
    """Normalise DNS/IP names before checking an X.509 subject alternative name."""
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        return host.lower().rstrip('.')


def trusted(host):
    """True only for a host-matching CA-trusted leaf with a matching private key."""
    if not host:
        return False
    try:
        stamp = (os.stat(paths.ACME_CRT).st_mtime_ns, os.stat(paths.ACME_KEY).st_mtime_ns)
    except OSError:
        return False
    ident = _identity(host)
    cache_key = (ident, stamp, int(time.time() // 60))
    with _trust_lock:
        if cache_key in _trust_cache:
            return _trust_cache[cache_key]
    valid = acme_valid(1) and ident in {_identity(n) for n in acme_names()}
    if valid:
        try:
            # SAN + expiry alone also accept staging, forged, and self-signed chains.
            # OpenSSL validates the full presented chain against OS trust roots.
            _openssl('verify', '-purpose', 'sslserver', '-untrusted',
                     paths.ACME_CRT, paths.ACME_CRT)
            # Independently ensure the leaf matches the private key used by our server.
            ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER).load_cert_chain(paths.ACME_CRT, paths.ACME_KEY)
        except (OSError, RuntimeError, ValueError):
            valid = False
    with _trust_lock:
        if len(_trust_cache) > 16:
            _trust_cache.clear()
        _trust_cache[cache_key] = valid
    return valid


def current(host=None):
    """(cert, key) paths to use right now."""
    if host is None:
        from . import db
        s = db.settings()
        host = s['domain'] or s['public_host']
    if host and trusted(host):
        return paths.ACME_CRT, paths.ACME_KEY
    return paths.SELF_CRT, paths.SELF_KEY


_CERT_BLOCK_RE = re.compile(r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', re.S)


def fingerprint(cert_path):
    """SHA-256 of the leaf certificate (hex), what clients pin for a self-signed cert."""
    with open(cert_path, encoding='utf-8') as f:
        pem = f.read()
    m = _CERT_BLOCK_RE.search(pem)
    leaf = m.group(0) if m else pem
    der = ssl.PEM_cert_to_DER_cert(leaf)
    return hashlib.sha256(der).hexdigest()


# --- ACME -------------------------------------------------------------------------
class AcmeError(RuntimeError):
    pass


class _Acme:
    def __init__(self, directory, account_key):
        self.key = account_key
        self.dir = self._get(directory)
        self.kid = None
        self._nonce = None
        mod = _openssl('rsa', '-in', account_key, '-noout', '-modulus').decode().strip().split('=', 1)[1]
        self.jwk = {'e': secure.b64url((65537).to_bytes(3, 'big')), 'kty': 'RSA',
                    'n': secure.b64url(bytes.fromhex(mod))}
        thumb = json.dumps(self.jwk, sort_keys=True, separators=(',', ':')).encode()
        self.thumbprint = secure.b64url(hashlib.sha256(thumb).digest())

    @staticmethod
    def _get(url):
        with urllib.request.urlopen(url, timeout=30) as r:
            return json.loads(r.read())

    def _nonce_get(self):
        if self._nonce:
            n, self._nonce = self._nonce, None
            return n
        req = urllib.request.Request(self.dir['newNonce'], method='HEAD')
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.headers['Replay-Nonce']

    def post(self, url, payload, tries=3):
        protected = {'alg': 'RS256', 'nonce': self._nonce_get(), 'url': url}
        if self.kid:
            protected['kid'] = self.kid
        else:
            protected['jwk'] = self.jwk
        p64 = secure.b64url(json.dumps(protected).encode())
        b64 = '' if payload is None else secure.b64url(json.dumps(payload).encode())
        sig = _openssl('dgst', '-sha256', '-sign', self.key, data=('%s.%s' % (p64, b64)).encode())
        body = json.dumps({'protected': p64, 'payload': b64, 'signature': secure.b64url(sig)}).encode()
        req = urllib.request.Request(url, data=body, headers={'Content-Type': 'application/jose+json',
                                                              'User-Agent': 'vps2vpn-acme'})
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                self._nonce = r.headers.get('Replay-Nonce')
                raw = r.read()
                return r, (json.loads(raw) if raw and 'json' in r.headers.get('Content-Type', '') else raw)
        except urllib.error.HTTPError as e:
            self._nonce = e.headers.get('Replay-Nonce')
            err = e.read().decode(errors='replace')
            if 'badNonce' in err and tries > 1:
                return self.post(url, payload, tries - 1)
            raise AcmeError('%s -> HTTP %d: %s' % (url, e.code, err[:400]))

    def poll(self, url, done=('valid',), timeout=120):
        end = time.time() + timeout
        while time.time() < end:
            _, obj = self.post(url, None)
            if obj['status'] in done:
                return obj
            if obj['status'] == 'invalid':
                raise AcmeError('validation failed: ' + json.dumps(obj)[:600])
            time.sleep(2)
        raise AcmeError('timed out waiting for ' + url)


class _ChallengeServer:
    """Answers http-01 challenges on port 80 for the few seconds an order takes."""

    def __init__(self):
        self.tokens = {}
        tokens = self.tokens

        class H(http.server.BaseHTTPRequestHandler):
            timeout = 10

            def do_GET(self):
                t = self.path.rsplit('/', 1)[-1]
                if self.path.startswith('/.well-known/acme-challenge/') and t in tokens:
                    body = tokens[t].encode()
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/octet-stream')
                    self.send_header('Content-Length', str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                else:
                    self.send_error(404)

            def log_message(self, *a):
                pass

        class S6(http.server.ThreadingHTTPServer):
            address_family = __import__('socket').AF_INET6
            daemon_threads = True

            def server_bind(self):
                import socket
                self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
                super().server_bind()

        class S4(http.server.ThreadingHTTPServer):
            daemon_threads = True

        try:
            self.httpd = S6(('::', 80), H)
        except OSError:
            try:
                self.httpd = S4(('0.0.0.0', 80), H)
            except OSError as e:
                raise AcmeError('port 80 is busy or blocked (%s); Let\'s Encrypt needs it for a few seconds' % e)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


def issue(host, email='', staging=False, log=print):
    """Get a Let's Encrypt certificate for a domain or an IP address. Raises AcmeError on failure."""
    paths.ensure_dirs()
    if not os.path.exists(paths.ACME_ACCOUNT):
        pem = _openssl('genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048')
        paths.write_atomic(paths.ACME_ACCOUNT, pem.replace(b'\r', b''), 0o600)
    ac = _Acme(LE_STAGING if staging else LE_DIRECTORY, paths.ACME_ACCOUNT)
    reg = {'termsOfServiceAgreed': True}
    if email:
        reg['contact'] = ['mailto:' + email]
    r, _ = ac.post(ac.dir['newAccount'], reg)
    ac.kid = r.headers['Location']
    ident = {'type': 'ip' if is_ip(host) else 'dns', 'value': host}
    order_req = {'identifiers': [ident]}
    profiles = ac.dir.get('meta', {}).get('profiles', {})
    if ident['type'] == 'ip':
        if 'shortlived' not in profiles:
            raise AcmeError('this ACME server does not offer IP certificates')
        order_req['profile'] = 'shortlived'
    log('ACME: ordering a certificate for %s' % host)
    r, order = ac.post(ac.dir['newOrder'], order_req)
    order_url = r.headers['Location']
    srv = _ChallengeServer()
    try:
        for auth_url in order['authorizations']:
            _, auth = ac.post(auth_url, None)
            if auth['status'] == 'valid':
                continue
            ch = next((c for c in auth['challenges'] if c['type'] == 'http-01'), None)
            if not ch:
                raise AcmeError('no http-01 challenge offered')
            srv.tokens[ch['token']] = ch['token'] + '.' + ac.thumbprint
            ac.post(ch['url'], {})
            ac.poll(auth_url)
    finally:
        srv.close()
    with tempfile.TemporaryDirectory() as d:
        key = os.path.join(d, 'k')
        _openssl('genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256', '-out', key)
        cfg = os.path.join(d, 'c')
        with open(cfg, 'w') as f:
            f.write('[req]\ndistinguished_name=dn\nreq_extensions=ext\nprompt=no\n[dn]\nO=vps2vpn\n'
                    '[ext]\nsubjectAltName=%s\n' % _san(host))
        csr = _openssl('req', '-new', '-key', key, '-config', cfg, '-outform', 'DER')
        ac.poll(order_url, done=('ready', 'valid'))
        _, order = ac.post(order['finalize'], {'csr': secure.b64url(csr)})
        order = ac.poll(order_url)
        _, chain = ac.post(order['certificate'], None)
        if isinstance(chain, bytes):
            chain = chain.decode()
        if '-----BEGIN CERTIFICATE-----' not in chain:
            raise AcmeError('unexpected certificate response')
        paths.write_atomic(paths.ACME_KEY, _pem(key), 0o640, 'vps2vpn')
        paths.write_atomic(paths.ACME_CRT, chain.replace('\r', ''), 0o644, 'vps2vpn')
    log('ACME: certificate installed for %s' % host)
    return True


def renew_if_needed(s, log=print):
    """Called periodically. IP certificates live ~6 days, so renew when under 3 days are left."""
    host = s['domain'] or s['public_host']
    if s['cert_mode'] != 'auto' or not host:
        return None
    if trusted(host) and acme_valid(72):
        return None
    try:
        issue(host, s['acme_email'], log=log)
        return 'ok'
    except (AcmeError, OSError, RuntimeError) as e:
        log('ACME failed: %s' % e)
        return str(e)
