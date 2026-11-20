"""Speed measurements shared by `vps2vpn bench` (on the server) and tools/bench.py (on your computer).

By default, measurements use public test endpoints over HTTPS:
  latency   https://www.gstatic.com/generate_204   (new connection every time, so it includes the whole handshake)
  download  https://speed.cloudflare.com/__down?bytes=N
  upload    https://speed.cloudflare.com/__up
`origin` can select an explicitly requested HTTP(S) test fixture instead of those defaults.
`proxy` is an http://host:port proxy (mihomo's mixed port) or None for a direct measurement.
"""
import base64
import http.client
import os
import statistics
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

LATENCY_URL = 'https://www.gstatic.com/generate_204'
DOWN_URL = 'https://speed.cloudflare.com/__down?bytes=%d'
UP_URL = 'https://speed.cloudflare.com/__up'
UA = {'User-Agent': 'vps2vpn-bench'}


class _ExplicitProxy(urllib.request.ProxyHandler):
    """A requested measurement proxy must not be silently bypassed by NO_PROXY."""
    def proxy_open(self, req, proxy, protocol):
        parsed = urllib.parse.urlsplit(proxy)
        if parsed.scheme != 'http' or not parsed.hostname or parsed.query or parsed.fragment or parsed.path not in ('', '/'):
            raise ValueError('measurement proxy must be an HTTP proxy URL')
        port = parsed.port or 80
        if not 1 <= port <= 65535:
            raise ValueError('invalid measurement proxy port')
        host = '[%s]' % parsed.hostname if ':' in parsed.hostname else parsed.hostname
        if parsed.username is not None:
            credentials = '%s:%s' % (urllib.parse.unquote(parsed.username), urllib.parse.unquote(parsed.password or ''))
            req.add_header('Proxy-Authorization', 'Basic ' + base64.b64encode(credentials.encode()).decode())
        req.set_proxy('%s:%d' % (host, port), 'http')
        return None


def _opener(proxy):
    handler = _ExplicitProxy({'http': proxy, 'https': proxy}) if proxy else urllib.request.ProxyHandler({})
    return urllib.request.build_opener(handler)


def measurement_urls(origin=None):
    if origin is None:
        return LATENCY_URL, DOWN_URL, UP_URL
    if not isinstance(origin, str) or any(c.isspace() or ord(c) < 32 for c in origin):
        raise ValueError('invalid measurement origin')
    parsed = urllib.parse.urlsplit(origin)
    if (parsed.scheme not in ('http', 'https') or not parsed.hostname or parsed.username is not None
            or parsed.password is not None or parsed.query or parsed.fragment or parsed.path not in ('', '/')
            or (parsed.port is not None and not 1 <= parsed.port <= 65535)):
        raise ValueError('measurement origin must be an HTTP(S) origin without credentials, path, query or fragment')
    base = urllib.parse.urlunsplit(parsed._replace(path=''))
    return base + '/generate_204', base + '/__down?bytes=%d', base + '/__up'


def _record_error(errors, phase, error):
    """Keep actionable transport/status information without copying URLs, credentials or response bodies."""
    if errors is None:
        return
    if isinstance(error, urllib.error.HTTPError):
        detail = 'HTTP %d' % error.code
        retry = error.headers.get('Retry-After', '') if error.headers else ''
        if retry:
            detail += '; Retry-After=' + (retry[:12] + 's' if retry.isascii() and retry.isdecimal() else 'present')
        error.close()
    else:
        reason = error.reason if isinstance(error, urllib.error.URLError) else error
        detail = type(reason).__name__ if not isinstance(reason, str) else type(error).__name__
        errno = getattr(reason, 'errno', None)
        if errno is not None:
            detail += ' (errno %s)' % errno
        ssl_reason = getattr(reason, 'reason', '')
        if isinstance(ssl_reason, str) and ssl_reason.replace('_', '').isalnum():
            detail += ': ' + ssl_reason[:80]
    message = phase + ': ' + detail
    if message not in errors:
        errors.append(message)


def latency(proxy=None, n=10, url=LATENCY_URL, timeout=10, errors=None):
    """Milliseconds for n fresh HTTPS requests. Returns {median, p90, min, fails}."""
    op, ms, fails = _opener(proxy), [], 0
    for _ in range(n):
        t0 = time.perf_counter()
        try:
            with op.open(urllib.request.Request(url, headers=UA), timeout=timeout) as r:
                r.read()
            ms.append((time.perf_counter() - t0) * 1000)
        except (OSError, http.client.HTTPException) as error:
            fails += 1
            _record_error(errors, 'latency', error)
    if not ms:
        return {'median': None, 'p90': None, 'min': None, 'fails': fails}
    ms.sort()
    return {'median': round(statistics.median(ms)), 'p90': round(ms[min(len(ms) - 1, int(len(ms) * 0.9))]),
            'min': round(ms[0]), 'fails': fails}


def download(proxy=None, streams=1, seconds=10, size=50 << 20, timeout=15, diagnostics=None, url=DOWN_URL, errors=None):
    """Mbit/s over `streams` parallel connections for `seconds` (after one second of warm-up).
    Cloudflare refuses single downloads near 100 MB, so each connection repeats 50 MB requests."""
    op = _opener(proxy)
    lock, total, stop = threading.Lock(), [0], time.perf_counter() + seconds + 1
    marks, failures = {}, []

    def one():
        while time.perf_counter() < stop:
            try:
                with op.open(urllib.request.Request(url % size, headers=UA), timeout=timeout) as r:
                    read = getattr(r, 'read1', r.read)       # read1: return whatever arrived, do not wait for 64 KB
                    while time.perf_counter() < stop:
                        b = read(65536)
                        if not b:
                            break
                        now = time.perf_counter()
                        with lock:
                            total[0] += len(b)
                            if 'warm' not in marks and now > stop - seconds:
                                marks['warm'] = (now, total[0])
                            marks['last'] = (now, total[0])
            except (OSError, http.client.HTTPException) as exc:
                with lock:
                    _record_error(failures, 'download %dx' % streams, exc)
                return

    ts = [threading.Thread(target=one, daemon=True) for _ in range(streams)]
    for t in ts:
        t.start()
    for t in ts:
        t.join(seconds + timeout + 5)
    end = time.perf_counter()
    if errors is not None:
        errors.extend(message for message in failures if message not in errors)
    if diagnostics is not None:
        diagnostics.update(bytes=total[0], errors=failures, warmup_complete='warm' in marks)
    if 'warm' not in marks:
        return 0.0
    t0, b0 = marks['warm']
    end, b1 = marks.get('last', (time.perf_counter(), total[0]))
    return round(max(0, b1 - b0) * 8 / max(0.001, end - t0) / 1e6, 1)


def upload(proxy=None, size=25 << 20, timeout=30, url=UP_URL, errors=None):
    """Mbit/s for one upload of `size` bytes."""
    op = _opener(proxy)
    block = os.urandom(min(size, 1 << 20))
    data = block * (size // len(block)) + block[:size % len(block)] if block else b''
    t0 = time.perf_counter()
    try:
        req = urllib.request.Request(url, data=data, headers=dict(UA, **{'Content-Type': 'application/octet-stream'}))
        with op.open(req, timeout=timeout) as r:
            r.read()
    except (OSError, http.client.HTTPException) as error:
        _record_error(errors, 'upload', error)
        return 0.0
    return round(len(data) * 8 / (time.perf_counter() - t0) / 1e6, 1)


def run(proxy=None, quick=False, log=print, origin=None):
    latency_url, down_url, up_url = measurement_urls(origin)
    errors = []
    out = {'errors': errors}
    log('  latency…')
    out['latency'] = latency(proxy, n=5 if quick else 10, url=latency_url, errors=errors)
    out['download_diagnostics'] = {}
    for streams in (1, 4):
        label = 'down_%d' % streams
        log('  download, %d connection%s…' % (streams, '' if streams == 1 else 's'))
        diagnostic = {}
        out[label] = download(proxy, streams, 5 if quick else 10, diagnostics=diagnostic, url=down_url, errors=errors)
        out['download_diagnostics'][label] = diagnostic
        for error in dict.fromkeys(diagnostic.get('errors', [])):
            log('  download failed: ' + error)
        if not diagnostic.get('warmup_complete'):
            log('  no sustained download sample (%d bytes before warm-up completed)' % diagnostic.get('bytes', 0))
    log('  upload…')
    out['up_1'] = upload(proxy, (8 if quick else 25) << 20, url=up_url, errors=errors)
    return out


def server_info():
    info = {'cpus': os.cpu_count()}
    try:
        with open('/proc/cpuinfo') as f:
            info['aes'] = ' aes ' in f.read().replace('\n', ' ')
    except OSError:
        pass
    return info


def table(rows):
    """rows: [(label, result)] -> plain text table."""
    head = '%-26s %9s %9s %11s %11s %9s' % ('', 'ping ms', 'p90 ms', 'down 1x', 'down 4x', 'up')
    lines = [head, '-' * len(head)]
    for label, r in rows:
        la = r['latency']
        lines.append('%-26s %9s %9s %8s Mb %8s Mb %6s Mb' % (
            label[:26], la['median'] if la['median'] is not None else 'fail', la['p90'] if la['p90'] is not None else '-',
            r['down_1'], r['down_4'], r['up_1']))
        lines.extend('  ! ' + error for error in r.get('errors', []))
    return '\n'.join(lines)
