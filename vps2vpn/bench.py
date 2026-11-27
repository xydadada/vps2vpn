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
# Cloudflare rate-limits __down and refuses it from some data-centre ranges (GitHub's runners among them),
# which used to show up as "0 Mb" download. These plain test files are tried in order instead.
DOWN_FALLBACKS = ('https://proof.ovh.net/files/100Mb.dat',
                  'https://ash-speed.hetzner.com/100MB.bin',
                  'https://fsn1-speed.hetzner.com/100MB.bin')


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


class _NoMeasurementRedirect(urllib.request.HTTPRedirectHandler):
    """An explicitly chosen test endpoint must not silently measure a different one."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _opener(proxy, allow_redirects=True):
    handler = _ExplicitProxy({'http': proxy, 'https': proxy}) if proxy else urllib.request.ProxyHandler({})
    handlers = [handler] if allow_redirects else [handler, _NoMeasurementRedirect()]
    return urllib.request.build_opener(*handlers)


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


def latency(proxy=None, n=10, url=LATENCY_URL, timeout=10, errors=None, allow_redirects=True):
    """Milliseconds for n fresh HTTPS requests. Returns {median, p90, min, fails}."""
    op, ms, fails = _opener(proxy, allow_redirects), [], 0
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


def download(proxy=None, streams=1, seconds=10, size=50 << 20, timeout=15, diagnostics=None, url=DOWN_URL, errors=None,
             allow_redirects=True):
    """Mbit/s over `streams` parallel connections for `seconds` (after one second of warm-up).
    Cloudflare refuses single downloads near 100 MB, so each connection repeats 50 MB requests."""
    op = _opener(proxy, allow_redirects)
    lock, total, stop = threading.Lock(), [0], time.perf_counter() + seconds + 1
    marks, failures, retried = {}, [], [0]

    def one():
        # One refused request (a proxy's momentary 502, a reset while several streams open at once) must not
        # end the stream: it is retried twice. Only a stream that keeps failing reports an error.
        retries = 2
        while time.perf_counter() < stop:
            try:
                with op.open(urllib.request.Request(url % size if '%d' in url else url, headers=UA),
                             timeout=timeout) as r:
                    read = getattr(r, 'read1', r.read)       # read1: return whatever arrived, do not wait for 64 KB
                    while time.perf_counter() < stop:
                        b = read(65536)
                        if not b:
                            break
                        with lock:
                            total[0] += len(b)
                            if 'warm' not in marks and time.perf_counter() > stop - seconds:
                                marks['warm'] = (time.perf_counter(), total[0])
            except (OSError, http.client.HTTPException) as exc:
                if retries and time.perf_counter() < stop:
                    retries -= 1
                    with lock:
                        retried[0] += 1
                    if isinstance(exc, urllib.error.HTTPError):
                        exc.close()
                    time.sleep(0.2)
                    continue
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
        diagnostics.update(bytes=total[0], errors=failures, warmup_complete='warm' in marks, retries=retried[0])
    if 'warm' not in marks:
        return 0.0
    t0, b0 = marks['warm']
    return round((total[0] - b0) * 8 / max(0.001, end - t0) / 1e6, 1)


def upload(proxy=None, size=25 << 20, timeout=30, url=UP_URL, errors=None, allow_redirects=True):
    """Mbit/s for one upload of `size` bytes."""
    op = _opener(proxy, allow_redirects)
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


def working_download_url(proxy=None, size=50 << 20, timeout=15, candidates=None):
    """The first download source that sends data through this proxy, or None."""
    op = _opener(proxy)
    for url in candidates or (DOWN_URL,) + DOWN_FALLBACKS:
        try:
            with op.open(urllib.request.Request(url % size if '%d' in url else url, headers=UA),
                         timeout=timeout) as r:
                if getattr(r, 'read1', r.read)(65536):
                    return url
        except (OSError, ValueError, http.client.HTTPException):
            continue
    return None


def _download_source_id(url, controlled):
    if controlled:
        return 'controlled'
    known = dict(zip((DOWN_URL,) + DOWN_FALLBACKS, ('cloudflare', 'ovh', 'hetzner-ash', 'hetzner-fsn')))
    return known.get(url, 'custom')


def run(proxy=None, quick=False, log=print, origin=None):
    latency_url, down_url, up_url = measurement_urls(origin)
    if origin is None:          # public endpoints: step past a refusing Cloudflare instead of reporting 0
        picked = working_download_url(proxy)
        if picked and picked != down_url:
            log('  (Cloudflare refused the download test; using %s)' % urllib.parse.urlsplit(picked).hostname)
        down_url = picked or down_url
    errors = []
    out = {'errors': errors, 'measurement': {
        'source_policy': 'controlled-no-fallback' if origin is not None else 'public-fallback',
        'latency_source_id': 'controlled' if origin is not None else 'gstatic',
        'upload_source_id': 'controlled' if origin is not None else 'cloudflare'}}
    log('  latency…')
    out['latency'] = latency(proxy, n=5 if quick else 10, url=latency_url, errors=errors,
                             allow_redirects=origin is None)
    out['download_diagnostics'] = {}
    for streams in (1, 4):
        label = 'down_%d' % streams
        log('  download, %d connection%s…' % (streams, '' if streams == 1 else 's'))
        diagnostic, attempts = {}, []

        def attempt(url):
            info = {}
            value = download(proxy, streams, 5 if quick else 10, diagnostics=info, url=url, errors=errors,
                             allow_redirects=origin is None)
            info['source_id'] = _download_source_id(url, origin is not None)
            attempts.append(dict(info, mbps=value))
            return value, info

        out[label], diagnostic = attempt(down_url)
        if not out[label] and origin is None:
            # the source answered the probe but broke off during the test: try the next public source
            rest = (DOWN_URL,) + DOWN_FALLBACKS
            for alt in rest[rest.index(down_url) + 1:] if down_url in rest else ():
                out[label], diagnostic = attempt(alt)
                if out[label]:
                    log('  (download source switched to %s)' % urllib.parse.urlsplit(alt).hostname)
                    down_url = alt
                    break
        diagnostic['attempts'] = attempts
        out['download_diagnostics'][label] = diagnostic
        for error in dict.fromkeys(diagnostic.get('errors', [])):
            log('  download failed: ' + error)
        if not diagnostic.get('warmup_complete'):
            log('  no sustained download sample (%d bytes before warm-up completed)' % diagnostic.get('bytes', 0))
    log('  upload…')
    out['up_1'] = upload(proxy, (8 if quick else 25) << 20, url=up_url, errors=errors, allow_redirects=origin is None)
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
