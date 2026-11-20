"""Speed measurements shared by `vps2vpn bench` (on the server) and tools/bench.py (on your computer).

Everything goes to public test endpoints over HTTPS:
  latency   https://www.gstatic.com/generate_204   (new connection every time, so it includes the whole handshake)
  download  https://speed.cloudflare.com/__down?bytes=N
  upload    https://speed.cloudflare.com/__up
`proxy` is an http://host:port proxy (mihomo's mixed port) or None for a direct measurement.
"""
import http.client
import os
import statistics
import threading
import time
import urllib.error
import urllib.request

LATENCY_URL = 'https://www.gstatic.com/generate_204'
DOWN_URL = 'https://speed.cloudflare.com/__down?bytes=%d'
UP_URL = 'https://speed.cloudflare.com/__up'
UA = {'User-Agent': 'vps2vpn-bench'}


def _opener(proxy):
    if proxy:
        return urllib.request.build_opener(urllib.request.ProxyHandler({'http': proxy, 'https': proxy}))
    return urllib.request.build_opener(urllib.request.ProxyHandler({}))


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


def download(proxy=None, streams=1, seconds=10, size=50 << 20, timeout=15, errors=None):
    """Mbit/s over `streams` parallel connections for `seconds` (after one second of warm-up).
    Cloudflare refuses single downloads near 100 MB, so each connection repeats 50 MB requests."""
    op = _opener(proxy)
    lock, total, stop = threading.Lock(), [0], time.perf_counter() + seconds + 1
    marks = {}

    def one():
        while time.perf_counter() < stop:
            try:
                with op.open(urllib.request.Request(DOWN_URL % size, headers=UA), timeout=timeout) as r:
                    read = getattr(r, 'read1', r.read)       # read1: return whatever arrived, do not wait for 64 KB
                    while time.perf_counter() < stop:
                        b = read(65536)
                        if not b:
                            break
                        with lock:
                            total[0] += len(b)
                            if 'warm' not in marks and time.perf_counter() > stop - seconds:
                                marks['warm'] = (time.perf_counter(), total[0])
            except (OSError, http.client.HTTPException) as error:
                with lock:
                    _record_error(errors, 'download %dx' % streams, error)
                return

    ts = [threading.Thread(target=one, daemon=True) for _ in range(streams)]
    for t in ts:
        t.start()
    for t in ts:
        t.join(seconds + timeout + 5)
    end = time.perf_counter()
    if 'warm' not in marks:
        return 0.0
    t0, b0 = marks['warm']
    return round((total[0] - b0) * 8 / max(0.001, end - t0) / 1e6, 1)


def upload(proxy=None, size=25 << 20, timeout=30, errors=None):
    """Mbit/s for one upload of `size` bytes."""
    op = _opener(proxy)
    data = os.urandom(1 << 20) * (size >> 20)
    t0 = time.perf_counter()
    try:
        req = urllib.request.Request(UP_URL, data=data, headers=dict(UA, **{'Content-Type': 'application/octet-stream'}))
        with op.open(req, timeout=timeout) as r:
            r.read()
    except (OSError, http.client.HTTPException) as error:
        _record_error(errors, 'upload', error)
        return 0.0
    return round(len(data) * 8 / (time.perf_counter() - t0) / 1e6, 1)


def run(proxy=None, quick=False, log=print):
    errors = []
    out = {'errors': errors}
    log('  latency…')
    out['latency'] = latency(proxy, n=5 if quick else 10, errors=errors)
    log('  download, 1 connection…')
    out['down_1'] = download(proxy, 1, 5 if quick else 10, errors=errors)
    log('  download, 4 connections…')
    out['down_4'] = download(proxy, 4, 5 if quick else 10, errors=errors)
    log('  upload…')
    out['up_1'] = upload(proxy, (8 if quick else 25) << 20, errors=errors)
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
