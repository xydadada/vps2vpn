"""Site monitor: can this server reach the sites people care about, and how fast?

Every 5 minutes the server itself opens GitHub, YouTube, ChatGPT, Google, X and Telegram over IPv4 and
IPv6 and times each step (DNS, TCP connect, TLS, first byte). ChatGPT's trace page also reveals the region
the site sees, which tells you whether it will let your users in. A small Cloudflare download measures
the server's own bandwidth. The last 288 rounds (24 hours) are kept.
"""
import http.client
import json
import os
import socket
import ssl
import threading
import time

from . import paths

TARGETS = [
    # id, label, host, path
    ('github', 'GitHub', 'github.com', '/'),
    ('youtube', 'YouTube', 'www.youtube.com', '/generate_204'),
    ('chatgpt', 'ChatGPT', 'chatgpt.com', '/cdn-cgi/trace'),
    ('google', 'Google', 'www.google.com', '/generate_204'),
    ('x', 'X', 'x.com', '/'),
    ('telegram', 'Telegram', 'api.telegram.org', '/'),
]
SPEED_URL = ('speed.cloudflare.com', '/__down?bytes=%d')
SPEED_BYTES = 4 << 20
SPEED_EVERY = 3600
KEEP = 288
FILE = paths.VAR + '/monitor.json'
# ChatGPT refuses these regions (OpenAI's list of unsupported countries includes them)
BLOCKED_REGIONS = {'CN', 'HK', 'MO', 'RU', 'IR', 'KP', 'SY', 'CU', 'BY', 'VE'}

_lock = threading.Lock()
_run_lock = threading.Lock()
_hist = None


def _ms(t0):
    return round((time.perf_counter() - t0) * 1000, 1)


def probe(host, path, family, timeout=8):
    """One HTTPS request with per-step timings. Never raises."""
    r = {'ok': False}
    t0 = time.perf_counter()
    sock = tls = None
    try:
        infos = socket.getaddrinfo(host, 443, family, socket.SOCK_STREAM)
        r['dns'] = _ms(t0)
        addr = infos[0][4]
        r['ip'] = addr[0]
        t1 = time.perf_counter()
        with socket.create_connection(addr[:2], timeout=timeout) as sock:
            r['connect'] = _ms(t1)
            t2 = time.perf_counter()
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                r['tls'] = _ms(t2)
                t3 = time.perf_counter()
                tls.sendall(('GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: close\r\n\r\n'
                             % (path, host)).encode())
                first = tls.recv(4096)
                r['ttfb'] = _ms(t3)
                body = first
                if path.endswith('/trace'):
                    while len(body) < 16384:
                        more = tls.recv(4096)
                        if not more:
                            break
                        body += more
        line = first.split(b'\r\n', 1)[0].decode('latin-1')
        r['status'] = int(line.split()[1]) if len(line.split()) > 1 else 0
        r['ok'] = 100 <= r['status'] < 500 and r['status'] != 403
        r['total'] = _ms(t0)
        if path.endswith('/trace'):
            for kv in body.decode('latin-1').split('\n'):
                if kv.startswith('loc='):
                    r['loc'] = kv[4:].strip()
    except (OSError, ValueError, IndexError) as e:
        r['error'] = (type(e).__name__ + ': ' + str(e))[:120]
        r['total'] = _ms(t0)
    finally:
        for s_obj in (tls, sock):
            if s_obj is not None:
                try:
                    s_obj.close()
                except OSError:
                    pass
    return r


def speed(timeout=20):
    host, path = SPEED_URL
    t0 = time.perf_counter()
    got = 0
    sock = tls = None
    try:
        with socket.create_connection((host, 443), timeout=timeout) as sock:
            with ssl.create_default_context().wrap_socket(sock, server_hostname=host) as tls:
                tls.sendall(('GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: vps2vpn\r\nConnection: close\r\n\r\n'
                             % (path % SPEED_BYTES, host)).encode())
                with http.client.HTTPResponse(tls) as response:
                    response.begin()
                    if response.status != 200:
                        return {'ok': False, 'bytes': 0, 'error': 'HTTP %d' % response.status}
                    t1 = time.perf_counter()
                    while got < SPEED_BYTES:
                        remaining = timeout - (time.perf_counter() - t0)
                        if remaining <= 0:
                            break
                        tls.settimeout(remaining)
                        chunk = response.read1(min(65536, SPEED_BYTES - got))
                        if not chunk:
                            break
                        got += len(chunk)
                    dt = max(time.perf_counter() - t1, 0.001)
        return {'ok': got > SPEED_BYTES // 2, 'bytes': got, 'mbps': round(got * 8 / dt / 1e6, 1), 'at': int(time.time())}
    except (OSError, http.client.HTTPException) as e:
        return {'ok': False, 'bytes': got, 'error': str(e)[:120], 'at': int(time.time())}
    finally:
        for s_obj in (tls, sock):
            if s_obj is not None:
                try:
                    s_obj.close()
                except OSError:
                    pass


def has_ipv6():
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as s:
            s.connect(('2606:4700:4700::1111', 53))
            return not s.getsockname()[0].startswith('fe80')
    except OSError:
        return False


def _recent_speed(now):
    with _lock:
        h = _load()
        for item in reversed(h):
            sp = item.get('speed') or {}
            at = sp.get('at', item.get('at', 0))
            if sp and now - at < SPEED_EVERY:
                return sp
    return None


def run_once(force_speed=False):
    v6 = has_ipv6()
    results = {}
    threads = []

    def go(tid, host, path, fam, key):
        results[key] = probe(host, path, fam)

    for tid, label, host, path in TARGETS:
        for fam, tag in ((socket.AF_INET, '4'), (socket.AF_INET6, '6')):
            if tag == '6' and not v6:
                continue
            th = threading.Thread(target=go, args=(tid, host, path, fam, tid + '/' + tag), daemon=True)
            th.start()
            threads.append(th)
    deadline = time.monotonic() + 20
    for th in threads:
        th.join(max(0.1, deadline - time.monotonic()))
    now = int(time.time())
    sp = None if force_speed else _recent_speed(now)
    entry = {'at': now, 'v6': v6, 'sites': results, 'speed': sp or speed()}
    loc = (results.get('chatgpt/4') or {}).get('loc') or (results.get('chatgpt/6') or {}).get('loc')
    if loc:
        entry['region'] = loc
        entry['chatgpt_region_ok'] = loc.upper() not in BLOCKED_REGIONS
    _append(entry)
    return entry


def _load():
    global _hist
    if _hist is None:
        try:
            with open(FILE, encoding='utf-8') as f:
                _hist = json.load(f)[-KEEP:]
        except (OSError, ValueError):
            _hist = []
    return _hist


def _append(entry):
    with _lock:
        h = _load()
        h.append(entry)
        del h[:-KEEP]
        try:
            paths.write_atomic(FILE, json.dumps(h, separators=(',', ':')), 0o600)
        except OSError:
            pass


def history():
    with _lock:
        return list(_load())


def summary():
    """Latest round plus per-site 24 h availability and median latency, for the panel."""
    h = history()
    if not h:
        return {'latest': None, 'sites': [], 'history': []}
    last = h[-1]
    sites = []
    for tid, label, host, _ in TARGETS:
        row = {'id': tid, 'label': label, 'host': host}
        for tag in ('4', '6'):
            seq = [e['sites'].get(tid + '/' + tag) for e in h if e['sites'].get(tid + '/' + tag)]
            if not seq:
                continue
            ok = [x for x in seq if x['ok']]
            lat = sorted(x['total'] for x in ok)
            row['v' + tag] = {'now': last['sites'].get(tid + '/' + tag), 'uptime': round(len(ok) / len(seq), 4),
                              'median_ms': lat[len(lat) // 2] if lat else None,
                              'spark': [x['total'] if x['ok'] else None for x in seq[-48:]]}
        sites.append(row)
    return {'latest': {k: last.get(k) for k in ('at', 'v6', 'region', 'chatgpt_region_ok', 'speed')}, 'sites': sites,
            'speed_history': [[e['at'], (e.get('speed') or {}).get('mbps')] for e in h[-96:]]}


def run_in_background(log=print):
    if not _run_lock.acquire(blocking=False):
        return

    def go():
        try:
            e = run_once()
            down = [k for k, v in e['sites'].items() if not v['ok'] and k.endswith('/4')]
            if down:
                log('monitor: cannot reach %s' % ', '.join(k.split('/')[0] for k in down))
        except Exception as ex:          # never take the scheduler down
            log('monitor error: %r' % ex)
        finally:
            _run_lock.release()
    try:
        threading.Thread(target=go, daemon=True, name='monitor').start()
    except Exception:
        _run_lock.release()
        raise


if __name__ == '__main__':
    print(json.dumps(run_once(), indent=1))
