"""Measure your vps2vpn server from your own computer, protocol by protocol, next to a direct baseline.

    python tools/bench.py https://<server>:<port>/s/<token> [--mihomo path/to/mihomo] [--quick] [--json out.json]

It downloads your subscription, starts a private mihomo (Clash Meta core) with one local port per protocol,
and measures latency (fresh HTTPS handshakes), download with 1 and 4 connections, and upload.
Nothing on your computer's proxy settings is touched; mihomo only listens on 127.0.0.1 while the test runs.
"""
import argparse
import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
from vps2vpn import bench  # noqa: E402


def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


MAX_SUBSCRIPTION_BYTES = 8 * 1024 * 1024


def subscription_url(url, insecure=False):
    """Validate before opening: only explicit HTTP opt-in may send a bearer token in plaintext."""
    if not isinstance(url, str) or not url or len(url) > 8192:
        raise ValueError('invalid subscription URL')
    if any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in url):
        raise ValueError('subscription URL contains whitespace or control characters')
    try:
        parsed = urllib.parse.urlsplit(url)
        port = parsed.port
    except ValueError as exc:
        raise ValueError('invalid subscription URL') from exc
    if (parsed.scheme not in ('http', 'https') or not parsed.hostname
            or parsed.username is not None or parsed.password is not None or parsed.fragment
            or (port is not None and not 1 <= port <= 65535)):
        raise ValueError('expected an HTTP(S) subscription URL without userinfo or a fragment')
    if parsed.scheme != 'https' and not insecure:
        raise ValueError('HTTP subscriptions expose credentials; use HTTPS or explicitly pass --insecure')
    return parsed


def _origin(parsed):
    return parsed.scheme, parsed.hostname.lower(), parsed.port or (443 if parsed.scheme == 'https' else 80)


class _SubscriptionRedirect(urllib.request.HTTPRedirectHandler):
    def __init__(self, origin, insecure):
        self.origin, self.insecure = origin, insecure

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = subscription_url(newurl, self.insecure)
        if _origin(parsed) != self.origin:
            raise ValueError('subscription redirects must stay on the original origin')
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def parse_proxies(raw):
    if len(raw) > MAX_SUBSCRIPTION_BYTES:
        raise ValueError('subscription exceeds the 8 MiB limit')
    # The server returns JSON (valid YAML), optionally prefixed by comment lines.
    content = raw.decode('utf-8')
    conf = json.loads(''.join(line for line in content.splitlines(True) if not line.lstrip().startswith('#')))
    proxies = conf.get('proxies') if isinstance(conf, dict) else None
    if not isinstance(proxies, list) or not proxies:
        raise ValueError('subscription must contain a nonempty proxies list')
    names = set()
    for proxy in proxies:
        name = proxy.get('name') if isinstance(proxy, dict) else None
        if not isinstance(name, str) or not name.strip() or name in names:
            raise ValueError('each proxy needs a unique nonempty name')
        names.add(name)
    return proxies


def fetch_proxies(url, insecure=False, ca_file=None):
    parsed = subscription_url(url, insecure)
    if insecure and ca_file:
        raise ValueError('--insecure and --ca-file are mutually exclusive')
    query = [(key, value) for key, value in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
             if key != 'format']
    query.append(('format', 'clash'))
    url = urllib.parse.urlunsplit(parsed._replace(query=urllib.parse.urlencode(query)))
    req = urllib.request.Request(url, headers={'User-Agent': 'clash.meta'})
    # Subscriptions contain reusable node credentials. Authenticate their TLS endpoint by default.
    ctx = ssl.create_default_context(cafile=ca_file)
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx),
                                        _SubscriptionRedirect(_origin(parsed), insecure))
    with opener.open(req, timeout=20) as response:
        raw = response.read(MAX_SUBSCRIPTION_BYTES + 1)
    return parse_proxies(raw)


def wait_port(port, timeout=15):
    end = time.time() + timeout
    while time.time() < end:
        try:
            socket.create_connection(('127.0.0.1', port), timeout=1).close()
            return True
        except OSError:
            time.sleep(0.2)
    return False


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('subscription', nargs='?', help='your subscription link')
    ap.add_argument('--config', help='use a Clash config file instead of a link')
    tls = ap.add_mutually_exclusive_group()
    tls.add_argument('--insecure', action='store_true', help='explicitly allow unverified HTTPS or plaintext HTTP subscriptions')
    tls.add_argument('--ca-file', help='PEM CA certificate for a private subscription server')
    ap.add_argument('--mihomo', default=shutil.which('mihomo') or shutil.which('mihomo.exe'))
    ap.add_argument('--quick', action='store_true', help='shorter tests')
    ap.add_argument('--origin', help='optional controlled measurement HTTP(S) origin; serves /generate_204, /__down and /__up')
    ap.add_argument('--no-direct', action='store_true', help='skip the direct (no proxy) baseline')
    ap.add_argument('--json', help='also write results to this file')
    a = ap.parse_args()
    if not (a.subscription or a.config):
        ap.error('give a subscription link or --config')
    if not a.mihomo or not os.path.exists(a.mihomo):
        sys.exit('mihomo not found: download it from https://github.com/MetaCubeX/mihomo/releases and pass --mihomo')
    if a.config:
        with open(a.config, 'rb') as f:
            proxies = parse_proxies(f.read(MAX_SUBSCRIPTION_BYTES + 1))
    else:
        proxies = fetch_proxies(a.subscription, insecure=a.insecure, ca_file=a.ca_file)
    bench.measurement_urls(a.origin)  # Validate before starting a core or sending measurement traffic.
    work = tempfile.mkdtemp(prefix='v2v-bench-')
    ports = {p['name']: free_port() for p in proxies}
    conf = {'mode': 'rule', 'log-level': 'warning', 'ipv6': True, 'allow-lan': False, 'proxies': proxies,
            'listeners': [{'name': 'in%d' % i, 'type': 'mixed', 'listen': '127.0.0.1', 'port': ports[p['name']],
                           'proxy': p['name']} for i, p in enumerate(proxies)],
            'rules': ['MATCH,DIRECT']}
    with open(os.path.join(work, 'config.yaml'), 'w', encoding='utf-8') as f:
        json.dump(conf, f)
    proc = subprocess.Popen([a.mihomo, '-d', work], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    rows = []
    try:
        if not all(wait_port(p) for p in ports.values()):
            sys.exit('mihomo did not start; run it by hand with -d %s to see why' % work)
        if not a.no_direct:
            print('direct (no proxy)')
            rows.append(('direct', bench.run(None, a.quick, origin=a.origin)))
        for p in proxies:
            print(p['name'])
            rows.append((p['name'], bench.run('http://127.0.0.1:%d' % ports[p['name']], a.quick, origin=a.origin)))
    finally:
        proc.terminate()
        try:
            proc.wait(5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        shutil.rmtree(work, ignore_errors=True)
    print()
    print(bench.table(rows))
    print('\nping = median of fresh HTTPS requests through the proxy; down/up in Mbit/s.')
    if a.json:
        with open(a.json, 'w', encoding='utf-8') as f:
            json.dump({'time': time.strftime('%Y-%m-%d %H:%M'), 'results': dict(rows)}, f, indent=1, ensure_ascii=False)

    failed = [label for label, result in rows if result['latency']['median'] is None
              or any(result[key] <= 0 for key in ('down_1', 'down_4', 'up_1'))
              or any(value.get('errors') for value in result.get('download_diagnostics', {}).values())]
    if failed:
        print('incomplete measurements: ' + ', '.join(failed), file=sys.stderr)
        raise SystemExit(1)


if __name__ == '__main__':
    main()
