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


def load_clash_json(text):
    # the Clash file is JSON (valid YAML) after a few '#' comment lines with the name and date
    return json.loads(''.join(l for l in text.splitlines(True) if not l.lstrip().startswith('#')))


def free_port(used=()):
    for _ in range(50):
        with socket.socket() as s:
            s.bind(('127.0.0.1', 0))
            p = s.getsockname()[1]
        if p not in used:
            return p
    raise RuntimeError('could not allocate a unique local port')


def fetch_proxies(url, insecure=False):
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme.lower() not in ('http', 'https') or not parsed.hostname:
        raise ValueError('subscription URL must use http:// or https://')
    sep = '&' if '?' in url else '?'
    req = urllib.request.Request(url + sep + 'format=clash', headers={'User-Agent': 'clash.meta'})
    ctx = ssl._create_unverified_context() if insecure else ssl.create_default_context()
    with urllib.request.urlopen(req, timeout=20, context=ctx) as r:
        text = r.read().decode('utf-8')
    return load_clash_json(text)['proxies']


def wait_port(port, proc=None, timeout=15):
    end = time.time() + timeout
    while time.time() < end:
        if proc is not None and proc.poll() is not None:
            return False
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=1):
                return True
        except OSError:
            time.sleep(0.2)
    return False


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('subscription', nargs='?', help='your subscription link')
    ap.add_argument('--config', help='use a Clash config file instead of a link')
    ap.add_argument('--mihomo', default=shutil.which('mihomo') or shutil.which('mihomo.exe'))
    ap.add_argument('--quick', action='store_true', help='shorter tests')
    ap.add_argument('--no-direct', action='store_true', help='skip the direct (no proxy) baseline')
    ap.add_argument('--insecure', action='store_true', help='skip TLS verification when fetching a self-signed subscription')
    ap.add_argument('--json', help='also write results to this file')
    a = ap.parse_args()
    if not (a.subscription or a.config):
        ap.error('give a subscription link or --config')
    if not a.mihomo or not os.path.exists(a.mihomo):
        sys.exit('mihomo not found: download it from https://github.com/MetaCubeX/mihomo/releases and pass --mihomo')
    if a.config:
        with open(a.config, encoding='utf-8') as f:
            proxies = load_clash_json(f.read())['proxies']
    else:
        proxies = fetch_proxies(a.subscription, insecure=a.insecure)
    work = tempfile.mkdtemp(prefix='v2v-bench-')
    used = set()
    ports = {}
    for p in proxies:
        port = free_port(used)
        used.add(port)
        ports[p['name']] = port
    conf = {'mode': 'rule', 'log-level': 'warning', 'ipv6': True, 'allow-lan': False, 'proxies': proxies,
            'listeners': [{'name': 'in%d' % i, 'type': 'mixed', 'listen': '127.0.0.1', 'port': ports[p['name']],
                           'proxy': p['name']} for i, p in enumerate(proxies)],
            'rules': ['MATCH,DIRECT']}
    with open(os.path.join(work, 'config.yaml'), 'w', encoding='utf-8') as f:
        json.dump(conf, f)
    err_path = os.path.join(work, 'mihomo.err')
    err_file = open(err_path, 'w+', encoding='utf-8', errors='replace')
    proc = subprocess.Popen([a.mihomo, '-d', work], stdout=subprocess.DEVNULL, stderr=err_file)
    rows = []
    try:
        if not all(wait_port(p, proc=proc) for p in ports.values()):
            err_file.flush()
            err_file.seek(0)
            tail = '\n'.join(err_file.read().splitlines()[-20:])
            msg = 'mihomo did not start'
            if tail:
                msg += ':\n' + tail
            sys.exit(msg)
        if not a.no_direct:
            print('direct (no proxy)')
            rows.append(('direct', bench.run(None, a.quick)))
        for p in proxies:
            print(p['name'])
            rows.append((p['name'], bench.run('http://127.0.0.1:%d' % ports[p['name']], a.quick)))
    finally:
        proc.terminate()
        try:
            proc.wait(5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(5)
        err_file.close()
        shutil.rmtree(work, ignore_errors=True)
    print()
    print(bench.table(rows))
    print('\nping = median of fresh HTTPS requests through the proxy; down/up in Mbit/s.')
    if a.json:
        with open(a.json, 'w', encoding='utf-8') as f:
            json.dump({'time': time.strftime('%Y-%m-%d %H:%M'), 'results': dict(rows)}, f, indent=1, ensure_ascii=False)


if __name__ == '__main__':
    main()
