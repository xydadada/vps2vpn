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
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
from vps2vpn import bench  # noqa: E402


def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def fetch_proxies(url, ca_cert=None):
    sep = '&' if '?' in url else '?'
    req = urllib.request.Request(url + sep + 'format=clash', headers={'User-Agent': 'clash.meta'})
    # Subscriptions contain credentials. A private CA/fallback certificate must be obtained separately.
    ctx = ssl.create_default_context(cafile=ca_cert)
    with urllib.request.urlopen(req, timeout=20, context=ctx) as r:
        text = r.read().decode('utf-8')
    # the Clash file is JSON (valid YAML) after a few '#' comment lines with the name and date
    conf = json.loads(''.join(l for l in text.splitlines(True) if not l.lstrip().startswith('#')))
    return conf['proxies']


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
    ap.add_argument('--ca-cert', help='PEM CA/certificate obtained through a trusted channel for HTTPS')
    ap.add_argument('--mihomo', default=shutil.which('mihomo') or shutil.which('mihomo.exe'))
    ap.add_argument('--quick', action='store_true', help='shorter tests')
    ap.add_argument('--no-direct', action='store_true', help='skip the direct (no proxy) baseline')
    ap.add_argument('--json', help='also write results to this file')
    a = ap.parse_args()
    if not (a.subscription or a.config):
        ap.error('give a subscription link or --config')
    if not a.mihomo or not os.path.exists(a.mihomo):
        sys.exit('mihomo not found: download it from https://github.com/MetaCubeX/mihomo/releases and pass --mihomo')
    if a.config:
        with open(a.config, encoding='utf-8') as f:
            proxies = json.load(f)['proxies']
    else:
        proxies = fetch_proxies(a.subscription, a.ca_cert)
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
            proc.wait()
        shutil.rmtree(work, ignore_errors=True)
    print()
    print(bench.table(rows))
    print('\nping = median of fresh HTTPS requests through the proxy; down/up in Mbit/s.')
    if a.json:
        with open(a.json, 'w', encoding='utf-8') as f:
            json.dump({'time': time.strftime('%Y-%m-%d %H:%M'), 'results': dict(rows)}, f, indent=1, ensure_ascii=False)


if __name__ == '__main__':
    main()
