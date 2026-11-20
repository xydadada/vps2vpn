"""End-to-end check with the real programs on one machine (no root, no VPS needed).

    python tests/e2e_local.py <dir with xray, hysteria, mihomo, sing-box binaries>

1. render the server configs and let Xray validate its own (`xray run -test`)
2. start Xray, Hysteria and sing-box (TUIC) servers on 127.0.0.1
3. render the Clash and sing-box subscriptions, validate them (`mihomo -t`, `sing-box check`)
4. send real traffic through each protocol with each client, and count it in the panel's stats
"""
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request

ROOT = tempfile.mkdtemp(prefix='v2v-e2e-')
HERE = os.path.dirname(os.path.abspath(__file__))
os.environ['VPS2VPN_ROOT'] = ROOT
os.environ['VPS2VPN_DEV'] = '1'
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from vps2vpn import abuse, certs, cores, db, monitor, paths, rules, subscription  # noqa: E402

BIN = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else '.')
EXE = '.exe' if os.name == 'nt' else ''


def find(name):
    for dp, _, files in os.walk(BIN):
        for f in files:
            if f.lower().startswith(name) and f.lower().endswith(EXE or f.lower()[-0:]) and not f.endswith('.zip'):
                return os.path.join(dp, f)
    sys.exit('missing binary: ' + name)


XRAY = os.environ.get('V2V_XRAY') or find('xray')
HY, MIHOMO, SINGBOX = find('hysteria'), find('mihomo'), find('sing-box')
ASSETS = next(dp for dp, _, files in os.walk(BIN) if 'geoip.dat' in files)
TARGET = 'http://www.baidu.com/'          # any site reachable from this machine
procs = []
results = []


def free_port(udp=False):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM if udp else socket.SOCK_STREAM)
    s.bind(('127.0.0.1', 0))
    p = s.getsockname()[1]
    s.close()
    return p


def start(cmd, name, env=None):
    log = open(os.path.join(ROOT, name + '.log'), 'w')
    p = subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT, env=dict(os.environ, **(env or {})), cwd=ROOT)
    procs.append(p)
    return p


def wait_port(port, timeout=15):
    end = time.time() + timeout
    while time.time() < end:
        try:
            socket.create_connection(('127.0.0.1', port), timeout=1).close()
            return True
        except OSError:
            time.sleep(0.2)
    return False


def fetch_via(port):
    proxy = urllib.request.ProxyHandler({'http': 'http://127.0.0.1:%d' % port, 'https': 'http://127.0.0.1:%d' % port})
    opener = urllib.request.build_opener(proxy)
    t0 = time.time()
    body = opener.open(TARGET, timeout=20).read()
    return len(body), int((time.time() - t0) * 1000)


def check(name, ok, detail=''):
    results.append((name, ok, detail))
    print(('PASS ' if ok else 'FAIL ') + name + ('  ' + detail if detail else ''), flush=True)


def tail(name, n=8):
    try:
        return ' | '.join(open(os.path.join(ROOT, name + '.log'), errors='replace').read().strip().splitlines()[-n:])
    except OSError:
        return ''


def main():
    db.ensure_secrets()
    port = free_port()
    db.set_settings(public_host='127.0.0.1', reality_port=port, hy2_port=port, hy2_hop=False, reality_target=os.environ.get('V2V_E2E_TARGET', 'www.taobao.com'),  # must be reachable from this machine
                   
                    traffic_api_port=free_port(), hy2_stats_port=free_port(), panel_port=free_port(), setup_done=True,
                    tuic_port=free_port(udp=True), tuic_api_port=free_port())
    certs.ensure_self_signed('127.0.0.1')
    uid = db.add_user('tester')
    s, u = db.settings(), db.user(uid)

    # --- server configs
    xc = cores.xray_config(s, [u])
    hc = cores.hysteria_config(s, [u])
    tc = cores.tuic_config(s, [u])
    hc['acl']['geoip'] = os.path.join(ASSETS, 'geoip.dat')
    xc['log'] = {'loglevel': 'debug'}
    with open(paths.XRAY_CONFIG, 'w') as f:
        json.dump(xc, f)
    with open(paths.HY2_CONFIG, 'w') as f:
        json.dump(hc, f)
    with open(paths.TUIC_CONFIG, 'w') as f:
        json.dump(tc, f)
    r = subprocess.run([SINGBOX, 'check', '-c', paths.TUIC_CONFIG], capture_output=True, text=True)
    check('sing-box accepts the TUIC server config', r.returncode == 0, (r.stdout + r.stderr).strip()[-160:])
    env = {'XRAY_LOCATION_ASSET': ASSETS}
    r = subprocess.run([XRAY, 'run', '-test', '-c', paths.XRAY_CONFIG], capture_output=True, text=True, env=dict(os.environ, **env))
    check('xray accepts the server config', r.returncode == 0, (r.stdout + r.stderr).strip().splitlines()[-1][:160])
    # the scratch file the panel validates before replacing a live config (its name must stay readable by Xray)
    test = cores.check_path(paths.XRAY_CONFIG)
    shutil.copy(paths.XRAY_CONFIG, test)
    r = subprocess.run([XRAY, 'run', '-test', '-c', test], capture_output=True, text=True, env=dict(os.environ, **env))
    os.unlink(test)
    check('xray accepts the pre-apply check file', r.returncode == 0, (r.stdout + r.stderr).strip().splitlines()[-1][:160])
    test = cores.check_path(paths.TUIC_CONFIG)
    shutil.copy(paths.TUIC_CONFIG, test)
    r = subprocess.run([SINGBOX, 'check', '-c', test], capture_output=True, text=True)
    os.unlink(test)
    check('sing-box accepts the pre-apply check file', r.returncode == 0, (r.stdout + r.stderr).strip()[-160:])
    r = subprocess.run([XRAY, 'x25519', '-i', s['reality_private_key']], capture_output=True, text=True)
    check('REALITY public key matches xray x25519', s['reality_public_key'] in r.stdout, 'derived from the stored private key')
    start([XRAY, 'run', '-c', paths.XRAY_CONFIG], 'xray', env)
    start([HY, 'server', '-c', paths.HY2_CONFIG, '--disable-update-check'], 'hysteria')
    check('xray server listening', wait_port(port), tail('xray', 3))
    time.sleep(1.5)
    check('hysteria server running', procs[-1].poll() is None, tail('hysteria', 3))
    start([SINGBOX, 'run', '-c', paths.TUIC_CONFIG], 'tuic')
    check('TUIC server (sing-box) running', wait_port(s['tuic_api_port']) and procs[-1].poll() is None, tail('tuic', 3))
    cores._tuic.sample(s)          # baseline: the TUIC meter counts from its first reading

    base = 'http://127.0.0.1:%d' % s['panel_port']
    # --- full subscriptions must pass the clients' own validators
    clash = subscription.clash(s, u, base)
    sb = subscription.singbox(s, u, base)
    cdir = os.path.join(ROOT, 'mihomo')
    os.makedirs(cdir)
    with open(os.path.join(cdir, 'full.yaml'), 'w', encoding='utf-8') as f:
        f.write(subscription.clash_yaml(s, u, base))
    r = subprocess.run([MIHOMO, '-t', '-d', cdir, '-f', os.path.join(cdir, 'full.yaml')], capture_output=True, text=True, timeout=120)
    check('mihomo -t accepts the full Clash subscription', r.returncode == 0, (r.stdout + r.stderr).strip().splitlines()[-1][:200])
    hop = dict(s, hy2_hop=True)
    with open(os.path.join(cdir, 'hop.yaml'), 'w', encoding='utf-8') as f:
        f.write(subscription.clash_yaml(hop, u, base))
    r = subprocess.run([MIHOMO, '-t', '-d', cdir, '-f', os.path.join(cdir, 'hop.yaml')], capture_output=True, text=True, timeout=120)
    check('mihomo -t accepts port hopping + obfs-free config', r.returncode == 0, (r.stdout + r.stderr).strip().splitlines()[-1][:200])
    sbf = os.path.join(ROOT, 'singbox-full.json')
    with open(sbf, 'w', encoding='utf-8') as f:
        json.dump(sb, f, ensure_ascii=False)
    r = subprocess.run([SINGBOX, 'check', '-c', sbf], capture_output=True, text=True, timeout=60)
    check('sing-box check accepts the full sing-box subscription', r.returncode == 0, (r.stdout + r.stderr).strip()[-200:])
    sbh = os.path.join(ROOT, 'singbox-hop.json')
    with open(sbh, 'w', encoding='utf-8') as f:
        json.dump(subscription.singbox(dict(s, hy2_hop=True, hy2_obfs='testobfs'), u, base), f)
    r = subprocess.run([SINGBOX, 'check', '-c', sbh], capture_output=True, text=True, timeout=60)
    check('sing-box check accepts hopping + salamander', r.returncode == 0, (r.stdout + r.stderr).strip()[-200:])

    # --- real traffic: each protocol through each client
    for p in clash['proxies']:
        mport = free_port()
        conf = {'mixed-port': mport, 'mode': 'rule', 'log-level': 'warning', 'ipv6': False,
                'proxies': [p], 'proxy-groups': [], 'rules': ['MATCH,%s' % p['name']]}
        d = os.path.join(ROOT, 'm-' + p['type'])
        os.makedirs(d)
        with open(os.path.join(d, 'config.yaml'), 'w', encoding='utf-8') as f:
            json.dump(conf, f, ensure_ascii=False)
        pr = start([MIHOMO, '-d', d], 'mihomo-' + p['type'])
        wait_port(mport)
        try:
            n, ms = fetch_via(mport)
            check('mihomo -> %s -> internet' % p['type'], n > 100, '%d bytes in %d ms' % (n, ms))
        except Exception as e:
            check('mihomo -> %s -> internet' % p['type'], False, '%s | %s' % (e, tail('mihomo-' + p['type'], 4)))
        pr.terminate()
    for o in [x for x in sb['outbounds'] if x['type'] in ('vless', 'hysteria2', 'tuic')]:
        sport = free_port()
        conf = {'log': {'level': 'warn'}, 'inbounds': [{'type': 'mixed', 'listen': '127.0.0.1', 'listen_port': sport}],
                'outbounds': [o, {'type': 'direct', 'tag': 'direct'}], 'route': {'final': o['tag']}}
        f = os.path.join(ROOT, 'sb-%s.json' % o['type'])
        with open(f, 'w', encoding='utf-8') as fh:
            json.dump(conf, fh, ensure_ascii=False)
        pr = start([SINGBOX, 'run', '-c', f], 'singbox-' + o['type'])
        wait_port(sport)
        try:
            n, ms = fetch_via(sport)
            check('sing-box -> %s -> internet' % o['type'], n > 100, '%d bytes in %d ms' % (n, ms))
        except Exception as e:
            check('sing-box -> %s -> internet' % o['type'], False, '%s | %s' % (e, tail('singbox-' + o['type'], 4)))
        pr.terminate()

    # --- traffic accounting from both cores
    paths.XRAY_BIN = XRAY
    cores.paths.XRAY_BIN = XRAY
    got = cores.collect_traffic(s)
    up, down = got.get(uid, (0, 0))
    check('per-user traffic counted (xray api + hysteria stats + TUIC meter)', down > 1000, 'up %d B, down %d B' % (up, down))
    # TUIC alone, on a fresh meter: a short connection that opens and closes between two readings
    m = cores.TuicMeter()
    m.collect(s)
    pr = start([SINGBOX, 'run', '-c', os.path.join(ROOT, 'sb-tuic.json')], 'singbox-tuic2')
    wait_port(json.load(open(os.path.join(ROOT, 'sb-tuic.json')))['inbounds'][0]['listen_port'])
    n, _ = fetch_via(json.load(open(os.path.join(ROOT, 'sb-tuic.json')))['inbounds'][0]['listen_port'])
    pr.terminate()
    tu, td = m.collect(s, users={uid}).get(uid, (0, 0))
    check('TUIC traffic attributed to the right user', td >= n * 0.9, 'fetched %d B, counted down %d B, up %d B' % (n, td, tu))

    # --- who is online, from the cores themselves: hold one tunnel open through each protocol
    held, clients = [], []
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    probe.connect(('192.0.2.1', 9))               # no packet sent: just picks this machine's LAN address
    lan = probe.getsockname()[0]
    probe.close()
    for kind in ('vless', 'hysteria2', 'tuic'):
        cf = json.load(open(os.path.join(ROOT, 'sb-%s.json' % kind)))
        if kind == 'vless':                       # Xray leaves 127.0.0.1 out of its online list on purpose
            cf['outbounds'][0]['server'] = lan
        cport = free_port()
        cf['inbounds'][0]['listen_port'] = cport
        with open(os.path.join(ROOT, 'hold-%s.json' % kind), 'w', encoding='utf-8') as fh:
            json.dump(cf, fh)
        clients.append(start([SINGBOX, 'run', '-c', os.path.join(ROOT, 'hold-%s.json' % kind)], 'hold-' + kind))
        wait_port(cport)
        host = urllib.parse.urlsplit(TARGET).hostname
        sk = socket.create_connection(('127.0.0.1', cport), timeout=10)
        sk.sendall(('CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\n\r\n' % (host, host)).encode())
        sk.recv(256)
        held.append(sk)
    time.sleep(1.5)
    on = cores.online_detail(s, max_age=0) or {}
    mine = on.get(uid, {})
    check('online users from Xray + Hysteria + TUIC', set(mine.get('protocols', [])) == {'reality', 'hy2', 'tuic'},
          json.dumps(mine))
    check('client addresses (devices) reported', lan in mine.get('ips', []) and '127.0.0.1' in mine.get('ips', []), str(mine.get('ips')))
    rep = abuse.scan(s)
    a = rep.get(uid, {})
    check('abuse watch reads Hysteria streams + TUIC connections', a.get('streams', 0) >= 2 and a.get('flags') == [],
          'streams %s, targets %s, coverage %s' % (a.get('streams'), a.get('targets'), abuse._last['coverage']))
    for sk in held:
        sk.close()
    for pr in clients:
        pr.terminate()

    # --- Shadowrocket: real rule list converted, config renders for this server
    try:
        lst = rules.fetch_converted('telegram-ip', 'shadowrocket').decode().splitlines()
        check('Shadowrocket rule list converted from upstream', len(lst) > 5 and all(l.startswith(('IP-CIDR,', 'IP-CIDR6,')) for l in lst),
              '%d lines, first %s' % (len(lst), lst[:1]))
    except OSError as e:
        check('Shadowrocket rule list converted from upstream', False, str(e))
    conf = subscription.shadowrocket(s, db.user(uid), 'https://127.0.0.1:1')
    check('Shadowrocket config has all three protocols', all(k in conf for k in ('= vless,', '= hysteria2,', '= tuic,')))

    # --- site monitor: one real probe with timings (to the test target, reachable from here)
    host = urllib.parse.urlsplit(TARGET).hostname
    pr_ = monitor.probe(host, '/', socket.AF_INET)
    check('site monitor probe times DNS / connect / TLS / first byte', pr_['ok'] and all(k in pr_ for k in ('dns', 'connect', 'tls', 'ttfb')),
          json.dumps({k: pr_.get(k) for k in ('status', 'dns', 'connect', 'tls', 'ttfb', 'error')}))
    # a wrong password must be refused
    bad = dict(clash['proxies'][0], password='wrong-password')
    mport = free_port()
    d = os.path.join(ROOT, 'm-bad')
    os.makedirs(d)
    with open(os.path.join(d, 'config.yaml'), 'w') as f:
        json.dump({'mixed-port': mport, 'mode': 'rule', 'proxies': [bad], 'rules': ['MATCH,%s' % bad['name']]}, f)
    pr = start([MIHOMO, '-d', d], 'mihomo-bad')
    wait_port(mport)
    try:
        fetch_via(mport)
        check('wrong Hysteria password is refused', False)
    except Exception:
        check('wrong Hysteria password is refused', True)
    pr.terminate()

    # --- the benchmark tool runs end to end through both protocols
    if os.environ.get('V2V_E2E_BENCH', '1') == '1':
        cf = os.path.join(ROOT, 'bench-sub.json')
        out = os.path.join(ROOT, 'bench.json')
        with open(cf, 'w', encoding='utf-8') as f:
            json.dump(clash, f, ensure_ascii=False)
        r = subprocess.run([sys.executable, os.path.join(HERE, '..', 'tools', 'bench.py'), '--config', cf, '--mihomo', MIHOMO,
                            '--quick', '--no-direct', '--json', out], capture_output=True, text=True, timeout=400,
                           encoding='utf-8', errors='replace')
        try:
            with open(out, encoding='utf-8') as f:
                res = json.load(f)['results']
            ok = len(res) == len(clash['proxies']) and all(v['latency']['median'] and v['down_1'] > 0 for v in res.values())
        except (OSError, ValueError, KeyError):
            ok, res = False, None
        check('tools/bench.py measures every protocol', ok, (r.stdout.strip().splitlines() or [r.stderr[-200:]])[-4:] if not ok else
              '; '.join('%s %sms %sMb' % (k.split()[-1], v['latency']['median'], v['down_4']) for k, v in res.items()))


if __name__ == '__main__':
    try:
        main()
    finally:
        for p in procs:
            if p.poll() is None:
                p.terminate()
        for p in procs:
            try:
                p.wait(5)
            except subprocess.TimeoutExpired:
                p.kill()
        db.close()
        failed = [r for r in results if not r[1]]
        print('\n%d passed, %d failed' % (len(results) - len(failed), len(failed)))
        if failed:
            print('logs kept in', ROOT)
        else:
            shutil.rmtree(ROOT, ignore_errors=True)
        sys.exit(1 if failed else 0)
