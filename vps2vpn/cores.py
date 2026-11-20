"""Server-side configs for Xray (VLESS+REALITY), Hysteria 2 and sing-box (TUIC), applying them, and reading
traffic and who is online."""
import json
import os
import re
import subprocess
import threading
import urllib.request

from . import certs, db, paths, system

XRAY_UNIT = 'vps2vpn-xray'
HY2_UNIT = 'vps2vpn-hysteria'
TUIC_UNIT = 'vps2vpn-tuic'


def active_users():
    return [u for u in db.users() if u['enabled']]


def email(u):
    """Stats key Xray reports traffic under."""
    return 'u%d' % u['id']


def xray_config(s, users):
    clients = [{'id': u['uuid'], 'flow': 'xtls-rprx-vision', 'email': email(u)} for u in users]
    rules = [{'ip': ['geoip:private'], 'outboundTag': 'block'}]
    if s['block_bt']:
        rules.append({'protocol': ['bittorrent'], 'outboundTag': 'block'})
    return {
        'log': {'loglevel': 'warning', 'access': 'none'},
        'api': {'tag': 'api', 'listen': '127.0.0.1:%d' % s['traffic_api_port'], 'services': ['StatsService']},
        'stats': {},
        'policy': {'levels': {'0': {'statsUserUplink': True, 'statsUserDownlink': True, 'statsUserOnline': True,
                                    'handshake': 4, 'connIdle': 300, 'bufferSize': 64}},
                   'system': {}},
        # encrypted DNS when reachable from this server, the system resolver otherwise
        'dns': {'servers': ['https+local://%s/dns-query' % ip for ip, _ in system.doh_servers()[:2]] + ['localhost'],
                'queryStrategy': 'UseIP'},
        'inbounds': [{
            'tag': 'reality', 'listen': '::', 'port': s['reality_port'], 'protocol': 'vless',
            'settings': {'clients': clients, 'decryption': 'none'},
            'streamSettings': {
                'network': 'raw', 'security': 'reality',
                'realitySettings': {
                    'show': False, 'target': '%s:443' % s['reality_target'], 'xver': 0,
                    'serverNames': [s['reality_target']],
                    'privateKey': s['reality_private_key'], 'shortIds': [s['reality_short_id']]}},
            'sniffing': {'enabled': True, 'destOverride': ['http', 'tls', 'quic'], 'routeOnly': True},
        }],
        'outbounds': [
            {'protocol': 'freedom', 'tag': 'direct', 'streamSettings': {'sockopt': {'domainStrategy': 'UseIP'}}},
            {'protocol': 'blackhole', 'tag': 'block'},
        ],
        'routing': {'domainStrategy': 'AsIs', 'rules': rules},
    }


def hysteria_config(s, users):
    cert, key = certs.current()
    conf = {
        'listen': ':%d' % s['hy2_port'],
        'tls': {'cert': cert, 'key': key},
        'auth': {'type': 'userpass', 'userpass': {email(u): u['hy2_pass'] for u in users}},
        'trafficStats': {'listen': '127.0.0.1:%d' % s['hy2_stats_port'], 'secret': s['stats_secret']},
        # Bigger receive windows than the defaults help on long, fast routes (e.g. China <-> US, ~200-300 ms).
        'quic': {'initStreamReceiveWindow': 16777216, 'maxStreamReceiveWindow': 16777216,
                 'initConnReceiveWindow': 41943040, 'maxConnReceiveWindow': 41943040,
                 'maxIdleTimeout': '60s', 'disablePathMTUDiscovery': False},
        # No fixed bandwidth: clients that send none get BBR, which adapts by itself.
        'ignoreClientBandwidth': False,
        'speedTest': True,
        'acl': {'inline': ['reject(geoip:private)', 'direct(all)'],
                'geoip': '/usr/local/lib/vps2vpn/geoip.dat'},
        'masquerade': {'type': 'proxy', 'proxy': {'url': s['hy2_masquerade'], 'rewriteHost': True}},
    }
    if s['hy2_obfs']:
        conf['obfs'] = {'type': 'salamander', 'salamander': {'password': s['hy2_obfs']}}
        del conf['masquerade']   # salamander traffic is not HTTP/3, so there is nothing to masquerade as
    doh = system.doh_servers()
    if doh:                      # otherwise Hysteria uses the system resolver
        conf['resolver'] = {'type': 'https', 'https': {'addr': doh[0][0] + ':443', 'timeout': '4s', 'sni': doh[0][1]}}
    return conf


def tuic_config(s, users):
    """sing-box serving TUIC v5. Each user leaves through an outbound tagged with their stats key, so the
    Clash API's connection list tells whose traffic is whose (official builds have no per-user counters)."""
    cert, key = certs.current()
    conf = {
        'log': {'level': 'warn'},
        'experimental': {'clash_api': {'external_controller': '127.0.0.1:%d' % s['tuic_api_port'],
                                       'secret': s['stats_secret']}},
        'inbounds': [{
            'type': 'tuic', 'tag': 'tuic', 'listen': '::', 'listen_port': s['tuic_port'],
            'users': [{'name': email(u), 'uuid': u['uuid'], 'password': u['hy2_pass']} for u in users],
            'congestion_control': 'bbr', 'auth_timeout': '3s', 'zero_rtt_handshake': False, 'heartbeat': '10s',
            'tls': {'enabled': True, 'alpn': ['h3'], 'certificate_path': cert, 'key_path': key}}],
        'outbounds': [{'type': 'direct', 'tag': 'direct'}] + [{'type': 'direct', 'tag': email(u)} for u in users],
        'route': {'rules': ([{'action': 'sniff'}, {'protocol': 'bittorrent', 'action': 'reject'}] if s['block_bt'] else [])
                  + [{'ip_is_private': True, 'action': 'reject'}]
                  + [{'auth_user': [email(u)], 'outbound': email(u)} for u in users],
                  'final': 'direct'},
    }
    doh = system.doh_servers()
    if doh:                      # encrypted DNS when reachable from this server, the system resolver otherwise
        conf['dns'] = {'servers': [{'type': 'https', 'tag': 'doh', 'server': doh[0][0], 'tls': {'server_name': doh[0][1]}},
                                   {'type': 'local', 'tag': 'local'}], 'final': 'doh'}
        conf['route']['default_domain_resolver'] = 'doh'
    return conf


def write_configs(s=None, errors=None):
    """Render the core configs. Returns the paths that changed; a config a core rejects is reported in `errors`."""
    s = s or db.settings()
    errors = [] if errors is None else errors
    users = active_users()
    changed = []
    group = 'vps2vpn'
    for path, data, on in ((paths.XRAY_CONFIG, xray_config(s, users), s['reality_enabled']),
                           (paths.HY2_CONFIG, hysteria_config(s, users), s['hy2_enabled']),
                           (paths.TUIC_CONFIG, tuic_config(s, users), s['tuic_enabled'])):
        if not on:
            continue
        text = json.dumps(data, indent=2, ensure_ascii=False) + '\n'
        try:
            with open(path) as f:
                if f.read() == text:
                    continue
        except FileNotFoundError:
            pass
        cmd = None
        if paths.LIVE and path == paths.XRAY_CONFIG and os.path.exists(paths.XRAY_BIN):
            cmd = [paths.XRAY_BIN, 'run', '-test', '-c']
        if paths.LIVE and path == paths.TUIC_CONFIG and os.path.exists(paths.SINGBOX_BIN):
            cmd = [paths.SINGBOX_BIN, 'check', '-c']
        if cmd:
            test = check_path(path)
            paths.write_atomic(test, text, 0o640, group)
            try:
                r = subprocess.run(cmd + [test], capture_output=True, text=True, timeout=30,
                                   env=dict(os.environ, XRAY_LOCATION_ASSET='/usr/local/lib/vps2vpn'))
            finally:
                os.unlink(test)
            if r.returncode != 0:
                # Keep the old file for this core, but still write the others (one bad config must not take all down).
                errors.append('%s rejected the new config, kept the old one: %s' % (
                    os.path.basename(cmd[0]), (r.stdout + r.stderr)[-400:]))
                continue
        paths.write_atomic(path, text, 0o640, group)
        changed.append(path)
    return changed


def check_path(path):
    """Scratch file for `xray -test` / `sing-box check`. It must end in .json: Xray picks the format from the
    extension and refuses anything else (a `.check` suffix once stopped every fresh install from starting)."""
    base, ext = os.path.splitext(path)
    return base + '.check' + (ext or '.json')


def apply(s=None, force=False):
    """Write configs and restart only what changed. Safe to call any time."""
    s = s or db.settings()
    errors = []
    changed = write_configs(s, errors)
    units = {XRAY_UNIT: s['reality_enabled'], HY2_UNIT: s['hy2_enabled'], TUIC_UNIT: s['tuic_enabled']}
    restart = []
    if force or paths.XRAY_CONFIG in changed:
        restart.append(XRAY_UNIT)
    if force or paths.HY2_CONFIG in changed:
        restart.append(HY2_UNIT)
    if force or paths.TUIC_CONFIG in changed:
        restart.append(TUIC_UNIT)
    for unit, on in units.items():
        if not on:
            system.systemctl('disable', '--now', unit)
        elif unit in restart:
            system.systemctl('enable', unit)
            system.systemctl('restart', unit)
    system.port_hopping(s)
    if errors:
        raise RuntimeError('; '.join(errors))
    return changed


def collect_traffic(s=None):
    """Read and reset the per-user counters of both cores. Returns {user_id: (up, down)}."""
    s = s or db.settings()
    out = {}

    def add(uid, up, down):
        a, b = out.get(uid, (0, 0))
        out[uid] = (a + up, b + down)

    if s['reality_enabled'] and os.path.exists(paths.XRAY_BIN):
        try:
            r = subprocess.run([paths.XRAY_BIN, 'api', 'statsquery', '--server=127.0.0.1:%d' % s['traffic_api_port'],
                                '-pattern', 'user>>>', '-reset'], capture_output=True, text=True, timeout=15)
            for st in json.loads(r.stdout or '{}').get('stat', []):
                parts = st['name'].split('>>>')        # user>>>u12>>>traffic>>>uplink
                if len(parts) == 4 and parts[1].startswith('u') and parts[1][1:].isdigit():
                    v = int(st.get('value', 0))
                    add(int(parts[1][1:]), v if parts[3] == 'uplink' else 0, v if parts[3] == 'downlink' else 0)
        except (OSError, ValueError, subprocess.SubprocessError):
            pass
    if s['hy2_enabled']:
        try:
            req = urllib.request.Request('http://127.0.0.1:%d/traffic?clear=1' % s['hy2_stats_port'],
                                         headers={'Authorization': s['stats_secret']})
            data = json.loads(urllib.request.urlopen(req, timeout=10).read())
            for name, t in data.items():
                if name.startswith('u') and name[1:].isdigit():
                    # Hysteria reports tx = bytes from the client (upload), rx = bytes to the client (download)
                    add(int(name[1:]), int(t.get('tx', 0)), int(t.get('rx', 0)))
        except (OSError, ValueError):
            pass
    if s['tuic_enabled']:
        for uid, (up, down) in _tuic.collect(s, users={u['id'] for u in active_users()}).items():
            add(uid, up, down)
    return out


class TuicMeter:
    """Per-user TUIC traffic from sing-box's Clash API (official builds have no per-user counters).

    Open connections carry their user (the outbound tag) and byte counts; the panel samples them every
    couple of seconds. A connection that opens and closes between two samples is only visible in the
    server-wide totals, so that remainder is split between users in proportion to what they were recently
    seen using (or given to the only user, when there is one). Per-user sums therefore match the server total."""

    def __init__(self):
        self.lock = threading.Lock()
        self.conns = {}            # connection id -> (uid, up, down) at the last sample
        self.total = None          # (up, down) server-wide at the last sample
        self.share = {}            # uid -> recent bytes (decaying): how to split the remainder
        self.acc = {}              # uid -> (up, down) not yet handed to collect_traffic
        self.pending = [0, 0]      # remainder nobody could be credited with yet

    @staticmethod
    def poll(s, timeout=3):
        req = urllib.request.Request('http://127.0.0.1:%d/connections' % s['tuic_api_port'],
                                     headers={'Authorization': 'Bearer ' + s['stats_secret']})
        return json.loads(urllib.request.urlopen(req, timeout=timeout).read())

    @staticmethod
    def owner(c):
        return next((int(x[1:]) for x in c.get('chains') or [] if x[:1] == 'u' and x[1:].isdigit()), None)

    def _add(self, uid, up, down):
        a, b = self.acc.get(uid, (0, 0))
        self.acc[uid] = (a + up, b + down)

    def sample(self, s, data=None, users=None):
        """Take one reading. `users` (ids) lets a lone user receive traffic nobody else could have made."""
        try:
            d = data if data is not None else self.poll(s)
        except (OSError, ValueError):
            with self.lock:
                self.total, self.conns = None, {}      # down or restarting: count afresh from the next reading
            return False
        with self.lock:
            seen, conns = {}, {}
            for c in d.get('connections') or []:
                uid = self.owner(c)
                if uid is None:
                    continue
                up, down = int(c.get('upload', 0)), int(c.get('download', 0))
                _, up0, down0 = self.conns.get(c.get('id'), (uid, 0, 0))
                conns[c.get('id')] = (uid, up, down)
                a, b = seen.get(uid, (0, 0))
                seen[uid] = (a + max(0, up - up0), b + max(0, down - down0))
            for uid, (a, b) in seen.items():
                self._add(uid, a, b)
            for uid in set(self.share) | set(seen):
                self.share[uid] = self.share.get(uid, 0) * 0.9 + sum(seen.get(uid, (0, 0)))
            total = (int(d.get('uploadTotal', 0)), int(d.get('downloadTotal', 0)))
            if self.total is not None and total[0] >= self.total[0] and total[1] >= self.total[1]:
                self.pending[0] += max(0, total[0] - self.total[0] - sum(v[0] for v in seen.values()))
                self.pending[1] += max(0, total[1] - self.total[1] - sum(v[1] for v in seen.values()))
            self.total, self.conns = total, conns
            weights = {k: v for k, v in self.share.items() if v > 0}
            if not weights and users is not None and len(users) == 1:
                weights = {next(iter(users)): 1}
            if any(self.pending) and weights:
                w = float(sum(weights.values()))
                for uid, v in weights.items():
                    self._add(uid, int(self.pending[0] * v / w), int(self.pending[1] * v / w))
                self.pending = [0, 0]
            return True

    def collect(self, s, users=None):
        self.sample(s, users=users)
        with self.lock:
            out, self.acc = self.acc, {}
        return out

    def online(self, s):
        try:
            return {'u%d' % u for u in (self.owner(c) for c in self.poll(s, 1.5).get('connections') or []) if u is not None}
        except (OSError, ValueError):
            return None


_tuic = TuicMeter()


UID_RE = re.compile(r'\bu(\d+)\b')
IP_RE = re.compile(r'"((?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]*:[0-9a-fA-F:]+)"\s*:')


def _xray_api(s, *args, timeout=4):
    r = subprocess.run([paths.XRAY_BIN, 'api'] + list(args) + ['--server=127.0.0.1:%d' % s['traffic_api_port']],
                       capture_output=True, text=True, timeout=timeout)
    return r.stdout if r.returncode == 0 else ''


_online_cache = {'at': 0, 'value': None}


def online_detail(s=None, max_age=4):
    """Who is connected right now: {uid: {'protocols': [...], 'ips': [...], 'conns': n}}, or None if no core
    could be asked. Xray and TUIC also report the client addresses (= devices); Hysteria reports a count.
    Cached for a few seconds: the panel asks on every refresh."""
    import time
    if max_age and time.time() - _online_cache['at'] < max_age:
        return _online_cache['value']
    value = _online_detail(s or db.settings())
    _online_cache.update(at=time.time(), value=value)
    return value


def _online_detail(s):
    out, known = {}, False

    def mark(uid, proto, ips=(), conns=0):
        d = out.setdefault(uid, {'protocols': set(), 'ips': set(), 'conns': 0, 'hy2': 0})
        d['protocols'].add(proto)
        if proto == 'hy2':
            d['hy2'] += conns      # Hysteria reports clients per user, not their addresses
        d['ips'].update(ip for ip in ips if ip)
        d['conns'] += conns

    if s['reality_enabled'] and os.path.exists(paths.XRAY_BIN):
        try:
            text = _xray_api(s, 'statsgetallonlineusers')
            known = known or bool(text)
            for uid in {int(m) for m in UID_RE.findall(text)}:
                ips = IP_RE.findall(_xray_api(s, 'statsonlineiplist', '-email', 'u%d' % uid))
                mark(uid, 'reality', ips, max(1, len(ips)))
        except (OSError, subprocess.SubprocessError):
            pass
    if s['hy2_enabled']:
        try:
            req = urllib.request.Request('http://127.0.0.1:%d/online' % s['hy2_stats_port'],
                                         headers={'Authorization': s['stats_secret']})
            for name, n in json.loads(urllib.request.urlopen(req, timeout=1.5).read()).items():
                if name[:1] == 'u' and name[1:].isdigit():
                    mark(int(name[1:]), 'hy2', conns=int(n or 1))
            known = True
        except (OSError, ValueError):
            pass
    if s['tuic_enabled']:
        try:
            for c in TuicMeter.poll(s, 1.5).get('connections') or []:
                uid = TuicMeter.owner(c)
                if uid is not None:
                    mark(uid, 'tuic', [(c.get('metadata') or {}).get('sourceIP', '')], 1)
            known = True
        except (OSError, ValueError):
            pass
    if not known:
        return None
    # devices: distinct client addresses (Xray, TUIC) plus Hysteria clients
    return {uid: {'protocols': sorted(d['protocols']), 'ips': sorted(d['ips']), 'conns': d['conns'],
                  'devices': len(d['ips']) + d['hy2']} for uid, d in out.items()}


def online_count(s=None):
    d = online_detail(s)
    return None if d is None else len(d)
