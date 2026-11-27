"""Server-side configs for Xray (VLESS+REALITY), Hysteria 2 and sing-box (TUIC), applying them, and reading
traffic and who is online."""
import contextlib
import copy
import hashlib
import ipaddress
import json
import os
import re
import socket
import subprocess
import threading
import time
import urllib.request
import uuid

from . import certs, db, paths, shaper, system

XRAY_UNIT = 'vps2vpn-xray'
HY2_UNIT = 'vps2vpn-hysteria'
TUIC_UNIT = 'vps2vpn-tuic'
XRAY_INBOUND = 'reality'          # tag of the REALITY inbound, used by the user API (`xray api adu`)
_ENABLED = {XRAY_UNIT: 'reality_enabled', HY2_UNIT: 'hy2_enabled', TUIC_UNIT: 'tuic_enabled'}

_apply_lock = threading.Lock()
_online_lock = threading.Lock()        # guards _online_cache only; never held while asking the cores
_online_refresh_lock = threading.Lock()  # single-flight: one thread refreshes, the others serve the cache


def _listen_addr():
    """'::' when this machine has IPv6 (dual-stack sockets), else '0.0.0.0' so the cores still start."""
    try:
        sk = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    except OSError:
        return '0.0.0.0'
    try:
        sk.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        sk.bind(('::', 0))
        return '::'
    except OSError:
        return '0.0.0.0'
    finally:
        sk.close()


def can_slow_here(s=None):
    """This server holds a slowed-down account to its speed: limits work here and it has a protocol besides
    Hysteria (which cannot hold one account to a speed)."""
    s = s or db.settings()
    return shaper.active() and bool(s['reality_enabled'] or s.get('tuic_enabled'))


def active_users():
    """Accounts the cores here serve: enabled, and (a main server's own accounts) allowed on this server. A
    slowed-down account is left out where it cannot be held to its speed (it runs on servers that can). On a
    joined server that holds for the main server's accounts too: the main decides from this server's last
    answer, and this server checks again now, in case Reality/TUIC or the limits stopped working since."""
    users = db.users()
    here = None
    out = []
    for u in users:
        if not u['enabled'] or not (u['remote_id'] or db.allowed_on(u, db.MAIN_SERVER)):
            continue
        if u['throttled']:
            if here is None:
                here = can_slow_here()
            if not here:
                continue
        out.append(u)
    return out


def limits(users):
    """{uid: Mbps} of the accounts held to a speed here, or {} where limits cannot be enforced."""
    if not users or not shaper.active():
        return {}
    return {u['id']: db.limit_mbps(u) for u in users if db.limit_mbps(u) > 0}


def email(u):
    """Stats key Xray reports traffic under."""
    return 'u%d' % u['id']


def _stat_uid(label):
    """Parse a core's u<id> marker without Unicode-digit or bigint surprises."""
    if not isinstance(label, str) or not label.startswith('u'):
        return None
    digits = label[1:]
    if not digits or len(digits) > 19 or not digits.isascii() or not digits.isdecimal():
        return None
    uid = int(digits)
    return uid if 0 < uid < (1 << 63) else None


def xray_config(s, users):
    clients = [{'id': u['uuid'], 'flow': 'xtls-rprx-vision', 'email': email(u)} for u in users]
    # Private destinations are blocked by IP and by name. Sniffing is not routeOnly, so a sniffed (possibly
    # spoofed) SNI/Host replaces the destination and is resolved here (IPIfNonMatch) before geoip:private
    # is checked: a client cannot reach 127.0.0.1 / LAN addresses by sending a fake domain.
    rules = [{'ip': ['geoip:private'], 'outboundTag': 'block'}]
    # geosite.dat ships with Xray and install.sh puts it next to the binary; without it Xray would refuse the
    # whole config, so the name rule is only added when the file is there (IPIfNonMatch still covers names).
    if not paths.LIVE or os.path.exists(os.path.join(os.path.dirname(paths.XRAY_BIN), 'geosite.dat')):
        rules.append({'domain': ['geosite:private'], 'outboundTag': 'block'})
    if s['block_bt']:
        rules.append({'protocol': ['bittorrent'], 'outboundTag': 'block'})
    held = limits(users)
    # A limited account leaves through an outbound of its own whose connections carry its mark (see shaper).
    rules += [{'user': ['u%d' % uid], 'outboundTag': 'lim%d' % uid} for uid in sorted(held)]
    limited_out = [{'protocol': 'freedom', 'tag': 'lim%d' % uid,
                    'streamSettings': {'sockopt': {'domainStrategy': 'UseIP', 'mark': shaper.mark(uid)}}}
                   for uid in sorted(held)]
    return {
        'log': {'loglevel': 'warning', 'access': 'none'},
        # HandlerService lets the panel add users to the running core (_xray_hot_add) instead of restarting it
        'api': {'tag': 'api', 'listen': '127.0.0.1:%d' % s['traffic_api_port'],
                'services': ['HandlerService', 'StatsService']},
        'stats': {},
        'policy': {'levels': {'0': {'statsUserUplink': True, 'statsUserDownlink': True, 'statsUserOnline': True,
                                    'handshake': 4, 'connIdle': 300, 'bufferSize': 64}},
                   'system': {}},
        # encrypted DNS when reachable from this server, the system resolver otherwise
        'dns': {'servers': ['https+local://%s/dns-query' % ip for ip, _ in system.doh_servers()[:2]] + ['localhost'],
                'queryStrategy': 'UseIP'},
        'inbounds': [{
            'tag': XRAY_INBOUND, 'listen': _listen_addr(), 'port': s['reality_port'], 'protocol': 'vless',
            'settings': {'clients': clients, 'decryption': 'none'},
            'streamSettings': {
                'network': 'raw', 'security': 'reality',
                'realitySettings': {
                    'show': False, 'target': '%s:443' % s['reality_target'], 'xver': 0,
                    'serverNames': [s['reality_target']],
                    'privateKey': s['reality_private_key'], 'shortIds': [s['reality_short_id']]}},
            'sniffing': {'enabled': True, 'destOverride': ['http', 'tls', 'quic']},
        }],
        'outbounds': [
            {'protocol': 'freedom', 'tag': 'direct', 'streamSettings': {'sockopt': {'domainStrategy': 'UseIP'}}},
            {'protocol': 'blackhole', 'tag': 'block'},
        ] + limited_out,
        # IPIfNonMatch resolves domain destinations before evaluating geoip:private, blocking DNS-based SSRF.
        'routing': {'domainStrategy': 'IPIfNonMatch', 'rules': rules},
    }


def _quic_windows(mem_mb=None):
    """Scale QUIC receive windows with host RAM so small 512 MB VPSes do not OOM under bursts."""
    mem_mb = mem_mb or system.mem_total_mb()
    if mem_mb >= 1800:
        return 16 << 20, 40 << 20
    if mem_mb >= 900:
        return 8 << 20, 20 << 20
    return 4 << 20, 10 << 20


def hysteria_config(s, users):
    cert, key = certs.current(s.get('domain') or s.get('public_host', ''))
    stream_win, conn_win = _quic_windows()
    # Hysteria cannot hold one account to a speed: limited accounts use Reality and TUIC instead (see shaper).
    # Only where Reality or TUIC can carry them: on a Hysteria-only server they keep Hysteria (unlimited), as the
    # subscription assumes (subscription.server_nodes).
    held = limits(users) if (s['reality_enabled'] or s.get('tuic_enabled')) else {}
    # With no enabled user the core must still start, but nobody may log in: one random placeholder account.
    userpass = {email(u): u['hy2_pass'] for u in users if u['id'] not in held} or {'u0': _placeholder(s)}
    conf = {
        'listen': ':%d' % s['hy2_port'],
        'tls': {'cert': cert, 'key': key},
        'auth': {'type': 'userpass', 'userpass': userpass},
        'trafficStats': {'listen': '127.0.0.1:%d' % s['hy2_stats_port'], 'secret': s['stats_secret']},
        # Bigger receive windows than the defaults help on long, fast routes (e.g. China <-> US, ~200-300 ms).
        # Windows start at half their ceiling and grow (init < max), so idle connections stay cheap.
        'quic': {'initStreamReceiveWindow': stream_win // 2, 'maxStreamReceiveWindow': stream_win,
                 'initConnReceiveWindow': conn_win // 2, 'maxConnReceiveWindow': conn_win,
                 'maxIdleTimeout': '60s', 'disablePathMTUDiscovery': False},
        # Always BBR: a client must not be able to demand an arbitrary Brutal send rate and flood the VPS.
        'ignoreClientBandwidth': True,
        'speedTest': False,
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
    cert, key = certs.current(s.get('domain') or s.get('public_host', ''))
    held = limits(users)
    # With no enabled user sing-box still needs one user to start: a random placeholder nobody knows.
    tuic_users = ([{'name': email(u), 'uuid': u['uuid'], 'password': u['hy2_pass']} for u in users]
                  or [{'name': 'u0', 'uuid': str(uuid.uuid5(uuid.NAMESPACE_OID, _placeholder(s))), 'password': _placeholder(s)}])
    conf = {
        'log': {'level': 'warn'},
        'experimental': {'clash_api': {'external_controller': '127.0.0.1:%d' % s['tuic_api_port'],
                                       'secret': s['stats_secret']}},
        'inbounds': [{
            'type': 'tuic', 'tag': 'tuic', 'listen': _listen_addr(), 'listen_port': s['tuic_port'],
            'users': tuic_users,
            'congestion_control': 'bbr', 'auth_timeout': '3s', 'zero_rtt_handshake': False, 'heartbeat': '10s',
            'tls': {'enabled': True, 'alpn': ['h3'], 'certificate_path': cert, 'key_path': key}}],
        'outbounds': [{'type': 'direct', 'tag': 'direct'}] + [
            dict({'type': 'direct', 'tag': email(u)}, **({'routing_mark': shaper.mark(u['id'])} if u['id'] in held else {}))
            for u in users],
        'route': {'rules': ([{'action': 'sniff'}, {'protocol': 'bittorrent', 'action': 'reject'}] if s['block_bt'] else [])
                  # resolve domains first so ip_is_private also catches names pointing at private addresses
                  + [{'action': 'resolve'}, {'ip_is_private': True, 'action': 'reject'}]
                  + [{'auth_user': [email(u)], 'outbound': email(u)} for u in users],
                  'final': 'direct'},
    }
    doh = system.doh_servers()
    if doh:                      # encrypted DNS when reachable from this server, the system resolver otherwise
        conf['dns'] = {'servers': [{'type': 'https', 'tag': 'doh', 'server': doh[0][0], 'tls': {'server_name': doh[0][1]}},
                                   {'type': 'local', 'tag': 'local'}], 'final': 'doh'}
        conf['route']['default_domain_resolver'] = 'doh'
    else:
        # The resolve rule above needs a resolver; name the system one rather than rely on a default.
        conf['dns'] = {'servers': [{'type': 'local', 'tag': 'local'}], 'final': 'local'}
        conf['route']['default_domain_resolver'] = 'local'
    return conf


def _placeholder(s):
    """Credential for the no-users placeholder account (a core refuses an empty user list). Nobody is given it,
    and it is the same on every build, so an unchanged panel does not rewrite the config and restart the core."""
    return hashlib.sha256(('vps2vpn-placeholder:' + s['stats_secret']).encode()).hexdigest()[:32]


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
            with open(path, encoding='utf-8') as f:     # written as UTF-8 by write_atomic
                if f.read() == text:
                    continue
        except (FileNotFoundError, UnicodeDecodeError):
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


def _read_json(path):
    try:
        with open(path, encoding='utf-8') as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def _split_clients(conf):
    """({email: client} of the REALITY inbound, the config with that list emptied), or None if unrecognisable."""
    try:
        rest = copy.deepcopy(conf)
        found = [inb for inb in rest['inbounds'] if inb.get('tag') == XRAY_INBOUND]
        if len(found) != 1:
            return None
        clients = {}
        for c in found[0]['settings']['clients']:
            if not isinstance(c, dict) or not isinstance(c.get('email'), str) or not c['email'] \
                    or c['email'].lower() in clients:
                return None              # Xray keys users by lower-cased email; the API cannot address these
            clients[c['email'].lower()] = c
        found[0]['settings']['clients'] = []
        return clients, rest
    except (KeyError, TypeError, AttributeError):
        return None


def xray_user_diff(old, new):
    """(added clients, removed emails) when the two Xray configs differ only in the REALITY client list,
    else None (anything else changed, or a config is missing: the core must be restarted). A client whose
    entry changed (new UUID after a link rotation) counts as removed and added."""
    a = _split_clients(old) if old else None
    b = _split_clients(new) if new else None
    if not a or not b or a[1] != b[1]:
        return None
    added = [c for e, c in sorted(b[0].items()) if a[0].get(e) != c]
    removed = sorted(e for e, c in a[0].items() if b[0].get(e) != c)
    return added, removed


def _xray_hot_add(s, conf, added):
    """Add users to the running Xray through its HandlerService. True only if every one was accepted.

    `xray api adu [--server=...] <file.json>` (Xray-core main/commands/all/api/inbound_user_add.go, v26.3.27)
    reads a config file's "inbounds", builds each one and adds its clients to the running inbound with the same
    tag. It exits 0 even when a user is refused (e.g. the email already exists) and only prints "Added N
    user(s) in total.", so N is checked. Go's flag parser stops at the first positional argument, so the
    flags go before the file."""
    if not added or not os.path.exists(paths.XRAY_BIN):
        return False
    path = os.path.splitext(paths.XRAY_CONFIG)[0] + '.adu.json'      # holds UUIDs: root-only, removed at once
    try:
        inb = copy.deepcopy(next(i for i in conf['inbounds'] if i.get('tag') == XRAY_INBOUND))
        inb['settings']['clients'] = added
        paths.write_atomic(path, json.dumps({'inbounds': [inb]}), 0o600)
        r = subprocess.run([paths.XRAY_BIN, 'api', 'adu', '--server=127.0.0.1:%d' % s['traffic_api_port'],
                            '-timeout=5', path], capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.SubprocessError, StopIteration, KeyError, TypeError):
        return False
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass
    m = re.search(r'Added (\d+) user', r.stdout or '')
    return r.returncode == 0 and bool(m) and int(m.group(1)) == len(added)


def _xray_live_update(s, old, new):
    """Bring the running Xray to the new config without a restart, when that is safe. True if it worked
    (or nothing needed doing); False means restart.

    Only additions are done live. `xray api rmu` exists, but removing a user only takes it out of the VLESS
    validator (proxy/vless/validator.go MemoryValidator.Del): connections it already has stay open, and
    neither HandlerService nor StatsService (app/proxyman/command, app/stats/command, v26.3.27) has a call
    that closes a user's connections. A user is removed when they are disabled (quota, expiry, device-limit
    pause) or deleted, and must then really be cut off, so a removal still restarts Xray."""
    diff = xray_user_diff(old, new)
    if diff is None:
        return False
    added, removed = diff
    if removed:
        return False
    if not added:
        return True                      # same configuration, only written differently
    if system.unit_active(XRAY_UNIT) is not True:
        return False                     # not running (or not a live system): a (re)start loads the file
    return _xray_hot_add(s, new, added)


# Reading a core's counters resets them, so bytes read but not yet stored exist nowhere else.
# If storing them fails (database locked, disk full), they wait here for the next reading.
_unsaved = {}
# Held from reading the cores to storing what they said, and by a restore while it replaces the
# accounts, so bytes counted for one account id are never billed to whoever has that id afterwards.
# Lock order: _apply_lock, then this, then the database and TUIC meter locks.
_unsaved_lock = threading.Lock()


def save_traffic(s=None):
    """Read and reset the cores' counters and add them to the users' usage. Returns the deltas.
    A failed database write raises, and what was read is billed with the next successful one."""
    s = s or db.settings()
    with _unsaved_lock:
        known = db.user_ids()
        fresh = collect_traffic(s)
        for uid, (up, down) in fresh.items():
            if up or down:
                up0, down0 = _unsaved.get(uid, (0, 0))
                _unsaved[uid] = (up0 + up, down0 + down)
        # Accounts deleted meanwhile have nobody left to bill.
        for uid in [uid for uid in _unsaved if uid not in known]:
            del _unsaved[uid]
        # This server's multiplier bills its own accounts; a main server's accounts are billed there.
        rate = float(s.get('traffic_rate', 1)) if db.valid_rate(s.get('traffic_rate', 1)) else 1.0
        remote = {u['id'] for u in db.users() if u['remote_id']} if rate != 1 else set()
        deltas = [(uid, up, down) if uid in remote else (uid, db.billed(up, rate), db.billed(down, rate))
                  for uid, (up, down) in _unsaved.items()]
        if deltas:
            db.add_traffic_many(deltas)
        _unsaved.clear()
    return deltas


@contextlib.contextmanager
def replacing_accounts(s):
    """Hold while a backup replaces the accounts. Once it has, what the cores counted so far and
    whatever was waiting to be stored belong to accounts that no longer exist (the restored ids may
    name other people): drop it. A restore that fails leaves both untouched."""
    with _unsaved_lock:
        yield
        try:
            collect_traffic(s)      # reading resets the counters, still under the old accounts
        except Exception as e:      # a core that cannot be read restarts with zero counters anyway
            print('could not reset traffic counters after restore: %s' % e, flush=True)
        _unsaved.clear()
        _tuic.forget_accounts()     # its own buffers (an unassigned remainder) outlive the reading above (#106)


def _save_before_restart(s, units):
    """A core starts its counters from zero when it restarts, so whatever it counted since the last
    collection would be lost: collect from the cores about to go down first. Only running ones are asked
    (a stopped core has nothing left, and asking it would only wait for a timeout). Never raises: a failed
    reading must not keep a core from restarting. Lock order is _apply_lock, then _unsaved_lock, then the
    database and TUIC meter locks, as write_configs already does; no holder of those ever waits for
    _apply_lock."""
    try:
        running = [u for u in units if system.unit_active(u) is True]
        if running:
            save_traffic(dict(s, **{flag: unit in running for unit, flag in _ENABLED.items()}))
    except Exception as e:           # accounting is best effort here, the restart is not
        print('traffic collection before restart failed: %s' % e, flush=True)


def apply(s=None, force=False):
    """Write configs and restart only what changed. Safe to call any time."""
    with _apply_lock:
        s = s or db.settings()
        errors = []
        old_xray = None if force else _read_json(paths.XRAY_CONFIG)
        changed = write_configs(s, errors)
        units = {XRAY_UNIT: s['reality_enabled'], HY2_UNIT: s['hy2_enabled'], TUIC_UNIT: s['tuic_enabled']}
        restart = []
        if force or paths.XRAY_CONFIG in changed:
            # Users only added: hand them to the running core and keep everyone else connected. The file is
            # already written, so a later restart comes up in the same state.
            if force or not s['reality_enabled'] or \
                    not _xray_live_update(s, old_xray, _read_json(paths.XRAY_CONFIG)):
                restart.append(XRAY_UNIT)
        if force or paths.HY2_CONFIG in changed:
            restart.append(HY2_UNIT)
        if force or paths.TUIC_CONFIG in changed:
            restart.append(TUIC_UNIT)
        # also when the config did not change but the service is down (protocol switched back on, crash)
        start = [u for u, on in units.items() if on and (u in restart or system.unit_active(u) is False)]
        _save_before_restart(s, start + [u for u, on in units.items() if not on])
        for unit, on in units.items():
            if not on:
                system.systemctl('disable', '--now', unit)
            elif unit in start:
                system.systemctl('enable', unit)
                r = system.systemctl('restart', unit)
                if r.returncode != 0:      # surfaces as an error, and apply_async retries with backoff
                    errors.append('%s did not start: %s' % (unit, (r.stderr or r.stdout or '').strip()[-200:]))
        # after the cores: they now mark exactly the accounts these classes are for
        # A host that cannot shape at all (no tc / IFB, a container) is reported by the health check
        # ("limits_unsupported"); retrying would never help there, so only a failure that can pass counts.
        if not shaper.apply(limits(active_users())) and shaper.available():
            errors.append('speed limits could not be applied')
        hop = system.port_hopping(s)
        if hop and hop.startswith('failed'):
            # Subscriptions stop listing the hop range; the watchdog tries again every 5 minutes.
            print('port hopping could not be set up (%s); listing only the Hysteria port' % hop, flush=True)
        if errors:
            raise RuntimeError('; '.join(errors))
        return changed


def _count(v):
    """A byte counter as a core reported it: a non-negative int, or 0 when the value is malformed. A broken
    stats reply must neither stop the collection for everyone nor bill (or refund) a user a negative amount."""
    try:
        n = int(v)
    except (TypeError, ValueError, OverflowError):
        return 0
    return n if 0 <= n < 1 << 60 else 0


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
            stats = json.loads(r.stdout or '{}')
            for st in (stats.get('stat') if isinstance(stats, dict) else None) or []:
                if not isinstance(st, dict) or not isinstance(st.get('name'), str):
                    continue
                parts = st['name'].split('>>>')        # user>>>u12>>>traffic>>>uplink
                uid = _stat_uid(parts[1]) if len(parts) == 4 else None
                if uid is not None and parts[3] in ('uplink', 'downlink'):
                    v = _count(st.get('value', 0))
                    add(uid, v if parts[3] == 'uplink' else 0, v if parts[3] == 'downlink' else 0)
        except (OSError, ValueError, subprocess.SubprocessError):
            pass
    if s['hy2_enabled']:
        try:
            req = urllib.request.Request('http://127.0.0.1:%d/traffic?clear=1' % s['hy2_stats_port'],
                                         headers={'Authorization': s['stats_secret']})
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read())
            for name, t in (data.items() if isinstance(data, dict) else ()):
                uid = _stat_uid(name)
                if uid is not None and isinstance(t, dict):
                    # Hysteria reports tx = bytes from the client (upload), rx = bytes to the client (download)
                    add(uid, _count(t.get('tx', 0)), _count(t.get('rx', 0)))
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
        self._clear()

    def _clear(self):
        self.conns = {}            # connection id -> (uid, up, down) at the last sample
        self.total = None          # (up, down) server-wide at the last sample
        self.share = {}            # uid -> recent bytes (decaying): how to split the remainder
        self.acc = {}              # uid -> (up, down) not yet handed to collect_traffic
        self.pending = [0, 0]      # remainder nobody could be credited with yet

    @staticmethod
    def poll(s, timeout=3):
        req = urllib.request.Request('http://127.0.0.1:%d/connections' % s['tuic_api_port'],
                                     headers={'Authorization': 'Bearer ' + s['stats_secret']})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read())

    @staticmethod
    def owner(c):
        """Decode a bounded, SQLite-compatible account ID from TUIC telemetry."""
        if not isinstance(c, dict):
            return None
        chains = c.get('chains')
        if not isinstance(chains, list):
            return None
        for tag in chains:
            if not isinstance(tag, str) or not tag.startswith('u'):
                continue
            uid = _stat_uid(tag)
            if uid is not None:
                return uid
        return None

    def _add(self, uid, up, down):
        if not (up or down):
            return
        a, b = self.acc.get(uid, (0, 0))
        self.acc[uid] = (a + up, b + down)

    def _sample_locked(self, s, data=None, users=None):
        try:
            d = data if data is not None else self.poll(s)
        except (OSError, ValueError):
            # Keep the last reading: once sing-box answers again the deltas since then are still credited.
            # (After a restart its connections have new ids and its totals start lower, which is handled below.)
            return False
        if not isinstance(d, dict):
            return False
        total = (_count(d.get('uploadTotal', 0)), _count(d.get('downloadTotal', 0)))
        raw = d.get('connections')
        # A non-list snapshot is invalid, not a genuine zero-connection poll.
        # Advancing total/conns here loses the running per-connection baseline
        # and can double-bill a persistent connection on the next valid poll.
        if raw is not None and not isinstance(raw, list):
            return False
        raw = raw or []
        # Connection IDs become dictionary keys. A malformed JSON array/object
        # ID is unhashable and must not abort quota accounting for valid users.
        listed = [c for c in (raw if isinstance(raw, list) else ())
                  if isinstance(c, dict) and
                  ((type(c.get('id')) is int and c['id'] >= 0) or
                   (isinstance(c.get('id'), str) and 0 < len(c['id']) <= 128))]
        if self.total is None:
            # First reading: only record a baseline. Bytes that open connections carried before we started
            # watching are not credited to anyone a second time.
            conns = {}
            for c in listed:
                uid = self.owner(c)
                if uid is not None:
                    conns[c['id']] = (uid, _count(c.get('upload', 0)), _count(c.get('download', 0)))
            self.total, self.conns = total, conns
            return True
        seen, conns = {}, {}
        for c in listed:
            uid = self.owner(c)
            if uid is None:
                continue
            up, down = _count(c.get('upload', 0)), _count(c.get('download', 0))
            _, up0, down0 = self.conns.get(c['id'], (uid, 0, 0))
            conns[c['id']] = (uid, up, down)
            a, b = seen.get(uid, (0, 0))
            seen[uid] = (a + max(0, up - up0), b + max(0, down - down0))
        for uid, (a, b) in seen.items():
            self._add(uid, a, b)
        for uid in set(self.share) | set(seen):
            val = self.share.get(uid, 0.0) * 0.9 + sum(seen.get(uid, (0, 0)))
            if val < 1.0:
                self.share.pop(uid, None)
            else:
                self.share[uid] = val
        if total[0] >= self.total[0] and total[1] >= self.total[1]:
            self.pending[0] += max(0, total[0] - self.total[0] - sum(v[0] for v in seen.values()))
            self.pending[1] += max(0, total[1] - self.total[1] - sum(v[1] for v in seen.values()))
        self.total, self.conns = total, conns
        weights = {k: v for k, v in self.share.items() if v > 0 and (users is None or k in users)}
        if not weights and users is not None and len(users) == 1:
            weights = {next(iter(users)): 1}
        if any(self.pending) and weights:
            w, given = float(sum(weights.values())), [0, 0]
            for uid, v in weights.items():
                a, b = int(self.pending[0] * v / w), int(self.pending[1] * v / w)
                self._add(uid, a, b)
                given[0], given[1] = given[0] + a, given[1] + b
            self.pending = [self.pending[0] - given[0], self.pending[1] - given[1]]   # rounding is carried, not lost
        return True

    def sample(self, s, data=None, users=None):
        """Take one reading. `users` (ids) lets a lone user receive traffic nobody else could have made."""
        with self.lock:
            return self._sample_locked(s, data=data, users=users)

    def collect(self, s, users=None):
        with self.lock:
            self._sample_locked(s, users=users)
            out, self.acc = self.acc, {}
        return out

    def forget_accounts(self):
        """The accounts were replaced (a restore): everything kept here was measured under the old ones.
        The remainder nobody was credited with yet, who was recently busy, and the per-connection baseline
        all name old account ids that may now be other people. Start over: the next reading is a baseline."""
        with self.lock:
            self._clear()

    def online(self, s):
        try:
            data = self.poll(s, 1.5)
            if not isinstance(data, dict):
                return None
            connections = data.get('connections') or []
            if not isinstance(connections, list):
                return None
            return {'u%d' % uid for uid in (self.owner(c) for c in connections) if uid is not None}
        except (OSError, ValueError):
            return None


_tuic = TuicMeter()


UID_RE = re.compile(r'\bu(\d+)\b')
IP_RE = re.compile(r'"((?:[0-9a-fA-F:]*:)?(?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]*:[0-9a-fA-F:]+)"\s*:')


def _xray_api(s, *args, timeout=4):
    r = subprocess.run([paths.XRAY_BIN, 'api'] + list(args) + ['--server=127.0.0.1:%d' % s['traffic_api_port']],
                       capture_output=True, text=True, timeout=timeout)
    return r.stdout if r.returncode == 0 else ''


_online_cache = {'at': None, 'value': None}


def online_detail(s=None, max_age=4):
    """Who is connected right now: {uid: {'protocols': [...], 'ips': [...], 'conns': n}}, or None if no core
    could be asked. Xray and TUIC also report the client addresses (= devices); Hysteria reports a count.
    Cached for a few seconds: the panel asks on every refresh."""
    def fresh():
        with _online_lock:
            at = _online_cache['at']
            if max_age and at is not None and time.monotonic() - at < max_age:
                return True, _online_cache['value']
            return False, (_online_cache['value'] if at is not None else None)

    ok, value = fresh()
    if ok:
        return value
    # Asking the cores can block for seconds; never do it while holding _online_lock. Only one thread
    # refreshes at a time; while it does, others get the last snapshot (or wait if there is none yet).
    if not _online_refresh_lock.acquire(blocking=False):
        if max_age:
            with _online_lock:
                if _online_cache['at'] is not None:
                    return _online_cache['value']
        _online_refresh_lock.acquire()
    try:
        ok, value = fresh()          # someone else may have refreshed while we waited
        if ok:
            return value
        value = _online_detail(s or db.settings())
        with _online_lock:
            _online_cache.update(at=time.monotonic(), value=value)
        return value
    finally:
        _online_refresh_lock.release()


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
            # Xray stats strings are not trusted numeric input: a single
            # 5000-digit or Unicode-digit marker must not abort this snapshot.
            ids = {_stat_uid('u' + marker) for marker in UID_RE.findall(text)}
            for uid in ids - {None}:
                ips = IP_RE.findall(_xray_api(s, 'statsonlineiplist', '-email', 'u%d' % uid))
                mark(uid, 'reality', ips, max(1, len(ips)))
        except (OSError, subprocess.SubprocessError):
            pass
    if s['hy2_enabled']:
        try:
            req = urllib.request.Request('http://127.0.0.1:%d/online' % s['hy2_stats_port'],
                                         headers={'Authorization': s['stats_secret']})
            with urllib.request.urlopen(req, timeout=1.5) as resp:
                online_map = json.loads(resp.read())
            if not isinstance(online_map, dict):
                raise ValueError('invalid Hysteria online response')
            for name, n in online_map.items():
                if not isinstance(name, str) or not name.startswith('u'):
                    continue
                uid = _stat_uid(name)
                if uid is None:
                    continue
                # Hysteria normally reports integer counts. Keep compatible
                # ASCII decimal strings, but reject arrays, booleans, and huge values.
                if type(n) is int:
                    cnt = n
                elif isinstance(n, str) and 1 <= len(n) <= 10 and n.isascii() and n.isdecimal():
                    cnt = int(n)
                else:
                    continue
                if 0 < cnt <= 1000000:
                    mark(uid, 'hy2', conns=cnt)
            known = True
        except (OSError, ValueError):
            pass
    if s['tuic_enabled']:
        try:
            snapshot = TuicMeter.poll(s, 1.5)
            if not isinstance(snapshot, dict):
                raise ValueError('invalid TUIC online response')
            connections = snapshot.get('connections') or []
            if not isinstance(connections, list):
                raise ValueError('invalid TUIC connection list')
            for c in connections:
                uid = TuicMeter.owner(c)
                if uid is None:
                    continue
                metadata = c.get('metadata')
                source = metadata.get('sourceIP') if isinstance(metadata, dict) else None
                if not isinstance(source, str):
                    source = ''
                mark(uid, 'tuic', [source], 1)
            known = True
        except (OSError, ValueError):
            pass
    if not known:
        return None
    return {uid: {'protocols': sorted(d['protocols']), 'ips': sorted(d['ips']), 'conns': d['conns'],
                  'devices': device_estimate(d['ips'], d['hy2'])} for uid, d in out.items()}


def device_estimate(ips, hy2_clients=0):
    """How many devices an account has online, never more than it can prove.

    One phone shows up several times: the app's smart line keeps Reality, Hysteria 2 and TUIC open at once,
    a dual-stack phone uses both the IPv4 and the IPv6 lines, and IPv6 privacy addresses rotate inside one
    /64. Adding these up paused people with a limit of 1 for using a single phone. So the estimate is the
    largest of: distinct IPv4 addresses, distinct IPv6 /64 networks, Hysteria clients (Hysteria reports a
    count, not addresses). Two devices on different families or protocols can be undercounted; a single
    device is never counted twice."""
    v4, v6 = set(), set()
    for raw in ips:
        try:
            ip = ipaddress.ip_address(str(raw).strip('[]').split('%')[0])
        except ValueError:
            continue
        if ip.version == 6 and ip.ipv4_mapped:
            ip = ip.ipv4_mapped
        if ip.version == 4:
            v4.add(ip)
        else:
            v6.add(ipaddress.ip_network((ip, 64), strict=False))
    return max(len(v4), len(v6), int(hy2_clients or 0))


def online_count(s=None):
    d = online_detail(s)
    return None if d is None else len(d)
