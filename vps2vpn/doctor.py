"""Self-check ("一键体检"): finds the usual reasons a VPN stops working and says how to fix them.

Every check returns {id, ok, detail, fix}. ok is True, False, or None (could not tell / not applicable).
"""
import json
import os
import shutil
import socket
import ssl
import time
import urllib.request

from . import XRAY_VERSION, certs, cores, db, paths, rules, system


def _check(cid, ok, detail='', fix=''):
    return {'id': cid, 'ok': ok, 'detail': detail, 'fix': fix if ok is not True else ''}


def services(s):
    out = []
    for name, unit, on in (('panel', 'vps2vpn', True), ('xray', cores.XRAY_UNIT, s['reality_enabled']),
                           ('hysteria', cores.HY2_UNIT, s['hy2_enabled']), ('tuic', cores.TUIC_UNIT, s['tuic_enabled'])):
        if not on:
            continue
        a = system.unit_active(unit)
        out.append(_check('service_' + name, a, unit, 'journalctl -u %s -n 50   then: vps2vpn apply --force' % unit))
    return out


def reality_handshake(s):
    """Unauthenticated TLS to our REALITY port must be forwarded to the camouflage site and show its certificate."""
    if not s['reality_enabled']:
        return []
    if system.unit_active(cores.XRAY_UNIT) is False:
        return [_check('reality_camouflage', None, 'skipped: Xray is not running (see above)')]
    t0 = time.monotonic()
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection(('127.0.0.1', s['reality_port']), timeout=8) as raw:
            with ctx.wrap_socket(raw, server_hostname=s['reality_target']) as tls:
                ok = tls.version() == 'TLSv1.3'
                return [_check('reality_camouflage', ok, '%s, %d ms' % (tls.version(), (time.monotonic() - t0) * 1000),
                               'pick another camouflage site in Settings')]
    except ssl.SSLCertVerificationError as e:
        return [_check('reality_camouflage', False, 'certificate mismatch: %s' % e,
                       'the camouflage site sent an unexpected certificate; pick another site in Settings')]
    except OSError as e:
        return [_check('reality_camouflage', False, str(e)[:160],
                       'Xray is not answering, or this server cannot reach %s. Pick another camouflage site.' % s['reality_target'])]


def hysteria_api(s):
    if not s['hy2_enabled']:
        return []
    if system.unit_active(cores.HY2_UNIT) is False:
        return [_check('hysteria_api', None, 'skipped: Hysteria is not running (see above)')]
    try:
        req = urllib.request.Request('http://127.0.0.1:%d/online' % s['hy2_stats_port'],
                                     headers={'Authorization': s['stats_secret']})
        with urllib.request.urlopen(req, timeout=2) as resp:
            data = json.loads(resp.read())
        if not isinstance(data, dict):
            raise ValueError('unexpected /online reply: %s' % type(data).__name__)
        n = sum(1 for v in data.values() if isinstance(v, (int, float, str)) and int(v or 0) > 0)
        return [_check('hysteria_api', True, 'online: %d' % n)]
    except (OSError, ValueError, TypeError) as e:
        return [_check('hysteria_api', False, str(e)[:120], 'systemctl restart %s' % cores.HY2_UNIT)]


def udp_listening(s):
    if not paths.LIVE:
        return []
    out = []
    for on, cid, port, prog, name, unit in (
        (s['hy2_enabled'], 'hysteria_port', s['hy2_port'], 'hysteria', 'Hysteria', cores.HY2_UNIT),
        (s['tuic_enabled'], 'tuic_port', s['tuic_port'], 'sing-box', 'TUIC', cores.TUIC_UNIT),
    ):
        if on:
            owner = system.port_owner('udp', port) or ''
            fix = ('%s is not listening on UDP %d; check: journalctl -u %s -n 50' % (name, port, unit)
                   if not owner else
                   'another program (%s) holds UDP %d; change the %s port in Settings' % (owner, port, name))
            out.append(_check(cid, prog in owner, 'UDP %d: %s' % (port, owner or 'nobody'), fix))
    return out


def port_hopping(s):
    if not (s['hy2_enabled'] and s['hy2_hop'] and paths.LIVE):
        return []
    r = system.run(['nft', 'list', 'table', 'inet', system.NFT_TABLE])
    return [_check('port_hopping', r.returncode == 0 and 'redirect' in r.stdout, s['hy2_hop_range'],
                   'vps2vpn apply --force   (needs the nftables package)')]


def certificate(s):
    host = s['domain'] or s['public_host']
    if certs.trusted(host):
        return [_check('certificate', certs.acme_valid(24), "Let's Encrypt for %s" % host,
                       'expires within a day and renewal is failing: open TCP 80, then run  vps2vpn cert')]
    # Apps other than the vps2vpn client cannot pin a self-signed certificate, so subscription links fall back
    # to plain HTTP and the account credentials in them cross the network readable. Say so.
    if s['cert_mode'] == 'self':
        return [_check('certificate', None, 'self-signed (chosen in Settings): subscription links use plain HTTP',
                       'switch the certificate to automatic so subscriptions are encrypted')]
    st = s['cert_status'] or 'not requested yet'
    return [_check('certificate', None, 'self-signed, so subscription links use plain HTTP; '
                                        'Let\'s Encrypt: %s' % st[:160],
                   'open TCP 80 in the provider firewall, then press "Get certificate now"')]


def kernel(s):
    out = [_check('bbr', system.bbr_active(), 'tcp_congestion_control', 'vps2vpn apply   (kernel may be too old for BBR)')]
    try:
        with open('/proc/sys/net/core/rmem_max') as f:
            v = int(f.read())
        out.append(_check('udp_buffers', v >= 7 << 20, 'rmem_max = %d' % v,
                          'turn on "Automatic network tuning" in Settings'))
    except OSError:
        pass
    return out


def clock():
    if not paths.LIVE or not shutil.which('timedatectl'):
        return []
    r = system.run(['timedatectl', 'show', '-p', 'NTPSynchronized', '--value'])
    return [_check('clock', r.stdout.strip() == 'yes', 'NTP synchronized: %s' % (r.stdout.strip() or '?'),
                   'timedatectl set-ntp true')]


def public_address(s):
    host = (s.get('domain') or s.get('public_host') or '').strip()
    if not host:
        return [_check('address', False, 'server address is not configured', 'set the server address in Settings')]
    if not certs.is_ip(host):
        try:
            ips = {certs._norm_host(a[4][0].split('%', 1)[0]) for a in socket.getaddrinfo(host, None)}
        except OSError as e:
            return [_check('address', False, '%s does not resolve: %s' % (host, e), 'check the domain\'s DNS records')]
        mine = [ip for ip in (system.public_ip(),) if ip]
        if not any(certs._norm_host(ip) in ips for ip in mine):
            mine += [ip for ip in (system.public_ip(v6=True),) if ip]     # IPv6-only / AAAA-only setups
        if not mine:
            return [_check('address', None, '%s -> %s (could not look up this server\'s public IP)' % (
                host, ', '.join(sorted(ips))))]
        ok = any(certs._norm_host(ip) in ips for ip in mine)
        return [_check('address', ok, '%s -> %s (this server: %s)' % (host, ', '.join(sorted(ips)), ', '.join(mine)),
                       'point the domain\'s %s record at %s' % ('AAAA' if ':' in mine[0] else 'A', mine[0]))]
    v6 = ':' in host                     # an IPv6-only server must be compared with its IPv6 egress address
    now = system.public_ip(v6=v6)
    if not now:
        return [_check('address', None, 'could not look up this server\'s public IP')]
    return [_check('address', certs._norm_host(now) == certs._norm_host(host), 'configured %s, actual %s' % (host, now),
                   'the server\'s IP changed: Settings > server address = %s (vps2vpn does this by itself within a day)' % now)]


def outbound():
    t0 = time.monotonic()
    try:
        with urllib.request.urlopen('https://www.gstatic.com/generate_204', timeout=8) as r:
            r.read()
        return [_check('internet', True, '%d ms' % ((time.monotonic() - t0) * 1000))]
    except OSError as e:
        return [_check('internet', False, str(e)[:160], 'this server cannot reach the internet; check its network / DNS')]


def resources():
    out = []
    try:
        st = os.statvfs('/')
        free = st.f_bavail * st.f_frsize
        out.append(_check('disk', free > 300 << 20, '%d MB free' % (free >> 20), 'free some disk space'))
    except (OSError, AttributeError):
        pass
    h = system.health()
    if h.get('mem_total'):
        used = h['mem_used'] / h['mem_total']
        out.append(_check('memory', used < 0.92, '%d%% used' % (used * 100), 'upgrade the plan or reduce other programs'))
    return out


def versions():
    try:
        with open(os.path.join(os.path.dirname(paths.XRAY_BIN), '.xray-version')) as f:
            v = f.read().strip()
    except OSError:
        return []
    return [_check('xray_version', v == XRAY_VERSION, v, 'bash install.sh   (re-run to get the tested version %s)' % XRAY_VERSION)]


def rule_mirror():
    age = rules.mirror_age()
    return [_check('rules', age is not None and age < 3 * 86400,
                   'updated %s hours ago' % (age // 3600) if age is not None else 'never',
                   'press "Update routing rules now"; the server needs to reach github.com')]


def speed_limits():
    """Accounts with a speed limit on a server that cannot hold them to it."""
    from . import shaper
    limited = [u for u in db.users() if u['enabled'] and db.limit_mbps(u) > 0]
    if not limited:
        return []
    if shaper.active():
        st = shaper.status()
        ok = not st['error']
        # `vps2vpn doctor` runs in its own process, where nothing has been applied yet: name the card it would use
        dev = st['dev'] or shaper.default_dev() or '?'
        return [_check('speed_limits', ok, '%d account(s) limited on %s' % (len(limited), dev)
                       if ok else st['error'], 'vps2vpn apply --force   (then see journalctl -u vps2vpn)')]
    if not shaper.available():
        return [_check('speed_limits', None, '%d account(s) have a speed limit, but this kernel has no tc/ifb '
                       '(container VPS?): they run at full speed' % len(limited))]
    return [_check('speed_limits', False, 'the Xray/TUIC services may not mark traffic yet',
                   'bash install.sh   (re-run once: it lets the cores mark limited accounts)')]


def run_all():
    s = db.settings()
    out = []
    for fn in (services, reality_handshake, hysteria_api, udp_listening, port_hopping, certificate, kernel):
        try:
            out += fn(s)
        except Exception as e:      # a broken check must not hide the others
            out.append(_check(fn.__name__, None, 'check failed: %s' % e))
    for fn in (clock, outbound, resources, versions, rule_mirror, speed_limits):
        try:
            out += fn()
        except Exception as e:
            out.append(_check(fn.__name__, None, 'check failed: %s' % e))
    try:
        out += public_address(s)
    except Exception as e:
        out.append(_check('address', None, 'check failed: %s' % e))
    return out


def report_text(results):
    mark = {True: ' OK ', False: 'FAIL', None: ' -- '}
    lines = []
    for r in results:
        lines.append('[%s] %-20s %s' % (mark[r['ok']], r['id'], r['detail']))
        if r['fix']:
            lines.append('       fix: ' + r['fix'])
    bad = sum(r['ok'] is False for r in results)
    lines.append('\n%s' % ('All good.' if not bad else '%d problem(s) found.' % bad))
    return '\n'.join(lines)


def dump(results):
    return json.dumps(results, ensure_ascii=False)
