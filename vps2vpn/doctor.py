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
    return {'id': cid, 'ok': ok, 'detail': detail, 'fix': fix if ok is False else ''}


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
    t0 = time.time()
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection(('127.0.0.1', s['reality_port']), timeout=8) as raw:
            with ctx.wrap_socket(raw, server_hostname=s['reality_target']) as tls:
                ok = tls.version() == 'TLSv1.3'
                return [_check('reality_camouflage', ok, '%s, %d ms' % (tls.version(), (time.time() - t0) * 1000),
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
    n = cores.online_count(s)
    return [_check('hysteria_api', n is not None, 'online: %s' % n, 'systemctl restart %s' % cores.HY2_UNIT)]


def udp_listening(s):
    if not paths.LIVE:
        return []
    out = []
    for on, cid, port, prog, name in ((s['hy2_enabled'], 'hysteria_port', s['hy2_port'], 'hysteria', 'Hysteria'),
                                      (s['tuic_enabled'], 'tuic_port', s['tuic_port'], 'sing-box', 'TUIC')):
        if on:
            owner = system.port_owner('udp', port)
            out.append(_check(cid, prog in owner, 'UDP %d: %s' % (port, owner or 'nobody'),
                              'another program holds UDP %d; change the %s port in Settings' % (port, name)))
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
    if s['cert_mode'] == 'self':
        return [_check('certificate', True, 'self-signed (chosen in Settings)')]
    st = s['cert_status'] or 'not requested yet'
    return [_check('certificate', None, 'self-signed; Let\'s Encrypt: %s' % st[:160],
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
    host = s['public_host']
    if not certs.is_ip(host):
        try:
            ips = {a[4][0] for a in socket.getaddrinfo(host, None)}
        except OSError as e:
            return [_check('address', False, '%s does not resolve: %s' % (host, e), 'check the domain\'s DNS records')]
        now = system.public_ip()
        return [_check('address', (not now) or now in ips, '%s -> %s (this server: %s)' % (host, ', '.join(sorted(ips)), now or '?'),
                       'point the domain\'s A record at %s' % now)]
    now = system.public_ip()
    if not now:
        return [_check('address', None, 'could not look up this server\'s public IP')]
    return [_check('address', now == host, 'configured %s, actual %s' % (host, now),
                   'the server\'s IP changed: Settings > server address = %s (vps2vpn does this by itself within a day)' % now)]


def outbound():
    t0 = time.time()
    try:
        urllib.request.urlopen('https://www.gstatic.com/generate_204', timeout=8).read()
        return [_check('internet', True, '%d ms' % ((time.time() - t0) * 1000))]
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


def run_all():
    s = db.settings()
    out = []
    for fn in (services, reality_handshake, hysteria_api, udp_listening, port_hopping, certificate, kernel):
        try:
            out += fn(s)
        except Exception as e:      # a broken check must not hide the others
            out.append(_check(fn.__name__, None, 'check failed: %s' % e))
    for fn in (clock, outbound, resources, versions, rule_mirror):
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
