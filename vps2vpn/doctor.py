"""Self-check ("一键体检"): finds the usual reasons a VPN stops working and says how to fix them.

Every check returns {id, ok, detail, fix, key, args}. ok is True, False, or None (could not tell / not applicable).
`detail` and `fix` are English (the command line and logs); `key` and `args` let localized() say the same in
the panel's language, keeping the English as the original.
"""
import json
import os
import shutil
import socket
import ssl
import time
import urllib.request

from . import XRAY_VERSION, certs, cores, db, paths, rules, system


def _check(cid, ok, detail='', fix='', key='', **args):
    return {'id': cid, 'ok': ok, 'detail': detail, 'fix': fix if ok is not True else '', 'key': key, 'args': args}


def services(s):
    out = []
    for name, unit, on in (('panel', 'vps2vpn', True), ('xray', cores.XRAY_UNIT, s['reality_enabled']),
                           ('hysteria', cores.HY2_UNIT, s['hy2_enabled']), ('tuic', cores.TUIC_UNIT, s['tuic_enabled'])):
        if not on:
            continue
        a = system.unit_active(unit)
        out.append(_check('service_' + name, a, unit, 'journalctl -u %s -n 50   then: vps2vpn apply --force' % unit,
                          'unit', unit=unit))
    return out


def reality_handshake(s):
    """Unauthenticated TLS to our REALITY port must be forwarded to the camouflage site and show its certificate."""
    if not s['reality_enabled']:
        return []
    if system.unit_active(cores.XRAY_UNIT) is False:
        return [_check('reality_camouflage', None, 'skipped: Xray is not running (see above)', key='skip_xray')]
    t0 = time.monotonic()
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection(('127.0.0.1', s['reality_port']), timeout=8) as raw:
            with ctx.wrap_socket(raw, server_hostname=s['reality_target']) as tls:
                ok = tls.version() == 'TLSv1.3'
                ms = int((time.monotonic() - t0) * 1000)
                return [_check('reality_camouflage', ok, '%s, %d ms' % (tls.version(), ms),
                               'pick another camouflage site in Settings', 'tls', ver=tls.version(), ms=ms)]
    except ssl.SSLCertVerificationError as e:
        return [_check('reality_camouflage', False, 'certificate mismatch: %s' % e,
                       'the camouflage site sent an unexpected certificate; pick another site in Settings', 'cert_mismatch')]
    except OSError as e:
        return [_check('reality_camouflage', False, str(e)[:160],
                       'Xray is not answering, or this server cannot reach %s. Pick another camouflage site.' % s['reality_target'],
                       'reality_down', target=s['reality_target'])]


def hysteria_api(s):
    if not s['hy2_enabled']:
        return []
    if system.unit_active(cores.HY2_UNIT) is False:
        return [_check('hysteria_api', None, 'skipped: Hysteria is not running (see above)', key='skip_hy2')]
    try:
        req = urllib.request.Request('http://127.0.0.1:%d/online' % s['hy2_stats_port'],
                                     headers={'Authorization': s['stats_secret']})
        with urllib.request.urlopen(req, timeout=2) as resp:
            data = json.loads(resp.read())
        if not isinstance(data, dict):
            raise ValueError('unexpected /online reply: %s' % type(data).__name__)
        n = sum(1 for v in data.values() if isinstance(v, (int, float, str)) and int(v or 0) > 0)
        return [_check('hysteria_api', True, 'online: %d' % n, key='hy2_online', n=n)]
    except (OSError, ValueError, TypeError) as e:
        return [_check('hysteria_api', False, str(e)[:120], 'systemctl restart %s' % cores.HY2_UNIT, 'hy2_silent')]


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
            out.append(_check(cid, prog in owner, 'UDP %d: %s' % (port, owner or 'nobody'), fix,
                              'udp_owner' if owner else 'udp_nobody', port=port, owner=owner))
    return out


def port_hopping(s):
    if not (s['hy2_enabled'] and s['hy2_hop'] and paths.LIVE):
        return []
    r = system.run(['nft', 'list', 'table', 'inet', system.NFT_TABLE])
    return [_check('port_hopping', r.returncode == 0 and 'redirect' in r.stdout, s['hy2_hop_range'],
                   'vps2vpn apply --force   (needs the nftables package)', 'hop', range=s['hy2_hop_range'])]


def certificate(s):
    host = s['domain'] or s['public_host']
    if certs.trusted(host):
        return [_check('certificate', certs.acme_valid(24), "Let's Encrypt for %s" % host,
                       'expires within a day and renewal is failing: open TCP 80, then run  vps2vpn cert',
                       'le', host=host)]
    # Apps other than the vps2vpn client cannot pin a self-signed certificate, so subscription links fall back
    # to plain HTTP and the account credentials in them cross the network readable. Say so.
    if s['cert_mode'] == 'self':
        return [_check('certificate', None, 'self-signed (chosen in Settings): subscription links use plain HTTP',
                       'switch the certificate to automatic so subscriptions are encrypted', 'self_chosen')]
    st = s['cert_status'] or 'not requested yet'
    return [_check('certificate', None, 'self-signed, so subscription links use plain HTTP; '
                                        'Let\'s Encrypt: %s' % st[:160],
                   'open TCP 80 in the provider firewall, then press "Get certificate now"',
                   'self_failed' if s['cert_status'].startswith('failed') else 'self_pending')]


def kernel(s):
    on = system.bbr_active()
    out = [_check('bbr', on, 'tcp_congestion_control', 'vps2vpn apply   (kernel may be too old for BBR)',
                  'bbr_on' if on else 'bbr_off' if on is False else '')]
    try:
        with open('/proc/sys/net/core/rmem_max') as f:
            v = int(f.read())
        out.append(_check('udp_buffers', v >= 7 << 20, 'rmem_max = %d' % v,
                          'turn on "Automatic network tuning" in Settings', 'rmem', mb=round(v / (1 << 20), 1)))
    except OSError:
        pass
    return out


def clock():
    if not paths.LIVE or not shutil.which('timedatectl'):
        return []
    r = system.run(['timedatectl', 'show', '-p', 'NTPSynchronized', '--value'])
    v = r.stdout.strip()
    return [_check('clock', v == 'yes', 'NTP synchronized: %s' % (v or '?'), 'timedatectl set-ntp true',
                   'ntp_yes' if v == 'yes' else 'ntp_no')]


def public_address(s):
    host = (s.get('domain') or s.get('public_host') or '').strip()
    if not host:
        return [_check('address', False, 'server address is not configured', 'set the server address in Settings',
                       'addr_unset')]
    if not certs.is_ip(host):
        try:
            ips = {certs._norm_host(a[4][0].split('%', 1)[0]) for a in socket.getaddrinfo(host, None)}
        except OSError as e:
            return [_check('address', False, '%s does not resolve: %s' % (host, e), 'check the domain\'s DNS records',
                           'dns_fail', host=host)]
        mine = [ip for ip in (system.public_ip(),) if ip]
        if not any(certs._norm_host(ip) in ips for ip in mine):
            mine += [ip for ip in (system.public_ip(v6=True),) if ip]     # IPv6-only / AAAA-only setups
        got = ', '.join(sorted(ips))
        if not mine:
            return [_check('address', None, '%s -> %s (could not look up this server\'s public IP)' % (host, got),
                           key='dns_noip', host=host, ips=got)]
        ok = any(certs._norm_host(ip) in ips for ip in mine)
        return [_check('address', ok, '%s -> %s (this server: %s)' % (host, got, ', '.join(mine)),
                       'point the domain\'s %s record at %s' % ('AAAA' if ':' in mine[0] else 'A', mine[0]),
                       'dns_match', host=host, ips=got, mine=', '.join(mine), rec='AAAA' if ':' in mine[0] else 'A')]
    v6 = ':' in host                     # an IPv6-only server must be compared with its IPv6 egress address
    now = system.public_ip(v6=v6)
    if not now:
        return [_check('address', None, 'could not look up this server\'s public IP', key='ip_unknown')]
    return [_check('address', certs._norm_host(now) == certs._norm_host(host), 'configured %s, actual %s' % (host, now),
                   'the server\'s IP changed: Settings > server address = %s (vps2vpn does this by itself within a day)' % now,
                   'ip_compare', host=host, now=now)]


def outbound():
    t0 = time.monotonic()
    try:
        with urllib.request.urlopen('https://www.gstatic.com/generate_204', timeout=8) as r:
            r.read()
        ms = int((time.monotonic() - t0) * 1000)
        return [_check('internet', True, '%d ms' % ms, key='ms', ms=ms)]
    except OSError as e:
        return [_check('internet', False, str(e)[:160], 'this server cannot reach the internet; check its network / DNS',
                       'net_fail')]


def resources():
    out = []
    try:
        st = os.statvfs('/')
        free = st.f_bavail * st.f_frsize
        out.append(_check('disk', free > 300 << 20, '%d MB free' % (free >> 20), 'free some disk space',
                          'disk', mb=free >> 20))
    except (OSError, AttributeError):
        pass
    h = system.health()
    if h.get('mem_total'):
        used = h['mem_used'] / h['mem_total']
        out.append(_check('memory', used < 0.92, '%d%% used' % (used * 100), 'upgrade the plan or reduce other programs',
                          'mem', pct=int(used * 100)))
    return out


def versions():
    try:
        with open(os.path.join(os.path.dirname(paths.XRAY_BIN), '.xray-version')) as f:
            v = f.read().strip()
    except OSError:
        return []
    return [_check('xray_version', v == XRAY_VERSION, v, 'bash install.sh   (re-run to get the tested version %s)' % XRAY_VERSION,
                   'xray_ver', v=v, want=XRAY_VERSION)]


def rule_mirror():
    age = rules.mirror_age()
    return [_check('rules', age is not None and age < 3 * 86400,
                   'updated %s hours ago' % (age // 3600) if age is not None else 'never',
                   'press "Update routing rules now"; the server needs to reach github.com',
                   'rules_age' if age is not None else 'rules_never', h=age // 3600 if age is not None else 0)]


def speed_limits():
    """Accounts with a speed limit on a server that cannot hold them to it."""
    from . import shaper
    # the accounts this server's cores serve (not those only on other servers, nor a slowed-down one sent to
    # servers that can hold it to its speed)
    limited = [u for u in cores.active_users() if db.limit_mbps(u) > 0]
    if not limited:
        return []
    n = len(limited)
    if shaper.active():
        st = shaper.status()
        ok = not st['error']
        # `vps2vpn doctor` runs in its own process, where nothing has been applied yet: name the card it would use
        dev = st['dev'] or shaper.default_dev()
        detail, key = st['error'], 'limits_err'
        if ok and not (dev and shaper.intact(dev)):
            # checked on the machine itself (card, ifb device, ingress redirect, nft rule): this process applied
            # nothing, the panel may have failed to, or a firewall reload took part of it away
            ok, detail, key = False, 'the speed limits are not (fully) set up on %s' % (dev or 'the network card'), 'limits_partial'
        return [_check('speed_limits', ok, '%d account%s limited on %s' % (n, '' if n == 1 else 's', dev) if ok else detail,
                       'vps2vpn apply --force   (then see journalctl -u vps2vpn)',
                       'limits_ok' if ok else key, n=n, dev=dev or '')]
    if not shaper.available():
        return [_check('speed_limits', None, '%d account%s a speed limit, but this kernel has no tc/ifb '
                       '(container VPS?): they run at full speed' % (n, ' has' if n == 1 else 's have'),
                       key='limits_unsupported', n=n)]
    return [_check('speed_limits', False, 'the Xray/TUIC services may not mark traffic yet',
                   'bash install.sh   (re-run once: it lets the cores mark limited accounts)', 'limits_nomark')]


def run_all():
    s = db.settings()
    out = []
    for fn in (services, reality_handshake, hysteria_api, udp_listening, port_hopping, certificate, kernel):
        try:
            out += fn(s)
        except Exception as e:      # a broken check must not hide the others
            out.append(_check(fn.__name__, None, 'check failed: %s' % e, key='check_failed'))
    for fn in (clock, outbound, resources, versions, rule_mirror, speed_limits):
        try:
            out += fn()
        except Exception as e:
            out.append(_check(fn.__name__, None, 'check failed: %s' % e, key='check_failed'))
    try:
        out += public_address(s)
    except Exception as e:
        out.append(_check('address', None, 'check failed: %s' % e, key='check_failed'))
    return out


# --- the panel's language -----------------------------------------------------------------------------
# id -> (name, what to do when it fails). Plain words: the person reading this may not run commands.
ZH_NAMES = {
    'service_panel': ('面板服务', ''),
    'service_xray': ('REALITY 服务（Xray）', '点击下方「重启代理服务」；仍然不行，就在服务器上运行 vps2vpn doctor 查看详情'),
    'service_hysteria': ('Hysteria 2 服务', '点击下方「重启代理服务」；仍然不行，可能是 UDP 端口被占用，请在设置中更换端口'),
    'service_tuic': ('TUIC 服务（sing-box）', '点击下方「重启代理服务」；仍然不行，可能是 UDP 端口被占用，请在设置中更换端口'),
    'reality_camouflage': ('伪装网站可用', '在「协议与设置」中点击「自动挑选最快的伪装网站」，然后保存'),
    'hysteria_api': ('Hysteria 2 响应', '点击「重启代理服务」'),
    'hysteria_port': ('UDP 端口归属', '这个 UDP 端口被其他程序占用，请在设置中更换端口'),
    'tuic_port': ('TUIC 端口归属', '这个 UDP 端口被其他程序占用，请在设置中更换 TUIC 端口'),
    'port_hopping': ('端口跳跃规则', '点击「重启代理服务」重新写入规则'),
    'certificate': ('证书', '在云服务商防火墙中放行 TCP 80，再到设置中点击「立即申请证书」；不放行也能使用，自签名同样加密'),
    'bbr': ('BBR 加速', '在设置中打开「自动网络调优」；内核太旧时需要升级系统'),
    'udp_buffers': ('UDP 缓冲区', '在设置中打开「自动网络调优」'),
    'clock': ('系统时间同步', '时间不准会导致无法连接；在服务器上运行 timedatectl set-ntp true'),
    'internet': ('服务器访问外网', '服务器自己无法访问外网，请检查云服务商的网络和 DNS 设置'),
    'disk': ('磁盘空间', '清理磁盘空间'),
    'memory': ('内存', '关闭服务器上其他占用内存的程序，或升级套餐'),
    'xray_version': ('内核版本', '在服务器上重新运行一次安装命令'),
    'rules': ('分流规则', '点击「立即更新分流规则」；服务器需要能访问 github.com'),
    'address': ('服务器地址', 'IP 变化后，vps2vpn 会在一天内自动更新；如需立即生效，请在设置中把服务器地址改成新 IP'),
    'speed_limits': ('按账号限速', '在服务器上重新运行一次安装命令，让内核服务可以标记限速账号；容器 VPS 不支持限速，这些账号按全速使用'),
    # a check that failed by itself is reported under its function's name
    'services': ('服务', ''), 'reality_handshake': ('伪装网站可用', ''), 'udp_listening': ('UDP 端口归属', ''),
    'kernel': ('内核参数', ''), 'outbound': ('服务器访问外网', ''), 'resources': ('磁盘和内存', ''),
    'versions': ('内核版本', ''), 'rule_mirror': ('分流规则', ''),
}


def _hours_zh(a):
    return '不到 1 小时前更新' if not a.get('h') else '%d 小时前更新' % a['h']


ZH_DETAIL = {
    'unit': '服务名 {unit}',
    'skip_xray': '已跳过：Xray 没有运行（见上一项）',
    'skip_hy2': '已跳过：Hysteria 没有运行（见上一项）',
    'tls': '{ver}，耗时 {ms} ms',
    'cert_mismatch': '伪装网站返回的证书不对',
    'reality_down': 'Xray 没有响应，或者这台服务器访问不了 {target}',
    'hy2_online': '当前在线 {n} 个连接',
    'hy2_silent': 'Hysteria 2 的统计接口没有响应',
    'udp_owner': 'UDP {port} 由 {owner} 占用',
    'udp_nobody': 'UDP {port} 上没有程序在监听',
    'hop': '端口范围 {range}',
    'le': '{host} 使用 Let\'s Encrypt 证书',
    'self_chosen': '自签名证书（在设置中选择）：订阅链接使用 HTTP，不加密',
    'self_pending': '自签名证书：订阅链接使用 HTTP，不加密；还没有申请 Let\'s Encrypt 证书',
    'self_failed': '自签名证书：订阅链接使用 HTTP，不加密；申请 Let\'s Encrypt 证书失败',
    'bbr_on': '已开启 BBR',
    'bbr_off': '没有使用 BBR',
    'rmem': '接收缓冲区上限 {mb} MB',
    'ntp_yes': '已与时间服务器同步',
    'ntp_no': '没有与时间服务器同步',
    'addr_unset': '还没有设置服务器地址',
    'dns_fail': '域名 {host} 解析失败',
    'dns_noip': '{host} 解析到 {ips}（查不到本机的公网 IP）',
    'dns_match': '{host} 解析到 {ips}（本机 {mine}）',
    'ip_unknown': '查不到本机的公网 IP',
    'ip_compare': '设置的地址 {host}，实际 {now}',
    'ms': '耗时 {ms} ms',
    'net_fail': '访问外网失败',
    'disk': '剩余 {mb} MB',
    'mem': '已用 {pct}%',
    'xray_ver': '当前 {v}，测试过的版本 {want}',
    'rules_age': _hours_zh,
    'rules_never': '从未更新',
    'limits_ok': '{n} 个账号在网卡 {dev} 上限速',
    'limits_partial': '限速没有完全生效（网卡 {dev}）',
    'limits_err': '限速设置失败',
    'limits_unsupported': '{n} 个账号设置了限速，但内核不支持 tc/ifb（可能是容器 VPS），这些账号按全速使用',
    'limits_nomark': '内核服务可能还不能标记限速账号的流量',
    'check_failed': '这一项检查本身出错了',
}
ZH_PLAIN = {True: '正常', False: '有问题', None: '无法判断'}


def localized(results, lang):
    """The results as the panel shows them: name, detail and fix in `lang`; `orig` is the English detail when it
    was translated (the panel shows it on hover / a click). English keeps the server's own text."""
    out = []
    for r in results:
        r = dict(r)
        if lang == 'en':
            r.update(name=r['id'].replace('_', ' '), orig='')
            out.append(r)
            continue
        name, fix = ZH_NAMES.get(r['id'], (r['id'].replace('_', ' '), ''))
        tpl, args = ZH_DETAIL.get(r.get('key') or ''), r.get('args') or {}
        try:
            zh = tpl(args) if callable(tpl) else tpl.format(**args) if tpl else ''
        except (KeyError, IndexError, ValueError):
            zh = ''
        if not zh and r.get('detail'):
            zh = ZH_PLAIN[r['ok']]                      # no translation: a word, and the original on hover
        r.update(name=name, orig=r.get('detail') or '', detail=zh,
                 fix=(fix or r.get('fix') or '') if r['ok'] is False else '')
        out.append(r)
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
