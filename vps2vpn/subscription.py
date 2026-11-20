"""Client subscriptions: Clash/mihomo (Clash Verge, FlClash, Mihomo Party, Stash...), sing-box
(sing-box apps, Hiddify, Karing...), a native Shadowrocket config (nodes + routing + DNS in one file)
and plain share links (v2rayN, NekoBox...). Entries of joined servers (see cluster.py) are included."""
import base64
import json
import time
import urllib.parse

from . import certs, rules

GROUP_NAMES = {
    'zh': {'proxy': '节点选择', 'auto': '自动选择', 'ai': 'AI服务', 'cn': '国内服务', 'final': '漏网之鱼'},
    'en': {'proxy': 'Proxy', 'auto': 'Auto', 'ai': 'AI', 'cn': 'China', 'final': 'Final'},
}


def names(s):
    return GROUP_NAMES.get(s.get('language'), GROUP_NAMES['zh'])


def tls_info(s):
    """What clients need to trust Hysteria's certificate."""
    host = s.get('domain') or s['public_host']
    if certs.trusted(host):
        return {'sni': host, 'pin': '', 'pem': ''}
    cert, _ = certs.current(host)
    try:
        with open(cert, encoding='utf-8') as f:
            pem = f.read()
        return {'sni': host, 'pin': certs.fingerprint(cert), 'pem': pem}
    except OSError:
        return {'sni': host, 'pin': '', 'pem': ''}


def server_nodes(s, tls, label, local_id, u):
    """Entries of one server. `s` holds its protocol settings, `local_id` is the user's id on that server."""
    out = []
    if s['hy2_enabled']:
        n = {'type': 'hy2', 'name': '%s Hysteria2' % label, 'server': s['public_host'], 'port': s['hy2_port'],
             # Hysteria's userpass auth expects "user:password" from the client
             'password': 'u%d:%s' % (local_id, u['hy2_pass']), 'obfs': s['hy2_obfs'], **tls}
        if s['hy2_hop']:
            n['hop'] = s['hy2_hop_range'].replace(':', '-').replace(' ', '')
        out.append(n)
    if s['reality_enabled']:
        out.append({'type': 'reality', 'name': '%s Reality' % label, 'server': s['public_host'],
                    'port': s['reality_port'], 'uuid': u['uuid'], 'sni': s['reality_target'],
                    'pbk': s['reality_public_key'], 'sid': s['reality_short_id']})
    if s.get('tuic_enabled'):
        out.append({'type': 'tuic', 'name': '%s TUIC' % label, 'server': s['public_host'], 'port': s['tuic_port'],
                    'uuid': u['uuid'], 'password': u['hy2_pass'], **tls})
    if s.get('ipv6_nodes') and s.get('public_ipv6') and ':' not in s['public_host']:
        # Same proxies over IPv6: useful where the IPv4 route is congested or blocked. TLS names stay the same.
        out += [dict(n, server=s['public_ipv6'], name=n['name'] + ' IPv6') for n in list(out)]
    for n in out:
        n['group'] = label
    return out


def nodes(s, u):
    """Protocol-neutral description of this user's proxies: this server first, then joined servers."""
    from . import aicheck
    main_label = s['node_name'] or 'vps2vpn'
    out = server_nodes(s, tls_info(s), main_label, u['id'], u)
    for n in out:
        n['ai_score'] = aicheck.score(aicheck.latest())
    seen_labels = {main_label}
    for x in s.get('servers') or []:
        info, lid = x.get('info'), (x.get('idmap') or {}).get(str(u['id']))
        if not x.get('enabled', True) or not info or lid is None:
            continue                       # not synced yet: the next sync (within a minute) adds it
        label = x['name']
        if label in seen_labels:
            label = '%s %s' % (x['name'], x['id'][:4])
        while label in seen_labels:
            label += '_'
        seen_labels.add(label)
        more = server_nodes(info, info.get('tls') or {'sni': info['public_host'], 'pin': '', 'pem': ''}, label, lid, u)
        for n in more:
            n['ai_score'] = info.get('ai_score', -1)
        out += more
    return out


def server_groups(ns):
    """[(server label, [entry names])] in order; only interesting when there is more than one server."""
    groups = []
    for n in ns:
        if not groups or groups[-1][0] != n['group']:
            groups.append((n['group'], []))
        groups[-1][1].append(n['name'])
    return groups


def ai_servers(ns, per):
    """Server labels for the AI group, the one whose address suits Claude / ChatGPT best first (this server
    wins ties). AI traffic then stays on one server - one address - instead of following "Auto" around:
    services like Claude are wary of accounts whose address keeps changing country."""
    score = {}
    for n in ns:
        score.setdefault(n['group'], n.get('ai_score', -1))
    return sorted((label for label, _ in per), key=lambda label: -score.get(label, -1))


def userinfo_header(u):
    total = int(u['quota_gb'] * (1 << 30)) if u['quota_gb'] else 0
    return 'upload=%d; download=%d; total=%d; expire=%d' % (u['used_up'], u['used_down'], total, u['expire_at'] or 0)


# --- share links ------------------------------------------------------------------
def share_link(n):
    tag = urllib.parse.quote(n['name'])
    if n['type'] == 'tuic':
        q = {'sni': n['sni'], 'alpn': 'h3', 'congestion_control': 'bbr', 'udp_relay_mode': 'native'}
        return 'tuic://%s:%s@%s:%d?%s#%s' % (n['uuid'], urllib.parse.quote(n['password'], safe=''), _host(n['server']),
                                            n['port'], urllib.parse.urlencode(q), tag)
    if n['type'] == 'reality':
        q = {'encryption': 'none', 'flow': 'xtls-rprx-vision', 'security': 'reality', 'sni': n['sni'],
             'fp': 'chrome', 'pbk': n['pbk'], 'sid': n['sid'], 'type': 'tcp', 'headerType': 'none'}
        return 'vless://%s@%s:%d?%s#%s' % (n['uuid'], _host(n['server']), n['port'], urllib.parse.urlencode(q), tag)
    q = {'sni': n['sni']}
    if n.get('pin'):
        q['pinSHA256'] = n['pin']
        q['insecure'] = '1'        # some apps only accept a pinned self-signed cert this way
    if n.get('obfs'):
        q['obfs'] = 'salamander'
        q['obfs-password'] = n['obfs']
    if n.get('hop'):
        q['mport'] = n['hop']
    return 'hysteria2://%s@%s:%d/?%s#%s' % (urllib.parse.quote(n['password'], safe=''), _host(n['server']),
                                           n['port'], urllib.parse.urlencode(q), tag)


def _host(h):
    return '[%s]' % h if ':' in h else h


def links_base64(s, u):
    # TUIC links have no certificate pinning, so they are only listed with a publicly trusted certificate
    text = '\n'.join(share_link(n) for n in nodes(s, u) if n['type'] != 'tuic' or not n.get('pin')) + '\n'
    return base64.b64encode(text.encode()).decode()


# --- Clash / mihomo -----------------------------------------------------------------
def clash(s, u, base_url):
    g = names(s)
    proxies = []
    ns = nodes(s, u)
    for n in ns:
        if n['type'] == 'hy2':
            p = {'name': n['name'], 'type': 'hysteria2', 'server': n['server'], 'port': n['port'],
                 'password': n['password'], 'sni': n['sni'], 'skip-cert-verify': False, 'alpn': ['h3']}
            if n.get('pin'):
                p['fingerprint'] = n['pin']
            if n.get('hop'):
                p['ports'] = n['hop']
                p['hop-interval'] = 30
            if n.get('obfs'):
                p.update({'obfs': 'salamander', 'obfs-password': n['obfs']})
        elif n['type'] == 'tuic':
            p = {'name': n['name'], 'type': 'tuic', 'server': n['server'], 'port': n['port'], 'uuid': n['uuid'],
                 'password': n['password'], 'sni': n['sni'], 'alpn': ['h3'], 'skip-cert-verify': False,
                 'congestion-controller': 'bbr', 'udp-relay-mode': 'native', 'reduce-rtt': True,
                 'request-timeout': 8000}
            if n.get('pin'):
                p['fingerprint'] = n['pin']
        else:
            p = {'name': n['name'], 'type': 'vless', 'server': n['server'], 'port': n['port'], 'uuid': n['uuid'],
                 'network': 'tcp', 'udp': True, 'tls': True, 'flow': 'xtls-rprx-vision', 'servername': n['sni'],
                 'client-fingerprint': 'chrome', 'reality-opts': {'public-key': n['pbk'], 'short-id': n['sid']}}
        proxies.append(p)
    pn = [p['name'] for p in proxies]
    per = server_groups(ns)
    many = len(per) > 1
    if pn:
        auto_group = {'name': g['auto'], 'type': 'fallback' if not many else 'url-test',
                      'proxies': pn if not many else [x[0] for x in per], 'url': 'https://www.gstatic.com/generate_204',
                      'interval': 300, 'lazy': True, **({'tolerance': 80} if many else {})}
    else:
        # Disabled accounts carry no proxies; keep a valid non-empty group so mihomo still loads Subscription-Userinfo.
        auto_group = {'name': g['auto'], 'type': 'select', 'proxies': ['REJECT']}
    groups = [
        {'name': g['proxy'], 'type': 'select', 'proxies': [g['auto']] + ([x[0] for x in per] if many else []) + pn},
        # Hysteria 2 first: it copes best with lossy routes; Reality takes over when UDP is blocked.
        auto_group,
    ]
    if many:      # one group per server: its protocols in fallback order; "Auto" picks the fastest server
        groups += [{'name': label, 'type': 'fallback', 'proxies': members, 'url': 'https://www.gstatic.com/generate_204',
                    'interval': 300, 'lazy': True} for label, members in per]
    if s.get('ai_group', True):
        groups.append({'name': g['ai'], 'type': 'select',
                       'proxies': (ai_servers(ns, per) if many else []) + [g['proxy']] + pn})
    groups += [{'name': g['cn'], 'type': 'select', 'proxies': ['DIRECT', g['proxy']]},
               {'name': g['final'], 'type': 'select', 'proxies': [g['proxy'], 'DIRECT']}]
    target = {'proxy': g['proxy'], 'direct': 'DIRECT', 'reject': 'REJECT', 'ai': g['ai'], 'cn': g['cn'],
              'final': g['final']}
    providers, rule_lines = {}, []
    for kind, value, to in rules.route_plan(s):
        t = target[to]
        if kind == 'set':
            providers[value] = {'type': 'http', 'behavior': rules.mrs_behavior(value), 'format': 'mrs',
                                'url': '%s/rules/%s.mrs' % (base_url, value), 'path': './vps2vpn/%s.mrs' % value,
                                'interval': 86400, 'proxy': 'DIRECT'}
            line = 'RULE-SET,%s,%s' % (value, t)
            if rules.mrs_behavior(value) == 'ipcidr':
                line += ',no-resolve'
            rule_lines.append(line)
        elif kind == 'suffix':
            rule_lines.append('DOMAIN-SUFFIX,%s,%s' % (value, t))
        else:
            rule_lines.append('MATCH,%s' % t)
    cn_dns = ['https://223.5.5.5/dns-query', 'https://1.12.12.12/dns-query']
    ns_policy = {'rule-set:cn,cn-download,steam-cn,apple-cn,microsoft-cn,private': cn_dns}
    for d in list(rules.CN_DIRECT_SUFFIX) + list(s.get('custom_direct') or []):
        ns_policy['+.' + d] = cn_dns
    return {
        'mixed-port': 7890, 'allow-lan': False, 'mode': 'rule', 'log-level': 'warning', 'ipv6': True,
        'unified-delay': True, 'tcp-concurrent': True, 'find-process-mode': 'strict',
        'global-client-fingerprint': 'chrome',
        'profile': {'store-selected': True, 'store-fake-ip': True},
        'sniffer': {'enable': True, 'sniff': {'HTTP': {'ports': [80, '8080-8880'], 'override-destination': True},
                                              'TLS': {'ports': [443, 8443]}, 'QUIC': {'ports': [443, 8443]}},
                    'skip-domain': ['Mijia Cloud', '+.push.apple.com']},
        'dns': {
            'enable': True, 'ipv6': True, 'enhanced-mode': 'fake-ip', 'fake-ip-range': '198.18.0.1/16',
            'fake-ip-filter': ['*.lan', '*.local', 'localhost.ptlogin2.qq.com', '+.msftconnecttest.com',
                               '+.msftncsi.com', 'time.*.com', 'ntp.*.com', '+.stun.*.*', '+.stun.*.*.*'],
            'respect-rules': True,
            'default-nameserver': ['223.5.5.5', '119.29.29.29'],
            'proxy-server-nameserver': cn_dns,
            # Foreign lookups go through the proxy, so neither the ISP nor a Chinese resolver sees them.
            'nameserver': ['https://1.1.1.1/dns-query', 'https://8.8.8.8/dns-query'],
            'nameserver-policy': ns_policy,
        },
        'proxies': proxies,
        'proxy-groups': groups,
        'rule-providers': providers,
        'rules': rule_lines,
    }


def clash_yaml(s, u, base_url):
    """JSON is valid YAML 1.2, and every Clash/mihomo build reads it as a YAML profile."""
    return '# vps2vpn %s - %s\n' % (u['name'], time.strftime('%Y-%m-%d %H:%M')) + \
        json.dumps(clash(s, u, base_url), ensure_ascii=False, indent=1)


# --- sing-box (1.12+ format) -----------------------------------------------------
def singbox(s, u, base_url):
    g = names(s)
    outs = []
    ns = nodes(s, u)
    for n in ns:
        if n['type'] == 'hy2':
            o = {'type': 'hysteria2', 'tag': n['name'], 'server': n['server'], 'server_port': n['port'],
                 'password': n['password'], 'tls': {'enabled': True, 'server_name': n['sni'], 'alpn': ['h3']}}
            if n.get('pem'):
                o['tls']['certificate'] = n['pem'].strip().splitlines()
            if n.get('hop'):
                o['server_ports'] = [n['hop'].replace('-', ':')]
                o['hop_interval'] = '30s'
            if n.get('obfs'):
                o['obfs'] = {'type': 'salamander', 'password': n['obfs']}
        elif n['type'] == 'tuic':
            o = {'type': 'tuic', 'tag': n['name'], 'server': n['server'], 'server_port': n['port'], 'uuid': n['uuid'],
                 'password': n['password'], 'congestion_control': 'bbr', 'udp_relay_mode': 'native', 'zero_rtt_handshake': False,
                 'tls': {'enabled': True, 'server_name': n['sni'], 'alpn': ['h3']}}
            if n.get('pem'):
                o['tls']['certificate'] = n['pem'].strip().splitlines()
        else:
            o = {'type': 'vless', 'tag': n['name'], 'server': n['server'], 'server_port': n['port'], 'uuid': n['uuid'],
                 'flow': 'xtls-rprx-vision', 'packet_encoding': 'xudp',
                 'tls': {'enabled': True, 'server_name': n['sni'], 'utls': {'enabled': True, 'fingerprint': 'chrome'},
                         'reality': {'enabled': True, 'public_key': n['pbk'], 'short_id': n['sid']}}}
        outs.append(o)
    tags = [o['tag'] for o in outs]
    if not tags:
        # Never fall back to a direct outbound when the subscription has no
        # active nodes. This is especially important for a disabled account:
        # loading an otherwise-valid TUN config must not leak traffic.
        return {
            'log': {'level': 'warn'},
            'inbounds': [
                {'type': 'tun', 'tag': 'tun-in', 'address': ['172.19.0.1/30', 'fdfe:dcba:9876::1/126'],
                 'auto_route': True, 'strict_route': True, 'stack': 'mixed'},
                {'type': 'mixed', 'tag': 'mixed-in', 'listen': '127.0.0.1', 'listen_port': 7890},
            ],
            'outbounds': [{'type': 'direct', 'tag': 'direct'}],
            'route': {'rules': [{'action': 'reject'}], 'auto_detect_interface': True},
        }
    per = server_groups(ns)
    many = len(per) > 1
    if tags:
        auto_group = {'type': 'urltest', 'tag': g['auto'], 'outbounds': tags, 'url': 'https://www.gstatic.com/generate_204',
                      'interval': '5m', 'tolerance': 150}
    else:
        auto_group = {'type': 'selector', 'tag': g['auto'], 'outbounds': ['direct'], 'default': 'direct'}
    groups = [{'type': 'selector', 'tag': g['proxy'], 'outbounds': [g['auto']] + ([x[0] for x in per] if many else []) + tags,
               'default': g['auto']},
              auto_group]
    if many:
        groups += [{'type': 'urltest', 'tag': label, 'outbounds': members, 'url': 'https://www.gstatic.com/generate_204',
                    'interval': '5m', 'tolerance': 150} for label, members in per]
    if s.get('ai_group', True):
        first = ai_servers(ns, per) if many else []
        groups.append({'type': 'selector', 'tag': g['ai'], 'outbounds': first + [g['proxy']] + tags,
                       'default': (first or [g['proxy']])[0]})
    groups += [{'type': 'selector', 'tag': g['cn'], 'outbounds': ['direct', g['proxy']]},
               {'type': 'selector', 'tag': g['final'], 'outbounds': [g['proxy'], 'direct']}]
    target = {'proxy': g['proxy'], 'direct': 'direct', 'ai': g['ai'], 'cn': g['cn'], 'final': g['final']}
    route_rules = [{'action': 'sniff'}, {'protocol': 'dns', 'action': 'hijack-dns'},
                   {'ip_is_private': True, 'outbound': 'direct'}]
    rule_sets, final = [], g['final']
    for kind, value, to in rules.route_plan(s):
        if kind == 'final':
            final = target[to]
            continue
        rule = {'rule_set': value} if kind == 'set' else {'domain_suffix': [value]}
        if to == 'reject':
            rule['action'] = 'reject'
        else:
            rule['outbound'] = target[to]
        route_rules.append(rule)
        if kind == 'set':
            rule_sets.append({'type': 'remote', 'tag': value, 'format': 'binary',
                              'url': '%s/rules/%s.srs' % (base_url, value), 'download_detour': 'direct',
                              'update_interval': '1d'})
    cn_sets = ['private', 'cn', 'cn-download', 'steam-cn', 'apple-cn', 'microsoft-cn']
    direct_suffixes = list(rules.CN_DIRECT_SUFFIX) + list(s.get('custom_direct') or [])
    dns_rules = [{'rule_set': cn_sets, 'server': 'local'}]
    if direct_suffixes:
        dns_rules.append({'domain_suffix': direct_suffixes, 'server': 'local'})
    return {
        'log': {'level': 'warn'},
        'dns': {
            'servers': [
                {'type': 'https', 'tag': 'remote', 'server': '1.1.1.1', 'detour': g['proxy']},
                {'type': 'https', 'tag': 'local', 'server': '223.5.5.5'},
            ],
            'rules': dns_rules,
            'final': 'remote', 'strategy': 'prefer_ipv4',
        },
        'inbounds': [
            {'type': 'tun', 'tag': 'tun-in', 'address': ['172.19.0.1/30', 'fdfe:dcba:9876::1/126'],
             'auto_route': True, 'strict_route': True, 'stack': 'mixed'},
            {'type': 'mixed', 'tag': 'mixed-in', 'listen': '127.0.0.1', 'listen_port': 7890},
        ],
        'outbounds': groups + outs + [{'type': 'direct', 'tag': 'direct'}],
        'route': {'rules': route_rules, 'rule_set': rule_sets, 'final': final, 'auto_detect_interface': True,
                  'default_domain_resolver': 'local'},
        'experimental': {'cache_file': {'enabled': True}},
    }


# --- Shadowrocket (native config: nodes + groups + rules + DNS in one file) ------------------
def _sr_safe(v):
    v = str(v)
    if any(c in v for c in '\r\n,='):
        raise ValueError('field not allowed in a Shadowrocket line: %r' % v[:20])
    return v


def _sr_pin(fp):
    """Shadowrocket hpkp = SHA-256 of the certificate DER, written AA:BB:..."""
    fp = fp.replace(':', '').upper()
    return ':'.join(fp[i:i + 2] for i in range(0, 64, 2)) if len(fp) == 64 else ''


def _sr_label(text):
    return str(text).replace(',', ' ').replace('=', '-')


def _sr_name(n):
    return _sr_label(n['name'])


def shadowrocket_proxy(n):
    """One [Proxy] line, or None for an entry Shadowrocket cannot express safely."""
    host = _sr_safe(n['server'])
    if n['type'] == 'reality':
        params = [('password', n['uuid']), ('tls', 'true'), ('peer', n['sni']), ('pbk', n['pbk']), ('sid', n['sid']),
                  ('xtls', '2'), ('fingerprint', 'chrome'), ('udp', '1')]
        head = 'vless, %s, %d' % (host, n['port'])
    elif n['type'] in ('hy2', 'tuic'):
        if n['type'] == 'hy2' and n.get('obfs'):
            return None                       # salamander is Clash/sing-box only here
        common = [('udp', '1'), ('peer', n['sni']), ('alpn', 'h3')]
        if n.get('pin'):
            common.append(('hpkp', _sr_pin(n['pin'])))
        if n['type'] == 'hy2':
            # No port hopping: its "443,20000-40000" form collides with the comma-separated line.
            head, params = 'hysteria2, %s, %d' % (host, n['port']), [('auth', n['password'])] + common
        else:
            head = 'tuic, %s, %d' % (host, n['port'])
            params = [('password', n['password']), ('user', n['uuid'])] + common + \
                [('congestion_control', 'bbr'), ('udp_relay_mode', 'native')]
    else:
        return None
    return '%s = %s, %s' % (_sr_name(n), head, ', '.join('%s=%s' % (k, _sr_safe(v) if k != 'auth' and k != 'password'
                                                                       else str(v).replace(',', '%2C'))
                                                          for k, v in params))


def shadowrocket(s, u, base_url, sub_url=''):
    g = names(s)
    ns = nodes(s, u)
    lines, ok = [], []
    for n in ns:
        line = shadowrocket_proxy(n)
        if line:
            lines.append(line)
            ok.append(n)
    pn = [_sr_name(n) for n in ok]
    raw_per = server_groups(ok)
    per = [(_sr_label(label), [_sr_name(n) for n in ok if n['group'] == label]) for label, _ in raw_per]
    many = len(per) > 1
    test = 'url=http://www.gstatic.com/generate_204, interval=120, timeout=5'
    groups = ['%s = select, %s' % (g['proxy'], ', '.join([g['auto']] + ([p[0] for p in per] if many else []) + pn))]
    if many:
        groups.append('%s = url-test, %s, %s, tolerance=80' % (g['auto'], ', '.join(p[0] for p in per), test))
        groups += ['%s = fallback, %s, %s' % (label, ', '.join(m), test) for label, m in per if m]
    else:
        groups.append('%s = fallback, %s, %s' % (g['auto'], ', '.join(pn) or 'REJECT', test))
    if s.get('ai_group', True):
        ai_labels = [_sr_label(l) for l in ai_servers(ok, raw_per)] if many else []
        groups.append('%s = select, %s' % (g['ai'], ', '.join(ai_labels + [g['proxy']] + pn)))
    groups += ['%s = select, DIRECT, %s' % (g['cn'], g['proxy']), '%s = select, %s, DIRECT' % (g['final'], g['proxy'])]
    target = {'proxy': g['proxy'], 'direct': 'DIRECT', 'reject': 'REJECT', 'ai': g['ai'], 'cn': g['cn'],
              'final': g['final']}
    rule_lines = []
    for kind, value, to in rules.route_plan(s):
        t = target[to]
        if kind == 'set':
            line = 'RULE-SET,%s/rules/%s.list,%s' % (base_url, value, t)
            if rules.mrs_behavior(value) == 'ipcidr':
                line += ',no-resolve'
            rule_lines.append(line)
        elif kind == 'suffix':
            rule_lines.append('DOMAIN-SUFFIX,%s,%s' % (value, t))
        else:
            rule_lines.append('FINAL,%s,dns-failed' % t)
    general = [
        '[General]',
        'bypass-system = true',
        'skip-proxy = 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, 100.64.0.0/10, 127.0.0.1, localhost, *.local, captive.apple.com',
        'tun-excluded-routes = 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, '
        '192.0.2.0/24, 192.88.99.0/24, 192.168.0.0/16, 198.51.100.0/24, 203.0.113.0/24, 224.0.0.0/4, 255.255.255.255/32',
        # Chinese resolvers only see Chinese names: foreign names are sent to the proxy unresolved.
        'dns-server = https://223.5.5.5/dns-query, https://1.12.12.12/dns-query',
        'fallback-dns-server = system',
        'ipv6 = true',
        'prefer-ipv6 = false',
        'dns-direct-system = false',
        'icmp-auto-reply = true',
        'always-reject-url-rewrite = false',
        'private-ip-answer = true',
        'dns-direct-fallback-proxy = true',
        'udp-policy-not-supported-behaviour = REJECT',
    ]
    if sub_url:
        general.append('update-url = %s?format=shadowrocket' % sub_url)
    head = '# vps2vpn %s - %s\n# Nodes, routing and DNS in one file. Pick this config, set Global Routing to "Config".\n' % (
        u['name'], time.strftime('%Y-%m-%d %H:%M'))
    return head + '\n'.join(general) + '\n\n[Proxy]\n' + '\n'.join(lines) + '\n\n[Proxy Group]\n' + \
        '\n'.join(groups) + '\n\n[Rule]\n' + '\n'.join(rule_lines) + '\n'


# --- choose a format from the client's User-Agent ---------------------------------
def detect_format(ua, wanted=''):
    if wanted in ('clash', 'singbox', 'links', 'shadowrocket'):
        return wanted
    ua = (ua or '').lower()
    if any(k in ua for k in ('sing-box', 'singbox', 'hiddify', 'karing', 'sfa', 'sfi', 'sfm')):
        return 'singbox'
    if any(k in ua for k in ('clash', 'mihomo', 'stash', 'flclash', 'verge', 'meta', 'nyanpasu')):
        return 'clash'
    if any(k in ua for k in ('shadowrocket', 'v2ray', 'nekobox', 'nekoray', 'quantumult', 'surge', 'loon')):
        return 'links'
    return ''      # a browser: show the landing page


def render(fmt, s, u, base_url):
    """(content_type, body, extra_headers)"""
    headers = {'Subscription-Userinfo': userinfo_header(u), 'Profile-Update-Interval': '12',
               'Content-Disposition': "attachment; filename*=UTF-8''%s" % urllib.parse.quote(s['node_name'] or 'vps2vpn'),
               'Cache-Control': 'no-store'}
    if fmt == 'clash':
        return 'text/yaml; charset=utf-8', clash_yaml(s, u, base_url), headers
    if fmt == 'singbox':
        return 'application/json; charset=utf-8', json.dumps(singbox(s, u, base_url), ensure_ascii=False, indent=1), headers
    if fmt == 'shadowrocket':
        headers['Content-Disposition'] = "attachment; filename*=UTF-8''%s.conf" % urllib.parse.quote(s['node_name'] or 'vps2vpn')
        return 'text/plain; charset=utf-8', shadowrocket(s, u, base_url, '%s/s/%s' % (base_url, u['sub_token'])), headers
    return 'text/plain; charset=utf-8', links_base64(s, u), headers


def import_links(sub_url, name):
    """One-tap import URLs for common apps."""
    q = urllib.parse.quote(sub_url, safe='')
    qn = urllib.parse.quote(name, safe='')
    b64 = base64.b64encode(sub_url.encode()).decode()
    return {
        'clash': 'clash://install-config?url=%s&name=%s' % (urllib.parse.quote(sub_url + '?format=clash', safe=''), qn),
        'shadowrocket': 'shadowrocket://add/sub://%s?remark=%s' % (b64, qn),
        # the full config (nodes + routing + DNS), not just a node list
        'shadowrocket_conf': 'shadowrocket://config/add/%s' % (sub_url + '?format=shadowrocket'),
        'singbox': 'sing-box://import-remote-profile?url=%s#%s' % (urllib.parse.quote(sub_url + '?format=singbox', safe=''), qn),
        'hiddify': 'hiddify://import/%s#%s' % (sub_url + '?format=singbox', qn),
        'v2rayng': 'v2rayng://install-sub?url=%s&name=%s' % (q, qn),
    }
