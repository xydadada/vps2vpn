"""Client subscriptions: Clash/mihomo (Clash Verge, FlClash, Mihomo Party, Stash...), sing-box
(sing-box apps, Hiddify, Karing...), a native Shadowrocket config (nodes + routing + DNS in one file)
and plain share links (v2rayN, NekoBox...). Entries of joined servers (see cluster.py) are included."""
import base64
import hashlib
import json
import re
import time
import urllib.parse

from . import certs, db, rules, system

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


def rate_label(label, rate):
    """'Tokyo' -> 'Tokyo x2' on a server whose traffic counts twice (what airport subscriptions show)."""
    return label if rate == 1 else '%s \u00d7%g' % (label, rate)


def server_nodes(s, tls, label, local_id, u):
    """Entries of one server. `s` holds its protocol settings, `local_id` is the user's id on that server."""
    out = []
    # Hysteria cannot hold one account to a speed: where that server enforces limits, a limited account
    # gets its other protocols only (unless Hysteria is all it has).
    skip_hy2 = (db.limit_mbps(u) > 0 and s.get('shaping') and (s['reality_enabled'] or s.get('tuic_enabled')))
    if s['hy2_enabled'] and not skip_hy2:
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
    from . import aicheck, cluster, cores, shaper
    # a slowed-down account gets only the servers that hold it to its speed: elsewhere it is switched off
    slowed = bool(u.get('throttled')) and not u.get('remote_id')
    main_rate = float(s.get('traffic_rate', 1)) if db.valid_rate(s.get('traffic_rate', 1)) else 1.0
    main_label = rate_label(s['node_name'] or 'vps2vpn', main_rate)
    out = []
    if db.allowed_on(u, db.MAIN_SERVER) and not (slowed and not cores.can_slow_here(s)):
        out = _ordered(s, server_nodes(dict(s, hy2_hop=system.hopping_listed(s), shaping=shaper.active()),
                                       tls_info(s), main_label, u['id'], u))
    # a server the owner marked "maintenance" (and announces: client_node_status) is left out of "Auto"
    from . import nodestatus
    marked = nodestatus.on(s)
    for n in out:
        n['ai_score'] = aicheck.score(aicheck.latest())
        n['rate'] = main_rate
        n['server_id'] = db.MAIN_SERVER
        n['maintenance'] = marked and nodestatus.of(s, db.MAIN_SERVER)['state'] == 'maintenance'
    seen_labels = {main_label}
    for x in s.get('servers') or []:
        info, lid = x.get('info'), (x.get('idmap') or {}).get(str(u['id']))
        if not x.get('enabled', True) or not info or lid is None or not db.allowed_on(u, x['id']):
            continue                       # not synced yet: the next sync (within a minute) adds it
        try:
            if slowed and not cluster.server_can_slow(info):
                continue
            label = rate_label(x['name'], cluster.server_rate(x))
            if label in seen_labels:
                label = rate_label('%s %s' % (x['name'], x['id'][:4]), cluster.server_rate(x))
            while label in seen_labels:
                label += '_'
            more = server_nodes(info, info.get('tls') or {'sni': info['public_host'], 'pin': '', 'pem': ''}, label, lid, u)
        except (KeyError, TypeError, ValueError, AttributeError) as e:
            # what a joined server reported lacks a field (another version, a damaged record): leave that
            # server out, so the member page and the subscription still work with the others
            _warn_bad_server(x, e)
            continue
        seen_labels.add(label)
        down = marked and nodestatus.current(x.get('status'))['state'] == 'maintenance'
        for n in more:
            n['ai_score'] = info.get('ai_score', -1)
            n['rate'] = cluster.server_rate(x)
            n['server_id'] = x['id']
            n['maintenance'] = down
        out += _ordered(s, more)
    if s.get('ipv4_only'):            # the old panel's ".ipv4.yaml" link
        out = [n for n in out if ':' not in n['server']]
    return out


_bad_warned = {}


def _warn_bad_server(x, e):
    """Log a joined server left out of subscriptions, at most once in 10 minutes per server."""
    sid, now = str(x.get('id', '?')), time.time()
    if now - _bad_warned.get(sid, 0) < 600:
        return
    _bad_warned[sid] = now
    from . import jobs
    jobs.log('warning: server %s (%s) left out of subscriptions, its info is incomplete: %r'
             % (x.get('name', '?'), sid, e))


def _ordered(s, entries):
    """One server's entries in the owner's line order. "TCP first" puts Reality (TCP) ahead of Hysteria 2 and
    TUIC (both UDP) for networks that slow UDP down; IPv4 entries stay ahead of their IPv6 copies."""
    if not s.get('tcp_first'):
        return entries
    return sorted(entries, key=lambda n: (n['name'].endswith(' IPv6'), n['type'] != 'reality'))


def server_groups(ns):
    """[(server label, [entry names])] in order; only interesting when there is more than one server."""
    groups = []
    for n in ns:
        if not groups or groups[-1][0] != n['group']:
            groups.append((n['group'], []))
        groups[-1][1].append(n['name'])
    return groups


def auto_servers(ns, per):
    """Server labels "Auto" may switch to. Not one whose traffic counts more than once (x2, x5): "Auto" picks by
    speed alone, and the member would burn quota several times as fast without ever choosing that server. It
    stays in the server list, with its rate in its name. When every server costs more, all of them.
    Not one marked "maintenance" either: it may still answer the speed test right up to the moment it goes away,
    and apps other than ours cannot see the status. It stays in the list to pick by hand; its node names do not
    change (the app matches api/me "nodes" to them). When every server is in maintenance, all of them."""
    rate, down = {}, {}
    for n in ns:
        rate.setdefault(n['group'], n.get('rate', 1))
        down.setdefault(n['group'], bool(n.get('maintenance')))
    pool = [label for label, _ in per if not down.get(label)] or [label for label, _ in per]
    cheap = [label for label in pool if rate.get(label, 1) <= 1]
    return cheap or pool


def ai_servers(ns, per):
    """Server labels for the AI group, the one whose address suits Claude / ChatGPT best first (this server
    wins ties). AI traffic then stays on one server - one address - instead of following "Auto" around:
    services like Claude are wary of accounts whose address keeps changing country."""
    score, down = {}, {}
    for n in ns:
        score.setdefault(n['group'], n.get('ai_score', -1))
        down.setdefault(n['group'], bool(n.get('maintenance')))
    # a server in maintenance last: it is the group's default choice when first
    return sorted((label for label, _ in per), key=lambda label: (down.get(label, False), -score.get(label, -1)))


def userinfo_header(u, quota_gb=None):
    """`quota_gb`: the effective quota (after what the account shares with invitees), where it is cut off.
    total=0 means unlimited to the apps, so a capped account that shared everything says 1 byte, not 0."""
    if not u['quota_gb']:
        total = 0
    else:
        quota = u['quota_gb'] if quota_gb is None else quota_gb
        total = max(1, int(quota * (1 << 30)))
    return 'upload=%d; download=%d; total=%d; expire=%d' % (u['used_up'], u['used_down'], total, u['expire_at'] or 0)


# Why an account gets no proxies: (Chinese, English). Shown as a placeholder entry and in the Announce header.
STATUS_TEXT = {
    'quota': ('流量已用完', 'Quota used up'),
    'expired': ('已到期', 'Expired'),
    'devices': ('设备过多，暂停中', 'Paused (too many devices)'),
}
DISABLED_TEXT = ('已停用', 'Disabled')
# The placeholder must never carry traffic: an unspecified address, a port nothing listens on, a dummy key,
# and the routing of a disabled profile rejects everything anyway.
PLACEHOLDER_HOST, PLACEHOLDER_PORT = '0.0.0.0', 1
PLACEHOLDER_UUID = '00000000-0000-0000-0000-000000000000'
# ASCII only: it goes out in an HTTP header (\U0010ffff, not \uffff: an emoji is outside the BMP).
SUPPORT_URL_RE = r'(?:https?://|tg://)[^\s<>"\x00-\x1f\x7f-\U0010ffff]{3,300}'


def status_text(u):
    """(zh, en) reason for a disabled account, or None while it works."""
    if u.get('enabled', 1):
        return None
    return STATUS_TEXT.get(u.get('disabled_reason') or '', DISABLED_TEXT)


# A working account close to its end: the apps that show `Announce` (Happ, Hiddify, Streisand...) say so,
# with the same thresholds as the member page.
WARN_DAYS = 7
WARN_USED = 0.9


def warning_text(u, quota_gb=None, now=None):
    """(zh, en) heads-up for a working account that expires within WARN_DAYS days or has used WARN_USED of
    its quota (`quota_gb`: the effective quota, defaults to the account's own), or None."""
    if not u.get('enabled', 1):
        return None
    now = time.time() if now is None else now
    parts = []
    exp = int(u.get('expire_at') or 0)
    if exp and now < exp <= now + WARN_DAYS * 86400:
        days = max(1, int(-(-(exp - now) // 86400)))          # 1.2 days left reads "2 days"
        date = time.strftime('%Y-%m-%d', time.localtime(exp))
        parts.append(('%d 天后到期（%s）' % (days, date), 'expires in %d day(s) on %s' % (days, date)))
    quota = u.get('quota_gb') if quota_gb is None else quota_gb
    if u.get('throttled') and u.get('throttle_mbps'):
        mbps = u['throttle_mbps']
        parts.append(('流量已用完，已降速到 %g Mbps' % mbps, 'quota used up, slowed down to %g Mbps' % mbps))
    elif quota and quota > 0:
        total = quota * (1 << 30)
        used = int(u.get('used_up') or 0) + int(u.get('used_down') or 0)
        if used >= WARN_USED * total:
            left = max(0.0, (total - used) / (1 << 30))
            parts.append(('流量只剩 %.2f GB' % left, '%.2f GB of data left' % left))
    if not parts:
        return None
    return ('，'.join(p[0] for p in parts), '; '.join(p[1] for p in parts))


UPDATE_HOURS_DEFAULT = 12


def update_hours(s):
    """Profile-Update-Interval in hours, from the `sub_update_hours` setting (1-168, anything else: 12)."""
    try:
        v = int(s.get('sub_update_hours') or UPDATE_HOURS_DEFAULT)
    except (TypeError, ValueError, OverflowError):
        return UPDATE_HOURS_DEFAULT
    return v if 1 <= v <= 168 else UPDATE_HOURS_DEFAULT


def placeholder_name(u):
    """Name of the unusable entry a disabled account sees in its app, or '' while it works."""
    st = status_text(u)
    return '%s %s - 请联系管理员 Contact admin' % st if st else ''


def header_b64(text):
    """`base64:` header form (Profile-Title, Announce): UTF-8 text survives, the value itself is ASCII."""
    return 'base64:' + base64.b64encode(str(text).encode('utf-8')).decode('ascii')


def safe_header(v):
    """A header value without CR/LF or any other control or non-ASCII character."""
    return ''.join(c for c in str(v) if 32 <= ord(c) < 127)


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


def placeholder_link(u):
    name = placeholder_name(u)
    if not name:
        return ''
    q = {'encryption': 'none', 'security': 'none', 'type': 'tcp'}
    return 'vless://%s@%s:%d?%s#%s' % (PLACEHOLDER_UUID, PLACEHOLDER_HOST, PLACEHOLDER_PORT,
                                      urllib.parse.urlencode(q), urllib.parse.quote(name))


def links_base64(s, u):
    # TUIC links have no certificate pinning, so they are only listed with a publicly trusted certificate
    lines = [share_link(n) for n in nodes(s, u) if n['type'] != 'tuic' or not n.get('pin')]
    if not lines and placeholder_link(u):
        lines = [placeholder_link(u)]      # a disabled account: one dead entry that names the reason
    text = '\n'.join(lines) + '\n'
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
                      'proxies': pn if not many else auto_servers(ns, per), 'url': 'https://www.gstatic.com/generate_204',
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
    if not pn:
        # No proxy nodes means no outbound routing or DNS lookups. The normal
        # DNS nameserver policy refers to remote rule providers and would be
        # invalid once those providers disappear. Do not configure them at all.
        dead = []
        ph = placeholder_name(u)
        if ph:
            # Only there to show the reason in the app: it points nowhere and the only rule is REJECT.
            dead = [{'name': ph, 'type': 'socks5', 'server': PLACEHOLDER_HOST, 'port': PLACEHOLDER_PORT}]
            groups[0]['proxies'] = [ph] + groups[0]['proxies']
        return dict({'mixed-port': 7890, 'allow-lan': False, 'mode': 'rule',
                     'log-level': 'warning', 'dns': {'enable': False},
                     'proxies': dead, 'proxy-groups': groups, 'rule-providers': {},
                     'rules': ['MATCH,REJECT']}, **_panel_pin(s))
    cn_dns = ['https://223.5.5.5/dns-query', 'https://1.12.12.12/dns-query']
    remote_dns = ['https://1.1.1.1/dns-query', 'https://8.8.8.8/dns-query']
    # in route_plan's order (first match wins): the named domains, then the Chinese lists
    ns_policy = {'+.' + d: cn_dns if where == 'local' else remote_dns for d, where in rules.dns_plan(s)}
    ns_policy['rule-set:cn,cn-download,steam-cn,apple-cn,microsoft-cn,private'] = cn_dns
    return {
        'mixed-port': 7890, 'allow-lan': False, 'mode': 'rule', 'log-level': 'warning', 'ipv6': True,
        'unified-delay': True, 'tcp-concurrent': True, 'find-process-mode': 'strict',
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
            # with respect-rules, names whose traffic goes DIRECT are resolved here instead of through the proxy
            'direct-nameserver': cn_dns,
            # Foreign lookups go through the proxy, so neither the ISP nor a Chinese resolver sees them.
            'nameserver': remote_dns,
            'nameserver-policy': ns_policy,
        },
        'proxies': proxies,
        'proxy-groups': groups,
        'rule-providers': providers,
        'rules': rule_lines,
        **_panel_pin(s),
    }


def _panel_pin(s):
    """With a self-signed certificate the vps2vpn app trusts the panel by this pin (mihomo ignores the key). The
    Hysteria 2 / TUIC entries carry it too, but a REALITY-only or a disabled account's subscription has none."""
    pin = tls_info(s)['pin']
    return {'x-vps2vpn-pin': pin} if pin else {}


def for_account(s, u):
    """The settings this account's subscription is built from: a paused one gets no proxies (only the usage
    header and the entry that says why)."""
    if u['enabled']:
        return s
    return dict(s, reality_enabled=False, hy2_enabled=False, tuic_enabled=False, servers=[])


def config_version(s, u, base_url):
    """A short value that changes whenever this account's subscription would: a server, port, key or name, the
    routing rules, the account being paused. api/me sends it, so our app (which reads api/me far more often than
    it refreshes the subscription) updates at once after a change instead of at the next refresh. Built from
    the Clash form, which holds everything the other formats do. The AI group's order follows the daily AI
    check, so it can also change once a day with nothing else changed."""
    body = json.dumps(clash(for_account(s, u), u, base_url), sort_keys=True, ensure_ascii=False, separators=(',', ':'))
    return hashlib.sha256(body.encode()).hexdigest()[:16]


def clash_yaml(s, u, base_url):
    """JSON is valid YAML 1.2, and every Clash/mihomo build reads it as a YAML profile."""
    # a comment line: a line break in the name (older panels let a rename through) would end it and add YAML
    name = re.sub(r'[\x00-\x1f\x7f\u0085  ]+', ' ', str(u['name']))
    return '# vps2vpn %s - %s\n' % (name, time.strftime('%Y-%m-%d %H:%M')) + \
        json.dumps(clash(s, u, base_url), ensure_ascii=False, indent=1)


# --- sing-box (1.12+ format) -----------------------------------------------------
def singbox(s, u, base_url):
    g = names(s)
    outs = []
    ns = nodes(s, u)
    for n in ns:
        if n['type'] == 'hy2':
            o = {'type': 'hysteria2', 'tag': n['name'], 'server': n['server'],
                 'password': n['password'], 'tls': {'enabled': True, 'server_name': n['sni'], 'alpn': ['h3']}}
            if n.get('pem'):
                o['tls']['certificate'] = n['pem'].strip().splitlines()
            if n.get('hop'):
                # sing-box uses either server_port or server_ports; with both it ignores the hopping range
                o['server_ports'] = [n['hop'].replace('-', ':')]
                o['hop_interval'] = '30s'
            else:
                o['server_port'] = n['port']
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
        # A disabled or exhausted subscription must not silently switch from
        # proxy to direct Internet access when all usable nodes disappear.
        dead = []
        ph = placeholder_name(u)
        if ph:
            # Shows the reason in the app; never used: the only route rule rejects everything.
            dead = [{'type': 'selector', 'tag': g['proxy'], 'outbounds': [ph], 'default': ph},
                    {'type': 'socks', 'tag': ph, 'server': PLACEHOLDER_HOST, 'server_port': PLACEHOLDER_PORT}]
        return {
            'log': {'level': 'warn'},
            'inbounds': [
                {'type': 'tun', 'tag': 'tun-in', 'address': ['172.19.0.1/30', 'fdfe:dcba:9876::1/126'],
                 'auto_route': True, 'strict_route': True, 'stack': 'mixed'},
                {'type': 'mixed', 'tag': 'mixed-in', 'listen': '127.0.0.1', 'listen_port': 7890},
            ],
            'outbounds': [{'type': 'direct', 'tag': 'direct'}] + dead,
            'route': {'rules': [{'action': 'reject'}], 'final': 'direct', 'auto_detect_interface': True},
        }
    per = server_groups(ns)
    many = len(per) > 1
    if tags:
        allowed = set(auto_servers(ns, per)) if many else None
        auto_group = {'type': 'urltest', 'tag': g['auto'],
                      'outbounds': [t for t, n in zip(tags, ns) if allowed is None or n['group'] in allowed],
                      'url': 'https://www.gstatic.com/generate_204', 'interval': '5m', 'tolerance': 150}
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
    # in route_plan's order (first match wins): the named domains, one rule per run going to the same resolver,
    # then the Chinese lists
    dns_rules = []
    for d, where in rules.dns_plan(s):
        if dns_rules and dns_rules[-1]['server'] == where:
            dns_rules[-1]['domain_suffix'].append(d)
        else:
            dns_rules.append({'domain_suffix': [d], 'server': where})
    dns_rules.append({'rule_set': cn_sets, 'server': 'local'})
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
    # Text names can come from a joined node's join code. Unlike JSON/YAML,
    # Shadowrocket's INI-like syntax treats raw newlines as new records.
    safe = re.sub(r'[\x00-\x1f\x7f\u0085\u2028\u2029]+', ' ', str(text))
    return safe.replace(',', ' ').replace('=', '-').strip()


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
    # Credentials bypass _sr_safe for comma escaping; never emit record separators.
    if any(re.search(r'[\x00-\x1f\x7f\u0085\u2028\u2029]', str(v)) for _, v in params):
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
    ph = _sr_label(placeholder_name(u)) if not ok else ''
    if ph:
        # Shows the reason in the app; points nowhere and the only rule is FINAL,REJECT.
        lines.append('%s = socks5, %s, %d' % (ph, PLACEHOLDER_HOST, PLACEHOLDER_PORT))
    raw_per = server_groups(ok)
    per = [(_sr_label(label), [_sr_name(n) for n in ok if n['group'] == label]) for label, _ in raw_per]
    many = len(per) > 1
    test = 'url=http://www.gstatic.com/generate_204, interval=120, timeout=5'
    groups = ['%s = select, %s' % (g['proxy'], ', '.join(([ph] if ph else []) + [g['auto']] +
                                                         ([p[0] for p in per] if many else []) + pn))]
    if many:
        allowed = set(auto_servers(ok, raw_per))
        groups.append('%s = url-test, %s, %s, tolerance=80' % (
            g['auto'], ', '.join(p[0] for p, (raw, _) in zip(per, raw_per) if raw in allowed), test))
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
    if not pn:
        # Ordinary DIRECT routing rules must not remain active after every
        # proxy has been withdrawn.
        rule_lines = ['FINAL,REJECT,dns-failed']
    general = [
        '[General]',
        'bypass-system = true',
        'skip-proxy = 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, 100.64.0.0/10, 127.0.0.1, localhost, *.local, captive.apple.com',
        'tun-excluded-routes = 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, '
        '192.0.2.0/24, 192.88.99.0/24, 192.168.0.0/16, 198.51.100.0/24, 203.0.113.0/24, 224.0.0.0/4, 255.255.255.255/32, '
        'fc00::/7, fe80::/10, ff00::/8, ::1/128',
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
        _sr_label(u['name']), time.strftime('%Y-%m-%d %H:%M'))
    return head + '\n'.join(general) + '\n\n[Proxy]\n' + '\n'.join(lines) + '\n\n[Proxy Group]\n' + \
        '\n'.join(groups) + '\n\n[Rule]\n' + '\n'.join(rule_lines) + '\n'


# --- choose a format from the client's User-Agent ---------------------------------
def detect_format(ua, wanted='', accept=None):
    """'' means "show the web page". `accept` is the Accept header: when given, only a client asking for
    text/html gets the page, and any app we do not recognise (Happ, Streisand, V2Box...) the plain share
    links. Without it an unknown User-Agent means a browser, as before."""
    if wanted in ('clash', 'singbox', 'links', 'shadowrocket'):
        return wanted
    ua = (ua or '').lower()
    if any(k in ua for k in ('sing-box', 'singbox', 'hiddify', 'karing', 'sfa', 'sfi', 'sfm')):
        return 'singbox'
    # 'meta' alone: Clash.Meta builds, but not Facebook's and Instagram's in-app browser ("MetaIAB").
    if (any(k in ua for k in ('clash', 'mihomo', 'stash', 'flclash', 'verge', 'nyanpasu'))
            or re.search(r'(?<![a-z])meta(?!iab)', ua)):
        return 'clash'
    if any(k in ua for k in ('shadowrocket', 'v2ray', 'nekobox', 'nekoray', 'quantumult', 'surge', 'loon')):
        return 'links'
    if accept is not None and 'text/html' not in accept.lower():
        return 'links'      # an unknown app: the generic share-link list imports almost everywhere
    return ''      # a browser: show the landing page


def render(fmt, s, u, base_url, quota_gb=None):
    """(content_type, body, extra_headers). `quota_gb`: the account's effective quota (after what it shares
    with invitees), used for the low-data heads-up; defaults to its own quota."""
    title = s['node_name'] or 'vps2vpn'
    qname = urllib.parse.quote(title, safe='')
    headers = {'Subscription-Userinfo': userinfo_header(u, quota_gb), 'Profile-Update-Interval': str(update_hours(s)),
               'Content-Disposition': "attachment; filename*=UTF-8''%s" % qname,
               'Profile-Title': header_b64(title),
               # the person's own page (usage, requests); a browser opening the subscription link gets it
               'Profile-Web-Page-Url': safe_header('%s/s/%s' % (base_url, u['sub_token'])),
               'Cache-Control': 'no-store'}
    support = s.get('support_url') or ''
    if support and re.fullmatch(SUPPORT_URL_RE, support):
        headers['Support-Url'] = support
    st = status_text(u)
    if st:
        headers['Announce'] = header_b64('%s %s - 请联系管理员 / Contact the admin' % st)
    else:
        from . import nodestatus
        warn = warning_text(u, quota_gb)
        if warn:
            headers['Announce'] = header_b64('%s，续期或加流量请联系管理员 / Account %s - contact the admin' % warn)
        elif nodestatus.on(s):
            # the apps that show Announce (Hiddify, Happ...) say which server is down for maintenance; the node
            # list itself never changes for it (docs/phase2-api.md 3.3)
            m = nodestatus.maintenance_text(s, u)
            if m:
                headers['Announce'] = header_b64('维护中 / Maintenance: %s' % m)
    if fmt == 'clash':
        return 'text/yaml; charset=utf-8', clash_yaml(s, u, base_url), headers
    if fmt == 'singbox':
        return 'application/json; charset=utf-8', json.dumps(singbox(s, u, base_url), ensure_ascii=False, indent=1), headers
    if fmt == 'shadowrocket':
        headers['Content-Disposition'] = "attachment; filename*=UTF-8''%s.conf" % qname
        return 'text/plain; charset=utf-8', shadowrocket(s, u, base_url, '%s/s/%s' % (base_url, u['sub_token'])), headers
    return 'text/plain; charset=utf-8', links_base64(s, u), headers


def import_links(sub_url, name):
    """One-tap import URLs for common apps."""
    q = urllib.parse.quote(sub_url, safe='')
    qn = urllib.parse.quote(name, safe='')
    b64 = base64.b64encode(sub_url.encode()).decode()
    return {
        # our own client (Windows): opens it and imports in one click
        'vps2vpn': 'vps2vpn://install-config?url=%s&name=%s' % (urllib.parse.quote(sub_url + '?format=clash', safe=''), qn),
        'clash': 'clash://install-config?url=%s&name=%s' % (urllib.parse.quote(sub_url + '?format=clash', safe=''), qn),
        'shadowrocket': 'shadowrocket://add/sub://%s?remark=%s' % (b64, qn),
        # the full config (nodes + routing + DNS), not just a node list
        'shadowrocket_conf': 'shadowrocket://config/add/%s' % urllib.parse.quote(sub_url + '?format=shadowrocket', safe=''),
        'singbox': 'sing-box://import-remote-profile?url=%s#%s' % (urllib.parse.quote(sub_url + '?format=singbox', safe=''), qn),
        'hiddify': 'hiddify://import/%s#%s' % (urllib.parse.quote(sub_url + '?format=singbox', safe=''), qn),
        'v2rayng': 'v2rayng://install-sub?url=%s&name=%s' % (q, qn),
        # iPhone apps besides Shadowrocket: Stash reads the Clash config, Karing picks its format by User-Agent
        'stash': 'stash://install-config?url=%s&name=%s' % (urllib.parse.quote(sub_url + '?format=clash', safe=''), qn),
        'karing': 'karing://install-config?url=%s&name=%s' % (q, qn),
    }
