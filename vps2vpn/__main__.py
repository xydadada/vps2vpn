"""Command line: python3 -m vps2vpn <command>"""
import argparse
import getpass
import json
import os
import random
import re
import sys

from . import VERSION, certs, cores, db, doctor, jobs, paths, rules, secure, system, web


def free_port():
    for _ in range(50):
        p = random.randint(20000, 60000)
        if 20000 <= p <= 40000:      # keep clear of the default hopping range
            continue
        if system.port_free('tcp', p):      # checks IPv4 and IPv6, like the panel's dual-stack listener
            return p
    return 54321


def panel_url(s, setup=False):
    host = s['domain'] or s['public_host'] or '<server-ip>'
    h = '[%s]' % host if ':' in host else host
    url = 'https://%s:%d/%s/' % (h, s['panel_port'], s['panel_path'])
    if setup:
        tok = web.setup_token()
        if tok:
            url += '?setup=' + tok
    return url


def cmd_init(a):
    """First-time preparation, run by install.sh. Safe to run again."""
    paths.ensure_dirs()
    s = db.ensure_secrets()
    if not s['panel_port']:
        if a.port and not (1 <= a.port <= 65535 and system.port_free('tcp', a.port)):
            # asked for on purpose (V2V_PANEL_PORT, to keep the subscription links of a moved main server)
            sys.exit('panel port %d is not free on this server / 面板端口 %d 被占用' % (a.port, a.port))
        db.set_settings(panel_port=a.port or free_port())
    v6 = system.public_ip(v6=True)
    if v6:
        db.set_settings(public_ipv6=v6)
    ip = None if s['public_host'] else (system.public_ip() or v6)   # IPv6-only servers get their IPv6 address
    # #163: this is another process than the panel; the address lock's file lock makes the two take turns
    # between reading the address and writing its certificate
    with certs.address_lock():
        if ip and not db.settings()['public_host']:
            db.set_settings(public_host=ip)
        s = certs.ensure_self_signed_saved()
    if not s['setup_done'] and not web.setup_token():
        paths.write_atomic(web.SETUP_TOKEN_FILE, secure.token(16), 0o600)
    warnings = []
    if not s['setup_done']:
        best, _ = system.best_target()
        db.set_settings(reality_target=best)
        warnings += pick_ports(db.settings())
    elif not os.path.exists(paths.TUIC_CONFIG):     # upgrade from a version without TUIC
        warnings += pick_ports(db.settings(), keys=(('tuic_port', 'udp'),))
    # open the host firewall (incl. TCP 80 for the http-01 challenge) before asking Let's Encrypt
    system.tune_network(db.settings()['tune_network'])
    system.open_firewall(db.settings())
    s_cur = db.settings()
    cert_host = s_cur['domain'] or s_cur['public_host']
    if a.acme and s_cur['cert_mode'] == 'auto' and cert_host and not certs.trusted(cert_host):
        try:
            certs.issue(cert_host, s_cur['acme_email'])
            db.set_settings(cert_status='ok')
        except Exception as e:      # never fail the install over a certificate
            db.set_settings(cert_status='failed: %s' % str(e)[:200])
            print('Let\'s Encrypt: %s (using a self-signed certificate for now)' % e)
    if not system.port_free('tcp', 80) and not certs.trusted(cert_host):
        owner = system.port_owner('tcp', 80) or 'another program'
        warnings.append("TCP 80 is used by %s, so no free Let's Encrypt certificate yet (self-signed is used, "
                        "still encrypted). / 80 端口被 %s 占用，暂用自签名证书（照样加密）。" % (owner, owner))
    ai = None
    if a.auto:
        from . import aicheck
        try:
            ai = aicheck.run()          # ~1-10 s; shown by the deployer and used for the server's name
        except Exception:
            ai = None
    auto = quick_setup(ai) if a.auto and not db.settings()['setup_done'] else None
    s = db.settings()
    done = s['setup_done']
    cloud = system.cloud_provider()
    name, how = system.CLOUD_HINTS.get(cloud, ('', ''))
    out = {'url': panel_url(s, setup=not done), 'setup_done': done, 'ports': system.needed_ports(s),
           'warnings': warnings, 'cloud': name, 'cloud_firewall': how}
    if a.auto:
        out['auto'] = dict(auto or {}, **result_info(s))
        if ai:
            out['auto']['ai'] = ai_brief(ai)
    print(json.dumps(out, ensure_ascii=False))


def ai_brief(res):
    """The AI check in the shape the deployers show."""
    from . import aicheck
    ip = res.get('ip') or {}
    return {'summary': aicheck.summary(res), 'place': aicheck.place_name(res), 'country': res.get('country', ''),
            'org': ip.get('org', ''), 'kind': aicheck.KIND_TEXT.get(ip.get('kind', ''), ''),
            'sites': {k: res['sites'][k] for k in aicheck.SITES}, 'advice': res.get('advice', [])}


def quick_setup(ai=None):
    """Finish the first-time setup without the web wizard (used by the one-click deployers).
    Returns the new admin login; it is shown once by the deployer and stored only on the owner's computer."""
    pw = secure.token(12)
    db.set_settings(admin_user='admin', admin_hash=secure.hash_password(pw))
    if ai and db.settings()['node_name'] == 'vps2vpn':
        from . import aicheck
        place = re.sub(r'[\x00-\x1f\x7f#,=]', '', aicheck.place_name(ai) or '').strip()[:24]   # ends up in share links
        if place:
            db.set_settings(node_name=place)        # entries read "悉尼 Hysteria2" in the apps
    if not db.users():
        db.add_user('我' if db.settings()['language'] == 'zh' else 'me')
    db.set_settings(setup_done=True)
    try:
        os.unlink(web.SETUP_TOKEN_FILE)
    except OSError:
        pass
    return {'admin_user': 'admin', 'admin_password': pw}


def result_info(s):
    """What a deployer needs to show and remember: links for the first account and the join code."""
    from . import cluster, subscription
    host = s['domain'] or s['public_host'] or '<server-ip>'
    h = '[%s]' % host if ':' in host else host
    base = '%s://%s:%d' % ('https' if certs.trusted(host) else 'http', h, s['panel_port'])
    crt, _ = certs.current(s['domain'] or s['public_host'])
    try:
        pin = certs.fingerprint(crt)
    except (OSError, ValueError):
        pin = ''
    info = {'panel': panel_url(s), 'pin': pin, 'join_code': cluster.join_code(s, base),
            'name': s['node_name'] or s['public_host'], 'host': s['public_host'], 'checks': port_checks(s)}
    users = db.users()
    if users:
        u = users[0]
        sub = '%s/s/%s' % (base, u['sub_token'])
        info.update(user=u['name'], sub_url=sub, qr_url=sub + '/qr.svg',
                    links=subscription.import_links(sub, s['node_name'] or 'vps2vpn'))
    return info


def port_checks(s):
    """Ports a deployer should test from the outside, with a plain name for each."""
    out = [['tcp', s['panel_port'], '管理面板']]
    if s['reality_enabled']:
        out.append(['tcp', s['reality_port'], 'REALITY 线路（TCP）'])
    if s['hy2_enabled']:
        out.append(['udp', s['hy2_port'], 'Hysteria 2 高速线路（UDP）'])
    if s.get('tuic_enabled'):
        out.append(['udp', s['tuic_port'], 'TUIC 备用线路（UDP）'])
    return out


def pick_ports(s, keys=(('reality_port', 'tcp'), ('hy2_port', 'udp'), ('tuic_port', 'udp'))):
    """On a first install, move off ports another program (nginx, another panel...) already holds."""
    out, change = [], {}
    for key, proto in keys:
        port = s[key]
        taken = {change.get('hy2_port', s['hy2_port'])} if key == 'tuic_port' else set()
        if proto == 'tcp' and s['panel_port']:
            taken.add(s['panel_port'])           # the panel is not running yet during init, so binding would succeed
        if port not in taken and system.port_free(proto, port):
            continue
        owner = 'the vps2vpn panel' if proto == 'tcp' and port == s['panel_port'] else \
            (system.port_owner(proto, port) or 'another program')
        for alt in (8443, 2053, 2083, 2087, 2096, 9443):
            if system.port_free(proto, alt) and alt != s['panel_port'] and alt not in taken:
                change[key] = alt
                out.append('%s %d is used by %s; vps2vpn uses %d instead. / %s %d 端口被 %s 占用，改用 %d。'
                           % (proto.upper(), port, owner, alt, proto.upper(), port, owner, alt))
                break
    if change:
        db.set_settings(**change)
    return out


def cmd_serve(a):
    web.serve(a.port)


def cmd_apply(a):
    print('changed:', cores.apply(force=a.force) or 'nothing')


def cmd_info(a):
    s = db.settings()
    print('vps2vpn %s' % VERSION)
    print('panel:  %s' % panel_url(s, setup=not s['setup_done']))
    print('setup:  %s' % ('done' if s['setup_done'] else 'waiting - open the link above'))
    print('cert:   %s' % ('trusted (Let\'s Encrypt)' if certs.trusted(s['domain'] or s['public_host']) else 'self-signed'))
    print('users:  %d' % len(db.users()))
    print('ports:  %s' % ', '.join('%s/%s' % (p, proto) for proto, p in system.needed_ports(s)))


def cmd_reset_password(a):
    pw = a.password or getpass.getpass('new admin password: ')
    if not 8 <= len(pw) <= 128:            # sign-in refuses longer ones: that would lock the admin out
        sys.exit('password must be 8 to 128 characters')
    user = (a.username or db.settings()['admin_user']).strip()[:32]
    if not user or any(ord(c) < 32 or ord(c) == 127 for c in user):
        sys.exit('invalid username')
    db.set_settings(admin_hash=secure.hash_password(pw), admin_user=user)
    db.end_all_sessions()
    print('password changed, all sessions logged out')


def cmd_rules(a):
    print('updated %d rule files' % rules.refresh())


def cmd_cert(a):
    s = db.settings()
    host = s['domain'] or s['public_host']
    if not host:
        sys.exit('no server address or domain configured')
    try:
        certs.issue(host, s['acme_email'], staging=a.staging)
    except Exception as e:
        if not a.staging:
            db.set_settings(cert_status='failed: %s' % str(e)[:200])
        sys.exit('Let\'s Encrypt%s: %s' % (' (staging)' if a.staging else '', e))
    if a.staging:
        # a staging certificate is untrusted and stored aside: do not mark the real one ok or hand it to the cores
        print('staging certificate obtained (test only; nothing was changed)')
        return
    db.set_settings(cert_status='ok')
    print('changed:', cores.apply(force=True) or 'nothing')     # force: same config text, new certificate files


def cmd_doctor(a):
    res = doctor.run_all()
    print(doctor.dump(res) if a.json else doctor.report_text(res))
    sys.exit(1 if any(r['ok'] is False for r in res) else 0)


def cmd_bench(a):
    from . import bench
    print('server: %s' % bench.server_info())
    r = bench.run(None, a.quick)
    print(bench.table([('this server -> internet', r)]))
    print('\nThis is the most the server itself can do; speeds through the VPN cannot be higher.')


def cmd_backup(a):
    print(jobs.backup())


def cmd_sysctl(a):
    print(system.sysctl_text())


def main(argv=None):
    p = argparse.ArgumentParser(prog='vps2vpn', description='vps2vpn %s' % VERSION)
    sub = p.add_subparsers(dest='cmd', required=True)
    x = sub.add_parser('init', help='prepare a fresh install (used by install.sh)')
    x.add_argument('--port', type=int, default=0)
    x.add_argument('--acme', action='store_true', help='try a Let\'s Encrypt certificate right away')
    x.add_argument('--auto', action='store_true', help='finish setup without the web wizard and print the login')
    x.set_defaults(fn=cmd_init)
    x = sub.add_parser('serve', help='run the panel')
    x.add_argument('--port', type=int, default=0)
    x.set_defaults(fn=cmd_serve)
    x = sub.add_parser('apply', help='rewrite core configs and restart what changed')
    x.add_argument('--force', action='store_true')
    x.set_defaults(fn=cmd_apply)
    sub.add_parser('info', help='show the panel link and status').set_defaults(fn=cmd_info)
    x = sub.add_parser('reset-password', help='set a new admin password')
    x.add_argument('--username')
    x.add_argument('--password')
    x.set_defaults(fn=cmd_reset_password)
    sub.add_parser('rules', help='refresh the routing rule mirror').set_defaults(fn=cmd_rules)
    x = sub.add_parser('cert', help='get a Let\'s Encrypt certificate now')
    x.add_argument('--staging', action='store_true')
    x.set_defaults(fn=cmd_cert)
    x = sub.add_parser('doctor', help='check everything and say how to fix problems')
    x.add_argument('--json', action='store_true')
    x.set_defaults(fn=cmd_doctor)
    x = sub.add_parser('bench', help='measure this server\'s own speed to the internet')
    x.add_argument('--quick', action='store_true')
    x.set_defaults(fn=cmd_bench)
    sub.add_parser('backup', help='write a backup to /var/lib/vps2vpn/backups now').set_defaults(fn=cmd_backup)
    sub.add_parser('sysctl', help='print the kernel tuning this machine would get').set_defaults(fn=cmd_sysctl)
    a = p.parse_args(argv)
    a.fn(a)


if __name__ == '__main__':
    main()
