"""Offline tests. Run from the repository root:  python -m unittest tests.test_unit tests.test_features tests.test_admin tests.test_deploy tests.test_ops -v"""
import base64
import http.client
import json
import os
import shutil
import ssl
import sys
import tempfile
import threading
import time
import unittest
import urllib.parse

ROOT = tempfile.mkdtemp(prefix='v2v-test-')
os.environ['VPS2VPN_ROOT'] = ROOT
os.environ['VPS2VPN_DEV'] = '1'
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vps2vpn import certs, cores, db, doctor, jobs, notify, qr, rules, secure, subscription, system, web  # noqa: E402

# Finishing the setup starts a real rule download in a thread; on Windows its half-written files then block
# the next test from deleting the data folder. Tests never need the real rule files.
rules.refresh_in_background = lambda log=print: None


def tearDownModule():
    db.close()
    shutil.rmtree(ROOT, ignore_errors=True)


class Secure(unittest.TestCase):
    def test_x25519_rfc7748_vector(self):
        priv = bytes.fromhex('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a')
        pub = secure.x25519(priv, (9).to_bytes(32, 'little'))
        self.assertEqual(pub.hex(), '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a')

    def test_shared_secret_agrees(self):
        a, b = os.urandom(32), os.urandom(32)
        base = (9).to_bytes(32, 'little')
        self.assertEqual(secure.x25519(a, secure.x25519(b, base)), secure.x25519(b, secure.x25519(a, base)))

    def test_password(self):
        h = secure.hash_password('correct horse')
        self.assertTrue(secure.check_password('correct horse', h))
        self.assertFalse(secure.check_password('wrong', h))
        self.assertFalse(secure.check_password('x', 'garbage'))
        self.assertFalse(secure.hmac_eq('', ''))


class QR(unittest.TestCase):
    def test_sizes(self):
        self.assertEqual(len(qr.matrix('a')), 21)
        self.assertEqual(len(qr.matrix("x" * 100)), 4 * 6 + 17)
        self.assertIn('<svg', qr.svg('https://example.com/s/abc'))
        with self.assertRaises(ValueError):
            qr.matrix('x' * 5000)


class Base(unittest.TestCase):
    def setUp(self):
        db.close()
        if os.path.exists(ROOT):
            shutil.rmtree(ROOT)
        db.ensure_secrets()
        db.set_settings(public_host='203.0.113.7', panel_port=54321)
        certs.ensure_self_signed('203.0.113.7')


class Settings(Base):
    def test_defaults_and_secrets(self):
        s = db.settings()
        self.assertEqual(len(secure.b64url_decode(s['reality_private_key'])), 32)
        self.assertEqual(secure.reality_public_key(s['reality_private_key']), s['reality_public_key'])
        self.assertEqual(len(s['reality_short_id']), 16)
        db.ensure_secrets()
        self.assertEqual(db.settings()['reality_private_key'], s['reality_private_key'])   # never regenerated

    def test_validate(self):
        s = db.settings()
        self.assertIsInstance(web.validate_settings({'public_host': 'not a host!'}, s), str)
        self.assertIsInstance(web.validate_settings({'reality_enabled': False, 'hy2_enabled': False, 'tuic_enabled': False}, s), str)
        self.assertIsInstance(web.validate_settings({'reality_enabled': False, 'hy2_enabled': False}, s), dict)   # TUIC alone is fine
        self.assertIsInstance(web.validate_settings({'tuic_port': s['hy2_port']}, s), str)       # same UDP port twice
        self.assertIsInstance(web.validate_settings({'tuic_port': 30000}, s), str)               # inside hop range
        self.assertIsInstance(web.validate_settings({'hy2_port': 25000}, s), str)        # inside hop range
        self.assertIsInstance(web.validate_settings({'hy2_hop_range': '80-90'}, s), str)
        ok = web.validate_settings({'domain': 'Vpn.Example.com', 'hy2_obfs': 'random', 'node_name': 'a#b\nc'}, s)
        self.assertEqual(ok['public_host'], 'vpn.example.com')
        self.assertEqual(len(ok['hy2_obfs']), 16)
        self.assertEqual(ok['node_name'], 'abc')


class Users(Base):
    def test_limits(self):
        uid = db.add_user('alice', quota_gb=1)
        db.add_traffic(uid, 600 << 20, 500 << 20)
        self.assertTrue(jobs.enforce())
        u = db.user(uid)
        self.assertEqual((u['enabled'], u['disabled_reason']), (0, 'quota'))
        db.update_user(uid, quota_gb=0)
        self.assertTrue(jobs.enforce())
        self.assertEqual(db.user(uid)['enabled'], 1)
        db.update_user(uid, expire_at=int(time.time()) - 5)
        jobs.enforce()
        self.assertEqual(db.user(uid)['disabled_reason'], 'expired')
        db.update_user(uid, enabled=0, disabled_reason='manual', expire_at=0)
        jobs.enforce()
        self.assertEqual(db.user(uid)['enabled'], 0)       # manual pause is never undone automatically

    def test_monthly_reset(self):
        uid = db.add_user('bob', reset_day=1)
        db.add_traffic(uid, 10, 20)
        jobs.enforce()
        u = db.user(uid)
        self.assertEqual(u['used_up'] + u['used_down'], 0)
        db.add_traffic(uid, 10, 20)
        jobs.enforce()
        self.assertEqual(db.user(uid)['used_down'], 20)    # only once per month

    def test_backup_roundtrip(self):
        db.add_user('carol', quota_gb=5)
        data = json.loads(json.dumps(db.export_all()))
        db.delete_user(db.users()[0]['id'])
        db.import_all(data)
        self.assertEqual([u['name'] for u in db.users()], ['carol'])
        self.assertEqual(db.users()[0]['enabled'], 1)


class Subscriptions(Base):
    def test_formats(self):
        from vps2vpn import cores
        uid = db.add_user('dave')
        s, u = db.settings(), db.user(uid)
        c = subscription.clash(s, u, 'https://203.0.113.7:54321')
        names = [p['name'] for p in c['proxies']]
        self.assertEqual(len(names), 3)
        hy = c['proxies'][0]
        self.assertEqual(hy['type'], 'hysteria2')
        self.assertEqual(hy['ports'], '20000-40000')
        self.assertEqual(len(hy['fingerprint']), 64)
        self.assertEqual(c['rules'][-1], 'MATCH,漏网之鱼')
        used = {r.split(',')[1] for r in c['rules'] if r.startswith('RULE-SET')}
        self.assertEqual(used, set(c['rule-providers']))
        self.assertTrue(all(p['url'].startswith('https://203.0.113.7:54321/rules/') for p in c['rule-providers'].values()))
        sb = subscription.singbox(s, u, 'https://203.0.113.7:54321')
        self.assertEqual({o['type'] for o in sb['outbounds']} >= {'hysteria2', 'vless', 'selector', 'urltest', 'direct'}, True)
        links = base64.b64decode(subscription.links_base64(s, u)).decode().split()
        self.assertTrue(links[0].startswith('hysteria2://') and 'mport=20000-40000' in links[0])
        self.assertTrue(links[1].startswith('vless://' + u['uuid']) and 'pbk=' + s['reality_public_key'] in links[1])
        x = cores.xray_config(s, [u])
        self.assertEqual(x['inbounds'][0]['settings']['clients'][0]['email'], 'u%d' % uid)
        h = cores.hysteria_config(s, [u])
        self.assertEqual(h['auth']['userpass'], {'u%d' % uid: u['hy2_pass']})
        # TUIC: same credentials as the user's other protocols, pinned like Hysteria while self-signed
        tu = c['proxies'][2]
        self.assertEqual((tu['type'], tu['uuid'], tu['password'], tu['port']), ('tuic', u['uuid'], u['hy2_pass'], s['tuic_port']))
        self.assertEqual(tu['fingerprint'], hy['fingerprint'])
        self.assertIn('tuic', {o['type'] for o in sb['outbounds']})
        self.assertFalse(any(l.startswith('tuic://') for l in links))        # no pinning in share links -> left out
        t = cores.tuic_config(s, [u])
        self.assertEqual(t['inbounds'][0]['users'], [{'name': 'u%d' % uid, 'uuid': u['uuid'], 'password': u['hy2_pass']}])
        self.assertIn({'auth_user': ['u%d' % uid], 'outbound': 'u%d' % uid}, t['route']['rules'])

    def test_tuic_meter(self):
        from vps2vpn import cores
        s = db.settings()
        m = cores.TuicMeter()
        conn = lambda cid, uid, up, down: {'id': cid, 'chains': ['u%d' % uid], 'upload': up, 'download': down}
        m.sample(s, {'uploadTotal': 0, 'downloadTotal': 0, 'connections': []})
        m.sample(s, {'uploadTotal': 300, 'downloadTotal': 3000, 'connections': [conn('a', 1, 100, 1000), conn('b', 2, 200, 2000)]})
        m.sample(s, {'uploadTotal': 400, 'downloadTotal': 4000, 'connections': [conn('a', 1, 150, 1500), conn('b', 2, 250, 2500)]})
        self.assertEqual(m.collect(s.copy() and dict(s, tuic_api_port=1)), {1: (150, 1500), 2: (250, 2500)})
        # a connection that came and went between two readings: only the totals saw it -> split by recent use
        m.sample(s, {'uploadTotal': 400, 'downloadTotal': 4000, 'connections': []})
        m.sample(s, {'uploadTotal': 700, 'downloadTotal': 7000, 'connections': []})
        got = m.collect(dict(s, tuic_api_port=1))
        self.assertAlmostEqual(sum(v[1] for v in got.values()), 3000, delta=2)    # integer split
        self.assertGreater(got[2][1], got[1][1])
        # restart (totals go back to zero): nothing negative, counting restarts cleanly
        m.sample(s, {'uploadTotal': 10, 'downloadTotal': 10, 'connections': []})
        self.assertEqual(m.collect(dict(s, tuic_api_port=1)), {})

    def test_detect(self):
        self.assertEqual(subscription.detect_format('clash-verge/v2.0'), 'clash')
        self.assertEqual(subscription.detect_format('FlClash/0.8 clash.meta'), 'clash')
        self.assertEqual(subscription.detect_format('Shadowrocket/2000 CFNetwork'), 'links')
        self.assertEqual(subscription.detect_format('HiddifyNext/2.5'), 'singbox')
        self.assertEqual(subscription.detect_format('Mozilla/5.0 Chrome/130'), '')
        self.assertEqual(subscription.detect_format('Mozilla/5.0', 'clash'), 'clash')

    def test_route_plan_covers_sets(self):
        for name in rules.used_sets(db.settings()):
            self.assertIn(name, rules.SETS)

    def test_sysctl_scales(self):
        small, big = system.sysctl_text(512), system.sysctl_text(8192)
        self.assertIn('net.core.rmem_max = 8388608', small)
        self.assertIn('net.core.rmem_max = 67108864', big)
        self.assertIn('bbr', small)


class Ops(Base):
    def test_backup_rotation(self):
        os.makedirs(jobs.paths.BACKUPS, exist_ok=True)
        for i in range(20):
            open(os.path.join(jobs.paths.BACKUPS, 'vps2vpn-200001%02d.json' % (i + 1)), 'w').close()
        name = jobs.backup(keep=14)
        files = sorted(os.listdir(jobs.paths.BACKUPS))
        self.assertEqual(len(files), 14)
        self.assertEqual(os.path.basename(name), files[-1])
        with open(name, encoding='utf-8') as f:
            self.assertIn('settings', json.load(f))

    def test_ip_follow_needs_two_sightings(self):
        seen = []
        orig = (system.public_ip, cores.apply, notify.send)
        system.public_ip, cores.apply = (lambda v6=False: '198.51.100.9'), (lambda force=False: seen.append(force))
        notify.send = lambda *a, **k: False
        try:
            w = jobs.IpWatch()
            self.assertIsNone(w.check(db.settings()))
            self.assertIsNone(w.check(db.settings()))                 # too soon to confirm
            self.assertEqual(db.settings()['public_host'], '203.0.113.7')
            w.seen_at -= w.CONFIRM_AFTER
            self.assertEqual(w.check(db.settings()), '198.51.100.9')
            self.assertEqual(db.settings()['public_host'], '198.51.100.9')
            self.assertEqual(seen, [True])
            db.set_settings(domain='vpn.example.com', public_host='vpn.example.com')
            self.assertIsNone(w.check(db.settings()))                 # domains are left alone
            db.set_settings(domain='', public_host='10.0.0.5')
            w.check(db.settings())
            w.seen_at -= w.CONFIRM_AFTER
            self.assertIsNone(w.check(db.settings()))                 # so are private addresses
        finally:
            system.public_ip, cores.apply, notify.send = orig

    def test_ipv6_nodes(self):
        u = db.user(db.add_user('a'))
        db.set_settings(public_ipv6='2001:db8::5')
        self.assertEqual(len(subscription.nodes(db.settings(), u)), 3)
        db.set_settings(ipv6_nodes=True)
        n = subscription.nodes(db.settings(), u)
        self.assertEqual(len(n), 6)
        self.assertEqual(n[3]['server'], '2001:db8::5')
        self.assertIn('[2001:db8::5]', subscription.share_link(n[3]))
        self.assertIn('IPv6', subscription.render('clash', db.settings(), u, 'https://x')[1])

    def test_notify_quiet_without_config(self):
        self.assertFalse(notify.send('hi'))


class Web(Base):
    """Drives the real HTTP(S) server on a local port."""

    def setUp(self):
        super().setUp()
        db.set_settings(public_host='127.0.0.1')
        certs.ensure_self_signed('127.0.0.1')
        paths_token = web.SETUP_TOKEN_FILE
        with open(paths_token, 'w') as f:
            f.write('setup-token-123')
        self.httpd = web.Server(('127.0.0.1', 0), web.Handler, web.TLSContext())
        self.port = self.httpd.server_address[1]
        db.set_settings(panel_port=self.port)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.pp = '/' + db.settings()['panel_path']
        self.cookie = ''
        web._fails.clear()

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()

    def req(self, method, path, body=None, tls=True, headers=None):
        ctx = ssl._create_unverified_context()
        c = http.client.HTTPSConnection('127.0.0.1', self.port, context=ctx, timeout=10) if tls else \
            http.client.HTTPConnection('127.0.0.1', self.port, timeout=10)
        h = {'X-V2V': '1', 'Content-Type': 'application/json'}
        if self.cookie:
            h['Cookie'] = self.cookie
        h.update(headers or {})
        c.request(method, path, json.dumps(body) if body is not None else None, h)
        r = c.getresponse()
        data = r.read()
        sc = r.getheader('Set-Cookie')
        if sc:
            self.cookie = sc.split(';')[0]
        c.close()
        return r.status, data, r

    def test_full_flow(self):
        st, body, _ = self.req('GET', '/')
        self.assertEqual(st, 404)
        st, body, _ = self.req('GET', self.pp + '/')
        self.assertEqual(st, 200)
        self.assertIn(b'app.js', body)
        web.paths.DEV = False                                        # production behaviour
        try:
            st, body, r = self.req('GET', self.pp + '/', tls=False)
            self.assertEqual(st, 301)                                # panel only over HTTPS
        finally:
            web.paths.DEV = True
        st, _, _ = self.req('POST', self.pp + '/api/setup', {'token': 'nope', 'password': 'x' * 10})
        self.assertEqual(st, 403)
        st, _, _ = self.req('POST', self.pp + '/api/setup', {'token': 'setup-token-123', 'password': 'short'})
        self.assertEqual(st, 400)
        st, body, _ = self.req('POST', self.pp + '/api/setup', {
            'token': 'setup-token-123', 'username': 'boss', 'password': 'longpassword', 'first_user': '小明',
            'settings': {'language': 'zh', 'public_host': '127.0.0.1'}})
        self.assertEqual(st, 200, body)
        self.assertFalse(os.path.exists(web.SETUP_TOKEN_FILE))
        st, body, _ = self.req('GET', self.pp + '/api/state')
        self.assertEqual(st, 200)
        state = json.loads(body)
        self.assertNotIn('admin_hash', state['settings'])
        self.assertNotIn('reality_private_key', state['settings'])
        self.assertEqual(state['users'][0]['name'], '小明')
        # POST without the custom header is refused (cross-site protection)
        st, _, _ = self.req('POST', self.pp + '/api/users', {'name': 'x'}, headers={'X-V2V': ''})
        self.assertEqual(st, 403)
        st, body, _ = self.req('POST', self.pp + '/api/users', {'name': 'eve', 'quota_gb': 10, 'reset_day': 1})
        self.assertEqual(st, 200, body)
        token = db.users()[1]['sub_token']
        st, body, r = self.req('GET', '/s/%s' % token, tls=False, headers={'User-Agent': 'clash-verge/2.0'})
        self.assertEqual(st, 200)
        self.assertIn('total=%d' % (10 << 30), r.getheader('Subscription-Userinfo'))
        clash = json.loads(body.decode().split('\n', 1)[1])
        self.assertEqual(len(clash['proxies']), 3)
        st, body, _ = self.req('GET', '/s/%s' % token, headers={'User-Agent': 'Shadowrocket/1.0'})
        self.assertTrue(base64.b64decode(body).startswith(b'hysteria2://'))
        st, body, _ = self.req('GET', '/s/%s' % token, headers={'User-Agent': 'Mozilla/5.0'})
        self.assertIn(('<base href="/s/%s/">' % token).encode(), body)   # the person's own page (member centre UI)
        web.paths.DEV = False
        try:      # plain HTTP (clients refusing self-signed certs): a self-contained page instead
            st, body, _ = self.req('GET', '/s/%s' % token, tls=False, headers={'User-Agent': 'Mozilla/5.0'})
            self.assertIn('Shadowrocket'.encode(), body)
        finally:
            web.paths.DEV = True
        st, body, _ = self.req('GET', '/s/%s/qr.svg' % token)
        self.assertTrue(body.startswith(b'<svg'))
        st, _, _ = self.req('GET', '/s/' + 'x' * 24)
        self.assertEqual(st, 404)
        # paused user: still answers, but with no nodes
        uid = db.users()[1]['id']
        self.req('POST', self.pp + '/api/users/%d/save' % uid, {'enabled': False})
        st, body, _ = self.req('GET', '/s/%s?format=clash' % token)
        self.assertEqual(json.loads(body.decode().split('\n', 1)[1])['proxies'], [])
        # rule file falls back to the CDN until the mirror has it
        st, _, r = self.req('GET', '/rules/cn.mrs')
        self.assertEqual(st, 302)
        self.assertIn('jsdelivr', r.getheader('Location'))
        # logout ends the session
        self.req('POST', self.pp + '/api/logout', {})
        st, _, _ = self.req('GET', self.pp + '/api/state')
        self.assertEqual(st, 401)

    def test_chunked_body(self):
        """Dart and Go send small bodies chunked, without Content-Length."""
        db.set_settings(setup_done=True, admin_hash=secure.hash_password('rightpassword'))
        c = http.client.HTTPSConnection('127.0.0.1', self.port, context=ssl._create_unverified_context(), timeout=10)
        body = iter([b'{"username": "admin", ', b'"password": "rightpassword"}'])
        c.request('POST', self.pp + '/api/login', body, {'X-V2V': '1', 'Content-Type': 'application/json'},
                  encode_chunked=True)
        r = c.getresponse()
        r.read()
        c.close()
        self.assertEqual(r.status, 200)
        self.assertIn('v2v=', r.getheader('Set-Cookie') or '')

    def test_doctor_and_telegram(self):
        db.set_settings(setup_done=True, admin_hash=secure.hash_password('rightpassword'))
        self.req('POST', self.pp + '/api/login', {'username': 'admin', 'password': 'rightpassword'})
        orig = doctor.run_all
        doctor.run_all = lambda: [{'id': 'bbr', 'ok': False, 'detail': 'x', 'fix': 'y'}]
        try:
            st, body, _ = self.req('POST', self.pp + '/api/doctor', {})
        finally:
            doctor.run_all = orig
        self.assertEqual(st, 200)
        self.assertFalse(json.loads(body)['results'][0]['ok'])
        st, body, _ = self.req('POST', self.pp + '/api/telegram', {'token': 'not-a-token'})
        self.assertEqual((st, json.loads(body)['error']), (400, 'bad_token'))
        orig = notify.find_chat
        notify.find_chat = lambda tok: (None, None)
        try:
            st, body, _ = self.req('POST', self.pp + '/api/telegram', {'token': '123456:' + 'A' * 35})
            self.assertEqual((st, json.loads(body)['error']), (400, 'no_chat'))
        finally:
            notify.find_chat = orig
        # the token never leaves the server
        db.set_settings(tg_token='123456:' + 'B' * 35, tg_chat='42')
        st, body, _ = self.req('GET', self.pp + '/api/state')
        self.assertNotIn(b'BBBBBBBB', body)
        self.assertTrue(json.loads(body)['settings']['tg_ready'])

    def test_login_rate_limit(self):
        db.set_settings(setup_done=True, admin_hash=secure.hash_password('rightpassword'))
        for _ in range(8):
            st, _, _ = self.req('POST', self.pp + '/api/login', {'username': 'admin', 'password': 'nope'})
            self.assertEqual(st, 403)
        st, _, _ = self.req('POST', self.pp + '/api/login', {'username': 'admin', 'password': 'rightpassword'})
        self.assertEqual(st, 429)


if __name__ == '__main__':
    unittest.main()
