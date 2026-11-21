"""Offline tests. Run from the repository root:  python -m unittest tests.test_unit tests.test_features tests.test_admin tests.test_deploy tests.test_ops -v"""
import base64
import http.client
import json
import subprocess
import os
import shutil
import ssl
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock
import urllib.parse

ROOT = tempfile.mkdtemp(prefix='v2v-test-')
os.environ['VPS2VPN_ROOT'] = ROOT
os.environ['VPS2VPN_DEV'] = '1'
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from vps2vpn import abuse, certs, cores, db, doctor, jobs, monitor, notify, paths, qr, rules, secure, subscription, system, web  # noqa: E402

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


class AdminEnabledValues(unittest.TestCase):

    def test_user_enabled_values_share_settings_boolean_contract(self):
        for val in (False, 0, 'false', '0', 'off', 'no', ''):
            with self.subTest(value=val):
                self.assertEqual(web.user_fields({'enabled': val}), {'enabled': 0})
        for val in (True, 1, 'true', '1', 'on', 'yes'):
            with self.subTest(value=val):
                self.assertEqual(web.user_fields({'enabled': val}), {'enabled': 1})
        for val in ('maybe', 2, None, [], {}, ['false']):
            with self.subTest(value=val):
                self.assertEqual(web.user_fields({'enabled': val}), 'enabled: expected true or false')


class AdminUserExpiryValidation(unittest.TestCase):
    def test_rejects_unpersistable_expire_at_before_sqlite_write(self):
        for raw in ((1 << 63), (1 << 70), '253402300800'):
            with self.subTest(value=raw):
                self.assertEqual(web.user_fields({'expire_at': raw}), 'expire_at is out of supported range')

    def test_accepts_supported_expirations_and_preserves_negative_to_zero(self):
        self.assertEqual(web.user_fields({'expire_at': '253402300799'}), {'expire_at': 253402300799})
        self.assertEqual(web.user_fields({'expire_at': -1}), {'expire_at': 0})
        self.assertEqual(web.user_fields({'expire_at': 0}), {'expire_at': 0})

    def test_non_finite_numeric_values_are_bad_requests_not_overflow_errors(self):
        for field in ('expire_at', 'reset_day', 'max_ips', 'expire_after_days', 'expire_days'):
            with self.subTest(field=field):
                self.assertEqual(web.user_fields({field: float('inf')}), 'invalid number')


class BenchSources(unittest.TestCase):
    """A refusing or breaking Cloudflare must not show up as a 0 Mb download."""

    def setUp(self):
        from vps2vpn import bench
        self.bench = bench
        self.saved = (bench.working_download_url, bench.download, bench.latency, bench.upload)
        bench.latency = lambda *a, **k: {'median': 10, 'p90': 12, 'min': 9, 'fails': 0}
        bench.upload = lambda *a, **k: 5.0

    def tearDown(self):
        (self.bench.working_download_url, self.bench.download, self.bench.latency, self.bench.upload) = self.saved

    def test_refused_cloudflare_uses_the_first_working_fallback(self):
        b = self.bench
        b.working_download_url = lambda proxy=None, **k: b.DOWN_FALLBACKS[0]
        used = []
        b.download = lambda proxy, streams, secs, url=None, **k: used.append(url) or 42.0
        r = b.run(quick=True, log=lambda m: None)
        self.assertEqual((r['down_1'], r['down_4']), (42.0, 42.0))
        self.assertEqual(set(used), {b.DOWN_FALLBACKS[0]})

    def test_source_breaking_off_mid_test_switches_to_the_next(self):
        b = self.bench
        b.working_download_url = lambda proxy=None, **k: b.DOWN_URL
        b.download = lambda proxy, streams, secs, url=None, **k: 0.0 if url == b.DOWN_URL else 30.0
        r = b.run(quick=True, log=lambda m: None)
        self.assertEqual((r['down_1'], r['down_4']), (30.0, 30.0))

    def test_one_refused_request_does_not_end_a_stream(self):
        import http.server
        served = [0]

        class Flaky(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                served[0] += 1
                if served[0] == 1:                      # a proxy's momentary 502
                    self.send_error(502)
                    return
                self.send_response(200)
                self.send_header('Content-Length', str(1 << 20))
                self.end_headers()
                try:
                    self.wfile.write(b'x' * (1 << 20))
                except OSError:
                    pass

            def log_message(self, *a):
                pass
        srv = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Flaky)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            diag, errors = {}, []
            mbps = self.saved[1](None, 1, 1, size=1 << 20, diagnostics=diag, errors=errors,
                                 url='http://127.0.0.1:%d/__down?bytes=%%d' % srv.server_address[1])
        finally:
            srv.shutdown()
            srv.server_close()
        self.assertGreater(mbps, 0)
        self.assertEqual((errors, diag['retries']), ([], 1))

    def test_explicit_origin_is_never_replaced(self):
        b = self.bench
        b.working_download_url = lambda *a, **k: self.fail('public sources probed for a fixture origin')
        b.download = lambda proxy, streams, secs, url=None, **k: 0.0
        r = b.run(quick=True, log=lambda m: None, origin='http://127.0.0.1:9')
        self.assertEqual(r['down_1'], 0.0)


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
        for d in ([ROOT] + ([paths.ETC, paths.VAR] if paths._root else [])):
            if os.path.exists(d):
                shutil.rmtree(d)
        web._fails.clear()
        monitor._hist = None
        abuse._last = {'at': 0, 'accounts': {}, 'coverage': []}
        notify._recent.clear()
        jobs._device_events.clear()
        db.ensure_secrets()
        db.set_settings(public_host='203.0.113.7', panel_port=54321)
        certs.ensure_self_signed('203.0.113.7')


class UsageHeader(unittest.TestCase):
    def test_total_is_where_the_account_is_cut_off(self):
        u = {'quota_gb': 50, 'used_up': 1, 'used_down': 2, 'expire_at': 0}
        self.assertIn('total=%d;' % (50 << 30), subscription.userinfo_header(u))
        self.assertIn('total=%d;' % (40 << 30), subscription.userinfo_header(u, 40))     # shares 10 GB
        self.assertIn('total=1;', subscription.userinfo_header(u, 0.0))                  # shared it all: not unlimited
        self.assertIn('total=0;', subscription.userinfo_header(dict(u, quota_gb=0), 0))   # unlimited plan


class PerClientConnections(unittest.TestCase):
    def test_one_address_cannot_take_every_worker(self):
        srv = web.Server.__new__(web.Server)
        srv._per_client, srv._per_client_lock = {}, threading.Lock()
        a, b = ('198.51.100.7', 1), ('198.51.100.8', 1)
        v6 = [('2001:db8:1:2::%x' % i, 1) for i in range(1, 30)]
        self.assertTrue(all(srv._client_slot(a, True) for _ in range(web.Server.PER_CLIENT)))
        self.assertFalse(srv._client_slot(a, True))                    # 17th from the same address
        self.assertTrue(srv._client_slot(b, True))                     # someone else still gets in
        taken = [srv._client_slot(addr, True) for addr in v6]          # one /64, many addresses
        self.assertEqual(taken.count(True), web.Server.PER_CLIENT)
        srv._client_slot(a, False)
        self.assertTrue(srv._client_slot(a, True))                     # a slot frees when a request ends
        for _ in range(web.Server.PER_CLIENT):
            srv._client_slot(a, False)
        self.assertNotIn('198.51.100.7', srv._per_client)             # no entry left behind
        # a reverse proxy on the same machine brings everyone from loopback; it is not capped
        self.assertTrue(all(srv._client_slot(('127.0.0.1', 1), True) for _ in range(web.Server.PER_CLIENT * 2)))
        self.assertTrue(all(srv._client_slot(('::ffff:127.0.0.1', 1), True) for _ in range(web.Server.PER_CLIENT * 2)))


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


class RestoreRouteSafety(Base):
    def test_invalid_backup_paths_are_rejected_before_any_database_writes(self):
        db.set_settings(setup_done=True)
        uid = db.add_user('restored-user', 5)
        self.assertTrue(db.user(uid))
        before = db.export_all()
        invalid = (
            ('panel_path', 42),
            ('member_path', ['not-a-path']),
            ('panel_path', ''),
            ('panel_path', '../admin'),
            ('member_path', 'member/api'),
            ('panel_path', 'x' * 129),
            ('member_path', before['settings']['panel_path']),
            ('setup_done', 'true'),
            ('member_enabled', 'false'),
        )
        for key, value in invalid:
            with self.subTest(key=key, value=value):
                damaged = json.loads(json.dumps(before))
                damaged['settings'][key] = value
                with self.assertRaises(ValueError):
                    db.import_all(damaged)
                self.assertEqual(db.export_all(), before)

    def test_backup_user_rows_are_checked_before_anything_is_replaced(self):
        db.set_settings(setup_done=True)
        uid = db.add_user('row-check', 5)
        db.update_user(uid, quota_gb=2.5, used_up=10, expire_at=2000000000)
        before = db.export_all()
        db.import_all(json.loads(json.dumps(before)))              # a real backup still restores
        self.assertEqual(db.export_all()['users'], before['users'])
        invalid = (('expire_at', 'not-a-number'), ('used_up', -1), ('used_down', 1 << 63), ('quota_gb', 'lots'),
                   ('quota_gb', 1e400), ('quota_gb', 1 << 1100), ('invite_deduct', 1 << 1100),
                   ('enabled', 2), ('reset_day', 31), ('name', 7), ('sub_token', ''),
                   ('max_ips', 1.5), ('id', 'x'), ('note', None))
        for key, value in invalid:
            with self.subTest(key=key, value=value):
                damaged = json.loads(json.dumps(before))
                damaged['users'][0][key] = value
                with self.assertRaises(ValueError):
                    db.import_all(damaged)
                self.assertEqual(db.export_all(), before)
        damaged = json.loads(json.dumps(before))
        damaged['users'].append('not a row')
        with self.assertRaises(ValueError):
            db.import_all(damaged)
        self.assertEqual(db.export_all(), before)

    def test_invite_usage_history_is_preflighted_before_restore(self):
        from vps2vpn import members
        uid = db.add_user('invite-restore', quota_gb=2)
        db.add_invite(code='restore-usage-code', kind='admin', valid_until=int(time.time()) + 86400,
                      used_by=str(uid), uses=1, status='used')
        before = db.export_all()
        bad_histories = ('not-an-id', '1,', '1,,2', '01', '0', '1\n2', '9' * 24, None, ['1'])
        for history in bad_histories:
            with self.subTest(history=history):
                damaged = json.loads(json.dumps(before))
                damaged['invites'][0]['used_by'] = history
                with self.assertRaisesRegex(ValueError, 'invite'):
                    db.import_all(damaged)
                self.assertEqual(db.export_all(), before)
        for bad_rows in (None, {}, [42]):
            with self.subTest(rows=bad_rows):
                damaged = json.loads(json.dumps(before))
                damaged['invites'] = bad_rows
                with self.assertRaises(ValueError):
                    db.import_all(damaged)
                self.assertEqual(db.export_all(), before)
        db.import_all(before)
        self.assertEqual(members.invite_view(db.invites()[0], {uid: 'invite-restore'})['used_by'],
                         ['invite-restore'])
        legacy = json.loads(json.dumps(before))
        del legacy['invites'][0]['used_by']
        db.import_all(legacy)
        self.assertEqual(db.invites()[0]['used_by'], '')

    def test_legacy_backup_without_member_path_still_imports(self):
        db.set_settings(setup_done=True)
        original = db.export_all()
        original['settings'].pop('member_path')
        db.import_all(original)
        self.assertEqual(db.settings()['panel_path'], original['settings']['panel_path'])
        self.assertEqual(db.settings()['member_path'], '')


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
        # every rule set named by a sing-box DNS or route rule must be defined, or sing-box refuses the config
        defined = {r['tag'] for r in sb['route'].get('rule_set', [])}
        def tags(rules):
            for r in rules:
                rs = r.get('rule_set', [])
                yield from ([rs] if isinstance(rs, str) else rs)
                yield from tags(r.get('rules', []))
        self.assertLessEqual(set(tags(sb['dns'].get('rules', []))) | set(tags(sb['route'].get('rules', []))), defined)
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

    def test_tuic_meter_survives_a_missed_reading_and_bad_values(self):
        from vps2vpn import cores
        s = db.settings()
        m = cores.TuicMeter()
        conn = lambda cid, up, down: {'id': cid, 'chains': ['u1'], 'upload': up, 'download': down}
        m.sample(s, {'uploadTotal': 0, 'downloadTotal': 0, 'connections': [conn('a', 0, 0)]})
        orig = m.poll
        m.poll = lambda *a, **k: (_ for _ in ()).throw(OSError('busy'))
        self.assertFalse(m.sample(s))                              # sing-box did not answer this time ...
        m.poll = orig
        m.sample(s, {'uploadTotal': 50, 'downloadTotal': 500, 'connections': [conn('a', 50, 500)]})
        self.assertEqual(m.acc, {1: (50, 500)})                    # ... the bytes in between are still billed
        m.sample(s, {'uploadTotal': None, 'downloadTotal': 'x', 'connections': [
            {'id': 'b', 'chains': [7, 'u1'], 'upload': -5, 'download': None}, 'junk', {'chains': ['u1']}]})
        self.assertEqual(m.acc, {1: (50, 500)})                    # malformed values: nothing negative, no crash
        self.assertEqual(cores._count('12'), 12)
        self.assertEqual([cores._count(v) for v in (-1, None, 'x', float('inf'), 1 << 70)], [0] * 5)

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
            with open(os.path.join(jobs.paths.BACKUPS, 'vps2vpn-200001%02d.json' % (i + 1)), 'w'):
                pass
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

    def test_switches_from_json_mean_what_they_say(self):
        for v, want in ((True, True), (False, False), (1, True), (0, False), ('false', False), ('0', False),
                        ('off', False), ('true', True), ('on', True)):
            self.assertIs(web.as_bool(v), want, v)
        for v in ([], {}, 'maybe', 2, None):
            with self.assertRaises(ValueError):
                web.as_bool(v)
        self.assertEqual(web.validate_settings({'block_ads': 'false'}, db.settings()), {'block_ads': False})
        self.assertIsInstance(web.validate_settings({'block_ads': ['x']}, db.settings()), str)

    def test_damaged_ai_result_reads_as_none(self):
        from vps2vpn import aicheck
        paths.ensure_dirs()
        for bad in ('[]', '{"sites": []}', '{"sites": {"claude": {}}}'):
            with open(aicheck.FILE, 'w', encoding='utf-8') as f:
                f.write(bad)
            self.assertIsNone(aicheck.latest(), bad)

    def test_notify_quiet_without_config(self):
        self.assertFalse(notify.send('hi'))

    def test_unverified_legacy_telegram_chat_cannot_send_secrets(self):
        # A pre-upgrade saved private chat ID is not proof that the owner paired it.
        db.set_settings(tg_token='123456:' + 'A' * 35, tg_chat='42',
                        tg_bot=True, setup_done=True, tg_verified=False)
        with mock.patch.object(notify, '_call') as call, \
             mock.patch.object(notify.urllib.request, 'urlopen') as upload:
            self.assertFalse(notify.send('a private username'))
            self.assertFalse(notify.send_file('backup.json', b'private credentials'))
        call.assert_not_called()
        upload.assert_not_called()

        stop = mock.Mock()
        stop.is_set.side_effect = [False, True]
        with mock.patch.object(notify, '_call') as call:
            notify.bot_loop(stop, lambda command: 'secret', lambda line: None)
        call.assert_not_called()

    def test_restoring_a_backup_always_revokes_telegram_pairing(self):
        db.set_settings(tg_token='123456:' + 'A' * 35, tg_chat='42',
                        tg_verified=True, tg_bot=True, setup_done=True)
        backup = db.export_all()
        self.assertTrue(backup['settings']['tg_verified'])
        db.import_all(backup)
        self.assertFalse(db.settings()['tg_verified'])
        self.assertEqual(db.settings()['tg_chat'], '42')
        self.assertFalse(notify.send('should not reach an old owner'))

    def test_notify_uses_the_telegram_target_of_now_not_a_stale_snapshot(self):
        sent = []
        orig = notify._call
        notify._call = lambda token, method, params: sent.append((token, params.get('chat_id'))) or {'ok': True}
        try:
            db.set_settings(tg_token='1234567:' + 'a' * 35, tg_chat='111', tg_verified=True)
            stale = db.settings()
            db.set_settings(tg_token='', tg_chat='', tg_verified=False)  # owner switched alerts off meanwhile
            self.assertFalse(notify.send('backup', s=stale))
            db.set_settings(tg_token='1234567:' + 'a' * 35, tg_chat='222', tg_verified=True)  # freshly rebound chat
            notify.send('backup', s=stale)
            self.assertEqual(sent, [('1234567:' + 'a' * 35, '222')])
        finally:
            notify._call = orig

    def test_notify_dedup_is_scoped_to_the_current_verified_chat(self):
        sent = []
        token = '1234567:' + 'a' * 35
        with mock.patch.object(notify, '_call', side_effect=lambda bot, method, params:
                               sent.append((bot, params['chat_id'])) or {'ok': True}):
            db.set_settings(tg_token=token, tg_chat='111', tg_verified=True)
            self.assertTrue(notify.send('service down', key='service-down', every=21600))
            self.assertFalse(notify.send('service down', key='service-down', every=21600))

            db.set_settings(tg_chat='222', tg_verified=True)
            self.assertTrue(notify.send('service down', key='service-down', every=21600))
            self.assertFalse(notify.send('service down', key='service-down', every=21600))

            db.set_settings(tg_token='7654321:' + 'b' * 35, tg_verified=True)
            self.assertTrue(notify.send('service down', key='service-down', every=21600))
        self.assertEqual(sent, [(token, '111'), (token, '222'),
                                ('7654321:' + 'b' * 35, '222')])

    def test_notify_dedup_cache_is_bounded_and_never_stores_raw_bot_tokens(self):
        token = '1234567:' + 'c' * 35
        db.set_settings(tg_token=token, tg_chat='777', tg_verified=True)
        with mock.patch.object(notify, '_call', return_value={'ok': True}):
            for n in range(1003):
                self.assertTrue(notify.send('note', key='unique-%d' % n))
        self.assertLessEqual(len(notify._recent), 1000)
        self.assertFalse(any(token in repr(key) for key in notify._recent))

    def test_notify_parallel_sends_reserve_one_in_flight_key(self):
        token = '1234567:' + 'd' * 35
        db.set_settings(tg_token=token, tg_chat='321', tg_verified=True)
        entered, release = threading.Event(), threading.Event()
        sent, outcomes = [], []

        def blocking_call(bot, method, params):
            sent.append(params['chat_id'])
            if params['chat_id'] == '321':
                entered.set()
                release.wait(timeout=3)
            return {'ok': True}

        with mock.patch.object(notify, '_call', side_effect=blocking_call):
            worker = threading.Thread(
                target=lambda: outcomes.append(notify.send('down', key='parallel-alert')),
                daemon=True,
            )
            worker.start()
            try:
                self.assertTrue(entered.wait(timeout=2), 'first alert did not start')
                self.assertFalse(notify.send('down', key='parallel-alert'))
                # Changing a verified destination while the old one is in
                # flight must not suppress the new owner's first warning.
                db.set_settings(tg_chat='654', tg_verified=True)
                self.assertTrue(notify.send('down', key='parallel-alert'))
            finally:
                release.set()
                worker.join(timeout=3)
            self.assertFalse(worker.is_alive())
        self.assertEqual(outcomes, [True])
        self.assertEqual(sent, ['321', '654'])
        self.assertEqual(len(notify._pending), 0)

    def test_failed_notification_does_not_keep_in_flight_reservation(self):
        db.set_settings(tg_token='1234567:' + 'e' * 35, tg_chat='890', tg_verified=True)
        with mock.patch.object(notify, '_call', side_effect=OSError('offline')):
            self.assertFalse(notify.send('down', key='retry-after-failure'))
        self.assertEqual(len(notify._pending), 0)
        with mock.patch.object(notify, '_call', return_value={'ok': True}) as sender:
            self.assertTrue(notify.send('down', key='retry-after-failure'))
            sender.assert_called_once()

    def test_failed_telegram_ack_must_not_suppress_next_notification(self):
        db.set_settings(tg_token='1234567:' + 'f' * 35, tg_chat='891', tg_verified=True)
        with mock.patch.object(notify, '_call', side_effect=[
                {'ok': False, 'error_code': 429, 'description': 'retry later'},
                {'ok': True}]) as telegram:
            self.assertFalse(notify.send('down', key='api-not-accepted'))
            self.assertTrue(notify.send('down', key='api-not-accepted'))
            self.assertFalse(notify.send('down', key='api-not-accepted'))
            self.assertEqual(telegram.call_count, 2)
        self.assertFalse(notify._pending)

    def test_missing_or_malformed_node_label_never_leaks_inflight_key(self):
        db.set_settings(tg_token='1234567:' + 'g' * 35, tg_chat='892', tg_verified=True)

        class BrokenLabel:
            def __str__(self):
                raise ValueError('invalid label')

        with mock.patch.object(notify, '_call', return_value={'ok': True}) as telegram:
            self.assertFalse(notify.send('down', key='bad-label', s={'node_name': BrokenLabel()}))
            self.assertFalse(notify._pending)
            self.assertTrue(notify.send('down', key='bad-label', s={'other': 'field'}))
            telegram.assert_called_once()
        self.assertFalse(notify._pending)

    def test_bot_commands_only_from_the_owner_in_a_private_chat(self):
        ok = notify._owner_private_message
        self.assertTrue(ok({'chat': {'id': 5, 'type': 'private'}, 'from': {'id': 5}}, '5'))
        self.assertFalse(ok({'chat': {'id': -9, 'type': 'group'}, 'from': {'id': 7}}, '-9'))   # a group member
        self.assertFalse(ok({'chat': {'id': 5, 'type': 'private'}, 'from': {'id': 6}}, '5'))
        self.assertFalse(ok({'chat': {'id': 5, 'type': 'private'}, 'from': {'id': 5, 'is_bot': True}}, '5'))
        self.assertFalse(ok(None, '5'))

    def test_apply_starts_a_reenabled_service_and_reports_a_failed_start(self):
        from vps2vpn import cores, system
        calls = []
        orig = (system.systemctl, system.unit_active, cores.write_configs, system.port_hopping)
        system.systemctl = lambda *a: (calls.append(a), subprocess.CompletedProcess(a, 1 if a[0] == 'restart' else 0,
                                                                                    '', 'bad config'))[1]
        system.unit_active = lambda unit: False                    # switched back on, config file unchanged
        cores.write_configs = lambda s, errors: set()
        system.port_hopping = lambda s: None
        try:
            db.set_settings(reality_enabled=True, hy2_enabled=False, tuic_enabled=False)
            with self.assertRaises(RuntimeError) as e:
                cores.apply()
            self.assertIn(('restart', cores.XRAY_UNIT), calls)
            self.assertIn('did not start', str(e.exception))
        finally:
            system.systemctl, system.unit_active, cores.write_configs, system.port_hopping = orig

    def test_failed_apply_is_retried(self):
        timers = []
        orig_apply, orig_timer = cores.apply, web.threading.Timer

        class FakeTimer:
            def __init__(self, delay, fn, kwargs=None):
                timers.append(delay)
                self.daemon = True

            def start(self):
                pass
        cores.apply = lambda force=False: (_ for _ in ()).throw(RuntimeError('systemctl failed'))
        web.threading.Timer = FakeTimer
        web._apply_retry[0] = 0
        try:
            web.apply_async()
            for _ in range(100):
                if timers:
                    break
                time.sleep(0.02)
        finally:
            cores.apply, web.threading.Timer = orig_apply, orig_timer
            web._apply_retry[0] = 0
        self.assertEqual(timers, [60])


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
        self._thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self._thread.start()
        self.pp = '/' + db.settings()['panel_path']
        self.cookie = ''
        self._apply = web.apply_async
        web.apply_async = lambda force=False: None

    def tearDown(self):
        web.apply_async = self._apply
        self.httpd.shutdown()
        self.httpd.server_close()
        self._thread.join(5)

    def req(self, method, path, body=None, tls=True, headers=None):
        ctx = ssl._create_unverified_context()
        c = http.client.HTTPSConnection('127.0.0.1', self.port, context=ctx, timeout=10) if tls else \
            http.client.HTTPConnection('127.0.0.1', self.port, timeout=10)
        h = {'X-V2V': '1', 'Content-Type': 'application/json'}
        if self.cookie:
            h['Cookie'] = self.cookie
        h.update(headers or {})
        try:
            c.request(method, path, json.dumps(body) if body is not None else None, h)
            r = c.getresponse()
            data = r.read()
            sc = r.getheader('Set-Cookie')
            if sc:
                self.cookie = sc.split(';')[0]
            return r.status, data, r
        finally:
            c.close()

    def test_invite_http_rejects_oversized_valid_json_integer(self):
        db.set_settings(setup_done=True, admin_hash=secure.hash_password('rightpassword'))
        status, body, _ = self.req('POST', self.pp + '/api/login',
                                   {'username': 'admin', 'password': 'rightpassword'})
        self.assertEqual(status, 200, body)
        huge_json_integer = json.loads('1' + '0' * 309)
        before = db.invites()
        status, body, _ = self.req('POST', self.pp + '/api/invites',
                                   {'kind': 'admin', 'quota_gb': huge_json_integer, 'valid_days': 7})
        self.assertEqual(status, 400, body)
        self.assertIn(b'number', body)
        self.assertEqual(db.invites(), before)

    def test_admin_and_member_json_number_overflows_return_400_without_writes(self):
        db.set_settings(setup_done=True, admin_hash=secure.hash_password('rightpassword'))
        status, body, _ = self.req('POST', self.pp + '/api/login',
                                   {'username': 'admin', 'password': 'rightpassword'})
        self.assertEqual(status, 200, body)
        uid = db.add_user('numeric-member', 20)
        token = db.user(uid)['sub_token']
        before_users, before_invites = db.users(), db.invites()
        before_settings = db.settings()

        def post_exact_json(path, json_text):
            # Preserve exponent notation (1e400 is legal JSON) rather than
            # json.dumps(float('inf')), which would emit nonstandard Infinity.
            conn = http.client.HTTPSConnection('127.0.0.1', self.port,
                                                context=ssl._create_unverified_context(), timeout=10)
            try:
                conn.request('POST', path, json_text, {
                    'Content-Type': 'application/json', 'X-V2V': '1', 'Cookie': self.cookie,
                })
                response = conn.getresponse()
                return response.status, response.read()
            finally:
                conn.close()

        huge = '1' + '0' * 309
        cases = (
            (self.pp + '/api/users-batch', '{"prefix":"batch","count":1e400}'),
            (self.pp + '/api/invites', '{"kind":"admin","quota_gb":1,"valid_days":7,"inviter":1e400}'),
            (self.pp + '/api/settings', '{"reality_port":1e400}'),
            (self.pp + '/api/settings', '{"server_reset_day":1e400}'),
            (self.pp + '/api/settings', '{"server_cap_gb":' + huge + '}'),
            ('/s/' + token + '/api/invite-revoke', '{"id":1e400}'),
        )
        for path, payload in cases:
            with self.subTest(path=path, payload=payload[:70]):
                code, text = post_exact_json(path, payload)
                self.assertEqual(code, 400, text)
                self.assertEqual(db.users(), before_users)
                self.assertEqual(db.invites(), before_invites)
                self.assertEqual(db.settings(), before_settings)

    def test_user_and_node_enabled_endpoints_reject_ambiguous_values(self):
        db.set_settings(setup_done=True, admin_hash=secure.hash_password('rightpassword'))
        status, _, _ = self.req('POST', self.pp + '/api/login',
                                {'username': 'admin', 'password': 'rightpassword'})
        self.assertEqual(status, 200)
        uid = db.add_user('toggle-test', 0)

        for val, enabled in (('false', 0), ('yes', 1), (False, 0), (True, 1)):
            with self.subTest(user_value=val):
                status, _, _ = self.req('POST', self.pp + '/api/users/%d/save' % uid,
                                        {'enabled': val})
                self.assertEqual(status, 200)
                self.assertEqual(db.user(uid)['enabled'], enabled)
        for bad in ('unknown', [], 2, None):
            with self.subTest(user_invalid=bad):
                status, body, _ = self.req('POST', self.pp + '/api/users/%d/save' % uid,
                                           {'enabled': bad})
                self.assertEqual(status, 400)
                self.assertIn(b'enabled', body)
                self.assertEqual(db.user(uid)['enabled'], 1)

        server_id = 'deadbeef'
        db.set_settings(servers=[{'id': server_id, 'name': 'backup',
                                  'url': 'https://example.org:443/admin', 'key': 'redacted',
                                  'enabled': True, 'info': {}, 'idmap': {}}])
        for val, enabled in (('false', False), ('yes', True), (0, False), (1, True)):
            with self.subTest(node_value=val):
                status, _, _ = self.req('POST', self.pp + '/api/servers/%s/save' % server_id,
                                        {'enabled': val})
                self.assertEqual(status, 200)
                self.assertIs(db.settings()['servers'][0]['enabled'], enabled)
        for bad in ('unknown', [], 2, None):
            with self.subTest(node_invalid=bad):
                status, body, _ = self.req('POST', self.pp + '/api/servers/%s/save' % server_id,
                                           {'enabled': bad})
                self.assertEqual(status, 400)
                self.assertIn(b'enabled', body)
                self.assertIs(db.settings()['servers'][0]['enabled'], True)

    def test_plain_http_subscription_is_redirected_when_https_is_trusted(self):
        db.set_settings(setup_done=True, public_host='203.0.113.9')
        uid = db.add_user('http-sub')
        u = db.user(uid)
        path = '/s/%s?format=clash' % u['sub_token']
        with mock.patch.object(web.certs, 'trusted', return_value=True):
            st, body, r = self.req('GET', path, tls=False, headers={'User-Agent': 'clash-verge/2.0'})
            self.assertEqual(st, 308)
            self.assertEqual(r.getheader('Location'), 'https://203.0.113.9:%d%s' % (db.settings()['panel_port'], path))
            self.assertNotIn(u['uuid'].encode(), body)
            self.assertNotIn(u['hy2_pass'].encode(), body)
        # a self-signed panel keeps plain HTTP: most apps cannot use its HTTPS
        with mock.patch.object(web.certs, 'trusted', return_value=False):
            st, body, _ = self.req('GET', path, tls=False, headers={'User-Agent': 'clash-verge/2.0'})
            self.assertEqual(st, 200)
            self.assertIn(u['uuid'].encode(), body)
        st, body, _ = self.req('GET', path, headers={'User-Agent': 'clash-verge/2.0'})    # over TLS: served
        self.assertEqual(st, 200)
        self.assertIn(u['uuid'].encode(), body)

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
        st, body, _ = self.req('GET', '/s/%s' % token, headers={'User-Agent': 'Mozilla/5.0', 'Accept': 'text/html,*/*;q=0.8'})
        self.assertIn(('<base href="/s/%s/">' % token).encode(), body)   # the person's own page (member centre UI)
        web.paths.DEV = False
        try:      # plain HTTP (clients refusing self-signed certs): a self-contained page instead
            st, body, _ = self.req('GET', '/s/%s' % token, tls=False, headers={'User-Agent': 'Mozilla/5.0', 'Accept': 'text/html,*/*;q=0.8'})
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
        paused = json.loads(body.decode().split('\n', 1)[1])
        # only the dead entry that names the reason; every rule still rejects
        self.assertEqual([(p['server'], p['port']) for p in paused['proxies']], [('0.0.0.0', 1)])
        self.assertIn('Disabled', paused['proxies'][0]['name'])
        self.assertEqual(paused['rules'], ['MATCH,REJECT'])
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
        try:
            c.request('POST', self.pp + '/api/login', body, {'X-V2V': '1', 'Content-Type': 'application/json'},
                      encode_chunked=True)
            r = c.getresponse()
            r.read()
        finally:
            c.close()
        self.assertEqual(r.status, 200)
        self.assertIn('v2v=', r.getheader('Set-Cookie') or '')

    def test_bad_chunk_size(self):
        """A negative or garbage chunk size is a 400, not a crash."""
        import socket
        db.set_settings(setup_done=True, admin_hash=secure.hash_password('rightpassword'))
        with socket.create_connection(('127.0.0.1', self.port), timeout=10) as raw:
            with ssl._create_unverified_context().wrap_socket(raw) as c:
                c.sendall(('POST %s/api/login HTTP/1.1\r\nHost: x\r\nX-V2V: 1\r\nTransfer-Encoding: chunked\r\n'
                           'Content-Type: application/json\r\n\r\n-5\r\nxx\r\n0\r\n\r\n' % self.pp).encode())
                data = b''
                try:
                    while not data.endswith(b'}') and len(data) < 65536:
                        d = c.recv(4096)
                        if not d:
                            break
                        data += d
                except socket.timeout:
                    pass
        self.assertTrue(data.startswith(b'HTTP/1.1 400') or data.startswith(b'HTTP/1.0 400'), data[:40])

    def test_every_api_handler_is_routed(self):
        """The panel's endpoint table is a whitelist: a handler left out of it silently 404s."""
        import inspect, re as _re
        src = inspect.getsource(web)
        defined = set(_re.findall(r'def (api_\w+)\(', src))
        routed = set(_re.findall(r'self\.(api_\w+)[(),]', src))
        self.assertEqual(defined - routed, set())

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
        notify.find_chat = lambda tok, challenge: (None, None)
        try:
            st, body, _ = self.req('POST', self.pp + '/api/telegram', {'token': '123456:' + 'A' * 35})
            self.assertEqual((st, json.loads(body)['error']), (400, 'pairing_required'))
            st, body, _ = self.req('POST', self.pp + '/api/telegram',
                                   {'token': '123456:' + 'A' * 35, 'challenge': 'x' * 32})
            self.assertEqual((st, json.loads(body)['error']), (400, 'pairing_required'))
            st, body, _ = self.req('POST', self.pp + '/api/telegram',
                                   {'token': '123456:' + 'A' * 35, 'challenge': 'a' * 32})
            self.assertEqual((st, json.loads(body)['error']), (400, 'no_chat'))
            self.assertFalse(db.settings()['tg_chat'])
        finally:
            notify.find_chat = orig
        db.set_settings(tg_token='123456:' + 'A' * 35, tg_chat='999', tg_verified=False)
        st, body, _ = self.req('GET', self.pp + '/api/state')
        self.assertFalse(json.loads(body)['settings']['tg_ready'])
        self.assertTrue(json.loads(body)['settings']['tg_repair_needed'])
        orig_send = notify.send
        notify.find_chat = lambda tok, challenge: ('42', 'Owner') if challenge == 'a' * 32 else (None, None)
        notify.send = lambda *args, **kwargs: True
        try:
            st, body, _ = self.req('POST', self.pp + '/api/telegram',
                                   {'token': '123456:' + 'A' * 35, 'challenge': 'a' * 32})
            self.assertEqual(st, 200)
            self.assertEqual(db.settings()['tg_chat'], '42')
            self.assertTrue(db.settings()['tg_verified'])
        finally:
            notify.find_chat, notify.send = orig, orig_send
        # the token never leaves the server
        db.set_settings(tg_token='123456:' + 'B' * 35, tg_chat='42')
        st, body, _ = self.req('GET', self.pp + '/api/state')
        self.assertNotIn(b'BBBBBBBB', body)
        self.assertTrue(json.loads(body)['settings']['tg_ready'])
        self.assertFalse(json.loads(body)['settings']['tg_repair_needed'])
        st, _, _ = self.req('POST', self.pp + '/api/telegram', {'off': True})
        self.assertEqual(st, 200)
        self.assertFalse(db.settings()['tg_verified'])

    def test_login_rate_limit(self):
        db.set_settings(setup_done=True, admin_hash=secure.hash_password('rightpassword'))
        for _ in range(8):
            st, _, _ = self.req('POST', self.pp + '/api/login', {'username': 'admin', 'password': 'nope'})
            self.assertEqual(st, 403)
        st, _, _ = self.req('POST', self.pp + '/api/login', {'username': 'admin', 'password': 'rightpassword'})
        self.assertEqual(st, 429)


if __name__ == '__main__':
    unittest.main()
