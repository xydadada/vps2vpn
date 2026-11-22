"""Owner chores: VPS renewal reminder, lines the apps report unreachable, moving a line to a new port,
and the AI result in the member API.

    python -m unittest tests.test_ops
"""
import json
import time
import unittest

from tests import test_unit as tu          # sets VPS2VPN_ROOT / dev mode first
from tests import test_features as tf
from vps2vpn import aicheck, db, jobs, notify, paths, web


class Renewal(tu.Base):
    def setUp(self):
        super().setUp()
        self.sent = []
        self._send = notify.send
        notify.send = lambda text, key=None, every=0, **kw: self.sent.append(key)

    def tearDown(self):
        notify.send = self._send
        super().tearDown()

    def test_days_left_and_steps(self):
        s = db.settings()
        self.assertIsNone(jobs.renew_days_left(s))
        day = 86400
        now = time.mktime((2026, 11, 20, 15, 0, 0, 0, 0, -1))
        for date, left, step in (('2026-12-31', 41, None), ('2026-11-27', 7, 7), ('2026-11-23', 3, 3),
                                 ('2026-11-21', 1, 1), ('2026-11-20', 0, 0), ('2026-11-10', -10, None)):
            db.set_settings(vps_renew_at=date, vps_renew_note='Lightsail')
            s = db.settings()
            self.assertEqual(jobs.renew_days_left(s, now), left, date)
            self.assertEqual(jobs.renew_reminder(s, now), step, date)
        self.assertEqual(self.sent, ['renew7-2026-11-27', 'renew3-2026-11-23', 'renew1-2026-11-21', 'renew0-2026-11-20'])
        self.assertEqual(jobs.renew_reminder(dict(s, vps_renew_at='bad'), now + day), None)


class QuotaWarningPeriods(tu.Base):
    def test_one_warning_per_billing_period_not_per_calendar_month(self):
        GB = 1 << 30
        t = lambda m, d: time.mktime((2026, m, d, 12, 0, 0, 0, 0, -1))
        u = tf.mk('ann', 10, reset_day=15, used_down=9 * GB)
        # 20 Nov and 1 Dec are the same period (15 Nov - 14 Dec); 20 Dec is the next one.
        self.assertEqual(jobs.quota_alert_key(u, 10, t(11, 20)), jobs.quota_alert_key(u, 10, t(12, 1)))
        self.assertNotEqual(jobs.quota_alert_key(u, 10, t(12, 1)), jobs.quota_alert_key(u, 10, t(12, 20)))
        # a raised quota warns again; an account that never resets has one period
        self.assertNotEqual(jobs.quota_alert_key(u, 10, t(11, 20)), jobs.quota_alert_key(u, 20, t(11, 20)))
        once = tf.mk('bob', 10, used_down=9 * GB)
        self.assertEqual(jobs.quota_alert_key(once, 10, t(11, 20)), jobs.quota_alert_key(once, 10, t(12, 20)))

    def test_manual_reset_rearms_the_warning(self):
        GB = 1 << 30
        db.set_settings(tg_token='1:x', tg_chat='42', tg_verified=True)
        uid = tf.mk('cat', 10, used_down=9 * GB)['id']
        sent = []
        real = notify._call
        notify._call = lambda token, method, params=None, timeout=10: sent.append(params['text']) or {'ok': True}
        try:
            jobs.enforce()
            jobs.enforce()
            self.assertEqual(len([m for m in sent if '80%' in m]), 1)
            jobs.forget_quota_alerts(uid)                              # what the admin's "reset traffic" does
            with notify._recent_lock:
                notify._recent.clear()                                 # and a restart on top of it
            jobs.enforce()
            self.assertEqual(len([m for m in sent if '80%' in m]), 2)
        finally:
            notify._call = real


class AccountExpiry(tu.Base):
    def setUp(self):
        super().setUp()
        self.sent = []
        self._send = notify.send
        notify.send = lambda text, key=None, every=0, **kw: self.sent.append((key, text))

    def tearDown(self):
        notify.send = self._send
        super().tearDown()

    def test_reminders_three_days_and_one_day_before(self):
        now = time.mktime((2026, 11, 20, 15, 0, 0, 0, 0, -1))
        day = 86400
        at = lambda d, h=12: int(time.mktime((2026, 11, 20 + d, h, 0, 0, 0, 0, -1)))
        a = tf.mk('alice', expire_at=at(3))
        tf.mk('far', expire_at=at(5))
        tf.mk('never')
        tf.mk('gone', expire_at=int(now - 60))                         # already over: the pause alert says so
        tf.mk('paused', expire_at=at(1), enabled=0, disabled_reason='manual')
        tf.mk('node-acc', expire_at=at(1), remote_id=7)                # the main server reminds its own accounts
        tf.mk('first-use', expire_after_days=30)                       # no date until first used
        self.assertEqual(jobs.expiry_reminders(now), [('alice', 3)])
        key, text = self.sent[-1]
        self.assertEqual(key, 'uexp3-%d-%d' % (a['id'], at(3)))
        self.assertIn('alice expires in 3 days (2026-11-23 12:00)', text)
        self.assertIn('alice 3 天后到期', text)
        self.assertEqual(jobs.expiry_reminders(now + day)[0], ('alice', 3))          # same key: notify dedups
        self.assertEqual(self.sent[-1][0], key)
        self.assertEqual(jobs.expiry_reminders(now + 2 * day), [('alice', 1), ('far', 3)])
        text = [t for k, t in self.sent if k.startswith('uexp1-%d-' % a['id'])][-1]
        self.assertIn('alice expires tomorrow', text)
        self.assertIn('明天', text)
        self.assertIn(('alice', 1), jobs.expiry_reminders(now + 3 * day - 5 * 3600))     # 10:00, ends at 12:00
        self.assertIn('alice expires today', [t for k, t in self.sent if k.startswith('uexp1-%d-' % a['id'])][-1])
        # extended: a new date is a new reminder
        db.update_user(a['id'], expire_at=at(33))
        self.assertEqual(jobs.expiry_reminders(now + 30 * day), [('alice', 3)])
        self.assertEqual(self.sent[-1][0], 'uexp3-%d-%d' % (a['id'], at(33)))

    def test_scheduler_runs_reminders_hourly(self):
        db.set_settings(setup_done=True)
        tf.mk('soon', expire_at=int(time.time() + 86400))
        sch = jobs.Scheduler()
        for name in ('collect', 'traffic', 'abuse', 'monitor', 'cert', 'rules', 'rules-missing', 'watchdog', 'ip', 'aicheck', 'backup'):
            sch.last[name] = time.monotonic()
        sch.tick()
        self.assertTrue(any(k.startswith('uexp1-') for k, _ in self.sent), self.sent)
        n = len(self.sent)
        sch.tick()                                                     # not again within the hour
        self.assertEqual(len(self.sent), n)

    def test_expiring_command(self):
        GIB = 1 << 30
        now = time.time()
        tf.mk('later', 10, expire_at=int(now + 6 * 86400))
        tf.mk('sooner', 0, expire_at=int(now + 86400))
        tf.mk('heavy', 10, used_down=9 * GIB)
        tf.mk('fine', 10, used_down=GIB, expire_at=int(now + 60 * 86400))
        tf.mk('stopped', 10, used_down=10 * GIB, enabled=0, disabled_reason='quota')
        out = jobs.tg_command('/expiring')
        self.assertLess(out.index('sooner'), out.index('later'))        # soonest first
        self.assertIn('heavy  9.00 / 10 GB', out)
        for name in ('fine', 'stopped'):
            self.assertNotIn(name, out)
        db.set_settings(language='en')
        self.assertIn('Ending within 7 days', jobs.tg_command('/expiring'))
        self.assertIn('/expiring', jobs.tg_command('/help'))
        db.delete_user(db.user_by_name('heavy')['id'])
        for name in ('later', 'sooner'):
            db.delete_user(db.user_by_name(name)['id'])
        self.assertEqual(jobs.tg_command('/expiring'), 'Nothing ends or runs out within 7 days')


class LineReports(tu.Base):
    def setUp(self):
        super().setUp()
        self.sent = []
        self._send = notify.send
        notify.send = lambda text, key=None, every=0, **kw: self.sent.append(key)

    def tearDown(self):
        notify.send = self._send
        super().tearDown()

    def test_one_vote_per_account_and_expiry(self):
        a, b = tf.mk('a'), tf.mk('b')
        now = time.time()
        jobs.report_line(a['id'], 'hy2', False, '1.2.3.4', now)
        jobs.report_line(a['id'], 'hy2', False, '1.2.3.4', now + 60)      # same account again: still one
        tr = jobs.line_trouble(db.settings(), now + 60)
        self.assertEqual(tr['hy2']['users'], [a['id']])
        self.assertEqual(self.sent, [])                                    # one person is not an alert yet
        jobs.report_line(b['id'], 'hy2', False, '1.2.3.4', now + 120)
        self.assertEqual(self.sent, ['line-hy2'])
        jobs.report_line(a['id'], 'hy2', True, '', now + 180)              # works again for a
        self.assertEqual(jobs.line_trouble(db.settings(), now + 180)['hy2']['users'], [b['id']])
        self.assertEqual(jobs.line_trouble(db.settings(), now + 2 * 86400), {})
        with self.assertRaises(ValueError):
            jobs.report_line(a['id'], 'ssh', False)

    def test_change_port_moves_and_clears(self):
        u = tf.mk('c')
        s = db.settings()
        jobs.report_line(u['id'], 'tuic', False)
        old = s['tuic_port']
        new = jobs.change_port('tuic')
        s = db.settings()
        self.assertNotEqual(new, old)
        self.assertEqual(s['tuic_port'], new)
        self.assertNotIn(new, (s['hy2_port'], s['panel_port']))
        lo, hi = map(int, s['hy2_hop_range'].split('-'))
        if s['hy2_hop']:
            self.assertFalse(lo <= new <= hi)
        self.assertNotIn('tuic', jobs.line_trouble(s))

    def test_hosts_recover_independently_and_count_distinct_accounts(self):
        a, b = tf.mk('multi-a'), tf.mk('multi-b')
        now = time.time()
        jobs.report_line(a['id'], 'tuic', False, 'a.invalid', now)
        jobs.report_line(a['id'], 'tuic', False, 'b.invalid', now + 1)
        self.assertEqual(self.sent, [])
        jobs.report_line(b['id'], 'tuic', False, 'b.invalid', now + 2)
        self.assertEqual(self.sent, ['line-tuic'])
        jobs.report_line(a['id'], 'tuic', True, 'b.invalid', now + 3)
        trouble = jobs.line_trouble(db.settings(), now + 3)['tuic']
        self.assertEqual(trouble['users'], [a['id'], b['id']])
        self.assertEqual(trouble['hosts'], ['a.invalid', 'b.invalid'])
        jobs.report_line(b['id'], 'tuic', True, 'b.invalid', now + 4)
        self.assertEqual(jobs.line_trouble(db.settings(), now + 4)['tuic']['hosts'], ['a.invalid'])
        jobs.report_line(a['id'], 'tuic', True, 'a.invalid', now + 5)
        self.assertEqual(jobs.line_trouble(db.settings(), now + 5), {})

    def test_legacy_entry_is_preserved_when_another_host_recovers(self):
        u = tf.mk('legacy')
        now = time.time()
        db.set_settings(line_reports={'hy2': {str(u['id']): [now, 'a.invalid']}})
        jobs.report_line(u['id'], 'hy2', False, 'b.invalid', now + 1)
        jobs.report_line(u['id'], 'hy2', True, 'b.invalid', now + 2)
        self.assertEqual(jobs.line_trouble(db.settings(), now + 2)['hy2']['hosts'], ['a.invalid'])

    def test_hostless_recovery_cannot_clear_multiple_hosts(self):
        u = tf.mk('no-host')
        now = time.time()
        for host in ('a.invalid', 'b.invalid'):
            jobs.report_line(u['id'], 'hy2', False, host, now)
        with self.assertRaisesRegex(ValueError, 'host required'):
            jobs.report_line(u['id'], 'hy2', True, '', now + 1)
        self.assertEqual(len(jobs.line_trouble(db.settings(), now + 1)['hy2']['hosts']), 2)

    def test_new_host_limit_does_not_block_recovery_or_expiry(self):
        u = tf.mk('bounded')
        now = time.time()
        for i in range(jobs.MAX_REPORTED_HOSTS):
            jobs.report_line(u['id'], 'tuic', False, '%d.invalid' % i, now)
        with self.assertRaisesRegex(ValueError, 'too many'):
            jobs.report_line(u['id'], 'tuic', False, 'extra.invalid', now + 1)
        jobs.report_line(u['id'], 'tuic', True, '0.invalid', now + 2)
        jobs.report_line(u['id'], 'tuic', False, 'extra.invalid', now + 3)
        self.assertEqual(jobs.line_trouble(db.settings(), now + jobs.REPORT_TTL + 4), {})


class OpsWeb(tf.MemberWeb):
    def test_member_api_failure_contract(self):
        import http.client
        import ssl
        from unittest.mock import patch
        from vps2vpn import cores
        u = tf.mk('contract')
        context = ssl.create_default_context(cafile=paths.SELF_CRT)

        def request(path, tls=True):
            c = http.client.HTTPSConnection('127.0.0.1', self.port, context=context, timeout=4) if tls else \
                http.client.HTTPConnection('127.0.0.1', self.port, timeout=4)
            try:
                c.request('GET', path, headers={'User-Agent': 'clash'})
                r = c.getresponse()
                return r.status, r.read()
            finally:
                c.close()

        with patch.object(paths, 'DEV', False), patch.object(cores, 'online_detail', return_value={}):
            path = '/s/%s' % u['sub_token']
            self.assertEqual(request(path, tls=False)[0], 200)
            status, body = request(path + '/api/me', tls=False)
            self.assertEqual(status, 426)
            self.assertEqual(json.loads(body), {'service': 'vps2vpn', 'error': 'https_required'})
            self.assertEqual(request(path + '/api/me')[0], 200)
            status, body = request('/s/' + 'x' * 24 + '/api/me')
            self.assertEqual(status, 404)                       # a wrong token looks like any nginx 404
            self.assertNotIn(b'vps2vpn', body)
            self.assertEqual(request('/s/' + 'x' * 24 + '/api/me', tls=False)[0], 404)
            self.assertEqual(request('/s/' + 'x' * 24)[0], 404)

    def test_report_state_and_change_port(self):
        u = tf.mk('dan', 10)
        base = '/s/%s/' % u['sub_token']
        st, body, _ = self.req('POST', base + 'api/report', {'line': 'hy2', 'ok': False, 'host': '127.0.0.1'})
        self.assertEqual(st, 200, body)
        st, _, _ = self.req('POST', base + 'api/report', {'line': 'nope', 'ok': False})
        self.assertEqual(st, 400)
        self.req('POST', '/adm/api/login', {'username': 'admin', 'password': 'adminpassword'})
        st, body, _ = self.req('POST', '/adm/api/settings', {'vps_renew_at': '31/12/2026'})
        self.assertEqual(st, 400)
        st, body, _ = self.req('POST', '/adm/api/settings', {'vps_renew_at': '2099-01-01', 'vps_renew_note': 'x' * 99})
        self.assertEqual(st, 200, body)
        state = json.loads(self.req('GET', '/adm/api/state')[1])
        self.assertNotIn('line_reports', state['settings'])
        self.assertEqual(len(state['settings']['vps_renew_note']), 40)
        self.assertGreater(state['renew_days'], 1000)
        tr = state['line_trouble']
        self.assertEqual((tr[0]['line'], tr[0]['users'], tr[0]['here']), ('hy2', 1, True))
        old = db.settings()['hy2_port']
        st, body, _ = self.req('POST', '/adm/api/change-port', {'line': 'hy2'})
        self.assertEqual(st, 200, body)
        self.assertNotEqual(json.loads(body)['port'], old)
        self.assertEqual(json.loads(self.req('GET', '/adm/api/state')[1])['line_trouble'], [])
        st, _, _ = self.req('POST', '/adm/api/change-port', {'line': 'x'})
        self.assertEqual(st, 400)

    def test_chunked_body(self):
        """The Dart / Go HTTP clients may send the body chunked instead of with a Content-Length."""
        import http.client, ssl
        u = tf.mk('gus', 10)
        ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        c = http.client.HTTPSConnection('127.0.0.1', self.port, context=ctx, timeout=10)
        try:
            body = iter([b'{"line": "tu', b'ic", "ok": false, "host": ""}'])
            c.request('POST', '/s/%s/api/report' % u['sub_token'], body=body, encode_chunked=True,
                      headers={'Content-Type': 'application/json', 'X-V2V': '1', 'Transfer-Encoding': 'chunked'})
            r = c.getresponse()
            self.assertEqual(r.status, 200, r.read())
            r.read()
            c.request('GET', '/s/%s/api/me' % u['sub_token'])           # same connection still usable
            r2 = c.getresponse()
            self.assertEqual(r2.status, 200)
            r2.read()
        finally:
            c.close()
        self.assertIn('tuic', jobs.line_trouble(db.settings()))

    def test_member_view_has_ai(self):
        u = tf.mk('eve', 10)
        base = '/s/%s/' % u['sub_token']
        self.assertIsNone(json.loads(self.req('GET', base + 'api/me')[1])['ai'])
        res = {'at': 1, 'country': 'US', 'ip': {'city': 'Tokyo', 'country': 'JP'},
               'sites': {k: {'status': 'ok', 'note': ''} for k in aicheck.SITES}}
        paths.write_atomic(aicheck.FILE, json.dumps(res), 0o644)
        ai = json.loads(self.req('GET', base + 'api/me')[1])['ai']
        self.assertEqual(ai['sites']['claude'], 'ok')
        self.assertIn('Claude', ai['summary'])
        self.assertEqual(ai['place'], '东京')


    def test_client_update(self):
        import os
        u = tf.mk('fay', 10)
        base = '/s/%s/' % u['sub_token']
        self.assertIsNone(json.loads(self.req('GET', base + 'api/me')[1])['client'])
        os.makedirs(paths.CLIENT, exist_ok=True)
        for n, data in (('vps2vpn-1.2.0-windows-setup.exe', b'old'), ('vps2vpn-1.10.0-windows-setup.exe', b'new' * 50000),
                        ('vps2vpn-1.10.0-android.apk', b'apk'), ('notes.txt', b'x')):
            with open(os.path.join(paths.CLIENT, n), 'wb') as f:
                f.write(data)
        c = json.loads(self.req('GET', base + 'api/me')[1])['client']
        self.assertEqual(c['version'], '1.10.0')                         # 1.10 is newer than 1.2
        self.assertTrue(c['url'].endswith(base + 'download/vps2vpn-1.10.0-windows-setup.exe'), c['url'])
        self.assertEqual(sorted(c['files']), ['android', 'windows'])
        st, body, _ = self.req('GET', base + 'download/vps2vpn-1.10.0-windows-setup.exe')
        self.assertEqual((st, len(body)), (200, 150000))
        self.assertEqual(self.req('GET', base + 'download/notes.txt')[0], 404)
        self.assertEqual(self.req('GET', base + 'download/..%2Fvps2vpn.db')[0], 404)
        self.assertEqual(self.req('GET', '/s/%s/download/vps2vpn-1.10.0-android.apk' % ('x' * 24))[0], 404)
        # update signatures: served next to their installer, never for other names, never large
        self.assertEqual(web.client_files()['unsigned'], ['vps2vpn-1.10.0-android.apk', 'vps2vpn-1.10.0-windows-setup.exe'])
        self.assertEqual(self.req('GET', base + 'download/vps2vpn-1.10.0-windows-setup.exe.sig')[0], 404)
        with open(os.path.join(paths.CLIENT, 'vps2vpn-1.10.0-windows-setup.exe.sig'), 'wb') as f:
            f.write(b'c2lnbmF0dXJl\n')
        with open(os.path.join(paths.CLIENT, 'vps2vpn-1.10.0-android.apk.sig'), 'w') as f:
            f.write('x' * 5000)
        with open(os.path.join(paths.CLIENT, 'notes.txt.sig'), 'w') as f:
            f.write('x')
        self.assertEqual(self.req('GET', base + 'download/vps2vpn-1.10.0-windows-setup.exe.sig')[:2], (200, b'c2lnbmF0dXJl\n'))
        self.assertEqual(self.req('GET', base + 'download/vps2vpn-1.10.0-android.apk.sig')[0], 404)   # too big
        self.assertEqual(self.req('GET', base + 'download/notes.txt.sig')[0], 404)
        self.assertEqual(web.client_files()['unsigned'], [])
        self.req('POST', '/adm/api/login', {'username': 'admin', 'password': 'adminpassword'})
        self.assertEqual(self.req('POST', '/adm/api/settings', {'client_version': 'one'})[0], 400)
        self.assertEqual(self.req('POST', '/adm/api/settings', {'client_url': 'javascript:alert(1)'})[0], 400)
        st, body, _ = self.req('POST', '/adm/api/settings', {'client_version': 'v2.0.1', 'client_url': 'https://example.com/a.exe',
                                                               'client_notes': '修复'})
        self.assertEqual(st, 200, body)
        c = json.loads(self.req('GET', base + 'api/me')[1])['client']
        self.assertEqual((c['version'], c['url'], c['notes']), ('2.0.1', 'https://example.com/a.exe', '修复'))
        self.assertEqual(c['files'], {})          # the 1.10.0 files here would be refused as "not newer"
        # a version typed in long ago does not hide the newer release the panel holds, nor point at its link
        self.assertEqual(self.req('POST', '/adm/api/settings', {'client_version': '1.0.5'})[0], 200)
        c = json.loads(self.req('GET', base + 'api/me')[1])['client']
        self.assertEqual(c['version'], '1.10.0')
        self.assertTrue(c['url'].endswith(base + 'download/vps2vpn-1.10.0-windows-setup.exe'), c['url'])
        self.assertEqual(sorted(c['files']), ['android', 'windows'])
        state = json.loads(self.req('GET', '/adm/api/state')[1])
        self.assertEqual(state['client']['found']['version'], '1.10.0')


    def test_current_client_release_asset_naming_and_download(self):
        import os
        u = tf.mk('release-member', 10)
        base = '/s/%s/' % u['sub_token']
        os.makedirs(paths.CLIENT, exist_ok=True)
        assets = {
            'vps2vpn-1.10.0-windows-setup.exe': b'legacy',
            'vps2vpn-dev-1.11.0-nightly.20261120.abcdefg-windows-amd64-setup.exe': b'prerelease',
            'vps2vpn-rs-1.11.0-windows-arm64-setup.exe': b'arm',
            'vps2vpn-rs-1.11.0-windows-amd64-portable.zip': b'portable',
            'vps2vpn-rs-1.11.0-windows-amd64-setup.exe': b'x64 setup',
            'vps2vpn-rs-1.11.0-android-armv7.apk': b'armv7',
            'vps2vpn-rs-1.11.0-android-arm64.apk': b'arm64',
            'vps2vpn-rs-1.11.0-macos-universal.dmg': b'macos',
        }
        for filename, payload in assets.items():
            with open(os.path.join(paths.CLIENT, filename), 'wb') as out:
                out.write(payload)

        found = web.client_files()
        self.assertEqual(found['version'], '1.11.0')
        self.assertEqual(found['files']['windows'], 'vps2vpn-rs-1.11.0-windows-amd64-setup.exe')
        self.assertEqual(found['files']['android'], 'vps2vpn-rs-1.11.0-android-arm64.apk')
        self.assertEqual(found['files']['macos'], 'vps2vpn-rs-1.11.0-macos-universal.dmg')
        self.assertGreater(web._ver('1.11.0'), web._ver('1.11.0-nightly.20261120.abcdefg'))
        self.assertGreater(web._ver('1.11.0-rs.10'), web._ver('1.11.0-rs.2'))
        self.assertGreater(web._ver('1.11.0'), web._ver('1.10.0'))

        status, body, _ = self.req('GET', base + 'api/me')
        self.assertEqual(status, 200, body)
        client = json.loads(body)['client']
        self.assertEqual(client['version'], '1.11.0')
        self.assertTrue(client['url'].endswith(base + 'download/' + found['files']['windows']))
        for platform, expected in (('windows', b'x64 setup'), ('android', b'arm64'), ('macos', b'macos')):
            url = base + 'download/' + found['files'][platform]
            self.assertTrue(client['files'][platform].endswith(url))
            status, data, _ = self.req('GET', url)
            self.assertEqual((status, data), (200, expected))
        # A valid old installer still works, but a crafted filename does not.
        self.assertEqual(self.req('GET', base + 'download/vps2vpn-1.10.0-windows-setup.exe')[0], 200)
        self.assertEqual(self.req('GET', base + 'download/vps2vpn-rs-1.11.0-windows-amd64-setup.exe.bak')[0], 404)


if __name__ == '__main__':
    unittest.main()
