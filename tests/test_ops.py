"""Owner chores: VPS renewal reminder, lines the apps report unreachable, moving a line to a new port,
and the AI result in the member API.

    python -m unittest tests.test_ops
"""
import json
import time
import unittest

from tests import test_unit as tu          # sets VPS2VPN_ROOT / dev mode first
from tests import test_features as tf
from vps2vpn import aicheck, db, jobs, notify, paths


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
        self.req('POST', '/adm/api/login', {'username': 'admin', 'password': 'adminpassword'})
        self.assertEqual(self.req('POST', '/adm/api/settings', {'client_version': 'one'})[0], 400)
        self.assertEqual(self.req('POST', '/adm/api/settings', {'client_url': 'javascript:alert(1)'})[0], 400)
        st, body, _ = self.req('POST', '/adm/api/settings', {'client_version': 'v2.0.1', 'client_url': 'https://example.com/a.exe',
                                                               'client_notes': '修复'})
        self.assertEqual(st, 200, body)
        c = json.loads(self.req('GET', base + 'api/me')[1])['client']
        self.assertEqual((c['version'], c['url'], c['notes']), ('2.0.1', 'https://example.com/a.exe', '修复'))
        state = json.loads(self.req('GET', '/adm/api/state')[1])
        self.assertEqual(state['client']['found']['version'], '1.10.0')


if __name__ == '__main__':
    unittest.main()
