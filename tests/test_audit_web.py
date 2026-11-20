"""HTTP boundary, concurrency, credential and CSV regressions."""
import csv
import io
import json
import socket
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from email.message import Message
from unittest import mock

from tests import test_unit as tu
from vps2vpn import certs, db, secure, web


class RequestFraming(unittest.TestCase):
    def handler(self, body, headers):
        h = object.__new__(web.Handler)
        h._raw = None
        h.headers = Message()
        for name, value in headers:
            h.headers[name] = value
        h.rfile = io.BytesIO(body)
        h.close_connection = False
        return h

    def test_rejects_ambiguous_and_incomplete_framing(self):
        cases = [
            ([('Content-Length', '-1')], b'{}'),
            ([('Content-Length', '+2')], b'{}'),
            ([('Content-Length', '2'), ('Content-Length', '2')], b'{}'),
            ([('Content-Length', '8')], b'{}'),
            ([('Transfer-Encoding', 'chunked'), ('Content-Length', '2')], b'{}'),
            ([('Transfer-Encoding', 'gzip, chunked')], b'0\r\n\r\n'),
            ([('Transfer-Encoding', 'chunked')], b'-1\r\nanything'),
            ([('Transfer-Encoding', 'chunked')], b'+2\r\n{}\r\n0\r\n\r\n'),
            ([('Transfer-Encoding', 'chunked')], b'2\r\n{'),
            ([('Transfer-Encoding', 'chunked')], b'2\r\n{}XX0\r\n\r\n'),
            ([('Transfer-Encoding', 'chunked')], b'0\r\n'),
            ([('Transfer-Encoding', 'chunked')], b'0\r\nbad trailer\r\n\r\n'),
        ]
        for headers, body in cases:
            with self.subTest(headers=headers, body=body):
                h = self.handler(body, headers)
                with self.assertRaises(ValueError):
                    h._read_body(1024)
                self.assertTrue(h.close_connection)

    def test_valid_chunks_preserve_next_request(self):
        h = self.handler(b'2;x=1\r\n{}\r\n0\r\nX-End: yes\r\n\r\nNEXT',
                         [('Transfer-Encoding', 'chunked')])
        self.assertEqual(h.body_json(), {})
        self.assertEqual(h.rfile.read(), b'NEXT')

    def test_body_limits_and_trailer_budget(self):
        cases = [
            ([('Content-Length', '3')], b'abc'),
            ([('Transfer-Encoding', 'chunked')], b'3\r\nabc\r\n0\r\n\r\n'),
            ([('Transfer-Encoding', 'chunked')], b'0\r\n' + b'X: value\r\n' * 2000 + b'\r\n'),
        ]
        for headers, body in cases:
            h = self.handler(body, headers)
            with self.assertRaises(ValueError):
                h._read_body(2)
            self.assertTrue(h.close_connection)

    def test_json_requires_finite_object(self):
        for body in (b'[]', b'null', b'1', b'{"x": NaN}', b'{"x": Infinity}', b'\xff'):
            with self.subTest(body=body):
                h = self.handler(body, [('Content-Length', str(len(body)))])
                with self.assertRaises((ValueError, UnicodeError)):
                    h.body_json()

    def test_concurrent_auth_attempts_reserve_slots(self):
        h = object.__new__(web.Handler)
        h.client_address = ('192.0.2.99', 123)
        with web._fails_lock:
            web._fails.clear()
        try:
            with ThreadPoolExecutor(max_workers=32) as pool:
                limited = list(pool.map(lambda _: h.rate_limited(), range(64)))
            self.assertEqual(limited.count(False), 8)
        finally:
            web._fails.clear()


class AuditWeb(tu.Base):
    req = tu.Web.req
    tearDown = tu.Web.tearDown

    def setUp(self):
        super().setUp()
        db.set_settings(public_host='127.0.0.1', setup_done=True,
                        admin_hash=secure.hash_password('old-password'))
        certs.ensure_self_signed('127.0.0.1')
        self.httpd = web.Server(('127.0.0.1', 0), web.Handler, web.TLSContext())
        self.port = self.httpd.server_address[1]
        db.set_settings(panel_port=self.port)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.pp = '/' + db.settings()['panel_path']
        self.cookie = 'v2v=' + db.new_session()
        with web._fails_lock:
            web._fails.clear()
        self.apply = mock.patch.object(web, 'apply_async').start()
        self.addCleanup(mock.patch.stopall)

    def test_negative_chunk_returns_400_and_closes(self):
        with socket.create_connection(('127.0.0.1', self.port), timeout=3) as c:
            request = ('POST %s/api/login HTTP/1.1\r\nHost: localhost\r\n'
                       'X-V2V: 1\r\nTransfer-Encoding: chunked\r\n\r\n-1\r\n' % self.pp)
            c.sendall(request.encode())
            response = b''
            while True:
                block = c.recv(4096)
                if not block:
                    break
                response += block
        self.assertTrue(response.startswith(b'HTTP/1.1 400'), response)

    def test_malformed_api_json_is_400(self):
        for body in ([], None, {'quota_gb': float('nan')}):
            if body is None:
                body = 'not an object'
            status, _, _ = self.req('POST', self.pp + '/api/users', body)
            self.assertEqual(status, 400)
        status, _, _ = self.req('POST', self.pp + '/api/settings', [])
        self.assertEqual(status, 400)

    def test_https_redirect_ignores_untrusted_host_and_preserves_path(self):
        db.set_settings(domain='vpn.example.test', member_enabled=True)
        configured = 'https://vpn.example.test:%d' % self.port
        for path in (self.pp + '/?setup=one-time-secret',
                     '/' + db.settings()['member_path'] + '/?next=profile'):
            with self.subTest(path=path):
                h = object.__new__(web.Handler)
                h.path = path
                h.headers = Message()
                h.headers['Host'] = 'attacker.example:8080'
                h.rfile = io.BytesIO()
                h.close_connection = False
                with mock.patch.object(web.Handler, 'secure_ok', return_value=False), mock.patch.object(web.Handler, 'send') as sent:
                    h.route('GET')
                self.assertEqual(sent.call_args.args[0], 301)
                self.assertEqual(sent.call_args.kwargs['headers']['Location'],
                                 configured + path)
        db.set_settings(domain='', public_host='')
        self.assertIsNone(h._https_location(db.settings()))

    def test_https_redirect_validates_ipv6_and_rejects_host_injection(self):
        h = object.__new__(web.Handler)
        h.path = self.pp + '/?token=secret'
        s = dict(db.settings(), domain='', public_host='2001:db8::1')
        self.assertEqual(h._https_location(s),
                         'https://[2001:db8::1]:%d%s' % (self.port, h.path))
        for host in ('evil.example@trusted.example', 'a/b.example',
                     'bad' + chr(10) + 'Location: https://attacker.example', '[::1]@evil'):
            with self.subTest(host=host):
                s['public_host'] = host
                self.assertIsNone(h._https_location(s))

    def test_get_cannot_change_authenticated_state(self):
        cookie = self.cookie
        for endpoint in ('logout', 'password', 'restart', 'rules-refresh'):
            status, _, response = self.req('GET', self.pp + '/api/' + endpoint)
            self.assertEqual(status, 405, endpoint)
            self.assertEqual(response.getheader('Allow'), 'POST')
        self.assertTrue(db.session_ok(cookie.split('=', 1)[1]))
        self.apply.assert_not_called()

    def test_duplicate_bulk_ids_are_applied_once(self):
        uid = db.add_user('one', 10)
        status, body, _ = self.req('POST', self.pp + '/api/users-bulk',
                                   {'action': 'add_gb', 'ids': [uid, uid], 'value': 5})
        self.assertEqual(status, 200, body)
        self.assertEqual(json.loads(body)['done'], 1)
        self.assertEqual(db.user(uid)['quota_gb'], 15)

    def test_csv_does_not_execute_user_supplied_formulas(self):
        uid = db.add_user('=1+1')
        db.update_user(uid, note=' \t@SUM(1,2)')
        status, body, _ = self.req('GET', self.pp + '/api/users-export')
        self.assertEqual(status, 200)
        rows = list(csv.reader(io.StringIO(body.decode('utf-8-sig'))))
        self.assertEqual(rows[1][1], "'=1+1")
        self.assertTrue(rows[1][10].startswith("'"))

    def test_member_password_revokes_existing_sessions(self):
        uid = db.add_user('member')
        db.update_user(uid, login_hash=secure.hash_password('member-old'))
        old = db.new_member_session(uid)
        token = db.user(uid)['sub_token']
        status, body, _ = self.req('POST', '/s/%s/api/password' % token,
                                   {'old': 'member-old', 'new': 'member-new'})
        self.assertEqual(status, 200, body)
        self.assertFalse(db.member_session(old))
        self.assertTrue(secure.check_password('member-new', db.user(uid)['login_hash']))

    def test_setup_is_serialized_and_refreshes_settings(self):
        db.set_settings(setup_done=False)
        with open(web.SETUP_TOKEN_FILE, 'w') as f:
            f.write('audit-setup-token')
        original = secure.hash_password
        def slow_hash(password):
            time.sleep(0.05)
            return original(password)
        payload = {'token': 'audit-setup-token', 'password': 'new-password'}
        with mock.patch.object(secure, 'hash_password', side_effect=slow_hash) as hashed, \
             mock.patch.object(web.system, 'tune_network'), mock.patch.object(web.system, 'open_firewall'):
            with ThreadPoolExecutor(max_workers=2) as pool:
                statuses = list(pool.map(lambda _: self.req('POST', self.pp + '/api/setup', payload)[0], range(2)))
        self.assertEqual(sorted(statuses), [200, 409])
        self.assertEqual(hashed.call_count, 1)

    def test_http_error_log_does_not_include_path_or_secrets(self):
        with mock.patch.object(web.Handler, 'api_state', side_effect=RuntimeError('secret-password')), \
             mock.patch.object(web.jobs, 'log') as logged:
            status, _, _ = self.req('GET', self.pp + '/api/state')
        self.assertEqual(status, 500)
        output = ' '.join(str(call) for call in logged.call_args_list)
        self.assertNotIn(self.pp, output)
        self.assertNotIn('secret-password', output)
        self.assertIn('RuntimeError', output)


if __name__ == '__main__':
    unittest.main()
