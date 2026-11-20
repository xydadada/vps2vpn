"""Regression cases for the 2026-11-20 security and reliability audit.

Offline only: real HTTP tests bind to loopback and do not alter host routes.
"""
import concurrent.futures
import csv
import http.client
import io
import json
import os
import sqlite3
import ssl
import threading
import unittest
from email.message import Message
from unittest import mock

from tests import test_unit as tu
from vps2vpn import db, jobs, members, paths, secure, subscription, web

GIB = 1 << 30


class Transactions(tu.Base):
    def test_traffic_failure_rolls_back_and_connection_recovers(self):
        uid = db.add_user('alice')
        db.x("CREATE TEMP TRIGGER fail_traffic BEFORE INSERT ON traffic "
             "BEGIN SELECT RAISE(ABORT, 'disk failure'); END")
        try:
            with self.assertRaises(sqlite3.IntegrityError):
                db.add_traffic(uid, 10, 20)
            self.assertEqual(db.user(uid)['used_down'], 0)
            self.assertEqual(db.user_traffic(uid), [])
        finally:
            db.x('DROP TRIGGER fail_traffic')
        db.add_traffic(uid, 1, 2)
        db.set_settings(node_name='still usable')
        self.assertEqual(db.user(uid)['used_down'], 2)

    def test_automatic_sqlite_rollback_preserves_original_exception(self):
        uid = db.add_user('alice')
        db.x("CREATE TEMP TRIGGER fail_traffic BEFORE INSERT ON traffic "
             "BEGIN SELECT RAISE(ROLLBACK, 'automatic rollback'); END")
        try:
            with self.assertRaisesRegex(sqlite3.IntegrityError, 'automatic rollback'):
                with db.transaction():
                    db.add_traffic(uid, 10, 20)
            self.assertFalse(db.connect().in_transaction)
            self.assertEqual(db.user(uid)['used_down'], 0)
        finally:
            db.x('DROP TRIGGER fail_traffic')
        db.add_traffic(uid, 1, 2)
        self.assertEqual(db.user(uid)['used_down'], 2)

    def test_nested_transaction_rolls_back_settings_and_traffic(self):
        uid = db.add_user('alice')
        before = db.settings()['node_name']
        with self.assertRaises(RuntimeError):
            with db.transaction():
                db.set_settings(node_name='temporary')
                db.add_traffic(uid, 4, 5)
                raise RuntimeError('later operation failed')
        self.assertEqual(db.settings()['node_name'], before)
        self.assertEqual(db.user(uid)['used_down'], 0)
        self.assertEqual(db.user_traffic(uid), [])

    def test_registration_failure_does_not_leave_free_account(self):
        inv = members.create_invite('admin', 10, 7)
        with mock.patch.object(db, 'update_invite', side_effect=RuntimeError('write failed')):
            with self.assertRaises(RuntimeError):
                members.register(inv['code'], 'alice', 'password123')
        self.assertIsNone(db.user_by_name('alice'))
        self.assertEqual(db.invite(inv['id'])['uses'], 0)

    def test_request_approval_is_not_double_granted_after_retry(self):
        uid = db.add_user('alice', quota_gb=10)
        rid = members.request_more(uid, 5, 'please')
        with mock.patch.object(db, 'decide_request', side_effect=RuntimeError('write failed')):
            with self.assertRaises(RuntimeError):
                members.decide(rid, True)
        self.assertEqual(db.user(uid)['quota_gb'], 10)
        members.decide(rid, True)
        self.assertEqual(db.user(uid)['quota_gb'], 15)

    def test_restore_invalidates_old_identity_sessions_and_history(self):
        uid = db.add_user('old')
        admin_token = db.new_session()
        member_token = db.new_member_session(uid)
        db.add_traffic(uid, 1, 2)
        data = db.export_all()
        data['users'][0]['name'] = 'replacement'
        db.import_all(data)
        self.assertFalse(db.session_ok(admin_token))
        self.assertIsNone(db.member_session(member_token))
        self.assertEqual(db.user_traffic(uid), [])
        self.assertEqual(db.user(uid)['name'], 'replacement')

    def test_bad_restore_rolls_back_every_table(self):
        uid = db.add_user('original')
        token = db.new_member_session(uid)
        data = db.export_all()
        data['users'][0]['name'] = 'replacement'
        data['requests'] = [{'unknown_column': 'bad'}]
        with self.assertRaises(ValueError):
            db.import_all(data)
        self.assertEqual(db.user(uid)['name'], 'original')
        self.assertEqual(db.member_session(token), uid)

    def test_case_insensitive_account_creation_is_atomic(self):
        ready = threading.Barrier(2)

        def create(name):
            ready.wait(timeout=5)
            try:
                return db.add_user(name)
            except ValueError:
                return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(create, ('Alice', 'alice')))
        self.assertEqual(sum(x is not None for x in outcomes), 1)
        self.assertEqual(len(db.users()), 1)

    def test_unknown_user_and_invalid_traffic_do_not_create_history(self):
        db.add_traffic(99999, 10, 20)
        self.assertEqual(db.traffic_days(), [])
        for counters in ((-1, 0), (0, -1), (True, 1), (1.5, 2)):
            with self.assertRaises(ValueError):
                db.add_traffic(99999, *counters)


class SharedQuota(tu.Base):
    def invite(self, parent, grant, name):
        inv = members.create_invite('member', grant, 7, inviter=parent, by_member=True)
        return members.register(inv['code'], name, 'password123')

    def test_used_parent_traffic_reduces_invite_capacity(self):
        parent = db.add_user('parent', quota_gb=10)
        db.add_traffic(parent, 0, 8 * GIB)
        self.assertEqual(members.capacity(db.user(parent)), 1)
        with self.assertRaises(members.Refused):
            self.invite(parent, 2, 'child')

    def test_exhausted_invitee_cannot_recycle_grant(self):
        parent = db.add_user('parent', quota_gb=10)
        child = self.invite(parent, 9, 'child')
        db.add_traffic(child, 0, 9 * GIB)
        jobs.enforce()
        self.assertFalse(db.user(child)['enabled'])
        self.assertEqual(members.effective_quota(db.user(parent)), 1)
        self.assertEqual(members.capacity(db.user(parent)), 0)
        with self.assertRaises(members.Refused):
            self.invite(parent, 1, 'another')

    def test_pause_returns_only_unconsumed_quota(self):
        parent = db.add_user('parent', quota_gb=10)
        child = self.invite(parent, 5, 'child')
        db.add_traffic(child, 0, 2 * GIB)
        db.update_user(child, enabled=0, disabled_reason='manual')
        self.assertEqual(members.effective_quota(db.user(parent)), 8)

    def test_active_grandchild_still_reserves_quota_through_paused_parent(self):
        parent = db.add_user('parent', quota_gb=10)
        child = self.invite(parent, 8, 'child')
        self.invite(child, 5, 'grandchild')
        db.update_user(child, enabled=0, disabled_reason='manual')
        self.assertEqual(members.given_away(parent), 5)

    def test_deletion_keeps_consumed_debt(self):
        parent = db.add_user('parent', quota_gb=10)
        child = self.invite(parent, 5, 'child')
        db.add_traffic(child, 0, 2 * GIB)
        db.delete_user(child)
        self.assertEqual(db.user(parent)['used_down'], 2 * GIB)
        self.assertEqual(members.capacity(db.user(parent)), 7)
        self.assertEqual(db.user_traffic(parent), [])

    def test_old_code_cannot_spend_parent_quota_twice(self):
        parent = db.add_user('parent', quota_gb=10)
        inv = members.create_invite('member', 5, 7, inviter=parent)
        db.add_traffic(parent, 0, 6 * GIB)
        with self.assertRaises(members.Refused):
            members.register(inv['code'], 'child', 'password123')
        self.assertEqual(db.invite(inv['id'])['uses'], 0)


    def test_deep_invitation_chain_has_bounded_python_stack(self):
        depth = 2500
        rows = [
            {'id': i, 'invited_by': i - 1, 'invite_deduct': depth - i + 2,
             'quota_gb': depth - i + 2, 'enabled': 0, 'expire_at': 0,
             'used_up': 0, 'used_down': 0}
            for i in range(1, depth + 1)
        ]
        rows[-1]['used_down'] = GIB
        self.assertEqual(members.given_away(1, rows, now=100), 1)
        self.assertEqual(members.spent_bytes(rows[0], rows), GIB)
        rows[-1]['enabled'] = 1
        self.assertEqual(members.given_away(1, rows, now=100), 2)
        self.assertEqual(members.spent_bytes(rows[0], rows), GIB)

    def test_imported_invitation_cycle_is_conservatively_bounded(self):
        rows = [
            {'id': 1, 'invited_by': 2, 'invite_deduct': 4, 'quota_gb': 4,
             'enabled': 0, 'expire_at': 0, 'used_up': 0, 'used_down': GIB},
            {'id': 2, 'invited_by': 1, 'invite_deduct': 4, 'quota_gb': 4,
             'enabled': 0, 'expire_at': 0, 'used_up': 0, 'used_down': GIB},
        ]
        self.assertEqual(members.given_away(1, rows, now=100), 4)
        self.assertEqual(members.effective_quota(rows[0], rows, now=100), 0)
        self.assertEqual(members.spent_bytes(rows[0], rows), 5 * GIB)

    def test_admin_delete_keeps_consumption_but_detaches_live_descendants(self):
        parent = db.add_user('parent', quota_gb=10)
        child = self.invite(parent, 8, 'child')
        grandchild = self.invite(child, 5, 'grandchild')
        db.add_traffic(grandchild, 0, GIB)
        db.delete_user(child)
        self.assertEqual(db.user(parent)['used_down'], GIB)
        self.assertEqual(db.user(grandchild)['invited_by'], 0)
        self.assertEqual(db.user(grandchild)['invite_deduct'], 0)
        self.assertTrue(db.user(grandchild)['enabled'])


class AtomicFiles(tu.Base):
    def test_predictable_temporary_symlink_is_not_followed(self):
        target = os.path.join(paths.VAR, 'atomic.txt')
        victim = os.path.join(paths.VAR, 'victim.txt')
        with open(victim, 'wb') as f:
            f.write(b'keep')
        os.symlink(victim, target + '.tmp')
        paths.write_atomic(target, b'replacement')
        with open(victim, 'rb') as f:
            self.assertEqual(f.read(), b'keep')
        with open(target, 'rb') as f:
            self.assertEqual(f.read(), b'replacement')

    def test_concurrent_writers_publish_complete_private_files(self):
        target = os.path.join(paths.VAR, 'atomic.txt')
        payloads = [bytes([i]) * 65536 for i in range(8)]
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(lambda data: paths.write_atomic(target, data), payloads))
        with open(target, 'rb') as f:
            self.assertIn(f.read(), payloads)
        self.assertEqual(os.stat(target).st_mode & 0o777, 0o600)
        self.assertFalse(any(n.startswith('.atomic.txt.') for n in os.listdir(paths.VAR)))


class HttpFraming(unittest.TestCase):
    def handler(self, body, headers):
        h = web.Handler.__new__(web.Handler)
        h._raw = None
        h.close_connection = False
        h.rfile = io.BytesIO(body)
        h.headers = Message()
        for name, value in headers:
            h.headers[name] = value
        return h

    def test_bad_chunks_close_connection(self):
        samples = [b'-1\r\n', b'', b'3\r\nab', b'1\r\nxZZ', b'0\r\n',
                   b'0\r\n' + b'X: y\r\n' * 101 + b'\r\n']
        for body in samples:
            with self.subTest(body=body[:30]):
                h = self.handler(body, [('Transfer-Encoding', 'chunked')])
                with self.assertRaises(web.BadRequest):
                    h._read_body(1024)
                self.assertTrue(h.close_connection)

    def test_ambiguous_or_negative_length_is_rejected(self):
        samples = [[('Content-Length', '-1')],
                   [('Content-Length', '2'), ('Content-Length', '2')],
                   [('Content-Length', '2'), ('Transfer-Encoding', 'chunked')],
                   [('Transfer-Encoding', 'gzip, chunked')]]
        for headers in samples:
            with self.subTest(headers=headers):
                h = self.handler(b'{}', headers)
                with self.assertRaises(web.BadRequest):
                    h._read_body(1024)
                self.assertTrue(h.close_connection)

    def test_valid_extensions_trailers_and_pipeline_boundary(self):
        h = self.handler(b'2;example=ok\r\n{}\r\n0\r\nX-Trace: yes\r\n\r\nNEXT',
                         [('Transfer-Encoding', 'chunked')])
        self.assertEqual(h.body_json(), {})
        self.assertEqual(h.rfile.read(), b'NEXT')

    def test_json_requires_object_and_finite_numbers(self):
        for body in (b'[]', b'null', b'{"n":NaN}', b'{"n":Infinity}', b'"hello"', b'{'):
            with self.subTest(body=body):
                h = self.handler(body, [('Content-Length', str(len(body)))])
                with self.assertRaises(web.BadRequest):
                    h.body_json()

    def test_parallel_authentication_reserves_rate_limit_slots(self):
        h = web.Handler.__new__(web.Handler)
        h.client_address = ('192.0.2.1', 1234)
        with web._fails_lock:
            web._fails.clear()
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=20) as pool:
                results = list(pool.map(lambda _: h.rate_limited(), range(20)))
            self.assertEqual(results.count(False), 8)
        finally:
            with web._fails_lock:
                web._fails.clear()


class SubscriptionIntegrity(tu.Base):
    def test_names_are_unique_across_proxies_groups_and_builtins(self):
        uid = db.add_user('alice')
        s = db.settings()
        s.update(language='en', node_name='Proxy')
        s['servers'] = [dict(id=str(i), name=name, info=dict(s), idmap={str(uid): uid})
                        for i, name in enumerate(('Proxy', 'Proxy', 'DIRECT', 'Proxy (2) Reality', 'x, y=z\nnext'))]
        u = db.user(uid)
        clash = subscription.clash(s, u, 'https://example.com')
        names = [p['name'] for p in clash['proxies'] + clash['proxy-groups']]
        self.assertEqual(len(names), len(set(names)))
        self.assertTrue(all(not any(c in name for c in '\n,=') for name in names))
        sb = subscription.singbox(s, u, 'https://example.com')
        tags = [o['tag'] for o in sb['outbounds']]
        self.assertEqual(len(tags), len(set(tags)))
        self.assertNotIn('x, y=z\nnext', subscription.shadowrocket(s, u, 'https://example.com'))

    def test_disabled_subscriptions_reject_instead_of_direct_fallback(self):
        uid = db.add_user('alice')
        s = dict(db.settings(), hy2_enabled=False, reality_enabled=False, tuic_enabled=False, servers=[])
        u = db.user(uid)
        clash = subscription.clash(s, u, 'https://example.com')
        auto = next(g for g in clash['proxy-groups'] if g['name'] == subscription.names(s)['auto'])
        self.assertEqual(auto['proxies'], ['REJECT'])
        self.assertEqual(subscription.singbox(s, u, 'https://example.com')['route']['rules'], [{'action': 'reject'}])
        self.assertIn('fallback, REJECT,', subscription.shadowrocket(s, u, 'https://example.com'))

    def test_account_name_cannot_inject_profile_lines(self):
        uid = db.add_user('alice\n[Rule]\nFINAL,DIRECT')
        s, u = db.settings(), db.user(uid)
        clash = subscription.clash_yaml(s, u, 'https://example.com')
        json.loads(clash.split('\n', 1)[1])
        sr = subscription.shadowrocket(s, u, 'https://example.com')
        self.assertEqual(sr.count('\n[Rule]\n'), 1)


class WebAudit(tu.Base):
    req = tu.Web.req

    def setUp(self):
        super().setUp()
        db.set_settings(setup_done=True, panel_path='adm', member_path='mem', public_host='127.0.0.1',
                        admin_hash=secure.hash_password('password123'))
        self.cookie = 'v2v=' + db.new_session()
        self.httpd = web.Server(('127.0.0.1', 0), web.Handler, web.TLSContext())
        self.port = self.httpd.server_address[1]
        db.set_settings(panel_port=self.port)
        self.worker = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.worker.start()
        with web._fails_lock:
            web._fails.clear()

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.worker.join(timeout=5)
        with web._fails_lock:
            web._fails.clear()

    def test_admin_base_without_slash_redirects_for_relative_assets(self):
        status, body, response = self.req('GET', '/adm')
        self.assertEqual(status, 301, body)
        self.assertEqual(response.getheader('Location'), '/adm/')

    def test_bulk_duplicate_ids_are_applied_once(self):
        uid = db.add_user('alice', quota_gb=10)
        with mock.patch.object(web, 'apply_async'):
            status, body, _ = self.req('POST', '/adm/api/users-bulk',
                                       {'ids': [uid, uid], 'action': 'add_gb', 'value': 5})
        self.assertEqual(status, 200, body)
        self.assertEqual(json.loads(body)['done'], 1)
        self.assertEqual(db.user(uid)['quota_gb'], 15)

    def test_csv_formula_cells_are_text(self):
        db.add_user('=2+3', note='@SUM(1,2)')
        status, body, _ = self.req('GET', '/adm/api/users-export')
        self.assertEqual(status, 200)
        rows = list(csv.reader(io.StringIO(body.decode('utf-8-sig'))))
        self.assertEqual(rows[1][1], "'=2+3")
        self.assertEqual(rows[1][-2], "'@SUM(1,2)")

    def test_member_password_revokes_other_sessions_and_rotates_own(self):
        uid = db.add_user('alice', login_hash=secure.hash_password('password123'))
        old = db.new_member_session(uid)
        other = db.new_member_session(uid)
        self.cookie = 'v2vm=' + old
        status, body, _ = self.req('POST', '/mem/api/password', {'old': 'password123', 'new': 'new-password123'})
        self.assertEqual(status, 200, body)
        self.assertIsNone(db.member_session(old))
        self.assertIsNone(db.member_session(other))
        self.assertEqual(db.member_session(self.cookie.split('=', 1)[1]), uid)

    def test_non_object_request_is_a_client_error(self):
        status, body, _ = self.req('POST', '/adm/api/login', [])
        self.assertEqual(status, 400, body)
        self.assertIn('object', json.loads(body)['error'])

    def test_mutating_actions_require_post(self):
        for endpoint in ('restart', 'rules-refresh', 'password', 'logout'):
            status, body, _ = self.req('GET', '/adm/api/' + endpoint)
            self.assertEqual(status, 405, (endpoint, body))


    def _auth_request(self, path, data, connection=None):
        conn = connection or http.client.HTTPConnection('127.0.0.1', self.port, timeout=15)
        try:
            conn.request('POST', path, json.dumps(data),
                         {'Content-Type': 'application/json', 'X-V2V': '1'})
            response = conn.getresponse()
            return response.status, response.read()
        finally:
            if connection is None:
                conn.close()

    def test_member_success_preserves_other_identity_failures(self):
        db.add_user('member', login_hash=secure.hash_password('member-password'))
        db.add_user('victim', login_hash=secure.hash_password('victim-password'))
        targets = (('/adm/api/login', {'username': 'admin', 'password': 'wrong'}),
                   ('/mem/api/login', {'name': 'victim', 'password': 'wrong'}))
        with mock.patch.object(web, '_auth_clock', return_value=1000):
            for path, credentials in targets:
                with self.subTest(path=path):
                    with web._fails_lock:
                        web._fails.clear()
                    for _ in range(7):
                        status, body = self._auth_request(path, credentials)
                        self.assertEqual(status, 403, body)
                    status, body = self._auth_request(
                        '/mem/api/login', {'name': 'member', 'password': 'member-password'})
                    self.assertEqual(status, 200, body)
                    status, body = self._auth_request(path, credentials)
                    self.assertEqual(status, 403, body)
                    status, body = self._auth_request(path, credentials)
                    self.assertEqual(status, 429, body)

    def test_parallel_success_preserves_same_tick_failed_reservations(self):
        db.add_user('member', login_hash=secure.hash_password('member-password'))
        wrong = {'username': 'admin', 'password': 'wrong'}
        entered, release = threading.Event(), threading.Event()
        real_check = secure.check_password

        def check(password, encoded):
            if password == 'member-password':
                entered.set()
                if not release.wait(10):
                    raise AssertionError('successful login was not released')
            return real_check(password, encoded)

        with mock.patch.object(web, '_auth_clock', return_value=1000):
            status, body = self._auth_request('/adm/api/login', wrong)
            self.assertEqual(status, 403, body)
            with web._fails_lock:
                first_failure = web._fails['127.0.0.1'][0]
            with mock.patch.object(secure, 'check_password', side_effect=check):
                with concurrent.futures.ThreadPoolExecutor(max_workers=7) as pool:
                    successful = pool.submit(self._auth_request, '/mem/api/login',
                                             {'name': 'member', 'password': 'member-password'})
                    try:
                        self.assertTrue(entered.wait(5))
                        failed = [pool.submit(self._auth_request, '/adm/api/login', wrong)
                                  for _ in range(6)]
                        for request in failed:
                            status, body = request.result(timeout=10)
                            self.assertEqual(status, 403, body)
                    finally:
                        release.set()
                    status, body = successful.result(timeout=10)
                    self.assertEqual(status, 200, body)
            with web._fails_lock:
                self.assertIn(first_failure, web._fails.get('127.0.0.1', []))
            status, body = self._auth_request('/adm/api/login', wrong)
            self.assertEqual(status, 403, body)
            status, body = self._auth_request('/adm/api/login', wrong)
            self.assertEqual(status, 429, body)

    def test_expired_success_does_not_clear_new_http_reservations(self):
        db.add_user('member', login_hash=secure.hash_password('member-password'))
        wrong = {'username': 'admin', 'password': 'wrong'}
        entered, release = threading.Event(), threading.Event()
        real_check = secure.check_password

        def check(password, encoded):
            if password == 'member-password':
                entered.set()
                if not release.wait(10):
                    raise AssertionError('expired login was not released')
            return real_check(password, encoded)

        with mock.patch.object(web, '_auth_clock', return_value=1000) as clock, \
                mock.patch.object(secure, 'check_password', side_effect=check):
            with concurrent.futures.ThreadPoolExecutor(max_workers=9) as pool:
                successful = pool.submit(self._auth_request, '/mem/api/login',
                                         {'name': 'member', 'password': 'member-password'})
                try:
                    self.assertTrue(entered.wait(5))
                    clock.return_value = 1601
                    failed = [pool.submit(self._auth_request, '/adm/api/login', wrong)
                              for _ in range(8)]
                    for request in failed:
                        status, body = request.result(timeout=10)
                        self.assertEqual(status, 403, body)
                finally:
                    release.set()
                status, body = successful.result(timeout=10)
                self.assertEqual(status, 200, body)
            status, body = self._auth_request('/adm/api/login', wrong)
            self.assertEqual(status, 429, body)

    def test_successful_keepalive_logins_do_not_spend_or_reset_failed_budget(self):
        db.add_user('member', login_hash=secure.hash_password('member-password'))
        wrong = {'username': 'admin', 'password': 'wrong'}
        conn = http.client.HTTPConnection('127.0.0.1', self.port, timeout=15)
        try:
            with mock.patch.object(web, '_auth_clock', return_value=1000):
                status, body = self._auth_request('/adm/api/login', wrong, conn)
                self.assertEqual(status, 403, body)
                original_socket = conn.sock
                for i in range(12):
                    path = '/adm/api/login' if i % 2 else '/mem/api/login'
                    credentials = ({'username': 'admin', 'password': 'password123'} if i % 2 else
                                   {'name': 'member', 'password': 'member-password'})
                    status, body = self._auth_request(path, credentials, conn)
                    self.assertEqual(status, 200, body)
                    self.assertIs(conn.sock, original_socket)
                for _ in range(7):
                    status, body = self._auth_request('/adm/api/login', wrong, conn)
                    self.assertEqual(status, 403, body)
                status, body = self._auth_request('/adm/api/login', wrong, conn)
                self.assertEqual(status, 429, body)
        finally:
            conn.close()



if __name__ == '__main__':
    unittest.main()
