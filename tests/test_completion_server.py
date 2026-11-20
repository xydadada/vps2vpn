"""Residual regressions found while consolidating both server audits on main 6542508.

All transports are loopback fixtures or mocks; no public service or real account is contacted.
"""
import email.message
import json
import socket
import threading
import time
import unittest
from unittest.mock import Mock, patch

from tests import test_unit as tu
from vps2vpn import certs, cluster, cores, db, jobs, paths, rules, secure, subscription, web


def handler(body):
    h = web.Handler.__new__(web.Handler)
    h.headers = email.message.Message()
    h.headers['X-V2V'] = '1'
    h.client_address = ('127.0.0.1', 1)
    h.body_json = Mock(return_value=body)
    h.json = Mock(side_effect=lambda value, code=200, headers=None: (code, value, headers))
    h.rate_limited = Mock(return_value=False)
    h.auth_succeeded = Mock()
    return h


class AuthenticationSnapshots(tu.Base):
    def setUp(self):
        super().setUp()
        db.set_settings(setup_done=True, member_path='members',
                        admin_hash=secure.hash_password('old-password'))

    def test_successful_old_admin_login_cannot_survive_credential_rotation(self):
        old = db.settings()
        h = handler({'username': old['admin_user'], 'password': 'old-password'})

        def verified(*args):
            with db.transaction():
                db.set_settings(admin_hash='new-password-hash')
                db.end_all_sessions()
            return True

        with patch.object(secure, 'check_password', side_effect=verified):
            self.assertEqual(h.api_login(old)[0], 403)
        self.assertEqual(db.session_count(), 0)
        h.auth_succeeded.assert_not_called()

    def test_successful_old_member_login_cannot_survive_password_rotation(self):
        uid = db.add_user('member', login_hash=secure.hash_password('old-password'))
        h = handler({'name': 'member', 'password': 'old-password'})

        def verified(*args):
            with db.transaction():
                db.update_user(uid, login_hash='new-password-hash')
                db.end_member_session(None, uid)
            return True

        with patch.object(secure, 'check_password', side_effect=verified):
            result = h.member_area('POST', '/api/login', db.settings(), None, '/members/')
        self.assertEqual(result[0], 403)
        self.assertEqual(db.q('SELECT * FROM member_sessions'), [])

    def test_concurrent_admin_password_change_cannot_overwrite_newer_credentials(self):
        old = db.settings()
        h = handler({'old': 'old-password', 'new': 'replacement-password'})

        def verified(*args):
            db.set_settings(admin_hash='another-request-won')
            return True

        with patch.object(secure, 'check_password', side_effect=verified):
            self.assertEqual(h.api_password('POST', old)[0], 403)
        self.assertEqual(db.settings()['admin_hash'], 'another-request-won')
        self.assertEqual(db.session_count(), 0)

    def test_deleted_member_cannot_receive_an_orphan_session(self):
        uid = db.add_user('member')
        db.delete_user(uid)
        with self.assertRaises(ValueError):
            db.new_member_session(uid)
        self.assertEqual(db.q('SELECT * FROM member_sessions'), [])

    def test_malformed_password_work_factors_and_oversize_password_fail_closed(self):
        for encoded in ('pbkdf2_sha256$0$salt$digest', 'pbkdf2_sha256$999999999999999999999$salt$digest',
                        'pbkdf2_sha256$-1$salt$digest', None, 3):
            self.assertFalse(secure.check_password('password', encoded))
        encoded = secure.hash_password('small')
        with patch.object(secure.hashlib, 'pbkdf2_hmac') as derive:
            self.assertFalse(secure.check_password('x' * 129, encoded))
            derive.assert_not_called()


class RequestDeadline(tu.Base):
    def test_trickled_headers_cannot_extend_the_total_read_budget(self):
        class ShortRequest(web.Handler):
            request_read_timeout = 0.35

        server = web.Server(('127.0.0.1', 0), ShortRequest, web.TLSContext())
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        connection = socket.create_connection(server.server_address, timeout=2)
        try:
            connection.sendall(b'GET / HTTP/1.1\r\nHost: localhost\r\nX-Slow: ')
            started = time.monotonic()
            for _ in range(8):
                time.sleep(0.07)
                try:
                    connection.sendall(b'x')
                except OSError:
                    break
            self.assertEqual(connection.recv(1024), b'')
            self.assertLess(time.monotonic() - started, 1.5)
        finally:
            connection.close()
            server.shutdown()
            server.server_close()
            worker.join(3)


class StateAndTransport(tu.Base):
    def test_billing_reset_catches_missed_boundary_before_next_reset_day(self):
        stamp = lambda year, month, day: time.mktime((year, month, day, 12, 0, 0, 0, 0, -1))
        user = {'reset_day': 15, 'last_reset': '2026-10', 'created_at': stamp(2026, 10, 1)}
        self.assertEqual(jobs.monthly_reset(user, stamp(2026, 12, 3)), (True, '2026-11'))
        user['last_reset'] = '2026-11'
        self.assertEqual(jobs.monthly_reset(user, stamp(2026, 12, 3)), (False, '2026-11'))
        self.assertEqual(jobs.monthly_reset(user, stamp(2027, 1, 3)), (True, '2026-12'))
        self.assertEqual(jobs.monthly_reset(user, stamp(2026, 10, 3)), (False, '2026-09'))

    def test_first_scheduler_tick_preserves_a_new_accounts_traffic(self):
        uid = db.add_user('fresh', reset_day=1)
        db.add_traffic(uid, 123, 456)
        jobs.enforce()
        user = db.user(uid)
        self.assertEqual((user['used_up'], user['used_down']), (123, 456))
        self.assertEqual(user['last_reset'], '')

    def test_duplicate_remote_uuid_rejects_complete_sync_before_mutating_state(self):
        first = {'id': 1, 'name': 'first', 'uuid': 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
                 'hy2_pass': 'password', 'enabled': True}
        second = dict(first, id=2, name='second', uuid=first['uuid'].upper())
        before = db.export_all()
        with self.assertRaisesRegex(ValueError, 'UUIDs must be unique'):
            cluster.handle_sync(db.settings(), {'users': [first, second]})
        self.assertEqual(db.export_all(), before)

    def test_remote_uuid_cannot_shadow_a_local_account(self):
        uid = db.add_user('local')
        remote = {'id': 1, 'name': 'remote', 'uuid': db.user(uid)['uuid'].upper(),
                  'hy2_pass': 'password', 'enabled': True}
        before = db.export_all()
        with self.assertRaisesRegex(ValueError, 'local account'):
            cluster.handle_sync(db.settings(), {'users': [remote]})
        self.assertEqual(db.export_all(), before)

    def test_host_scoped_line_reports_roundtrip_after_main_upgrade(self):
        uid = db.add_user('member')
        reports = {'hy2': {str(uid) + '@node.example': [123, 'node.example'],
                           str(uid): [120, 'legacy.example']}}
        db.set_settings(line_reports=reports)
        db.import_all(json.loads(json.dumps(db.export_all())))
        self.assertEqual(db.settings()['line_reports'], reports)

    def test_self_signed_mode_overrides_a_still_trusted_acme_certificate(self):
        s = dict(db.settings(), cert_mode='self')
        with patch.object(certs, 'trusted', return_value=True):
            self.assertEqual(certs.current(s['public_host'], s['cert_mode']), (paths.SELF_CRT, paths.SELF_KEY))
            self.assertFalse(certs.using_acme(s))
            tls = subscription.tls_info(s)
        self.assertTrue(tls['pin'])
        self.assertIn('BEGIN CERTIFICATE', tls['pem'])

    def test_failed_batch_does_not_create_partial_accounts_or_apply_them(self):
        h = handler({'prefix': 'batch', 'count': 3})
        original = db.add_user
        created = []

        def add(*args, **kwargs):
            if created:
                raise OSError('injected write failure')
            created.append(original(*args, **kwargs))
            return created[-1]

        with patch.object(db, 'add_user', side_effect=add), patch.object(web, 'apply_async') as apply:
            with self.assertRaises(OSError):
                h.api_users_batch('POST', db.settings())
        self.assertEqual(db.users(), [])
        apply.assert_not_called()

    def test_local_stats_response_is_bounded_and_closed_on_failure(self):
        response = Mock()
        response.read.return_value = b'x' * ((8 << 20) + 1)
        context = Mock()
        context.__enter__ = Mock(return_value=response)
        context.__exit__ = Mock(return_value=False)
        with patch.object(cores._LOCAL_OPENER, 'open', return_value=context):
            with self.assertRaisesRegex(ValueError, 'too large'):
                cores._local_json(object(), 1)
        context.__exit__.assert_called_once()
        self.assertEqual(response.read.call_args.args, ((8 << 20) + 1,))

    def test_rule_size_limit_rejects_instead_of_publishing_truncated_data(self):
        response = Mock()
        response.read.return_value = b'x' * ((50 << 20) + 1)
        context = Mock()
        context.__enter__ = Mock(return_value=response)
        context.__exit__ = Mock(return_value=False)
        with patch.object(rules.urllib.request, 'urlopen', return_value=context):
            with self.assertRaisesRegex(ValueError, 'exceeds'):
                rules._fetch('https://fixture.invalid/rules')
        context.__exit__.assert_called_once()


if __name__ == '__main__':
    unittest.main()
