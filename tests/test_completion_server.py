"""Final audit regressions: certificate identity and credential publication races."""
import http.client
import io
import json
import os
import ssl
import tempfile
import threading
import time
import types
import unittest
from unittest import mock

from tests import test_unit as tu
from vps2vpn import certs, cluster, cores, db, members, notify, paths, secure, subscription, web
from vps2vpn import __main__ as cli


def handler(body):
    h = object.__new__(web.Handler)
    h.headers = {'X-V2V': '1', 'User-Agent': 'audit-test'}
    h.client_address = ('127.0.0.1', 1)
    h.body_json = lambda **kwargs: body
    h.rate_limited = lambda: False
    h.json = lambda value, code=200, headers=None: (code, value, headers or {})
    return h


class CredentialPublication(tu.Base):
    def test_cli_password_reset_uses_the_login_length_limits(self):
        old_hash = secure.hash_password('old-password')
        db.set_settings(admin_user='admin', admin_hash=old_hash)
        token = db.new_session()
        for password in ('x' * 7, 'x' * 129):
            with self.subTest(length=len(password)), self.assertRaises(SystemExit):
                cli.cmd_reset_password(types.SimpleNamespace(password=password, username='new-admin'))
            self.assertEqual(db.settings()['admin_hash'], old_hash)
            self.assertEqual(db.settings()['admin_user'], 'admin')
            self.assertTrue(db.session_ok(token))
        with mock.patch('builtins.print'):
            cli.cmd_reset_password(types.SimpleNamespace(password='x' * 128, username='new-admin'))
        self.assertTrue(secure.check_password('x' * 128, db.settings()['admin_hash']))
        self.assertFalse(db.session_ok(token))

    def test_cli_password_reset_rolls_back_if_session_revocation_fails(self):
        old_hash = secure.hash_password('old-password')
        db.set_settings(admin_hash=old_hash)
        token = db.new_session()
        with mock.patch.object(db, 'end_all_sessions', side_effect=RuntimeError('storage unavailable')):
            with self.assertRaisesRegex(RuntimeError, 'storage unavailable'):
                cli.cmd_reset_password(types.SimpleNamespace(password='new-password', username=None))
        self.assertEqual(db.settings()['admin_hash'], old_hash)
        self.assertTrue(db.session_ok(token))

    def test_admin_login_cannot_publish_after_identity_or_second_factor_changes(self):
        old_hash = secure.hash_password('old-password')
        new_hash = secure.hash_password('new-password')
        for changes in ({'admin_hash': new_hash}, {'admin_user': 'renamed'},
                        {'admin_totp': secure.totp_secret()}):
            with self.subTest(changes=list(changes)):
                db.set_settings(admin_user='admin', admin_hash=old_hash, admin_totp='')
                s = db.settings()
                check = secure.check_password

                def verify(password, stored):
                    result = check(password, stored)
                    db.set_settings(**changes)
                    db.end_all_sessions()
                    return result

                h = handler({'username': 'admin', 'password': 'old-password'})
                with mock.patch.object(secure, 'check_password', side_effect=verify):
                    status, _, headers = h.api_login(s)
                self.assertEqual(status, 403)
                self.assertNotIn('Set-Cookie', headers)
                self.assertEqual(db.session_count(), 0)

    def test_member_login_cannot_publish_after_password_reset_or_deletion(self):
        for deleted in (False, True):
            with self.subTest(deleted=deleted):
                uid = db.add_user('member-' + str(deleted), login_hash=secure.hash_password('old-password'))
                old = db.user(uid)
                check = secure.check_password

                def verify(password, stored):
                    result = check(password, stored)
                    if deleted:
                        db.delete_user(uid)
                    else:
                        db.update_user(uid, login_hash=secure.hash_password('new-password'))
                        db.end_member_session(None, uid)
                    return result

                h = handler({'name': old['name'], 'password': 'old-password'})
                s = db.settings()
                with mock.patch.object(secure, 'check_password', side_effect=verify):
                    status, _, headers = h.member_area('POST', '/api/login', s, None, '/member/')
                self.assertEqual(status, 403)
                self.assertNotIn('Set-Cookie', headers)
                self.assertEqual(db.q('SELECT * FROM member_sessions WHERE user_id=?', (uid,)), [])

    def test_admin_password_change_rolls_back_if_session_issuance_fails(self):
        old_hash = secure.hash_password('old-password')
        db.set_settings(admin_hash=old_hash)
        token = db.new_session()
        h = handler({'old': 'old-password', 'new': 'new-password'})
        with mock.patch.object(db, 'new_session', side_effect=RuntimeError('storage unavailable')):
            with self.assertRaisesRegex(RuntimeError, 'storage unavailable'):
                h.api_password('POST', db.settings())
        self.assertEqual(db.settings()['admin_hash'], old_hash)
        self.assertTrue(db.session_ok(token))

    def test_late_admin_password_change_cannot_overwrite_new_credentials(self):
        old_hash = secure.hash_password('old-password')
        winner = secure.hash_password('winner-password')
        db.set_settings(admin_hash=old_hash)
        s = db.settings()
        hash_password = secure.hash_password

        def delayed_hash(password):
            db.set_settings(admin_hash=winner)
            return hash_password(password)

        with mock.patch.object(secure, 'hash_password', side_effect=delayed_hash):
            status, _, headers = handler({'old': 'old-password', 'new': 'loser-password'}).api_password('POST', s)
        self.assertEqual(status, 403)
        self.assertNotIn('Set-Cookie', headers)
        self.assertEqual(db.settings()['admin_hash'], winner)

    def test_late_member_password_change_cannot_overwrite_new_credentials(self):
        uid = db.add_user('member', login_hash=secure.hash_password('old-password'))
        old = db.user(uid)
        winner = secure.hash_password('winner-password')
        hash_password = secure.hash_password

        def delayed_hash(password):
            db.update_user(uid, login_hash=winner)
            return hash_password(password)

        h = handler({'old': 'old-password', 'new': 'loser-password'})
        with mock.patch.object(secure, 'hash_password', side_effect=delayed_hash):
            status, _, headers = h.member_area('POST', '/api/password', db.settings(), old, '/s/token/')
        self.assertEqual(status, 403)
        self.assertNotIn('Set-Cookie', headers)
        self.assertEqual(db.user(uid)['login_hash'], winner)


class InviteReservations(tu.Base):
    def history_after(self, uid, count=101):
        for number in range(count):
            db.add_invite(code='retired-%d' % number, kind='member', inviter=uid, quota_gb=0.1,
                          valid_until=2_000_000_000, status='revoked')

    def test_old_live_invitation_keeps_its_reservation_beyond_history_window(self):
        uid = db.add_user('owner', quota_gb=10)
        old = members.create_invite('member', 5, 7, inviter=uid, by_member=True)
        self.history_after(uid)
        self.assertNotIn(old['id'], [entry['id'] for entry in db.invites(uid)])
        self.assertEqual(members.reserved(uid), 5)
        self.assertEqual(members.capacity(db.user(uid)), 4)
        with self.assertRaisesRegex(members.Refused, 'not enough quota'):
            members.create_invite('member', 9, 7, inviter=uid, by_member=True)
        child = members.register(old['code'], 'child', 'password123')
        self.assertEqual(db.user(child)['quota_gb'], 5)
        self.assertEqual(members.capacity(db.user(uid)), 4)

    def test_pending_code_limit_counts_codes_outside_history_window(self):
        uid = db.add_user('owner', quota_gb=100)
        for _ in range(members.MEMBER_PENDING_MAX):
            members.create_invite('member', 1, 7, inviter=uid, by_member=True)
        self.history_after(uid)
        with self.assertRaisesRegex(members.Refused, 'at most 5'):
            members.create_invite('member', 1, 7, inviter=uid, by_member=True)


class NotificationOwnership(tu.Base):
    def test_pending_long_poll_cannot_run_commands_after_bot_is_disabled(self):
        db.set_settings(tg_token='fixture', tg_chat='7', tg_bot=True, setup_done=True)
        stop = threading.Event()

        def poll(*args, **kwargs):
            db.set_settings(tg_bot=False)
            stop.set()
            return {'ok': True, 'result': [{'update_id': 1, 'message': {
                'date': int(time.time()) + 1, 'text': '/backup',
                'chat': {'id': 7, 'type': 'private'}, 'from': {'id': 7}}}]}

        with mock.patch.object(notify, '_call', side_effect=poll), \
                mock.patch.object(notify, 'send_file') as send_file:
            handle = mock.Mock()
            notify.bot_loop(stop, handle, lambda text: None)
        handle.assert_not_called()
        send_file.assert_not_called()

    def test_failed_api_result_releases_cooldown_for_retry(self):
        responses = [io.BytesIO(json.dumps(value).encode()) for value in
                     ({'ok': False, 'description': 'rejected'}, {'ok': True, 'result': {}})]
        settings = {'tg_token': 'fixture', 'tg_chat': '7', 'node_name': 'node'}
        with mock.patch.object(notify, '_recent', {}), mock.patch.object(notify, '_pending', set()), \
                mock.patch.object(notify.urllib.request, 'urlopen', side_effect=responses) as request:
            self.assertFalse(notify.send('test', key='same', s=settings))
            self.assertTrue(notify.send('test', key='same', s=settings))
            self.assertFalse(notify.send('test', key='same', s=settings))
            self.assertEqual(request.call_count, 2)
        self.assertTrue(all(response.closed for response in responses))

    def test_parallel_alerts_reserve_one_inflight_send(self):
        entered, release = threading.Event(), threading.Event()
        results = []
        settings = {'tg_token': 'fixture', 'tg_chat': '7', 'node_name': 'node'}

        def call(*args, **kwargs):
            entered.set()
            if not release.wait(5):
                raise RuntimeError('test did not release sender')
            return {'ok': True}

        with mock.patch.object(notify, '_recent', {}), mock.patch.object(notify, '_pending', set()), \
                mock.patch.object(notify, '_call', side_effect=call) as request:
            worker = threading.Thread(target=lambda: results.append(notify.send('test', key='same', s=settings)))
            worker.start()
            try:
                self.assertTrue(entered.wait(3))
                self.assertFalse(notify.send('test', key='same', s=settings))
            finally:
                release.set()
                worker.join(5)
            self.assertFalse(worker.is_alive())
            self.assertEqual(results, [True])
            request.assert_called_once()


class CertificateIdentity(tu.Base):
    def test_distinct_connection_host_uses_domain_certificate_everywhere(self):
        with tempfile.TemporaryDirectory() as directory:
            ca, ca_key, csr, extensions = [os.path.join(directory, name) for name in
                                           ('ca.pem', 'ca.key', 'leaf.csr', 'extensions.cnf')]
            certs._openssl('req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1',
                           '-nodes', '-keyout', ca_key, '-out', ca, '-days', '2', '-subj', '/CN=Audit Local CA',
                           '-addext', 'basicConstraints=critical,CA:TRUE')
            certs._openssl('req', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1',
                           '-nodes', '-keyout', paths.ACME_KEY, '-out', csr, '-subj', '/CN=localhost')
            with open(extensions, 'w') as stream:
                stream.write('subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\n')
            certs._openssl('x509', '-req', '-in', csr, '-CA', ca, '-CAkey', ca_key, '-CAcreateserial',
                           '-out', paths.ACME_CRT, '-days', '2', '-extfile', extensions)
            db.set_settings(public_host='127.0.0.1', domain='localhost', setup_done=True)
            certs._trust_cache.clear()
            with mock.patch.dict(os.environ, {'SSL_CERT_FILE': ca}):
                s = db.settings()
                self.assertTrue(certs.trusted('localhost'))
                self.assertFalse(certs.trusted('127.0.0.1'))
                self.assertEqual(certs.current(), (paths.ACME_CRT, paths.ACME_KEY))
                self.assertEqual(subscription.tls_info(s), {'sni': 'localhost', 'pin': '', 'pem': ''})
                self.assertEqual(cores.hysteria_config(s, [])['tls']['cert'], paths.ACME_CRT)
                self.assertEqual(cores.tuic_config(s, [])['inbounds'][0]['tls']['certificate_path'], paths.ACME_CRT)
                joined = cluster.parse_join_code(cluster.join_code(s, 'https://localhost:443'))
                self.assertEqual(joined['pin'], certs.fingerprint(paths.ACME_CRT))
                server = web.Server(('127.0.0.1', 0), web.Handler, web.TLSContext())
                worker = threading.Thread(target=server.serve_forever, daemon=True)
                worker.start()
                connection = http.client.HTTPSConnection('localhost', server.server_address[1], timeout=5,
                                                        context=ssl.create_default_context(cafile=ca))
                try:
                    connection.request('GET', '/missing')
                    response = connection.getresponse()
                    self.assertEqual(response.status, 404)
                    response.read()
                finally:
                    connection.close()
                    server.shutdown()
                    server.server_close()
                    worker.join(5)
            certs._trust_cache.clear()


if __name__ == '__main__':
    unittest.main()
