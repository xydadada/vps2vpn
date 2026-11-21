"""Tests for the management features: bulk actions, batch creation, CSV export, device limits, lifetime from
first use, two-step sign-in, sign-in history, custom routing, Telegram commands, 24-hour server history.

    python -m unittest tests.test_admin
"""
import json
import os
import threading
import time
import unittest

from tests import test_unit as tu          # sets VPS2VPN_ROOT / dev mode first
from vps2vpn import certs, db, jobs, notify, rules, secure, subscription, web

GIB = 1 << 30


class Totp(unittest.TestCase):
    def test_rfc6238_vector(self):
        # RFC 6238 appendix B, SHA-1, secret "12345678901234567890"
        import base64
        sec = base64.b32encode(b'12345678901234567890').decode()
        self.assertEqual(secure.totp(sec, at=59, digits=8), '94287082')
        self.assertEqual(secure.totp(sec, at=1111111109, digits=8), '07081804')

    def test_check_window(self):
        sec = secure.totp_secret()
        now = 1_700_000_000
        self.assertTrue(secure.totp_check(sec, secure.totp(sec, now), at=now))
        self.assertTrue(secure.totp_check(sec, secure.totp(sec, now - 30), at=now))     # clock drift
        self.assertFalse(secure.totp_check(sec, secure.totp(sec, now - 120), at=now))
        self.assertFalse(secure.totp_check(sec, '', at=now))
        self.assertFalse(secure.totp_check('', '123456', at=now))


class Limits(tu.Base):
    def test_lifetime_starts_on_first_use(self):
        uid = db.add_user('later', 0, expire_after_days=30)
        jobs.enforce()
        self.assertEqual(db.user(uid)['expire_at'], 0)                 # not used yet: clock not started
        db.add_traffic(uid, 10, 1000)
        jobs.enforce()
        u = db.user(uid)
        self.assertAlmostEqual(u['expire_at'], time.time() + 30 * 86400, delta=60)
        self.assertEqual(u['expire_after_days'], 0)

    def test_device_limit_pause_and_release(self):
        uid = db.add_user('busy', 0, max_ips=2)
        other = db.add_user('fine', 0, max_ips=2)
        online = {uid: {'ips': ['1.1.1.1', '2.2.2.2'], 'devices': 3, 'protocols': ['hy2', 'reality']},
                  other: {'ips': ['3.3.3.3'], 'devices': 1, 'protocols': ['reality']}}
        now = time.time()
        self.assertTrue(jobs.device_limits(db.settings(), online, now))
        u = db.user(uid)
        self.assertEqual((u['enabled'], u['disabled_reason']), (0, 'devices'))
        self.assertTrue(db.user(other)['enabled'])
        self.assertEqual(db.events('devices')[0]['user_id'], uid)
        jobs.enforce(now + 60)
        self.assertFalse(db.user(uid)['enabled'])                      # still inside the 10 minutes
        jobs.enforce(now + jobs.DEVICE_PAUSE + 1)
        u = db.user(uid)
        self.assertEqual((u['enabled'], u['disabled_reason']), (1, ''))

    def test_device_limit_warn_only(self):
        db.set_settings(ip_limit_pause=False)
        uid = db.add_user('warned', 0, max_ips=1)
        self.assertFalse(jobs.device_limits(db.settings(), {uid: {'ips': ['1.1.1.1', '2.2.2.2'], 'devices': 2}}))
        self.assertTrue(db.user(uid)['enabled'])
        self.assertEqual(len(db.events('devices')), 1)


class Routing(tu.Base):
    def test_custom_lists_in_every_format(self):
        s = dict(db.settings(), custom_direct=['corp.example'], custom_proxy=['news.example'],
                 custom_block=['tracker.example', 'corp.example'])
        plan = rules.route_plan(s)
        mine = [p for p in plan if p[1] in ('corp.example', 'news.example', 'tracker.example')]
        self.assertEqual(mine, [('suffix', 'tracker.example', 'reject'), ('suffix', 'corp.example', 'reject'),
                                ('suffix', 'news.example', 'proxy')])                 # block wins, no duplicates
        self.assertLess(plan.index(mine[0]), plan.index(('set', 'cn', 'cn')))
        uid = db.add_user('r', 0)
        u = db.user(uid)
        s['public_host'] = '203.0.113.5'
        clash = subscription.clash(s, u, 'https://x')
        self.assertIn('DOMAIN-SUFFIX,tracker.example,REJECT', clash['rules'])
        self.assertIn('DOMAIN-SUFFIX,news.example,%s' % subscription.names(s)['proxy'], clash['rules'])
        sb = subscription.singbox(s, u, 'https://x')
        self.assertIn({'domain_suffix': ['tracker.example'], 'action': 'reject'}, sb['route']['rules'])
        sr = subscription.shadowrocket(s, u, 'https://x')
        self.assertIn('DOMAIN-SUFFIX,tracker.example,REJECT', sr)

    def test_validation(self):
        s = db.settings()
        out = web.validate_settings({'custom_direct': 'https://Example.COM/path\n*.foo.org, +.bar.net\n\nexample.com'}, s)
        self.assertEqual(out['custom_direct'], ['example.com', 'foo.org', 'bar.net'])
        self.assertIsInstance(web.validate_settings({'custom_block': 'not a domain!'}, s), str)


class TelegramCommands(tu.Base):
    def test_commands(self):
        db.add_user('heavy', 10, used_down=5 * GIB)
        db.add_user('light', 0)
        out = jobs.tg_command('/users')
        self.assertLess(out.index('heavy'), out.index('light'))         # biggest first
        self.assertIn('heavy', jobs.tg_command('/user HEAVY'))
        self.assertIn('/status', jobs.tg_command('/help'))
        kind, name, data, _ = jobs.tg_command('/backup')
        self.assertEqual(kind, 'file')
        self.assertEqual(json.loads(data)['format'], 'vps2vpn-backup-1')

    def test_bot_answers_only_the_owner(self):
        db.set_settings(tg_token='1:x', tg_chat='42', tg_verified=True, setup_done=True)
        calls, sent = [], []
        stop = threading.Event()
        batches = [{'result': [{'update_id': 1, 'message': {'chat': {'id': 42, 'type': 'private'}, 'from': {'id': 42}, 'text': '/old'}}]},   # before start
                   {'result': [{'update_id': 2, 'message': {'chat': {'id': 7}, 'text': '/status'}},  # stranger
                               {'update_id': 3, 'message': {'chat': {'id': 42, 'type': 'group'}, 'from': {'id': 9},
                                                            'text': '/backup'}},       # a group that took the id
                               {'update_id': 4, 'message': {'chat': {'id': 42, 'type': 'private'}, 'from': {'id': 42},
                                                            'text': '/help'}}]}]

        def fake_call(token, method, params=None, timeout=10):
            calls.append((method, dict(params or {})))
            if method == 'getUpdates':
                if not batches:
                    stop.set()
                    return {'result': []}
                return batches.pop(0)
            sent.append(params)
            return {'ok': True}
        real = notify._call
        notify._call = fake_call
        try:
            notify.bot_loop(stop, lambda text: 'reply to ' + text, lambda m: None)
        finally:
            notify._call = real
        self.assertEqual([p['text'] for p in sent], ['reply to /help'])
        self.assertEqual(sent[0]['chat_id'], '42')
        self.assertEqual(calls[1][1]['offset'], 2)                       # old update acknowledged, not answered

    def test_disabled_or_rebound_during_poll_must_drop_stale_commands(self):
        changes = (
            {'tg_token': '', 'tg_chat': ''},
            {'tg_token': '2:y'},
            {'tg_chat': '99'},
            {'tg_bot': False},
        )
        for changed in changes:
            with self.subTest(changed=changed):
                db.set_settings(tg_token='1:x', tg_chat='42', tg_verified=True, tg_bot=True, setup_done=True)
                handled, sent = [], []
                stop = threading.Event()
                poll_count = [0]

                def fake_call(token, method, params=None, timeout=10):
                    if method == 'getUpdates':
                        poll_count[0] += 1
                        if poll_count[0] == 1:
                            return {'ok': True, 'result': []}  # initial backlog drained
                        db.set_settings(**changed)  # admin acts during the long-poll
                        stop.set()
                        return {'ok': True, 'result': [
                            {'update_id': 2, 'message': {'chat': {'id': 42, 'type': 'private'}, 'from': {'id': 42}, 'text': '/status'}}]}
                    sent.append((token, params))
                    return {'ok': True}

                def handle(command):
                    handled.append(command)
                    return 'private data'
                orig = notify._call
                notify._call = fake_call
                try:
                    notify.bot_loop(stop, handle, lambda line: None)
                finally:
                    notify._call = orig
                self.assertEqual(poll_count[0], 2)
                self.assertEqual(handled, [])
                self.assertEqual(sent, [])

    def test_disabling_during_handler_cancels_reply_and_later_commands(self):
        db.set_settings(tg_token='1:x', tg_chat='42', tg_verified=True, tg_bot=True, setup_done=True)
        handled, sent = [], []
        stop = threading.Event()
        polls = [0]

        def fake_call(token, method, params=None, timeout=10):
            if method == 'getUpdates':
                polls[0] += 1
                if polls[0] == 1:
                    return {'ok': True, 'result': []}
                stop.set()
                return {'ok': True, 'result': [
                    {'update_id': 2, 'message': {'chat': {'id': 42, 'type': 'private'}, 'from': {'id': 42}, 'text': '/status'}},
                    {'update_id': 3, 'message': {'chat': {'id': 42, 'type': 'private'}, 'from': {'id': 42}, 'text': '/backup'}}]}
            sent.append(params)
            return {'ok': True}

        def handle(command):
            handled.append(command)
            db.set_settings(tg_token='', tg_chat='')  # revocation while handle() is working
            return 'must not be sent'
        orig = notify._call
        notify._call = fake_call
        try:
            notify.bot_loop(stop, handle, lambda line: None)
        finally:
            notify._call = orig
        self.assertEqual(handled, ['/status'])
        self.assertEqual(sent, [])

    def test_long_reply_stops_between_chunks_after_revocation(self):
        db.set_settings(tg_token='1:x', tg_chat='42', tg_verified=True, tg_bot=True, setup_done=True)
        snapshot = db.settings()
        sent = []
        orig = notify._call

        def fake_call(token, method, params=None, timeout=10):
            sent.append((token, params['chat_id'], params['text']))
            db.set_settings(tg_token='', tg_chat='')
            return {'ok': True}
        notify._call = fake_call
        try:
            notify.reply(snapshot, '42', 'x' * (notify.MAX_TEXT + 10))
        finally:
            notify._call = orig
        self.assertEqual(len(sent), 1)
        self.assertEqual(sent[0][1], '42')
        self.assertEqual(len(sent[0][2]), notify.MAX_TEXT)


class History(tu.Base):
    def test_sample_and_reload(self):
        path = os.path.join(tu.ROOT if hasattr(tu, 'ROOT') else '.', 'hist-test.json')
        hst = jobs.History(path)
        hst.sample({'mem_total': 1000, 'mem_used': 250, 'rx_rate': 10, 'tx_rate': 20}, now=100)
        self.assertEqual(hst.points[-1][2:], [25.0, 10, 20])
        hst.save()
        self.assertEqual(jobs.History(path).points, hst.points)
        os.unlink(path)


class AdminWeb(tu.Base):
    """The admin API over real HTTPS."""

    def setUp(self):
        super().setUp()
        db.set_settings(public_host='127.0.0.1', setup_done=True, member_path='mem', panel_path='adm',
                        admin_hash=secure.hash_password('adminpassword'))
        certs.ensure_self_signed('127.0.0.1')
        self.httpd = web.Server(('127.0.0.1', 0), web.Handler, web.TLSContext())
        self.port = self.httpd.server_address[1]
        db.set_settings(panel_port=self.port)
        self._thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self._thread.start()
        self.cookie = ''
        web._fails.clear()
        self._apply = web.apply_async
        web.apply_async = lambda force=False: None

    def tearDown(self):
        web.apply_async = self._apply
        self.httpd.shutdown()
        self.httpd.server_close()
        self._thread.join(5)

    req = tu.Web.req

    def login(self, **extra):
        return self.req('POST', '/adm/api/login', dict({'username': 'admin', 'password': 'adminpassword'}, **extra))

    def test_batch_bulk_and_export(self):
        self.login()
        st, body, _ = self.req('POST', '/adm/api/users-batch', {'prefix': 'team', 'count': 3, 'quota_gb': 10,
                                                               'expire_after_days': 7, 'max_ips': 2})
        self.assertEqual(st, 200, body)
        ids = json.loads(body)['ids']
        users = [db.user(i) for i in ids]
        self.assertEqual([u['name'] for u in users], ['team-01', 'team-02', 'team-03'])
        self.assertEqual({(u['quota_gb'], u['expire_after_days'], u['max_ips']) for u in users}, {(10, 7, 2)})
        st, body, _ = self.req('POST', '/adm/api/users-batch', {'prefix': 'team', 'count': 1})
        self.assertEqual(db.user(json.loads(body)['ids'][0])['name'], 'team-04')     # skips taken names
        dated = db.add_user('dated', 0, expire_at=int(time.time()) - 86400)            # already expired
        for action, value in (('add_gb', 5), ('extend', 10), ('disable', 0)):
            st, body, _ = self.req('POST', '/adm/api/users-bulk', {'ids': ids + [dated], 'action': action, 'value': value})
            self.assertEqual(st, 200, body)
        self.assertEqual(db.user(ids[0])['quota_gb'], 15)
        self.assertAlmostEqual(db.user(dated)['expire_at'], time.time() + 10 * 86400, delta=60)   # from today
        self.assertEqual(db.user(ids[0])['expire_at'], 0)            # no date yet: extend leaves it alone
        self.assertEqual(db.user(ids[1])['disabled_reason'], 'manual')
        self.assertEqual(self.req('POST', '/adm/api/users-bulk', {'ids': ids, 'action': 'extend', 'value': -1})[0], 400)
        self.assertEqual(self.req('POST', '/adm/api/users-bulk', {'ids': ids, 'action': 'drop'})[0], 400)
        st, body, headers = self.req('GET', '/adm/api/users-export')
        self.assertEqual(st, 200)
        text = body.decode('utf-8-sig')
        self.assertIn('team-01', text)
        self.assertIn('/s/' + db.user(ids[0])['sub_token'], text)
        st, body, _ = self.req('POST', '/adm/api/users-bulk', {'ids': ids, 'action': 'delete'})
        self.assertIsNone(db.user(ids[0]))

    def test_bulk_rejects_oversized_requests_atomically(self):
        self.login()
        uid = db.add_user('bulk-limit', 10)
        ids = [uid] + list(range(100000, 102000))
        st, body, _ = self.req('POST', '/adm/api/users-bulk',
                               {'ids': ids, 'action': 'disable'})
        self.assertEqual(st, 400, body)
        self.assertIn('2000', json.loads(body)['error'])
        self.assertEqual(db.user(uid)['enabled'], 1)

    def test_bulk_expire_extension_respects_max_epoch_atomically(self):
        self.login()
        first_expiry = int(time.time()) + 15 * 86400
        first = db.add_user('expiry-ok-first', 1, expire_at=first_expiry)
        boundary = db.add_user('expiry-at-max', 1, expire_at=web.MAX_ACCOUNT_EXPIRE_AT)
        status, body, _ = self.req('POST', '/adm/api/users-bulk',
                                   {'ids': [first, boundary], 'action': 'extend', 'value': 1})
        self.assertEqual(status, 400, body)
        self.assertIn('expire_at', json.loads(body)['error'])
        self.assertEqual(db.user(first)['expire_at'], first_expiry)
        self.assertEqual(db.user(boundary)['expire_at'], web.MAX_ACCOUNT_EXPIRE_AT)

    def test_bulk_repeated_ids_are_applied_only_once(self):
        self.login()
        expires = int(time.time()) + 20 * 86400
        uid = db.add_user('bulk-once', 10, expire_at=expires)
        repeated = [uid, str(uid), uid]

        status, body, _ = self.req('POST', '/adm/api/users-bulk',
                                   {'ids': repeated, 'action': 'add_gb', 'value': 3})
        self.assertEqual(status, 200, body)
        self.assertEqual(json.loads(body)['done'], 1)
        self.assertEqual(db.user(uid)['quota_gb'], 13)

        status, body, _ = self.req('POST', '/adm/api/users-bulk',
                                   {'ids': repeated, 'action': 'extend', 'value': 2})
        self.assertEqual(status, 200, body)
        self.assertEqual(json.loads(body)['done'], 1)
        self.assertEqual(db.user(uid)['expire_at'], expires + 2 * 86400)

        # A string is not an ID array: iterating its characters used to
        # silently mutate unrelated accounts that happened to have those IDs.
        for bad in (str(uid), {'id': uid}, 10, True):
            status, _, _ = self.req('POST', '/adm/api/users-bulk',
                                    {'ids': bad, 'action': 'add_gb', 'value': 99})
            self.assertEqual(status, 400)
        # Even inside a correctly typed array, lossy int(True/1.9) must not
        # silently edit user #1. Parse and validate the complete target list
        # before touching any account.
        for bad_id in (True, False, 1.5, -1, 0, '1e0', {'id': uid}):
            status, _, _ = self.req('POST', '/adm/api/users-bulk',
                                    {'ids': [uid, bad_id], 'action': 'add_gb', 'value': 99})
            self.assertEqual(status, 400, bad_id)
        self.assertEqual(db.user(uid)['quota_gb'], 13)

    def test_two_step_sign_in_and_history(self):
        self.login()
        st, body, _ = self.req('GET', '/adm/api/totp')
        sec = json.loads(body)['secret']
        now = time.time()
        valid = {secure.totp(sec, now + d) for d in (-30, 0, 30)}
        wrong = next('%06d' % i for i in range(10) if '%06d' % i not in valid)
        self.assertEqual(self.req('POST', '/adm/api/totp', {'secret': sec, 'code': wrong})[0], 400)
        st, body, _ = self.req('POST', '/adm/api/totp', {'secret': sec, 'code': secure.totp(sec)})
        self.assertEqual(st, 200, body)
        state = json.loads(self.req('GET', '/adm/api/state')[1])
        self.assertTrue(state['settings']['totp_on'])
        self.assertNotIn('admin_totp', state['settings'])
        self.cookie = ''
        st, body, _ = self.login()
        self.assertEqual((st, json.loads(body)['error']), (403, 'totp_required'))
        self.assertEqual(self.login(code=wrong)[0], 403)
        st, body, _ = self.login(code=secure.totp(sec))
        self.assertEqual(st, 200, body)
        hist = json.loads(self.req('GET', '/adm/api/security')[1])
        self.assertEqual([x['kind'] for x in hist['logins'][:3]], ['ok', 'fail2fa', 'ok'])
        self.assertEqual(self.req('POST', '/adm/api/totp', {'off': True, 'password': 'wrong'})[0], 403)
        self.assertEqual(self.req('POST', '/adm/api/totp', {'off': True, 'password': 'adminpassword'})[0], 200)
        self.assertEqual(db.settings()['admin_totp'], '')

    def test_sign_out_other_devices(self):
        self.login()
        mine = self.cookie
        other = db.new_session()
        self.req('POST', '/adm/api/security', {'logout_others': True})
        self.assertFalse(db.session_ok(other))
        self.assertEqual(self.req('GET', '/adm/api/state')[0], 200)
        self.assertEqual(self.cookie, mine)


if __name__ == '__main__':
    unittest.main()
