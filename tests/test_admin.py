"""Tests for the management features: bulk actions, batch creation, CSV export, device limits, lifetime from
first use, two-step sign-in, sign-in history, custom routing, Telegram commands, 24-hour server history.

    python -m unittest tests.test_admin
"""
import json
import os
import threading
import time
import unittest
from unittest import mock

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
        now = time.time()
        for minute in range(1, 30):                                   # still over the limit every check
            jobs.device_limits(db.settings(), {uid: {'ips': ['1.1.1.1', '2.2.2.2'], 'devices': 2}}, now + 60 * minute)
        self.assertEqual(len(db.events('devices')), 1)
        jobs.device_limits(db.settings(), {uid: {'ips': ['1.1.1.1', '2.2.2.2'], 'devices': 2}}, now + 3700)
        self.assertEqual(len(db.events('devices')), 2)


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

    def test_day_scale_reminder_is_not_repeated_after_a_restart(self):
        db.set_settings(tg_token='1:x', tg_chat='42', tg_verified=True)
        sent = []

        def fake_call(token, method, params=None, timeout=10):
            sent.append((params or {}).get('text'))
            return {'ok': True}
        real = notify._call
        notify._call = fake_call
        try:
            self.assertTrue(notify.send('ends tomorrow', key='uexp1-7-100', every=40 * 86400))
            with notify._recent_lock:
                notify._recent.clear()                                   # what a restart forgets
            self.assertFalse(notify.send('ends tomorrow', key='uexp1-7-100', every=40 * 86400))
            # Short-window alerts stay in memory only and may repeat after a restart.
            self.assertTrue(notify.send('core down', key='down', every=600))
            with notify._recent_lock:
                notify._recent.clear()
            self.assertTrue(notify.send('core down', key='down', every=600))
            # A new owner chat still gets its first reminder.
            db.set_settings(tg_chat='43')
            self.assertTrue(notify.send('ends tomorrow', key='uexp1-7-100', every=40 * 86400))
            # Once the window has passed it is sent again.
            db.set_settings(tg_chat='42')
            with notify._recent_lock:
                notify._recent.clear()
            stored = [r['key'] for r in db.q('SELECT key FROM alerts_sent') if r['key'].endswith(':42:uexp1-7-100')]
            db.mark_alert_sent(stored[0], at=time.time() - 41 * 86400)
            self.assertTrue(notify.send('ends tomorrow', key='uexp1-7-100', every=40 * 86400))
        finally:
            notify._call = real
        self.assertEqual(len(sent), 5)

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

    def test_nonfinite_admin_numbers_are_bad_requests_without_changes(self):
        # JSON numbers such as 1e309 decode to float('inf'), then int(inf)
        # raises OverflowError. Every affected API should return HTTP 400.
        self.login()
        users_before = len(db.users())
        invites_before = len(db.invites())
        settings_before = db.settings()
        nonfinite = float('inf')
        cases = (
            ('users-batch', {'prefix': 'nonfinite', 'count': nonfinite}),
            ('invites', {'kind': 'admin', 'inviter': nonfinite}),
            ('invites', {'kind': 'admin', 'max_uses': nonfinite}),
            ('invites', {'kind': 'admin', 'valid_days': nonfinite}),
            ('settings', {'hy2_port': nonfinite}),
            ('settings', {'server_reset_day': nonfinite}),
        )
        for endpoint, payload in cases:
            with self.subTest(endpoint=endpoint, payload=payload):
                status, body, _ = self.req('POST', '/adm/api/' + endpoint, payload)
                self.assertEqual(status, 400, body)
        self.assertEqual(len(db.users()), users_before)
        self.assertEqual(len(db.invites()), invites_before)
        self.assertEqual(db.settings()['hy2_port'], settings_before['hy2_port'])
        self.assertEqual(db.settings()['server_reset_day'], settings_before['server_reset_day'])

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

    def test_bulk_value_too_large_for_float_is_rejected_not_500(self):
        self.login()
        uid = db.add_user('bulk-huge', 10)
        with mock.patch.object(web.jobs, 'enforce') as enforce:
            for action in ('extend', 'add_gb', 'set_quota'):
                status, body, _ = self.req('POST', '/adm/api/users-bulk',
                                           {'ids': [uid], 'action': action, 'value': 10 ** 309})
                self.assertEqual(status, 400, body)
                self.assertIn('invalid number', json.loads(body)['error'])
            enforce.assert_not_called()
        self.assertEqual(db.user(uid)['quota_gb'], 10)
        self.assertEqual(db.user(uid)['expire_at'], 0)

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
        # A stolen-but-valid session must not replace the enrolled factor:
        # the attacker can generate a valid code for its own proposed secret.
        replacement_secret = secure.totp_secret()
        self.assertNotEqual(replacement_secret, sec)
        st, body, _ = self.req('POST', '/adm/api/totp',
                               {'secret': replacement_secret,
                                'code': secure.totp(replacement_secret)})
        self.assertEqual(st, 409, body)
        self.assertEqual(db.settings()['admin_totp'], sec)
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


    def test_parallel_totp_disable_cannot_erase_successful_enrollment(self):
        self.login()
        new_secret = secure.totp_secret()
        off_entered = threading.Event()
        off_continue = threading.Event()
        enroll_verified = threading.Event()
        enroll_done = threading.Event()
        results = {}
        original_set = db.set_settings
        original_check = secure.totp_check

        def slow_disable(**values):
            if values.get('admin_totp') == '':
                off_entered.set()
                if not off_continue.wait(5):
                    raise RuntimeError('disable interleaving timed out')
            return original_set(**values)

        def signal_verify(secret, code, *args, **kwargs):
            if secret == new_secret:
                enroll_verified.set()
            return original_check(secret, code, *args, **kwargs)

        def disable():
            results['off'] = self.req('POST', '/adm/api/totp',
                                      {'off': True, 'password': 'adminpassword'})

        def enroll():
            try:
                results['enroll'] = self.req('POST', '/adm/api/totp',
                                              {'secret': new_secret, 'code': secure.totp(new_secret)})
            finally:
                enroll_done.set()

        # Starting with no factor is intentional: the off endpoint currently
        # permits a password-confirmed no-op; it must still be serializable.
        with mock.patch.object(db, 'set_settings', side_effect=slow_disable), \
             mock.patch.object(secure, 'totp_check', side_effect=signal_verify):
            off_thread = threading.Thread(target=disable)
            enroll_thread = threading.Thread(target=enroll)
            off_thread.start()
            try:
                self.assertTrue(off_entered.wait(5), 'disable never reached the DB write')
                enroll_thread.start()
                self.assertTrue(enroll_verified.wait(5), 'enrollment did not validate its code')
                self.assertFalse(enroll_done.wait(0.1),
                                 'enrollment must wait for in-flight disable to commit')
            finally:
                off_continue.set()
                off_thread.join(5)
                if enroll_thread.ident is not None:
                    enroll_thread.join(5)
        self.assertFalse(off_thread.is_alive())
        self.assertFalse(enroll_thread.is_alive())
        self.assertEqual(results['off'][0], 200, results)
        self.assertEqual(results['enroll'][0], 200, results)
        self.assertEqual(db.settings()['admin_totp'], new_secret)

    def test_sign_out_other_devices(self):
        self.login()
        mine = self.cookie
        other = db.new_session()
        self.req('POST', '/adm/api/security', {'logout_others': True})
        self.assertFalse(db.session_ok(other))
        self.assertEqual(self.req('GET', '/adm/api/state')[0], 200)
        self.assertEqual(self.cookie, mine)


class AuthHardening(tu.Base):
    """Security audit 2026-11: lockout bypasses, session rotation, secrets in logs, headers."""

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

    tearDown = AdminWeb.tearDown
    req = tu.Web.req
    login = AdminWeb.login

    def _member(self, name, password):
        uid = db.add_user(name, 0)
        db.update_user(uid, login_hash=secure.hash_password(password))
        return uid

    def test_own_member_login_does_not_reset_the_admin_or_member_lockout(self):
        self._member('mallory', 'mallorypassword')
        self._member('victim', 'victimpassword')
        for _ in range(7):
            self.assertEqual(self.login(password='guess')[0], 403)
        # a successful login to an account the attacker owns must not wipe the count
        self.assertEqual(self.req('POST', '/mem/api/login', {'name': 'mallory', 'password': 'mallorypassword'})[0], 200)
        self.cookie = ''
        self.assertEqual(self.login(password='guess')[0], 403)
        self.assertEqual(self.login()[0], 429)
        web._fails.clear()
        for _ in range(7):
            self.assertEqual(self.req('POST', '/mem/api/login', {'name': 'victim', 'password': 'guess'})[0], 403)
        self.assertEqual(self.req('POST', '/mem/api/login', {'name': 'mallory', 'password': 'mallorypassword'})[0], 200)
        self.cookie = ''
        self.assertEqual(self.req('POST', '/mem/api/login', {'name': 'victim', 'password': 'guess'})[0], 403)
        self.assertEqual(self.req('POST', '/mem/api/login', {'name': 'victim', 'password': 'victimpassword'})[0], 429)

    def test_member_failures_do_not_lock_out_the_admin(self):
        for _ in range(8):
            self.req('POST', '/mem/api/login', {'name': 'nobody', 'password': 'guess'})
        self.assertEqual(self.login()[0], 200)

    def test_parallel_guesses_cannot_exceed_the_limit(self):
        codes = []
        lock = threading.Lock()

        def guess():
            st = self.req('POST', '/adm/api/login', {'username': 'admin', 'password': 'guess'})[0]
            with lock:
                codes.append(st)
        threads = [threading.Thread(target=guess) for _ in range(24)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(60)
        self.assertEqual(len(codes), 24)
        self.assertLessEqual(codes.count(403), 8, codes)
        self.assertEqual(codes.count(403) + codes.count(429), 24, codes)

    def test_admin_password_change_is_rate_limited_and_bounded(self):
        self.login()
        for _ in range(8):
            self.assertEqual(self.req('POST', '/adm/api/password', {'old': 'guess', 'new': 'newpassword'})[0], 403)
        self.assertEqual(self.req('POST', '/adm/api/password', {'old': 'adminpassword', 'new': 'newpassword'})[0], 429)
        self.assertTrue(secure.check_password('adminpassword', db.settings()['admin_hash']))
        web._fails.clear()
        # login refuses passwords over 128 characters, so one must not be settable here
        st, _, _ = self.req('POST', '/adm/api/password', {'old': 'adminpassword', 'new': 'x' * 129})
        self.assertEqual(st, 400)
        self.assertTrue(secure.check_password('adminpassword', db.settings()['admin_hash']))

    def test_member_password_change_is_rate_limited(self):
        uid = self._member('zed', 'zedpassword1')
        link = '/s/%s/api/password' % db.user(uid)['sub_token']
        for _ in range(8):
            self.assertEqual(self.req('POST', link, {'old': 'guess', 'new': 'otherpassword'})[0], 403)
        self.assertEqual(self.req('POST', link, {'old': 'zedpassword1', 'new': 'otherpassword'})[0], 429)
        self.assertTrue(secure.check_password('zedpassword1', db.user(uid)['login_hash']))

    def test_pending_member_login_cannot_reauthorize_an_old_password(self):
        uid = self._member('member-race', 'oldmemberpassword')
        self.assertEqual(self.req('POST', '/mem/api/login',
                                  {'name': 'member-race', 'password': 'oldmemberpassword'})[0], 200)
        entered, resume = threading.Event(), threading.Event()
        result = []
        original_check = secure.check_password

        def slow_check(password, stored):
            # The login is checked by the HTTPS server worker, not the
            # client thread that calls self.req(). Pause its first check.
            if password == 'oldmemberpassword' and not entered.is_set():
                entered.set()
                if not resume.wait(10):
                    raise RuntimeError('member login race timed out')
            return original_check(password, stored)

        def old_login():
            result.append(self.req('POST', '/mem/api/login',
                                   {'name': 'member-race', 'password': 'oldmemberpassword'}))

        worker = threading.Thread(target=old_login, daemon=True)
        with mock.patch.object(secure, 'check_password', side_effect=slow_check):
            worker.start()
            try:
                self.assertTrue(entered.wait(5), 'login never reached password verification')
                status, body, _ = self.req('POST', '/mem/api/password',
                                           {'old': 'oldmemberpassword', 'new': 'newmemberpassword'})
                self.assertEqual(status, 200, body)
            finally:
                resume.set()
                worker.join(5)
        self.assertFalse(worker.is_alive())
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0][0], 409, result[0][1])
        self.assertEqual(db.member_session(self.cookie.split('=', 1)[1]), uid)
        self.cookie = ''
        self.assertEqual(self.req('POST', '/mem/api/login',
                                  {'name': 'member-race', 'password': 'oldmemberpassword'})[0], 403)
        self.assertEqual(self.req('POST', '/mem/api/login',
                                  {'name': 'member-race', 'password': 'newmemberpassword'})[0], 200)

    def test_member_password_change_ends_a_stolen_copy_of_the_session(self):
        self._member('yan', 'yanpassword1')
        self.assertEqual(self.req('POST', '/mem/api/login', {'name': 'yan', 'password': 'yanpassword1'})[0], 200)
        stolen = self.cookie
        st, body, _ = self.req('POST', '/mem/api/password', {'old': 'yanpassword1', 'new': 'yanpassword2'})
        self.assertEqual(st, 200, body)
        self.assertNotEqual(self.cookie, stolen)
        self.assertEqual(self.req('GET', '/mem/api/me')[0], 200)
        self.cookie = stolen
        self.assertEqual(self.req('GET', '/mem/api/me')[0], 401)

    def test_2fa_changes_end_every_other_session(self):
        self.login()
        other = db.new_session()
        stolen = self.cookie
        sec = secure.totp_secret()
        st, body, _ = self.req('POST', '/adm/api/totp', {'secret': sec, 'code': secure.totp(sec)})
        self.assertEqual(st, 200, body)
        self.assertNotEqual(self.cookie, stolen)
        self.assertFalse(db.session_ok(other))
        self.assertFalse(db.session_ok(stolen.split('=', 1)[1]))
        self.assertEqual(self.req('GET', '/adm/api/state')[0], 200)
        other, stolen = db.new_session(), self.cookie
        st, body, _ = self.req('POST', '/adm/api/totp', {'off': True, 'password': 'adminpassword'})
        self.assertEqual(st, 200, body)
        self.assertFalse(db.session_ok(other))
        self.assertFalse(db.session_ok(stolen.split('=', 1)[1]))
        self.assertEqual(self.req('GET', '/adm/api/state')[0], 200)

    def test_request_errors_do_not_log_link_tokens_or_secret_paths(self):
        db.set_settings(panel_path='Pq7secretpanel', member_path='Mx9secretmember')
        uid = db.add_user('logged', 0)
        token = db.user(uid)['sub_token']
        self._member('mlog', 'mlogpassword')
        jobs.LOG.clear()
        with mock.patch.object(web.Handler, 'member_view', side_effect=RuntimeError('boom')), \
                mock.patch.object(web.Handler, 'api_state', side_effect=RuntimeError('boom')):
            self.assertEqual(self.req('GET', '/s/%s/api/me' % token)[0], 500)
            self.assertEqual(self.req('POST', '/Pq7secretpanel/api/login',
                                      {'username': 'admin', 'password': 'adminpassword'})[0], 200)
            self.assertEqual(self.req('GET', '/Pq7secretpanel/api/state')[0], 500)
            self.cookie = ''
            self.assertEqual(self.req('POST', '/Mx9secretmember/api/login',
                                      {'name': 'mlog', 'password': 'mlogpassword'})[0], 200)
            self.assertEqual(self.req('GET', '/Mx9secretmember/api/me')[0], 500)
        text = '\n'.join(jobs.LOG)
        self.assertEqual(text.count('http error'), 3, text)
        for secret in (token, token[:12], 'Pq7secretpanel', 'Mx9secretmember'):
            self.assertNotIn(secret, text)

    def test_member_page_csp_restricts_base_and_forms(self):
        uid = db.add_user('csp', 0)
        for path in ('/mem/', '/s/%s/' % db.user(uid)['sub_token']):
            st, _, resp = self.req('GET', path, headers={'Accept': 'text/html'})
            self.assertEqual(st, 200)
            csp = resp.getheader('Content-Security-Policy')
            self.assertIn("base-uri 'self'", csp)
            self.assertIn("form-action 'self'", csp)
            self.assertIn("object-src 'none'", csp)


if __name__ == '__main__':
    unittest.main()
