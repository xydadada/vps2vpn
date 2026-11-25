"""Business-logic review of 2026-11-24 (docs/logic-review.md), the items fixed in 0.2.39:
python -m unittest tests.test_logic_review -v

L-01  removing a joined server tells it: the accounts it was sent stop there, their last traffic is billed
L-02  panel and member-page hints that are only true for the vps2vpn app say so
L-06  an account without a monthly reset is not told "until the next reset"
L-08  a failing renewal of a domain certificate is reported a week ahead
0.2.40:
L-09  a removed server that could not be told is told later, by every sync round, for up to 30 days
L-10  "Auto" does not switch to a server whose traffic counts more than once
L-11  the IP-change notice says the subscription links themselves changed
L-12  pasted join codes and obfuscation passwords: invisible characters removed or refused
0.2.41:
L-13  an expiry date is the end of that day in the panel's time zone, not the admin browser's (M-8)
L-14  changing the reset day: the period runs until the new day comes, and the panel says when (M-9)
L-15  Telegram: no hourly repeats all night; several joined servers down make one message
"""
import datetime as dt
import threading
import base64
import inspect
import json
import os
import re
import time
import unittest
from unittest import mock

from tests import test_unit as tu          # sets VPS2VPN_ROOT / dev mode first
from vps2vpn import certs, clock, cluster, cores, db, jobs, notify, paths, secure, subscription, system, web

GB = 1 << 30
SID = '44444444'


def _static(name):
    with open(os.path.join(paths.STATIC, name), encoding='utf-8') as f:
        return f.read()


class RemoveTellsTheServer(tu.Base):
    """L-01, main-server side"""
    def setUp(self):
        super().setUp()
        self.uid = db.add_user('traveller', 50)
        db.set_settings(servers=[{'id': SID, 'name': 'Osaka', 'url': 'https://osaka.example/panel', 'key': 'k',
                                  'pin': '', 'enabled': True, 'idmap': {str(self.uid): 7},
                                  'seen': {str(self.uid): [0, 1 * GB]}}])

    def test_the_server_is_released_and_the_last_traffic_billed(self):
        answer = {'ok': True, 'info': {}, 'idmap': {}, 'traffic': {str(self.uid): [0, 3 * GB]}}
        with mock.patch.object(cluster, '_request', return_value=(answer, 'ab' * 32)) as send:
            self.assertTrue(cluster.remove_server(SID, log=lambda _: None))
        body = send.call_args[0][1]
        self.assertEqual(body['users'], [])
        self.assertIs(body['release'], True)
        self.assertEqual(db.settings()['servers'], [])
        u = db.user(self.uid)
        self.assertEqual(u['used_up'] + u['used_down'], 2 * GB)        # 3 GB there, 1 GB already billed

    def test_an_unreachable_server_is_still_removed_and_the_panel_says_so(self):
        with mock.patch.object(cluster, '_request', side_effect=cluster.SyncError('timed out')):
            self.assertFalse(cluster.remove_server(SID, log=lambda _: None))
        self.assertEqual(db.settings()['servers'], [])
        self.assertEqual([x['id'] for x in db.settings()['servers_leaving']], [SID])     # L-09: it is told later
        self.assertIn("r.released === false", _static('app.js'))
        self.assertIn('换一个加入码', _static('app.js'))


def _quiet(_):
    pass


class LeavingServer(tu.Base):
    """L-09: a removed server that could not be reached is not forgotten"""
    def setUp(self):
        super().setUp()
        cluster._leave_next.clear()
        self.uid = db.add_user('traveller', 50)
        db.set_settings(servers=[{'id': SID, 'name': 'Osaka', 'url': 'https://osaka.example/panel', 'key': 'k',
                                  'pin': '', 'enabled': True, 'rate': 2, 'idmap': {str(self.uid): 7},
                                  'seen': {str(self.uid): [0, 1 * GB]}}])
        with mock.patch.object(cluster, '_request', side_effect=cluster.SyncError('timed out')):
            self.assertFalse(cluster.remove_server(SID, log=_quiet))

    def _round(self, **request):
        cluster._leave_next.clear()                                      # the retry is due
        with mock.patch.object(cluster, '_request', **request) as send:
            cluster.sync_all(log=_quiet)
        return send

    def test_it_is_told_when_it_answers_and_its_last_traffic_billed(self):
        self.assertEqual(db.settings()['servers'], [])                   # out of every subscription at once
        self.assertNotIn(SID, db.user(self.uid)['servers'] or '')
        answer = {'ok': True, 'info': {}, 'idmap': {}, 'traffic': {str(self.uid): [0, 3 * GB]}}
        send = self._round(return_value=(answer, 'ab' * 32))
        self.assertIs(send.call_args[0][1]['release'], True)
        self.assertEqual(send.call_args[0][1]['users'], [])
        self.assertEqual(db.settings()['servers_leaving'], [])
        u = db.user(self.uid)
        self.assertEqual(u['used_up'] + u['used_down'], 4 * GB)          # 2 GB more there, at its rate of 2

    def test_not_retried_before_it_is_due(self):
        with mock.patch.object(cluster, '_request') as send:
            cluster.sync_all(log=_quiet)
        send.assert_not_called()

    def test_still_unreachable_it_keeps_waiting_and_the_panel_shows_it(self):
        self._round(side_effect=cluster.SyncError('timed out'))
        left = db.settings()['servers_leaving']
        self.assertEqual(left[0]['error'], 'timed out')
        view = cluster.leaving_view(db.settings())
        self.assertEqual((view[0]['name'], view[0]['days_left']), ('Osaka', 30))
        self.assertNotIn('key', view[0])

    def test_a_server_with_a_new_join_code_is_dropped(self):
        self._round(side_effect=cluster.SyncError('node answered 403: bad node key', 403))
        self.assertEqual(db.settings()['servers_leaving'], [])

    def test_a_server_taken_over_by_another_main_is_dropped(self):
        self._round(side_effect=cluster.SyncError('node answered 409', 409))
        self.assertEqual(db.settings()['servers_leaving'], [])

    def test_after_30_days_it_gives_up_and_says_what_to_do(self):
        left = db.settings()['servers_leaving']
        left[0]['removed_at'] = int(time.time()) - 31 * 86400
        db.set_settings(servers_leaving=left)
        sent = []
        with mock.patch.object(notify, 'send', lambda text, **k: sent.append(text)):
            self._round(side_effect=cluster.SyncError('timed out'))
        self.assertEqual(db.settings()['servers_leaving'], [])
        self.assertEqual(len(sent), 1)
        self.assertIn('换一个加入码', sent[0])

    def test_stop_waiting(self):
        self.assertTrue(cluster.forget_leaving(SID))
        self.assertEqual(db.settings()['servers_leaving'], [])
        self.assertFalse(cluster.forget_leaving(SID))

    def test_adding_it_again_ends_the_wait(self):
        raw = json.dumps({'u': 'https://osaka.example/panel', 'k': 'k2', 'p': ''})
        code = 'v2v1.' + base64.urlsafe_b64encode(raw.encode()).decode().rstrip('=')
        answer = {'ok': True, 'info': {}, 'idmap': {}, 'traffic': {}}
        with mock.patch.object(cluster, '_request', return_value=(answer, 'ab' * 32)):
            cluster.add_server(code, 'Osaka')
        self.assertEqual(db.settings()['servers_leaving'], [])

    def test_the_keys_stay_out_of_the_panel_settings_and_backups_check_it(self):
        src = inspect.getsource(web)
        self.assertIn("'node_key', 'servers', 'servers_leaving', 'server_month'", src)
        self.assertIn("_check_import_servers(keep['servers_leaving'])", inspect.getsource(db))


class AutoSkipsCostlyServers(tu.Base):
    """L-10"""
    def setUp(self):
        super().setUp()
        self.uid = db.add_user('member', 50)
        info = cluster.public_info(dict(db.settings(), public_host='198.51.100.5', node_name='Tokyo'))
        db.set_settings(servers=[{'id': SID, 'name': 'Tokyo', 'url': 'https://198.51.100.5:1/x', 'key': 'k', 'pin': '',
                                  'enabled': True, 'info': info, 'idmap': {str(self.uid): 42}, 'rate': 5}])

    def _all(self):
        s, u = db.settings(), db.user(self.uid)
        g = subscription.names(s)
        ns = subscription.nodes(s, u)
        costly = [n['name'] for n in ns if n['group'] == 'Tokyo ×5']
        self.assertTrue(costly)
        clash = subscription.clash(s, u, 'https://192.0.2.1:1')
        auto = next(x for x in clash['proxy-groups'] if x['name'] == g['auto'])['proxies']
        pick = next(x for x in clash['proxy-groups'] if x['name'] == g['proxy'])['proxies']
        self.assertIn('Tokyo ×5', pick)                                  # still there to choose by hand
        sb = subscription.singbox(s, u, 'https://192.0.2.1:1')
        sb_auto = next(o for o in sb['outbounds'] if o['tag'] == g['auto'])['outbounds']
        sr = subscription.shadowrocket(s, u, 'https://192.0.2.1:1')
        sr_auto = next(line for line in sr.splitlines() if line.startswith(g['auto'] + ' = url-test'))
        return auto, set(costly) & set(sb_auto), 'Tokyo' in sr_auto

    def test_auto_leaves_out_a_x5_server(self):
        auto, sb_costly, sr_costly = self._all()
        self.assertNotIn('Tokyo ×5', auto)
        self.assertEqual(sb_costly, set())
        self.assertFalse(sr_costly)

    def test_when_every_server_costs_more_auto_uses_them_all(self):
        db.set_settings(traffic_rate=2)
        auto, sb_costly, sr_costly = self._all()
        self.assertIn('Tokyo ×5', auto)
        self.assertTrue(sb_costly)
        self.assertTrue(sr_costly)


class IpChangeNotice(tu.Base):
    """L-11"""
    def _notice(self, **settings):
        db.set_settings(public_host='203.0.113.7', domain='', **settings)
        sent = []
        with mock.patch.object(system, 'public_ip', lambda v6=False: '198.51.100.9'), \
                mock.patch.object(cores, 'apply', lambda force=False: None), \
                mock.patch.object(notify, 'send', lambda text, **k: sent.append(text)):
            w = jobs.IpWatch()
            w.check(db.settings())
            w.seen_at -= w.CONFIRM_AFTER
            self.assertEqual(w.check(db.settings()), '198.51.100.9')
        return sent[0]

    def test_this_server_says_the_links_changed(self):
        text = self._notice()
        self.assertIn('新链接重新发给每个人', text)
        self.assertNotIn('next subscription update', text)

    def test_a_joined_server_says_the_main_server_handles_it(self):
        self.assertIn('主服务器一分钟内', self._notice(node_master='main', node_master_id='m1'))


class PastedValues(tu.Base):
    """L-12"""
    def test_join_code_with_line_breaks_and_invisible_characters(self):
        raw = json.dumps({'u': 'https://198.51.100.5:8443/panel', 'k': 'key', 'p': 'ab' * 32})
        code = 'v2v1.' + base64.urlsafe_b64encode(raw.encode()).decode().rstrip('=')
        messy = '\ufeff' + code[:20] + '\n' + code[20:40] + '\u200b' + code[40:] + ' \r\n'
        self.assertEqual(cluster.parse_join_code(messy), cluster.parse_join_code(code))

    def test_obfuscation_password(self):
        s = db.settings()
        self.assertEqual(web.validate_settings({'hy2_obfs': ' k3y-Ok\n'}, s)['hy2_obfs'], 'k3y-Ok')
        self.assertEqual(web.validate_settings({'hy2_obfs': ''}, s)['hy2_obfs'], '')
        self.assertEqual(len(web.validate_settings({'hy2_obfs': 'random'}, s)['hy2_obfs']), 16)
        for bad in ('ab\u200bcd', 'a,b', 'a b', 'x' * 65, 'a#b'):
            self.assertIsInstance(web.validate_settings({'hy2_obfs': bad}, s), str, bad)


class ReleasedServer(tu.Base):
    """L-01, joined-server side"""
    def _sync(self, users, **extra):
        with mock.patch.object(web, 'apply_async', lambda *a, **k: None):
            return cluster.handle_sync(db.settings(), dict({'master': 'main', 'master_id': 'm1', 'users': users},
                                                           **extra))

    def setUp(self):
        super().setUp()
        self._sync([{'id': 9, 'name': 'guest', 'uuid': '11111111-2222-4333-8444-555555555555',
                     'hy2_pass': 'secretsecretsecret1', 'enabled': True}])
        self.assertEqual(db.settings()['node_master_id'], 'm1')

    def test_release_deletes_the_accounts_and_frees_this_server(self):
        guest = next(u for u in db.users() if u['remote_id'] == 9)
        db.update_user(guest['id'], used_down=2 * GB)
        ans = self._sync([], release=True)
        self.assertEqual([u for u in db.users() if u['remote_id']], [])
        s = db.settings()
        self.assertEqual((s['node_master'], s['node_master_id']), ('', ''))
        self.assertEqual(ans['traffic'].get('9'), [0, 2 * GB])                             # the last count goes back to be billed

    def test_an_empty_list_without_release_keeps_the_main_server(self):
        self._sync([])                                                   # a main server whose accounts all left
        self.assertEqual(db.settings()['node_master_id'], 'm1')

    def test_another_main_cannot_release_it(self):
        ans = cluster.handle_sync(db.settings(), {'master': 'x', 'master_id': 'other', 'users': [], 'release': True})
        self.assertTrue(ans.get('conflict'))
        self.assertEqual(db.settings()['node_master_id'], 'm1')
        self.assertEqual(len([u for u in db.users() if u['remote_id']]), 1)


class CertificateWarning(tu.Base):
    """L-08: a failing renewal of a domain certificate is reported a week ahead, not 36 hours ahead"""
    def _renew(self, host, hours_left):
        from vps2vpn import certs, jobs, notify
        db.set_settings(domain=host if not certs.is_ip(host) else '', public_host=host)
        sent = []
        with mock.patch.object(certs, 'renew_if_needed', lambda s, log=print: 'port 80 blocked'), \
                mock.patch.object(certs, 'trusted', lambda h=None: True), \
                mock.patch.object(certs, 'acme_valid', lambda h=24: h <= hours_left), \
                mock.patch.object(notify, 'send', lambda text, **k: sent.append(text)):
            jobs.Scheduler().renew_cert(db.settings())
        return sent

    def test_domain_certificate(self):
        self.assertEqual(self._renew('vpn.example.com', 20 * 24), [])          # 20 days left: keep trying quietly
        self.assertEqual(len(self._renew('vpn.example.com', 6 * 24)), 1)       # 6 days left: tell the admin

    def test_ip_certificate(self):
        self.assertEqual(self._renew('192.0.2.10', 48), [])
        self.assertEqual(len(self._renew('192.0.2.10', 30)), 1)


class OnlyTheVps2vpnApp(unittest.TestCase):
    """L-02: features that only our own app has say so, in both languages"""
    def test_panel_hints(self):
        js = _static('app.js')
        rank = re.findall(r"client_traffic_rank: '([^']*)'", js)
        self.assertEqual(len(rank), 2)
        self.assertIn('仅 vps2vpn 客户端支持', rank[0])
        self.assertIn('vps2vpn app only', rank[1])
        self.assertIn('vps2vpn 客户端报告', js)                           # line trouble comes from our app only
        self.assertIn('用其他软件的人不会报告', js)
        self.assertIn('收不到这个更新', js)                               # the installers folder is ours only
        self.assertNotIn('12 小时内会自动更新', js)                       # the interval is a setting


class NoMonthlyReset(unittest.TestCase):
    """L-06"""
    def test_member_page_texts(self):
        js = _static('member.js')
        self.assertEqual(js.count('more_tip_nr:'), 2)
        self.assertEqual(js.count('slowed_nr:'), 2)
        self.assertIn("t(me.reset_day ? 'slowed' : 'slowed_nr')", js)
        self.assertIn("t(me.reset_day ? 'more_tip' : 'more_tip_nr')", js)



def _ts(text, tz):
    return int(dt.datetime.fromisoformat(text).replace(tzinfo=tz).timestamp())


UTC8 = dt.timezone(dt.timedelta(hours=8))


class ExpiryInThePanelsTimeZone(tu.Base):
    """L-13 (M-8)"""
    def setUp(self):
        super().setUp()
        db.set_settings(time_zone='UTC+8')
        clock.forget()

    def tearDown(self):
        db.set_settings(time_zone='')
        clock.forget()
        super().tearDown()

    def test_end_of_the_day_there(self):
        self.assertEqual(clock.day_end('2026-12-31'), _ts('2026-12-31T23:59:59', UTC8))
        self.assertEqual(clock.date_of(_ts('2026-12-31T23:59:59', UTC8)), '2026-12-31')
        self.assertEqual(clock.date_of(_ts('2027-01-01T00:00:00', UTC8)), '2027-01-01')
        self.assertEqual(clock.date_of(0), '')

    def test_the_panel_sends_a_day(self):
        self.assertEqual(web.user_fields({'expire_date': '2026-12-31'})['expire_at'], _ts('2026-12-31T23:59:59', UTC8))
        self.assertEqual(web.user_fields({'expire_date': ''})['expire_at'], 0)
        for bad in ('31/12/2026', '2026-13-01', '2026-02-30', 'x'):
            self.assertIsInstance(web.user_fields({'expire_date': bad}), str, bad)
        js = _static('app.js')
        self.assertIn('{expire_date: exp}', js)
        self.assertNotIn("T23:59:59').getTime()", js)                   # the browser's time zone is not used

    def test_lists_and_member_page_show_the_day_there(self):
        uid = db.add_user('dated')
        db.update_user(uid, expire_at=_ts('2026-12-31T23:59:59', UTC8))
        self.assertIn('u.expire_day ||', _static('app.js'))
        self.assertIn('me.expire_day ||', _static('member.js'))
        self.assertIn("'expire_day': clock.date_of(u['expire_at'])", inspect.getsource(web))


class ResetDayChange(tu.Base):
    """L-14 (M-9)"""
    def test_the_period_runs_until_the_new_day(self):
        tz = dt.timezone.utc
        db.set_settings(time_zone='UTC')
        clock.forget()
        try:
            on_10th = _ts('2026-11-10T12:00:00', tz)
            # 1st -> 20th on the 10th: reset on the 20th this month (not a ~50-day period)
            label = clock.label_after_change(20, on_10th)
            self.assertEqual(label, '2026-10')
            u = {'reset_day': 20, 'last_reset': label}
            self.assertFalse(jobs.monthly_reset(u, on_10th)[0])
            self.assertTrue(jobs.monthly_reset(u, _ts('2026-11-20T00:00:01', tz))[0])
            # 20th -> 5th on the 10th: nothing is wiped now; next reset on 5 December
            label = clock.label_after_change(5, on_10th)
            self.assertEqual(label, '2026-11')
            u = {'reset_day': 5, 'last_reset': label}
            self.assertFalse(jobs.monthly_reset(u, on_10th)[0])
            self.assertFalse(jobs.monthly_reset(u, _ts('2026-11-30T23:00:00', tz))[0])
            self.assertTrue(jobs.monthly_reset(u, _ts('2026-12-05T00:00:01', tz))[0])
            # January: last month is December of the year before
            self.assertEqual(clock.label_after_change(20, _ts('2027-01-03T00:00:00', tz)), '2026-12')
        finally:
            db.set_settings(time_zone='')
            clock.forget()


class SaveOverHttps(tu.Base):
    """L-13 and L-14 through the panel's API"""
    def setUp(self):
        super().setUp()
        db.set_settings(public_host='127.0.0.1', setup_done=True, member_path='mem', panel_path='adm',
                        admin_hash=secure.hash_password('adminpassword'), time_zone='UTC+8')
        clock.forget()
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
        self.req('POST', '/adm/api/login', {'username': 'admin', 'password': 'adminpassword'})

    def tearDown(self):
        web.apply_async = self._apply
        self.httpd.shutdown()
        self.httpd.server_close()
        self._thread.join(5)
        db.set_settings(time_zone='')
        clock.forget()
        super().tearDown()

    req = tu.Web.req

    def test_save_with_a_day_and_a_new_reset_day(self):
        uid = db.add_user('member', 10)
        db.update_user(uid, reset_day=1, last_reset=clock.month(), used_down=3 * GB)
        st, body, _ = self.req('POST', '/adm/api/users/%d/save' % uid, {'expire_date': '2027-03-31', 'reset_day': 28})
        self.assertEqual(st, 200, body)
        ans = json.loads(body)
        u = db.user(uid)
        self.assertEqual(u['expire_at'], _ts('2027-03-31T23:59:59', UTC8))
        self.assertEqual(u['used_down'], 3 * GB)                          # not wiped by the change
        self.assertEqual(ans['period_ends'], clock.date_of(clock.next_reset(28)))
        st, body, _ = self.req('GET', '/adm/api/state')
        if st == 200:
            row = next((r for r in json.loads(body).get('users', []) if r['id'] == uid), None)
            if row:
                self.assertEqual(row['expire_day'], '2027-03-31')
        # saving something else leaves the period alone and says nothing about it
        st, body, _ = self.req('POST', '/adm/api/users/%d/save' % uid, {'note': 'x', 'reset_day': 28})
        self.assertEqual(json.loads(body)['period_ends'], '')


class QuieterTelegram(unittest.TestCase):
    """L-15"""
    def test_several_joined_servers_down_make_one_message(self):
        sent = []
        with mock.patch.object(notify, 'send', lambda text, **k: sent.append((text, k['key']))):
            cluster._alert([('server A unreachable', 'node-down-aaaa1111'), ('server B unreachable', 'node-down-bbbb2222'),
                            ('something else', 'other')])
        self.assertEqual(len(sent), 2)
        merged = next(t for t, k in sent if k.startswith('node-down-'))
        self.assertIn('2 台子服务器连不上了', merged)
        self.assertIn('server A', merged)
        self.assertIn('server B', merged)
        sent.clear()
        with mock.patch.object(notify, 'send', lambda text, **k: sent.append((text, k['key']))):
            cluster._alert([('server A unreachable', 'node-down-aaaa1111')])
        self.assertEqual(sent, [('server A unreachable', 'node-down-aaaa1111')])

    def test_repeats_are_spaced_out(self):
        src = inspect.getsource(jobs)
        self.assertIn("every=6 * 3600 if ok else 3600", src)              # a core that keeps coming back
        self.assertIn("every=6 * 3600 if s['ip_limit_pause'] else 86400", src)   # devices over the limit
        self.assertIn("key='cert', every=86400", src)


if __name__ == '__main__':
    unittest.main()
