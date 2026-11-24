"""Business-logic review of 2026-11-24 (docs/logic-review.md), the items fixed in 0.2.39:
python -m unittest tests.test_logic_review -v

L-01  removing a joined server tells it: the accounts it was sent stop there, their last traffic is billed
L-02  panel and member-page hints that are only true for the vps2vpn app say so
L-06  an account without a monthly reset is not told "until the next reset"
L-08  a failing renewal of a domain certificate is reported a week ahead
"""
import os
import re
import unittest
from unittest import mock

from tests import test_unit as tu          # sets VPS2VPN_ROOT / dev mode first
from vps2vpn import cluster, db, paths, web

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
        self.assertIn("r.released === false", _static('app.js'))
        self.assertIn('换一个加入码', _static('app.js'))


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


if __name__ == '__main__':
    unittest.main()
