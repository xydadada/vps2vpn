"""Round 11 of the outside review (server part, S11-01..03):  python -m unittest tests.test_audit11 -v

S11-01  slowed-down accounts on joined servers: already fixed in 0.2.37 (S10-04, the "slowed" flag); the tests
        are SlowedOnJoinedServers in tests/test_audit10.py. One more check here: the flag survives a round trip.
S11-02  a top-up approved for this period no longer voids the member's own invite codes
S11-03  no "80% used" notice right after "used up, slowed down"; the trust cache knows a replaced certificate
"""
import os
import unittest
from unittest import mock

from tests import test_unit as tu          # sets VPS2VPN_ROOT / dev mode first
from vps2vpn import certs, cluster, db, jobs, members, notify, paths, web

GB = 1 << 30


class SlowedFlagRoundTrip(tu.Base):
    """S11-01"""
    def test_main_to_joined_server(self):
        uid = db.add_user('slow', 1)
        db.update_user(uid, throttle_mbps=2, throttled=1)
        pushed = cluster.push_users(None)
        self.assertIs(pushed[0]['slowed'], True)
        db.delete_user(uid)                                       # this test server now plays the joined one
        with mock.patch.object(web, 'apply_async', lambda *a, **k: None):
            cluster.handle_sync(db.settings(), {'master': 'main', 'master_id': 'm1', 'users': pushed})
        mine = next(u for u in db.users() if u['remote_id'] == uid)
        self.assertEqual(mine['throttled'], 1)


class TopUpKeepsCodes(tu.Base):
    """S11-02"""
    def setUp(self):
        super().setUp()
        self.uid = db.add_user('mia', 10)                          # 10 GB plan
        self.inv = members.create_invite('member', 2, 7, 1, inviter=self.uid, by_member=True)

    def test_using_the_top_up_does_not_void_a_code(self):
        db.update_user(self.uid, extra_gb=50, used_down=12 * GB)  # 12 of 60 GB used: 48 GB left this period
        self.assertFalse(members.void_code(db.invite_by_code(self.inv['code'])))
        self.assertAlmostEqual(members.capacity(db.user(self.uid)), 10 - 2 - 1)   # the plan's room, minus the code
        new = members.register(self.inv['code'], 'mia-friend', 'friend-password-1')
        self.assertTrue(db.user(new))

    def test_the_top_up_itself_is_never_shared(self):
        db.update_user(self.uid, extra_gb=50)
        self.assertAlmostEqual(members.capacity(db.user(self.uid)), 10 - 2 - 1)   # not 59 - 2
        with self.assertRaises(members.Refused):
            members.create_invite('member', 20, 7, 1, inviter=self.uid, by_member=True)

    def test_past_the_top_up_the_base_quota_counts_again(self):
        db.update_user(self.uid, extra_gb=5, used_down=14 * GB)   # 9 GB of the plan used: 1 GB left, 2 promised
        self.assertTrue(members.void_code(db.invite_by_code(self.inv['code'])))


class SlowedDownNotices(tu.Base):
    """S11-03 (1)"""
    def test_slowed_down_is_told_once_without_an_80_percent_notice(self):
        uid = db.add_user('fast', 1)
        db.update_user(uid, throttle_mbps=2, used_down=int(1.5 * GB))     # past 100% in one step
        sent = []
        with mock.patch.object(notify, 'send', lambda text, **kw: sent.append(text)), \
                mock.patch.object(jobs.cores, 'can_slow_here', return_value=True):
            jobs.enforce()
            jobs.enforce()
        self.assertEqual(db.user(uid)['throttled'], 1)
        self.assertEqual(len([t for t in sent if 'slowed down' in t]), 1)
        self.assertEqual([t for t in sent if '80%' in t], [])

    def test_the_80_percent_notice_still_comes_before_that(self):
        uid = db.add_user('steady', 10)
        db.update_user(uid, throttle_mbps=2, used_down=int(8.5 * GB))
        sent = []
        with mock.patch.object(notify, 'send', lambda text, **kw: sent.append(text)), \
                mock.patch.object(jobs.cores, 'can_slow_here', return_value=True):
            jobs.enforce()
        self.assertEqual(len([t for t in sent if '80%' in t]), 1)


class TrustCache(tu.Base):
    """S11-03 (2)"""
    def test_a_certificate_replaced_with_the_same_time_stamp_is_checked_again(self):
        paths.ensure_dirs()
        for p, data in ((paths.ACME_CRT, b'first certificate'), (paths.ACME_KEY, b'first key')):
            with open(p, 'wb') as f:
                f.write(data)
        stamp = os.stat(paths.ACME_CRT).st_mtime_ns
        certs._trust_cache.clear()
        self.addCleanup(certs._trust_cache.clear)
        with mock.patch.object(certs, 'acme_valid', return_value=True), \
                mock.patch.object(certs, 'acme_names', return_value=['vpn.example']), \
                mock.patch.object(certs, '_openssl', return_value=b'') as verify, \
                mock.patch.object(certs.ssl, 'SSLContext'):
            self.assertTrue(certs.trusted('vpn.example'))
            self.assertTrue(certs.trusted('vpn.example'))
            self.assertEqual(verify.call_count, 1)                       # cached while nothing changed
            with open(paths.ACME_CRT, 'wb') as f:
                f.write(b'a different, longer certificate')
            os.utime(paths.ACME_CRT, ns=(stamp, stamp))                  # same time stamp as before
            self.assertTrue(certs.trusted('vpn.example'))
            self.assertEqual(verify.call_count, 2)                       # the new file was checked


if __name__ == '__main__':
    unittest.main()
