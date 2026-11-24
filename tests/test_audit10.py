"""Round 10 of the outside review (server part, S10-01..05):  python -m unittest tests.test_audit10 -v

S10-01  the limits' probe never touches the live ifb device, and "the limits hold" means every piece of them
S10-02  legend_import --lines checks the short id, the obfs password, the key and the ports
S10-03  (deployers; the cases live in tests/test_audit9_deployers.py, run by all three)
S10-04  a joined server leaves out a slowed-down account it cannot hold to its speed
S10-05  an emptied number box is sent as null, not 0
"""
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

from tests import test_unit as tu          # sets VPS2VPN_ROOT / dev mode first
from vps2vpn import cluster, cores, db, doctor, paths, shaper, web

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, 'tools'))
import legend_import as li  # noqa: E402


def read(*parts):
    with open(os.path.join(ROOT, *parts), encoding='utf-8') as f:
        return f.read()


class Kernel:
    """A stand-in for `ip`, `tc` and `nft` that answers like a machine with the limits set up, minus `broken`."""
    def __init__(self, broken=()):
        self.broken, self.calls = set(broken), []

    def __call__(self, cmd, stdin=None, timeout=15):
        self.calls.append(cmd)
        if cmd[:3] == ['tc', 'qdisc', 'show']:
            dev = cmd[4]
            return 0, '' if ('htb-' + dev) in self.broken else 'qdisc htb 1a5: root refcnt 2 r2q 10 default 0x1\n'
        if cmd[:4] == ['ip', '-o', 'link', 'show']:
            if 'ifb-gone' in self.broken:
                return 1, 'Device "v2vifb0" does not exist.'
            flags = '<BROADCAST,NOARP>' if 'ifb-down' in self.broken else '<BROADCAST,NOARP,UP,LOWER_UP>'
            return 0, '9: v2vifb0: %s mtu 1500 qdisc htb state UNKNOWN mode DEFAULT qlen 32\n' % flags
        if cmd[:3] == ['tc', 'filter', 'show']:
            if 'ingress' in self.broken:
                return 0, 'filter protocol all pref 1 u32 chain 0\n  action order 1: connmark zone 0 pipe\n'
            return 0, ('filter protocol all pref 2 fw chain 0 handle 0x56000000/0xff000000\n'
                       '  action order 1: mirred (Egress Redirect to device v2vifb0) stolen\n')
        if cmd[:3] == ['nft', 'list', 'table']:
            return (1, 'Error: No such file or directory') if 'nft' in self.broken else (0, 'table inet vps2vpn_shape {}')
        return 0, ''


class LimitsHold(tu.Base):
    """S10-01"""
    def test_the_probe_uses_a_device_of_its_own(self):
        k = Kernel()
        with mock.patch.object(paths, 'LIVE', True), mock.patch.object(shaper.shutil, 'which', return_value='/sbin/x'), \
                mock.patch.object(shaper, '_run', k), mock.patch.dict(shaper._state, available=None):
            self.assertTrue(shaper.available())
        touched = [c for c in k.calls if c[:2] == ['ip', 'link']]
        self.assertEqual([c[2] for c in touched], ['add', 'show', 'del'])
        probe = touched[0][3]
        self.assertNotEqual(probe, shaper.IFB)                    # the live device is never added or deleted
        self.assertTrue(all(c[3] == probe for c in touched))
        self.assertLessEqual(len(probe), 15)                      # IFNAMSIZ

    def test_every_piece_must_be_there(self):
        with mock.patch.object(shaper, '_run', Kernel()):
            self.assertTrue(shaper.intact('eth0'))
            self.assertFalse(shaper.intact(''))
        for broken in ('htb-eth0', 'htb-v2vifb0', 'ifb-gone', 'ifb-down', 'ingress', 'nft'):
            with self.subTest(broken=broken), mock.patch.object(shaper, '_run', Kernel([broken])):
                self.assertFalse(shaper.intact('eth0'))

    def test_apply_sets_it_up_again_when_a_firewall_reload_took_the_nft_table(self):
        k = Kernel(['nft'])
        with mock.patch.object(shaper, 'available', return_value=True), \
                mock.patch.object(shaper, 'default_dev', return_value='eth0'), mock.patch.object(shaper, '_run', k), \
                mock.patch.dict(shaper._state, applied={5: 10.0}, dev='eth0', error=''):
            self.assertTrue(shaper.apply({5: 10}, log=lambda *_: None))
            self.assertIn(['tc', '-batch', '-'], k.calls)         # not the "nothing changed" shortcut
        k = Kernel()
        with mock.patch.object(shaper, 'available', return_value=True), \
                mock.patch.object(shaper, 'default_dev', return_value='eth0'), mock.patch.object(shaper, '_run', k), \
                mock.patch.dict(shaper._state, applied={5: 10.0}, dev='eth0', error=''):
            self.assertTrue(shaper.apply({5: 10}, log=lambda *_: None))
            self.assertNotIn(['tc', '-batch', '-'], k.calls)      # all there: nothing redone

    def test_a_redirect_to_a_deleted_ifb_device_is_still_ours(self):
        # what tc printed on the test server after `ip link del v2vifb0`: the target became "device *", and
        # leaving this ingress behind made every rebuild fail ("Exclusivity flag on, cannot modify")
        orphan = ('filter protocol all pref 2 fw chain 0 handle 0x56000000/0xff000000\n'
                  '\taction order 1: mirred (Egress Redirect to device *) stolen\n')
        for root in ('qdisc htb 1a5: root refcnt 2', ''):
            calls = []

            def run(cmd, stdin=None, timeout=15):
                calls.append(cmd)
                if cmd[:3] == ['tc', 'qdisc', 'show']:
                    return 0, root
                return (0, orphan) if cmd[:3] == ['tc', 'filter', 'show'] else (0, '')
            with self.subTest(root=root), mock.patch.object(shaper, '_run', run):
                shaper._teardown('eth0')
                self.assertIn(['tc', 'qdisc', 'del', 'dev', 'eth0', 'ingress'], calls)
                self.assertFalse(shaper.intact('eth0'))

    def test_doctor_reports_a_missing_nft_table_or_ifb_device(self):
        uid = db.add_user('capped', 0)
        db.update_user(uid, speed_mbps=10)
        for broken in ('nft', 'ifb-gone'):
            with self.subTest(broken=broken), mock.patch.object(shaper, 'active', return_value=True), \
                    mock.patch.object(shaper, 'default_dev', return_value='eth0'), \
                    mock.patch.object(shaper, '_run', Kernel([broken])), mock.patch.dict(shaper._state, dev='', error=''):
                r = doctor.speed_limits()[0]
                self.assertFalse(r['ok'])
                self.assertIn('eth0', r['detail'])
        with mock.patch.object(shaper, 'active', return_value=True), \
                mock.patch.object(shaper, 'default_dev', return_value='eth0'), \
                mock.patch.object(shaper, '_run', Kernel()), mock.patch.dict(shaper._state, dev='', error=''):
            self.assertTrue(doctor.speed_limits()[0]['ok'])


class LegendLines(unittest.TestCase):
    """S10-02"""
    def setUp(self):
        from vps2vpn import secure
        self.private, self.public = secure.reality_keypair()

    def config(self, sid='0123456789abcdef', obfs=None, hy2=True):
        hy = {'type': 'hysteria2', 'listen_port': 26443}
        if obfs is not None:
            hy['obfs'] = obfs
        return {'inbounds': [
            {'type': 'vless', 'tls': {'server_name': 'www.example.org', 'reality': {
                'enabled': True, 'private_key': self.private, 'short_id': [sid],
                'handshake': {'server': 'www.example.org'}}}},
            {'type': 'tuic', 'listen_port': 28443}] + ([hy] if hy2 else [])}

    def test_short_id_in_pairs_any_case(self):
        self.assertEqual(li.convert_lines(self.config('A1B2C3D4'))['reality_short_id'], 'a1b2c3d4')
        self.assertEqual(li.convert_lines(self.config(''))['reality_short_id'], '')
        for bad in ('abc', '0123456789abcdef00', 'zz'):
            with self.subTest(sid=bad), self.assertRaises(li.Problem):
                li.convert_lines(self.config(bad))

    def test_obfs_is_salamander_with_a_plain_password(self):
        self.assertEqual(li.convert_lines(self.config(obfs={'type': 'salamander', 'password': 'k3y-Ok'}))['hy2_obfs'], 'k3y-Ok')
        self.assertEqual(li.convert_lines(self.config())['hy2_obfs'], '')
        for bad in ({'type': 'other', 'password': 'x'}, {'type': 'salamander', 'password': 'two\nlines'},
                    {'type': 'salamander', 'password': 'a b'}, {'type': 'salamander', 'password': ''},
                    {'type': 'salamander', 'password': 7}, {'type': 'salamander', 'password': 'x' * 65}, 'salamander'):
            with self.subTest(obfs=bad), self.assertRaises(li.Problem):
                li.convert_lines(self.config(obfs=bad))

    def test_a_key_that_is_no_key_is_a_plain_problem(self):
        broken = mock.Mock(reality_public_key=mock.Mock(side_effect=ValueError('not a point')))
        with mock.patch.object(li, '_panel', return_value=broken), self.assertRaises(li.Problem):
            li.convert_lines(self.config())

    def test_ports_that_collide_with_the_new_panel_are_refused(self):
        lines = li.convert_lines(self.config())
        ok = li.merge_lines({'settings': {'panel_port': 43470}, 'users': []}, lines)
        self.assertEqual(ok['settings']['reality_port'], 443)
        with self.assertRaises(li.Problem):                        # the new panel itself on TCP 443
            li.merge_lines({'settings': {'panel_port': 443}, 'users': []}, lines)
        no_hy2 = li.convert_lines(self.config(hy2=False))          # Hysteria keeps the new panel's own port
        with self.assertRaises(li.Problem):
            li.merge_lines({'settings': {'panel_port': 43470, 'hy2_enabled': True, 'hy2_port': 8443}, 'users': []}, no_hy2)
        with self.assertRaises(li.Problem):                        # TUIC's 8443 inside the hop range
            li.merge_lines({'settings': {'panel_port': 43470, 'hy2_enabled': True, 'hy2_hop': True, 'hy2_port': 443,
                                         'hy2_hop_range': '8000-9000'}, 'users': []}, no_hy2)

    def test_output_goes_through_a_temp_file_of_its_own(self):
        d = tempfile.mkdtemp(prefix='legend-out-')
        self.addCleanup(shutil.rmtree, d, True)
        out = os.path.join(d, 'merged.json')
        with open(out + '.tmp', 'w') as f:                       # someone else's file with the old fixed name
            f.write('keep me')
        li.write_private(out, {'a': 1})
        with open(out + '.tmp') as f:
            self.assertEqual(f.read(), 'keep me')
        self.assertEqual(sorted(os.listdir(d)), ['merged.json', 'merged.json.tmp'])


class SlowedOnJoinedServers(tu.Base):
    """S10-04"""
    UUID = '00000000-0000-4000-8000-0000000000%02d'

    def snap(self, slowed):
        return {'master': 'main', 'master_id': 'm1', 'users': [
            {'id': 7, 'name': 'slow', 'uuid': self.UUID % 7, 'hy2_pass': 'pass-seven', 'enabled': True,
             'expire_at': 0, 'limit_mbps': 2.0, 'slowed': slowed},
            {'id': 8, 'name': 'capped', 'uuid': self.UUID % 8, 'hy2_pass': 'pass-eight', 'enabled': True,
             'expire_at': 0, 'limit_mbps': 20.0}]}

    def served(self, can_slow):
        with mock.patch.object(cores, 'can_slow_here', return_value=can_slow):
            return sorted(u['remote_id'] for u in cores.active_users())

    def test_main_sends_the_flag(self):
        uid = db.add_user('main-own', 1)
        db.update_user(uid, throttle_mbps=2, throttled=1)
        self.assertIs(cluster.push_users(None)[0]['slowed'], True)
        db.update_user(uid, throttled=0)
        self.assertIs(cluster.push_users(None)[0]['slowed'], False)

    def test_joined_server_leaves_it_out_when_it_cannot_hold_it(self):
        with mock.patch.object(web, 'apply_async', lambda *a, **k: None):
            cluster.handle_sync(db.settings(), self.snap(True))
            self.assertEqual(self.served(True), [7, 8])
            self.assertEqual(self.served(False), [8])                 # a speed cap alone still runs, unlimited
            mine = next(u for u in db.users() if u['remote_id'] == 7)
            self.assertEqual(db.limit_mbps(mine), 2.0)                  # the flag does not change the speed
            cluster.handle_sync(db.settings(), self.snap(False))       # quota topped up on the main server
            self.assertEqual(self.served(False), [7, 8])
            old = self.snap(True)
            del old['users'][0]['slowed']                              # a main server before 0.2.37
            cluster.handle_sync(db.settings(), old)
            self.assertEqual(self.served(False), [7, 8])
            for bad in ('yes', 2, None):
                with self.subTest(slowed=bad), self.assertRaises(ValueError):
                    cluster.handle_sync(db.settings(), self.snap(bad))


class EmptyNumberBoxes(tu.Base):
    """S10-05: Number('') is 0, which the server reads as "0 GB" or "unlimited"; null means "not given"."""
    def test_admin_page(self):
        js = read('vps2vpn', 'static', 'app.js')
        self.assertIn("body = {add_gb: numOrNull(gb.trim())}", js)       # empty = approve what was asked
        self.assertIn('留空 = 按申请的数量批准', js)
        self.assertIn("quota_gb: numOrNull(f.quota.value), expire_days: numOrNull(f.life.value)", js)
        self.assertNotIn('add_gb: Number(', js)

    def test_member_page(self):
        js = read('vps2vpn', 'static', 'member.js')
        self.assertIn("const numOrNull = v => (v === '' ? null : Number(v));", js)
        self.assertIn("add_gb: numOrNull(f.gb.value)", js)
        self.assertIn("quota_gb: numOrNull(f.gb.value), max_uses: numOrNull(f.uses.value)", js)
        self.assertNotIn('Number(f.', js)

    def test_server_approves_what_was_asked_when_the_box_is_empty(self):
        from vps2vpn import members
        uid = db.add_user('asker', 10)
        members.request_more(uid, 5, 'exams')
        rid = db.requests(uid)[0]['id']
        members.decide(rid, True, None)
        self.assertEqual(members.extra(db.user(uid)), 5)


if __name__ == '__main__':
    unittest.main()
