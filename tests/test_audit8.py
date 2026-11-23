"""Outside review, round 8 (base v0.2.26): S8-05 (web side), S8-06, S8-07, S8-10, S8-11.
    python -m unittest tests.test_audit8 -v"""
import os
import re
import subprocess
import tempfile
import shutil
import unittest

from tests.test_deploy import INSTALL_SH, TEST_BASH, _posix

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def read(*parts):
    with open(os.path.join(ROOT, *parts), encoding='utf-8') as f:
        return f.read()


# fake tools: eth0 carries our limits (HTB 1a5: and an ingress that redirects to v2vifb0); ens5 has someone
# else's qdiscs, which must stay
STUBS = {
    'ip': r'''#!/bin/sh
echo "ip $*" >> "$FIX/calls"
if [ "$1 $2 $3" = "-o link show" ]; then
  printf '1: lo: <LOOPBACK,UP>\n2: eth0: <UP>\n3: ens5@if7: <UP>\n9: v2vifb0: <UP>\n'
fi
''',
    'tc': r'''#!/bin/sh
echo "tc $*" >> "$FIX/calls"
case "$*" in
  "qdisc show dev eth0") echo "qdisc htb 1a5: root refcnt 2 r2q 10 default 0x1" ;;
  "qdisc show dev ens5") echo "qdisc htb 1: root refcnt 2" ;;
  "filter show dev eth0 parent ffff:") echo "action order 1: mirred (Egress Redirect to device v2vifb0) stolen" ;;
  "filter show dev ens5 parent ffff:") echo "action order 1: mirred (Egress Redirect to device ifb9) stolen" ;;
esac
''',
    'nft': '#!/bin/sh\necho "nft $*" >> "$FIX/calls"\n',
}
# leaves a mark next to itself: on Windows test runs a non-ASCII path in the environment reaches Python garbled
FAKE_SHAPER = "import os\n\ndef clear(log=print):\n    open(os.path.join(os.path.dirname(__file__), 'cleared'), 'w').close()\n"


@unittest.skipUnless(TEST_BASH, 'needs bash (on Windows set V2V_TEST_BASH to Git bash)')
class UninstallClearsSpeedLimits(unittest.TestCase):
    """S8-06: limits live in the kernel; uninstalling must take ours down and leave other qdiscs alone."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.fix, stubs = os.path.join(self.tmp, 'fix'), os.path.join(self.tmp, 'stubs')
        app = os.path.join(self.tmp, 'lib', 'app', 'vps2vpn')
        for d in (self.fix, stubs, app):
            os.makedirs(d)
        for name, body in dict(STUBS, python3='#!/bin/sh\nexec "%s" "$@"\n' % _posix(__import__('sys').executable)).items():
            with open(os.path.join(stubs, name), 'w', encoding='utf-8', newline='\n') as f:
                f.write(body)
            os.chmod(os.path.join(stubs, name), 0o755)
        for name, body in (('__init__.py', ''), ('shaper.py', FAKE_SHAPER)):
            with open(os.path.join(app, name), 'w', encoding='utf-8', newline='\n') as f:
                f.write(body)
        self.env = dict(os.environ, FIX=_posix(self.fix), STUBS=_posix(stubs), INSTALL=_posix(INSTALL_SH),
                        # not _posix: Windows' Python reads PYTHONPATH itself and knows C:/x, not /c/x (bash takes both)
                        LIBDIR=os.path.join(self.tmp, 'lib').replace(os.sep, '/'))

    def calls(self, body):
        script = 'export PATH="$STUBS:$PATH"\nsource "$INSTALL"\nLIB="$LIBDIR"\n' + body
        out = subprocess.run([TEST_BASH, '-c', script], env=self.env, capture_output=True, text=True, timeout=120)
        self.assertEqual(out.returncode, 0, out.stderr)
        path = os.path.join(self.fix, 'calls')
        with open(path, encoding='utf-8') as f:
            calls = f.read().splitlines()
        if os.path.exists(os.path.join(self.tmp, 'lib', 'app', 'vps2vpn', 'cleared')):
            calls.append('shaper.clear')
        return calls

    def test_ours_go_and_others_stay(self):
        calls = self.calls('clear_speed_limits')
        self.assertIn('shaper.clear', calls)
        self.assertIn('tc qdisc del dev eth0 root', calls)
        self.assertIn('tc qdisc del dev eth0 ingress', calls)
        self.assertFalse([c for c in calls if c.startswith('tc qdisc del dev ens5')], calls)
        self.assertFalse([c for c in calls if 'dev v2vifb0' in c and c.startswith('tc ')], calls)
        self.assertIn('ip link del v2vifb0', calls)
        self.assertIn('nft delete table inet vps2vpn_shape', calls)

    def test_nothing_to_clear_does_not_stop_the_uninstall(self):
        # in CI's containers every tool fails (no ifb device, no table): set -e must not end the uninstall there
        for name in ('ip', 'tc', 'nft'):
            with open(os.path.join(self.tmp, 'stubs', name), 'a', encoding='utf-8', newline='\n') as f:
                f.write('exit 1\n')
        calls = self.calls('set -euo pipefail\nclear_speed_limits\necho after >> "$FIX/calls"')
        self.assertIn('ip link del v2vifb0', calls)
        self.assertIn('nft delete table inet vps2vpn_shape', calls)
        self.assertEqual(calls[-2:], ['after', 'shaper.clear'])

    def test_without_the_panel_code_the_fallback_still_runs(self):
        shutil.rmtree(os.path.join(self.tmp, 'lib'))
        calls = self.calls('clear_speed_limits')
        self.assertNotIn('shaper.clear', calls)
        self.assertIn('tc qdisc del dev eth0 root', calls)
        self.assertIn('nft delete table inet vps2vpn_shape', calls)

    def test_uninstall_clears_after_stopping_the_panel_and_before_deleting_it(self):
        body = read('install.sh')
        un = body[body.index('do_uninstall() {'):]
        stop, clear, rm = un.index('systemctl disable --now vps2vpn'), un.index('clear_speed_limits'), un.index('rm -rf "$LIB"')
        self.assertTrue(stop < clear < rm)


class MemberPageZeroQuota(unittest.TestCase):
    """S8-11: a capped plan that shared everything shows 0 B and a full ring, not 1 B / 0 %."""

    def test_zero_effective_quota_is_not_one_byte(self):
        js = read('vps2vpn', 'static', 'member.js')
        self.assertNotIn('Math.max(1, (me.quota_eff', js)
        self.assertIn("q = me.quota_gb ? Math.max(0, (me.quota_eff || 0) * GB) : null", js)
        self.assertIn('const frac = q == null ? 0 : q > 0 ? used / q : 1;', js)
        self.assertIn("stat(t('quota'), q != null ? fmt.bytes(q) : t('unlimited'))", js)
        self.assertIn("new Ring(ringBox.firstChild).set(frac,", js)
        self.assertIn('q != null && (q > 0 ? used / q : 1) >= .9', js)        # and the "almost used up" note shows
        self.assertNotRegex(js, r'\bq \? ')                                     # no "0 means unlimited" test left


if __name__ == '__main__':
    unittest.main()


from tests import test_member_page as tm          # noqa: E402  (sets VPS2VPN_ROOT / dev mode first)
from vps2vpn import cluster, db, notify, qr, web  # noqa: E402
import json                                       # noqa: E402
import threading                                  # noqa: E402
import time                                       # noqa: E402


class NoBoolsAsNumbers(unittest.TestCase):
    """S8-07: int(True) == 1 - a JSON true must not become port 1, 1 GB or day 1."""

    def test_number_helper(self):
        for v in (True, False):
            with self.assertRaises(ValueError):
                web.number(v)
        self.assertEqual((web.number(None), web.number(''), web.number('', True, 1)), (0, 0, 1))
        self.assertEqual((web.number('2.5'), web.number(7, True)), (2.5, 7))

    def test_account_fields(self):
        for k in ('quota_gb', 'expire_at', 'reset_day', 'max_ips', 'expire_after_days', 'expire_days',
                  'speed_mbps', 'throttle_mbps'):
            for v in (True, False):
                self.assertIsInstance(web.user_fields({k: v}), str, (k, v))
        self.assertEqual(web.user_fields({'quota_gb': 5, 'reset_day': 3}), {'quota_gb': 5.0, 'reset_day': 3})

    def test_settings(self):
        s = db.settings()
        for k in ('reality_port', 'hy2_port', 'tuic_port', 'traffic_rate', 'server_cap_gb', 'server_reset_day'):
            self.assertIsInstance(web.validate_settings({k: True}, s), str, k)
        self.assertEqual(web.validate_settings({'reality_port': 8443}, s).get('reality_port'), 8443)


class AdminAndMember(tm.Server):
    def setUp(self):
        super().setUp()
        st, body, _ = self.req('POST', '/adm/api/login', {'username': 'admin', 'password': 'adminpassword'})
        self.assertEqual(st, 200, body)

    def test_bulk_and_batch_refuse_true(self):
        uid = db.add_user('bulk-one', 10)
        st, _ = self.j('POST', '/adm/api/users-bulk', {'action': 'add_gb', 'ids': [uid], 'value': True})
        self.assertEqual(st, 400)
        self.assertEqual(db.user(uid)['quota_gb'], 10)
        st, _ = self.j('POST', '/adm/api/users-batch', {'prefix': 'b', 'count': True})
        self.assertEqual(st, 400)
        st, _ = self.j('POST', '/adm/api/users/%d/save' % uid, {'quota_gb': True})
        self.assertEqual(st, 400)
        self.assertEqual(db.user(uid)['quota_gb'], 10)

    def test_server_rate_refuses_true(self):
        db.set_settings(servers=[{'id': '0123abcd', 'name': 'two', 'url': 'https://198.51.100.7:8443/x',
                                  'enabled': True, 'rate': 2}])
        st, _ = self.j('POST', '/adm/api/servers/0123abcd/save', {'rate': True})
        self.assertEqual(st, 400)
        self.assertEqual(db.settings()['servers'][0]['rate'], 2)

    def test_settings_refuse_true_port(self):
        before = db.settings()['reality_port']
        st, _ = self.j('POST', '/adm/api/settings', {'reality_port': True})
        self.assertEqual(st, 400)
        self.assertEqual(db.settings()['reality_port'], before)

    def test_rename_drops_line_breaks(self):
        """S8-05 (web side): a renamed account cannot carry YAML into the Clash file's comment line."""
        uid = db.add_user('plain', 10)
        evil = 'alice' + chr(10) + 'proxies: []' + chr(0x2028) + chr(13) + 'x'
        st, d = self.j('POST', '/adm/api/users/%d/save' % uid, {'name': evil})
        self.assertEqual(st, 200, d)
        name = db.user(uid)['name']
        self.assertEqual(name, 'aliceproxies: []x')
        self.assertEqual(web.user_fields({'name': chr(10) + chr(9)}), {})          # nothing left: name unchanged

    def test_new_node_key_waits_for_a_running_sync(self):
        """S8-10: a sync from the old main server must not bring back what the new key removed."""
        db.set_settings(node_master='old-main', node_master_id='abcd1234')
        remote = db.add_user('from-main', 5)
        db.update_user(remote, remote_id=77)
        lock = threading.Lock()
        orig, cluster._node_lock = cluster._node_lock, lock
        self.addCleanup(setattr, cluster, '_node_lock', orig)
        lock.acquire()                                  # a sync is running
        out = {}
        t = threading.Thread(target=lambda: out.update(r=self.j('POST', '/adm/api/node-key', {})))
        t.start()
        time.sleep(0.5)
        self.assertEqual(db.settings()['node_master'], 'old-main')     # waited
        self.assertIsNotNone(db.user(remote))
        lock.release()
        t.join(10)
        self.assertEqual(out['r'][0], 200, out)
        self.assertEqual(db.settings()['node_master'], '')
        self.assertIsNone(db.user(remote))


class MemberQrAndRequests(tm.Server):
    def setUp(self):
        super().setUp()
        self.uid = db.add_user('mia', 20)
        self.base = '/s/%s/' % db.user(self.uid)['sub_token']

    def test_qr_has_the_svg_policy_and_refuses_too_long(self):
        st, _, r = self.req('GET', self.base + 'api/qr')
        self.assertEqual(st, 200)
        self.assertEqual(r.getheader('Content-Security-Policy'), web._SVG_CSP)
        orig = qr.svg
        def too_long(*a, **k):
            raise ValueError('data too long')
        qr.svg = too_long
        self.addCleanup(setattr, qr, 'svg', orig)
        st, body, _ = self.req('GET', self.base + 'api/qr')
        self.assertEqual(st, 413, body)

    def test_request_notice_uses_the_checked_number(self):
        sent = []
        orig = notify.send
        notify.send = lambda text, **k: sent.append(text)
        self.addCleanup(setattr, notify, 'send', orig)
        nl = chr(10)
        st, d = self.j('POST', self.base + 'api/request', {'add_gb': '10' + nl * 3, 'reason': 'more'})
        self.assertEqual(st, 200, d)
        self.assertEqual(len(sent), 1)
        self.assertIn('+10 GB', sent[0])
        self.assertNotIn(nl, sent[0])


class ShaperOffText(unittest.TestCase):
    """S8-11: the note said the opposite of what happens on a server that cannot limit speed."""

    def test_says_accounts_stop_here(self):
        js = read('vps2vpn', 'static', 'app.js')
        self.assertNotIn('流量用完的账号仍会降速而不是停用，但速度不受限', js)
        self.assertNotIn('still slow down instead of stopping, but at full speed', js)
        self.assertIn('流量用完后在这台上会停用，不会降速', js)
        self.assertIn('stops on this server instead', js)
