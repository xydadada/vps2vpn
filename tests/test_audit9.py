"""Outside review, round 9 (base v0.2.30): S9-04 (deploy-mac.command) and S9-05 (whole numbers, server reset day).
    python -m unittest tests.test_audit9 -v"""
import json
import os
import re
import shutil
import subprocess
import unittest
from unittest import mock

from tests.test_deploy import TARGETS, TEST_BASH

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def read(*parts):
    with open(os.path.join(ROOT, *parts), encoding='utf-8') as f:
        return f.read()


# pasted into the Mac deployer's IP prompt -> (host, user, port); quotes used to turn into the letter x
MAC_TARGETS = [
    ('"203.0.113.10"', ('203.0.113.10', '', '')),
    ("'root@203.0.113.10'", ('203.0.113.10', 'root', '')),
    ('"203.0.113.10:2222"', ('203.0.113.10', '', '2222')),
    ('ssh -p "2222" -l "ubuntu" 203.0.113.10', ('203.0.113.10', 'ubuntu', '2222')),
    ('ssh "ubuntu@203.0.113.10"', ('203.0.113.10', 'ubuntu', '')),
    ("ssh -i 'My Key.pem' -p 22 'root'@203.0.113.10", ('203.0.113.10', 'root', '22')),
    ('"ssh -i k.pem -p 2222 ubuntu@203.0.113.10"', ('203.0.113.10', 'ubuntu', '2222')),   # the whole command quoted
    ('SSH -p2222 root@203.0.113.10', ('203.0.113.10', 'root', '2222')),
    ('ssh.exe -p 2222 root@203.0.113.10', ('203.0.113.10', 'root', '2222')),             # copied from Windows
    ('ssh -p2222abc root@203.0.113.10', ('203.0.113.10', 'root', '')),                   # not a port
    ('ssh -p', ('', '', '')),
    ('ssh', ('', '', '')),
    ('"', ('', '', '')),
    ('', ('', '', '')),
]

# the cases go in on stdin: Windows hands quotes in arguments to Git bash mangled
HARNESS = ('set -euo pipefail\n%s\n'
           'while IFS= read -r t; do parse_target "$t"; printf "%%s|%%s|%%s\\n" "$HOST" "$T_USER" "$T_PORT"; done\n')


@unittest.skipUnless(TEST_BASH, 'needs bash (on Windows set V2V_TEST_BASH to Git bash)')
class MacDeployerTarget(unittest.TestCase):
    """S9-04: what is inside quotes is kept, SSH / ssh.exe are ssh, -p takes digits only."""

    def run_targets(self, texts, prelude=''):
        fn = re.search(r'(?ms)^parse_target\(\) \{.*?^\}$', read('deploy-mac.command')).group(0)
        p = subprocess.run([TEST_BASH, '-c', HARNESS % (prelude + fn)], input=''.join(t + '\n' for t in texts).encode(),
                           capture_output=True, timeout=60)
        self.assertEqual(p.returncode, 0, p.stderr)
        lines = p.stdout.decode('utf-8').splitlines()
        self.assertEqual(len(lines), len(texts), p.stdout)
        return [tuple(line.split('|')) for line in lines]

    def test_quotes_and_ssh_spellings(self):
        for (text, want), got in zip(MAC_TARGETS, self.run_targets([t for t, _ in MAC_TARGETS])):
            self.assertEqual(got, want, text)

    def test_the_shared_cases_under_set_e(self):
        # the cases every deployer takes the same way, now under set -euo pipefail as well
        for (text, want), got in zip(TARGETS, self.run_targets([t for t, _ in TARGETS])):
            self.assertEqual(got, want, text)

    def test_a_failing_perl_stops_nothing(self):
        # perl (only there for full-width digits) failing must not end the script under set -e
        ascii_cases = [(t, w) for t, w in TARGETS + MAC_TARGETS if t.isascii()]
        got = self.run_targets([t for t, _ in ascii_cases], 'perl() { cat >/dev/null; return 1; }\n')
        for (text, want), g in zip(ascii_cases, got):
            self.assertEqual(g, want, text)

    def test_the_old_quote_eraser_is_gone(self):
        self.assertNotIn('s/"[^"]*"/x/g', read('deploy-mac.command'))


from tests import test_member_page  # noqa: E402,F401  (sets VPS2VPN_ROOT / dev mode first)
from vps2vpn import db, jobs, web   # noqa: E402


class WholeNumbers(unittest.TestCase):
    """S9-05: int(443.9) == 443 - a port, day or count with a fraction is refused, not cut."""

    def test_number_helper(self):
        for v in (443.9, 0.5, -1.5, float('inf'), float('nan')):
            with self.assertRaises((ValueError, OverflowError)):
                web.number(v, True)
        self.assertEqual((web.number(443.0, True), web.number('443', True), web.number(443, True)), (443, 443, 443))
        self.assertEqual(web.number(2.5), 2.5)                  # not whole: fractions are fine
        with self.assertRaises(ValueError):
            web.number('443.9', True)

    def test_settings_and_accounts(self):
        s = db.settings()
        for k in ('reality_port', 'hy2_port', 'tuic_port', 'server_reset_day'):
            self.assertIsInstance(web.validate_settings({k: 9.5}, s), str, k)
        self.assertEqual(web.validate_settings({'reality_port': 8443.0}, s).get('reality_port'), 8443)
        for k in ('reset_day', 'max_ips', 'expire_after_days', 'expire_at'):
            self.assertIsInstance(web.user_fields({k: 3.5}), str, k)
        self.assertEqual(web.user_fields({'max_ips': 3.0}), {'max_ips': 3})


class ServerResetDay(unittest.TestCase):
    """S9-05: the server's billing day takes 29-31 like an account's (the last day in shorter months)."""

    def test_settings_take_1_to_31(self):
        s = db.settings()
        for day in (1, 28, 29, 30, 31):
            self.assertEqual(web.validate_settings({'server_reset_day': day}, s).get('server_reset_day'), day)
        for day in (0, 32, -1):
            self.assertEqual(web.validate_settings({'server_reset_day': day}, s), 'server reset day must be 1-31')

    def test_traffic_period_uses_day_31(self):
        s = dict(db.settings(), server_reset_day=31, server_month={})
        with mock.patch.object(jobs, 'period_of', return_value='2026-01-31') as period_of:
            jobs.server_month(s, health={'rx_total': 0, 'tx_total': 0}, now=1.0e9)
        self.assertEqual(period_of.call_args[0][1], 31)
        self.assertNotRegex(read('vps2vpn', 'jobs.py'), r'min\(28, int\(s\[.server_reset_day')

    def test_page_and_messages(self):
        self.assertRegex(read('vps2vpn', 'static', 'app.js'), r"dayIn = h\('input', \{type: 'number', min: '1', max: '31'")
        kit = read('vps2vpn', 'static', 'kit.js')
        self.assertNotIn('1–28', kit)
        self.assertIn("[/^server reset day must be/,'服务器流量重置日必须是 1–31", kit)

    @unittest.skipUnless(shutil.which('node'), 'needs node to run kit.js')
    def test_message_in_chinese(self):
        kit = read('vps2vpn', 'static', 'kit.js')
        code = kit[kit.index('const ERR_LBL'):kit.index('function toast(')]
        script = ('const KT_ZH={}, KT=KT_ZH;\n' + code +
                  '\nprocess.stdout.write(JSON.stringify(%s.map(errText)));' %
                  json.dumps(['server reset day must be 1-31', 'reset day must be 1-31 (0 = never)']))
        out = subprocess.run(['node', '-e', script], capture_output=True, text=True, encoding='utf-8', timeout=60)
        self.assertEqual(out.returncode, 0, out.stderr)
        server, account = json.loads(out.stdout)
        self.assertIn('服务器流量重置日必须是 1–31', server)
        self.assertIn('0 = 不重置', account)                    # the account message keeps its own text


if __name__ == '__main__':
    unittest.main()
