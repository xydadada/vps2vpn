"""0.2.52: open issues from the 2026-11-23 outside review that were still open.
python -m unittest tests.test_052 -v

- #126 a settings save whose certificate cannot be written keeps the old address (no half-saved state)
- #120 an upgrade whose `systemctl enable` / `restart` fails (or whose `journalctl` fails) puts the previous
  version back instead of stopping half way
"""
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

from tests import test_unit as tu
from tests.test_deploy import INSTALL_SH, TEST_BASH, _posix
from vps2vpn import certs, db, paths, secure, system


class _Web(tu.Web):
    """tu.Web's server and helpers without its own tests (they already run in test_unit)."""


for _name in [n for n in dir(tu.Web) if n.startswith('test')]:
    setattr(_Web, _name, None)


class FailedCertificateKeepsOldAddress(_Web):
    def setUp(self):
        super().setUp()
        db.set_settings(setup_done=True, admin_hash=secure.hash_password('rightpassword'))
        status, _, _ = self.req('POST', self.pp + '/api/login', {'username': 'admin', 'password': 'rightpassword'})
        self.assertEqual(status, 200)
        self._fw = mock.patch.object(system, 'open_firewall', lambda s: None)
        self._fw.start()

    def tearDown(self):
        self._fw.stop()
        super().tearDown()

    def test_one_failed_write_then_a_retry(self):
        before = db.settings()
        real = certs._publish_pair
        calls = []

        def once(*a, **k):
            calls.append(1)
            if len(calls) == 1:
                raise OSError(28, 'No space left on device')
            return real(*a, **k)

        with mock.patch.object(certs, '_publish_pair', once):
            status, body, _ = self.req('POST', self.pp + '/api/settings',
                                       {'public_host': '203.0.113.7', 'member_notice': 'new notice'})
            self.assertEqual(status, 500, body)
            self.assertIn('certificate for the new address', json.loads(body)['error'])
            s = db.settings()
            self.assertEqual(s['public_host'], before['public_host'])
            self.assertEqual(s['member_notice'], before['member_notice'])
            with open(paths.SELF_CRT + '.host', encoding='utf-8') as f:
                self.assertEqual(f.read(), '127.0.0.1')
            # the same request again, now that the disk has room: saved, certificate for the new address
            status, body, _ = self.req('POST', self.pp + '/api/settings',
                                       {'public_host': '203.0.113.7', 'member_notice': 'new notice'})
            self.assertEqual(status, 200, body)
        s = db.settings()
        self.assertEqual((s['public_host'], s['member_notice']), ('203.0.113.7', 'new notice'))
        with open(paths.SELF_CRT + '.host', encoding='utf-8') as f:
            self.assertEqual(f.read(), '203.0.113.7')

    def test_translated(self):
        with open(os.path.join(os.path.dirname(certs.__file__), 'static', 'kit.js'), encoding='utf-8') as f:
            self.assertIn('/^certificate for the new address could not be written/', f.read())


@unittest.skipUnless(TEST_BASH, 'needs bash (on Windows set V2V_TEST_BASH to Git bash)')
class FailedActivationRollsBack(unittest.TestCase):
    INIT = 'case "$*" in *init*) echo \'{"setup_done": true}\' ;; esac\nexit 0\n'
    SCRIPT = '\n'.join([
        'export PATH="$STUBS:$PATH"', 'source "$INSTALL"', 'set -euo pipefail', 'LIB="$LIBDIR"',
        'PY="$STUBS/fakepy"', 'SNAPSHOT=""',
        'for f in need_root detect_arch install_packages prepare_system install_cores install_app install_units '
        'show_result; do eval "$f() { :; }"; done',
        'sleep() { :; }', 'do_install', ''])

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.stubs = os.path.join(self.tmp, 'stubs')
        os.makedirs(self.stubs)
        for ver in ('vps2vpn', 'vps2vpn.old'):
            d = os.path.join(self.tmp, 'lib', 'app', ver)
            os.makedirs(d)
            with open(os.path.join(d, 'which'), 'w') as f:
                f.write('new' if ver == 'vps2vpn' else 'old')
        self.stub('fakepy', self.INIT)
        self.stub('journalctl', 'exit 1\n')

    def stub(self, name, body):
        with open(os.path.join(self.stubs, name), 'w', encoding='utf-8', newline='\n') as f:
            f.write('#!/bin/sh\n' + body)
        os.chmod(os.path.join(self.stubs, name), 0o755)

    def run_install(self, systemctl):
        self.stub('systemctl', systemctl)
        env = dict(os.environ, STUBS=_posix(self.stubs), INSTALL=_posix(INSTALL_SH),
                   LIBDIR=_posix(os.path.join(self.tmp, 'lib')))
        out = subprocess.run([TEST_BASH, '-c', self.SCRIPT], env=env, capture_output=True, text=True, timeout=120)
        with open(os.path.join(self.tmp, 'lib', 'app', 'vps2vpn', 'which')) as f:
            return out, f.read()

    def test_restart_fails(self):
        # the first restart (the new code) fails, the one after the rollback works
        out, live = self.run_install('case "$1" in\n'
                                     '  restart) [ -f "$STUBS/restarted" ] && exit 0; : > "$STUBS/restarted"; exit 1 ;;\n'
                                     '  is-active) exit 3 ;;\nesac\nexit 0\n')
        self.assertNotEqual(out.returncode, 0)
        self.assertIn('previous version was restored', out.stdout + out.stderr)
        self.assertEqual(live, 'old')
        self.assertFalse(os.path.exists(os.path.join(self.tmp, 'lib', 'app', 'vps2vpn.old')))

    def test_enable_fails(self):
        out, live = self.run_install('case "$1" in enable) exit 1 ;; is-active) exit 3 ;; esac\nexit 0\n')
        self.assertNotEqual(out.returncode, 0)
        self.assertIn('previous version was restored', out.stdout + out.stderr)
        self.assertEqual(live, 'old')

    def test_a_good_upgrade_keeps_the_new_code(self):
        out, live = self.run_install('exit 0\n')
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertEqual(live, 'new')


if __name__ == '__main__':
    unittest.main()
