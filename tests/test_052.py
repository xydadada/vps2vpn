"""0.2.52: open issues from the 2026-11-23 outside review that were still open.
python -m unittest tests.test_052 -v

- #126 a settings save whose certificate cannot be written keeps the old address (no half-saved state)
- #157 the Windows and Mac deployers stop a remote install that runs past its deadline
- #120 an upgrade whose `systemctl enable` / `restart` fails (or whose `journalctl` fails) puts the previous
  version back instead of stopping half way
"""
import base64
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

from tests import test_unit as tu
from tests.test_deploy import INSTALL_SH, TEST_BASH, _posix
from vps2vpn import certs, db, paths, secure, system


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


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
        out = subprocess.run([TEST_BASH, '-c', self.SCRIPT], env=env, capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=120)
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

    # #164: the old process can still be active after a refused restart (a unit that no longer loads, a job
    # that timed out), and a failed enable means the panel does not come back after a reboot.
    def test_refused_restart_with_the_old_process_still_active_rolls_back(self):
        out, live = self.run_install('case "$1" in restart) [ -f "$STUBS/restarted" ] && exit 0; '
                                     ': > "$STUBS/restarted"; exit 1 ;; esac\nexit 0\n')
        self.assertNotEqual(out.returncode, 0)
        self.assertIn('previous version was restored', out.stdout + out.stderr)
        self.assertIn('systemctl restart vps2vpn failed', out.stdout + out.stderr)
        self.assertEqual(live, 'old')

    def test_failed_enable_with_an_active_panel_rolls_back(self):
        out, live = self.run_install('case "$1" in enable) exit 1 ;; esac\nexit 0\n')
        self.assertNotEqual(out.returncode, 0)
        self.assertIn('previous version was restored', out.stdout + out.stderr)
        self.assertIn('systemctl enable vps2vpn failed', out.stdout + out.stderr)
        self.assertEqual(live, 'old')

    def test_a_fresh_install_says_which_step_failed(self):
        shutil.rmtree(os.path.join(self.tmp, 'lib', 'app', 'vps2vpn.old'))
        out, live = self.run_install('case "$1" in enable) exit 1 ;; esac\nexit 0\n')
        self.assertNotEqual(out.returncode, 0)
        self.assertIn('systemctl enable vps2vpn failed', out.stdout + out.stderr)
        self.assertIn('panel failed to start', out.stdout + out.stderr)
        self.assertEqual(live, 'new')


MAC_HARNESS = r'''%s
STALL="$TMPD/stalled"
start=$SECONDS
out=$(printf 'hello\n' | run_with_deadline 2 sh -c 'cat; exec sleep 30' | cat)
rc=$?
echo "slow|$out|$([ -f "$STALL" ] && echo stalled)|$((SECONDS - start))"
rm -f "$STALL"
start=$SECONDS
out=$(printf 'hi\n' | run_with_deadline 30 sh -c 'cat' | cat)
echo "fast|$out|$([ -f "$STALL" ] && echo stalled)|$((SECONDS - start))"
'''

PS_DEADLINE_HARNESS = r'''param([string]$Ps1)
$ErrorActionPreference = 'Stop'
$errs = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($Ps1, [ref]$null, [ref]$errs)
if ($errs.Count) { throw "deploy.ps1 does not parse: $($errs[0].Message)" }
foreach ($f in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)) {
  if ($f.Name -in @('Test-Stalled', 'Get-StalledMsg')) { . ([scriptblock]::Create($f.Extent.Text)) }
}
function New-Job([int]$ago) {
  $p = Start-Process -FilePath ping.exe -ArgumentList '-n 60 127.0.0.1' -WindowStyle Hidden -PassThru
  @{ Proc = $p; Started = [DateTime]::UtcNow.AddSeconds(-$ago) }
}
$old = New-Job 100
$late = Test-Stalled $old 50
$null = $old.Proc.WaitForExit(10000)
$new = New-Job 0
$early = Test-Stalled $new 50
$alive = -not $new.Proc.HasExited
$new.Proc.Kill()
$msg = Get-StalledMsg 1800
[Console]::Out.WriteLine("$late|$($old.Proc.HasExited)|$early|$alive|" + [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($msg)))
'''


class DeployersHaveAnInstallDeadline(unittest.TestCase):
    """#157: the Python deployer got its deadline in 0.2.51; the Windows and Mac ones now stop too."""

    @unittest.skipUnless(TEST_BASH, 'needs bash (on Windows set V2V_TEST_BASH to Git bash)')
    def test_mac_deployer(self):
        with open(os.path.join(ROOT, 'deploy-mac.command'), encoding='utf-8') as f:
            body = f.read()
        fn = re.search(r'(?ms)^run_with_deadline\(\) \{.*?^\}$', body).group(0)
        self.assertIn('run_with_deadline "$DEADLINE" ssh', body)
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        p = subprocess.run([TEST_BASH, '-c', MAC_HARNESS % fn], env=dict(os.environ, TMPD=_posix(tmp)),
                           capture_output=True, timeout=60)
        self.assertEqual(p.returncode, 0, p.stderr)
        slow, fast = p.stdout.decode('utf-8').splitlines()
        name, out, stalled, secs = slow.split('|')
        self.assertEqual((out, stalled), ('hello', 'stalled'))       # stdin reached the command, then it was stopped
        self.assertLess(int(secs), 15)
        name, out, stalled, secs = fast.split('|')
        self.assertEqual((out, stalled), ('hi', ''))
        self.assertLess(int(secs), 4)                              # the watcher does not hold the pipe open

    @unittest.skipUnless(os.name == 'nt' and shutil.which('powershell'), 'needs Windows PowerShell')
    def test_windows_deployer(self):
        with open(os.path.join(ROOT, 'deploy', 'deploy.ps1'), encoding='utf-8-sig') as f:
            body = f.read()
        self.assertIn("if ($script:stage -eq 'install' -and (Test-Stalled $j $InstallDeadline))", body)
        self.assertIn('if (Test-Stalled $j $InstallDeadline) { Remove-Secrets; throw', body)
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        harness = os.path.join(tmp, 'harness.ps1')
        with open(harness, 'w', encoding='utf-8-sig') as f:
            f.write(PS_DEADLINE_HARNESS)
        p = subprocess.run(['powershell', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', harness,
                            '-Ps1', os.path.join(ROOT, 'deploy', 'deploy.ps1')], capture_output=True, timeout=120)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        late, killed, early, alive, msg = p.stdout.decode('ascii').strip().splitlines()[-1].split('|')
        self.assertEqual((late, killed, early, alive), ('True', 'True', 'False', 'True'))
        msg = base64.b64decode(msg).decode('utf-8')
        self.assertIn('30 分钟', msg)
        self.assertIn('vps2vpn info', msg)


def _static(name):
    with open(os.path.join(ROOT, 'vps2vpn', 'static', name), encoding='utf-8') as f:
        return f.read()


class PanelWording(unittest.TestCase):
    """docs/admin-review.md P2: question titles with a verb button, one word for accounts, no English captions in
    the Chinese panel, singular and plural in English."""

    def test_chinese_panel(self):
        app = _static('app.js')
        zh = app[:app.index('\n  en: {')]
        for word in ('使用者', '其它', '不等了', '记得续费', '有就填', '这些人', 'OVERVIEW', 'USERS', 'MEMBERS', 'SERVERS',
                     'MONITOR', 'SETTINGS', 'SYSTEM'):
            self.assertNotIn(word, zh)
        for literal in ("'SELF-HOSTED VPN'", "'ADMIN CONSOLE'", "'LIVE')"):
            self.assertNotIn(literal, app)

    def test_every_confirm_box_names_its_action(self):
        for name in ('app.js', 'member.js'):
            for call in re.findall(r"confirmBox\((.*?)\)\)?\s*(?:return|\{|await|act|fbAct)", _static(name)):
                with self.subTest(file=name, call=call[:60]):
                    self.assertIn('confirm:', call)
                    self.assertTrue(call.startswith("t('q_") or call.startswith("t('fb_del_q')") or
                                    call.startswith("t('dv_revoke_t')") or call.startswith("t('change_port_q')"), call)

    def test_new_texts_in_both_languages(self):
        app = _static('app.js')
        i = app.index('\n  en: {')
        zh, en = app[:i], app[i:app.index('\n};', i)]
        for key in re.findall(r"t\('(q_[a-z_]+|restart_tip|restart_ok|fb_del_tip|revoke_tip|brand_sub|console|live_pill)'\)", app):
            with self.subTest(key=key):
                self.assertIn(key + ':', zh)
                self.assertIn(key + ':', en)
        for key in ('users_n_1', 'devices_1', 'doctor_bad_1'):
            self.assertIn(key + ':', en)
        self.assertFalse(re.findall(r'[a-z]\(s\)(?!:)', en))         # http(s):// is fine
        self.assertNotIn('airports', en)


if __name__ == '__main__':
    unittest.main()
