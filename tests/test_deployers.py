"""Deployer and installer checks that need no server: key files people commonly drag in by mistake, cloud images
that refuse root, and install.sh picking panel code only from next to a real script file."""
import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT_DIR, 'deploy'))
import deploy  # noqa: E402

PS1 = os.path.join(ROOT_DIR, 'deploy', 'deploy.ps1')
INSTALL_SH = os.path.join(ROOT_DIR, 'install.sh')
AWS_ROOT = 'Please login as the user "ubuntu" rather than the user "root".\n\n'


def openssh_key(cipher):
    """A minimal new-format OpenSSH private key blob: only the header matters to the check."""
    def s(b):
        return len(b).to_bytes(4, 'big') + b
    raw = b'openssh-key-v1\x00' + s(cipher) + s(b'none' if cipher == b'none' else b'bcrypt') + s(b'') + b'\x00' * 8
    body = base64.b64encode(raw).decode()
    return '-----BEGIN OPENSSH PRIVATE KEY-----\n%s\n-----END OPENSSH PRIVATE KEY-----\n' % body


KEYS = {
    'ok_openssh': (openssh_key(b'none'), ''),
    'ok_openssh_crlf': (openssh_key(b'none').replace('\n', '\r\n'), ''),
    'ok_pem': ('-----BEGIN RSA PRIVATE KEY-----\nMIIEow==\n-----END RSA PRIVATE KEY-----\n', ''),
    'ppk': ('PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\n', 'PuTTY'),
    'pub': ('ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA me@pc\n', '公钥'),
    'junk': ('hello\n', 'PRIVATE KEY'),
    'enc_openssh': (openssh_key(b'aes256-ctr'), '密码保护'),
    'enc_pem': ('-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00\n\nMIIE==\n'
                '-----END RSA PRIVATE KEY-----\n', '密码保护'),
}


class KeyChecks(unittest.TestCase):
    def test_key_problem(self):
        for name, (text, want) in KEYS.items():
            with self.subTest(name):
                got = deploy.key_problem(text)
                if want:
                    self.assertIn(want, got)
                else:
                    self.assertEqual(got, '')

    @unittest.skipUnless(shutil.which('ssh-keygen'), 'needs ssh-keygen')
    def test_real_keys(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        for pw, bad in (('', False), ('secret-pass', True)):
            path = os.path.join(d, 'k%d' % bad)
            subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', pw, '-f', path], check=True,
                           capture_output=True)
            with open(path) as f:
                self.assertEqual(bool(deploy.key_problem(f.read())), bad)

    def test_login_as_hint(self):
        self.assertEqual(deploy.login_as_hint(AWS_ROOT), 'ubuntu')
        self.assertEqual(deploy.login_as_hint('Please login as the user "ec2-user" rather than the user "root".'),
                         'ec2-user')
        self.assertEqual(deploy.login_as_hint('Permission denied (publickey).'), '')
        self.assertEqual(deploy.login_as_hint('login as the user "x; rm -rf /" rather than'), '')

    def test_start_refuses_unusable_key(self):
        """The local page gets a clear 400 instead of a job that fails later with an ssh error."""
        sent = {}
        h = deploy.H.__new__(deploy.H)
        body = json.dumps({'host': '203.0.113.10', 'key': KEYS['ppk'][0]}).encode()
        h.headers = {'Content-Length': str(len(body))}
        h.rfile = __import__('io').BytesIO(body)
        h.path = '/start?t=' + deploy.TOKEN
        h.reply = lambda code, text, *a, **k: sent.update(code=code, text=text)
        with mock.patch.object(deploy.threading, 'Thread') as th:
            h.do_POST()
        self.assertEqual(sent['code'], 400, sent)
        self.assertIn('PuTTY', json.loads(sent['text'])['error'])
        th.assert_not_called()


class LoginAsRetry(unittest.TestCase):
    """AWS images answer a root login with 'Please login as the user "ubuntu"': try that user once by itself."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)
        self._old = deploy.RECORDS
        deploy.RECORDS = self.dir
        self.addCleanup(setattr, deploy, 'RECORDS', self._old)

    def run_with(self, answers):
        calls = []

        def fake_probe(cmd, env, user):
            calls.append((cmd[-1], user))
            out, rc = answers[len(calls) - 1]
            return subprocess.CompletedProcess(cmd, rc, out, '')
        job, err = deploy.new_job('203.0.113.10', 'root', '22')
        self.assertFalse(err)
        job['key'] = os.path.join(self.dir, 'key')
        job['no_import'] = True
        with mock.patch.object(deploy, 'probe', fake_probe), \
                mock.patch.object(deploy.shutil, 'which', return_value='ssh'):
            deploy.run_job(job)
        return job, calls

    def test_retries_with_the_user_the_server_names(self):
        job, calls = self.run_with([(AWS_ROOT, 142), ('', 255)])
        self.assertEqual(calls, [('root@203.0.113.10', 'root'), ('ubuntu@203.0.113.10', 'ubuntu')])
        self.assertEqual(job['user'], 'ubuntu')
        self.assertEqual(job['state'], 'error')

    def test_no_retry_for_other_errors(self):
        job, calls = self.run_with([('Permission denied (publickey).', 255)])
        self.assertEqual(len(calls), 1)
        self.assertEqual(job['user'], 'root')
        self.assertIn('ubuntu / ec2-user', job['error'])


PS_HARNESS = r'''param([string]$Ps1, [string]$Dir)
$ErrorActionPreference = 'Stop'
$errs = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($Ps1, [ref]$null, [ref]$errs)
if ($errs.Count) { throw "deploy.ps1 does not parse: $($errs[0].Message)" }
$want = 'Get-KeyProblem', 'Get-LoginAsUser', 'Explain'
foreach ($f in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)) {
  if ($want -contains $f.Name) { . ([scriptblock]::Create($f.Extent.Text)) }
}
$User = 'root'; $Port = 22; $Server = '203.0.113.10'; $Records = $Dir
$out = [ordered]@{}
foreach ($k in Get-ChildItem -LiteralPath $Dir -Filter '*.key') {
  $out[$k.BaseName] = Get-KeyProblem (([IO.File]::ReadAllText($k.FullName)) -replace "`r`n", "`n")
}
$out['_login'] = Get-LoginAsUser 'Please login as the user "ubuntu" rather than the user "root".'
$out['_explain'] = Explain 'Please login as the user "ubuntu" rather than the user "root".'
[Console]::Out.WriteLine([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($out | ConvertTo-Json -Compress))))
'''


@unittest.skipUnless(os.name == 'nt' and shutil.which('powershell'), 'needs Windows PowerShell')
class PowerShellDeployer(unittest.TestCase):
    """deploy.ps1 gives the same answers as deploy.py for the same key files."""

    def test_same_key_checks(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        for name, (text, _) in KEYS.items():
            with open(os.path.join(d, name + '.key'), 'w', encoding='utf-8', newline='') as f:
                f.write(text)
        harness = os.path.join(d, 'harness.ps1')
        with open(harness, 'w', encoding='utf-8-sig') as f:
            f.write(PS_HARNESS)
        p = subprocess.run(['powershell', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', harness,
                            '-Ps1', PS1, '-Dir', d], capture_output=True, text=True, timeout=120)
        self.assertEqual(p.returncode, 0, p.stderr)
        got = json.loads(base64.b64decode(p.stdout.strip().splitlines()[-1]).decode('utf-8'))
        for name, (text, want) in KEYS.items():
            with self.subTest(name):
                self.assertEqual(got[name] or '', deploy.key_problem(text))
        self.assertEqual(got['_login'], 'ubuntu')
        self.assertIn('把用户名改成 ubuntu', got['_explain'])

    def test_aws_default_user_rule(self):
        with open(PS1, encoding='utf-8-sig') as f:
            src = f.read()
        self.assertNotIn(r"'Lightsail|\.pem$'", src)     # any .pem used to switch the user to ubuntu


@unittest.skipUnless(shutil.which('bash'), 'needs bash')
class InstallerCodeSource(unittest.TestCase):
    """install.sh uses panel code next to itself only when it is a real file, never the current directory of a
    piped install (curl ... | bash), which would replace the verified release download."""

    def setUp(self):
        with open(INSTALL_SH, encoding='utf-8') as f:
            sh = f.read()
        start = sh.index('install_app() {')
        end = sh.index('    fetch_panel_code "$tmp"\n  fi\n', start) + len('    fetch_panel_code "$tmp"\n  fi\n')
        self.snippet = ('set -eu\n_TMPDIRS=()\nsay() { echo "SAY: $*"; }\nfetch_panel_code() { echo FETCH; }\n'
                        + sh[start:end] + '}\ninstall_app\n')
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)
        os.makedirs(os.path.join(self.dir, 'vps2vpn'))
        open(os.path.join(self.dir, 'vps2vpn', '__init__.py'), 'w').close()

    def bash(self, args, stdin=None):
        p = subprocess.run(['bash'] + args, input=stdin, cwd=self.dir, capture_output=True, text=True, timeout=60)
        self.assertEqual(p.returncode, 0, p.stderr)
        return p.stdout

    def test_piped_ignores_current_directory(self):
        out = self.bash(['-s'], self.snippet)
        self.assertIn('FETCH', out)
        self.assertNotIn('next to this script', out)

    def test_script_file_uses_code_next_to_it(self):
        with open(os.path.join(self.dir, 'inst.sh'), 'w', newline='\n') as f:
            f.write(self.snippet)
        out = self.bash(['inst.sh'])
        self.assertIn('next to this script', out)
        self.assertNotIn('FETCH', out)


class MacDeployer(unittest.TestCase):
    def test_rules(self):
        with open(os.path.join(ROOT_DIR, 'deploy-mac.command'), encoding='utf-8') as f:
            src = f.read()
        self.assertNotIn('*.pem) USER_DEF=ubuntu', src)
        self.assertIn("tr -d '\\r' < \"$KEY\"", src)                    # CRLF keys from Windows work
        self.assertIn('PuTTY-User-Key-File', src)
        self.assertIn('login as the user', src)


if __name__ == '__main__':
    unittest.main()
