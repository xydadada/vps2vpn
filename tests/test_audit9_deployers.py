"""Round 9 follow-up: the Windows and browser deployers took quotes off before splitting a pasted ssh command, so
ssh "ubuntu@203.0.113.10" gave the user name "ubuntu (with a quote) and 'root'@203.0.113.10 fell apart.
All three deployers now read the same pastes the same way.   python -m unittest tests.test_audit9_deployers -v"""
import base64
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest

from tests.test_audit9 import HARNESS, MAC_TARGETS
from tests.test_deploy import PS_TARGET_HARNESS, ROOT_DIR, TARGETS, TEST_BASH, deploy

ALL = TARGETS + MAC_TARGETS + [
    ("ssh 'root'@203.0.113.10", ('203.0.113.10', 'root', '')),            # a quoted part of one word
    ('ssh -l "ubuntu" "203.0.113.10"', ('203.0.113.10', 'ubuntu', '')),
    ('ssh -i "C:\\Users\\me\\.ssh\\id_ed25519" root@203.0.113.10', ('203.0.113.10', 'root', '')),  # a Windows key path
    ('ssh -i "My Key.pem root@203.0.113.10', ('Key.pem', '', '')),         # unclosed: plain words, as before
    # round 10 (S10-03): "-p 2222" and "-l ROOT" follow the same rules as "-p2222" and "ROOT@host"
    ('ssh -p 2222abc root@203.0.113.10', ('203.0.113.10', 'root', '')),
    ('ssh -p 2222 -l ROOT 203.0.113.10', ('203.0.113.10', 'root', '2222')),
    ('ssh -l Ubuntu -p "" 203.0.113.10', ('203.0.113.10', 'ubuntu', '')),
]


class SameAnswerEverywhere(unittest.TestCase):
    def test_browser_deployer(self):
        for text, want in ALL:
            self.assertEqual(deploy.parse_target(text), want, text)

    @unittest.skipUnless(os.name == 'nt' and shutil.which('powershell'), 'needs Windows PowerShell')
    def test_windows_deployer(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        harness, cases = os.path.join(tmp, 'harness.ps1'), os.path.join(tmp, 'cases.json')
        with open(harness, 'w', encoding='utf-8-sig') as f:
            f.write(PS_TARGET_HARNESS)
        with open(cases, 'w', encoding='utf-8') as f:
            json.dump([t for t, _ in ALL], f)
        p = subprocess.run(['powershell', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', harness,
                            '-Ps1', os.path.join(ROOT_DIR, 'deploy', 'deploy.ps1'), '-Cases', cases],
                           capture_output=True, timeout=120)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        got = json.loads(base64.b64decode(p.stdout.decode('ascii', 'replace').strip().splitlines()[-1]))
        self.assertEqual(len(got), len(ALL))
        for (text, want), g in zip(ALL, got):
            self.assertEqual(tuple(g), want, text)

    @unittest.skipUnless(TEST_BASH, 'needs bash (on Windows set V2V_TEST_BASH to Git bash)')
    def test_mac_deployer(self):
        with open(os.path.join(ROOT_DIR, 'deploy-mac.command'), encoding='utf-8') as f:
            fn = re.search(r'(?ms)^parse_target\(\) \{.*?^\}$', f.read()).group(0)
        p = subprocess.run([TEST_BASH, '-c', HARNESS % fn], input=''.join(t + '\n' for t, _ in ALL).encode(),
                           capture_output=True, timeout=60)
        self.assertEqual(p.returncode, 0, p.stderr)
        lines = p.stdout.decode('utf-8').splitlines()
        self.assertEqual(len(lines), len(ALL), p.stdout)
        for (text, want), line in zip(ALL, lines):
            self.assertEqual(tuple(line.split('|')), want, text)

    def test_windows_deployer_keeps_its_bom(self):
        with open(os.path.join(ROOT_DIR, 'deploy', 'deploy.ps1'), 'rb') as f:
            self.assertEqual(f.read(3), b'\xef\xbb\xbf')       # Windows PowerShell 5.1 reads it as ANSI without


if __name__ == '__main__':
    unittest.main()
