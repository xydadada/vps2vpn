"""Fixes from a beginner's walk through the admin panel and member page (local panel, made-up accounts):
an empty "set password" box no longer removes the member's sign-in, and server messages a beginner meets are
shown in Chinese on the Chinese pages.   python -m unittest tests.test_beginner_ui -v"""
import json
import os
import re
import shutil
import subprocess
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATIC = os.path.join(ROOT, 'vps2vpn', 'static')


def read(*parts):
    with open(os.path.join(ROOT, *parts), encoding='utf-8') as f:
        return f.read()


class SetPasswordBox(unittest.TestCase):
    def test_empty_box_does_not_reach_the_server(self):
        js = read('vps2vpn', 'static', 'app.js')
        # the password '' is how "remove password login" works: "set / reset" must never send it
        m = re.search(r"actBtn\('btn', 'lock', t\('set_pw'\), b => \{(.*?)\}\),", js, re.S)
        self.assertIsNotNone(m, 'set-password button not found')
        body = m.group(1)
        guard, call = body.find('if (!pwIn.value)'), body.find("api(`users/${u.id}/login`")
        self.assertTrue(0 <= guard < call, body)
        self.assertIn("toast(t('pw_first'), 'err')", body[guard:call])
        self.assertIn('return;', body[guard:call])

    def test_box_says_what_goes_in_it(self):
        js = read('vps2vpn', 'static', 'app.js')
        self.assertIn("placeholder: t('pw_ph')", js)
        for lang in ("pw_ph: '新密码（至少 8 位）'", "pw_ph: 'New password (8+ characters)'"):
            self.assertIn(lang, js)
        self.assertEqual(js.count('pw_first:'), 2)


# (message the server sends, file, text in that file) - the source check catches a reworded message
SERVER_MESSAGES = [
    ('a domain is set, so the server address is the domain: clear the domain first to use an IP', 'web.py',
     'a domain is set, so the server address is the domain'),
    ('the domain was cleared: enter this server IP as the server address', 'web.py', 'the domain was cleared'),
    ('too long for a QR code; copy the link instead', 'web.py', 'too long for a QR code'),
    ('this account has no traffic limit', 'members.py', 'this account has no traffic limit'),
    ('managed by the main server: change it there', 'web.py', 'managed by the main server'),
    ('speed limit must be 0-100000 Mbps', 'web.py', "'%s must be 0-%d Mbps'"),
    ('slow-down speed must be 0-100000 Mbps', 'web.py', "('throttle_mbps', 'slow-down speed')"),
    ('traffic rate must be 0-100', 'web.py', 'traffic rate must be 0-100'),
    ('update interval must be a whole number of hours', 'web.py', 'update interval must be a whole number'),
    ('update interval must be 1-168 hours', 'web.py', 'update interval must be 1-168 hours'),
    ('support link must start with http://, https:// or tg:// (one line, no spaces)', 'web.py',
     'support link must start with'),
    ('certificate renewal already in progress', 'web.py', 'certificate renewal already in progress'),
    ('disable existing 2FA before enrolling again', 'web.py', 'disable existing 2FA before enrolling again'),
    ('login settings changed; retry', 'web.py', 'login settings changed; retry'),
    ('sign-in settings changed meanwhile; reload and try again', 'web.py', 'sign-in settings changed meanwhile'),
    ('account credentials changed; retry', 'web.py', 'account credentials changed; retry'),
    ('cannot resolve server address: example.invalid', 'cluster.py', "'cannot resolve server address: %s'"),
    ('cannot resolve server address', 'cluster.py', "'cannot resolve server address'"),
    ('too many IDs (maximum 2000)', 'web.py', 'too many IDs (maximum'),
    ('expire_at is out of supported range', 'web.py', 'expire_at is out of supported range'),
    ('text required', 'web.py', "'text required'"),
    # already translated before: kept working
    ('extra quota (GB) must be between 1 and 10000', 'members.py', "'extra quota (GB)'"),
    ('password must be at least 8 characters', 'web.py', 'password must be at least 8 characters'),
]


@unittest.skipUnless(shutil.which('node'), 'needs node to run kit.js')
class ChineseErrors(unittest.TestCase):
    def test_messages_a_beginner_meets_are_translated(self):
        kit = read('vps2vpn', 'static', 'kit.js')
        code = kit[kit.index('const ERR_LBL'):kit.index('function toast(')]
        script = ('const KT_ZH={}, KT=KT_ZH;\n' + code +
                  '\nconst msgs=JSON.parse(require("fs").readFileSync(0,"utf8"));'
                  '\nprocess.stdout.write(JSON.stringify(msgs.map(errText)));')
        msgs = [m[0] for m in SERVER_MESSAGES]
        out = subprocess.run(['node', '-e', script], input=json.dumps(msgs), capture_output=True, text=True,
                             encoding='utf-8', timeout=60)
        self.assertEqual(out.returncode, 0, out.stderr)
        for (msg, src, snippet), zh in zip(SERVER_MESSAGES, json.loads(out.stdout)):
            self.assertRegex(zh, r'[一-鿿]', msg)
            self.assertIn(snippet, read('vps2vpn', src), msg)


class MemberHeaderOnPhones(unittest.TestCase):
    def test_brand_text_gives_way_to_the_buttons(self):
        css = read('vps2vpn', 'static', 'style.css')
        self.assertIn('.m-top .brand>div{min-width:0}', css)
        self.assertRegex(css, r'@media\(max-width:420px\)\{\.m-top \.brand small\{display:none\}')


class AdminOpensOurApp(unittest.TestCase):
    def test_user_drawer_offers_the_vps2vpn_app_on_windows(self):
        js = read('vps2vpn', 'static', 'app.js')
        self.assertRegex(js, r"imp\.vps2vpn && /Windows/i\.test\(navigator\.userAgent[^)]*\) \?\s*h\('a', \{class: 'btn', href: imp\.vps2vpn")
        self.assertIn("open_app: '在 vps2vpn 客户端中打开'", js)
        self.assertIn("apps_hint: 'Windows 推荐 vps2vpn 客户端", js)


class EmptyNumberBoxes(unittest.TestCase):
    def test_an_empty_box_is_not_sent_as_zero(self):
        js = read('vps2vpn', 'static', 'app.js')
        self.assertIn("const numOrNull = v => (v === '' ? null : Number(v));", js)
        self.assertIn('traffic_rate: numOrNull(r.value)', js)
        self.assertIn("el.type === 'number' ? numOrNull(el.value)", js)
        self.assertNotIn('traffic_rate: Number(', js)

    def test_server_rejects_an_empty_traffic_rate(self):
        from tests import test_unit  # noqa: F401  (sets VPS2VPN_ROOT / dev mode first)
        from vps2vpn import db, web
        s = db.settings()
        self.assertIsInstance(web.validate_settings({'traffic_rate': None}, s), str)
        self.assertEqual(web.validate_settings({'server_reset_day': None}, s)['server_reset_day'], 1)


class SettingsOnPhones(unittest.TestCase):
    def test_installer_folder_path_wraps(self):
        js = read('vps2vpn', 'static', 'app.js')
        self.assertIn("style: 'font-size:12.5px;overflow-wrap:anywhere'}, found)", js)

    def test_two_button_rows_wrap_long_labels(self):
        css = read('vps2vpn', 'static', 'style.css')
        self.assertIn('.act-grid .btn{justify-content:flex-start;padding:10px 12px;min-width:0;white-space:normal', css)
        js = read('vps2vpn', 'static', 'app.js')
        self.assertIn("h('div', {style: 'display:flex;flex-wrap:wrap;gap:8px'}, rulesBtn, restartBtn)", js)


if __name__ == '__main__':
    unittest.main()
