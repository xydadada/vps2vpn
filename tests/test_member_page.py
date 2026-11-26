"""Member page fixes from a walkthrough as a member: chat-app banner, invite wording, quota kept for unused codes,
rotating the link, sign-up errors, app buttons, the plain fallback page and passwords in link mode."""
import json
import os
import shutil
import subprocess
import threading
import unittest

from tests import test_unit as tu          # sets VPS2VPN_ROOT / dev mode first
from vps2vpn import certs, db, members, secure, subscription, web

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GB = 1 << 30


def member_js():
    with open(os.path.join(ROOT, 'vps2vpn', 'static', 'member.js'), encoding='utf-8') as f:
        return f.read()


class Server(tu.Base):
    def setUp(self):
        super().setUp()
        db.set_settings(public_host='127.0.0.1', setup_done=True, member_path='mem', panel_path='adm',
                        admin_hash=secure.hash_password('adminpassword'))
        certs.ensure_self_signed('127.0.0.1')
        self.httpd = web.Server(('127.0.0.1', 0), web.Handler, web.TLSContext())
        self.port = self.httpd.server_address[1]
        db.set_settings(panel_port=self.port)
        self._thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self._thread.start()
        self.cookie = ''
        web._fails.clear()
        self._apply = web.apply_async
        web.apply_async = lambda force=False: None

    def tearDown(self):
        web.apply_async = self._apply
        self.httpd.shutdown()
        self.httpd.server_close()
        self._thread.join(5)
        super().tearDown()

    req = tu.Web.req

    def j(self, *a):
        st, body, _ = self.req(*a)
        return st, json.loads(body or b'{}')


class SignUpErrors(Server):
    def test_only_wrong_codes_count_toward_the_limit(self):
        db.add_user('taken', 10)
        rec = members.create_invite('admin', 10, 7, max_uses=1)
        for _ in range(12):        # typos in the name or password are not guesses
            st, d = self.j('POST', '/mem/api/register', {'code': rec['code'], 'name': 'taken', 'password': 'goodpassword'})
            self.assertEqual(st, 400, d)
            st, d = self.j('POST', '/mem/api/register', {'code': rec['code'], 'name': 'newbie', 'password': 'short'})
            self.assertEqual(st, 400, d)
        st, d = self.j('POST', '/mem/api/register', {'code': rec['code'], 'name': 'newbie', 'password': 'goodpassword'})
        self.assertEqual(st, 200, d)
        for _ in range(8):
            st, _ = self.j('POST', '/mem/api/register', {'code': 'WRONG-CODE1', 'name': 'x' + str(_) + 'y', 'password': 'goodpassword'})
            self.assertEqual(st, 400)
        st, _ = self.j('POST', '/mem/api/register', {'code': 'WRONG-CODE1', 'name': 'zzz', 'password': 'goodpassword'})
        self.assertEqual(st, 429)

    def test_page_keeps_passwords_after_a_sign_up_error(self):
        src = member_js()
        self.assertIn("if (!reg) f.pw.value = ''", src)
        self.assertNotIn("f.pw.value = ''; f.pw2.value = ''", src)


class LinkMode(Server):
    def setUp(self):
        super().setUp()
        uid = db.add_user('zoe', 20)
        db.update_user(uid, login_hash=secure.hash_password('oldpassword'))
        self.base = '/s/%s/' % db.user(uid)['sub_token']
        self.uid = uid

    def test_link_sets_password_without_the_old_one(self):
        st, d = self.j('POST', self.base + 'api/password', {'new': 'brandnewpass'})
        self.assertEqual(st, 200, d)
        self.assertTrue(secure.check_password('brandnewpass', db.user(self.uid)['login_hash']))

    def test_member_centre_still_needs_the_old_password(self):
        st, _ = self.j('POST', '/mem/api/login', {'name': 'zoe', 'password': 'oldpassword'})
        self.assertEqual(st, 200)
        st, d = self.j('POST', '/mem/api/password', {'old': 'nope-nope', 'new': 'brandnewpass'})
        self.assertEqual(st, 403, d)

    def test_link_password_changes_are_rate_limited(self):
        codes = [self.j('POST', self.base + 'api/password', {'new': 'pw%07d' % i})[0] for i in range(10)]
        self.assertEqual(codes[:8], [200] * 8)
        self.assertEqual(codes[8:], [429, 429])

    def test_rotate_returns_the_new_link_and_the_page_shows_it(self):
        st, d = self.j('POST', self.base + 'api/rotate', {})
        self.assertEqual(st, 200, d)
        self.assertTrue(d['sub_url'].endswith('/s/' + db.user(self.uid)['sub_token']))
        src = member_js()
        self.assertIn("modal({title: t('new_link')", src)
        self.assertIn("t(byLink ? 'rotate_q_link' : 'rotate_q')", src)
        self.assertIn('如果还没有设置密码，建议先在上方设置', src)


class ReservedQuota(Server):
    def test_reserved_and_void_codes(self):
        uid = db.add_user('amy', 10)
        db.update_user(uid, login_hash=secure.hash_password('goodpassword'))
        code = members.create_invite('member', 3, 7, inviter=uid)
        self.j('POST', '/mem/api/login', {'name': 'amy', 'password': 'goodpassword'})
        st, me = self.j('GET', '/mem/api/me')
        self.assertEqual(st, 200, me)
        self.assertEqual(me['reserved_gb'], 3)
        self.assertFalse(me['invites'][0]['void'])
        # the inviter burns through the quota: the unused code can no longer be honoured
        db.update_user(uid, used_down=9 * GB)
        st, me = self.j('GET', '/mem/api/me')
        self.assertTrue(me['invites'][0]['void'])
        with self.assertRaises(members.Refused):
            members.register(code['code'], 'friend', 'goodpassword')
        src = member_js()
        self.assertIn("q - used - (me.reserved_gb || 0) * GB", src)
        self.assertIn("i.void ? chip('bad', t('st_void'))", src)


class Texts(unittest.TestCase):
    def test_chat_app_banner(self):
        src = member_js()
        self.assertIn('/MicroMessenger|QQ\\//i', src)
        self.assertIn('请点击右上角 ···，选择「在浏览器打开」', src)
        self.assertGreaterEqual(src.count('chatBanner()'), 2)      # sign-in page and dashboard

    def test_invite_wording(self):
        src = member_js()
        self.assertIn('朋友注册后，你每月的额度会立即减去分给对方的部分', src)
        self.assertIn('要收回已注册用户的额度，请联系管理员', src)

    def test_iphone_apps_have_buttons_and_honest_prices(self):
        links = subscription.import_links('https://h:1/s/tok', 'n')
        self.assertTrue(links['stash'].startswith('stash://install-config?url='))
        self.assertTrue(links['karing'].startswith('karing://install-config?url='))
        src = member_js()
        self.assertIn("im.stash}, 'Stash'", src)
        self.assertIn("im.karing}, 'Karing'", src)
        self.assertIn('Stash（都要付费）', src)
        self.assertNotIn('Stash 或 Karing（免费）', src)
        self.assertNotIn('Stash 或 Karing（免费）', json.dumps(web.LANDING, ensure_ascii=False))


class OpenOurClient(unittest.TestCase):
    def test_vps2vpn_link_and_button(self):
        links = subscription.import_links('https://h:1/s/tok', 'n')
        self.assertTrue(links['vps2vpn'].startswith('vps2vpn://install-config?url=https%3A%2F%2Fh%3A1%2Fs%2Ftok%3Fformat%3Dclash'))
        src = member_js()
        self.assertIn("h('a', {class: 'btn primary', href: im.vps2vpn}", src)
        self.assertIn('在 vps2vpn 客户端中打开', src)
        self.assertIn('vps2vpn-client/releases/latest', src)
        self.assertIn('vps2vpn 客户端', dict(web.LANDING['zh']['apps'])['Windows'])


class Landing(tu.Base):
    def test_uses_effective_quota(self):
        a = db.add_user('amy', 10)
        b = db.add_user('bob', 4, invited_by=a, invite_deduct=4)
        s = db.settings()
        page = web.landing_page(s, db.user(a), 'https://h:1/s/x')
        self.assertIn('6.0 GB', page.replace('6.00', '6.0'))
        self.assertIn('Stash', page)
        self.assertTrue(b)


class TrafficRankSwitch(Server):
    """The app shows its per-app traffic ranking only when the admin turns it on; the member API says so in
    features.traffic_rank, for link pages and the member centre alike."""
    def setUp(self):
        super().setUp()
        uid = db.add_user('tia', 20)
        db.update_user(uid, login_hash=secure.hash_password('tiapassword'))
        self.base = '/s/%s/' % db.user(uid)['sub_token']

    def features(self):
        st, d = self.j('GET', self.base + 'api/me')
        self.assertEqual(st, 200, d)
        return d['features']

    def test_off_by_default(self):
        self.assertIs(db.settings()['client_traffic_rank'], False)
        self.assertEqual(self.features(), {'traffic_rank': False, 'node_status': False, 'feedback': False, 'devices': False})

    def test_admin_switch_reaches_the_app(self):
        changes = web.validate_settings({'client_traffic_rank': True}, db.settings())
        self.assertEqual(changes, {'client_traffic_rank': True})
        db.set_settings(**changes)
        self.assertEqual(self.features(), {'traffic_rank': True, 'node_status': False, 'feedback': False, 'devices': False})
        st, _ = self.j('POST', '/mem/api/login', {'name': 'tia', 'password': 'tiapassword'})
        self.assertEqual(st, 200)
        st, d = self.j('GET', '/mem/api/me')
        self.assertEqual((st, d['features']), (200, {'traffic_rank': True, 'node_status': False, 'feedback': False, 'devices': False}))
        db.set_settings(**web.validate_settings({'client_traffic_rank': 'false'}, db.settings()))
        self.assertEqual(self.features(), {'traffic_rank': False, 'node_status': False, 'feedback': False, 'devices': False})

    def test_only_a_real_true_turns_it_on(self):
        self.assertIsInstance(web.validate_settings({'client_traffic_rank': 'maybe'}, db.settings()), str)
        db.set_settings(client_traffic_rank='false')          # e.g. from a hand-edited backup
        self.assertEqual(self.features(), {'traffic_rank': False, 'node_status': False, 'feedback': False, 'devices': False})

    def test_admin_page_has_the_switch(self):
        with open(os.path.join(ROOT, 'vps2vpn', 'static', 'app.js'), encoding='utf-8') as f:
            js = f.read()
        self.assertEqual(js.count("client_traffic_rank: '"), 2)             # Chinese and English labels
        self.assertIn("saveSettings({client_traffic_rank: e.checked})", js)


class SameWordsAsTheApp(unittest.TestCase):
    """0.2.48: the member centre uses the client's word list (remove a device, node, sign in) and its date style."""

    def test_words(self):
        js = member_js()
        zh = js[js.index('  zh: {'):js.index('\n  en: {')]
        en = js[js.index('\n  en: {'):js.index('\n};')]
        for old in ('踢', '线路', '的话', '别人', '连不上', "'MEMBER'"):
            self.assertNotIn(old, zh, old)
        self.assertIn("dv_revoke: '移除'", zh)
        self.assertIn("dv_revoke: 'Remove'", en)
        for old in ('Log in', 'Log out', 'centre', "dv_revoke: 'Sign out'", 'answer'):
            self.assertNotIn(old, en, old)
        for f in ('app.js', 'kit.js'):
            with open(os.path.join(ROOT, 'vps2vpn', 'static', f), encoding='utf-8') as fh:
                self.assertNotIn('踢', fh.read(), f)

    @unittest.skipUnless(shutil.which('node'), 'needs node')
    def test_dates(self):
        js = member_js()
        code = js[js.index('const MONTHS'):js.index('};', js.index('const dateStr')) + 2]
        script = ('const t = k => k; let L;\n'
                  'const localDay = ms => { const d = new Date(ms); return d.getFullYear() + "-" + '
                  'String(d.getMonth() + 1).padStart(2, "0") + "-" + String(d.getDate()).padStart(2, "0"); };\n'
                  + code + '\nconst y = new Date().getFullYear(), out = [];\n'
                  'for (L of ["zh", "en"]) out.push(dateStr(y + "-11-26"), dateStr((y + 1) + "-01-05"), dateStr(0));\n'
                  'process.stdout.write(JSON.stringify([y, out]));')
        res = subprocess.run(['node', '-e', script], capture_output=True, text=True, encoding='utf-8', timeout=60)
        self.assertEqual(res.returncode, 0, res.stderr)
        y, out = json.loads(res.stdout)
        self.assertEqual(out, ['11月26日', '%d年1月5日' % (y + 1), 'never',
                               'Nov 26', 'Jan 5, %d' % (y + 1), 'never'])
        self.assertIn('dateStr(me.expire_day || me.expire_at)', js)          # the server's own day is still shown


class DeviceRowsAndDetails(unittest.TestCase):
    """0.2.49: one device row in both pages, dates that never split, soft removal described as it works."""

    @staticmethod
    def read(name):
        with open(os.path.join(ROOT, 'vps2vpn', 'static', name), encoding='utf-8') as f:
            return f.read()

    def test_one_device_row(self):
        kit, css = self.read('kit.js'), self.read('style.css')
        self.assertIn('function deviceRow(', kit)
        self.assertIn("title:fmt.ago(x.last_seen)},seenLabel+' '+fmt.time(x.last_seen))", kit)   # date, age on hover
        self.assertIn("[x.name?pf:'',x.version,x.ip]", kit)        # platform · version · IP; no repeat for a nameless one
        self.assertIn("macos:'macOS'", kit)
        for name in ('member.js', 'app.js'):
            js = self.read(name)
            self.assertIn("deviceRow(x, t('dv_seen'),", js, name)
            self.assertNotIn("t('dv_seen') + ' ' +", js, name)                  # no hand-made rows left
        self.assertIn('.nw{white-space:nowrap}', css)
        self.assertIn('.dv-name{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}', css)

    def test_member_words(self):
        js = member_js()
        for old in ('(es)', 'forgets this subscription', '删除这个订阅', '已被移除', "sr_full: '小火箭（",
                    "stat(t('status')"):
            self.assertNotIn(old, js, old)
        self.assertIn("'1 IP address is using this account now'", js)
        self.assertIn('info.hidden = !r.online_ips;', js)
        self.assertIn("L === 'zh' ? '会员中心' : 'MEMBER'", js)

    def test_admin_words(self):
        js = self.read('app.js')
        for old in (' centre', 'Centre', "'Log in'", "'Log out'", '他的', '发给他。', '他可以', '1.0.29 起', '「换订阅链接」',
                    "rotate: '更换链接'"):
            self.assertNotIn(old, js, old)
        self.assertIn('「更换订阅链接」', js)
        zh = js[js.index('  zh: {'):js.index('\n  en: {')]
        en = js[js.index('\n  en: {'):js.index('\n};', js.index('\n  en: {'))]
        # the whole admin page: written language, 点击, 更换, 节点 in sentences, "X中…" for states
        for old in ('线路', '连不上', '搞定', '不懂就别动', '点「', '点按钮', '再点连接', '换一个', '同时在线设备上限',
                    '正在', '会员页'):
            self.assertNotIn(old, zh, old)
        for old in (' tap ', 'one-tap', 'Press ', 'password login', 'member page', 'a line of another'):
            self.assertNotIn(old, en, old)
        self.assertNotIn('不支持的线路', self.read('kit.js'))


if __name__ == '__main__':
    unittest.main()
