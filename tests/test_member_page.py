"""Member page fixes from a walkthrough as a member: chat-app banner, invite wording, quota kept for unused codes,
rotating the link, sign-up errors, app buttons, the plain fallback page and passwords in link mode."""
import json
import os
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
        self.assertIn('还没设密码的话', src)


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
        self.assertIn('请点右上角 ··· 选「在浏览器打开」', src)
        self.assertGreaterEqual(src.count('chatBanner()'), 2)      # sign-in page and dashboard

    def test_invite_wording(self):
        src = member_js()
        self.assertIn('朋友一注册，你每月的额度就立刻少掉分给他的那部分', src)
        self.assertIn('需要找管理员', src)

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


if __name__ == '__main__':
    unittest.main()
