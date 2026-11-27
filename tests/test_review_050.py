"""0.2.50: the P1 items of the admin / member-center review (review-server-admin, items 1-6 and 42):
python -m unittest tests.test_review_050 -v

 1  joined-server rows: the actions wrap on a phone; the error is not a 442 px chip
 2  server messages in the panel's language: health check (name, detail, fix; the English on hover),
    sync and certificate errors, the note an invited sign-up gets
 3  url and datetime-local inputs are styled (dark mode)
 4  a member who signs in with a password sees the admin's notice without reloading
 5  the member page that failed to load: brand, a plain sentence, a retry button
 6  the closed drawer's shadow does not show at the right edge
42  a joined server whose info lacks a field is left out; the page and the subscriptions keep working
"""
import ast
import json
import os
import re
import shutil
import subprocess
import unittest
from unittest import mock

from tests import test_unit as tu          # sets VPS2VPN_ROOT / dev mode first
from tests.test_member_page import Server
from vps2vpn import cluster, db, doctor, jobs, members, paths, subscription

SID, BAD = '44444444', '55555555'


def _static(name):
    with open(os.path.join(paths.STATIC, name), encoding='utf-8') as f:
        return f.read()


class BrokenJoinedServer(Server):
    """42"""
    def setUp(self):
        super().setUp()
        self.uid = db.add_user('member', 50)
        good = cluster.public_info(dict(db.settings(), public_host='198.51.100.5', node_name='Tokyo'))
        bad = dict(good, node_name='Osaka', public_host='198.51.100.6')
        del bad['hy2_port']                                  # e.g. another version, a damaged record
        db.set_settings(servers=[
            {'id': BAD, 'name': 'Osaka', 'url': 'https://198.51.100.6:1/x', 'key': 'k', 'pin': '', 'enabled': True,
             'info': bad, 'idmap': {str(self.uid): 7}},
            {'id': SID, 'name': 'Tokyo', 'url': 'https://198.51.100.5:1/x', 'key': 'k', 'pin': '', 'enabled': True,
             'info': good, 'idmap': {str(self.uid): 42}}])
        subscription._bad_warned.clear()

    def test_the_others_stay_in_every_format(self):
        s, u = db.settings(), db.user(self.uid)
        with mock.patch.object(jobs, 'log') as log:
            ns = subscription.nodes(s, u)
            groups = {n['group'] for n in ns}
            self.assertIn('Tokyo', groups)
            self.assertNotIn('Osaka', groups)
            self.assertTrue(any(n['server_id'] == db.MAIN_SERVER for n in ns))
            subscription.clash(s, u, 'https://192.0.2.1:1')
            subscription.singbox(s, u, 'https://192.0.2.1:1')
            subscription.shadowrocket(s, u, 'https://192.0.2.1:1')
        # one warning per server in 10 minutes, naming it
        self.assertEqual(log.call_count, 1)
        self.assertIn('Osaka', log.call_args[0][0])
        self.assertIn('hy2_port', log.call_args[0][0])

    def test_member_page_loads(self):
        st, d = self.j('GET', '/s/%s/api/me' % db.user(self.uid)['sub_token'])
        self.assertEqual(st, 200, d)
        st, body, _ = self.req('GET', '/s/%s' % db.user(self.uid)['sub_token'])
        self.assertEqual(st, 200)


class DoctorInTheirLanguage(tu.Base):
    """2: the health check"""
    def _calls(self):
        with open(doctor.__file__, encoding="utf-8") as f:
            tree = ast.parse(f.read())
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and getattr(node.func, 'id', '') == '_check':
                yield node

    @staticmethod
    def _consts(node):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return {node.value}
        if isinstance(node, ast.IfExp):
            return DoctorInTheirLanguage._consts(node.body) | DoctorInTheirLanguage._consts(node.orelse)
        return set()

    def test_every_key_and_name_has_chinese(self):
        keys, ids = set(), set()
        for c in self._calls():
            k = [kw.value for kw in c.keywords if kw.arg == 'key'] or c.args[4:5]
            for x in k:
                keys |= self._consts(x)
            ids |= self._consts(c.args[0])
        keys.discard('')
        self.assertGreater(len(keys), 25)
        self.assertEqual(keys - set(doctor.ZH_DETAIL), set())
        self.assertEqual(ids - set(doctor.ZH_NAMES), set())
        # services: 'service_' + name; failed checks: the function's name
        for n in ('panel', 'xray', 'hysteria', 'tuic'):
            self.assertIn('service_' + n, doctor.ZH_NAMES)
        for fn in ('services', 'reality_handshake', 'hysteria_api', 'udp_listening', 'port_hopping', 'certificate',
                   'kernel', 'clock', 'outbound', 'resources', 'versions', 'rule_mirror', 'speed_limits'):
            self.assertIn(fn, doctor.ZH_NAMES)

    def test_chinese_with_the_english_kept(self):
        rs = [doctor._check('rules', True, 'updated 0 hours ago', key='rules_age', h=0),
              doctor._check('rules', False, 'updated 80 hours ago', 'press it', 'rules_age', h=80),
              doctor._check('certificate', None, "self-signed, so subscription links use plain HTTP; Let's Encrypt: "
                            'not requested yet', 'open TCP 80', 'self_pending'),
              doctor._check('address', True, 'configured 198.51.100.7, actual 198.51.100.7', '', 'ip_compare',
                            host='198.51.100.7', now='198.51.100.7'),
              {'id': 'bbr', 'ok': False, 'detail': 'x', 'fix': 'y'},          # an older shape: no key
              doctor._check('new_check', False, 'boom', 'do it')]           # no translation at all
        zh = doctor.localized(rs, 'zh')
        self.assertEqual((zh[0]['name'], zh[0]['detail'], zh[0]['orig']), ('分流规则', '不到 1 小时前更新', 'updated 0 hours ago'))
        self.assertEqual(zh[0]['fix'], '')
        self.assertEqual(zh[1]['detail'], '80 小时前更新')
        self.assertIn('github.com', zh[1]['fix'])
        self.assertFalse(re.search('[A-Za-z]{4,}', zh[1]['fix'].replace('github', '')), zh[1]['fix'])
        self.assertIn('还没有申请', zh[2]['detail'])
        self.assertEqual(zh[3]['detail'], '设置的地址 198.51.100.7，实际 198.51.100.7')
        self.assertEqual((zh[4]['name'], zh[4]['detail'], zh[4]['orig']), ('BBR 加速', '有问题', 'x'))
        self.assertEqual((zh[5]['detail'], zh[5]['orig'], zh[5]['fix']), ('有问题', 'boom', 'do it'))
        en = doctor.localized(rs, 'en')
        self.assertEqual((en[0]['name'], en[0]['detail'], en[0]['orig']), ('rules', 'updated 0 hours ago', ''))
        # the input is left as it was (the command line prints English)
        self.assertEqual(rs[0]['detail'], 'updated 0 hours ago')

    def test_plural(self):
        with mock.patch('vps2vpn.cores.active_users', return_value=[{'speed_mbps': 5}]), \
                mock.patch('vps2vpn.db.limit_mbps', return_value=5), \
                mock.patch('vps2vpn.shaper.active', return_value=False), \
                mock.patch('vps2vpn.shaper.available', return_value=False):
            r = doctor.speed_limits()[0]
        self.assertIn('1 account has a speed limit', r['detail'])
        self.assertEqual(doctor.localized([r], 'zh')[0]['detail'][:2], '1 ')

    def test_telegram_uses_the_names(self):
        db.set_settings(language='zh')
        with mock.patch.object(doctor, 'run_all', return_value=[doctor._check('disk', False, '100 MB free', 'free it', 'disk', mb=100)]):
            out = jobs.tg_command('/doctor')
        self.assertEqual(out, '❌ 磁盘空间：清理磁盘空间')
        db.set_settings(language='en')
        with mock.patch.object(doctor, 'run_all', return_value=[doctor._check('disk', False, '100 MB free', 'free it', 'disk', mb=100)]):
            self.assertEqual(jobs.tg_command('/doctor'), '❌ disk: free it')


class DoctorEndpoint(Server):
    def test_panel_gets_the_translation(self):
        self.j('POST', '/adm/api/login', {'username': 'admin', 'password': 'adminpassword'})
        db.set_settings(language='zh')
        with mock.patch.object(doctor, 'run_all', return_value=[doctor._check('memory', False, '95% used', 'x', 'mem', pct=95)]):
            st, d = self.j('POST', '/adm/api/doctor', {})
        self.assertEqual(st, 200, d)
        r = d['results'][0]
        self.assertEqual((r['name'], r['detail'], r['orig'], r['ok']), ('内存', '已用 95%', '95% used', False))


class InviteNote(tu.Base):
    """2: the note an invited sign-up gets"""
    def _register(self, lang):
        db.set_settings(language=lang, member_enabled=True)
        rec = members.create_invite('admin', 10, 7, max_uses=1, note='同事')
        uid = members.register(rec['code'], 'new' + lang, 'goodpassword')
        return rec['code'], db.user(uid)['note']

    def test_language(self):
        code, note = self._register('zh')
        self.assertEqual(note, '邀请码 %s · 同事' % code)
        code, note = self._register('en')
        self.assertEqual(note, 'invite %s · 同事' % code)

    def test_old_notes_are_shown_in_chinese(self):
        self.assertIn("n.replace(/^invite ([A-Z0-9-]+)/, '邀请码 $1')", _static('app.js'))


class PageSource(unittest.TestCase):
    def test_server_rows(self):
        app, css = _static('app.js'), _static('style.css')
        self.assertNotIn('slice(0, 60)', app)                           # 2: not cut at 60 characters
        self.assertIn("x.error ? srvErr(x.error) : null", app)
        self.assertIn("chip('bad', t('sync_failed'))", app)
        acts = re.search(r'\.tl-acts\{[^}]*\}', css).group(0)          # 1: the buttons wrap
        self.assertIn('flex-wrap:wrap', acts)
        self.assertIn('max-width:100%', acts)
        self.assertIn('-webkit-line-clamp:2', css)

    def test_inputs_and_drawer(self):
        css = _static('style.css')
        rule = css[css.index('.input,input[type=text]'):css.index('{', css.index('.input,input[type=text]'))]
        for t in ('url', 'datetime-local', 'tel', 'time'):                # 3
            self.assertIn('input[type=%s]' % t, rule)
        drawer = re.search(r'\.drawer\{[^}]*\}', css).group(0)          # 6
        self.assertNotIn('translateX(102%)', drawer)
        self.assertIn('translateX(calc(100% + 100px))', drawer)

    def test_member_page(self):
        js = _static('member.js')
        sign_in = js[js.index('form.onsubmit = async e =>'):]
        self.assertLess(sign_in.index("M.hello = await api('hello')"), sign_in.index('await renderHome()'))   # 4
        self.assertIn('failPage(e.message, renderHome)', js)              # 5
        self.assertIn('failPage(e.message, boot)', js)
        self.assertNotIn("h('div', {class: 'empty'}, e.message)", js)
        self.assertIn("t('retry')", js)

    @unittest.skipUnless(shutil.which('node'), 'needs node')
    def test_sync_errors_in_chinese(self):
        kit = _static('kit.js')
        code = kit[kit.index('const KT_ZH'):kit.index('\n', kit.index('function errText'))]
        msgs = ['certificate changed and is not publicly trusted (UNEXPECTED_EOF); remove and re-add the server',
                'URLError: <urlopen error timed out>', 'ConnectionRefusedError: [Errno 111] Connection refused',
                'node sync refused: unknown endpoint', 'node answered 502: bad gateway', 'something brand new']
        script = code + '\nKT = KT_ZH; process.stdout.write(JSON.stringify(%s.map(errText)));' % json.dumps(msgs)
        res = subprocess.run(['node', '-e', script], capture_output=True, text=True, encoding='utf-8', timeout=60)
        self.assertEqual(res.returncode, 0, res.stderr)
        out = json.loads(res.stdout)
        self.assertTrue(out[0].startswith('这台服务器的证书变了，而且不是公开信任的证书'), out[0])
        self.assertEqual(out[1], '连接这台服务器超时')
        self.assertIn('拒绝连接', out[2])
        self.assertIn('这个功能不可用', out[3])
        self.assertTrue(out[4].startswith('这台服务器返回错误 502'))
        self.assertEqual(out[5], 'something brand new')       # the row then says "sync failed" and keeps this on hover


if __name__ == '__main__':
    unittest.main()
