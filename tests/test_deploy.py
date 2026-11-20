"""Tests for the one-click path: setup without the web wizard, what the deployer remembers, the firewall
check from the outside, and adding a second server to the first through the panel API.

    python -m unittest tests.test_deploy
"""
import json
import os
import shutil
import socket
import sys
import tempfile
import threading
import unittest
import urllib.parse

from tests import test_unit as tu          # sets VPS2VPN_ROOT / dev mode first
from vps2vpn import __main__ as cli, cluster, db, secure, web

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'deploy'))
import deploy  # noqa: E402


class QuickSetup(tu.Base):
    def test_finishes_setup_and_returns_login(self):
        open(web.SETUP_TOKEN_FILE, 'w').write('tok')
        a = cli.quick_setup()
        s = db.settings()
        self.assertTrue(s['setup_done'])
        self.assertEqual(a['admin_user'], 'admin')
        self.assertGreaterEqual(len(a['admin_password']), 12)
        self.assertTrue(secure.check_password(a['admin_password'], s['admin_hash']))
        self.assertEqual([u['name'] for u in db.users()], ['我'])
        self.assertFalse(os.path.exists(web.SETUP_TOKEN_FILE))        # the setup link stops working

    def test_result_info(self):
        cli.quick_setup()
        info = cli.result_info(db.settings())
        u = db.users()[0]
        self.assertTrue(info['sub_url'].endswith('/s/' + u['sub_token']))
        self.assertTrue(info['qr_url'].endswith('/qr.svg'))
        self.assertTrue(info['links']['clash'].startswith('clash://install-config?url='))
        self.assertEqual(len(info['pin']), 64)
        self.assertEqual(cluster.parse_join_code(info['join_code'])['key'], db.settings()['node_key'])
        names = [c[2] for c in info['checks']]
        self.assertEqual(names[0], '管理面板')
        self.assertEqual([c[0] for c in info['checks']], ['tcp', 'tcp', 'udp', 'udp'])
        self.assertNotIn('admin_password', info)


class Records(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self._old = deploy.RECORDS
        deploy.RECORDS = self.dir

    def tearDown(self):
        deploy.RECORDS = self._old
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_upgrade_keeps_saved_password(self):
        job = {'host': '203.0.113.9', 'user': 'root', 'port': 22}
        first = {'auto': {'admin_user': 'admin', 'admin_password': 'secret-1', 'panel': 'https://a/p/', 'join_code': 'v2v1.a'}}
        deploy.save_record(job['host'], deploy.merge_record(job, first))
        later = {'auto': {'panel': 'https://a/p/', 'join_code': 'v2v1.b'}, 'cloud': 'AWS Lightsail'}
        rec = deploy.merge_record(job, later)
        self.assertEqual(rec['admin_password'], 'secret-1')
        self.assertEqual(rec['join_code'], 'v2v1.b')
        p = deploy.save_record(job['host'], rec)
        self.assertEqual(deploy.load_records()[0]['host'], '203.0.113.9')
        if os.name != 'nt':
            self.assertEqual(os.stat(p).st_mode & 0o077, 0)


class PortCheck(unittest.TestCase):
    def test_tcp_and_quic_probe(self):
        srv = socket.socket()
        srv.bind(('127.0.0.1', 0))
        srv.listen(1)
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.bind(('127.0.0.1', 0))
        seen = []

        def answer():               # what a QUIC server does with an unknown version
            d, addr = udp.recvfrom(2048)
            seen.append(len(d))
            udp.sendto(bytes([0x80]) + b'\0\0\0\0' + d[5:23] + b'\0\0\0\1', addr)
        threading.Thread(target=answer, daemon=True).start()
        try:
            out = deploy.check_ports('127.0.0.1', [['tcp', srv.getsockname()[1], 'panel'],
                                                   ['udp', udp.getsockname()[1], 'hy2']], tries=1)
            self.assertEqual([c['ok'] for c in out], [True, True])
            self.assertEqual(seen, [1200])               # QUIC needs a full-size first packet
            closed = socket.socket()
            closed.bind(('127.0.0.1', 0))
            port = closed.getsockname()[1]
            closed.close()
            self.assertFalse(deploy.tcp_open('127.0.0.1', port, timeout=2))
        finally:
            srv.close()
            udp.close()


class JoinMain(tu.Base):
    """The deployer logs in to the first server's panel (pinned certificate) and adds the second one."""
    def test_login_and_add(self):
        a = cli.quick_setup()
        s = db.settings()
        srv = web.Server(('127.0.0.1', 0), web.Handler, web.TLSContext())
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            port = srv.server_address[1]
            rec = cli.result_info(s)
            main = {'panel': 'https://127.0.0.1:%d/%s/' % (port, s['panel_path']), 'pin': rec['pin'],
                    'admin_user': 'admin', 'admin_password': a['admin_password']}
            added = []
            orig = cluster.add_server
            cluster.add_server = lambda code, name='': added.append((code, name)) or {'id': 'x', 'name': name}
            try:
                self.assertEqual(deploy.join_main(main, {'join_code': 'v2v1.code'}, '198.51.100.7'), 'ok')
            finally:
                cluster.add_server = orig
            self.assertEqual(added, [('v2v1.code', '198.51.100.7')])
            with self.assertRaises(deploy.PanelError):
                deploy.join_main(dict(main, pin='00' * 32), {'join_code': 'x'}, 'y')     # someone else's certificate
            with self.assertRaises(deploy.PanelError):
                deploy.join_main(dict(main, admin_password='wrong-one'), {'join_code': 'x'}, 'y')
        finally:
            srv.shutdown()
            srv.server_close()


if __name__ == '__main__':
    unittest.main()


class AICheck(tu.Base):
    """The AI availability check, with the network replaced by canned answers."""
    def fake(self, answers):
        from vps2vpn import aicheck
        orig = aicheck._req

        def req(url, method='GET', data=None, headers=None, timeout=12):
            for key, ans in answers.items():
                if key in url:
                    return ans
            return 0, {}, b'', url
        aicheck._req = req
        self.addCleanup(setattr, aicheck, '_req', orig)

    US_OK = {
        'cdn-cgi/trace': (200, {}, b'ip=1.2.3.4\nloc=US\n', ''),
        'ipinfo.io': (200, {}, json.dumps({'country': 'US', 'city': 'Seattle', 'org': 'AS16509 Amazon'}).encode(), ''),
        'ip-api.com': (200, {}, json.dumps({'status': 'success', 'countryCode': 'US', 'hosting': True}).encode(), ''),
        'claude.ai/': (403, {'cf-mitigated': 'challenge'}, b'Just a moment', 'https://claude.ai/'),
        'api.anthropic.com': (401, {}, b'{"type":"error","error":{"type":"authentication_error"}}', ''),
        'api.openai.com': (200, {}, b'{"cookie_requirements":"none"}', ''),
        'gemini.google.com': (200, {}, b'<html>', ''),
    }

    def test_all_usable(self):
        from vps2vpn import aicheck
        self.fake(self.US_OK)
        res = aicheck.run()
        self.assertEqual(res['country'], 'US')
        self.assertEqual({k: v['status'] for k, v in res['sites'].items()},
                         {'claude': 'ok', 'claude_api': 'ok', 'chatgpt': 'ok', 'gemini': 'ok'})
        self.assertIn('人机验证', res['sites']['claude']['note'])
        self.assertEqual(aicheck.summary(res), 'Claude ✓  ChatGPT ✓  Gemini ✓')
        self.assertEqual(aicheck.score(res), 4)
        self.assertEqual(res['ip']['kind'], 'hosting')
        self.assertEqual(aicheck.place_name(res), '西雅图')
        self.assertEqual(aicheck.latest()['at'], res['at'])          # saved for the panel

    def test_blocked_region(self):
        from vps2vpn import aicheck
        ans = dict(self.US_OK)
        ans['cdn-cgi/trace'] = (200, {}, b'loc=HK\n', '')
        ans['claude.ai/'] = (200, {}, b'', 'https://claude.ai/app-unavailable-in-region')
        ans['api.anthropic.com'] = (403, {}, b'{"error":{"type":"forbidden","message":"Request not allowed"}}', '')
        ans['api.openai.com'] = (403, {}, b'{"error":{"code":"unsupported_country"}}', '')
        self.fake(ans)
        res = aicheck.run()
        self.assertEqual(res['sites']['claude']['status'], 'blocked')
        self.assertEqual(res['sites']['claude_api']['status'], 'blocked')
        self.assertEqual(res['sites']['chatgpt']['status'], 'blocked')
        self.assertEqual(res['sites']['gemini']['status'], 'blocked')
        self.assertEqual(aicheck.summary(res), 'Claude ✗  ChatGPT ✗  Gemini ✗')
        self.assertEqual(aicheck.score(res), 0)
        self.assertTrue(any('Claude' in a for a in res['advice']))

    def test_offline_and_changes(self):
        from vps2vpn import aicheck
        self.fake({})
        res = aicheck.run()
        self.assertEqual({v['status'] for v in res['sites'].values()}, {'unreachable'})
        self.fake(self.US_OK)
        new = aicheck.run()
        diff = aicheck.changed(res, new)
        self.assertEqual(len(diff), 4)
        self.assertEqual(aicheck.changed(new, new), [])
        self.assertEqual(aicheck.score(None), -1)
        self.assertEqual(aicheck.summary(None), '')

    def test_names_server_after_place(self):
        from vps2vpn import aicheck
        self.fake(self.US_OK)
        res = aicheck.run()
        cli.quick_setup(res)
        self.assertEqual(db.settings()['node_name'], '西雅图')
        brief = cli.ai_brief(res)
        self.assertEqual(brief['summary'], 'Claude ✓  ChatGPT ✓  Gemini ✓')
        self.assertEqual(brief['kind'], aicheck.KIND_TEXT['hosting'])

    def test_telegram_command(self):
        from vps2vpn import jobs
        self.fake(self.US_OK)
        out = jobs.tg_command('/ai')
        self.assertIn('Claude ✓', out)
        self.assertIn('/ai', jobs.tg_command('/help'))


class AIRouting(tu.Base):
    def test_ai_sites_go_to_ai_group_everywhere(self):
        from vps2vpn import subscription
        uid = db.add_user('erin')
        s, u = db.settings(), db.user(uid)
        c = subscription.clash(s, u, 'https://e.org')
        self.assertIn('DOMAIN-SUFFIX,claude.ai,AI服务', c['rules'])
        self.assertIn('DOMAIN-SUFFIX,anthropic.com,AI服务', c['rules'])
        sb = subscription.singbox(s, u, 'https://e.org')
        self.assertIn({'domain_suffix': ['claude.ai'], 'outbound': 'AI服务'}, sb['route']['rules'])
        sr = subscription.shadowrocket(s, u, 'https://e.org')
        self.assertIn('DOMAIN-SUFFIX,claude.ai,AI服务', sr)
        # turned off: no AI group, no AI lines
        c = subscription.clash(dict(s, ai_group=False), u, 'https://e.org')
        self.assertFalse(any('AI服务' in r for r in c['rules']))

    def test_best_ai_server_first(self):
        from vps2vpn import subscription
        ns = [{'group': 'Sydney', 'ai_score': 3}, {'group': 'HK', 'ai_score': 0}, {'group': 'Tokyo', 'ai_score': 4},
              {'group': 'Seattle', 'ai_score': 4}]
        per = [('Sydney', []), ('HK', []), ('Tokyo', []), ('Seattle', [])]
        self.assertEqual(subscription.ai_servers(ns, per), ['Tokyo', 'Seattle', 'Sydney', 'HK'])


class ServerNames(tu.Base):
    def test_same_city_gets_a_number(self):
        db.set_settings(node_name='悉尼', servers=[{'id': 'a1', 'name': '悉尼 2'}, {'id': 'b2', 'name': '东京'}])
        s = db.settings()
        self.assertEqual(cluster.unique_name('悉尼', s), '悉尼 3')
        self.assertEqual(cluster.unique_name('东京', s), '东京 2')
        self.assertEqual(cluster.unique_name('东京', s, skip='b2'), '东京')      # renaming a server to its own name
        self.assertEqual(cluster.unique_name('首尔', s), '首尔')
