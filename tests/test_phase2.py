"""Phase 2 server API for the vps2vpn app (docs/phase2-api.md), one part per release.

0.2.42  server status (section 3): maintenance / congested per server, sent in api/me "nodes"
"""
import base64
import datetime as dt
import json
import os
import threading
import time
import unittest

from tests import test_unit as tu          # sets VPS2VPN_ROOT / dev mode first
from vps2vpn import certs, clock, cluster, db, nodestatus, secure, subscription, web

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SID = 'a1b2c3d4'
UTC8 = dt.timezone(dt.timedelta(hours=8))


def _static(name):
    with open(os.path.join(ROOT, 'vps2vpn', 'static', name), encoding='utf-8') as f:
        return f.read()


def _with_joined(uid, name='Osaka'):
    info = cluster.public_info(dict(db.settings(), public_host='198.51.100.5', node_name=name))
    db.set_settings(node_name='Tokyo', servers=[{'id': SID, 'name': name, 'url': 'https://198.51.100.5:1/x', 'key': 'k',
                                                 'pin': '', 'enabled': True, 'info': info, 'idmap': {str(uid): 42}}])


class StatusValues(tu.Base):
    def test_clean(self):
        now = int(time.time())
        self.assertEqual(nodestatus.clean({'state': 'ok', 'note': 'ignored', 'until': now + 60}), nodestatus.OK)
        st = nodestatus.clean({'state': 'maintenance', 'note': ' 今晚\n换机房​ ', 'until': now + 3600}, now)
        self.assertEqual(st, {'state': 'maintenance', 'note': '今晚 换机房', 'until': now + 3600})
        self.assertEqual(len(nodestatus.clean({'state': 'congested', 'note': 'x' * 300})['note']), 100)
        self.assertEqual(nodestatus.clean({'state': 'congested'})['until'], 0)              # until changed by hand
        for bad in ({'state': 'down'}, {'state': 'maintenance', 'note': 5}, {'state': 'maintenance', 'until': now - 1},
                    {'state': 'maintenance', 'until': now + 400 * 86400}, {'state': 'maintenance', 'until': '1795012200'},
                    {'state': 'maintenance', 'until': True}, {'state': 'maintenance', 'until_local': '31/12/2026 23:00'},
                    {'state': 'maintenance', 'until_local': '2026-02-30T10:00'}, 'maintenance'):
            with self.assertRaises(ValueError, msg=bad):
                nodestatus.clean(bad, now)

    def test_until_is_in_the_panels_time_zone(self):
        db.set_settings(time_zone='UTC+8')
        clock.forget()
        try:
            self.assertEqual(nodestatus.until_of('2027-01-02T23:30'),
                             int(dt.datetime(2027, 1, 2, 23, 30, tzinfo=UTC8).timestamp()))
            self.assertEqual(nodestatus.until_of('2027-01-02 23:30'), nodestatus.until_of('2027-01-02T23:30'))
            st = {'state': 'maintenance', 'note': '', 'until': nodestatus.until_of('2027-01-02T23:30')}
            self.assertEqual(nodestatus.view(st)['until_local'], '2027-01-02T23:30')
        finally:
            db.set_settings(time_zone='')
            clock.forget()

    def test_past_its_end_or_unreadable_is_ok(self):
        now = int(time.time())
        self.assertEqual(nodestatus.current({'state': 'maintenance', 'note': 'x', 'until': now - 1}), nodestatus.OK)
        self.assertEqual(nodestatus.current({'state': 'maintenance', 'note': 'x', 'until': now + 60})['state'], 'maintenance')
        for junk in (None, [], 'maintenance', {'state': 'broken'}, {'state': 'maintenance', 'until': 'soon'},
                     {'state': 'maintenance', 'until': -5}):
            self.assertEqual(nodestatus.current(junk), nodestatus.OK, junk)       # a hand-edited backup
        self.assertEqual(nodestatus.current({'state': 'congested', 'note': None})['note'], '')

    def test_joined_server_keeps_its_status_through_panel_edits(self):
        uid = db.add_user('m')
        _with_joined(uid)
        nodestatus.set_status(SID, {'state': 'congested', 'note': '晚高峰'})
        cluster.update_server(SID, rate=2, name='Osaka')
        self.assertEqual(nodestatus.of(db.settings(), SID)['state'], 'congested')
        with self.assertRaises(LookupError):
            nodestatus.set_status('ffffffff', {'state': 'congested'})
        nodestatus.set_status('main', {'state': 'maintenance'})
        self.assertEqual(db.settings()['node_status']['state'], 'maintenance')


class NodesForTheApp(tu.Base):
    def setUp(self):
        super().setUp()
        self.uid = db.add_user('member', 50)
        _with_joined(self.uid)

    def test_names_match_the_subscription(self):
        s, u = db.settings(), db.user(self.uid)
        nodestatus.set_status(SID, {'state': 'maintenance', 'note': '换机房'})
        nodes = nodestatus.for_member(db.settings(), u)
        self.assertEqual([n['id'] for n in nodes], ['main', SID])
        self.assertEqual([n['state'] for n in nodes], ['ok', 'maintenance'])
        self.assertEqual(nodes[1]['note'], '换机房')
        clash = subscription.clash(s, u, 'https://192.0.2.1:1')
        proxies = [p['name'] for p in clash['proxies']]
        self.assertEqual([x for n in nodes for x in n['names']], proxies)        # same names, same order
        groups = [g['name'] for g in clash['proxy-groups']]
        for n in nodes:
            self.assertIn(n['group'], groups)                                     # each server's own group
        sb = subscription.singbox(s, u, 'https://192.0.2.1:1')
        tags = {o['tag'] for o in sb['outbounds']}
        self.assertTrue(all(x in tags for n in nodes for x in n['names']))

    def test_only_servers_the_account_gets(self):
        db.update_user(self.uid, servers=SID)
        self.assertEqual([n['id'] for n in nodestatus.for_member(db.settings(), db.user(self.uid))], [SID])
        db.update_user(self.uid, servers='main')
        self.assertEqual([n['id'] for n in nodestatus.for_member(db.settings(), db.user(self.uid))], ['main'])

    def test_the_subscription_itself_does_not_change(self):
        s, u = db.settings(), db.user(self.uid)
        before = (subscription.clash(s, u, 'https://192.0.2.1:1'), subscription.singbox(s, u, 'https://192.0.2.1:1'),
                  subscription.links_base64(s, u))
        db.set_settings(client_node_status=True)
        nodestatus.set_status('main', {'state': 'maintenance', 'note': 'x'})
        nodestatus.set_status(SID, {'state': 'congested'})
        s = db.settings()
        after = (subscription.clash(s, u, 'https://192.0.2.1:1'), subscription.singbox(s, u, 'https://192.0.2.1:1'),
                 subscription.links_base64(s, u))
        self.assertEqual(before, after)

    def _announce(self):
        _, _, headers = subscription.render('clash', db.settings(), db.user(self.uid), 'https://192.0.2.1:1')
        a = headers.get('Announce', '')
        return base64.b64decode(a[7:]).decode() if a.startswith('base64:') else a

    def test_maintenance_in_the_announce_header(self):
        nodestatus.set_status(SID, {'state': 'maintenance', 'note': '今晚 23:00 换机房'})
        self.assertEqual(self._announce(), '')                        # switch off: nothing is announced
        db.set_settings(client_node_status=True)
        self.assertIn('Osaka：今晚 23:00 换机房', self._announce())
        nodestatus.set_status(SID, {'state': 'congested', 'note': 'busy'})
        self.assertEqual(self._announce(), '')                        # congested: the app only
        nodestatus.set_status(SID, {'state': 'maintenance'})
        db.update_user(self.uid, servers='main')
        self.assertEqual(self._announce(), '')                        # not one of this account's servers
        db.update_user(self.uid, servers='', expire_at=int(time.time()) + 86400)
        self.assertNotIn('Osaka', self._announce())                   # the account's own warning comes first


class OverHttps(tu.Base):
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
        self.uid = db.add_user('tia', 20)
        db.update_user(self.uid, login_hash=secure.hash_password('tiapassword'))
        _with_joined(self.uid)
        self.me = '/s/%s/api/me' % db.user(self.uid)['sub_token']

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

    def test_off_by_default_no_nodes(self):
        self.assertIs(db.settings()['client_node_status'], False)
        st, d = self.j('GET', self.me)
        self.assertEqual(st, 200)
        self.assertIs(d['features']['node_status'], False)
        self.assertNotIn('nodes', d)

    def test_admin_marks_a_server_and_the_app_sees_it(self):
        st, d = self.j('POST', '/adm/api/login', {'username': 'admin', 'password': 'adminpassword'})
        self.assertEqual(st, 200)
        st, d = self.j('POST', '/adm/api/settings', {'client_node_status': True})
        self.assertEqual(st, 200, d)
        st, d = self.j('POST', '/adm/api/node-status', {'id': SID, 'state': 'maintenance', 'note': '换机房', 'until_local': ''})
        self.assertEqual(st, 200, d)
        self.assertEqual([(x['id'], x['state']) for x in d['servers']], [('main', 'ok'), (SID, 'maintenance')])
        self.assertIs(d['on'], True)
        st, d = self.j('POST', '/adm/api/node-status', {'id': SID, 'state': 'gone'})
        self.assertEqual(st, 400)
        self.assertIn('state must be', d['error'])
        st, d = self.j('POST', '/adm/api/node-status', {'id': 'ffffffff', 'state': 'ok'})
        self.assertEqual(st, 404)
        st, d = self.j('GET', '/adm/api/node-status')
        self.assertEqual((st, len(d['servers'])), (200, 2))
        self.cookie = ''
        st, d = self.j('GET', self.me)
        self.assertEqual(st, 200)
        self.assertIs(d['features']['node_status'], True)
        self.assertEqual([(n['id'], n['state'], n['note']) for n in d['nodes']], [('main', 'ok', ''), (SID, 'maintenance', '换机房')])
        self.assertEqual(d['nodes'][1]['group'], 'Osaka')
        # the member centre gets the same
        st, _ = self.j('POST', '/mem/api/login', {'name': 'tia', 'password': 'tiapassword'})
        self.assertEqual(st, 200)
        st, d = self.j('GET', '/mem/api/me')
        self.assertEqual((st, d['nodes'][1]['state']), (200, 'maintenance'))

    def test_admin_only(self):
        st, _ = self.j('POST', '/adm/api/node-status', {'id': 'main', 'state': 'maintenance'})
        self.assertIn(st, (401, 403))
        self.assertEqual(nodestatus.of(db.settings(), 'main'), nodestatus.OK)


class Pages(unittest.TestCase):
    def test_panel_and_member_page(self):
        js = _static('app.js')
        self.assertEqual(js.count("client_node_status: '"), 2)
        self.assertEqual(js.count("node_status_tip: '"), 2)
        self.assertIn("api('node-status', {id: x.id", js)
        self.assertIn("saveSettings({client_node_status: e.checked}", js)
        m = _static('member.js')
        self.assertIn('me.nodes ||', m)
        self.assertEqual(m.count("node_maint: '"), 2)


if __name__ == '__main__':
    unittest.main()
