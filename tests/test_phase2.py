"""Phase 2 server API for the vps2vpn app (docs/phase2-api.md), one part per release.

0.2.42  server status (section 3): maintenance / congested per server, sent in api/me "nodes"
0.2.43  a server in maintenance is left out of "Auto" in every subscription format (logic review C-19);
        one-tap feedback (section 1)
"""
import base64
import datetime as dt
import json
import os
import threading
import time
import unittest
from unittest import mock

from tests import test_unit as tu          # sets VPS2VPN_ROOT / dev mode first
from vps2vpn import certs, clock, cluster, db, feedback, jobs, nodestatus, notify, secure, subscription, web

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

    def _formats(self):
        s, u = db.settings(), db.user(self.uid)
        return (subscription.clash(s, u, 'https://192.0.2.1:1'), subscription.singbox(s, u, 'https://192.0.2.1:1'),
                subscription.links_base64(s, u))

    def test_congested_changes_no_subscription(self):
        before = self._formats()
        db.set_settings(client_node_status=True)
        nodestatus.set_status('main', {'state': 'congested', 'note': 'x'})
        nodestatus.set_status(SID, {'state': 'congested'})
        self.assertEqual(before, self._formats())

    def _auto(self):
        """(Clash auto, sing-box auto, Shadowrocket auto line, Clash AI group, Clash entry names)"""
        s, u = db.settings(), db.user(self.uid)
        g = subscription.names(s)
        clash = subscription.clash(s, u, 'https://192.0.2.1:1')
        auto = next(x for x in clash['proxy-groups'] if x['name'] == g['auto'])['proxies']
        ai = next(x for x in clash['proxy-groups'] if x['name'] == g['ai'])['proxies']
        sb = subscription.singbox(s, u, 'https://192.0.2.1:1')
        sb_auto = next(o for o in sb['outbounds'] if o['tag'] == g['auto'])['outbounds']
        sr = subscription.shadowrocket(s, u, 'https://192.0.2.1:1')
        sr_auto = next(line for line in sr.splitlines() if line.startswith(g['auto'] + ' = url-test'))
        return auto, sb_auto, sr_auto, ai, [p['name'] for p in clash['proxies']]

    def test_maintenance_leaves_auto_in_every_format(self):
        db.set_settings(client_node_status=True)
        auto, sb_auto, sr_auto, ai, names = self._auto()
        self.assertEqual(auto, ['Tokyo', 'Osaka'])
        nodestatus.set_status(SID, {'state': 'maintenance', 'note': '换机房'})
        auto, sb_auto, sr_auto, ai, names2 = self._auto()
        self.assertEqual(auto, ['Tokyo'])
        self.assertFalse([t for t in sb_auto if t.startswith('Osaka')])
        self.assertTrue([t for t in sb_auto if t.startswith('Tokyo')])
        self.assertNotIn('Osaka', sr_auto)
        self.assertEqual(names2, names)                                   # names never change: the app matches them
        self.assertEqual(ai[:2], ['Tokyo', 'Osaka'])                       # AI group: the one in maintenance last
        # until it is over
        st = db.settings()['servers']
        st[0]['status']['until'] = int(time.time()) - 1
        db.set_settings(servers=st)
        self.assertEqual(self._auto()[0], ['Tokyo', 'Osaka'])

    def test_maintenance_only_when_announced_and_never_an_empty_auto(self):
        nodestatus.set_status('main', {'state': 'maintenance'})
        self.assertEqual(self._auto()[0], ['Tokyo', 'Osaka'])            # switch off: subscriptions as before
        db.set_settings(client_node_status=True)
        self.assertEqual(self._auto()[0], ['Osaka'])
        nodestatus.set_status(SID, {'state': 'maintenance'})
        self.assertEqual(self._auto()[0], ['Tokyo', 'Osaka'])            # all in maintenance: all of them

    def test_maintenance_and_rates_together(self):
        db.set_settings(client_node_status=True)
        st = db.settings()['servers']
        st[0]['rate'] = 5
        db.set_settings(servers=st)
        self.assertEqual(self._auto()[0], ['Tokyo'])                     # the x5 one is left out (L-10)
        nodestatus.set_status('main', {'state': 'maintenance'})
        self.assertEqual(self._auto()[0], ['Osaka ×5'])                  # better a x5 server than one going away

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



APP = {'version': '1.0.29', 'platform': 'windows', 'os': 'Windows 11 23H2', 'core': 'mihomo 1.19.34'}


class FeedbackValues(tu.Base):
    def setUp(self):
        super().setUp()
        self.uid = db.add_user('ann', 10)
        self.u = db.user(self.uid)

    def test_ip_addresses_are_masked(self):
        m = feedback.mask_ips
        self.assertEqual(m('to 203.0.113.7:443 failed'), 'to 203.0.x.x:443 failed')
        self.assertEqual(m('[2001:db8::1]:443 and fe80::1%eth0'), '[2001:db8:x:x:...]:443 and fe80::x:x:...%eth0')
        for keep in ('at 12:30:45', 'mihomo 1.19.34', 'v 192.0.2.4.5', '999.0.2.1', 'aa:bb:cc:dd:ee:ff'):
            self.assertEqual(m(keep), keep)

    def test_secrets_and_addresses_never_reach_the_database(self):
        u = self.u
        fid = feedback.add(u, {'text': 'my link /s/%s fails from 198.51.100.23' % u['sub_token'],
                               'diagnosis': {'steps': [{'id': 'dns', 'ok': False, 'detail': 'server 203.0.113.9'}],
                                             u['uuid']: 'key'},
                               'log': 'uuid=%s pass=%s ip 2001:db8:1:2::5' % (u['uuid'], u['hy2_pass']),
                               'client': APP})
        raw = json.dumps([dict(r) for r in db.q('SELECT * FROM feedback')], ensure_ascii=False)
        for secret in (u['sub_token'], u['uuid'], u['hy2_pass'], '198.51.100.23', '203.0.113.9', '2001:db8:1:2::5'):
            self.assertNotIn(secret, raw)
        row = feedback.admin_get(fid)
        self.assertIn('/s/<hidden> fails from 198.51.x.x', row['text'])
        self.assertEqual(row['diagnosis']['steps'][0]['detail'], 'server 203.0.x.x')
        self.assertIn('<hidden>', row['diagnosis'])
        self.assertEqual(row['client'], APP)
        self.assertEqual(row['name'], 'ann')

    def test_what_is_refused(self):
        def refused(d, code='bad_request'):
            with self.assertRaises(feedback.Refused) as cm:
                feedback.clean(d, self.u)
            self.assertEqual(cm.exception.code, code, d)
        refused({'text': 'x'})                                                     # no client
        refused({'text': 'x', 'client': {'platform': 'symbian'}})
        refused({'text': 'x', 'client': dict(APP, version='v' * 65)})
        refused({'text': 'x', 'client': dict(APP, version=3)})
        refused({'client': APP})                                                   # nothing to say
        refused({'text': '   ', 'client': APP})
        refused({'text': 'x' * 1001, 'client': APP})
        refused({'text': 'x', 'diagnosis': [1], 'client': APP})
        refused({'diagnosis': {'a': 'x' * (33 << 10)}, 'client': APP}, 'too_large')
        refused({'log': 'x' * (65 << 10), 'client': APP}, 'too_large')
        refused({'text': 'x', 'device_id': 'ABC', 'client': APP})
        ok = feedback.clean({'text': 'a\x00b\nc', 'device_id': '3f2c9a1e-7b1d-4c3e-9a55-0d1e2f3a4b5c',
                             'client': {'platform': 'web', 'version': 'web'}}, self.u)
        self.assertEqual(ok['text'], 'ab\nc')                                       # control characters gone, newline kept

    def test_how_often(self):
        now = 1_800_000_000
        feedback.add(self.u, {'text': '1', 'client': APP}, now)
        with self.assertRaises(feedback.Refused) as cm:
            feedback.add(self.u, {'text': '2', 'client': APP}, now + 60)
        self.assertEqual((cm.exception.code, cm.exception.status, cm.exception.retry), ('rate_limited', 429, 60))
        for i in range(1, 5):
            feedback.add(self.u, {'text': str(i), 'client': APP}, now + i * 200)
        with self.assertRaises(feedback.Refused) as cm:
            feedback.add(self.u, {'text': 'six', 'client': APP}, now + 5 * 200)
        self.assertEqual(cm.exception.retry, 86400 - 5 * 200)                     # when the first one leaves the day
        feedback.add(self.u, {'text': 'next day', 'client': APP}, now + 86400)
        other = db.user(db.add_user('bob'))
        feedback.add(other, {'text': 'mine', 'client': APP}, now + 60)               # per account

    def test_how_many_are_kept(self):
        now = 1_800_000_000
        for i in range(23):
            feedback.add(self.u, {'text': str(i), 'client': APP}, now + i * 90000)
        texts = [r['text'] for r in db.q('SELECT text FROM feedback ORDER BY id')]
        self.assertEqual(texts, [str(i) for i in range(3, 23)])                     # the newest 20
        other = db.user(db.add_user('bob'))
        with mock.patch.object(feedback, 'TOTAL_KEEP', 5):
            feedback.add(other, {'text': 'b', 'client': APP}, now + 30 * 90000)
        self.assertEqual(db.q('SELECT COUNT(*) FROM feedback')[0][0], 5)
        feedback.prune(now + 23 * 90000 + 31 * 86400)
        self.assertEqual(db.q('SELECT COUNT(*) FROM feedback')[0][0], 1)              # 30 days
        self.assertIn("self.due('feedback', 86400)", __import__('inspect').getsource(jobs))

    def test_answers_and_unread(self):
        fid = feedback.add(self.u, {'text': 'slow', 'client': APP})
        self.assertEqual((feedback.unread(self.uid), feedback.open_count()), (0, 1))
        self.assertTrue(feedback.admin_act(fid, 'answer', '换了线路，再试一下'))
        self.assertEqual((feedback.unread(self.uid), feedback.open_count()), (1, 0))
        items = feedback.for_member(self.uid)
        self.assertEqual((items[0]['answer'], items[0]['status']), ('换了线路，再试一下', 'done'))
        self.assertNotIn('log', items[0])
        self.assertEqual(feedback.unread(self.uid), 0)                                 # read now
        self.assertTrue(feedback.admin_act(fid, 'reopen'))
        self.assertEqual(feedback.open_count(), 1)
        with self.assertRaises(feedback.Refused):
            feedback.admin_act(fid, 'answer', 'x' * 501)
        with self.assertRaises(feedback.Refused):
            feedback.admin_act(fid, 'answer', '  ')
        self.assertFalse(feedback.admin_act(fid + 1, 'done'))
        self.assertTrue(feedback.admin_act(fid, 'delete'))
        self.assertEqual(feedback.admin_list(), [])

    def test_not_in_backups_and_gone_with_the_account(self):
        feedback.add(self.u, {'text': 'hello', 'client': APP})
        data = db.export_all()
        self.assertNotIn('feedback', json.dumps(list(data)))
        self.assertNotIn('hello', json.dumps(data, ensure_ascii=False))
        db.import_all(data)
        self.assertEqual(db.q('SELECT COUNT(*) FROM feedback')[0][0], 0)              # a restore brings none back
        uid = db.add_user('cat')
        feedback.add(db.user(uid), {'text': 'bye', 'client': APP})
        db.delete_user(uid)
        self.assertEqual(db.q('SELECT COUNT(*) FROM feedback')[0][0], 0)


class FeedbackOverHttps(OverHttps):
    def setUp(self):
        super().setUp()
        self.fb = '/s/%s/api/feedback' % db.user(self.uid)['sub_token']
        self.sent = []
        self._send = mock.patch.object(notify, 'send', lambda text, **k: self.sent.append((text, k.get('key'))))
        self._send.start()

    def tearDown(self):
        self._send.stop()
        super().tearDown()

    def test_off_until_the_admin_turns_it_on(self):
        st, d = self.j('POST', self.fb, {'text': 'x', 'client': APP})
        self.assertEqual((st, d['code']), (503, 'feature_off'))
        st, d = self.j('GET', self.me)
        self.assertIs(d['features']['feedback'], False)
        self.assertNotIn('feedback_unread', d)

    def test_send_answer_read(self):
        db.set_settings(client_feedback=True)
        st, d = self.j('POST', self.fb, {'text': 'YouTube 打不开', 'client': APP, 'diagnosis': {'steps': []}})
        self.assertEqual(st, 200, d)
        fid = d['id']
        self.assertEqual(self.sent[-1][1], 'fb-%d' % self.uid)
        self.assertIn('YouTube 打不开', self.sent[-1][0])
        st, d = self.j('POST', self.fb, {'text': 'again', 'client': APP})
        self.assertEqual((st, d['code']), (429, 'rate_limited'))
        st, _, r = self.req('POST', self.fb, {'text': 'again', 'client': APP})
        self.assertTrue(1 <= int(r.getheader('Retry-After')) <= 120)
        st, d = self.j('POST', self.fb, {'text': 'x', 'client': {'platform': 'nokia'}})
        self.assertEqual((st, d['code']), (400, 'bad_request'))
        st, _, _ = self.req('POST', self.fb, {'text': 'x', 'client': APP}, headers={'X-V2V': ''})
        self.assertEqual(st, 403)                                                     # the same header as other POSTs
        # the admin
        st, _ = self.j('POST', '/adm/api/login', {'username': 'admin', 'password': 'adminpassword'})
        st, d = self.j('GET', '/adm/api/feedback')
        self.assertEqual((st, [x['id'] for x in d['items']], d['items'][0]['client']['platform']), (200, [fid], 'windows'))
        st, d = self.j('GET', '/adm/api/state')
        self.assertEqual(d['open_feedback'], 1)
        st, d = self.j('GET', '/adm/api/feedback/%d' % fid)
        self.assertEqual((st, d['text']), (200, 'YouTube 打不开'))
        st, d = self.j('POST', '/adm/api/feedback/%d/answer' % fid, {'answer': '已经换了线路'})
        self.assertEqual(st, 200, d)
        st, d = self.j('POST', '/adm/api/feedback/999/done', {})
        self.assertEqual(st, 404)
        self.cookie = ''
        st, d = self.j('GET', self.me)
        self.assertEqual((d['features']['feedback'], d['feedback_unread']), (True, 1))
        st, d = self.j('GET', self.fb)
        self.assertEqual((st, d['items'][0]['answer'], d['items'][0]['status']), (200, '已经换了线路', 'done'))
        st, d = self.j('GET', self.me)
        self.assertEqual(d['feedback_unread'], 0)

    def test_size_and_entry_points(self):
        db.set_settings(client_feedback=True)
        st, d = self.j('POST', self.fb, {'log': 'x' * (130 << 10), 'client': APP})
        self.assertEqual((st, d['code']), (413, 'too_large'))
        st, d = self.j('POST', '/mem/api/feedback', {'text': 'x', 'client': {'platform': 'web', 'version': 'web'}})
        self.assertEqual((st, d['code']), (401, 'login_required'))
        st, _ = self.j('POST', '/mem/api/login', {'name': 'tia', 'password': 'tiapassword'})
        st, d = self.j('POST', '/mem/api/feedback', {'text': '网页上发的', 'client': {'platform': 'web', 'version': 'web'}})
        self.assertEqual(st, 200, d)
        st, _, _ = self.req('GET', '/s/wrong-token-0000000000/api/feedback')     # the plain 404 page, not JSON
        self.assertEqual(st, 404)

    def test_admin_only(self):
        st, _ = self.j('GET', '/adm/api/feedback')
        self.assertIn(st, (401, 403))


class FeedbackPages(unittest.TestCase):
    def test_panel_and_member_page(self):
        js = _static('app.js')
        self.assertEqual(js.count("client_feedback: '"), 2)
        self.assertIn("api(`feedback/${x.id}/${a}`", js)
        self.assertIn('S.data.open_feedback', js)
        m = _static('member.js')
        self.assertIn("me.features.feedback) blocks.push(feedbackPanel())", m)
        self.assertIn("client: {platform: 'web', version: 'web'}", m)


if __name__ == '__main__':
    unittest.main()
