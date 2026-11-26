"""Phase 2 server API for the vps2vpn app (docs/phase2-api.md), one part per release.

0.2.42  server status (section 3): maintenance / congested per server, sent in api/me "nodes"
0.2.43  a server in maintenance is left out of "Auto" in every subscription format (logic review C-19);
        one-tap feedback (section 1)
0.2.44  devices the app reports, soft and hard kick (section 2)
0.2.45  api/me config_version: the app notices a changed subscription at once (logic review O-10)
0.2.46  the member's view of all of it: a paused account, a new link, the limits a normal app meets
0.2.47  kick-others can be retried: same old link + same request_id -> the same new link for 10 minutes
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
from vps2vpn import certs, clock, cluster, cores, db, devices, feedback, jobs, nodestatus, notify, secure, subscription, web

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

    def test_until_uses_wall_time_across_daylight_saving_changes(self):
        try:
            from zoneinfo import ZoneInfo
            zone = ZoneInfo('America/New_York')
        except (ImportError, KeyError):
            self.skipTest('IANA time zones unavailable')
        with mock.patch.object(clock, 'zone', return_value=zone):
            for date in ((2027, 3, 14, 4, 30), (2027, 11, 7, 3, 30)):
                expected = dt.datetime(*date, tzinfo=zone)
                text = expected.strftime('%Y-%m-%dT%H:%M')
                self.assertEqual(nodestatus.until_of(text), int(expected.timestamp()))
                self.assertEqual(nodestatus.view({'state': 'maintenance', 'note': '',
                                                  'until': nodestatus.until_of(text)})['until_local'], text)

    def test_until_validates_and_preserves_optional_seconds(self):
        with mock.patch.object(clock, 'zone', return_value=UTC8):
            self.assertEqual(nodestatus.until_of('2027-01-02T23:30:45'),
                             int(dt.datetime(2027, 1, 2, 23, 30, 45, tzinfo=UTC8).timestamp()))
            with self.assertRaises(ValueError):
                nodestatus.until_of('2027-01-02T23:30:99')

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



DEV1 = '3f2c9a1e-7b1d-4c3e-9a55-0d1e2f3a4b5c'
DEV2 = '0b7e2a44-1c3d-4e5f-8a9b-0c1d2e3f4a5b'
PIXEL = {'device_id': DEV1, 'name': '小明的 Pixel 8', 'platform': 'android', 'version': '1.0.29'}


class DeviceValues(tu.Base):
    def setUp(self):
        super().setUp()
        self.uid = db.add_user('dan')
        self.u = db.user(self.uid)

    def test_report_list_revoke(self):
        now = 1_800_000_000
        self.assertFalse(devices.report(self.u, PIXEL, '198.51.100.23', now))
        # within a minute: answered, not stored (the version stays, last_seen too)
        self.assertFalse(devices.report(self.u, dict(PIXEL, version='9.9'), '198.51.100.23', now + 30))
        self.assertEqual((devices.listing(self.uid)[0]['version'], devices.listing(self.uid)[0]['last_seen']),
                         (PIXEL['version'], now))
        self.assertFalse(devices.report(self.u, dict(PIXEL, name='Pixel', version='1.0.30'), '2001:db8:1::9', now + 61))
        rows = devices.listing(self.uid, DEV1)
        self.assertEqual(len(rows), 1)
        r = rows[0]
        self.assertEqual((r['name'], r['version'], r['first_seen'], r['last_seen'], r['ip'], r['this_device'], r['revoked']),
                         ('Pixel', '1.0.30', now, now + 61, '2001:db8:x:x:...', True, False))
        self.assertTrue(devices.set_revoked(self.uid, DEV1, True))
        self.assertTrue(devices.report(self.u, PIXEL, '198.51.100.23', now + 62))        # told at once, even within a minute
        self.assertTrue(devices.report(self.u, PIXEL, '198.51.100.23', now + 200))       # it is told on its next report
        self.assertTrue(devices.report(self.u, PIXEL, '198.51.100.23', now + 300))       # and keeps being told
        self.assertTrue(devices.set_revoked(self.uid, DEV1, False))
        self.assertFalse(devices.report(self.u, PIXEL, '198.51.100.23', now + 400))
        self.assertFalse(devices.set_revoked(self.uid, DEV2, True))
        other = db.add_user('eve')
        self.assertFalse(devices.set_revoked(other, DEV1, True))                         # not someone else's device

    def test_what_is_refused(self):
        for bad in ({}, dict(PIXEL, device_id='3F2C9A1E-7B1D-4C3E-9A55-0D1E2F3A4B5C'), dict(PIXEL, device_id='x'),
                    dict(PIXEL, platform='web'), dict(PIXEL, name='n' * 41), dict(PIXEL, version=1.0),
                    dict(PIXEL, version='v' * 33)):
            with self.assertRaises(devices.Refused, msg=bad):
                devices.report(self.u, bad, '')
        devices.report(self.u, dict(PIXEL, name=' a\u200bb\nc '), '')
        self.assertEqual(devices.listing(self.uid)[0]['name'], 'abc')

    def test_fifty_per_account_and_ninety_days(self):
        now = 1_800_000_000
        for i in range(52):
            devices.report(self.u, dict(PIXEL, device_id='%08x-0000-4000-8000-000000000000' % i), '', now + i)
        ids = [r['device_id'] for r in devices.listing(self.uid)]
        self.assertEqual(len(ids), 50)
        self.assertNotIn('%08x-0000-4000-8000-000000000000' % 0, ids)                     # the longest unseen goes
        self.assertEqual(devices.prune(now + 46 + 90 * 86400), 44)              # last seen before now+46
        self.assertEqual(len(devices.listing(self.uid)), 6)
        self.assertEqual(devices.recent_names(self.uid, now + 52), ['小明的 Pixel 8'] * 6)

    def test_new_link_forgets_the_others_and_kicks_are_counted(self):
        devices.report(self.u, PIXEL, '', 1)
        devices.report(self.u, dict(PIXEL, device_id=DEV2), '', 1)
        devices.forget_others(self.uid, DEV2)
        self.assertEqual([r['device_id'] for r in devices.listing(self.uid)], [DEV2])
        devices.forget_others(self.uid)
        self.assertEqual(devices.listing(self.uid), [])
        devices._kicks.clear()
        self.assertEqual([devices.kick_allowed(self.uid, 1000 + i) for i in range(3)], [0, 0, 0])
        self.assertEqual(devices.kick_allowed(self.uid, 1500), 3100)
        self.assertEqual(devices.kick_allowed(self.uid, 4601), 0)

    def test_not_in_backups_and_gone_with_the_account(self):
        devices.report(self.u, PIXEL, '', 1)
        data = db.export_all()
        self.assertNotIn(DEV1, json.dumps(data))
        db.import_all(data)
        self.assertEqual(db.q('SELECT COUNT(*) FROM devices')[0][0], 0)
        uid = db.add_user('fay')
        devices.report(db.user(uid), PIXEL, '', 1)
        db.delete_user(uid)
        self.assertEqual(db.q('SELECT COUNT(*) FROM devices')[0][0], 0)

    def test_device_limit_notice_names_the_apps_devices(self):
        db.set_settings(client_devices=True)
        db.update_user(self.uid, max_ips=1)
        devices.report(self.u, PIXEL, '', int(time.time()))
        sent = []
        with mock.patch.object(notify, 'send', lambda text, **k: sent.append(text)):
            jobs.device_limits(db.settings(), {self.uid: {'ips': ['198.51.100.1', '198.51.100.2']}})
        self.assertIn('vps2vpn: 小明的 Pixel 8', sent[0])
        self.assertIn('小明的 Pixel 8', db.events('devices')[0]['detail'] if hasattr(db, 'events') else sent[0])


class DevicesOverHttps(OverHttps):
    def setUp(self):
        super().setUp()
        self.base = '/s/%s/api/' % db.user(self.uid)['sub_token']
        devices._kicks.clear()

    def test_off_until_the_admin_turns_it_on(self):
        st, d = self.j('POST', self.base + 'device', PIXEL)
        self.assertEqual((st, d['code']), (503, 'feature_off'))
        st, d = self.j('GET', self.me)
        self.assertIs(d['features']['devices'], False)

    def test_report_list_revoke_kick(self):
        db.set_settings(client_devices=True)
        st, d = self.j('POST', self.base + 'device', PIXEL)
        self.assertEqual((st, d), (200, {'ok': True, 'revoked': False}))
        st, d = self.j('POST', self.base + 'device', PIXEL)
        self.assertEqual((st, d), (200, {'ok': True, 'revoked': False}))          # reconnecting within a minute
        st, d = self.j('POST', self.base + 'device', dict(PIXEL, platform='symbian'))
        self.assertEqual((st, d['code']), (400, 'bad_request'))
        st, d = self.j('GET', self.base + 'device')
        self.assertEqual((st, d['code']), (405, 'post_only'))
        st, _, r = self.req('GET', self.base + 'devices', headers={'X-V2V-Device': DEV1})
        d = json.loads(_)
        self.assertEqual(st, 200)
        self.assertEqual((d['devices'][0]['ip'], d['devices'][0]['this_device'], d['max_ips']), ('127.0.x.x', True, 0))
        self.assertIn('online_ips', d)
        st, d = self.j('POST', self.base + 'devices/%s/revoke' % DEV1, {})
        self.assertEqual((st, d), (200, {'ok': True}))
        st, d = self.j('POST', self.base + 'devices/%s/revoke' % DEV2, {})
        self.assertEqual((st, d['code']), (404, 'not_found'))
        st, d = self.j('POST', self.base + 'device', PIXEL)                       # still within the minute
        self.assertEqual(d, {'ok': True, 'revoked': True})
        db.q('UPDATE devices SET last_seen=last_seen-120')
        st, d = self.j('POST', self.base + 'device', PIXEL)
        self.assertEqual(d, {'ok': True, 'revoked': True})
        st, d = self.j('GET', self.me)
        self.assertIs(d['features']['devices'], True)
        # the admin sees and restores it
        st, _ = self.j('POST', '/adm/api/login', {'username': 'admin', 'password': 'adminpassword'})
        st, d = self.j('GET', '/adm/api/users/%d/devices' % self.uid)
        self.assertEqual((st, d['on'], d['devices'][0]['revoked']), (200, True, True))
        st, d = self.j('POST', '/adm/api/users/%d/devices/%s/unrevoke' % (self.uid, DEV1), {})
        self.assertEqual(st, 200)
        self.assertFalse(devices.listing(self.uid)[0]['revoked'])
        st, d = self.j('POST', '/adm/api/users/%d/devices/%s/unrevoke' % (self.uid, DEV2), {})
        self.assertEqual(st, 404)
        self.cookie = ''
        # hard kick: a new link; the device that asked stays listed, the others are forgotten
        devices.report(db.user(self.uid), dict(PIXEL, device_id=DEV2), '', 1)
        old = db.user(self.uid)
        st, d = self.j('POST', self.base + 'devices/kick-others', {'device_id': DEV1})
        self.assertEqual(st, 200, d)
        new = db.user(self.uid)
        self.assertNotEqual((new['sub_token'], new['uuid'], new['hy2_pass']), (old['sub_token'], old['uuid'], old['hy2_pass']))
        self.assertTrue(d['sub_url'].endswith('/s/' + new['sub_token']))
        self.assertEqual([r['device_id'] for r in devices.listing(self.uid)], [DEV1])
        st, _, _ = self.req('GET', self.me)
        self.assertEqual(st, 404)                                                     # the old link is gone
        base = '/s/%s/api/' % new['sub_token']
        for _ in range(2):
            st, d = self.j('POST', base + 'devices/kick-others', {}, )
            self.assertEqual(st, 200)
            base = '/s/%s/api/' % db.user(self.uid)['sub_token']
        st, _, r = self.req('POST', base + 'devices/kick-others', {})
        self.assertEqual(st, 429)
        self.assertTrue(int(r.getheader('Retry-After')) > 3000)

    def test_admin_new_link_forgets_every_device(self):
        db.set_settings(client_devices=True)
        devices.report(db.user(self.uid), PIXEL, '', 1)
        st, _ = self.j('POST', '/adm/api/login', {'username': 'admin', 'password': 'adminpassword'})
        st, d = self.j('POST', '/adm/api/users/%d/rotate' % self.uid, {})
        self.assertEqual(st, 200, d)
        self.assertEqual(devices.listing(self.uid), [])


class DevicePages(unittest.TestCase):
    def test_panel_and_member_page(self):
        js = _static('app.js')
        self.assertEqual(js.count("client_devices: '"), 2)
        self.assertIn("api('users/' + u.id + '/devices')", js)
        m = _static('member.js')
        self.assertIn("me.features.devices) blocks.push(devicesPanel())", m)
        self.assertEqual(m.count("dv_tip: '"), 2)



class ConfigVersion(tu.Base):
    def setUp(self):
        super().setUp()
        self.uid = db.add_user('gil', 10)
        _with_joined(self.uid)

    def v(self):
        return subscription.config_version(db.settings(), db.user(self.uid), 'https://192.0.2.1:1')

    def test_changes_with_the_subscription_only(self):
        first = self.v()
        self.assertRegex(first, r'^[0-9a-f]{16}$')
        self.assertEqual(self.v(), first)
        db.update_user(self.uid, used_down=3 << 30, last_seen=int(time.time()))          # traffic: same subscription
        self.assertEqual(self.v(), first)
        seen = {first}
        for change in (lambda: db.set_settings(hy2_port=db.settings()['hy2_port'] + 1),
                       lambda: db.set_settings(custom_direct=['example.cn']),
                       lambda: db.rotate_user(self.uid),
                       lambda: db.set_settings(client_node_status=True) or nodestatus.set_status(SID, {'state': 'maintenance'}),
                       lambda: db.update_user(self.uid, enabled=0, disabled_reason='manual')):
            change()
            v = self.v()
            self.assertNotIn(v, seen)
            seen.add(v)

    def test_in_api_me(self):
        src = __import__('inspect').getsource(web)
        self.assertIn("'config_version': subscription.config_version(s, u, base)", src)


if __name__ == '__main__':
    unittest.main()


class AsTheMemberSeesIt(OverHttps):
    """0.2.46 review of the phase 2 API from the member's side: a paused or expired account, a new link (every
    old address stops at once), and the limits a normal app meets."""

    def setUp(self):
        super().setUp()
        devices._kicks.clear()

    def _all_on(self):        # per test: the inherited OverHttps tests expect the switches off
        db.set_settings(client_node_status=True, client_feedback=True, client_devices=True)

    def _api(self, tok):
        return '/s/%s/api/' % tok

    def test_paused_or_expired_account(self):
        self._all_on()
        tok = db.user(self.uid)['sub_token']
        st, before = self.j('GET', self.me)
        self.assertEqual((st, len(before['nodes'])), (200, 2))
        for reason in ('expired', 'quota', 'manual'):
            db.update_user(self.uid, enabled=0, disabled_reason=reason)
            st, d = self.j('GET', self.me)
            self.assertEqual((st, d['enabled'], d['disabled_reason']), (200, False, reason))
            self.assertEqual(d['nodes'], [])                         # like its subscription: no servers
            self.assertNotEqual(d['config_version'], before['config_version'])   # the app refreshes to the empty one
            self.assertEqual(d['features'], before['features'])
        # it can still say what is wrong, and its devices still report and list
        st, d = self.j('POST', self._api(tok) + 'feedback', {'client': {'platform': 'android', 'version': '1.0.29'},
                                                             'text': '到期了，怎么续？'})
        self.assertEqual(st, 200, d)
        st, d = self.j('POST', self._api(tok) + 'device', PIXEL)
        self.assertEqual((st, d), (200, {'ok': True, 'revoked': False}))
        st, d = self.j('GET', self._api(tok) + 'devices')
        self.assertEqual((st, len(d['devices'])), (200, 1))
        db.update_user(self.uid, enabled=1, disabled_reason='')
        st, d = self.j('GET', self.me)
        self.assertEqual((d['config_version'], len(d['nodes'])), (before['config_version'], 2))

    def _old_addresses_gone(self, old):
        for method, path in (('GET', '/s/%s' % old), ('GET', '/s/%s?format=clash' % old), ('GET', '/s/%s/qr.svg' % old),
                             ('GET', '/sub/%s.yaml' % old), ('GET', self._api(old) + 'me'),
                             ('GET', self._api(old) + 'feedback'), ('GET', self._api(old) + 'devices'),
                             ('POST', self._api(old) + 'device'), ('POST', self._api(old) + 'feedback'),
                             ('POST', self._api(old) + 'devices/kick-others'), ('POST', self._api(old) + 'rotate')):
            st, _, _ = self.req(method, path, PIXEL if method == 'POST' else None)
            self.assertEqual(st, 404, (method, path.replace(old, '<old>')))

    def test_every_new_link_ends_every_old_address(self):
        self._all_on()
        devices.report(db.user(self.uid), PIXEL, '', 1)
        # 1) the member, from the link page
        old = db.user(self.uid)['sub_token']
        st, d = self.j('POST', self._api(old) + 'rotate', {})
        self.assertEqual(st, 200, d)
        self._old_addresses_gone(old)
        # 2) the app's hard kick
        old = db.user(self.uid)['sub_token']
        st, d = self.j('POST', self._api(old) + 'devices/kick-others', {'device_id': DEV1})
        self.assertEqual(st, 200, d)
        self._old_addresses_gone(old)
        new = db.user(self.uid)['sub_token']
        st, d = self.j('GET', self._api(new) + 'me')
        self.assertEqual((st, d['sub_url'].endswith('/s/' + new)), (200, True))
        # 3) the admin; a member-centre session opened before it ends too
        st, _ = self.j('POST', '/mem/api/login', {'name': 'tia', 'password': 'tiapassword'})
        self.assertEqual(st, 200)
        member_cookie = self.cookie
        self.assertEqual(self.j('GET', '/mem/api/me')[0], 200)
        self.cookie = ''
        st, _ = self.j('POST', '/adm/api/login', {'username': 'admin', 'password': 'adminpassword'})
        old = db.user(self.uid)['sub_token']
        st, d = self.j('POST', '/adm/api/users/%d/rotate' % self.uid, {})
        self.assertEqual(st, 200, d)
        self.cookie = ''
        self._old_addresses_gone(old)
        self.cookie = member_cookie
        st, d = self.j('GET', '/mem/api/me')
        self.assertEqual((st, d.get('code')), (401, 'login_required'))
        st, d = self.j('GET', '/mem/api/devices')
        self.assertEqual((st, d.get('code')), (401, 'login_required'))

    def test_a_normal_app_is_never_refused(self):
        self._all_on()
        tok = db.user(self.uid)['sub_token']
        for _ in range(30):                                                    # api/me as often as the app likes
            self.assertEqual(self.req('GET', self.me)[0], 200)
        for _ in range(5):                    # a report on every reconnect, several a minute, from two devices
            for dev in (DEV1, DEV2):
                st, d = self.j('POST', self._api(tok) + 'device', dict(PIXEL, device_id=dev))
                self.assertEqual((st, d['ok']), (200, True))
        for _ in range(5):
            self.assertEqual(self.j('GET', self._api(tok) + 'devices')[0], 200)
            self.assertEqual(self.j('GET', self._api(tok) + 'feedback')[0], 200)
        # feedback: one, then a 429 with a Retry-After the app can show ("wait a moment"), never a lockout
        body = {'client': {'platform': 'android', 'version': '1.0.29'}, 'text': '连不上'}
        self.assertEqual(self.j('POST', self._api(tok) + 'feedback', body)[0], 200)
        st, _, r = self.req('POST', self._api(tok) + 'feedback', body)
        self.assertEqual(st, 429)
        self.assertTrue(0 < int(r.getheader('Retry-After')) <= feedback.GAP)
        self.assertEqual(self.req('GET', self.me)[0], 200)                     # nothing else is held back
        self.assertEqual(web._fails, {})                                       # and no sign-in budget was spent


RID = 'Zq3xV9-kP2_mN7bR4tY8wL'          # 22 base64url characters: what a 128-bit random id looks like
RID2 = '0123456789abcdef0123456789abcdef'


class KickRetryValues(tu.Base):
    def setUp(self):
        super().setUp()
        devices._replays.clear()

    def test_request_id(self):
        self.assertEqual(devices.request_id(None), '')
        self.assertEqual(devices.request_id(''), '')
        self.assertEqual(devices.request_id(RID), RID)
        for bad in ('short', 'x' * 21, 'x' * 129, 'has space ' * 3, 12345678901234567890123, ['x' * 30], 'é' * 30):
            with self.assertRaises(devices.Refused, msg=bad):
                devices.request_id(bad)

    def test_remembered_for_ten_minutes_by_old_link_and_id(self):
        now = 1_800_000_000
        devices.remember_kick('oldtoken', RID, 7, 'newtoken', now)
        self.assertEqual(devices.replayed_kick('oldtoken', RID, now + 599), (7, 'newtoken'))
        self.assertIsNone(devices.replayed_kick('oldtoken', RID, now + 600))
        self.assertIsNone(devices.replayed_kick('oldtoken', RID2, now))
        self.assertIsNone(devices.replayed_kick('othertoken', RID, now))
        self.assertIsNone(devices.replayed_kick('oldtoken', '', now))
        self.assertNotIn('oldtoken', repr(devices._replays))                 # only a hash of the old link is kept
        devices.remember_kick('oldtoken', '', 7, 'x', now)                    # no id: nothing to remember
        self.assertEqual(len(devices._replays), 1)
        devices.remember_kick('t2', RID, 8, 'n2', now + 601)                  # the expired one is cleaned up
        self.assertEqual(len(devices._replays), 1)

    def test_bounded(self):
        with mock.patch.object(devices, 'REPLAY_MAX', 3):
            for i in range(5):
                devices.remember_kick('t%d' % i, RID, i, 'n%d' % i, 1000)
            self.assertEqual(len(devices._replays), 3)
            self.assertIsNone(devices.replayed_kick('t0', RID, 1000))         # the oldest went first
            self.assertEqual(devices.replayed_kick('t4', RID, 1000), (4, 'n4'))


class KickRetryOverHttps(OverHttps):
    def setUp(self):
        super().setUp()
        devices._kicks.clear()
        devices._replays.clear()

    def _kick(self, tok, body):
        return self.j('POST', '/s/%s/api/devices/kick-others' % tok, body)

    def test_a_lost_answer_is_retried_safely(self):
        db.set_settings(client_devices=True)
        old = db.user(self.uid)['sub_token']
        st, first = self._kick(old, {'device_id': DEV1, 'request_id': RID})
        self.assertEqual(st, 200, first)
        new = db.user(self.uid)['sub_token']
        self.assertTrue(first['sub_url'].endswith('/s/' + new))
        # the answer never arrived: the app sends the same request again on the old link
        for _ in range(2):
            st, again = self._kick(old, {'device_id': DEV1, 'request_id': RID})
            self.assertEqual(st, 200, again)
            self.assertEqual((again['sub_url'], again['base'], again['replayed']), (first['sub_url'], first['base'], True))
        self.assertEqual(db.user(self.uid)['sub_token'], new)                 # no second kick
        self.assertEqual(len(devices._kicks[self.uid]), 1)                    # and not counted again
        # everything else on the old link is still gone
        for body in ({'request_id': RID2}, {}, {'request_id': 'short'}, {'device_id': DEV1}):
            st, _, _ = self.req('POST', '/s/%s/api/devices/kick-others' % old, body)
            self.assertEqual(st, 404, body)
        st, _, _ = self.req('POST', '/s/%s/api/devices/kick-others' % old, None, headers={'Content-Type': 'text/plain'})
        self.assertEqual(st, 404)
        for path in ('me', 'devices'):
            self.assertEqual(self.req('GET', '/s/%s/api/%s' % (old, path))[0], 404)
        st, _, _ = self.req('POST', '/s/%s/api/devices/kick-others' % old, {'request_id': RID}, headers={'X-V2V': ''})
        self.assertEqual(st, 404)
        # a later new link (here: the admin's) ends the retry too
        st, _ = self.j('POST', '/adm/api/login', {'username': 'admin', 'password': 'adminpassword'})
        self.assertEqual(self.j('POST', '/adm/api/users/%d/rotate' % self.uid, {})[0], 200)
        self.cookie = ''
        self.assertEqual(self.req('POST', '/s/%s/api/devices/kick-others' % old, {'request_id': RID})[0], 404)

    def test_ten_minutes_then_gone(self):
        db.set_settings(client_devices=True)
        old = db.user(self.uid)['sub_token']
        self.assertEqual(self._kick(old, {'request_id': RID})[0], 200)
        for k, v in list(devices._replays.items()):
            devices._replays[k] = (v[0], v[1], time.time() - 1)
        self.assertEqual(self.req('POST', '/s/%s/api/devices/kick-others' % old, {'request_id': RID})[0], 404)

    def test_switch_off_or_bad_id(self):
        db.set_settings(client_devices=True)
        old = db.user(self.uid)['sub_token']
        st, d = self._kick(old, {'request_id': 'not random enough'})
        self.assertEqual((st, d['code']), (400, 'bad_request'))
        self.assertEqual(db.user(self.uid)['sub_token'], old)                 # refused before any kick
        self.assertEqual(self._kick(old, {'request_id': RID})[0], 200)
        db.set_settings(client_devices=False)
        self.assertEqual(self.req('POST', '/s/%s/api/devices/kick-others' % old, {'request_id': RID})[0], 404)

    def test_a_retry_racing_the_first_kick(self):
        """The retry arrives while the first kick still runs: it waits, then gets the same link (no second kick)."""
        db.set_settings(client_devices=True)
        old = db.user(self.uid)['sub_token']
        results = []
        rotate = db.rotate_user

        def slow_rotate(uid):
            time.sleep(0.5)
            rotate(uid)
        with mock.patch.object(db, 'rotate_user', slow_rotate):
            threads = [threading.Thread(target=lambda: results.append(self._kick(old, {'request_id': RID})))
                       for _ in range(2)]
            for t in threads:
                t.start()
                time.sleep(0.1)
            for t in threads:
                t.join(10)
        self.assertEqual(sorted(st for st, _ in results), [200, 200])
        self.assertEqual(len({d['sub_url'] for _, d in results}), 1)
        self.assertEqual(len(devices._kicks[self.uid]), 1)

