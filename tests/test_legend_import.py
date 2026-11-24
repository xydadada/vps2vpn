"""tools/legend_import.py, with made-up old-panel data only:  python -m unittest tests.test_legend_import -v

The merged file is restored into a real (temporary) vps2vpn database, and every account is then checked
against what the old panel computed: the same subscription link, the same remaining traffic and the same
usage line in the apps, the same expiry second, and the same member-centre password."""
import contextlib
import datetime as dt
import hashlib
import io
import json
import os
import shutil
import sqlite3
import sys
import tempfile
import unittest

ROOT = tempfile.mkdtemp(prefix='v2v-legend-')
os.environ['VPS2VPN_ROOT'] = ROOT
os.environ['VPS2VPN_DEV'] = '1'
HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, 'tools'))

from vps2vpn import db, jobs, members, rules, secure, subscription  # noqa: E402
import legend_import as li  # noqa: E402

rules.refresh_in_background = lambda log=print: None
SG = li.SG
NOW = int(dt.datetime(2026, 11, 25, 12, 0, tzinfo=SG).timestamp())   # the same day in every time zone CI uses
GB = 1_000_000_000                                                    # the old panel's GB


def tearDownModule():
    db.close()
    shutil.rmtree(ROOT, ignore_errors=True)


def read(path):
    with open(path, 'rb') as f:
        return f.read()


def end_of(day):
    """The old panel's expiry for "usable through <day>": next midnight, Singapore time."""
    return int(dt.datetime.combine(dt.date.fromisoformat(day) + dt.timedelta(days=1), dt.time(), SG).timestamp())


def login(username, password, rounds=1000, enabled=True):
    salt = os.urandom(32)
    return {'username': username, 'salt': salt.hex(), 'iterations': rounds, 'enabled': enabled, 'version': 'v1',
            'password_hash': hashlib.pbkdf2_hmac('sha256', password.encode(), salt, rounds).hex()}


def account(i, **kw):
    u = {'id': 'u%d' % i, 'remark': '', 'token': ('T%02d' % i) * 14 + 'x', 'uuid': '00000000-0000-4000-8000-%012d' % i,
         'hy_password': 'hy-pass-%d' % i, 'tuic_uuid': '10000000-0000-4000-8000-%012d' % i,
         'tuic_password': 'tuic-%d' % i, 'total': 0, 'expire': 0, 'enabled': True, 'cycle_day': 20,
         'quota_overrun': 'throttle', 'created_at': 1700000000 + i}
    u.update(kw)
    return u


USERS = [
    account(1, remark='alice', total=100 * GB, cycle_day=20, expire=end_of('2027-01-31'),
            quota_bonus={'cycle': '2026-11-20', 'bytes': 5 * GB}, member_login=login('alice', 'alice-pass-1'),
            speed_policy={'exempt': False, 'free_gb': '200', 'upload_mbps': '5', 'download_mbps': '50',
                          'follow_quota': True}),
    # invited by alice: 10 GB of alice's quota is hers while she is active
    account(2, remark='bob', total=10 * GB, cycle_day=31, expire=end_of('2027-01-31'), invited_by='u1',
            invite_deduct=10 * GB, nodes=['jp'], member_login=login('Bobby', 'bob-pass-22')),
    account(3, remark='carol', total=0, expire=0, enabled=False),                          # unlimited, switched off
    account(4, remark='张三 (VIP)', total=50 * GB, cycle_day=1, expire=end_of('2026-12-01'),
            speed_policy={'exempt': True}),
    account(5, remark='erin', total=20 * GB, cycle_day=15, expire=end_of('2026-11-20'),    # already expired
            quota_bonus={'cycle': '2026-10-15', 'bytes': 7 * GB}),                         # last period's top-up
    account(6, remark='alice', total=30 * GB, quota_overrun='stop', cycle_day=28,          # name clash with u1
            expire=end_of('2026-11-25')),                                                  # last day today
]
# (id, cycle, day, upload, download): this period, and older periods that must not count
USAGE = [
    ('u1', '2026-11-20', '2026-11-20', 1 * GB, 30 * GB), ('u1', '2026-11-20', '2026-11-24', 2 * GB, 7 * GB + 12345),
    ('u1', '2026-10-20', '2026-11-01', 9 * GB, 90 * GB),
    ('u2', '2026-10-31', '2026-11-03', 123456789, 4 * GB),
    ('u3', '2026-11-20', '2026-11-21', 5 * GB, 500 * GB),
    ('u4', '2026-11-01', '2026-11-02', 1, 60 * GB),                                         # over its quota
    ('u5', '2026-11-15', '2026-11-16', 0, 3 * GB),
    ('u6', '2026-10-28', '2026-11-01', 10 * GB, 0),
]
RULES = [
    'DOMAIN-SUFFIX,google.com,节点选择', 'DOMAIN-SUFFIX,mail.google.com,国内服务',            # dead in the old file
    'DOMAIN-SUFFIX,baidu.com,国内服务', 'DOMAIN,www.qq.com,国内服务', 'DOMAIN-SUFFIX,.doubleclick.net,广告过滤',
    'DOMAIN-SUFFIX,anthropic.com,Claude', 'DOMAIN-SUFFIX,api.openai.com,节点选择',            # left to the AI group
    'DOMAIN-KEYWORD,adservice,广告过滤', 'IP-CIDR,192.0.2.0/24,DIRECT,no-resolve', 'IP-CIDR6,2001:db8::/32,DIRECT',
    'DOMAIN-SUFFIX,steamcontent.com,Steam下载', 'DOMAIN-SUFFIX,example.org,某个分组',
    'DOMAIN-SUFFIX,cdn.cn-site.com,节点选择', 'DOMAIN-SUFFIX,cn-site.com,国内服务',            # proxy under direct
    'DOMAIN-SUFFIX,bad_name!,DIRECT', 'GEOIP,CN,DIRECT', 'MATCH,节点选择',
]


def legend_header(u, ledger):
    """The subscription-userinfo header the old panel sent (legend_sub.py)."""
    up, down = ledger
    return 'upload=%d; download=%d; total=%d; expire=%d' % (up, down, li.legend_quota(u, USERS, NOW), int(u.get('expire', 0)))


def ledger_of(uid):
    u = next(x for x in USERS if x['id'] == uid)
    key = li.cycle_key(u['cycle_day'], NOW)
    rows = [r for r in USAGE if r[0] == uid and r[1] == key]
    return sum(r[3] for r in rows), sum(r[4] for r in rows)


class LegendImport(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp(prefix='legend-files-')
        p = lambda n: os.path.join(cls.dir, n)
        cls.paths = {'base': p('base.json'), 'settings': p('settings.json'), 'usage': p('usage.sqlite3'),
                     'template': p('template.json'), 'out': p('merged.json')}
        # in a full run the database is shared and may still hold an earlier test's accounts
        for u in db.users():
            db.delete_user(u['id'])
        # the new panel already has one account of its own; it must survive untouched
        cls.mine = db.add_user('owner-phone', 0)
        db.set_settings(custom_direct=['example.cn'])
        with open(cls.paths['base'], 'w', encoding='utf-8') as f:
            json.dump(db.export_all(), f)
        with open(cls.paths['settings'], 'w', encoding='utf-8') as f:
            json.dump({'base_url': 'https://sub.example.test', 'users': USERS,
                       'legacy': {'hy_id': 'legacy', 'hy_password': 'old-shared'}}, f, ensure_ascii=False)
        with open(cls.paths['template'], 'w', encoding='utf-8') as f:
            json.dump({'rules': RULES}, f, ensure_ascii=False)
        c = sqlite3.connect(cls.paths['usage'])
        c.execute('CREATE TABLE daily(user_id TEXT, cycle TEXT, day TEXT, upload INTEGER, download INTEGER, '
                  'PRIMARY KEY(user_id, cycle, day))')
        c.executemany('INSERT INTO daily VALUES(?,?,?,?,?)', USAGE)
        c.commit()
        c.close()
        cls.before = {k: read(cls.paths[k]) for k in ('settings', 'usage', 'template')}
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            cls.code = li.main(['--base', cls.paths['base'], '--settings', cls.paths['settings'],
                                '--usage', cls.paths['usage'], '--template', cls.paths['template'],
                                '-o', cls.paths['out'], '--now', str(NOW)])
        cls.report = out.getvalue()
        with open(cls.paths['out'], encoding='utf-8') as f:
            db.import_all(json.load(f))

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.dir, ignore_errors=True)

    def user(self, old):
        u = db.user_by_token(old['token'])
        self.assertIsNotNone(u, old['id'])
        return u

    def test_writes_the_file_and_leaves_the_old_files_alone(self):
        self.assertEqual(self.code, 0, self.report)
        for k, data in self.before.items():
            self.assertEqual(read(self.paths[k]), data, k)

    def test_every_old_link_and_credential_still_works(self):
        for old in USERS:
            u = self.user(old)
            self.assertEqual((u['uuid'], u['hy2_pass']), (old['uuid'], old['hy_password']))
            if u['enabled']:                    # the account behind the old link gets working nodes
                self.assertIn(old['uuid'], json.dumps(subscription.nodes(db.settings(), u)))

    def test_remaining_traffic_and_expiry_match_the_old_panel(self):
        for old in USERS:
            u = self.user(old)
            quota = members.effective_quota(u, now=NOW)
            # what Clash / Shadowrocket show: the same bytes up, down, total and the same expiry
            self.assertEqual(subscription.userinfo_header(u, quota), legend_header(old, ledger_of(old['id'])), old['id'])
            if old['total']:
                left_old = li.legend_quota(old, USERS, NOW) - sum(ledger_of(old['id']))
                left_new = quota * (1 << 30) - u['used_up'] - u['used_down']
                self.assertEqual(left_new, left_old, old['id'])
            else:
                self.assertEqual((u['quota_gb'], quota), (0, 0))

    def test_cut_off_at_the_same_moment(self):
        for old in USERS:
            u = self.user(old)
            if old['expire']:
                self.assertNotEqual(jobs.over_limit(u, now=old['expire'] - 1, quota=1e9), 'expired', old['id'])
                self.assertEqual(jobs.over_limit(u, now=old['expire'], quota=1e9), 'expired', old['id'])
            else:
                self.assertEqual(u['expire_at'], 0)
        self.assertEqual(jobs.over_limit(self.user(USERS[4]), now=NOW), 'expired')        # erin: already over
        self.assertEqual(self.user(USERS[5])['expire_at'], end_of('2026-11-25'))          # usable to tonight

    def test_this_period_is_not_reset_on_moving_day(self):
        for old in USERS:
            u = self.user(old)
            due, _ = jobs.monthly_reset(u, NOW)
            self.assertFalse(due, old['id'])
            self.assertEqual((u['used_up'], u['used_down']), ledger_of(old['id']))
        # and the next reset comes on the old reset day (alice: the 20th). vps2vpn counts days on the server's
        # clock, the old panel on Singapore's: 23:00 there is the 20th on any server from UTC-15 to UTC+8.
        alice = self.user(USERS[0])
        self.assertTrue(jobs.monthly_reset(alice, int(dt.datetime(2026, 12, 20, 23, tzinfo=SG).timestamp()))[0])
        self.assertFalse(jobs.monthly_reset(alice, int(dt.datetime(2026, 12, 19, 12, tzinfo=SG).timestamp()))[0])
        # the panel now changes months on Singapore's clock too: midnight there, whatever the server's zone
        self.assertEqual(db.settings()['time_zone'], 'UTC+8')
        self.assertTrue(jobs.monthly_reset(alice, int(dt.datetime(2026, 12, 20, 0, 0, 1, tzinfo=SG).timestamp()))[0])
        self.assertFalse(jobs.monthly_reset(alice, int(dt.datetime(2026, 12, 19, 23, 59, tzinfo=SG).timestamp()))[0])
        # bob resets on the 31st: the 30th in November, as on the old panel
        bob = self.user(USERS[1])
        self.assertEqual(bob['reset_day'], 31)
        self.assertTrue(jobs.monthly_reset(bob, int(dt.datetime(2026, 11, 30, 1, tzinfo=SG).timestamp()))[0])
        self.assertFalse(jobs.monthly_reset(bob, int(dt.datetime(2026, 11, 29, 23, tzinfo=SG).timestamp()))[0])

    def test_top_up_only_for_the_current_period(self):
        self.assertEqual(self.user(USERS[0])['extra_gb'] * (1 << 30), 5 * GB)
        self.assertEqual(self.user(USERS[4])['extra_gb'], 0)

    def test_invites_switch_off_and_slow_down(self):
        alice, bob = self.user(USERS[0]), self.user(USERS[1])
        self.assertEqual(bob['invited_by'], alice['id'])
        self.assertEqual(self.user(USERS[2])['enabled'], 0)
        self.assertEqual(self.user(USERS[2])['disabled_reason'], 'manual')
        self.assertEqual(alice['throttle_mbps'], 50)                    # used up: slows down as before
        self.assertEqual(self.user(USERS[5])['throttle_mbps'], 0)       # "stop" accounts still stop
        self.assertEqual(self.user(USERS[3])['throttle_mbps'], db.MAX_MBPS)

    def test_member_password_and_names(self):
        alice, bob = self.user(USERS[0]), self.user(USERS[1])
        self.assertEqual(alice['name'], 'alice')
        self.assertEqual(db.user_by_name('Bobby')['id'], bob['id'])     # members sign in with their old user name
        self.assertTrue(secure.check_password('alice-pass-1', alice['login_hash']))
        self.assertTrue(secure.check_password('bob-pass-22', bob['login_hash']))
        self.assertFalse(secure.check_password('wrong', bob['login_hash']))
        self.assertEqual(self.user(USERS[2])['login_hash'], '')
        names = [self.user(o)['name'] for o in USERS]
        self.assertEqual(len({n.casefold() for n in names}), len(names))
        for n in names:
            self.assertRegex(n, members.NAME_RE)
        self.assertEqual(self.user(USERS[3])['name'], '张三VIP')
        self.assertIn('u6 的名字 “alice”', self.report)                 # the renamed clash is named
        self.assertNotIn('u2 的名字', self.report)                       # named after its login: not a rename

    def test_the_new_panels_own_account_and_settings_stay(self):
        mine = db.user(self.mine)
        self.assertEqual(mine['name'], 'owner-phone')
        self.assertEqual(len(db.users()), len(USERS) + 1)
        self.assertIn('example.cn', db.settings()['custom_direct'])

    def test_report_names_what_did_not_carry_over(self):
        r = self.report
        for text in ('UTC+8', 'legacy', 'TUIC', 'DOMAIN-KEYWORD', 'IP 规则', '某个分组', 'cdn.cn-site.com',
                     '部分节点', '导入了 6 个旧账号'):
            self.assertIn(text, r)


def first_match(plan, domain):
    for kind, value, to in plan:
        if kind == 'suffix' and (domain == value or domain.endswith('.' + value)):
            return to
    return None


class LegendRules(unittest.TestCase):
    def test_rules_land_in_the_right_lists_and_route_as_before(self):
        lists, rep = li.convert_rules(RULES)
        self.assertEqual(lists['proxy'], ['google.com', 'cdn.cn-site.com'])
        self.assertEqual(lists['direct'], ['baidu.com', 'www.qq.com', 'steamcontent.com', 'cn-site.com'])
        self.assertEqual(lists['block'], ['doubleclick.net'])
        self.assertEqual((rep['dead'], rep['ai'], rep['keyword'], rep['ip'], rep['exact']), (1, 2, 1, 3, 1))
        self.assertEqual(rep['unknown_target'], {'某个分组': 1})
        self.assertEqual(rep['shadowed'], [('cdn.cn-site.com', 'proxy', 'cn-site.com', 'direct')])
        plan = rules.route_plan({'custom_block': lists['block'], 'custom_direct': lists['direct'],
                                 'custom_proxy': lists['proxy']})
        want = {'www.google.com': 'proxy', 'mail.google.com': 'proxy', 'tieba.baidu.com': 'direct',
                'ad.doubleclick.net': 'reject', 'claude.anthropic.com': 'ai', 'api.openai.com': 'ai'}
        for d, to in want.items():
            self.assertEqual(first_match(plan, d), to, d)

    def test_option_maps_an_unknown_group(self):
        lists, rep = li.convert_rules(RULES, dict(li.TARGETS, 某个分组='direct'))
        self.assertIn('example.org', lists['direct'])
        self.assertEqual(rep['unknown_target'], {})

    def test_long_lists_are_flagged(self):
        from vps2vpn import web
        self.assertEqual(li.PANEL_LIST_MAX, web.CUSTOM_LIST_MAX)        # the tool warns at the panel's own limit
        lists, _ = li.convert_rules(['DOMAIN-SUFFIX,site%d.com,DIRECT' % i for i in range(li.PANEL_LIST_MAX + 1)])
        text = li.describe({'renamed': [], 'login_renamed': [], 'reset_day': [], 'exempt': [], 'free_gb': [],
                            'updown': [], 'nodes': [], 'orphans': [], 'chain': [], 'no_login': [], 'legacy': False,
                            'count': 0}, li.convert_rules([])[1], {'custom_direct': lists['direct']})
        self.assertIn('超过 %d 条' % li.PANEL_LIST_MAX, text)


class LegendRefuses(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix='legend-bad-')
        self.addCleanup(shutil.rmtree, self.dir, True)

    def run_tool(self, base, settings):
        p = lambda n: os.path.join(self.dir, n)
        if os.path.exists(p('out.json')):
            os.unlink(p('out.json'))
        for name, data in (('base.json', base), ('settings.json', settings)):
            with open(p(name), 'w', encoding='utf-8') as f:
                json.dump(data, f)
        sqlite3.connect(p('usage.sqlite3')).execute(
            'CREATE TABLE IF NOT EXISTS daily(user_id TEXT, cycle TEXT, day TEXT, upload INTEGER, download INTEGER)'
        ).connection.close()
        err = io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            code = li.main(['--base', p('base.json'), '--settings', p('settings.json'), '--usage', p('usage.sqlite3'),
                            '-o', p('out.json'), '--now', str(NOW)])
        return code, err.getvalue(), os.path.exists(p('out.json'))

    def test_a_token_already_on_the_new_panel(self):
        base = {'format': 'vps2vpn-backup-1', 'settings': {}, 'users': [
            {'id': 1, 'name': 'test', 'uuid': 'x', 'hy2_pass': 'y', 'sub_token': USERS[0]['token']}]}
        code, err, wrote = self.run_tool(base, {'users': [USERS[0]]})
        self.assertEqual((code, wrote), (2, False))
        self.assertIn('重复', err)

    def test_not_a_backup(self):
        code, err, wrote = self.run_tool({'users': []}, {'users': []})
        self.assertEqual((code, wrote), (2, False))
        self.assertIn('--base', err)

    # audit 9 S9-03 ----------------------------------------------------------------------------------------
    BASE = {'format': 'vps2vpn-backup-1', 'settings': {}, 'users': []}

    def test_bad_credentials_and_counts_are_refused_before_anything_is_written(self):
        bad = [({'uuid': 'not-a-uuid'}, 'uuid'), ({'hy_password': 'has space, comma'}, 'Hysteria'),
               ({'total': -1}, 'total'), ({'total': True}, 'total'), ({'expire': -5}, 'expire'),
               ({'invite_deduct': 1.5e400}, 'invite_deduct'),
               ({'speed_policy': {'download_mbps': float('nan')}}, 'download_mbps'),
               ({'speed_policy': {'download_mbps': True}}, 'download_mbps'),
               ({'speed_policy': {'upload_mbps': 'inf'}}, 'upload_mbps')]
        for change, word in bad:
            with self.subTest(change=change):
                code, err, wrote = self.run_tool(self.BASE, {'users': [dict(account(1, total=10 * GB), **change)]})
                self.assertEqual((code, wrote), (2, False), err)
                self.assertIn(word, err)

    def test_null_and_odd_records_mean_not_set(self):
        u = account(1, total=10 * GB, cycle_day=None, invite_deduct=None, quota_bonus=None, speed_policy=None,
                    expire=None, created_at=1700000000.5)
        code, err, wrote = self.run_tool(self.BASE, {'users': [u, account(2, quota_bonus=[], speed_policy='x')]})
        self.assertEqual((code, wrote), (0, True), err)
        with open(os.path.join(self.dir, 'out.json'), encoding='utf-8') as f:
            got = {x['name']: x for x in json.load(f)['users']}
        self.assertEqual((got['u1']['reset_day'], got['u1']['expire_at'], got['u1']['created_at']), (20, 0, 1700000000))
        self.assertEqual(got['u1']['throttle_mbps'], 50.0)

    def test_template_must_be_an_object(self):
        p = lambda n: os.path.join(self.dir, n)
        self.run_tool(self.BASE, {'users': []})
        with open(p('template.json'), 'w', encoding='utf-8') as f:
            json.dump(['DOMAIN-SUFFIX,example.org,DIRECT'], f)
        err = io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            code = li.main(['--base', p('base.json'), '--settings', p('settings.json'), '--usage', p('usage.sqlite3'),
                            '--template', p('template.json'), '-o', p('out2.json'), '--now', str(NOW)])
        self.assertEqual((code, os.path.exists(p('out2.json'))), (2, False))
        self.assertIn('template', err.getvalue())

    def test_the_result_is_readable_by_its_owner_only(self):
        code, err, wrote = self.run_tool(self.BASE, {'users': [account(1)]})
        self.assertEqual((code, wrote), (0, True), err)
        if os.name == 'posix':
            self.assertEqual(os.stat(os.path.join(self.dir, 'out.json')).st_mode & 0o777, 0o600)
        self.assertFalse(os.path.exists(os.path.join(self.dir, 'out.json.tmp')))

    def test_last_reset_follows_the_new_panels_time_zone(self):
        # 2026-11-20 03:00 in Singapore is still the 19th in UTC-8: there the 20th's reset has not happened yet
        now = int(dt.datetime(2026, 11, 20, 3, 0, tzinfo=SG).timestamp())
        for zone, month in (('', '2026-11'), ('UTC+8', '2026-11'), ('UTC-8', '2026-10')):
            with self.subTest(zone=zone):
                base = dict(self.BASE, settings={'time_zone': zone})
                u = account(1, total=10 * GB, cycle_day=20)
                out, _ = li.import_users(base, {'users': [u]}, {'u1': (0, 0)}, now)
                self.assertEqual(out['users'][0]['last_reset'], month)
                db.import_all(dict(db.export_all(), users=out['users'], settings=dict(
                    db.export_all()['settings'], time_zone=out['settings']['time_zone'])))
                got = db.users()[0]
                self.assertFalse(jobs.monthly_reset(got, now)[0])          # not cleared on the first check
        self.assertEqual(li._parse_tz('UTC-8').utcoffset(None), dt.timedelta(hours=-8))
        with self.assertRaises(li.Problem):
            li._parse_tz('Mars/Olympus')

    def test_ai_list_matches_the_panels(self):
        self.assertEqual(set(li.AI_SUFFIX), set(rules.AI_SUFFIX))
        self.assertNotIn('28', li.describe({'count': 0, 'renamed': [], 'login_renamed': [], 'no_login': [],
                                            'exempt': [], 'free_gb': [], 'updown': [], 'nodes': [], 'orphans': [],
                                            'chain': [], 'legacy': False, 'time_zone': ''}, None, {}))

    def test_output_over_an_input(self):
        p = os.path.join(self.dir, 'settings.json')
        with open(p, 'w') as f:
            f.write('{"users": []}')
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(li.main(['--base', p, '--settings', p, '--usage', p, '-o', p]), 2)
        self.assertEqual(read(p), b'{"users": []}')


if __name__ == '__main__':
    unittest.main()


class LegendLines(unittest.TestCase):
    """--lines: the old proxy's Reality key, short id, handshake site and ports carry over, so a client that
    never refreshes its subscription still reaches the new server over Reality."""
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix='legend-lines-')
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.private, self.public = secure.reality_keypair()

    def config(self, **reality):
        r = dict({'enabled': True, 'handshake': {'server': 'www.example.org', 'server_port': 443},
                  'private_key': self.private, 'short_id': ['0123456789abcdef']}, **reality)
        return {'inbounds': [
            {'type': 'vless', 'listen_port': 26443, 'tls': {'enabled': True, 'server_name': 'www.example.org',
                                                            'reality': r}, 'users': []},
            {'type': 'hysteria2', 'listen_port': 26443, 'tls': {}, 'users': []},
            {'type': 'tuic', 'listen_port': 28443, 'tls': {}, 'users': []}]}

    def run_tool(self, cfg):
        p = lambda n: os.path.join(self.dir, n)
        for name, data in (('base.json', {'format': 'vps2vpn-backup-1', 'settings': {}, 'users': []}),
                           ('settings.json', {'users': [account(1)]}), ('config.json', cfg)):
            with open(p(name), 'w', encoding='utf-8') as f:
                json.dump(data, f)
        sqlite3.connect(p('usage.sqlite3')).execute(
            'CREATE TABLE IF NOT EXISTS daily(user_id TEXT, cycle TEXT, day TEXT, upload INTEGER, download INTEGER)'
        ).connection.close()
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(out):
            code = li.main(['--base', p('base.json'), '--settings', p('settings.json'), '--usage', p('usage.sqlite3'),
                            '--lines', p('config.json'), '-o', p('out.json'), '--now', str(NOW)])
        merged = None
        if os.path.exists(p('out.json')):
            with open(p('out.json'), encoding='utf-8') as f:
                merged = json.load(f)
        return code, out.getvalue() + err.getvalue(), merged

    def test_old_reality_key_and_ports_carry_over(self):
        code, text, merged = self.run_tool(self.config())
        self.assertEqual(code, 0, text)
        s = merged['settings']
        self.assertEqual((s['reality_private_key'], s['reality_public_key'], s['reality_short_id'], s['reality_target']),
                         (self.private, self.public, '0123456789abcdef', 'www.example.org'))
        self.assertEqual((s['reality_port'], s['hy2_port'], s['hy2_hop'], s['hy2_hop_range'], s['tuic_port']),
                         (443, 443, True, '20000-25999', 8443))
        self.assertIn('Reality 不用更新', text)
        db.import_all(merged)
        here = db.settings()
        self.assertEqual((here['reality_public_key'], here['reality_short_id']), (self.public, '0123456789abcdef'))
        u = db.user_by_name(merged['users'][0]['name'])
        self.assertIn(self.public, subscription.clash_yaml(here, u, 'https://192.0.2.1:8443'))
        self.assertIn('0123456789abcdef', subscription.clash_yaml(here, u, 'https://192.0.2.1:8443'))

    def test_a_config_without_a_usable_key_is_refused(self):
        for bad in ({'private_key': 'short'}, {'enabled': False}, {'short_id': ['not-hex!']},
                    {'handshake': {'server': 'not a host'}}):
            with self.subTest(bad=bad):
                cfg = self.config(**bad)
                if 'handshake' in bad:
                    cfg['inbounds'][0]['tls']['server_name'] = ''
                code, text, merged = self.run_tool(cfg)
                self.assertEqual((code, merged), (2, None), text)
        code, text, merged = self.run_tool({'nothing': 1})
        self.assertEqual((code, merged), (2, None))
