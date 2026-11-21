"""Tests for the features ported from the original console: member centre, invite codes, quota requests,
per-user history, server monthly traffic, site monitor, abuse watch, Shadowrocket config, several servers.

    python -m unittest tests.test_unit tests.test_features
"""
import base64
import hashlib
import http.client
import io
import json
import os
import socket
import sqlite3
import ssl
import tempfile
import threading
import time
import unittest
import urllib.parse
import zlib
import unittest.mock
from unittest import mock

from tests import test_unit as tu          # sets VPS2VPN_ROOT / dev mode first
from vps2vpn import abuse, certs, cluster, cores, db, jobs, members, monitor, paths, rules, secure, subscription, system, web

GIB = 1 << 30


def mk(name, quota=0, **kv):
    uid = db.add_user(name, quota)
    if kv:
        db.update_user(uid, **kv)
    return db.user(uid)


class CachedTelemetry(tu.Base):
    def test_ai_cache_rejects_malformed_status_and_metadata(self):
        from vps2vpn import aicheck
        paths.ensure_dirs()
        valid = {
            'at': 123, 'country': 'US', 'ip': {},
            'sites': {key: {'status': 'ok'} for key in aicheck.SITES},
        }
        bad_cases = [
            dict(valid, sites={**valid['sites'], 'claude': {'status': []}}),
            dict(valid, sites={**valid['sites'], 'claude_api': {'status': {}}}),
            dict(valid, sites={**valid['sites'], 'gemini': {'status': 'unexpected'}}),
            dict(valid, sites={**valid['sites'], 'chatgpt': {}}),
            dict(valid, ip=['not-an-object']),
            dict(valid, ip={'city': ['Austin']}),
            dict(valid, ip={'country': ['US']}),
            dict(valid, ip={'city': {'name': 'Austin'}}),
            dict(valid, country=['US']),
        ]
        for bad in bad_cases:
            paths.write_atomic(aicheck.FILE, json.dumps(bad))
            self.assertIsNone(aicheck.latest(), bad)
        paths.write_atomic(aicheck.FILE, json.dumps(valid))
        self.assertEqual(aicheck.latest(), valid)
        self.assertIn('Claude', aicheck.summary(aicheck.latest()))
        # An absent/null city from ipinfo is allowed; valid location text is
        # safe to look up and display after the cache validation.
        with_city = dict(valid, ip={'city': 'Tokyo', 'country': 'JP'})
        paths.write_atomic(aicheck.FILE, json.dumps(with_city))
        self.assertEqual(aicheck.place_name(aicheck.latest()), '东京')
        with_null = dict(valid, ip={'city': None, 'country': None})
        paths.write_atomic(aicheck.FILE, json.dumps(with_null))
        self.assertEqual(aicheck.place_name(aicheck.latest()), '美国')

    def test_monitor_recovers_from_non_array_and_skips_corrupt_rows(self):
        paths.ensure_dirs()
        good = {'at': 123, 'v6': False,
                'sites': {'github/4': {'ok': True, 'total': 12.5}},
                'speed': {'ok': True, 'at': 123, 'mbps': 32.0}}
        broken = [
            42, None, {'at': 123}, {'at': 123, 'sites': []},
            {'at': 123, 'sites': {'github/4': {'ok': []}}},
            {'at': 123, 'sites': {'github/4': {'ok': True, 'total': 'slow'}}},
            {'at': 123, 'sites': {}, 'speed': ['bad']},
            {'at': 123, 'sites': {}, 'speed': {'at': 'yesterday'}},
        ]
        for document, expected in (({'sites': []}, []), (broken, []),
                                   (broken + [good], [good])):
            paths.write_atomic(monitor.FILE, json.dumps(document))
            monitor._hist = None
            self.assertEqual(monitor.history(), expected)
            report = monitor.summary()
            self.assertEqual(report['latest']['at'] if expected else None,
                             123 if expected else None)
        self.assertEqual(monitor.summary()['sites'][0]['v4']['median_ms'], 12.5)


class TrustAndRouting(tu.Base):
    def test_untrusted_chain_does_not_satisfy_public_ca_predicate(self):
        paths.ensure_dirs()
        with open(paths.ACME_CRT, 'wb') as out:
            out.write(b'placeholder certificate')
        with open(paths.ACME_KEY, 'wb') as out:
            out.write(b'placeholder private key')
        certs._trust_cache.clear()
        self.addCleanup(certs._trust_cache.clear)
        with mock.patch.object(certs, 'acme_valid', return_value=True), \
             mock.patch.object(certs, 'acme_names', return_value=['vpn.example']), \
             mock.patch.object(certs, '_openssl', side_effect=RuntimeError('not CA trusted')) as verify:
            self.assertFalse(certs.trusted('vpn.example'))
            self.assertFalse(certs.trusted('vpn.example'))
            self.assertEqual(verify.call_count, 1)

    def test_public_ip_probe_rejects_private_answers(self):
        def answer(text):
            return io.BytesIO(('ip=' + text + '\n').encode())
        with mock.patch.object(system.urllib.request, 'urlopen',
                               side_effect=lambda *a, **kw: answer('127.0.0.1')):
            self.assertEqual(system.public_ip(), '')
        with mock.patch.object(system.urllib.request, 'urlopen',
                               side_effect=lambda *a, **kw: answer('8.8.8.8')):
            self.assertEqual(system.public_ip(), '8.8.8.8')
        with mock.patch.object(system.urllib.request, 'urlopen',
                               side_effect=lambda *a, **kw: answer('2001:4860:4860::8888')):
            self.assertEqual(system.public_ip(v6=True), '2001:4860:4860::8888')

    def test_xray_resolves_sniffed_names_before_the_private_address_block(self):
        # Sniffed names stay the destination: clients that resolve locally (redir-host, polluted DNS) would
        # otherwise send Google & co. to wrong addresses. A spoofed name is resolved on the server and still
        # hits the private-address block first.
        config = cores.xray_config(db.settings(), [])
        self.assertEqual(config['routing']['domainStrategy'], 'IPIfNonMatch')
        self.assertEqual(config['inbounds'][0]['sniffing']['destOverride'], ['http', 'tls', 'quic'])
        self.assertEqual(config['routing']['rules'][0]['ip'], ['geoip:private'])
        self.assertEqual(config['routing']['rules'][0]['outboundTag'], 'block')


class Invites(tu.Base):
    def test_admin_code_register(self):
        rec = members.create_invite('admin', 50, 7, max_uses=2, expire_days=30, reset_day=5, note='team')
        self.assertRegex(rec['code'], r'^[A-Z2-9]{5}-[A-Z2-9]{5}$')
        uid = members.register(rec['code'].lower().replace('-', ' '), '新人', 'password123')   # forgiving input
        u = db.user(uid)
        self.assertEqual((u['quota_gb'], u['reset_day']), (50, 5))
        self.assertAlmostEqual(u['expire_at'], time.time() + 30 * 86400, delta=60)
        self.assertTrue(secure.check_password('password123', u['login_hash']))
        with self.assertRaises(members.Refused):
            members.register(rec['code'], '新人', 'password123')           # name taken
        members.register(rec['code'], 'second', 'password123')
        with self.assertRaises(members.Refused):
            members.register(rec['code'], 'third', 'password123')          # used up (2 uses)
        self.assertEqual(db.invite(rec['id'])['status'], 'used')

    def test_member_code_carves_quota(self):
        alice = mk('alice', 10)
        self.assertEqual(members.capacity(alice), 9.0)                    # always keeps 1 GB
        with self.assertRaises(members.Refused):
            members.create_invite('member', 5, 7, max_uses=2, inviter=alice['id'], by_member=True)   # 10 > 9
        rec = members.create_invite('member', 3, 7, max_uses=2, inviter=alice['id'], by_member=True)
        self.assertEqual(members.capacity(db.user(alice['id'])), 3.0)    # 6 GB promised
        bob = members.register(rec['code'], 'bob', 'password123')
        self.assertEqual(db.user(bob)['invited_by'], alice['id'])
        self.assertEqual(members.effective_quota(db.user(alice['id'])), 7.0)
        self.assertEqual(members.capacity(db.user(alice['id'])), 3.0)    # still 3 (one use left on the code)
        # alice's effective quota is what enforcement uses
        db.update_user(alice['id'], used_down=int(7.5 * GIB))
        jobs.enforce()
        self.assertEqual(db.user(alice['id'])['disabled_reason'], 'quota')
        # bob paused -> alice gets her share back (and is re-enabled by the next enforcement)
        db.update_user(bob, enabled=0, disabled_reason='manual')
        jobs.enforce()
        self.assertTrue(db.user(alice['id'])['enabled'])
        # unlimited accounts cannot carve
        carol = mk('carol', 0)
        self.assertIsNone(members.capacity(carol))
        with self.assertRaises(members.Refused):
            members.create_invite('member', 1, 7, inviter=carol['id'], by_member=True)

    def test_pending_limit_and_revoke(self):
        a = mk('a', 100)
        codes = [members.create_invite('member', 1, 7, inviter=a['id'], by_member=True) for _ in range(5)]
        with self.assertRaises(members.Refused):
            members.create_invite('member', 1, 7, inviter=a['id'], by_member=True)
        other = mk('other', 100)
        with self.assertRaises(members.Refused):
            members.revoke_invite(codes[0]['id'], by_member=other['id'])  # not theirs
        members.revoke_invite(codes[0]['id'], by_member=a['id'])
        with self.assertRaises(members.Refused):
            members.register(codes[0]['code'], 'late', 'password123')
        members.create_invite('member', 1, 7, inviter=a['id'], by_member=True)    # room again

    def test_requests(self):
        u = mk('dave', 10, enabled=0, disabled_reason='quota', used_down=11 * GIB)
        rid = members.request_more(u['id'], 20, 'exams')
        with self.assertRaises(members.Refused):
            members.request_more(u['id'], 5, 'again')                       # one at a time
        members.decide(rid, True, add_gb=15)
        u = db.user(u['id'])
        self.assertEqual((u['quota_gb'], u['enabled']), (25, 1))
        self.assertEqual(db.requests(u['id'])[0]['add_gb'], 15)
        rid = members.request_more(u['id'], 5, '')
        members.decide(rid, False, answer='not now')
        self.assertEqual(db.requests(u['id'])[0]['status'], 'rejected')
        with self.assertRaises(members.Refused):
            members.decide(rid, True)

    def test_too_small_approval_does_not_switch_back_on(self):
        u = mk('erin', 10, enabled=0, disabled_reason='quota', used_down=14 * GIB)
        rid = members.request_more(u['id'], 2, '')
        members.decide(rid, True)                                          # 12 GB < 14 GB used
        u = db.user(u['id'])
        self.assertEqual((u['quota_gb'], u['enabled'], u['disabled_reason']), (12, 0, 'quota'))
        rid = members.request_more(u['id'], 5, '')
        members.decide(rid, True)                                          # 17 GB covers it
        self.assertEqual(db.user(u['id'])['enabled'], 1)

    def test_invitee_of_an_unstarted_account_gets_its_own_countdown(self):
        a = mk('fay', 20, expire_after_days=30)                            # clock not started
        rec = members.create_invite('member', 2, 7, inviter=a['id'], by_member=True)
        b = members.register(rec['code'], 'gus', 'password123')
        self.assertEqual((db.user(b)['expire_at'], db.user(b)['expire_after_days']), (0, 30))
        db.update_user(b, used_down=GIB)                                   # the invitee connects first
        jobs.enforce()
        self.assertAlmostEqual(db.user(b)['expire_at'], time.time() + 30 * 86400, delta=60)
        db.update_user(a['id'], used_down=GIB)                             # later the inviter starts too
        jobs.enforce()
        self.assertEqual(db.user(b)['expire_at'], db.user(a['id'])['expire_at'])

    def test_delete_inviter_cleans_up(self):
        a = mk('a', 20)
        rec = members.create_invite('member', 2, 7, max_uses=3, inviter=a['id'])
        b = members.register(rec['code'], 'bee', 'password123')
        db.delete_user(a['id'])
        self.assertEqual(db.invite(rec['id'])['status'], 'revoked')
        self.assertEqual(db.user(b)['invited_by'], 0)


class Storage(tu.Base):
    def test_migration_adds_columns(self):
        db.close()
        os.remove(paths.DB)
        c = sqlite3.connect(paths.DB)                 # a database from the first release
        try:
            c.executescript('CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE, uuid TEXT NOT NULL,'
                            'hy2_pass TEXT NOT NULL, sub_token TEXT NOT NULL UNIQUE, quota_gb REAL NOT NULL DEFAULT 0,'
                            'expire_at INTEGER NOT NULL DEFAULT 0, reset_day INTEGER NOT NULL DEFAULT 0, used_up INTEGER NOT NULL DEFAULT 0,'
                            'used_down INTEGER NOT NULL DEFAULT 0, enabled INTEGER NOT NULL DEFAULT 1, disabled_reason TEXT NOT NULL DEFAULT "",'
                            'note TEXT NOT NULL DEFAULT "", last_seen INTEGER NOT NULL DEFAULT 0, last_reset TEXT NOT NULL DEFAULT "",'
                            'created_at INTEGER NOT NULL);'
                            "INSERT INTO users(name, uuid, hy2_pass, sub_token, created_at) VALUES('old', 'u', 'p', 'tok', 1);")
            c.commit()
        finally:
            c.close()
        u = db.users()[0]
        self.assertEqual((u['name'], u['login_hash'], u['invited_by'], u['remote_id']), ('old', '', 0, 0))

    def test_backup_keeps_invites_and_ids(self):
        a = mk('a', 10)
        db.delete_user(mk('gap')['id'])
        b = mk('b', 10)
        members.create_invite('admin', 5, 7)
        data = json.loads(json.dumps(db.export_all()))
        db.delete_user(a['id'])
        db.import_all(data)
        self.assertEqual([u['id'] for u in db.users()], [a['id'], b['id']])  # ids survive (history, invites refer to them)
        self.assertEqual(len(db.invites()), 1)

    def test_user_history(self):
        a = mk('a')
        db.add_traffic(a['id'], 100, 1000, now=time.time() - 86400)
        db.add_traffic(a['id'], 1, 2)
        db.add_traffic(mk('b')['id'], 5, 5)
        h = db.user_traffic(a['id'])
        self.assertEqual([(x['up'], x['down']) for x in h], [(100, 1000), (1, 2)])


class ScaleHelpers(tu.Base):
    """Helpers that keep the panel fast with hundreds of users must give the same answers as the slow paths."""

    def chain(self):
        root = mk('root', 100)
        a = mk('a', 20, invited_by=root['id'], invite_deduct=20)
        b = mk('b', 10, invited_by=a['id'], invite_deduct=10)
        c = mk('c', 5, invited_by=b['id'], invite_deduct=5, enabled=0, disabled_reason='manual')
        d = mk('d', 8, invited_by=root['id'], invite_deduct=8, expire_at=int(time.time()) - 10)
        e = mk('e', 3, invited_by=d['id'], invite_deduct=3)          # active below an expired one: still counts
        other = mk('other', 50)
        mk('stranger', 4, invited_by=other['id'], invite_deduct=4)
        return root, a, b, c, d, e, other

    def test_invite_tree_is_the_whole_subtree_only(self):
        root, a, b, c, d, e, other = self.chain()
        self.assertEqual([u['id'] for u in db.invite_tree(root['id'])], sorted([a['id'], b['id'], c['id'], d['id'], e['id']]))
        self.assertEqual([u['id'] for u in db.invite_tree(b['id'])], [c['id']])
        self.assertEqual(db.invite_tree(c['id']), [])
        self.assertEqual(db.invite_tree(999999), [])
        self.assertEqual(db.invite_tree(root['id'])[0]['name'], 'a')          # full rows
        self.assertEqual([u['id'] for u in db.users_invited_by(root['id'])], [a['id'], d['id']])

    def test_invite_tree_stops_on_a_loop(self):
        x = mk('x', 10)
        y = mk('y', 10, invited_by=x['id'], invite_deduct=2)
        db.update_user(x['id'], invited_by=y['id'], invite_deduct=2)          # damaged data: a cycle
        self.assertEqual(sorted(u['id'] for u in db.invite_tree(x['id'])), sorted([x['id'], y['id']]))
        self.assertEqual(members.given_away(x['id']), members.given_away(x['id'], db.users()))

    def test_tree_index_and_full_list_agree(self):
        users_before = self.chain()
        all_users = db.users()
        index = members.invitee_index(all_users)
        now = time.time()
        for u in all_users:
            full = members.effective_quota(u, all_users, now)
            self.assertEqual(members.effective_quota(u, now=now), full, u['name'])
            self.assertEqual(members.effective_quota(u, now=now, index=index), full, u['name'])
            self.assertEqual(members.given_away(u['id'], now=now), members.given_away(u['id'], all_users, now))
        root = users_before[0]
        self.assertEqual(members.given_away(root['id']), 20 + 3)               # a deducts 20; d expired -> e's 3
        self.assertEqual(members.effective_quota(db.user(root['id'])), 77)

    def test_ids_and_names(self):
        a, b = mk('a'), mk('名字')
        self.assertEqual(db.user_ids(), {a['id'], b['id']})
        self.assertEqual(db.user_names(), {a['id']: 'a', b['id']: '名字'})

    def test_add_traffic_many_matches_single_adds(self):
        a, b = mk('a'), mk('b')
        db.add_traffic_many([(a['id'], 1, 2), (b['id'], 3, 4), (a['id'], 10, 20)], now=time.time())
        db.add_traffic_many([])
        self.assertEqual((db.user(a['id'])['used_up'], db.user(a['id'])['used_down']), (11, 22))
        self.assertEqual([(x['up'], x['down']) for x in db.user_traffic(b['id'])], [(3, 4)])
        self.assertGreater(db.user(b['id'])['last_seen'], 0)

    def test_save_traffic_writes_known_users_in_one_go(self):
        a = mk('a')
        with mock.patch.object(cores, 'collect_traffic', return_value={a['id']: (5, 6), 424242: (1, 1), a['id'] + 1000: (0, 0)}):
            self.assertEqual(cores.save_traffic(db.settings()), [(a['id'], 5, 6)])
        self.assertEqual(db.user(a['id'])['used_down'], 6)

    def test_indexes_used_by_hot_queries_exist(self):
        have = {r['name'] for r in db.q("SELECT name FROM sqlite_master WHERE type='index'")}
        for name in ('idx_users_invited_by', 'idx_users_remote_id', 'idx_traffic_user_day', 'idx_events_kind_id',
                     'idx_invites_inviter_status', 'idx_requests_user_status'):
            self.assertIn(name, have)
        plan = ' '.join(str(tuple(r)) for r in db.q(
            'EXPLAIN QUERY PLAN WITH RECURSIVE tree(id) AS (SELECT id FROM users WHERE invited_by=? '
            'UNION SELECT u.id FROM users u JOIN tree t ON u.invited_by=t.id) SELECT id FROM tree', (1,)))
        self.assertIn('idx_users_invited_by', plan)

    def test_acme_names_cached_until_the_file_changes(self):
        certs._names_cache.clear()
        if os.path.exists(paths.ACME_CRT):
            os.remove(paths.ACME_CRT)
        with mock.patch.object(certs, '_openssl', return_value=b'DNS:a.example') as run:
            self.assertEqual(certs.acme_names(), [])                          # no file: openssl not started
            self.assertEqual(run.call_count, 0)
            os.makedirs(os.path.dirname(paths.ACME_CRT), exist_ok=True)
            with open(paths.ACME_CRT, 'w') as f:
                f.write('one')
            self.assertEqual(certs.acme_names(), ['a.example'])
            self.assertEqual(certs.acme_names(), ['a.example'])
            self.assertEqual(run.call_count, 1)
            run.return_value = b'DNS:b.example, IP Address:203.0.113.9'
            with open(paths.ACME_CRT, 'w') as f:
                f.write('second')                                             # renewed (size and time change)
            self.assertEqual(certs.acme_names(), ['b.example', '203.0.113.9'])
            self.assertEqual(run.call_count, 2)
        with mock.patch.object(certs, '_openssl', side_effect=RuntimeError('bad')):
            with open(paths.ACME_CRT, 'w') as f:
                f.write('broken file')
            self.assertEqual(certs.acme_names(), [])
        os.remove(paths.ACME_CRT)
        certs._names_cache.clear()


class ServerMonth(tu.Base):
    def test_counts_across_reboot_and_period(self):
        s = db.settings()
        t0 = time.mktime((2026, 3, 10, 12, 0, 0, 0, 0, -1))
        jobs.server_month(s, {'rx_total': 1000, 'tx_total': 5000}, t0)            # first look: baseline only
        rec = jobs.server_month(db.settings(), {'rx_total': 1500, 'tx_total': 9000}, t0 + 60)
        self.assertEqual((rec['rx'], rec['tx'], rec['period']), (500, 4000, '2026-03-01'))
        rec = jobs.server_month(db.settings(), {'rx_total': 200, 'tx_total': 300}, t0 + 120)   # rebooted
        self.assertEqual((rec['rx'], rec['tx']), (700, 4300))
        db.set_settings(server_reset_day=15)
        rec = jobs.server_month(db.settings(), {'rx_total': 300, 'tx_total': 400}, t0 + 6 * 86400)   # March 16
        self.assertEqual((rec['period'], rec['rx'], rec['tx']), ('2026-03-15', 100, 100))
        self.assertEqual(jobs.period_of(time.mktime((2026, 1, 3, 0, 0, 0, 0, 0, -1)), 15), '2025-12-15')


    def test_an_interface_going_away_is_not_a_reboot(self):
        s = db.settings()
        t0 = time.mktime((2026, 3, 10, 12, 0, 0, 0, 0, -1))
        h = lambda ifs: {'rx_total': sum(v[0] for v in ifs.values()), 'tx_total': sum(v[1] for v in ifs.values()),
                         'net_ifaces': ifs}
        jobs.server_month(s, h({'eth0': [10 << 30, 20 << 30], 'wg0': [5 << 30, 5 << 30]}), t0)
        rec = jobs.server_month(db.settings(), h({'eth0': [11 << 30, 21 << 30]}), t0 + 60)   # wg0 went down
        self.assertEqual((rec['rx'], rec['tx']), (1 << 30, 1 << 30))
        rec = jobs.server_month(db.settings(), h({'eth0': [12 << 30, 22 << 30], 'wg0': [100, 200]}), t0 + 120)
        self.assertEqual((rec['rx'], rec['tx']), ((2 << 30) + 100, (2 << 30) + 200))
        rec = jobs.server_month(db.settings(), h({'eth0': [1000, 2000]}), t0 + 180)             # rebooted
        self.assertEqual((rec['rx'], rec['tx']), ((2 << 30) + 1100, (2 << 30) + 2200))

    def test_upgrade_from_summed_counters_continues(self):
        s = db.settings()
        t0 = time.mktime((2026, 3, 10, 12, 0, 0, 0, 0, -1))
        jobs.server_month(s, {'rx_total': 1000, 'tx_total': 5000}, t0)
        rec = jobs.server_month(db.settings(), {'rx_total': 1500, 'tx_total': 5500,
                                                'net_ifaces': {'eth0': [1500, 5500]}}, t0 + 60)
        self.assertEqual((rec['rx'], rec['tx']), (500, 500))

    def test_only_physical_nics_are_billed(self):
        dev = ('Inter-|   Receive\n face |bytes\n'
               '    lo: 900 0 0 0 0 0 0 0 900 0 0 0 0 0 0 0\n'
               '  eth0: 100 0 0 0 0 0 0 0 200 0 0 0 0 0 0 0\n'
               'docker0: 50 0 0 0 0 0 0 0 60 0 0 0 0 0 0 0\n'
               'veth1a: 50 0 0 0 0 0 0 0 60 0 0 0 0 0 0 0\n')
        virtual = lambda n: n != 'eth0'
        self.assertEqual(system.net_counters(dev, virtual), {'eth0': [100, 200]})
        # a container sees only virtual links: then those are its traffic
        self.assertEqual(system.net_counters(dev, lambda n: True),
                         {'eth0': [100, 200], 'docker0': [50, 60], 'veth1a': [50, 60]})


class Abuse(tu.Base):
    def test_flags(self):
        flows = [(1, 'h%d.example' % i, 1000 + i % 40) for i in range(250)] + [(2, 'a.com', 443)] * 300 + \
                [(3, 'mx%d.example' % i, 25) for i in range(30)]
        rep = abuse.aggregate(flows, {4: {'ips': ['10.0.0.%d' % i for i in range(9)]}, 2: {'ips': ['1.1.1.1']}})
        self.assertEqual(rep[1]['flags'], ['fanout'])
        self.assertEqual(rep[2]['flags'], [])                  # many streams to one site is normal
        self.assertEqual(rep[3]['flags'], ['mail'])
        self.assertEqual(rep[4]['flags'], ['shared'])
        # one phone rotating IPv6 privacy addresses (the cores count it as one device) is not a shared link
        v6 = ['2001:db8:5:6::%x' % i for i in range(1, 12)]
        self.assertEqual(abuse.aggregate([], {5: {'ips': v6, 'devices': cores.device_estimate(v6)}})[5]['flags'], [])
        self.assertEqual(abuse.split_addr('[2001:db8::1]:443'), ('2001:db8::1', 443))
        self.assertIsNone(abuse.split_addr('nonsense'))

    def test_invalid_stream_addresses_are_not_ports(self):
        for value in ('host:' + '9' * 5000, 'host:４４３', 'host:0',
                      'host:65536', '[::1]:' + '1' * 10000, 'host:+80'):
            self.assertIsNone(abuse.split_addr(value))
        self.assertEqual(abuse.split_addr('host:65535'), ('host', 65535))

    def test_malformed_hysteria_stream_does_not_discard_valid_records(self):
        s = dict(db.settings(), hy2_enabled=True, tuic_enabled=False, reality_enabled=False)
        records = [
            None, {'auth': 42, 'req_addr': 'wrong.example:443'},
            {'auth': 'u' + '9' * 5000, 'req_addr': 'wrong.example:443'},
            {'auth': 'u2', 'req_addr': 'wrong.example:' + '8' * 5000},
            {'auth': 'u7', 'req_addr': 'valid.example:443'},
        ]
        with unittest.mock.patch.object(abuse, '_hy2_streams', return_value=records), \
             unittest.mock.patch.object(abuse.cores, 'online_detail', return_value={}):
            report = abuse.scan(s)
        self.assertEqual(report[7]['streams'], 1)
        self.assertEqual(report[7]['targets'], 1)
        self.assertEqual(abuse.latest()['coverage'], ['hy2'])

    def test_invalid_tuic_container_does_not_drop_valid_hysteria(self):
        s = dict(db.settings(), hy2_enabled=True, tuic_enabled=True,
                 reality_enabled=False)
        streams = [{'auth': 'u7', 'req_addr': 'valid.example:443'}]
        for malformed in (None, [], {'connections': 'broken'}, {'connections': 42}):
            with self.subTest(malformed=malformed):
                with mock.patch.object(abuse, '_hy2_streams', return_value=streams):
                    with mock.patch.object(abuse.cores.TuicMeter, 'poll', return_value=malformed):
                        with mock.patch.object(abuse.cores, 'online_detail', return_value={}):
                            result = abuse.scan(s)
                self.assertEqual(result[7]['streams'], 1)
                self.assertEqual(abuse.latest()['coverage'], ['hy2'])

    def test_invalid_hysteria_container_does_not_drop_valid_tuic(self):
        s = dict(db.settings(), hy2_enabled=True, tuic_enabled=True,
                 reality_enabled=False)
        conn = {'metadata': {'destinationPort': 443, 'host': 'valid.example'},
                'chains': ['u7']}
        for malformed in (None, {}, {'not': 'a list'}, 'bad'):
            with self.subTest(malformed=malformed):
                with mock.patch.object(abuse, '_hy2_streams', return_value=malformed):
                    with mock.patch.object(abuse.cores.TuicMeter, 'poll',
                                           return_value={'connections': [conn]}):
                        with mock.patch.object(abuse.cores, 'online_detail', return_value={}):
                            result = abuse.scan(s)
                self.assertEqual(result[7]['streams'], 1)
                self.assertEqual(abuse.latest()['coverage'], ['tuic'])


    def test_malformed_tuic_connection_does_not_discard_valid_records(self):
        s = dict(db.settings(), hy2_enabled=False, tuic_enabled=True, reality_enabled=False)
        records = [
            None, {'metadata': {'destinationPort': '443'}, 'chains': [5]},
            {'metadata': {'destinationPort': '４４３'}, 'chains': ['u7']},
            {'metadata': {'destinationPort': '443'}, 'chains': ['u' + '9' * 5000]},
            {'metadata': {'destinationPort': '443', 'host': ['bad.example']}, 'chains': ['u7']},
            {'metadata': {'destinationPort': '443', 'destinationIP': {'bad': 'value'}}, 'chains': ['u7']},
            {'metadata': {'destinationPort': 443, 'host': 'valid.example'}, 'chains': ['u7']},
        ]
        with unittest.mock.patch.object(abuse.cores.TuicMeter, 'poll', return_value={'connections': records}), \
             unittest.mock.patch.object(abuse.cores, 'online_detail', return_value={}):
            report = abuse.scan(s)
        self.assertEqual(report[7]['streams'], 1)
        self.assertEqual(report[7]['targets'], 1)
        self.assertEqual(abuse.latest()['coverage'], ['tuic'])



class HistoryCache(tu.Base):
    def test_non_array_json_cannot_abort_history_initialization(self):
        path = os.path.join(paths.VAR, 'bad-history.json')
        for payload in ('null', 'true', '123', '{"points": []}'):
            with self.subTest(payload=payload):
                with open(path, 'w', encoding='utf-8') as f:
                    f.write(payload)
                self.assertEqual(jobs.History(path=path).snapshot(), [])

    def test_corrupted_five_field_records_cannot_reach_charts(self):
        path = os.path.join(paths.VAR, 'corrupted-history.json')
        valid = [1000, 15.0, None, 12, 13]
        invalid = [
            [None, 15, 40, 12, 13],
            [True, 15, 40, 12, 13],
            [1000, {'bad': 'cpu'}, 40, 12, 13],
            [1000, 15, 'oops', 12, 13],
            [1000, 15, 40, [-1], 13],
            [1000, 15, 40, -3, 13],
            [1000, 150, 40, 12, 13],
            [1000, float('nan'), 40, 12, 13],
            [1000, 15, 40, 1 << 5000, 13],
            [1 << 5000, 15, 40, 12, 13],
        ]
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(invalid + [valid], f)
        self.assertEqual(jobs.History(path=path).snapshot(), [valid])

    def test_valid_list_keeps_only_five_field_samples(self):
        path = os.path.join(paths.VAR, 'mixed-history.json')
        good = [1000, 15.0, 40.0, 12, 13]
        with open(path, 'w', encoding='utf-8') as f:
            json.dump([[], good, None, [1, 2, 3]], f)
        self.assertEqual(jobs.History(path=path).snapshot(), [good])


class Monitor(tu.Base):
    def test_summary(self):
        monitor._hist = []
        for i in range(3):
            monitor._append({'at': 1000 + i, 'v6': False, 'region': 'SG', 'chatgpt_region_ok': True,
                             'speed': {'ok': True, 'mbps': 300 + i},
                             'sites': {'github/4': {'ok': i != 1, 'total': 100.0 + i}, 'chatgpt/4': {'ok': True, 'total': 50.0}}})
        sm = monitor.summary()
        gh = next(x for x in sm['sites'] if x['id'] == 'github')
        self.assertAlmostEqual(gh['v4']['uptime'], 2 / 3, places=3)
        self.assertEqual(gh['v4']['spark'], [100.0, None, 102.0])
        self.assertEqual(sm['latest']['region'], 'SG')
        with open(monitor.FILE, encoding='utf-8') as f:
            self.assertEqual(len(json.load(f)), 3)


# Real zstd frame generated from the bytes b'MRS\\x01fixture'. This verifies outer
# framing only; parsing a full rule set remains the responsibility of the core.
MRS_ZSTD_FRAME = bytes.fromhex('28b52ffd04585900004d525301666978747572659fb54dd4')


class RuleMirrorDownloads(tu.Base):
    def test_actual_compressed_mrs_frame_is_accepted_but_inner_marker_is_not(self):
        # The real frame was made with zstd(b'MRS\\x01fixture'); the MRS version byte is INSIDE it.
        with mock.patch.object(rules, '_fetch', return_value=MRS_ZSTD_FRAME) as fetch:
            self.assertEqual(rules.fetch_converted('private', 'clash'), MRS_ZSTD_FRAME)
            fetch.assert_called_once()
        with mock.patch.object(rules, '_fetch', side_effect=[b'MRS\x01uncompressed', MRS_ZSTD_FRAME]) as fetch:
            self.assertEqual(rules.fetch_converted('private', 'clash'), MRS_ZSTD_FRAME)
            self.assertEqual(fetch.call_count, 2)

    def test_singbox_srs_frame_is_accepted_after_plaintext_error(self):
        valid = b'SRS\x01' + zlib.compress(b'\x00')  # SRS version 1; empty compressed rules
        with mock.patch.object(rules, '_fetch',
                               side_effect=[b'Access denied: upstream temporary failure', valid]) as fetch:
            self.assertEqual(rules.fetch_converted('private', 'singbox'), valid)
            self.assertEqual(fetch.call_count, 2)
        with mock.patch.object(rules, '_fetch', return_value=valid) as fetch:
            self.assertEqual(rules.fetch_converted('private', 'singbox'), valid)
            self.assertEqual(fetch.call_count, 1)

    def test_binary_magic_prefix_alone_never_wins_the_rule_mirror_fallback(self):
        srs = b'SRS\x05' + zlib.compress(b'\x00')
        malformed = {
            'clash': [rules.MRS_ZSTD_MAGIC + b'Gateway timeout' * 4,
                      MRS_ZSTD_FRAME[:-1],
                      MRS_ZSTD_FRAME + b'<html>trailing error</html>'],
            'singbox': [b'SRS' + b'502 Bad Gateway' * 4,
                        b'SRS\x00' + zlib.compress(b'\x00'),
                        srs[:-1],
                        srs + b'<html>trailing error</html>'],
        }
        for fmt, broken_list in malformed.items():
            good = MRS_ZSTD_FRAME if fmt == 'clash' else srs
            for broken in broken_list:
                with self.subTest(fmt=fmt, broken=broken[:16]):
                    with mock.patch.object(rules, '_fetch', side_effect=[broken, good]) as fetch:
                        self.assertEqual(rules.fetch_converted('private', fmt), good)
                        self.assertEqual(fetch.call_count, 2)

    def test_srs_rejects_invalid_checksum_and_decompression_bombs(self):
        valid = b'SRS\x05' + zlib.compress(b'\x00')
        corrupt = bytearray(valid)
        corrupt[-1] ^= 0xff              # bad Adler-32 checksum
        with mock.patch.object(rules, '_fetch', side_effect=[bytes(corrupt), valid]):
            self.assertEqual(rules.fetch_converted('private', 'singbox'), valid)
        # A valid highly compressible rule set can require several
        # decompress(..., max_length=1MiB) calls from ONE tiny input chunk.
        # Do not mistake the shortened unconsumed_tail for trailing garbage.
        expanded = b'SRS\x05' + zlib.compress(b'x' * (3 << 20))
        with mock.patch.object(rules, '_fetch', return_value=expanded):
            self.assertEqual(rules.fetch_converted('private', 'singbox'), expanded)
        bomb = b'SRS\x05' + zlib.compress(b'x' * 10000)
        with mock.patch.object(rules, 'MAX_SRS_DECODE_BYTES', 1024), \
             mock.patch.object(rules, '_fetch', side_effect=[bomb, valid]) as fetch:
            self.assertEqual(rules.fetch_converted('private', 'singbox'), valid)
            self.assertEqual(fetch.call_count, 2)

    def test_invalid_binary_frames_never_replace_working_rule_files(self):
        paths.ensure_dirs()
        old = {'clash': MRS_ZSTD_FRAME,
               'singbox': b'SRS\x05' + zlib.compress(b'\x00')}
        for fmt, payload in old.items():
            paths.write_atomic(rules.local_file('private', fmt), payload, 0o644)
        with mock.patch.object(rules, 'SETS', {'private': ('geosite', 'private')}), \
             mock.patch.object(rules, 'FORMATS', ('clash', 'singbox')), \
             mock.patch.object(rules, '_fetch', return_value=b'SRS\x05broken' + b'x' * 20):
            self.assertEqual(rules.refresh(), 0)
        for fmt, payload in old.items():
            with open(rules.local_file('private', fmt), 'rb') as source:
                self.assertEqual(source.read(), payload)

    def test_plaintext_200_errors_never_replace_cached_mrs_or_srs(self):
        paths.ensure_dirs()
        old = {
            'clash': MRS_ZSTD_FRAME,
            'singbox': b'SRS\x01' + zlib.compress(b'\x00'),
        }
        for fmt, payload in old.items():
            paths.write_atomic(rules.local_file('private', fmt), payload, 0o644)
        logs = []
        with mock.patch.object(rules, 'SETS', {'private': ('geosite', 'private')}), \
             mock.patch.object(rules, 'FORMATS', ('clash', 'singbox')), \
             mock.patch.object(rules, '_fetch',
                               return_value=b'Access denied: upstream temporary failure'):
            self.assertEqual(rules.refresh(log=logs.append), 0)
        for fmt, payload in old.items():
            with open(rules.local_file('private', fmt), 'rb') as f:
                self.assertEqual(f.read(), payload)
        self.assertEqual(sum('download failed' in line for line in logs), 2)

    def test_shadowrocket_text_conversion_remains_supported(self):
        with mock.patch.object(rules, '_fetch', return_value=b'+.example.org\n'):
            self.assertEqual(rules.fetch_converted('private', 'shadowrocket'),
                             b'DOMAIN-SUFFIX,example.org\n')


    def test_oversized_download_rejected_and_old_mirror_retained(self):
        paths.ensure_dirs()
        old = MRS_ZSTD_FRAME
        dst = rules.local_file('private', 'clash')
        paths.write_atomic(dst, old, 0o644)
        logs = []
        with mock.patch.object(rules, 'SETS', {'private': ('geosite', 'private')}), \
             mock.patch.object(rules, 'FORMATS', ('clash',)), \
             mock.patch.object(rules, 'MAX_RULE_DOWNLOAD_BYTES', 16), \
             mock.patch.object(rules.urllib.request, 'urlopen',
                               side_effect=lambda *a, **kw: io.BytesIO(b'x' * 17)):
            self.assertEqual(rules.refresh(log=logs.append), 0)
        with open(dst, 'rb') as f:
            self.assertEqual(f.read(), old)
        self.assertTrue(any('download failed' in line for line in logs))

    def test_http_200_html_upstream_falls_back_to_cdn(self):
        valid = MRS_ZSTD_FRAME
        with mock.patch.object(rules, '_fetch',
                               side_effect=[b'<!DOCTYPE html><html>error</html>', valid]) as fetch:
            self.assertEqual(rules.fetch_converted('private', 'clash'), valid)
            self.assertEqual(fetch.call_count, 2)
            self.assertIn('github.com', fetch.call_args_list[0].args[0])
            self.assertIn('jsdelivr.net', fetch.call_args_list[1].args[0])

    def test_both_mirrors_error_pages_do_not_overwrite_existing_rules(self):
        paths.ensure_dirs()
        dst = rules.local_file('private', 'clash')
        old = MRS_ZSTD_FRAME
        paths.write_atomic(dst, old, 0o644)
        logs = []
        with mock.patch.object(rules, 'SETS', {'private': ('geosite', 'private')}), \
             mock.patch.object(rules, 'FORMATS', ('clash',)), \
             mock.patch.object(rules, '_fetch', return_value=b'<html><body>blocked</body></html>'):
            self.assertEqual(rules.refresh(log=logs.append), 0)
        with open(dst, 'rb') as f:
            self.assertEqual(f.read(), old)
        self.assertTrue(any('download failed' in line for line in logs))





class MonitorSpeed(unittest.TestCase):
    def test_background_runner_forwards_speed_refresh_to_sampler(self):
        for force in (False, True):
            with self.subTest(force_speed=force):
                with mock.patch.object(monitor, 'run_once', return_value={'sites': {}}) as sampler, \
                     mock.patch.object(monitor.threading, 'Thread') as worker:
                    worker.return_value.start.side_effect = lambda: worker.call_args.kwargs['target']()
                    monitor.run_in_background(log=lambda _: None, with_speed=force)
                sampler.assert_called_once_with(force_speed=force)

    def test_busy_monitor_is_skipped_without_spawning_a_thread(self):
        with monitor._run_lock:
            with mock.patch.object(monitor.threading, 'Thread') as worker:
                self.assertFalse(monitor.run_in_background(log=lambda _: None, with_speed=True))
            worker.assert_not_called()

    def test_scheduler_retries_unaccepted_forced_speed_check(self):
        scheduler = jobs.Scheduler()
        original_due = scheduler.due
        def monitor_only_due(name, interval):
            return original_due(name, interval) if name in ('monitor', 'monitor_speed') else False

        settings = {'setup_done': True, 'monitor_enabled': True, 'abuse_guard': False}
        with mock.patch.object(jobs.db, 'settings', return_value=settings), \
             mock.patch.object(jobs.paths, 'LIVE', True), \
             mock.patch.object(scheduler, 'due', side_effect=monitor_only_due), \
             mock.patch.object(jobs.monitor, 'run_in_background', side_effect=[False, True]) as launch:
            scheduler.tick()
            self.assertNotIn('monitor', scheduler.last)
            self.assertNotIn('monitor_speed', scheduler.last)
            scheduler.tick()
            self.assertIn('monitor', scheduler.last)
            self.assertIn('monitor_speed', scheduler.last)
        self.assertEqual(launch.call_count, 2)
        self.assertEqual(launch.call_args_list[0].kwargs, {'with_speed': True})
        self.assertEqual(launch.call_args_list[1].kwargs, {'with_speed': True})

    def test_thread_start_failure_releases_monitor_reservation(self):
        with mock.patch.object(monitor.threading, 'Thread') as worker:
            worker.return_value.start.side_effect = RuntimeError('thread unavailable')
            with self.assertRaisesRegex(RuntimeError, 'thread unavailable'):
                monitor.run_in_background(log=lambda _: None, with_speed=True)
        self.assertTrue(monitor._run_lock.acquire(blocking=False))
        monitor._run_lock.release()

    def measure(self, packet):
        class FakeSocket:
            def __init__(self, response):
                self.response = response
                self.request = None

            def sendall(self, request):
                self.request = request

            def makefile(self, mode):
                return io.BytesIO(self.response)

            def close(self):
                pass

        class FakeTLS:
            def wrap_socket(self, conn, server_hostname):
                return conn

        sock = FakeSocket(packet)
        with mock.patch.object(monitor.socket, 'create_connection', return_value=sock), \
             mock.patch.object(monitor.ssl, 'create_default_context', return_value=FakeTLS()), \
             mock.patch.object(monitor, 'SPEED_BYTES', 32):
            result = monitor.speed(timeout=1)
        return result, sock.request

    def test_successful_response_counts_only_exact_entity_body(self):
        body = b'a' * 32
        packet = b'HTTP/1.1 200 OK\r\nContent-Length: 32\r\nX-Extra: headers-not-payload\r\n\r\n' + body
        result, request = self.measure(packet)
        self.assertTrue(result['ok'])
        self.assertEqual(result['bytes'], len(body))
        self.assertIn(b'GET /__down?bytes=32 HTTP/1.1', request)
        self.assertIn(b'Accept-Encoding: identity', request)

    def test_successful_chunked_response_counts_only_entity_body(self):
        packet = (b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n'
                  + b'20\r\n' + b'a' * 32 + b'\r\n0\r\n\r\n')
        result, _ = self.measure(packet)
        self.assertTrue(result['ok'])
        self.assertEqual(result['bytes'], 32)

    def test_http_errors_bad_lengths_and_partial_responses_fail(self):
        for label, packet in (
            ('not found', b'HTTP/1.1 404 Not Found\r\nContent-Length: 32\r\n\r\n' + b'X' * 32),
            ('wrong length', b'HTTP/1.1 200 OK\r\nContent-Length: 64\r\n\r\n' + b'a' * 64),
            ('short body', b'HTTP/1.1 200 OK\r\nContent-Length: 32\r\n\r\n' + b'a' * 12),
            ('compressed', b'HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 32\r\n\r\n' + b'a' * 32),
            ('extra chunk', b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n'
             + b'21\r\n' + b'a' * 33 + b'\r\n0\r\n\r\n'),
        ):
            with self.subTest(case=label):
                result, _ = self.measure(packet)
                self.assertFalse(result['ok'])
                self.assertIn('error', result)




class RuleFileColdCache(tu.Base):
    """Cold Shadowrocket requests must not turn invalid upstream data into a permanent cache."""

    def test_busy_refresh_returns_503_without_occupying_a_worker(self):
        # A public request must not wait behind a remote fetch holding the
        # shared refresh lock. Run the request in a thread so the regression
        # fails within one second rather than hanging the entire test suite.
        with tempfile.TemporaryDirectory() as directory:
            filename = os.path.join(directory, 'private.list')
            sent = []
            handler = type('HandlerStub', (), {
                'send': lambda _, *args, **kwargs: sent.append((args, kwargs)),
                'not_found': lambda _: self.fail('known rule set refused'),
            })()
            with mock.patch.object(rules, 'local_file', return_value=filename), \
                 mock.patch.object(rules, 'fetch_converted', return_value=b'DOMAIN-SUFFIX,example.org\n') as fetch:
                self.assertTrue(rules._refresh_lock.acquire(blocking=False))
                try:
                    worker = threading.Thread(
                        target=web.Handler.rule_file, args=(handler, 'private', 'list'), daemon=True)
                    worker.start()
                    worker.join(timeout=1)
                    self.assertFalse(worker.is_alive(), 'cold public request blocked behind the refresh lock')
                    self.assertEqual(sent[-1][0][0], 503)
                    fetch.assert_not_called()
                finally:
                    rules._refresh_lock.release()
                    worker.join(timeout=2)

                self.assertFalse(os.path.exists(filename))
                web.Handler.rule_file(handler, 'private', 'list')
                self.assertEqual(sent[-1][0][0], 200)
                fetch.assert_called_once()
                self.assertTrue(os.path.isfile(filename))

    def test_empty_converted_rules_do_not_get_cached(self):
        paths.ensure_dirs()
        filename = rules.local_file('private', 'shadowrocket')
        sent = []
        handler = type('HandlerStub', (), {
            'send': lambda _, *args, **kwargs: sent.append((args, kwargs)),
            'not_found': lambda _: self.fail('known rule set refused'),
        })()
        with mock.patch.object(rules, 'fetch_converted', side_effect=[
                b'\n', b'DOMAIN-SUFFIX,example.org\n']) as download:
            web.Handler.rule_file(handler, 'private', 'list')
            self.assertEqual(sent[-1][0][0], 503)
            self.assertFalse(os.path.exists(filename))
            web.Handler.rule_file(handler, 'private', 'list')
            self.assertEqual(sent[-1][0][:2], (200, b'DOMAIN-SUFFIX,example.org\n'))
            self.assertTrue(os.path.exists(filename))
            web.Handler.rule_file(handler, 'private', 'list')
            self.assertEqual(download.call_count, 2)
            self.assertEqual(sent[-1][0][0], 200)

    def test_malformed_converted_rule_lines_never_overwrite_cold_cache(self):
        paths.ensure_dirs()
        filename = rules.local_file('private', 'shadowrocket')
        sent = []
        handler = type('HandlerStub', (), {
            'send': lambda _, *args, **kwargs: sent.append(args),
            'not_found': lambda _: self.fail('known rule set refused'),
        })()
        samples = (b'<html>temporary error</html>', b'DOMAIN-SUFFIX,example.org\ninvalid', b'DOMAIN,')
        with mock.patch.object(rules, 'fetch_converted', side_effect=samples):
            for _ in samples:
                web.Handler.rule_file(handler, 'private', 'list')
                self.assertEqual(sent[-1][0], 503)
                self.assertFalse(os.path.exists(filename))


class CoreOnlineTelemetry(tu.Base):
    """Malformed local core JSON must not break online users or traffic accounting."""

    def test_invalid_connection_array_never_advances_traffic_baseline(self):
        meter = cores.TuicMeter()
        first = {'uploadTotal': 100, 'downloadTotal': 80,
                 'connections': [{'id': 'active', 'chains': ['u7'],
                                  'upload': 40, 'download': 30}]}
        self.assertTrue(meter.sample({}, data=first, users={7}))
        snapshot = (meter.total, dict(meter.conns), dict(meter.acc), list(meter.pending))
        for value in ('malformed', {}, 7, False):
            bad = {'uploadTotal': 110, 'downloadTotal': 95, 'connections': value}
            with self.subTest(value=value):
                self.assertFalse(meter.sample({}, data=bad, users={7}))
                self.assertEqual(
                    (meter.total, meter.conns, meter.acc, meter.pending), snapshot)
        second = {'uploadTotal': 120, 'downloadTotal': 100,
                  'connections': [{'id': 'active', 'chains': ['u7'],
                                   'upload': 50, 'download': 40}]}
        self.assertTrue(meter.sample({}, data=second, users={7}))
        self.assertEqual(meter.acc[7], (20, 20))

    def test_bounded_core_account_ids(self):
        for value in (None, 'u0', 'u' + '9' * 5000, 'u４４', 'user7', 'u9223372036854775808'):
            self.assertIsNone(cores._stat_uid(value))
        self.assertEqual(cores._stat_uid('u7'), 7)
        self.assertEqual(cores._stat_uid('u9223372036854775807'), (1 << 63) - 1)

    def test_bad_xray_user_id_does_not_discard_good_traffic(self):
        settings = dict(db.settings(), reality_enabled=True, hy2_enabled=False, tuic_enabled=False)
        bad_name = 'user>>>u' + '9' * 5000 + '>>>traffic>>>uplink'
        stats = {'stat': [
            {'name': bad_name, 'value': 10},
            {'name': 'user>>>u7>>>traffic>>>uplink', 'value': 100},
            {'name': 'user>>>u8>>>traffic>>>downlink', 'value': 50},
        ]}
        with mock.patch.object(cores.os.path, 'exists', return_value=True), \
             mock.patch.object(cores.subprocess, 'run',
                               return_value=mock.Mock(returncode=0, stdout=json.dumps(stats))):
            result = cores.collect_traffic(settings)
        self.assertEqual(result, {7: (100, 0), 8: (0, 50)})

    def test_bad_hysteria_user_id_does_not_discard_good_traffic(self):
        settings = dict(db.settings(), reality_enabled=False, hy2_enabled=True, tuic_enabled=False)
        counters = {'u' + '9' * 5000: {'tx': 10, 'rx': 10},
                    'u7': {'tx': 5, 'rx': 6}}
        with mock.patch.object(cores.urllib.request, 'urlopen',
                               return_value=io.BytesIO(json.dumps(counters).encode())):
            self.assertEqual(cores.collect_traffic(settings), {7: (5, 6)})

    def test_bad_xray_online_marker_keeps_valid_online_users(self):
        settings = dict(db.settings(), reality_enabled=True, hy2_enabled=False, tuic_enabled=False)

        def answer(settings, command, *extra):
            return 'u' + '9' * 5000 + ' u7 u8' if command == 'statsgetallonlineusers' else '"1.1.1.1": 1'

        with mock.patch.object(cores.os.path, 'exists', return_value=True), \
             mock.patch.object(cores, '_xray_api', side_effect=answer):
            result = cores._online_detail(settings)
        self.assertEqual(sorted(result), [7, 8])
        self.assertEqual(result[7]['ips'], ['1.1.1.1'])

    def test_tuic_owner_rejects_bad_tags_and_unhashable_connection_ids(self):
        meter = cores.TuicMeter()
        self.assertIsNone(meter.owner(None))
        self.assertIsNone(meter.owner({'chains': [9, 'u' + '9' * 5000]}))
        self.assertIsNone(meter.owner({'chains': ['u0', 'u４４']}))
        self.assertEqual(meter.owner({'chains': ['not-an-account', 'u7']}), 7)
        first = {
            'uploadTotal': 0, 'downloadTotal': 0,
            'connections': [
                {'id': [], 'chains': ['u7'], 'upload': 4, 'download': 3},
                {'id': {'bad': 'id'}, 'chains': ['u7']},
                {'id': 'valid', 'chains': ['u7'], 'upload': 0, 'download': 0},
                None,
            ],
        }
        self.assertTrue(meter.sample({}, data=first, users={7}))
        self.assertEqual(meter.conns, {'valid': (7, 0, 0)})
        second = {
            'uploadTotal': 20, 'downloadTotal': 10,
            'connections': [
                {'id': [], 'chains': ['u7'], 'upload': 3, 'download': 2},
                {'id': 'valid', 'chains': ['u7'], 'upload': 10, 'download': 5},
            ],
        }
        self.assertTrue(meter.sample({}, data=second, users={7}))
        self.assertIn(7, meter.acc)

    def test_online_detail_skips_bad_hysteria_and_tuic_rows(self):
        settings = dict(db.settings(), reality_enabled=False, hy2_enabled=True, tuic_enabled=True)
        hy2 = {'u7': 2, 'u8': '1', 'u9': [], 'u10': True,
               'u' + '9' * 5000: 4, 'u0': 1, 'u11': -3}
        tuic = {
            'connections': [
                None, {'chains': ['u' + '9' * 5000]},
                {'chains': ['u7'], 'metadata': {'sourceIP': ['not-a-string']}},
                {'chains': ['u8'], 'metadata': {'sourceIP': '1.2.3.4'}},
                {'chains': ['u9'], 'metadata': 'not-a-dict'},
            ],
        }
        with mock.patch.object(cores.urllib.request, 'urlopen',
                               return_value=io.BytesIO(json.dumps(hy2).encode())), \
             mock.patch.object(cores.TuicMeter, 'poll', return_value=tuic):
            report = cores._online_detail(settings)
        self.assertEqual(report[7]['devices'], 2)
        self.assertEqual(report[7]['conns'], 3)
        self.assertEqual(report[8]['ips'], ['1.2.3.4'])
        self.assertEqual(report[8]['devices'], 1)        # one Hysteria client and one TUIC address: one phone
        self.assertEqual(report[9]['ips'], [])
        self.assertNotIn(0, report)

    def test_device_estimate_counts_one_phone_once(self):
        est = cores.device_estimate
        self.assertEqual(est([]), 0)
        self.assertEqual(est(['1.2.3.4'], 1), 1)                       # smart line: TUIC + Hysteria
        self.assertEqual(est(['1.2.3.4', '2001:db8:1:2::10'], 1), 1)   # dual stack
        self.assertEqual(est(['2001:db8:1:2::10', '2001:db8:1:2:a:b:c:d', '[2001:db8:1:2::11]']), 1)
        self.assertEqual(est(['::ffff:1.2.3.4', '1.2.3.4']), 1)        # IPv4-mapped is the same address
        self.assertEqual(est(['1.2.3.4', '5.6.7.8', '2001:db8:1:2::1']), 2)
        self.assertEqual(est(['2001:db8:1:2::1', '2001:db8:9:9::1']), 2)
        self.assertEqual(est(['1.2.3.4'], 3), 3)                       # Hysteria alone can prove more
        self.assertEqual(est(['not-an-ip', 'fe80::1%eth0']), 1)

    def test_online_detail_keeps_valid_protocol_when_other_snapshot_is_invalid(self):
        settings = dict(db.settings(), reality_enabled=False, hy2_enabled=True, tuic_enabled=True)
        valid_tuic = {'connections': [None, {'chains': ['u7'], 'metadata': {'sourceIP': '1.1.1.1'}}]}
        with mock.patch.object(cores.urllib.request, 'urlopen',
                               return_value=io.BytesIO(b'["invalid hy2 format"]')), \
             mock.patch.object(cores.TuicMeter, 'poll', return_value=valid_tuic):
            report = cores._online_detail(settings)
        self.assertEqual(report[7]['protocols'], ['tuic'])
        self.assertEqual(report[7]['ips'], ['1.1.1.1'])
        with mock.patch.object(cores.TuicMeter, 'poll', return_value=['invalid']):
            self.assertIsNone(cores.TuicMeter().online(settings))


class Shadowrocket(tu.Base):
    def test_config(self):
        db.set_settings(hy2_obfs='')
        u = mk('ann', 10)
        conf = subscription.shadowrocket(db.settings(), u, 'https://example.org:8443', 'https://example.org:8443/s/x')
        self.assertIn('[Proxy]', conf)
        lines = conf.split('[Proxy]\n', 1)[1].split('\n\n', 1)[0].splitlines()
        kinds = [l.split(' = ', 1)[1].split(',')[0] for l in lines]
        self.assertEqual(kinds, ['hysteria2', 'vless', 'tuic'])
        self.assertIn('xtls=2', lines[1])
        pin = subscription._sr_pin(subscription.tls_info(db.settings())['pin'])
        self.assertIn('hpkp=' + pin, lines[0])
        self.assertIn('RULE-SET,https://example.org:8443/rules/cn.list,', conf)
        self.assertIn(',no-resolve', conf)
        self.assertTrue(conf.rstrip().splitlines()[-1].startswith('FINAL,'))
        self.assertIn('update-url = https://example.org:8443/s/x?format=shadowrocket', conf)
        db.set_settings(hy2_obfs='secret')
        conf = subscription.shadowrocket(db.settings(), u, 'https://e.org')
        self.assertNotIn('hysteria2,', conf)                      # salamander is not expressible there
        self.assertEqual(subscription.detect_format('', 'shadowrocket'), 'shadowrocket')

    def test_joined_node_label_cannot_inject_ini_sections(self):
        user = mk('shadowrocket-member', 20)
        db.set_settings(hy2_obfs='')
        info = cluster.public_info(db.settings())
        dangerous = 'Edge\\r\\n[Proxy]\\nEvil'.replace('\\r', '\r').replace('\\n', '\n')
        node = {'id': 'abcd1234', 'name': dangerous, 'enabled': True,
                'info': info, 'idmap': {str(user['id']): 42}}
        db.set_settings(servers=[node])
        conf = subscription.shadowrocket(db.settings(), user, 'https://example.org')

        self.assertEqual(conf.splitlines().count('[Proxy]'), 1)
        self.assertEqual(conf.splitlines().count('[Proxy Group]'), 1)
        self.assertEqual(conf.splitlines().count('[Rule]'), 1)
        remote_line = next(line for line in conf.splitlines() if 'Edge [Proxy] Evil Hysteria2' in line)
        self.assertIn(' = hysteria2, ', remote_line)
        self.assertEqual(subscription._sr_label('上海 Tokyo, A=B'), '上海 Tokyo  A-B')
        self.assertEqual(len(subscription._sr_label('x\\u2028y'.replace('\\u2028', '\u2028')).splitlines()), 1)

    def test_rule_conversion(self):
        out = rules.to_shadowrocket(b'+.google.com\nexample.org\n# c\nregexp:^x\n', 'geosite').decode().splitlines()
        self.assertEqual(out, ['DOMAIN-SUFFIX,google.com', 'DOMAIN,example.org'])
        out = rules.to_shadowrocket(b'1.0.1.0/24\n2001:db8::/32\nbad\n', 'geoip').decode().splitlines()
        self.assertEqual(out, ['IP-CIDR,1.0.1.0/24', 'IP-CIDR6,2001:db8::/32'])


class EmptySubscription(tu.Base):
    def test_empty_node_list_cannot_fall_back_to_direct_in_any_format(self):
        uid = db.add_user('empty-proxy-list')
        user = db.user(uid)
        settings = dict(db.settings(), reality_enabled=False, hy2_enabled=False,
                        tuic_enabled=False, servers=[])
        base = 'https://example.invalid'
        self.assertEqual(subscription.nodes(settings, user), [])

        clash = subscription.clash(settings, user, base)
        auto = subscription.names(settings)['auto']
        group = next(g for g in clash['proxy-groups'] if g['name'] == auto)
        self.assertEqual(group['proxies'], ['REJECT'])
        self.assertEqual(clash['rules'], ['MATCH,REJECT'])
        self.assertEqual(clash['rule-providers'], {})
        self.assertFalse(clash['dns']['enable'])

        singbox = subscription.singbox(settings, user, base)
        self.assertEqual(singbox['route']['rules'], [{'action': 'reject'}])
        self.assertFalse(any(o['type'] in ('selector', 'urltest') for o in singbox['outbounds']))

        shadow = subscription.shadowrocket(settings, user, base)
        self.assertIn('%s = fallback, REJECT' % auto, shadow)
        self.assertIn('FINAL,REJECT,dns-failed', shadow)
        self.assertNotIn('%s = fallback, DIRECT' % auto, shadow)

    def test_all_node_protocols_disabled_still_reject_traffic(self):
        user = mk('no-protocol')
        settings = dict(db.settings(), reality_enabled=False, hy2_enabled=False,
                        tuic_enabled=False, servers=[])
        self.assertEqual(subscription.nodes(settings, user), [])
        self.assertEqual(subscription.clash(settings, user, 'https://example.invalid')['rules'], ['MATCH,REJECT'])
        self.assertEqual(subscription.singbox(settings, user, 'https://example.invalid')['route']['rules'],
                         [{'action': 'reject'}])


class Servers(tu.Base):
    def test_node_side_sync(self):
        local = mk('own-user')
        db.set_settings(setup_done=True)
        orig = web.apply_async
        web.apply_async = lambda force=False: None
        try:
            users = [{'id': 7, 'name': 'x', 'uuid': '00000000-0000-4000-8000-000000000007', 'hy2_pass': 'pass-seven', 'enabled': True},
                     {'id': 9, 'name': 'own-user', 'uuid': '00000000-0000-4000-8000-000000000009', 'hy2_pass': 'pass-nine', 'enabled': False}]
            ans = cluster.handle_sync(db.settings(), {'master': 'main', 'users': users})
            mine = {u['remote_id']: u for u in db.users() if u['remote_id']}
            self.assertEqual(set(mine), {7, 9})
            self.assertEqual(mine[7]['uuid'], '00000000-0000-4000-8000-000000000007')
            self.assertFalse(mine[9]['enabled'])
            self.assertEqual(ans['idmap'], {'7': mine[7]['id'], '9': mine[9]['id']})
            self.assertIn('reality_public_key', ans['info'])
            self.assertNotIn('reality_private_key', ans['info'])
            db.add_traffic(mine[7]['id'], 10, 20)
            # node limits never touch accounts of the main server
            jobs.enforce()
            self.assertTrue(db.user(mine[7]['id'])['enabled'])
            ans = cluster.handle_sync(db.settings(), {'master': 'main', 'users': users[:1]})
            self.assertEqual(ans['traffic'], {'7': [10, 20]})
            self.assertEqual([u['name'] for u in db.users()], ['own-user', 'x@main'])   # 9 removed, own user kept
            self.assertEqual(db.user(local['id'])['remote_id'], 0)
            # once bound to one main server (by id), a different one is refused instead of fighting over accounts
            cluster.handle_sync(db.settings(), {'master': 'main', 'master_id': 'id-one', 'users': users[:1]})
            ans = cluster.handle_sync(db.settings(), {'master': 'other', 'master_id': 'id-two', 'users': []})
            self.assertTrue(ans.get('conflict'))
            self.assertEqual(len([u for u in db.users() if u['remote_id']]), 1)
            self.assertNotIn('error', cluster.handle_sync(db.settings(), {'master': 'main', 'master_id': 'id-one',
                                                                          'users': users[:1]}))
        finally:
            web.apply_async = orig

    def test_malformed_node_snapshot_cannot_delete_or_rewrite_accounts(self):
        original = web.apply_async
        web.apply_async = lambda force=False: None
        legitimate = {'id': 7, 'name': 'remote', 'uuid': '00000000-0000-4000-8000-000000000007',
                      'hy2_pass': 'pass-seven', 'enabled': True}
        local = mk('local')
        try:
            cluster.handle_sync(db.settings(), {'master': 'main', 'master_id': 'main-one', 'users': [legitimate]})
            before = [(u['id'], u['name'], u['uuid'], u['remote_id']) for u in db.users()]
            scenarios = [
                {'master': 'main', 'master_id': 'main-one', 'users': [dict(legitimate, id=8), dict(legitimate, id=8)]},
                {'master': 'main', 'master_id': 'main-one', 'users': [legitimate, dict(legitimate, id=8)]},
                {'master': 'main', 'master_id': 'main-one', 'users': [dict(legitimate, uuid='broken')]},
                {'master': 'main', 'master_id': 'main-one', 'users': 'bad-not-a-list'},
                {'master': 'main', 'master_id': 'main-one',
                 'users': [dict(legitimate, uuid=db.user(local['id'])['uuid'])]},
                {'master': 'main', 'master_id': 'main-one', 'users': [dict(legitimate, enabled='true')]},
            ]
            for value in scenarios:
                with self.subTest(value=value), self.assertRaises(ValueError):
                    cluster.handle_sync(db.settings(), value)
                self.assertEqual([(u['id'], u['name'], u['uuid'], u['remote_id']) for u in db.users()], before)
            self.assertEqual(db.settings()['node_master_id'], 'main-one')
            rejected = cluster.handle_sync(db.settings(), {'master': 'legacy', 'users': []})
            self.assertTrue(rejected['conflict'])
        finally:
            web.apply_async = original

    def test_node_snapshot_rolls_back_after_second_insert_fails(self):
        original_add, original_apply = db.add_user, web.apply_async
        web.apply_async = lambda force=False: None
        count = [0]
        target = [{'id': i, 'name': 'remote%d' % i,
                   'uuid': '00000000-0000-4000-8000-%012d' % i,
                   'hy2_pass': 'pass-%d' % i, 'enabled': True} for i in (51, 52)]
        before = [(u['id'], u['name'], u['uuid'], u['remote_id']) for u in db.users()]
        def fail_second(*args, **kw):
            count[0] += 1
            if count[0] == 2:
                raise RuntimeError('injected second account failure')
            return original_add(*args, **kw)
        db.add_user = fail_second
        try:
            with self.assertRaisesRegex(RuntimeError, 'second account failure'):
                cluster.handle_sync(db.settings(), {'master': 'main', 'master_id': 'new-main', 'users': target})
        finally:
            db.add_user = original_add
            web.apply_async = original_apply
        self.assertEqual([(u['id'], u['name'], u['uuid'], u['remote_id']) for u in db.users()], before)
        self.assertEqual(db.settings()['node_master_id'], '')
        self.assertEqual(count, [2])

    def test_main_side_counts_and_subscribes(self):
        u = mk('ann', 10)
        info = cluster.public_info(dict(db.settings(), public_host='198.51.100.5', node_name='tokyo'))
        answers = [{'ok': True, 'info': info, 'idmap': {str(u['id']): 42}, 'traffic': {str(u['id']): [0, 0]}},
                   {'ok': True, 'info': info, 'idmap': {str(u['id']): 42}, 'traffic': {str(u['id']): [100, 1000]}},
                   {'ok': True, 'info': info, 'idmap': {str(u['id']): 42}, 'traffic': {str(u['id']): [50, 60]}}]   # node lost counts
        orig = cluster._request
        cluster._request = lambda server, body, timeout=15: (answers.pop(0), 'ab' * 32)
        try:
            server = {'id': 'abcd1234', 'name': 'Tokyo', 'url': 'https://198.51.100.5:1/x', 'key': 'k', 'pin': ''}
            for _ in range(3):
                self.assertTrue(cluster.sync_one(server))
        finally:
            cluster._request = orig
        got = db.user(u['id'])
        self.assertEqual((got['used_up'], got['used_down']), (150, 1060))
        db.set_settings(servers=[server])
        ns = subscription.nodes(db.settings(), db.user(u['id']))
        remote = [n for n in ns if n['group'] == 'Tokyo']
        self.assertEqual(len(remote), 3)
        self.assertEqual(next(n for n in remote if n['type'] == 'hy2')['password'].split(':')[0], 'u42')
        self.assertEqual(remote[0]['server'], '198.51.100.5')
        clash = subscription.clash(db.settings(), db.user(u['id']), 'https://e.org')
        names = [g['name'] for g in clash['proxy-groups']]
        self.assertIn('Tokyo', names)
        self.assertIn(db.settings()['node_name'], names)
        sb = subscription.singbox(db.settings(), db.user(u['id']), 'https://e.org')
        self.assertIn('Tokyo', [o['tag'] for o in sb['outbounds']])
        # paused user: no entries anywhere
        self.assertEqual(subscription.nodes(dict(db.settings(), reality_enabled=False, hy2_enabled=False,
                                                 tuic_enabled=False, servers=[]), db.user(u['id'])), [])

    def test_sync_rejects_malformed_http_200_without_losing_previous_state(self):
        node = {'id': 'abc12345', 'name': 'Tokyo', 'url': 'https://node.example/adm',
                'key': 'secret', 'pin': 'ab' * 32, 'info': {'node_name': 'Tokyo'},
                'idmap': {'7': 12}, 'seen': {'7': [100, 200]}, 'fail_count': 0}
        for response in ({'error': 'another master', 'conflict': True},
                         {'ok': False, 'info': {}, 'idmap': {}, 'traffic': {}},
                         {'info': {}, 'idmap': {}, 'traffic': {}},
                         {'ok': None, 'info': {}, 'idmap': {}, 'traffic': {}},
                         {'info': [], 'idmap': {}, 'traffic': {}},
                         {'info': {}, 'idmap': [], 'traffic': {}},
                         {'info': {}, 'idmap': {}, 'traffic': []},
                         ['not a mapping']):
            node['fail_count'] = 0
            with mock.patch.object(cluster, '_request', return_value=(response, 'cd' * 32)):
                self.assertFalse(cluster.sync_one(node))
            self.assertEqual(node['fail_count'], 1)
            self.assertEqual(node['info'], {'node_name': 'Tokyo'})
            self.assertEqual(node['idmap'], {'7': 12})
            self.assertEqual(node['seen'], {'7': [100, 200]})
            self.assertEqual(node['pin'], 'ab' * 32)

    def test_http_200_missing_success_marker_is_a_sync_error(self):
        conn = mock.Mock()
        conn.sock.getpeercert.return_value = b'fixture cert'
        conn.getresponse.return_value.status = 200
        conn.getresponse.return_value.read.return_value = (
            b'{"info":{},"idmap":{},"traffic":{}}')
        with mock.patch.object(cluster.http.client, 'HTTPSConnection', return_value=conn):
            with self.assertRaisesRegex(cluster.SyncError, 'refused'):
                cluster._request({'url': 'https://node.example/adm', 'key': 'token'},
                                 {'users': []})
            conn.close.assert_called()

    def test_sync_dns_rebinding_rejected_before_tcp_connection(self):
        answers = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('8.8.8.8', 443)),
                   (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('127.0.0.1', 443))]
        with mock.patch.object(paths, 'LIVE', True):
            with mock.patch.object(cluster.socket, 'getaddrinfo', return_value=answers):
                with mock.patch.object(cluster.http.client, 'HTTPSConnection') as factory:
                    with self.assertRaisesRegex(cluster.SyncError, 'non-public'):
                        cluster._request({'url': 'https://node.example/adm', 'key': 'token'},
                                         {'users': []})
                    factory.assert_not_called()

    def test_sync_keeps_tls_hostname_but_only_dials_vetted_ip(self):
        answers = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('8.8.8.8', 443))]
        conn = mock.Mock()
        conn.sock.getpeercert.return_value = b'fixture cert'
        conn.getresponse.return_value.status = 200
        conn.getresponse.return_value.read.return_value = (
            b'{"ok":true,"info":{},"idmap":{},"traffic":{}}')
        marker = object()
        with mock.patch.object(paths, 'LIVE', True):
            with mock.patch.object(cluster.socket, 'getaddrinfo', return_value=answers):
                with mock.patch.object(cluster.http.client, 'HTTPSConnection', return_value=conn) as maker:
                    with mock.patch.object(cluster.socket, 'create_connection', return_value=marker) as dial:
                        value, pin = cluster._request(
                            {'url': 'https://node.example/adm', 'key': 'token'}, {'users': []})
                        self.assertTrue(value['ok'])
                        self.assertEqual(pin, hashlib.sha256(b'fixture cert').hexdigest())
                        self.assertIs(conn._create_connection(('node.example', 443), 4), marker)
                        dial.assert_called_once_with(('8.8.8.8', 443), 4, None)
                        self.assertEqual(maker.call_args[0][:2], ('node.example', 443))

    def test_http_200_conflict_is_a_sync_error(self):
        conn = mock.Mock()
        conn.sock.getpeercert.return_value = b'fixture cert'
        conn.getresponse.return_value.status = 200
        conn.getresponse.return_value.read.return_value = (
            b'{"error":"wrong master","conflict":true}')
        with mock.patch.object(cluster.http.client, 'HTTPSConnection', return_value=conn):
            with self.assertRaisesRegex(cluster.SyncError, 'wrong master'):
                cluster._request({'url': 'https://node.example/adm', 'key': 'token'},
                                 {'users': []})
            conn.close.assert_called()


    def test_invalid_join_code_port_is_rejected_before_sync(self):
        for uri in ('https://node.example:0/adm', 'https://node.example:65536/adm',
                    'https://node.example:notanumber/adm'):
            code = 'v2v1.' + secure.b64url(
                json.dumps({'u': uri, 'k': 'node-secret', 'p': ''}).encode())
            with self.subTest(uri=uri), self.assertRaisesRegex(ValueError, 'damaged'):
                cluster.parse_join_code(code)
        # A saved older configuration may contain invalid ports.
        with self.assertRaisesRegex(cluster.SyncError, 'invalid node port'):
            cluster._request({'url': 'https://node.example:65536/adm', 'key': 'k'},
                             {'users': []})


    def test_join_code(self):
        db.set_settings(panel_path='pp', node_name='Osaka')
        code = cluster.join_code(db.settings(), 'https://203.0.113.7:9443')
        j = cluster.parse_join_code(code)
        self.assertEqual((j['url'], j['name']), ('https://203.0.113.7:9443/pp', 'Osaka'))
        self.assertEqual(j['pin'], certs.fingerprint(certs.current()[0]))
        with self.assertRaises(ValueError):
            cluster.parse_join_code('v2v1.broken')


class MemberWeb(tu.Base):
    """The member centre over real HTTPS."""

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

    req = tu.Web.req

    def test_register_login_and_self_service(self):
        st, body, _ = self.req('GET', '/mem/')
        self.assertIn(b'<base href="/mem/">', body)
        st, body, _ = self.req('GET', '/mem/api/me')
        self.assertEqual(st, 401)
        rec = members.create_invite('admin', 30, 7, max_uses=1)
        st, body, _ = self.req('POST', '/mem/api/register', {'code': rec['code'], 'name': 'zoe', 'password': 'short'})
        self.assertEqual(st, 400)
        st, body, _ = self.req('POST', '/mem/api/register', {'code': rec['code'], 'name': 'zoe', 'password': 'goodpassword'})
        self.assertEqual(st, 200, body)
        st, body, _ = self.req('GET', '/mem/api/me')
        me = json.loads(body)
        self.assertEqual((me['name'], me['quota_gb']), ('zoe', 30))
        self.assertTrue(me['sub_url'].endswith('/s/' + db.user_by_name('zoe')['sub_token']))
        self.assertIn('shadowrocket_conf', me['import'])
        st, body, _ = self.req('POST', '/mem/api/invite', {'quota_gb': 5, 'max_uses': 2, 'valid_days': 3})
        self.assertEqual(st, 200, body)
        code = json.loads(body)['code']
        st, body, _ = self.req('POST', '/mem/api/request', {'add_gb': 20, 'reason': 'more'})
        self.assertEqual(st, 200, body)
        st, body, _ = self.req('GET', '/mem/api/qr')
        self.assertTrue(body.startswith(b'<svg'))
        # logout, a friend registers with zoe's code, zoe logs in again
        self.req('POST', '/mem/api/logout', {})
        st, _, _ = self.req('GET', '/mem/api/me')
        self.assertEqual(st, 401)
        st, body, _ = self.req('POST', '/mem/api/register', {'code': code, 'name': 'friend', 'password': 'goodpassword'})
        self.assertEqual(st, 200, body)
        self.cookie = ''
        st, _, _ = self.req('POST', '/mem/api/login', {'name': 'zoe', 'password': 'wrongpassword'})
        self.assertEqual(st, 403)
        st, _, _ = self.req('POST', '/mem/api/login', {'name': 'ZOE', 'password': 'goodpassword'})
        self.assertEqual(st, 200)
        me = json.loads(self.req('GET', '/mem/api/me')[1])
        self.assertEqual(me['quota_eff'], 25)
        self.assertEqual([x['name'] for x in me['invitees']], ['friend'])
        # admin sees and approves the request
        self.cookie = ''
        self.req('POST', '/adm/api/login', {'username': 'admin', 'password': 'adminpassword'})
        reqs = json.loads(self.req('GET', '/adm/api/requests')[1])['requests']
        self.assertEqual(len(reqs), 1)
        st, body, _ = self.req('POST', '/adm/api/requests/%d/approve' % reqs[0]['id'], {'add_gb': 10})
        self.assertEqual(st, 200, body)
        self.assertEqual(db.user_by_name('zoe')['quota_gb'], 40)
        st, body, _ = self.req('GET', '/adm/api/state')
        z = next(u for u in json.loads(body)['users'] if u['name'] == 'zoe')
        self.assertEqual((z['quota_eff'], z['shared_gb'], z['has_login']), (35, 5, True))
        self.assertNotIn(b'node_key', body)
        st, body, _ = self.req('POST', '/adm/api/invites', {'kind': 'admin', 'quota_gb': 0, 'valid_days': 5})
        self.assertEqual(json.loads(body)['invite']['register_url'][-17:-11], 'ister=')
        st, body, _ = self.req('GET', '/adm/api/users/%d/history' % z['id'])
        self.assertEqual(json.loads(body)['days'], [])
        # admin can turn the member centre off
        db.set_settings(member_enabled=False)
        st, _, _ = self.req('GET', '/mem/')
        self.assertEqual(st, 404)

    def test_link_page(self):
        u = mk('lee', 10)
        base = '/s/%s/' % u['sub_token']
        st, body, _ = self.req('GET', base + 'api/hello')
        self.assertEqual(json.loads(body)['mode'], 'link')
        me = json.loads(self.req('GET', base + 'api/me')[1])
        self.assertEqual(me['name'], 'lee')
        st, body, _ = self.req('POST', base + 'api/login', {'name': 'lee', 'password': 'x'})
        self.assertEqual(st, 404)                           # no password guessing through link pages
        st, _, _ = self.req('POST', base + 'api/password', {'new': 'mynewpassword'})
        self.assertEqual(st, 200)
        st, _, _ = self.req('POST', base + 'api/password', {'new': 'another-password'})
        self.assertEqual(st, 403)                           # changing needs the current one
        st, _, _ = self.req('GET', '/s/%s/api/me' % ('x' * 24))
        self.assertEqual(st, 404)
        st, body, _ = self.req('GET', base + 'static/member.js')
        self.assertIn(b'member centre', body)
        st, _, _ = self.req('GET', base + 'static/app.js')
        self.assertEqual(st, 404)                           # the admin app is not served there
        st, body, r = self.req('GET', '/s/%s?format=shadowrocket' % u['sub_token'])
        self.assertIn(b'[Proxy Group]', body)

    def test_admin_edits_and_link_rotation(self):
        a = mk('amy', 20, expire_at=int(time.time()) + 86400)
        rec = members.create_invite('member', 5, 7, inviter=a['id'])
        fid = members.register(rec['code'], 'amyfriend', 'goodpassword')
        self.req('POST', '/adm/api/login', {'username': 'admin', 'password': 'adminpassword'})
        st, body, _ = self.req('POST', '/adm/api/users', {'name': 'AMY'})
        self.assertEqual(st, 400)                           # names are unique ignoring case
        st, body, _ = self.req('POST', '/adm/api/users/%d/save' % fid, {'name': 'Amy'})
        self.assertEqual(st, 400)
        st, body, _ = self.req('POST', '/adm/api/users/%d/save' % a['id'], {'quota_gb': 'nan'})
        self.assertEqual(st, 400)
        later = int(time.time()) + 90 * 86400
        st, body, _ = self.req('POST', '/adm/api/users/%d/save' % a['id'], {'expire_at': later})
        self.assertEqual(st, 200, body)
        self.assertEqual(db.user(fid)['expire_at'], later)  # the carved account follows its inviter's lifetime
        st, body, _ = self.req('GET', '/adm/api/users/%d/history?days=abc' % a['id'])
        self.assertEqual(st, 200)
        self.req('POST', '/adm/api/settings', {'member_notice': 'maintenance tonight\x07'})
        self.assertEqual(db.settings()['member_notice'], 'maintenance tonight')
        # the member changes a leaked link from the link page itself
        old = db.user(fid)['sub_token']
        self.assertEqual(json.loads(self.req('GET', '/s/%s/api/hello' % old)[1])['notice'], 'maintenance tonight')
        st, body, _ = self.req('POST', '/s/%s/api/rotate' % old, {})
        self.assertEqual(st, 200, body)
        new = db.user(fid)['sub_token']
        self.assertNotEqual(old, new)
        self.assertEqual(json.loads(body)['base'], '/s/%s/' % new)
        self.assertEqual(self.req('GET', '/s/%s/api/me' % old)[0], 404)

    def test_rotating_leaked_credentials_revokes_prior_member_sessions(self):
        victim = mk('revoked-member', 5, login_hash=secure.hash_password('correctpassword'))
        peer = mk('unrelated-member', 5, login_hash=secure.hash_password('peerpassword'))
        old_link = victim['sub_token']
        stolen = db.new_member_session(victim['id'])
        second = db.new_member_session(victim['id'])
        unaffected = db.new_member_session(peer['id'])

        # A session issued before the rotation can read the member centre.
        self.cookie = 'v2vm=' + stolen
        self.assertEqual(self.req('GET', '/mem/api/me')[0], 200)
        st, body, _ = self.req('POST', '/mem/api/rotate', {})
        self.assertEqual(st, 200, body)
        new_link = db.user(victim['id'])['sub_token']
        self.assertNotEqual(new_link, old_link)
        self.assertIsNone(db.member_session(stolen))
        self.assertIsNone(db.member_session(second))
        self.assertEqual(db.member_session(unaffected), peer['id'])
        # The member who rotated keeps a fresh session; the old cookies are dead.
        fresh = self.cookie.split('=', 1)[1]
        self.assertNotIn(fresh, (stolen, second))
        self.assertEqual(db.member_session(fresh), victim['id'])
        self.assertEqual(self.req('GET', '/mem/api/me')[0], 200)
        self.cookie = 'v2vm=' + stolen
        self.assertEqual(self.req('GET', '/mem/api/me')[0], 401)
        self.assertEqual(self.req('GET', '/s/%s/api/me' % old_link)[0], 404)
        self.assertEqual(self.req('GET', '/s/%s/api/me' % new_link)[0], 200)

        # Rotation does not delete the password, so the legitimate member
        # can log in again with fresh credentials and receive a fresh cookie.
        self.cookie = ''
        st, body, _ = self.req('POST', '/mem/api/login',
                                {'name': 'revoked-member', 'password': 'correctpassword'})
        self.assertEqual(st, 200, body)
        fresh = self.cookie.split('=', 1)[1]
        self.assertEqual(db.member_session(fresh), victim['id'])

    def test_admin_and_bulk_rotation_also_revoke_member_sessions(self):
        first = mk('admin-rotated', 10)
        second = mk('bulk-rotated', 10)
        first_cookie = db.new_member_session(first['id'])
        second_cookie = db.new_member_session(second['id'])
        self.assertEqual(self.req('POST', '/adm/api/login',
                                  {'username': 'admin', 'password': 'adminpassword'})[0], 200)
        self.assertEqual(self.req('POST', '/adm/api/users/%d/rotate' % first['id'], {})[0], 200)
        self.assertIsNone(db.member_session(first_cookie))
        self.assertEqual(db.member_session(second_cookie), second['id'])
        self.assertEqual(self.req('POST', '/adm/api/users-bulk',
                                  {'action': 'rotate', 'ids': [second['id']]} )[0], 200)
        self.assertIsNone(db.member_session(second_cookie))

    def test_parallel_registrations_respect_uses(self):
        rec = members.create_invite('admin', 1, 7, max_uses=3)
        orig, ok = members.check_password, []
        members.check_password = lambda pw: (time.sleep(0.05), pw)[1]     # widen the race window
        try:
            def go(i):
                try:
                    members.register(rec['code'], 'racer%d' % i, 'goodpassword')
                    ok.append(i)
                except members.Refused:
                    pass
            ts = [threading.Thread(target=go, args=(i,)) for i in range(8)]
            [t.start() for t in ts]
            [t.join() for t in ts]
        finally:
            members.check_password = orig
        self.assertEqual(len(ok), 3)
        self.assertEqual(db.invite(rec['id'])['uses'], 3)

    def test_unread_request_body_does_not_break_the_connection(self):
        """Endpoints that ignore the body (check now / scan now) must still consume it."""
        ctx = ssl.create_default_context()
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
        c = http.client.HTTPSConnection('127.0.0.1', self.port, context=ctx, timeout=10)
        orig = abuse.check
        abuse.check = lambda s=None, log=print: {}
        try:
            c.request('POST', '/adm/api/login', json.dumps({'username': 'admin', 'password': 'adminpassword'}),
                      {'Content-Type': 'application/json', 'X-V2V': '1'})
            r = c.getresponse()
            cookie = r.getheader('Set-Cookie').split(';')[0]
            r.read()
            hdr = {'Content-Type': 'application/json', 'X-V2V': '1', 'Cookie': cookie}
            for _ in range(2):          # same keep-alive connection: leftover bytes would garble the next request
                c.request('POST', '/adm/api/abuse', json.dumps({'pad': 'x' * 5000}), hdr)
                r = c.getresponse()
                self.assertEqual(r.status, 200)
                r.read()
            c.request('GET', '/adm/api/hello', headers=hdr)
            r = c.getresponse()
            self.assertEqual(r.status, 200)
            self.assertTrue(json.loads(r.read())['logged_in'])
        finally:
            abuse.check = orig
            c.close()

    def test_node_endpoint_needs_key(self):
        st, _, _ = self.req('POST', '/adm/api/node/sync', {'users': []}, headers={'Authorization': 'Bearer wrong'})
        self.assertEqual(st, 403)
        key = db.settings()['node_key']
        st, body, _ = self.req('POST', '/adm/api/node/sync', {'master': 'm', 'users': []}, headers={'Authorization': 'Bearer ' + key})
        self.assertEqual(st, 200, body)
        self.assertIn('info', json.loads(body))

    def test_real_two_way_sync_over_https(self):
        """The main-server client talks to this server's node endpoint with the pinned certificate."""
        db.set_settings(node_name='nodeA')
        code = cluster.join_code(db.settings(), 'https://127.0.0.1:%d' % self.port)
        j = cluster.parse_join_code(code)
        server = {'id': 'feedbeef', 'name': 'A', 'url': j['url'], 'key': j['key'], 'pin': j['pin']}
        ans, pin = cluster._request(server, {'master': 'main', 'users': [
            {'id': 501, 'name': 'r', 'uuid': '00000000-0000-4000-8000-000000000007', 'hy2_pass': 'pass-501', 'enabled': True}]})
        self.assertEqual(pin, j['pin'])
        self.assertIn('501', ans['idmap'])
        with self.assertRaises(cluster.SyncError):
            cluster._request(dict(server, pin='00' * 32), {'users': []})    # wrong pin, not publicly trusted
        with self.assertRaises(cluster.SyncError):
            cluster._request(dict(server, key='nope'), {'users': []})


if __name__ == '__main__':
    unittest.main()


class AuditFollowUps(tu.Base):
    """Findings from the 2026-11-20 review rounds that the earlier fixes did not cover yet."""

    def test_child_server_stops_expired_main_accounts_even_while_the_main_is_away(self):
        db.set_settings(setup_done=True)
        orig = web.apply_async
        web.apply_async = lambda force=False: None
        try:
            past, future = int(time.time()) - 60, int(time.time()) + 86400
            users = [{'id': 7, 'name': 'late', 'uuid': '00000000-0000-4000-8000-000000000007', 'hy2_pass': 'pass-seven',
                      'enabled': True, 'expire_at': past},
                     {'id': 8, 'name': 'soon', 'uuid': '00000000-0000-4000-8000-000000000008', 'hy2_pass': 'pass-eight',
                      'enabled': True, 'expire_at': future}]
            cluster.handle_sync(db.settings(), {'master': 'main', 'users': users})
            mine = {u['remote_id']: u for u in db.users() if u['remote_id']}
            self.assertEqual((mine[7]['enabled'], mine[7]['disabled_reason']), (0, 'expired'))
            self.assertEqual((mine[8]['enabled'], mine[8]['expire_at']), (1, future))
            jobs.enforce(now=future + 1)                     # main unreachable, the account runs out
            self.assertFalse(db.user(mine[8]['id'])['enabled'])
            with self.assertRaises(ValueError):
                cluster.handle_sync(db.settings(), {'master': 'main', 'users': [dict(users[0], expire_at='soon')]})
        finally:
            web.apply_async = orig

    def test_answers_of_a_round_started_before_a_restore_are_dropped(self):
        server = {'id': 'n1', 'name': 'n', 'url': 'https://203.0.113.5:8443', 'key': 'k', 'pin': '', 'enabled': True,
                  'info': {}, 'idmap': {}, 'seen': {}}
        db.set_settings(servers=[server])
        uid = mk('alice')['id']

        def fake_request(srv, payload, timeout=15):
            with cluster.restoring():            # a restore lands while the round waits for the node
                pass
            return {'ok': True, 'info': {}, 'idmap': {str(uid): 1}, 'traffic': {str(uid): [500, 500]}}, ''
        with mock.patch.object(cluster, '_request', fake_request):
            cluster.sync_all(log=lambda m: None)
        self.assertEqual(db.user(uid)['used_up'], 0)

    def test_unreachable_alert_is_sent_outside_the_locks(self):
        server = {'id': 'n2', 'name': 'n', 'url': 'https://203.0.113.6:8443', 'key': 'k', 'pin': '', 'enabled': True,
                  'info': {}, 'idmap': {}, 'seen': {}, 'fail_count': 4}
        db.set_settings(servers=[server])
        held = []
        with mock.patch.object(cluster, '_request', side_effect=cluster.SyncError('timed out')), \
                mock.patch.object(cluster.notify, 'send', lambda *a, **k: held.append(cluster._lock.locked())):
            cluster.sync_all(log=lambda m: None)
        self.assertEqual(held, [False])

    def test_qr_refuses_instead_of_cutting_the_link(self):
        from vps2vpn import qr
        with self.assertRaises(ValueError):
            qr.svg('x' * 5000)

    def test_placeholder_account_is_stable(self):
        s = db.settings()
        self.assertEqual(cores.hysteria_config(s, []), cores.hysteria_config(s, []))
        self.assertEqual(cores.tuic_config(s, []), cores.tuic_config(s, []))

    def test_self_signed_pair_is_recreated_when_the_key_is_lost(self):
        certs.ensure_self_signed('192.0.2.1')
        os.remove(paths.SELF_KEY)
        certs.ensure_self_signed('192.0.2.1')
        self.assertTrue(certs._pair_ok(paths.SELF_CRT, paths.SELF_KEY))

    def test_failed_certificate_write_puts_the_old_key_back(self):
        d = paths.ROOT if hasattr(paths, 'ROOT') else os.path.dirname(paths.SELF_KEY)
        key, crt = os.path.join(d, 'pair.key'), os.path.join(d, 'pair.crt')
        with open(key, 'wb') as f:
            f.write(b'old key')
        real = paths.write_atomic

        def failing(path, data, *a, **k):
            if path == crt:
                raise OSError('disk full')
            return real(path, data, *a, **k)
        with mock.patch.object(paths, 'write_atomic', failing), self.assertRaises(OSError):
            certs._publish_pair(key, b'new key', crt, b'new cert')
        with open(key, 'rb') as f:
            self.assertEqual(f.read(), b'old key')


class FewerRestarts(tu.Base):
    """Adding users reaches the running Xray through its API; a restart first banks the counters it would zero."""

    def setUp(self):
        super().setUp()
        db.set_settings(setup_done=True, reality_enabled=True, hy2_enabled=False, tuic_enabled=False)
        self.calls, self.runs, self.adu_files = [], [], []
        self.adu_answer = (0, 'Added 1 user(s) in total.\n')
        self.running = {cores.XRAY_UNIT}       # units systemd reports active

        def systemctl(*a):
            self.calls.append(a)
            return mock.Mock(returncode=0, stdout='', stderr='')

        def run(cmd, **kw):
            self.runs.append(cmd)
            if cmd[1:3] == ['api', 'adu']:
                with open(cmd[-1], encoding='utf-8') as f:
                    self.adu_files.append(json.load(f))
                code, out = self.adu_answer
                return mock.Mock(returncode=code, stdout=out, stderr='')
            return mock.Mock(returncode=0, stdout='{}', stderr='')
        for patch in (mock.patch.object(system, 'systemctl', systemctl),
                      mock.patch.object(system, 'unit_active', lambda unit: unit in self.running),
                      mock.patch.object(system, 'port_hopping', lambda s: None),
                      mock.patch.object(system, 'doh_servers', lambda max_age=86400: []),
                      mock.patch.object(cores.subprocess, 'run', run),
                      mock.patch.object(cores.paths, 'XRAY_BIN', os.path.abspath(__file__))):
            patch.start()
            self.addCleanup(patch.stop)

    def write_old(self, users, s=None):
        s = s or db.settings()
        paths.ensure_dirs()
        with open(paths.XRAY_CONFIG, 'w', encoding='utf-8') as f:
            f.write(json.dumps(cores.xray_config(s, users), indent=2, ensure_ascii=False) + '\n')

    def restarted(self):
        return [a[1] for a in self.calls if a[0] == 'restart']

    def adu_calls(self):
        return [c for c in self.runs if c[1:3] == ['api', 'adu']]

    def test_xray_config_enables_the_user_api(self):
        self.assertIn('HandlerService', cores.xray_config(db.settings(), [])['api']['services'])

    def test_added_user_goes_through_the_api_without_a_restart(self):
        old = mk('old')
        self.write_old([old])
        new = mk('new')
        cores.apply()
        self.assertNotIn(cores.XRAY_UNIT, self.restarted())
        adu = self.adu_calls()
        self.assertEqual(len(adu), 1)
        # Go's flag parser stops at the first positional argument: flags must come before the file
        self.assertEqual(adu[0][3], '--server=127.0.0.1:%d' % db.settings()['traffic_api_port'])
        inbound = self.adu_files[0]['inbounds'][0]
        self.assertEqual(inbound['tag'], cores.XRAY_INBOUND)
        self.assertEqual(inbound['settings']['clients'],
                         [{'id': new['uuid'], 'flow': 'xtls-rprx-vision', 'email': 'u%d' % new['id']}])
        self.assertFalse(os.path.exists(adu[0][-1]))          # the file with the UUIDs is gone again
        with open(paths.XRAY_CONFIG, encoding='utf-8') as f:  # and a later restart loads the same users
            emails = [c['email'] for c in json.load(f)['inbounds'][0]['settings']['clients']]
        self.assertEqual(sorted(emails), sorted(['u%d' % old['id'], 'u%d' % new['id']]))

    def test_other_change_restarts(self):
        u = mk('a')
        s = db.settings()
        self.write_old([u], dict(s, block_bt=not s['block_bt']))
        mk('b')
        cores.apply()
        self.assertIn(cores.XRAY_UNIT, self.restarted())
        self.assertFalse(self.adu_calls())

    def test_removed_or_rotated_user_restarts(self):
        a, b = mk('a'), mk('b')
        self.write_old([a, b])
        db.update_user(b['id'], enabled=0)                    # cut off: existing connections must drop too
        cores.apply()
        self.assertIn(cores.XRAY_UNIT, self.restarted())
        self.assertFalse(self.adu_calls())
        old = cores.xray_config(db.settings(), [a])
        new = cores.xray_config(db.settings(), [dict(a, uuid='00000000-0000-4000-8000-000000000000')])
        added, removed = cores.xray_user_diff(old, new)
        self.assertEqual((len(added), removed), (1, ['u%d' % a['id']]))
        self.assertIsNone(cores.xray_user_diff(None, new))

    def test_failed_api_call_falls_back_to_a_restart(self):
        for answer in ((1, 'failed to dial 127.0.0.1'), (0, 'User u2 already exists.\nAdded 0 user(s) in total.')):
            self.calls[:], self.runs[:] = [], []
            self.adu_answer = answer
            for u in db.users():
                db.delete_user(u['id'])
            self.write_old([mk('x')])
            mk('y')
            cores.apply()
            self.assertEqual(len(self.adu_calls()), 1, answer)
            self.assertIn(cores.XRAY_UNIT, self.restarted(), answer)

    def test_stopped_xray_is_started_not_called(self):
        self.write_old([mk('a')])
        mk('b')
        self.running = set()
        cores.apply()
        self.assertIn(cores.XRAY_UNIT, self.restarted())
        self.assertFalse(self.adu_calls())

    def test_traffic_is_collected_before_a_restart(self):
        u = mk('a')
        order = []

        def collect(s):
            order.append(('collect', s['reality_enabled'], s['hy2_enabled'], s['tuic_enabled']))
            return {u['id']: (100, 200)}

        def systemctl(*a):
            order.append(a)
            return mock.Mock(returncode=0, stdout='', stderr='')
        with mock.patch.object(cores, 'collect_traffic', collect), mock.patch.object(system, 'systemctl', systemctl):
            cores.apply(force=True)
        self.assertEqual(order[0], ('collect', True, False, False))     # only the cores going down: Xray here
        self.assertIn(('restart', cores.XRAY_UNIT), order)
        self.assertEqual(db.user(u['id'])['used_up'], 100)
        self.assertEqual(db.user(u['id'])['used_down'], 200)

    def test_failed_collection_does_not_block_the_restart(self):
        mk('a')
        with mock.patch.object(cores, 'collect_traffic', mock.Mock(side_effect=RuntimeError('core hung'))):
            cores.apply(force=True)
        self.assertIn(cores.XRAY_UNIT, self.restarted())

    def test_stopped_core_is_not_asked_for_counters(self):
        mk('a')
        self.running = set()
        with mock.patch.object(cores, 'collect_traffic', mock.Mock(return_value={})) as collect:
            cores.apply(force=True)
        collect.assert_not_called()
        self.assertIn(cores.XRAY_UNIT, self.restarted())

    def test_hot_add_does_not_collect(self):
        self.write_old([mk('a')])
        mk('b')
        with mock.patch.object(cores, 'collect_traffic', mock.Mock(return_value={})) as collect:
            cores.apply()
        collect.assert_not_called()
        self.assertEqual(self.restarted(), [])

    def test_only_the_core_whose_config_changed_restarts(self):
        db.set_settings(hy2_enabled=True, tuic_enabled=True)
        self.running = {cores.XRAY_UNIT, cores.HY2_UNIT, cores.TUIC_UNIT}
        mk('a')
        cores.write_configs()
        self.calls[:] = []
        db.set_settings(hy2_obfs='changed-obfs')              # a Hysteria-only setting
        with mock.patch.object(cores, 'collect_traffic', mock.Mock(return_value={})):
            cores.apply()
        self.assertEqual(self.restarted(), [cores.HY2_UNIT])

    def test_certificate_renewal_does_not_restart_the_quic_cores(self):
        db.set_settings(hy2_enabled=True, tuic_enabled=True)
        sched = jobs.Scheduler()
        with mock.patch.object(certs, 'renew_if_needed', lambda s, log=print: 'ok'), \
                mock.patch.object(cores, 'apply') as apply:
            sched.renew_cert(db.settings())
        apply.assert_not_called()
        self.assertEqual(self.restarted(), [])
        self.assertEqual(db.settings()['cert_status'], 'ok')
        # a certificate in other files (self-signed -> Let's Encrypt) changes the configs: apply them
        seq = iter([(paths.SELF_CRT, paths.SELF_KEY), (paths.ACME_CRT, paths.ACME_KEY)])
        with mock.patch.object(certs, 'renew_if_needed', lambda s, log=print: 'ok'), \
                mock.patch.object(certs, 'current', lambda host=None: next(seq)), \
                mock.patch.object(cores, 'apply') as apply:
            sched.renew_cert(db.settings())
        apply.assert_called_once_with()



class SubscriptionUX(tu.Base):
    """Browser-or-app detection, profile headers, the reason shown to disabled accounts, fetch bookkeeping."""

    def test_accept_decides_between_page_and_links(self):
        d = subscription.detect_format
        html_accept = 'text/html,application/xhtml+xml,*/*;q=0.8'
        self.assertEqual(d('Mozilla/5.0 Chrome/130', '', html_accept), '')
        self.assertEqual(d('Mozilla/5.0 Chrome/130', '', 'TEXT/HTML'), '')
        for ua in ('Happ/1.0', 'Streisand/2.1', 'V2Box/1.4', '', None, 'okhttp/4.9', 'Mozilla/5.0'):
            self.assertEqual(d(ua, '', ''), 'links', ua)
            self.assertEqual(d(ua, '', '*/*'), 'links', ua)
        # recognised apps keep their format whatever they accept
        for ua, fmt in (('clash-verge/v2.0', 'clash'), ('HiddifyNext/2.5', 'singbox'),
                        ('Shadowrocket/2000 CFNetwork', 'links'), ('mihomo/1.18', 'clash')):
            self.assertEqual(d(ua, '', html_accept), fmt)
            self.assertEqual(d(ua, '', ''), fmt)
        self.assertEqual(d('Mozilla/5.0', 'clash', html_accept), 'clash')
        self.assertEqual(d('Mozilla/5.0 Chrome/130'), '')            # callers without Accept: unchanged

    def _decode(self, v):
        self.assertTrue(v.startswith('base64:'), v)
        return base64.b64decode(v[len('base64:'):]).decode('utf-8')

    def test_profile_headers(self):
        db.set_settings(node_name='香港 节点', support_url='https://t.me/helpdesk')
        u = mk('ann')
        s = db.settings()
        for fmt in ('clash', 'singbox', 'links', 'shadowrocket'):
            _, _, h = subscription.render(fmt, s, u, 'https://example.org:8443')
            self.assertEqual(self._decode(h['Profile-Title']), '香港 节点')
            self.assertEqual(h['Profile-Web-Page-Url'], 'https://example.org:8443/s/%s' % u['sub_token'])
            self.assertEqual(h['Support-Url'], 'https://t.me/helpdesk')
            self.assertNotIn('Announce', h)                               # nothing to say while it works
            for v in h.values():
                v.encode('ascii')
                self.assertNotIn('\r', v)
                self.assertNotIn('\n', v)
        db.set_settings(support_url='')
        _, _, h = subscription.render('clash', db.settings(), u, 'https://example.org:8443')
        self.assertNotIn('Support-Url', h)
        # a bad value that got stored anyway (old backup, edited database) is not sent
        _, _, h = subscription.render('clash', dict(db.settings(), support_url='https://a.b/\r\nX-Evil: 1'), u, 'https://x')
        self.assertNotIn('Support-Url', h)
        for reason, word in (('quota', 'Quota used up'), ('expired', 'Expired'), ('devices', 'Paused'),
                             ('manual', 'Disabled'), ('', 'Disabled')):
            off = dict(u, enabled=0, disabled_reason=reason)
            _, _, h = subscription.render('links', db.settings(), off, 'https://x')
            self.assertIn(word, self._decode(h['Announce']))
            self.assertIn('请联系管理员', self._decode(h['Announce']))
            h['Announce'].encode('ascii')

    def test_heads_up_announce_for_a_working_account(self):
        s = db.settings()
        now = time.time()
        u = mk('soon', 10, expire_at=int(now + 2.5 * 86400))
        _, _, h = subscription.render('links', s, u, 'https://x')
        text = self._decode(h['Announce'])
        self.assertIn('3 天后到期', text)
        self.assertIn('expires in 3 day(s)', text)
        self.assertIn('请联系管理员', text)
        h['Announce'].encode('ascii')
        # far away, never, already past: nothing to say (a past date is the stopped-account text's job)
        for exp in (int(now + 30 * 86400), 0):
            _, _, h = subscription.render('clash', s, dict(u, expire_at=exp), 'https://x')
            self.assertNotIn('Announce', h, exp)
        self.assertIsNone(subscription.warning_text(dict(u, expire_at=int(now - 60))))
        # 90% of the quota used: how much is left
        low = dict(u, expire_at=0, used_down=int(9.5 * (1 << 30)))
        text = self._decode(subscription.render('singbox', s, low, 'https://x')[2]['Announce'])
        self.assertIn('0.50 GB', text)
        self.assertIn('流量只剩', text)
        self.assertNotIn('Announce', subscription.render('links', s, dict(low, used_down=8 << 30), 'https://x')[2])
        # the effective quota counts: 8 GB used of 10 is fine, of 10 minus 1.5 shared with an invitee it is not
        self.assertIn('Announce', subscription.render('links', s, dict(low, used_down=8 << 30), 'https://x', 8.5)[2])
        self.assertNotIn('Announce', subscription.render('links', s, dict(low, quota_gb=0), 'https://x')[2])
        both = subscription.warning_text(dict(low, expire_at=int(now + 86400)))
        self.assertIn('到期', both[0])
        self.assertIn('GB of data left', both[1])
        # a stopped account keeps its own reason, not the heads-up
        off = dict(low, enabled=0, disabled_reason='quota')
        self.assertIn('Quota used up', self._decode(subscription.render('links', s, off, 'https://x')[2]['Announce']))

    def test_update_interval_setting(self):
        s = db.settings()
        self.assertEqual(s['sub_update_hours'], 12)
        u = mk('upd')
        self.assertEqual(subscription.render('links', s, u, 'https://x')[2]['Profile-Update-Interval'], '12')
        for ok in (1, 6, '24', 168):
            self.assertEqual(web.validate_settings({'sub_update_hours': ok}, s), {'sub_update_hours': int(ok)})
        for bad in (0, -1, 169, 'often', None, 1e400, '1.5', 1.5, True):
            self.assertIsInstance(web.validate_settings({'sub_update_hours': bad}, s), str, bad)
        db.set_settings(sub_update_hours=6)
        self.assertEqual(subscription.render('clash', db.settings(), u, 'https://x')[2]['Profile-Update-Interval'], '6')
        # a bad value that got stored anyway (old backup, edited database) falls back to 12
        for bad in (0, 5000, 'x', None):
            self.assertEqual(subscription.update_hours(dict(s, sub_update_hours=bad)), 12, bad)

    def test_support_url_validation(self):
        s = db.settings()
        for ok in ('https://t.me/help', 'http://example.org/support?x=1', 'tg://resolve?domain=helpdesk', ''):
            self.assertEqual(web.validate_settings({'support_url': ok}, s), {'support_url': ok})
        self.assertEqual(web.validate_settings({'support_url': '  https://t.me/help\n'}, s),
                         {'support_url': 'https://t.me/help'})
        for bad in ('javascript:alert(1)', 'ftp://x.org/a', 'https://a.b/\r\nSet-Cookie: x', 'https://a b.c/',
                    'https://例子.cn/', 'tg://', 't.me/help', 'https://x.org/' + 'a' * 400):
            self.assertIsInstance(web.validate_settings({'support_url': bad}, s), str, bad)

    def _disabled(self, reason):
        u = mk('off-' + reason, 1, enabled=0, disabled_reason=reason)
        s = db.settings()
        # what web.subscription() hands over for a disabled account
        return u, dict(s, reality_enabled=False, hy2_enabled=False, tuic_enabled=False, servers=[]), s

    def _no_secrets(self, text, u, s):
        for secret in (s['public_host'], u['uuid'], u['hy2_pass'], s['reality_public_key'], s['reality_short_id']):
            self.assertNotIn(secret, text)

    def test_disabled_placeholder_per_format(self):
        u, off, s = self._disabled('expired')
        base = 'https://example.org:8443'
        name = subscription.placeholder_name(u)
        self.assertIn('已到期', name)
        self.assertIn('Expired', name)
        # Clash: one dead entry, selectable in the main group, all traffic still rejected
        c = subscription.clash(off, u, base)
        self.assertEqual([(p['name'], p['server'], p['port']) for p in c['proxies']], [(name, '0.0.0.0', 1)])
        self.assertEqual(c['rules'], ['MATCH,REJECT'])
        self.assertIn(name, c['proxy-groups'][0]['proxies'])
        self._no_secrets(json.dumps(c, ensure_ascii=False), u, s)
        # sing-box: same, and the route keeps rejecting everything
        sb = subscription.singbox(off, u, base)
        tags = {o['tag']: o for o in sb['outbounds']}
        self.assertEqual((tags[name]['server'], tags[name]['server_port']), ('0.0.0.0', 1))
        self.assertEqual(sb['route']['rules'], [{'action': 'reject'}])
        self.assertEqual(sb['route']['final'], 'direct')
        self.assertNotIn('dns', sb)
        self._no_secrets(json.dumps(sb, ensure_ascii=False), u, s)
        # Shadowrocket: a socks line to nowhere, FINAL,REJECT
        sr = subscription.shadowrocket(off, u, base, base + '/s/' + u['sub_token'])
        proxy = sr.split('[Proxy]\n', 1)[1].split('\n\n', 1)[0]
        self.assertEqual(proxy, '%s = socks5, 0.0.0.0, 1' % subscription._sr_label(name))
        self.assertIn('[Rule]\nFINAL,REJECT,dns-failed\n', sr)
        self._no_secrets('\n'.join(l for l in sr.splitlines() if not l.startswith('update-url')), u, s)
        # share links: one vless link to 0.0.0.0:1 with a zero key, named with the reason
        links = base64.b64decode(subscription.links_base64(off, u)).decode().split()
        self.assertEqual(len(links), 1)
        self.assertTrue(links[0].startswith('vless://00000000-0000-0000-0000-000000000000@0.0.0.0:1?'))
        self.assertEqual(urllib.parse.unquote(links[0].split('#', 1)[1]), name)
        self._no_secrets(links[0], u, s)
        # an account that works has no placeholder
        ok = mk('fine')
        self.assertEqual(subscription.placeholder_name(ok), '')
        self.assertNotIn('0.0.0.0', json.dumps(subscription.clash(s, ok, base)))
        for reason, word in (('quota', '流量已用完'), ('devices', '设备过多'), ('manual', '已停用')):
            self.assertIn(word, subscription.placeholder_name(dict(u, disabled_reason=reason)))

    def test_fetch_recording_and_throttle(self):
        u = mk('fetcher')
        self.assertEqual((u['sub_fetched_at'], u['sub_ua']), (0, ''))
        ua = 'clash-verge/2.0\r\n\x00évil' + 'x' * 300
        self.assertTrue(db.record_sub_fetch(u, ua, now=1000))
        u = db.user(u['id'])
        self.assertEqual(u['sub_fetched_at'], 1000)
        self.assertTrue(u['sub_ua'].startswith('clash-verge/2.0vil'))
        self.assertLessEqual(len(u['sub_ua']), db.SUB_UA_MAX)
        self.assertTrue(all(32 <= ord(c) < 127 for c in u['sub_ua']))
        self.assertFalse(db.record_sub_fetch(u, ua, now=1000 + db.SUB_FETCH_QUIET - 1))   # same app, soon after
        self.assertEqual(db.user(u['id'])['sub_fetched_at'], 1000)
        self.assertTrue(db.record_sub_fetch(u, ua, now=1000 + db.SUB_FETCH_QUIET))       # later: written again
        u = db.user(u['id'])
        self.assertTrue(db.record_sub_fetch(u, 'Shadowrocket/2000', now=u['sub_fetched_at'] + 5))   # another app
        self.assertEqual(db.user(u['id'])['sub_ua'], 'Shadowrocket/2000')

    def test_migration_and_backup_keep_fetch_columns(self):
        db.close()
        os.remove(paths.DB)
        c = sqlite3.connect(paths.DB)          # a database from before these columns
        try:
            c.executescript(
                'CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE, uuid TEXT NOT NULL,'
                'hy2_pass TEXT NOT NULL, sub_token TEXT NOT NULL UNIQUE, quota_gb REAL NOT NULL DEFAULT 0,'
                'expire_at INTEGER NOT NULL DEFAULT 0, reset_day INTEGER NOT NULL DEFAULT 0, used_up INTEGER NOT NULL DEFAULT 0,'
                'used_down INTEGER NOT NULL DEFAULT 0, enabled INTEGER NOT NULL DEFAULT 1, disabled_reason TEXT NOT NULL DEFAULT "",'
                'note TEXT NOT NULL DEFAULT "", last_seen INTEGER NOT NULL DEFAULT 0, last_reset TEXT NOT NULL DEFAULT "",'
                'created_at INTEGER NOT NULL, login_hash TEXT NOT NULL DEFAULT "", invited_by INTEGER NOT NULL DEFAULT 0,'
                'invite_deduct REAL NOT NULL DEFAULT 0, remote_id INTEGER NOT NULL DEFAULT 0, max_ips INTEGER NOT NULL DEFAULT 0,'
                'paused_until INTEGER NOT NULL DEFAULT 0, expire_after_days INTEGER NOT NULL DEFAULT 0);'
                "INSERT INTO users(name, uuid, hy2_pass, sub_token, created_at) VALUES('old', 'u', 'p', 'tok', 1);")
            c.commit()
        finally:
            c.close()
        u = db.users()[0]
        self.assertEqual((u['name'], u['sub_fetched_at'], u['sub_ua']), ('old', 0, ''))
        db.record_sub_fetch(u, 'Happ/1.0', now=12345)
        data = json.loads(json.dumps(db.export_all()))
        db.import_all(data)
        u = db.users()[0]
        self.assertEqual((u['sub_fetched_at'], u['sub_ua']), (12345, 'Happ/1.0'))
        # a backup made before these columns existed still imports
        for row in data['users']:
            row.pop('sub_fetched_at')
            row.pop('sub_ua')
        db.import_all(data)
        self.assertEqual((db.users()[0]['sub_fetched_at'], db.users()[0]['sub_ua']), (0, ''))


class SubscriptionUXWeb(tu.Base):
    """The same over real HTTPS."""

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

    tearDown = MemberWeb.tearDown
    req = tu.Web.req

    def _b64(self, v):
        return base64.b64decode(v.split(':', 1)[1]).decode('utf-8')

    def test_unknown_app_gets_links_browser_gets_page(self):
        u = mk('web-user', 10)
        path = '/s/%s' % u['sub_token']
        st, body, r = self.req('GET', path, headers={'User-Agent': 'Happ/1.0'})
        self.assertEqual(st, 200)
        self.assertTrue(base64.b64decode(body).startswith(b'hysteria2://'))
        self.assertEqual(self._b64(r.getheader('Profile-Title')), 'vps2vpn')
        self.assertTrue(r.getheader('Profile-Web-Page-Url').endswith(path))
        self.assertIsNone(r.getheader('Support-Url'))
        self.assertIsNone(r.getheader('Announce'))
        st, body, r = self.req('GET', path, headers={'User-Agent': 'Mozilla/5.0', 'Accept': 'text/html,*/*'})
        self.assertIn(('<base href="/s/%s/">' % u['sub_token']).encode(), body)
        st, body, r = self.req('GET', path, headers={'User-Agent': 'clash-verge/2.0', 'Accept': 'text/html'})
        self.assertIn(b'"proxies"', body)                        # a recognised app stays an app

    def test_fetch_recorded_and_shown_to_admin(self):
        u = mk('seen', 10)
        path = '/s/%s' % u['sub_token']
        self.req('GET', path, headers={'User-Agent': 'Mozilla/5.0', 'Accept': 'text/html'})
        self.assertEqual(db.user(u['id'])['sub_fetched_at'], 0)          # the web page is not a fetch
        self.req('GET', path, headers={'User-Agent': 'V2Box/1.4'})
        first = db.user(u['id'])
        self.assertEqual(first['sub_ua'], 'V2Box/1.4')
        self.assertGreater(first['sub_fetched_at'], 0)
        with mock.patch.object(db, 'record_sub_fetch', wraps=db.record_sub_fetch) as rec:
            st, _, _ = self.req('GET', path, headers={'User-Agent': 'V2Box/1.4'})   # throttled: nothing written
        self.assertEqual(st, 200)
        self.assertEqual(rec.call_count, 1)
        self.assertEqual(db.user(u['id'])['sub_fetched_at'], first['sub_fetched_at'])
        st, body, _ = self.req('POST', '/adm/api/login', {'username': 'admin', 'password': 'adminpassword'})
        self.assertEqual(st, 200, body)
        st, body, _ = self.req('GET', '/adm/api/state')
        row = [x for x in json.loads(body)['users'] if x['id'] == u['id']][0]
        self.assertEqual((row['sub_ua'], row['sub_fetched_at']), ('V2Box/1.4', first['sub_fetched_at']))
        st, body, _ = self.req('POST', '/adm/api/settings', {'support_url': 'tg://resolve?domain=help'})
        self.assertEqual(st, 200, body)
        st, _, r = self.req('GET', path, headers={'User-Agent': 'V2Box/1.4'})
        self.assertEqual(r.getheader('Support-Url'), 'tg://resolve?domain=help')
        st, body, _ = self.req('POST', '/adm/api/settings', {'support_url': 'https://a.b/\r\nX: y'})
        self.assertEqual(st, 400)

    def test_heads_up_and_interval_over_https(self):
        u = mk('ending', 10, expire_at=int(time.time() + 86400 + 600))
        path = '/s/%s' % u['sub_token']
        st, _, r = self.req('GET', path, headers={'User-Agent': 'Happ/1.0'})
        self.assertEqual(st, 200)
        self.assertIn('expires in 2 day(s)', self._b64(r.getheader('Announce')))
        self.assertEqual(r.getheader('Profile-Update-Interval'), '12')
        st, body, _ = self.req('POST', '/adm/api/login', {'username': 'admin', 'password': 'adminpassword'})
        self.assertEqual(st, 200, body)
        st, body, _ = self.req('POST', '/adm/api/settings', {'sub_update_hours': 3})
        self.assertEqual(st, 200, body)
        st, _, r = self.req('GET', path, headers={'User-Agent': 'Happ/1.0'})
        self.assertEqual(r.getheader('Profile-Update-Interval'), '3')
        st, body, _ = self.req('GET', '/adm/api/state')
        self.assertEqual(json.loads(body)['settings']['sub_update_hours'], 3)
        st, _, _ = self.req('POST', '/adm/api/settings', {'sub_update_hours': 999})
        self.assertEqual(st, 400)
        # a member who shares part of the quota is warned against what is left to them
        inv = mk('inv', 2, invited_by=u['id'], invite_deduct=1.5)
        db.update_user(u['id'], expire_at=0, used_down=int(8 * (1 << 30)))
        st, _, r = self.req('GET', path, headers={'User-Agent': 'Happ/1.0'})
        self.assertIn('0.50 GB', self._b64(r.getheader('Announce')))
        db.update_user(inv['id'], invite_deduct=0)
        st, _, r = self.req('GET', path, headers={'User-Agent': 'Happ/1.0'})
        self.assertIsNone(r.getheader('Announce'))

    def test_disabled_user_over_https(self):
        u = mk('gone', 1, enabled=0, disabled_reason='quota')
        s = db.settings()
        for fmt in ('clash', 'singbox', 'shadowrocket', 'links'):
            st, body, r = self.req('GET', '/s/%s?format=%s' % (u['sub_token'], fmt), headers={'User-Agent': 'x'})
            self.assertEqual(st, 200)
            text = base64.b64decode(body).decode() if fmt == 'links' else body.decode()
            self.assertIn('0.0.0.0', text)
            if fmt != 'links':
                self.assertIn('流量已用完', text)
            for secret in (u['uuid'], u['hy2_pass'], s['reality_public_key']):
                self.assertNotIn(secret, text)
            self.assertIn('Quota used up', self._b64(r.getheader('Announce')))
