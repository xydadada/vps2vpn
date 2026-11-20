"""Tests for the features ported from the original console: member centre, invite codes, quota requests,
per-user history, server monthly traffic, site monitor, abuse watch, Shadowrocket config, several servers.

    python -m unittest tests.test_unit tests.test_features
"""
import hashlib
import http.client
import io
import json
import os
import socket
import sqlite3
import ssl
import threading
import time
import unittest
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


class Abuse(tu.Base):
    def test_flags(self):
        flows = [(1, 'h%d.example' % i, 1000 + i % 40) for i in range(250)] + [(2, 'a.com', 443)] * 300 + \
                [(3, 'mx%d.example' % i, 25) for i in range(30)]
        rep = abuse.aggregate(flows, {4: {'ips': ['10.0.0.%d' % i for i in range(9)]}, 2: {'ips': ['1.1.1.1']}})
        self.assertEqual(rep[1]['flags'], ['fanout'])
        self.assertEqual(rep[2]['flags'], [])                  # many streams to one site is normal
        self.assertEqual(rep[3]['flags'], ['mail'])
        self.assertEqual(rep[4]['flags'], ['shared'])
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
        self.assertEqual(report[8]['devices'], 2)
        self.assertEqual(report[9]['ips'], [])
        self.assertNotIn(0, report)

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
