"""Backend audit regressions. All network-facing tests use loopback servers or mocks."""
import concurrent.futures
import copy
import errno
import hashlib
import http.client
import json
import os
from pathlib import Path
import sqlite3
import socket
import ssl
import subprocess
import tempfile
import threading
import unittest
from unittest import mock

from tests import test_unit as tu
from vps2vpn import certs, cluster, cores, db, jobs, members, paths, subscription, system, web


class AtomicWrites(unittest.TestCase):
    def test_concurrent_writers_publish_complete_files(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'config.json'
            barrier = threading.Barrier(6)
            replace = os.replace
            payloads = [json.dumps({'writer': i, 'payload': str(i) * 20000}) for i in range(6)]

            def together(source, destination):
                barrier.wait(timeout=5)
                replace(source, destination)

            with mock.patch.object(paths.os, 'replace', side_effect=together):
                with concurrent.futures.ThreadPoolExecutor(6) as executor:
                    futures = [executor.submit(paths.write_atomic, target, value) for value in payloads]
                    for future in futures:
                        future.result(timeout=10)
            self.assertIn(target.read_text(), payloads)
            self.assertEqual(list(Path(directory).iterdir()), [target])
            if os.name != 'nt':
                self.assertEqual(target.stat().st_mode & 0o777, 0o600)

    def test_failed_publish_preserves_old_file_and_removes_scratch(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'secret'
            target.write_text('previous')
            with mock.patch.object(paths.os, 'replace', side_effect=OSError('rename failed')):
                with self.assertRaises(OSError):
                    paths.write_atomic(target, 'replacement')
            self.assertEqual(target.read_text(), 'previous')
            self.assertEqual(list(Path(directory).iterdir()), [target])


class DatabaseTransactions(tu.Base):
    def test_failed_extra_user_fields_leave_no_partial_account(self):
        with self.assertRaises(KeyError):
            db.add_user('partial', unsupported_field='bad')
        self.assertIsNone(db.user_by_name('partial'))
        self.assertFalse(db.connect().in_transaction)

    def test_case_insensitive_names_are_unique_inside_transaction(self):
        db.add_user('Alice')
        with self.assertRaises(ValueError):
            db.add_user('alice')
        self.assertEqual(len(db.users()), 1)

    def test_history_failure_rolls_back_usage_and_keeps_connection_usable(self):
        uid = db.add_user('alice')
        db.x("CREATE TEMP TRIGGER fail_history BEFORE INSERT ON traffic "
             "BEGIN SELECT RAISE(ABORT, 'history failed'); END")
        with self.assertRaises(sqlite3.IntegrityError):
            db.add_traffic(uid, 10, 20)
        self.assertEqual((db.user(uid)['used_up'], db.user(uid)['used_down']), (0, 0))
        self.assertFalse(db.connect().in_transaction)
        db.x('DROP TRIGGER fail_history')
        db.add_traffic(uid, 10, 20)
        self.assertEqual((db.user(uid)['used_up'], db.user(uid)['used_down']), (10, 20))

    def test_nested_transaction_rollback(self):
        with self.assertRaises(RuntimeError):
            with db.transaction():
                db.add_user('rolled-back')
                db.set_settings(node_name='rolled-back')
                raise RuntimeError('abort')
        self.assertIsNone(db.user_by_name('rolled-back'))
        self.assertNotEqual(db.settings()['node_name'], 'rolled-back')

    def test_bad_backup_cannot_mutate_tables_or_leave_transaction_open(self):
        db.add_user('retained')
        before = db.export_all()
        for bad in ([], dict(before, users='bad'), dict(before, invites=[{'unknown_column': 1}]),
                    dict(before, users=[dict(before['users'][0], quota_gb=float('nan'))])):
            with self.subTest(backup=type(bad).__name__):
                with self.assertRaises(ValueError):
                    db.import_all(bad)
                self.assertEqual(db.export_all(), before)
                self.assertFalse(db.connect().in_transaction)

    def test_restore_invalidates_sessions_and_roundtrips_history(self):
        uid = db.add_user('alice')
        db.add_traffic(uid, 10, 20)
        data = db.export_all()
        admin = db.new_session()
        member = db.new_member_session(uid)
        db.add_traffic(uid, 90, 180)
        db.import_all(data)
        self.assertFalse(db.session_ok(admin))
        self.assertIsNone(db.member_session(member))
        self.assertEqual([(r['up'], r['down']) for r in db.user_traffic(uid)], [(10, 20)])

    def test_legacy_backup_does_not_retain_unrelated_ids(self):
        uid = db.add_user('old')
        db.add_traffic(uid, 10, 20)
        members.create_invite('admin', 1, 1)
        db.add_request(uid, 2, 'old request')
        data = db.export_all()
        for table in ('traffic', 'requests', 'invites'):
            data.pop(table)
        db.import_all(data)
        self.assertEqual(db.user_traffic(uid), [])
        self.assertEqual(db.invites(), [])
        self.assertEqual(db.requests(), [])

    def test_restore_rejects_invalid_identity_and_user_ranges(self):
        db.add_user('alice')
        db.add_user('bob')
        before = db.export_all()
        for field, value in (('id', 0), ('uuid', 'not-a-uuid'), ('reset_day', 29),
                             ('expire_at', 253402300800), ('max_ips', 101), ('enabled', 2),
                             ('expire_after_days', 3651), ('hy2_pass', 'bad password'),
                             ('sub_token', 'bad/token'), ('name', 'bad\nname')):
            bad = copy.deepcopy(before)
            bad['users'][0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                db.import_all(bad)
            self.assertEqual(db.export_all(), before)
        for field, value in (('name', 'ALICE'), ('uuid', before['users'][0]['uuid'])):
            bad = copy.deepcopy(before)
            bad['users'][1][field] = value
            with self.subTest(duplicate=field), self.assertRaises(ValueError):
                db.import_all(bad)
            self.assertEqual(db.export_all(), before)

    def test_restore_rejects_orphan_and_cyclic_relationships(self):
        alice, bob = db.add_user('alice'), db.add_user('bob')
        db.add_traffic(alice, 10, 20)
        db.add_request(alice, 2, 'request')
        before = db.export_all()
        for table in ('traffic', 'requests'):
            bad = copy.deepcopy(before)
            bad[table][0]['user_id'] = 9999
            with self.subTest(table=table), self.assertRaises(ValueError):
                db.import_all(bad)
            self.assertEqual(db.export_all(), before)
        bad = copy.deepcopy(before)
        bad['users'][0]['invited_by'] = bob
        bad['users'][1]['invited_by'] = alice
        with self.assertRaisesRegex(ValueError, 'cyclic'):
            db.import_all(bad)
        self.assertEqual(db.export_all(), before)

    def test_restore_checks_nested_server_state_before_mutation(self):
        uid = db.add_user('alice')
        server = {'id': 'node1', 'name': 'node', 'url': 'https://node.example/p', 'key': 'node-key',
                  'pin': '', 'info': cluster.public_info(db.settings()), 'idmap': {str(uid): 42},
                  'seen': {str(uid): [10, 20]}, 'seen_epochs': {str(uid): 0}}
        db.set_settings(servers=[server])
        before = db.export_all()
        for field, value in (('info', []), ('info', {'public_host': 'incomplete'}),
                             ('idmap', {str(uid): '42'}), ('seen', {str(uid): [-1, 20]}),
                             ('seen_epochs', {str(uid): -1}), ('url', 'http://node.example/p')):
            bad = copy.deepcopy(before)
            bad['settings']['servers'][0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                db.import_all(bad)
            self.assertEqual(db.export_all(), before)
        db.import_all(before)
        self.assertEqual(db.export_all(), before)

    def test_restore_keeps_legacy_booleans_and_deleted_invite_history(self):
        inviter = db.add_user('inviter', 10)
        code = members.create_invite('member', 2, 7, inviter=inviter)
        child = members.register(code['code'], 'child', 'password123')
        db.delete_user(child)
        db.delete_user(inviter)
        uid = db.add_user('remaining')
        data = db.export_all()
        data['settings']['member_enabled'] = 1
        data['users'][0]['enabled'] = True
        db.import_all(data)
        self.assertEqual(db.user(uid)['enabled'], 1)
        self.assertIs(db.settings()['member_enabled'], True)
        self.assertEqual(db.invite(code['id'])['used_by'], str(child))

    def test_legacy_users_without_ids_receive_valid_unique_ids(self):
        db.add_user('legacy')
        data = db.export_all()
        data['users'][0].pop('id')
        db.import_all(data)
        self.assertGreater(db.users()[0]['id'], 0)

    def test_deleted_users_cannot_accrue_orphan_traffic(self):
        uid = db.add_user('deleted')
        db.delete_user(uid)
        db.add_traffic(uid, 10, 20)
        self.assertEqual(db.q('SELECT * FROM traffic'), [])

    def test_manual_counter_replacement_advances_epoch(self):
        uid = db.add_user('alice')
        before = db.user(uid)['traffic_epoch']
        db.add_traffic(uid, 10, 20)
        self.assertEqual(db.user(uid)['traffic_epoch'], before)
        db.update_user(uid, used_up=0, used_down=0)
        self.assertGreater(db.user(uid)['traffic_epoch'], before)

    def test_member_cannot_gift_already_consumed_quota(self):
        uid = db.add_user('alice', 10)
        db.add_traffic(uid, 0, 8 << 30)
        self.assertEqual(members.capacity(db.user(uid)), 2)
        with self.assertRaises(members.Refused):
            members.create_invite('member', 3, 7, inviter=uid, by_member=True)
        members.create_invite('member', 2, 7, inviter=uid, by_member=True)
        self.assertEqual(members.capacity(db.user(uid)), 0)

    def test_pending_invite_is_rechecked_after_inviter_spends_quota(self):
        uid = db.add_user('alice', 10)
        invite = members.create_invite('member', 9, 7, inviter=uid, by_member=True)
        db.add_traffic(uid, 0, 2 << 30)
        with self.assertRaises(members.Refused):
            members.register(invite['code'], 'child', 'password123')
        self.assertIsNone(db.user_by_name('child'))
        self.assertEqual(db.invite(invite['id'])['uses'], 0)

    def test_exhausted_child_cannot_refund_spent_quota_for_repeated_gifts(self):
        parent = db.add_user('parent', 10)
        invite = members.create_invite('member', 9, 7, inviter=parent, by_member=True)
        child = members.register(invite['code'], 'child', 'password123')
        db.add_traffic(child, 0, 9 << 30)
        jobs.enforce()
        self.assertFalse(db.user(child)['enabled'])
        self.assertEqual(members.effective_quota(db.user(parent)), 1)
        self.assertEqual(members.capacity(db.user(parent)), 0)
        with self.assertRaises(members.Refused):
            members.create_invite('member', 9, 7, inviter=parent, by_member=True)

    def test_inactive_child_releases_only_unused_part_and_keeps_grandchild_commitment(self):
        parent = db.add_user('parent', 10)
        invite = members.create_invite('member', 9, 7, inviter=parent)
        child = members.register(invite['code'], 'child', 'password123')
        invite2 = members.create_invite('member', 7, 7, inviter=child, by_member=True)
        grandchild = members.register(invite2['code'], 'grandchild', 'password123')
        db.add_traffic(child, 0, 1 << 30)
        db.update_user(child, enabled=0, disabled_reason='manual')
        self.assertEqual(members.given_away(parent), 8)  # 1 consumed + 7 still committed downstream
        db.add_traffic(grandchild, 0, 3 << 30)
        db.update_user(grandchild, enabled=0, disabled_reason='manual')
        self.assertEqual(members.given_away(parent), 4)  # Only the 5 unused GB return
        self.assertEqual(members.capacity(db.user(parent)), 5)

    def test_zero_use_pause_still_releases_the_whole_share(self):
        parent = db.add_user('parent', 10)
        invite = members.create_invite('member', 3, 7, inviter=parent)
        child = members.register(invite['code'], 'child', 'password123')
        db.update_user(child, enabled=0, disabled_reason='manual')
        self.assertEqual(members.given_away(parent), 0)
        self.assertEqual(members.capacity(db.user(parent)), 9)

    def test_deep_inactive_sharing_chain_does_not_recurse(self):
        users = [{'id': i, 'invited_by': i - 1, 'invite_deduct': 1, 'enabled': 0,
                  'expire_at': 0, 'used_up': 0, 'used_down': 1 if i == 1500 else 0}
                 for i in range(1, 1501)]
        self.assertEqual(members.given_away(0, users=users), 0)  # ID zero is never a real inviter.
        users[0]['invited_by'] = 2000
        self.assertEqual(members.given_away(2000, users=users), 1 / (1 << 30))

    def test_registration_failure_cannot_leave_an_unconsumed_grant(self):
        invite = members.create_invite('admin', 5, 1)
        with mock.patch.object(db, 'update_invite', side_effect=RuntimeError('write failed')):
            with self.assertRaises(RuntimeError):
                members.register(invite['code'], 'new-member', 'password123')
        self.assertIsNone(db.user_by_name('new-member'))
        self.assertEqual(db.invite(invite['id'])['uses'], 0)

    def test_only_one_registration_can_consume_last_invite_use(self):
        invite = members.create_invite('admin', 5, 1)
        barrier = threading.Barrier(4)

        def register(number):
            barrier.wait(timeout=5)
            try:
                return members.register(invite['code'], 'member%d' % number, 'password123')
            except members.Refused:
                return None

        with concurrent.futures.ThreadPoolExecutor(4) as executor:
            results = list(executor.map(register, range(4)))
        self.assertEqual(sum(uid is not None for uid in results), 1)
        self.assertEqual(db.invite(invite['id'])['uses'], 1)


class ClusterState(tu.Base):
    @staticmethod
    def remote(uid=7):
        return {'id': uid, 'name': 'member', 'uuid': '00000000-0000-4000-8000-%012d' % uid,
                'hy2_pass': 'test-password', 'enabled': True}

    def test_bound_master_cannot_be_bypassed_by_omitting_identity(self):
        with mock.patch.object(web, 'apply_async'):
            cluster.handle_sync(db.settings(), {'master_id': 'owner', 'users': [self.remote()]})
            result = cluster.handle_sync(db.settings(), {'users': []})
        self.assertTrue(result['conflict'])
        self.assertEqual(len([u for u in db.users() if u['remote_id']]), 1)

    def test_malformed_snapshot_never_deletes_existing_accounts(self):
        with mock.patch.object(web, 'apply_async'):
            cluster.handle_sync(db.settings(), {'users': [self.remote()]})
            before = db.users()
            for body in ({}, {'users': None}, {'users': {}}, {'users': [dict(self.remote(), uuid='bad')]},
                         {'users': [self.remote(), self.remote()]}, {'users': [dict(self.remote(), id=0)]}):
                with self.subTest(body=body):
                    with self.assertRaises(ValueError):
                        cluster.handle_sync(db.settings(), body)
                    self.assertEqual(db.users(), before)

    def test_node_update_failure_rolls_back_whole_snapshot(self):
        add_user = db.add_user
        calls = []

        def fail_second(*args, **kwargs):
            calls.append(1)
            if len(calls) == 2:
                raise RuntimeError('write failed')
            return add_user(*args, **kwargs)

        with mock.patch.object(db, 'add_user', side_effect=fail_second), mock.patch.object(web, 'apply_async'):
            with self.assertRaises(RuntimeError):
                cluster.handle_sync(db.settings(), {'users': [self.remote(7), self.remote(8)]})
        self.assertEqual(db.users(), [])

    def prepared_server(self):
        uid = db.add_user('alice')
        rid = str(uid)
        server = {'id': 'node1', 'name': 'node', 'url': 'https://node.example/p', 'key': 'node-key',
                  'pin': 'ab' * 32, 'seen': {rid: [10, 20]}, 'seen_epochs': {rid: 0}, 'idmap': {rid: 42}}
        db.set_settings(servers=[server])
        answer = {'info': {}, 'idmap': {rid: 42}, 'traffic': {rid: [100, 200]}, 'traffic_epochs': {rid: 0}}
        return uid, rid, server, answer

    def test_usage_and_remote_checkpoint_commit_together(self):
        uid, rid, server, answer = self.prepared_server()
        with mock.patch.object(cluster, '_request', return_value=(answer, server['pin'])):
            with mock.patch.object(db, 'set_settings', side_effect=RuntimeError('checkpoint failed')):
                with self.assertRaises(RuntimeError):
                    cluster.sync_one(server)
            self.assertEqual((db.user(uid)['used_up'], db.user(uid)['used_down']), (0, 0))
            self.assertEqual(db.settings()['servers'][0]['seen'][rid], [10, 20])
            self.assertTrue(cluster.sync_one(server))
            self.assertTrue(cluster.sync_one(server))
        self.assertEqual((db.user(uid)['used_up'], db.user(uid)['used_down']), (90, 180))
        self.assertEqual(db.settings()['servers'][0]['seen'][rid], [100, 200])

    def test_epoch_detects_reset_even_if_new_counters_already_exceed_old(self):
        uid, rid, server, answer = self.prepared_server()
        answer['traffic_epochs'][rid] = 1
        with mock.patch.object(cluster, '_request', return_value=(answer, server['pin'])):
            self.assertTrue(cluster.sync_one(server))
        self.assertEqual((db.user(uid)['used_up'], db.user(uid)['used_down']), (100, 200))

    def test_negative_node_counters_are_refused(self):
        uid, rid, server, answer = self.prepared_server()
        answer['traffic'][rid] = [-1, 20]
        with mock.patch.object(cluster, '_request', return_value=(answer, server['pin'])):
            self.assertFalse(cluster.sync_one(server))
        self.assertEqual(db.user(uid)['used_up'], 0)
        self.assertEqual(db.settings()['servers'][0]['seen'][rid], [10, 20])


class ClusterTLS(tu.Base):
    def setUp(self):
        super().setUp()
        db.set_settings(public_host='127.0.0.1', setup_done=True, panel_path='audit')
        certs.ensure_self_signed('127.0.0.1')
        self.server = web.Server(('127.0.0.1', 0), web.Handler, web.TLSContext())
        self.port = self.server.server_address[1]
        db.set_settings(panel_port=self.port)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.peer = {'url': 'https://127.0.0.1:%d/audit' % self.port,
                     'key': db.settings()['node_key'], 'pin': certs.fingerprint(paths.SELF_CRT)}

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()

    def test_pinned_self_signed_node_connects(self):
        answer, pin = cluster._request(self.peer, {'master_id': 'audit-master', 'users': []})
        self.assertTrue(answer['ok'])
        self.assertEqual(pin, self.peer['pin'])

    def test_missing_pin_never_disables_certificate_verification(self):
        with self.assertRaises(cluster.SyncError):
            cluster._request(dict(self.peer, pin=''), {'master_id': 'unauthenticated-peer', 'users': []})
        self.assertEqual(db.settings()['node_master_id'], '')


class CoreRegression(tu.Base):
    @staticmethod
    def sample(total, *connections):
        return {'uploadTotal': total, 'downloadTotal': total, 'connections': list(connections)}

    @staticmethod
    def connection(cid, uid, value):
        return {'id': cid, 'chains': ['u%d' % uid], 'upload': value, 'download': value}

    def test_tuic_timeout_does_not_recount_a_live_connection(self):
        meter = cores.TuicMeter()
        meter.sample({}, self.sample(0))
        meter.sample({}, self.sample(100, self.connection('c', 1, 100)))
        with mock.patch.object(meter, 'poll', side_effect=OSError('temporary timeout')):
            self.assertFalse(meter.sample({}))
        meter.sample({}, self.sample(150, self.connection('c', 1, 150)))
        self.assertEqual(meter.acc[1], (150, 150))

    def test_tuic_remainder_distribution_preserves_every_byte(self):
        meter = cores.TuicMeter()
        meter.sample({}, self.sample(0), users={1, 2})
        meter.sample({}, self.sample(200, self.connection('a', 1, 100),
                                    self.connection('b', 2, 100)), users={1, 2})
        meter.sample({}, self.sample(201), users={1, 2})
        self.assertEqual(sum(value[0] for value in meter.acc.values()), 201)
        self.assertEqual(sum(value[1] for value in meter.acc.values()), 201)

    def test_tuic_drops_deleted_user_weights(self):
        meter = cores.TuicMeter()
        meter.sample({}, self.sample(0), users={1})
        meter.sample({}, self.sample(100, self.connection('old', 1, 100)), users={1})
        meter.sample({}, self.sample(300), users={2})
        self.assertNotIn(1, meter.share)
        self.assertEqual(meter.acc[2], (200, 200))

    def test_reenable_restarts_unchanged_stopped_core(self):
        s = dict(db.settings(), hy2_enabled=False, tuic_enabled=False)
        with mock.patch.object(cores, 'write_configs', return_value=[]), \
                mock.patch.object(system, 'unit_active', return_value=False), \
                mock.patch.object(system, 'systemctl', return_value=subprocess.CompletedProcess([], 0, '', '')) as ctl, \
                mock.patch.object(system, 'port_hopping', return_value=None):
            cores.apply(s)
        self.assertIn(mock.call('restart', cores.XRAY_UNIT), ctl.call_args_list)

    def test_failed_systemctl_is_reported(self):
        with mock.patch.object(cores, 'write_configs', return_value=[]), \
                mock.patch.object(system, 'systemctl', return_value=subprocess.CompletedProcess([], 1, '', 'denied')), \
                mock.patch.object(system, 'port_hopping', return_value=None):
            with self.assertRaisesRegex(RuntimeError, 'denied'):
                cores.apply(db.settings(), force=True)

    def test_empty_hysteria_auth_is_private_stable_and_removed_for_real_users(self):
        s = db.settings()
        with mock.patch.object(system, 'doh_servers', return_value=[]):
            empty = cores.hysteria_config(s, [])['auth']['userpass']
            self.assertEqual(empty, cores.hysteria_config(s, [])['auth']['userpass'])
            changed = cores.hysteria_config(dict(s, stats_secret='different-secret'), [])['auth']['userpass']
            self.assertNotEqual(empty, changed)
            self.assertEqual(list(empty), ['_v2v_no_active_users'])
            self.assertEqual(len(next(iter(empty.values()))), 64)
            self.assertNotEqual(next(iter(empty.values())), s['stats_secret'])
            uid = db.add_user('alice')
            real = cores.hysteria_config(s, [db.user(uid)])['auth']['userpass']
        self.assertEqual(real, {'u%d' % uid: db.user(uid)['hy2_pass']})

    def test_private_destination_checks_run_after_dns_resolution(self):
        with mock.patch.object(system, 'doh_servers', return_value=[]):
            xray = cores.xray_config(db.settings(), [])
            tuic = cores.tuic_config(db.settings(), [])
        self.assertEqual(xray['routing']['domainStrategy'], 'IPOnDemand')
        rules = tuic['route']['rules']
        resolve = next(i for i, rule in enumerate(rules) if rule.get('action') == 'resolve')
        private = next(i for i, rule in enumerate(rules) if rule.get('ip_is_private'))
        self.assertLess(resolve, private)
        self.assertIn(tuic['route']['default_domain_resolver'], {s['tag'] for s in tuic['dns']['servers']})


class CertificateAndAddress(tu.Base):
    def test_acme_challenge_falls_back_when_ipv6_is_unavailable(self):
        for code in (errno.EAFNOSUPPORT, errno.EADDRNOTAVAIL):
            fake = mock.MagicMock()
            fake.getsockname.return_value = ('0.0.0.0', 80)
            with self.subTest(errno=code), \
                    mock.patch.object(certs.socket, 'socket', side_effect=[OSError(code, 'IPv6 unavailable'), fake]) as create, \
                    mock.patch.object(certs.socket, 'getfqdn', return_value='localhost'), \
                    mock.patch.object(certs.threading, 'Thread'):
                challenge = certs._ChallengeServer()
                try:
                    self.assertEqual([call.args[0] for call in create.call_args_list],
                                     [socket.AF_INET6, socket.AF_INET])
                    fake.bind.assert_called_once_with(('0.0.0.0', 80))
                finally:
                    challenge.httpd.server_close()

    def test_acme_challenge_does_not_hide_port_busy(self):
        with mock.patch.object(certs.socket, 'socket', side_effect=OSError(errno.EADDRINUSE, 'port busy')) as create, \
                mock.patch.object(certs.threading, 'Thread') as thread:
            with self.assertRaisesRegex(certs.AcmeError, 'busy'):
                certs._ChallengeServer()
        create.assert_called_once()
        thread.assert_not_called()

    def test_missing_self_signed_key_is_recreated_as_a_matching_pair(self):
        os.unlink(paths.SELF_KEY)
        certs.ensure_self_signed('203.0.113.7')
        ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER).load_cert_chain(paths.SELF_CRT, paths.SELF_KEY)

    def test_ipv6_subject_alternative_name_is_compared_canonically(self):
        certs._trust_cache.clear()
        with mock.patch.object(certs.os, 'stat', return_value=mock.Mock(st_mtime_ns=1)), \
                mock.patch.object(certs, '_openssl'), mock.patch.object(certs.ssl, 'SSLContext'), \
                mock.patch.object(certs, 'acme_valid', return_value=True), \
                mock.patch.object(certs, 'acme_names', return_value=['2001:DB8:0:0:0:0:0:1']):
            self.assertTrue(certs.trusted('2001:db8::1'))

    def test_chain_fingerprint_uses_leaf_certificate(self):
        with open(paths.SELF_CRT) as source:
            pem = source.read()
        expected = hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem)).hexdigest()
        target = Path(paths.CERT_DIR) / 'chain.pem'
        target.write_text(pem + pem)
        self.assertEqual(certs.fingerprint(target), expected)

    def test_public_ip_requires_authenticated_https(self):
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.read.return_value = b'ip=8.8.8.8\n'
        with mock.patch.object(system.urllib.request, 'urlopen', return_value=response) as opening:
            self.assertEqual(system.public_ip(), '8.8.8.8')
        context = opening.call_args.kwargs['context']
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)

    def test_public_ip_rejects_names_and_private_addresses(self):
        response = mock.MagicMock()
        response.__enter__.return_value = response
        for value in ('attacker.example', '127.0.0.1', 'not an address'):
            response.read.return_value = ('ip=' + value + '\n').encode()
            with self.subTest(value=value), mock.patch.object(system.urllib.request, 'urlopen', return_value=response):
                self.assertEqual(system.public_ip(), '')


class SubscriptionNamespace(tu.Base):
    def test_proxy_and_group_names_remain_unique_across_servers(self):
        uid = db.add_user('alice')
        u = db.user(uid)
        s = dict(db.settings(), node_name='Auto', language='en')
        info = cluster.public_info(s)
        s['servers'] = [{'id': 'node2', 'name': 'Auto 2 Hysteria2', 'info': info, 'idmap': {str(uid): 7}},
                        {'id': 'node3', 'name': 'Auto', 'info': info, 'idmap': {str(uid): 8}}]
        clash = subscription.clash(s, u, 'https://example.com')
        names = [p['name'] for p in clash['proxies']] + [g['name'] for g in clash['proxy-groups']]
        self.assertEqual(len(names), len(set(names)))
        known = set(names) | {'DIRECT', 'REJECT'}
        for group in clash['proxy-groups']:
            self.assertTrue(set(group['proxies']) <= known)
            self.assertNotIn(group['name'], group['proxies'])
        singbox = subscription.singbox(s, u, 'https://example.com')
        tags = [o['tag'] for o in singbox['outbounds']]
        self.assertEqual(len(tags), len(set(tags)))

    def test_subscription_usage_header_reports_shared_effective_quota(self):
        uid = db.add_user('alice', quota_gb=10)
        invite = members.create_invite('member', 3, 1, inviter=uid)
        members.register(invite['code'], 'bob', 'password123')
        self.assertIn('total=%d;' % (7 << 30), subscription.userinfo_header(db.user(uid)))


if __name__ == '__main__':
    unittest.main()
