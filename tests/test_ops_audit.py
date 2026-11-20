"""Regression cases for the 2026-11-20 operational/security audit.

Run with: python -m unittest tests.test_ops_audit -v
These tests use temporary dev paths and mocks, never production services.
"""
import base64
import copy
import http.client
import http.server
import importlib.util
import io
import json
import os
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import types
import unittest
import urllib.error
from unittest.mock import MagicMock, patch

from tests import test_unit as tu
from tests.test_deploy import deploy
from vps2vpn import __main__ as cli
from vps2vpn import aicheck, bench, certs, cluster, cores, db, jobs, monitor, notify, paths, system, web


def remote(uid, name='member'):
    return {'id': uid, 'name': name, 'uuid': '00000000-0000-4000-8000-%012d' % uid,
            'hy2_pass': 'safe-password', 'enabled': True}


class ClusterSafety(tu.Base):
    def test_rejects_incomplete_snapshots_without_deleting_accounts(self):
        with patch.object(web, 'apply_async'):
            cluster.handle_sync(db.settings(), {'master_id': 'owner', 'users': [remote(7)]})
            before = db.users()
            for bad in ({}, {'users': None}, {'users': [dict(remote(7), uuid='broken')]},
                        {'users': [remote(7), remote(7)]}, {'users': [remote(0)]}):
                bad['master_id'] = 'owner'
                with self.subTest(body=bad), self.assertRaises(ValueError):
                    cluster.handle_sync(db.settings(), bad)
                self.assertEqual(db.users(), before)
            self.assertTrue(cluster.handle_sync(db.settings(), {'users': []})['conflict'])
            self.assertEqual(db.users(), before)
            self.assertTrue(cluster.handle_sync(db.settings(),
                {'master_id': db.settings()['install_id'], 'users': []})['conflict'])

    def test_snapshot_rolls_back_and_truncated_names_are_unique(self):
        real_add = db.add_user
        calls = []

        def fail_second(*args, **kwargs):
            calls.append(1)
            if len(calls) == 2:
                raise RuntimeError('injected failure')
            return real_add(*args, **kwargs)

        rows = [remote(7, 'x' * 24), remote(9, 'x' * 24)]
        with patch.object(db, 'add_user', side_effect=fail_second), patch.object(web, 'apply_async') as apply:
            with self.assertRaises(RuntimeError):
                cluster.handle_sync(db.settings(), {'master': 'y' * 24, 'users': rows})
            self.assertEqual(db.users(), [])
            apply.assert_not_called()
        with patch.object(web, 'apply_async'):
            cluster.handle_sync(db.settings(), {'master': 'y' * 24, 'users': rows})
        names = [u['name'] for u in db.users()]
        self.assertEqual(len(set(names)), 2)
        self.assertTrue(all(len(n) <= 32 for n in names))

    def test_traffic_and_cursor_commit_together_and_retry_is_idempotent(self):
        uid = db.add_user('local')
        server = {'id': 'node1', 'name': 'node', 'url': 'https://node/p', 'key': 'secret',
                  'pin': '', 'seen': {str(uid): [100, 200]}}
        db.set_settings(servers=[server])
        stale = copy.deepcopy(server)
        answer = {'traffic': {str(uid): [150, 260]}, 'info': {}, 'idmap': {}}
        with patch.object(cluster, '_request', return_value=(answer, 'a' * 64)):
            with patch.object(db, 'set_settings', side_effect=RuntimeError('disk full')):
                with self.assertRaises(RuntimeError):
                    cluster.sync_one(server)
            self.assertEqual(db.user(uid)['used_up'], 0)
            self.assertEqual(db.settings()['servers'][0]['seen'][str(uid)], [100, 200])
            self.assertTrue(cluster.sync_one(server))
            self.assertTrue(cluster.sync_one(stale))
        user = db.user(uid)
        self.assertEqual((user['used_up'], user['used_down']), (50, 60))
        self.assertEqual(db.settings()['servers'][0]['seen'][str(uid)], [150, 260])

    def test_malformed_traffic_cannot_partially_charge(self):
        uid = db.add_user('local')
        server = {'id': 'node1', 'name': 'node', 'url': 'https://node/p', 'key': 'secret',
                  'seen': {str(uid): [0, 0]}}
        db.set_settings(servers=[server])
        answer = {'traffic': {str(uid): [100, 0], 'bad': [-1, 0]}}
        with patch.object(cluster, '_request', return_value=(answer, 'a' * 64)):
            self.assertFalse(cluster.sync_one(server))
        self.assertEqual(db.user(uid)['used_up'], 0)
        self.assertEqual(db.settings()['servers'][0]['seen'][str(uid)], [0, 0])

    def test_join_code_validation(self):
        for url, pin in (('https://user:pw@example.org/p', ''), ('https://example.org:99999/p', ''),
                         ('https://example.org/p?x=1', ''), ('https://example.org/p', 'broken'),
                         ('https://example.org/\npath', ''), ('http://example.org/p', '')):
            raw = json.dumps({'u': url, 'k': 'secret', 'p': pin}).encode()
            code = 'v2v1.' + base64.urlsafe_b64encode(raw).decode().rstrip('=')
            with self.subTest(url=url), self.assertRaises(ValueError):
                cluster.parse_join_code(code)

    def test_no_secret_post_to_untrusted_unpinned_tls_peer(self):
        certs.ensure_self_signed('127.0.0.1')
        posts = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                posts.append(self.rfile.read(int(self.headers['Content-Length'])))
                body = b'{"traffic": {}}'
                self.send_response(200)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        server = http.server.HTTPServer(('127.0.0.1', 0), Handler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(paths.SELF_CRT, paths.SELF_KEY)
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        node = {'url': 'https://127.0.0.1:%d/p' % server.server_port, 'key': 'secret', 'pin': ''}
        try:
            with self.assertRaises(cluster.SyncError):
                cluster._request(node, {'users': [remote(7)]}, timeout=3)
            self.assertEqual(posts, [])
            node['pin'] = certs.fingerprint(paths.SELF_CRT)
            answer, pin = cluster._request(node, {'users': [remote(7)]}, timeout=3)
            self.assertEqual(answer['traffic'], {})
            self.assertEqual(pin, node['pin'])
            self.assertEqual(len(posts), 1)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(3)


class TuicAccounting(unittest.TestCase):
    @staticmethod
    def reading(total, uid=1):
        return {'uploadTotal': total, 'downloadTotal': 0,
                'connections': [{'id': 'connection', 'chains': ['u%d' % uid],
                                 'upload': total, 'download': 0}]}

    def test_transient_poll_failure_keeps_connection_baseline(self):
        meter = cores.TuicMeter()
        meter.sample({}, self.reading(0), {1})
        meter.sample({}, self.reading(100), {1})
        with patch.object(meter, 'poll', side_effect=OSError('temporary outage')):
            self.assertEqual(meter.collect({}, {1}), {1: (100, 0)})
        meter.sample({}, self.reading(150), {1})
        self.assertEqual(meter.acc, {1: (50, 0)})

    def test_poll_and_update_order_is_serialized(self):
        meter = cores.TuicMeter()
        meter.sample({}, self.reading(0), {1})
        entered, release, second_poll = threading.Event(), threading.Event(), threading.Event()
        count = []

        def poll(_s):
            count.append(1)
            if len(count) == 1:
                entered.set()
                if not release.wait(3):
                    raise RuntimeError('test timed out')
                return self.reading(100)
            second_poll.set()
            return self.reading(200)

        with patch.object(meter, 'poll', side_effect=poll):
            a = threading.Thread(target=meter.sample, args=({},), kwargs={'users': {1}})
            b = threading.Thread(target=meter.sample, args=({},), kwargs={'users': {1}})
            a.start()
            try:
                self.assertTrue(entered.wait(2))
                b.start()
                self.assertFalse(second_poll.wait(0.1))
            finally:
                release.set()
                a.join(3)
                if b.ident is not None:
                    b.join(3)
        self.assertFalse(a.is_alive())
        self.assertFalse(b.is_alive())
        self.assertEqual(meter.acc[1], (200, 0))

    def test_remainder_rounding_and_inactive_weights(self):
        meter = cores.TuicMeter()
        meter.total, meter.share = (0, 0), {1: 10, 2: 10}
        meter.sample({}, {'uploadTotal': 1, 'downloadTotal': 0, 'connections': []}, {1, 2})
        self.assertEqual(sum(v[0] for v in meter.acc.values()), 1)
        before = meter.acc.get(1, (0, 0))
        meter.sample({}, {'uploadTotal': 101, 'downloadTotal': 0, 'connections': []}, {2})
        self.assertEqual(meter.acc.get(1, (0, 0)), before)
        self.assertEqual(sum(v[0] for v in meter.acc.values()), 101)


class TrustAndOperations(tu.Base):
    def test_public_ip_authenticates_peer_and_rejects_nonpublic_data(self):
        def response(text):
            r = MagicMock()
            r.__enter__.return_value.read.return_value = text.encode()
            return r

        with patch.object(system.urllib.request, 'urlopen', return_value=response('ip=8.8.8.8\n')) as call:
            self.assertEqual(system.public_ip(), '8.8.8.8')
            ctx = call.call_args.kwargs['context']
            self.assertTrue(ctx.check_hostname)
            self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)
        for ip in ('127.0.0.1', '169.254.169.254', 'not-an-address'):
            with patch.object(system.urllib.request, 'urlopen', return_value=response('ip=' + ip)):
                self.assertEqual(system.public_ip(), '')

    def test_missing_self_key_is_regenerated_and_self_cert_is_not_public_trust(self):
        os.unlink(paths.SELF_KEY)
        certs.ensure_self_signed('203.0.113.7')
        ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER).load_cert_chain(paths.SELF_CRT, paths.SELF_KEY)
        shutil.copyfile(paths.SELF_CRT, paths.ACME_CRT)
        shutil.copyfile(paths.SELF_KEY, paths.ACME_KEY)
        certs._trust_cache.clear()
        self.assertTrue(certs.acme_valid())
        self.assertFalse(certs.trusted('203.0.113.7'))
        self.assertEqual(certs._identity('2001:0db8:0:0::1'), certs._identity('2001:db8::1'))

    def test_staging_does_not_activate_and_live_issuance_forces_core_reload(self):
        with patch.object(certs, 'issue'), patch.object(cores, 'apply') as apply:
            before = db.settings()['cert_status']
            cli.cmd_cert(types.SimpleNamespace(staging=True))
            self.assertEqual(db.settings()['cert_status'], before)
            apply.assert_not_called()
            cli.cmd_cert(types.SimpleNamespace(staging=False))
            apply.assert_called_once_with(force=True)

    def test_monthly_reset_precedes_all_quota_checks(self):
        ids = [db.add_user(name, quota_gb=10, reset_day=1) for name in ('parent', 'child')]
        for uid in ids:
            db.add_traffic(uid, 100, 200)
        checked = []

        def effective(user, users, now):
            self.assertTrue(all(u['used_up'] == u['used_down'] == 0 for u in users))
            checked.append(user['id'])
            return user['quota_gb']

        with patch.object(jobs.members, 'effective_quota', side_effect=effective):
            jobs.enforce()
        self.assertCountEqual(checked, ids)

    def test_kernel_memory_uses_actual_page_size(self):
        with patch.object(system.os, 'sysconf', return_value=65536, create=True):
            self.assertIn('net.ipv4.tcp_mem = 1024 2048 4096', system.sysctl_text(1024))

    def test_nft_replacement_is_one_transaction(self):
        ok = subprocess.CompletedProcess([], 0, '', '')
        with patch.object(paths, 'LIVE', True), patch.object(system.shutil, 'which', return_value='/sbin/nft'), \
                patch.object(system, 'run', return_value=ok) as run, \
                patch.object(system.subprocess, 'run', return_value=ok) as execute:
            self.assertEqual(system.port_hopping(db.settings()), 'ok')
        self.assertEqual(run.call_args.args[0], ['nft', 'list', 'table', 'inet', system.NFT_TABLE])
        self.assertEqual(execute.call_count, 1)
        self.assertTrue(execute.call_args.kwargs['input'].startswith('delete table inet vps2vpn\n'))

    def test_failed_service_restart_reaches_installer(self):
        failed = subprocess.CompletedProcess([], 1, '', 'injected restart failure')
        with patch.object(cores, 'write_configs', return_value=[]), \
                patch.object(system, 'systemctl', return_value=failed), patch.object(system, 'port_hopping', return_value=None):
            with self.assertRaisesRegex(RuntimeError, 'injected restart failure'):
                cores.apply(force=True)

    def test_private_address_routing_keeps_real_destination(self):
        cfg = cores.xray_config(db.settings(), [])
        self.assertEqual(cfg['routing']['domainStrategy'], 'IPOnDemand')
        self.assertEqual(cfg['inbounds'][0]['sniffing']['destOverride'], [])

    def test_probe_closes_both_sockets_on_read_failure(self):
        raw, tls = MagicMock(), MagicMock()
        raw.__enter__.return_value = raw
        tls.__enter__.return_value = tls
        tls.recv.side_effect = OSError('read failed')
        ctx = MagicMock()
        ctx.wrap_socket.return_value = tls
        with patch.object(monitor.socket, 'getaddrinfo', return_value=[(0, 0, 0, '', ('127.0.0.1', 443))]), \
                patch.object(monitor.socket, 'create_connection', return_value=raw), \
                patch.object(monitor.ssl, 'create_default_context', return_value=ctx):
            self.assertFalse(monitor.probe('example.org', '/', socket.AF_INET)['ok'])
        raw.__exit__.assert_called_once()
        tls.__exit__.assert_called_once()

    def test_claude_summary_does_not_hide_failed_website(self):
        for status in ('unknown', 'unreachable', 'blocked'):
            res = {'sites': {name: {'status': 'ok'} for name in aicheck.SITES}}
            res['sites']['claude']['status'] = status
            self.assertNotIn('Claude ' + aicheck.MARK['ok'], aicheck.summary(res))



class EnforcementConcurrency(tu.Base):
    def interleave(self, update):
        """Pause immediately after the scheduler snapshot and attempt a competing write."""
        captured, resume, attempted, completed = (threading.Event() for _ in range(4))
        original = db.users
        errors = []

        def snapshot():
            rows = original()
            captured.set()
            if not resume.wait(5):
                raise RuntimeError('snapshot test timeout')
            return rows

        def enforce():
            try:
                jobs.enforce()
            except BaseException as exc:
                errors.append(exc)

        def mutate():
            attempted.set()
            try:
                update()
            except BaseException as exc:
                errors.append(exc)
            finally:
                completed.set()

        a = threading.Thread(target=enforce, daemon=True)
        b = threading.Thread(target=mutate, daemon=True)
        with patch.object(db, 'users', side_effect=snapshot), patch.object(jobs, 'log'):
            a.start()
            try:
                self.assertTrue(captured.wait(3))
                b.start()
                self.assertTrue(attempted.wait(3))
                self.assertFalse(completed.wait(0.1), 'write interleaved after the scheduler snapshot')
            finally:
                resume.set()
                a.join(5)
                if b.ident is not None:
                    b.join(5)
        self.assertFalse(a.is_alive())
        self.assertFalse(b.is_alive())
        self.assertEqual(errors, [])

    def test_month_reset_does_not_erase_concurrent_traffic(self):
        uid = db.add_user('metered', reset_day=1)
        db.add_traffic(uid, 100, 200)
        self.interleave(lambda: db.add_traffic(uid, 7, 11))
        u = db.user(uid)
        self.assertEqual((u['used_up'], u['used_down']), (7, 11))
        self.assertEqual(u['last_reset'], time.strftime('%Y-%m'))

    def test_enforce_cannot_overwrite_a_concurrent_manual_pause(self):
        uid = db.add_user('paused', enabled=0, disabled_reason='quota')
        self.interleave(lambda: db.update_user(uid, enabled=0, disabled_reason='manual'))
        u = db.user(uid)
        self.assertEqual((u['enabled'], u['disabled_reason']), (0, 'manual'))

    def test_alerts_are_sent_after_database_commit(self):
        uid = db.add_user('exhausted', quota_gb=1)
        db.add_traffic(uid, 0, 1 << 30)
        sent = []

        def send(text, **kwargs):
            self.assertFalse(db.connect().in_transaction)
            self.assertEqual(db.user(uid)['disabled_reason'], 'quota')
            sent.append(text)

        with patch.object(notify, 'send', side_effect=send), patch.object(jobs, 'log'):
            self.assertTrue(jobs.enforce())
        self.assertEqual(len(sent), 1)

    def test_failed_reset_rolls_back_every_account_without_external_side_effects(self):
        ids = [db.add_user(name, reset_day=1) for name in ('first', 'second')]
        for uid in ids:
            db.add_traffic(uid, 100, 200)
        original, calls = db.update_user, []

        def update(uid, **kwargs):
            calls.append(uid)
            if len(calls) == 2:
                raise RuntimeError('injected update failure')
            return original(uid, **kwargs)

        with patch.object(db, 'update_user', side_effect=update), \
                patch.object(notify, 'send') as send, patch.object(jobs, 'log') as log:
            with self.assertRaisesRegex(RuntimeError, 'injected update failure'):
                jobs.enforce()
            send.assert_not_called()
            log.assert_not_called()
        for uid in ids:
            self.assertEqual((db.user(uid)['used_up'], db.user(uid)['used_down']), (100, 200))
            self.assertEqual(db.user(uid)['last_reset'], '')

    def test_restored_ids_do_not_change_descendant_first_enforcement(self):
        parent = db.add_user('parent', quota_gb=10)
        child = db.add_user('child', quota_gb=4, invited_by=parent, invite_deduct=4,
                            enabled=0, disabled_reason='quota')
        db.add_traffic(parent, 0, 8 << 30)
        backup = db.export_all()
        for u in backup['users']:
            if u['id'] == parent:
                u['id'] = 200
            elif u['id'] == child:
                u.update(id=100, invited_by=200)
        db.import_all(backup)
        with patch.object(notify, 'send'), patch.object(jobs, 'log'):
            self.assertTrue(jobs.enforce())
        self.assertEqual(db.user(100)['enabled'], 1)
        self.assertEqual((db.user(200)['enabled'], db.user(200)['disabled_reason']), (0, 'quota'))

    def test_quota_order_handles_deep_graphs_and_cycles_without_recursion(self):
        rows = [{'id': i, 'invited_by': i - 1} for i in range(1, 2501)]
        self.assertEqual([u['id'] for u in jobs._quota_order(rows)], list(range(2500, 0, -1)))
        cycle = [{'id': 1, 'invited_by': 2}, {'id': 2, 'invited_by': 1}]
        self.assertCountEqual([u['id'] for u in jobs._quota_order(cycle)], [1, 2])


class NodeSyncHttp(tu.Base):
    def setUp(self):
        super().setUp()
        db.set_settings(setup_done=True, panel_path='adm', public_host='127.0.0.1')
        self.httpd = web.Server(('127.0.0.1', 0), web.Handler, web.TLSContext())
        self.port = self.httpd.server_address[1]
        self.worker = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.worker.start()

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.worker.join(5)

    def test_malformed_node_snapshots_are_http_400_and_leave_accounts_unchanged(self):
        with patch.object(web, 'apply_async'):
            cluster.handle_sync(db.settings(), {'master_id': 'owner', 'users': [remote(7)]})
        before = db.users()
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # this isolated test connects to the temporary self-signed server
        bodies = [b'{', b'[]', b'{"master_id":"owner"}',
                  json.dumps({'master_id': 'owner', 'users': [dict(remote(7), uuid='broken')]}).encode()]
        for body in bodies:
            conn = http.client.HTTPSConnection('127.0.0.1', self.port, context=ctx, timeout=5)
            try:
                conn.request('POST', '/adm/api/node/sync', body,
                             headers={'Content-Type': 'application/json', 'X-V2V': '1',
                                      'Authorization': 'Bearer ' + db.settings()['node_key']})
                response = conn.getresponse()
                content = response.read()
                self.assertEqual(response.status, 400, content)
                self.assertIn('error', json.loads(content))
            finally:
                conn.close()
            self.assertEqual(db.users(), before)


class TelegramSafety(tu.Base):
    def test_empty_startup_poll_does_not_discard_first_command(self):
        db.set_settings(tg_token='token', tg_chat='7', tg_bot=True, setup_done=True)
        stop = threading.Event()
        seen = []

        def call(_token, _method, params, **kwargs):
            seen.append(dict(params))
            if len(seen) == 1:
                return {'result': []}
            stop.set()
            return {'result': [{'update_id': 1, 'message': {'date': int(time.time()), 'text': '/status',
                                'chat': {'id': 7, 'type': 'private'}, 'from': {'id': 7}}}]}

        with patch.object(notify, '_call', side_effect=call), patch.object(notify, 'reply'), \
                patch.object(notify, 'send_file'):
            handle = MagicMock(return_value='ok')
            notify.bot_loop(stop, handle, lambda *_: None)
        handle.assert_called_once_with('/status')
        self.assertEqual(seen[0]['offset'], -1)
        self.assertEqual(seen[1]['offset'], 0)

    def test_reenabling_bot_skips_messages_received_while_disabled(self):
        enabled = {'tg_token': 'token', 'tg_chat': '7', 'tg_bot': True, 'setup_done': True}
        disabled = dict(enabled, tg_bot=False)
        stop, calls = threading.Event(), []

        def call(_token, _method, params, **kwargs):
            calls.append(dict(params))
            if len(calls) == 1:
                return {'result': []}
            stop.set()
            return {'result': [{'update_id': 1, 'message': {'date': 150, 'text': '/backup',
                                'chat': {'id': 7, 'type': 'private'}, 'from': {'id': 7}}}]}

        with patch.object(db, 'settings', side_effect=[enabled, disabled, enabled]), \
                patch.object(notify.time, 'time', side_effect=[100, 100, 200]), \
                patch.object(stop, 'wait', return_value=False), \
                patch.object(notify, '_call', side_effect=call), patch.object(notify, 'reply'):
            handle = MagicMock()
            notify.bot_loop(stop, handle, lambda *_: None)
        handle.assert_not_called()
        self.assertEqual([p['offset'] for p in calls], [-1, -1])

    def test_groups_cannot_receive_backup_or_replace_private_discovery(self):
        updates = {'result': [{'message': {'chat': {'id': 7, 'type': 'private', 'username': 'owner'}}},
                              {'message': {'chat': {'id': -8, 'type': 'group', 'title': 'group'}}}]}
        with patch.object(notify, '_call', return_value=updates):
            self.assertEqual(notify.find_chat('token'), ('7', 'owner'))
        with patch.object(notify.urllib.request, 'urlopen') as request:
            self.assertFalse(notify.send_file('backup.json', b'secret',
                                             s={'tg_token': 'token', 'tg_chat': '-8'}))
            request.assert_not_called()



class BenchmarkErrors(unittest.TestCase):
    def test_http_failure_is_reported_once_without_secret_url(self):
        errors = []
        error = urllib.error.HTTPError('https://user:password@example.org/s/secret?token=private',
                                       429, 'Too Many Requests', {'Retry-After': '60'}, io.BytesIO())
        opener = MagicMock()
        opener.open.side_effect = error
        with patch.object(bench, '_opener', return_value=opener):
            self.assertEqual(bench.download(streams=4, seconds=0.01, errors=errors), 0)
        self.assertEqual(errors, ['download 4x: HTTP 429; Retry-After=60s'])
        self.assertNotIn('secret', ' '.join(errors))
        self.assertNotIn('password', ' '.join(errors))

    def test_network_failure_is_not_an_unexplained_zero(self):
        errors = []
        opener = MagicMock()
        opener.open.side_effect = urllib.error.URLError(ConnectionRefusedError(111, 'connection refused'))
        with patch.object(bench, '_opener', return_value=opener):
            result = bench.latency(n=1, errors=errors)
        self.assertIsNone(result['median'])
        self.assertEqual(result['fails'], 1)
        self.assertEqual(errors, ['latency: ConnectionRefusedError (errno 111)'])
        row = {'latency': result, 'down_1': 0, 'down_4': 0, 'up_1': 0, 'errors': errors}
        self.assertIn(errors[0], bench.table([('test', row)]))


class DeploySafety(unittest.TestCase):
    def test_known_hosts_survives_deployer_work_directory_changes(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(deploy, 'RECORDS', directory):
            job = {'host': 'example.org', 'user': 'root', 'port': 22}
            with patch.object(deploy, 'WORK', '/temporary/first'):
                first, _ = deploy.ssh_base(job)
            with patch.object(deploy, 'WORK', '/temporary/second'):
                second, _ = deploy.ssh_base(job)
            expected = 'UserKnownHostsFile=' + os.path.join(directory, 'known_hosts')
            self.assertIn(expected, first)
            self.assertIn(expected, second)
            self.assertTrue(os.path.isfile(os.path.join(directory, 'known_hosts')))

    def test_invalid_ssh_ports(self):
        for port in ('0', '65536', '9' * 100, '-1', '２２'):
            with self.subTest(port=port):
                job, error = deploy.new_job('example.org', 'root', port)
                self.assertIsNone(job)
                self.assertTrue(error)
        self.assertEqual(deploy.new_job('example.org', 'root', '22')[0]['port'], 22)

    def test_benchmark_subscription_uses_certificate_validation(self):
        filename = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'tools', 'bench.py')
        spec = importlib.util.spec_from_file_location('audit_bench_cli', filename)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        response = MagicMock()
        response.__enter__.return_value.read.return_value = b'{"proxies": []}'
        with patch.object(module.urllib.request, 'urlopen', return_value=response) as call:
            self.assertEqual(module.fetch_proxies('https://example.org/s/token'), [])
            context = call.call_args.kwargs['context']
            self.assertTrue(context.check_hostname)
            self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)


if __name__ == '__main__':
    unittest.main()
