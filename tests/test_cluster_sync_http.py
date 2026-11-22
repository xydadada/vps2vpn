"""Regression tests for malformed HTTP responses from synchronized VPN nodes.

The main sync loop catches SyncError to keep unrelated nodes running.
"""
import unittest
from unittest import mock

from tests import test_unit as tu  # sets the isolated test root before imports
from vps2vpn import cluster, db, subscription


class NodeSyncHttpErrors(tu.Base):
    def test_nonobject_http_error_bodies_always_raise_sync_error(self):
        conn = mock.Mock()
        conn.sock.getpeercert.return_value = b'fixture cert'
        conn.getresponse.return_value.status = 503
        for body in (b'[]', b'null', b'7', b'"offline"', b'{"error":[]}',
                     b'{"error":{"details":"offline"}}', b'{"error":"offline"}',
                     b'<html>backend unavailable</html>'):
            with self.subTest(body=body):
                conn.getresponse.return_value.read.return_value = body
                with mock.patch.object(cluster.http.client, 'HTTPSConnection', return_value=conn):
                    with self.assertRaisesRegex(cluster.SyncError, 'node answered 503'):
                        cluster._request({'url': 'https://node.example/admin', 'key': 'secret'},
                                         {'users': []})
                    conn.close.assert_called()

    def test_failing_node_does_not_block_healthy_node_sync(self):
        servers = [
            {'id': '11111111', 'name': 'Offline', 'url': 'https://offline.example/panel',
             'key': 'k1', 'pin': '', 'enabled': True},
            {'id': '22222222', 'name': 'Healthy', 'url': 'https://healthy.example/panel',
             'key': 'k2', 'pin': '', 'enabled': True},
        ]
        db.set_settings(servers=servers)
        answer = {'ok': True, 'info': {'node_name': 'healthy'},
                  'idmap': {}, 'traffic': {}}
        with mock.patch.object(cluster, '_request', side_effect=[
            cluster.SyncError('node answered 503: []'), (answer, 'ab' * 32),
        ]) as send:
            cluster.sync_all(log=lambda _: None)
        self.assertEqual(send.call_count, 2)
        final = db.settings()['servers']
        self.assertEqual(final[0]['fail_count'], 1)
        self.assertEqual(final[1]['info']['node_name'], 'healthy')
        self.assertEqual(final[1]['error'], '')


    def test_malformed_mapped_metadata_and_ids_preserve_previous_snapshot(self):
        uid = db.add_user('mapped-user')
        rid = str(uid)
        info = cluster.public_info(dict(db.settings(), public_host='198.51.100.42'))
        legacy_tls = {'ok': True, 'info': dict(info, tls={}),
                      'idmap': {rid: 42}, 'traffic': {}}
        self.assertIs(cluster._validate_sync_answer(legacy_tls), legacy_tls)
        minimal_tls = {'ok': True, 'info': dict(info, tls={'sni': 'node.example'}),
                       'idmap': {rid: 42}, 'traffic': {}}
        self.assertIs(cluster._validate_sync_answer(minimal_tls), minimal_tls)
        old = {'id': '11111111', 'name': 'old-good', 'url': 'https://node.example/panel',
               'key': 'key', 'pin': 'aa' * 32, 'info': info, 'idmap': {rid: 42},
               'seen': {rid: [9, 10]}, 'fail_count': 0}
        bad_info = (
            dict(info, public_host=[]),
            dict(info, public_host='node example'),
            dict(info, public_host='node.example\n[Proxy]'),
            dict(info, reality_target='bad.example,unexpected'),
            dict(info, tls=dict(info['tls'], sni='bad\rserver')),
            dict(info, hy2_enabled=True, hy2_port='443'),
            dict(info, hy2_hop_range=[]),
            dict(info, reality_enabled=True, reality_public_key=None),
            dict(info, tls=['invalid']),
            dict(info, tls={'pin': 'ab' * 32}),
            dict(info, tls=dict(info['tls'], password='changed')),
            dict(info, tls=dict(info['tls'], server='other.example')),
            dict(info, ai_score='invalid'),
            dict(info, ipv6_nodes=True, public_ipv6=[]),
        )
        answers = [
            {'ok': True, 'info': broken, 'idmap': {rid: 42}, 'traffic': {}}
            for broken in bad_info
        ] + [
            {'ok': True, 'info': info, 'idmap': ids, 'traffic': {}}
            for ids in ({rid: '42'}, {rid: True}, {'0' + rid: 42}, {rid: 0})
        ]
        for answer in answers:
            with self.subTest(answer=answer):
                node = dict(old)
                with mock.patch.object(cluster, '_request', return_value=(answer, 'bb' * 32)):
                    self.assertFalse(cluster.sync_one(node, log=lambda _: None))
                self.assertEqual(node['info'], info)
                self.assertEqual(node['idmap'], {rid: 42})
                self.assertEqual(node['seen'], {rid: [9, 10]})
                self.assertEqual(node['pin'], 'aa' * 32)
                self.assertEqual(node['fail_count'], 1)

    def test_invalid_node_does_not_block_healthy_sibling_or_subscription(self):
        uid = db.add_user('subscriber')
        rid = str(uid)
        good = cluster.public_info(dict(db.settings(), public_host='198.51.100.55'))
        first = {'id': '11111111', 'name': 'Previously synced',
                 'url': 'https://first.example/panel', 'key': 'k1', 'pin': 'aa' * 32,
                 'enabled': True, 'info': good, 'idmap': {rid: 41},
                 'seen': {rid: [0, 0]}, 'fail_count': 0}
        second = {'id': '22222222', 'name': 'Healthy',
                  'url': 'https://second.example/panel', 'key': 'k2',
                  'pin': 'bb' * 32, 'enabled': True}
        db.set_settings(servers=[first, second])
        broken = {'ok': True, 'info': {'hy2_enabled': True},
                  'idmap': {rid: 42}, 'traffic': {}}
        valid = {'ok': True, 'info': good, 'idmap': {rid: 43},
                 'traffic': {rid: [0, 0]}}
        with mock.patch.object(cluster, '_request',
                               side_effect=[(broken, 'cc' * 32), (valid, 'dd' * 32)]) as request:
            cluster.sync_all(log=lambda _: None)
        self.assertEqual(request.call_count, 2)
        saved = db.settings()['servers']
        self.assertEqual(saved[0]['info'], good)
        self.assertEqual(saved[0]['idmap'], {rid: 41})
        self.assertEqual(saved[0]['pin'], 'aa' * 32)
        self.assertEqual(saved[0]['fail_count'], 1)
        self.assertEqual(saved[1]['idmap'], {rid: 43})
        self.assertEqual(saved[1]['fail_count'], 0)
        entries = subscription.nodes(db.settings(), db.user(uid))
        self.assertEqual(len([n for n in entries if n['group'] == 'Previously synced']), 3)
        self.assertEqual(len([n for n in entries if n['group'] == 'Healthy']), 3)


if __name__ == '__main__':
    unittest.main()


class OwnerWalkthrough(tu.Base):
    """What the owner runs into when moving, pausing or removing servers (0.2.19)."""

    def test_paused_server_is_still_synced_with_every_account_off(self):
        uid = db.add_user('mum')
        db.set_settings(servers=[{'id': '33333333', 'name': 'Tokyo', 'url': 'https://tokyo.example/panel',
                                  'key': 'k', 'pin': '', 'enabled': False}])
        answer = {'ok': True, 'info': {'node_name': 'tokyo'}, 'idmap': {}, 'traffic': {}}
        with mock.patch.object(cluster, '_request', return_value=(answer, 'ab' * 32)) as send:
            cluster.sync_all(log=lambda _: None)
        self.assertEqual(send.call_count, 1)
        pushed = send.call_args[0][1]['users']
        self.assertEqual([(x['id'], x['enabled']) for x in pushed], [(uid, False)])

    def test_removing_a_server_leaves_nobody_with_an_empty_subscription(self):
        only = db.add_user('only-tokyo')
        both = db.add_user('both')
        db.update_user(only, servers='33333333')
        db.update_user(both, servers='main,33333333')
        db.set_settings(servers=[{'id': '33333333', 'name': 'Tokyo', 'url': 'https://tokyo.example/panel',
                                  'key': 'k', 'pin': '', 'enabled': True}])
        cluster.remove_server('33333333')
        self.assertEqual(db.user(only)['servers'], 'main')
        self.assertEqual(db.user(both)['servers'], 'main')
        self.assertEqual(db.settings()['servers'], [])

    def test_restore_keeps_this_panel_address_and_the_top_ups(self):
        uid = db.add_user('mum')
        db.update_user(uid, quota_gb=50, extra_gb=20)
        db.set_settings(panel_path='oldpath', panel_port=1111, public_host='198.51.100.1')
        backup = db.export_all()
        db.set_settings(panel_path='newpath', panel_port=2222, public_host='203.0.113.9')
        db.import_all(backup)
        s = db.settings()
        self.assertEqual((s['panel_path'], s['panel_port'], s['public_host']), ('newpath', 2222, '203.0.113.9'))
        self.assertEqual(db.user_by_name('mum')['extra_gb'], 20)
        # a domain moves with the backup: its DNS follows the owner to the new server
        db.set_settings(domain='vpn.example.org', public_host='vpn.example.org')
        backup = db.export_all()
        db.set_settings(domain='', public_host='203.0.113.9')
        db.import_all(backup)
        self.assertEqual(db.settings()['public_host'], 'vpn.example.org')


class DomainAndAddress(tu.Base):
    def test_domain_and_server_address_never_disagree_silently(self):
        from vps2vpn import web
        s = dict(db.settings(), domain='vpn.example.org', public_host='vpn.example.org')
        ok = web.validate_settings({'domain': 'vpn.example.org', 'public_host': 'vpn.example.org'}, s)
        self.assertEqual(ok['public_host'], 'vpn.example.org')
        self.assertIsInstance(web.validate_settings({'domain': 'vpn.example.org', 'public_host': '203.0.113.9'}, s), str)
        self.assertIsInstance(web.validate_settings({'domain': '', 'public_host': 'vpn.example.org'}, s), str)
        out = web.validate_settings({'domain': '', 'public_host': '203.0.113.9'}, s)
        self.assertEqual((out['domain'], out['public_host']), ('', '203.0.113.9'))
        new = web.validate_settings({'domain': 'new.example.org', 'public_host': 'vpn.example.org'}, s)
        self.assertEqual(new['public_host'], 'new.example.org')
