"""Regression tests for malformed HTTP responses from synchronized VPN nodes.

The main sync loop catches SyncError to keep unrelated nodes running.
"""
import unittest
from unittest import mock

from tests import test_unit as tu  # sets the isolated test root before imports
from vps2vpn import cluster, db


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


if __name__ == '__main__':
    unittest.main()
