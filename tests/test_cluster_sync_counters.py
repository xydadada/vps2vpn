"""Regression tests for signed SQLite boundaries in cross-node traffic sync."""
import unittest
from unittest import mock

from tests import test_unit as tu  # configure the isolated data root
from vps2vpn import cluster, db

MAX = (1 << 63) - 1


class NodeTrafficBoundaries(tu.Base):
    def _answer(self, traffic):
        return {'ok': True, 'info': {'node_name': 'node'},
                'idmap': {}, 'traffic': traffic}

    def _server(self, uid):
        return {'id': '11111111', 'name': 'node',
                'url': 'https://node.example/admin', 'key': 'secret',
                'pin': '', 'enabled': True, 'seen': {str(uid): [0, 0]}}

    def test_oversized_counter_rejected_before_db_write(self):
        for pair in ([MAX + 1, 0], [0, MAX + 1]):
            with self.subTest(pair=pair), self.assertRaisesRegex(
                    cluster.SyncError, 'oversized traffic counters'):
                cluster._validate_sync_answer(self._answer({'1': pair}))
        cluster._validate_sync_answer(self._answer({'1': [MAX, MAX]}))

    def test_account_total_never_silently_becomes_sqlite_real(self):
        user = db.add_user('boundary')
        db.update_user(user, used_up=MAX - 3)
        srv = self._server(user)
        snapshot = dict(srv)
        answer = self._answer({str(user): [10, 0]})
        with mock.patch.object(cluster, '_request', return_value=(answer, 'aa' * 32)):
            self.assertFalse(cluster.sync_one(srv, log=lambda _: None))
        value = db.q('SELECT used_up, typeof(used_up) kind FROM users WHERE id=?', (user,))[0]
        self.assertEqual((value['used_up'], value['kind']), (MAX - 3, 'integer'))
        self.assertEqual(srv['seen'], snapshot['seen'])
        self.assertEqual(srv['fail_count'], 1)

    def test_daily_history_boundary_is_checked_even_after_a_quota_reset(self):
        uid = db.add_user('daily-boundary')
        db.add_traffic(uid, MAX - 3, 0)
        # A reset affects the account counter but not earlier daily history.
        db.update_user(uid, used_up=0)
        answer = self._answer({str(uid): [10, 0]})
        srv = self._server(uid)
        with mock.patch.object(cluster, '_request', return_value=(answer, 'bb' * 32)):
            self.assertFalse(cluster.sync_one(srv, log=lambda _: None))
        row = db.q('SELECT up, typeof(up) kind FROM traffic WHERE user_id=?', (uid,))[0]
        self.assertEqual((row['up'], row['kind']), (MAX - 3, 'integer'))
        self.assertEqual(db.user(uid)['used_up'], 0)

    def test_bad_node_counters_do_not_starve_the_next_healthy_node(self):
        user = db.add_user('shared')
        one = self._server(user)
        two = dict(self._server(user), id='22222222', name='healthy',
                   url='https://healthy.example/admin', seen={})
        db.set_settings(servers=[one, two])
        replies = [(self._answer({str(user): [MAX + 1, 0]}), 'aa' * 32),
                   (self._answer({}), 'bb' * 32)]
        with mock.patch.object(cluster, '_request', side_effect=replies) as request:
            cluster.sync_all(log=lambda _: None)
        self.assertEqual(request.call_count, 2)
        stored = db.settings()['servers']
        self.assertEqual(stored[0]['fail_count'], 1)
        self.assertEqual(stored[1]['info']['node_name'], 'node')
        self.assertEqual(stored[1]['fail_count'], 0)


if __name__ == '__main__':
    unittest.main()
