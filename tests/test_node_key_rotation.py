"""A request authenticated before a key rotation must not restore the old master."""
import json
import threading
import unittest
from unittest import mock

from tests import test_unit as tu
from vps2vpn import cluster, db, secure


class _Web(tu.Web):
    pass


for _name in [n for n in dir(tu.Web) if n.startswith('test')]:
    setattr(_Web, _name, None)


class NodeKeyRotation(_Web):
    def setUp(self):
        super().setUp()
        db.set_settings(setup_done=True, admin_hash=secure.hash_password('REDACTED-password'))
        status, _, _ = self.req('POST', self.pp + '/api/login',
                                {'username': 'admin', 'password': 'REDACTED-password'})
        self.assertEqual(status, 200)
        self.local = db.add_user('local-account')
        self.payload = {'master': 'old-main', 'master_id': 'old-master-id', 'users': [
            {'id': 7, 'name': 'remote-account', 'uuid': '00000000-0000-4000-8000-000000000007',
             'hy2_pass': 'REDACTED-password', 'enabled': True}]}

    def sync(self, key, payload=None):
        return self.req('POST', self.pp + '/api/node/sync', self.payload if payload is None else payload,
                        headers={'Authorization': 'Bearer ' + key})

    def test_late_authenticated_request_cannot_undo_rotation(self):
        old_key = db.settings()['node_key']
        self.assertEqual(self.sync(old_key)[0], 200)
        admitted, resume = threading.Event(), threading.Event()
        original = cluster._validated_sync_snapshot
        answer = {}

        def paused(body):
            result = original(body)
            admitted.set()
            if not resume.wait(5):
                raise RuntimeError('test did not release the sync request')
            return result

        def request():
            answer['response'] = self.sync(old_key)

        with mock.patch.object(cluster, '_validated_sync_snapshot', side_effect=paused):
            worker = threading.Thread(target=request)
            worker.start()
            try:
                self.assertTrue(admitted.wait(5))
                status, body, _ = self.req('POST', self.pp + '/api/node-key', {})
                self.assertEqual(status, 200)
                self.assertEqual(db.settings()['node_master_id'], '')
                self.assertEqual([u['id'] for u in db.users()], [self.local])
            finally:
                resume.set()
                worker.join(5)
        self.assertFalse(worker.is_alive())
        status, body, _ = answer['response']
        self.assertEqual(status, 403)
        self.assertEqual(json.loads(body), {'error': 'bad node key'})
        self.assertEqual(db.settings()['node_master_id'], '')
        self.assertEqual([u['id'] for u in db.users()], [self.local])
        self.assertEqual(self.sync(old_key)[0], 403)
        self.assertEqual(self.sync(db.settings()['node_key'])[0], 200)

    def test_current_key_keeps_legacy_master_compatibility(self):
        status, body, _ = self.sync(db.settings()['node_key'], {'master': 'legacy-main', 'users': []})
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(body)['ok'])
        self.assertEqual(db.settings()['node_master'], 'legacy-main')
        self.assertEqual([u['id'] for u in db.users()], [self.local])


if __name__ == '__main__':
    unittest.main()
