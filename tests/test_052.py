"""0.2.52: open issues from the 2026-11-23 outside review that were still open.
python -m unittest tests.test_052 -v

- #126 a settings save whose certificate cannot be written keeps the old address (no half-saved state)
"""
import json
import os
import unittest
from unittest import mock

from tests import test_unit as tu
from vps2vpn import certs, db, paths, secure, system


class _Web(tu.Web):
    """tu.Web's server and helpers without its own tests (they already run in test_unit)."""


for _name in [n for n in dir(tu.Web) if n.startswith('test')]:
    setattr(_Web, _name, None)


class FailedCertificateKeepsOldAddress(_Web):
    def setUp(self):
        super().setUp()
        db.set_settings(setup_done=True, admin_hash=secure.hash_password('rightpassword'))
        status, _, _ = self.req('POST', self.pp + '/api/login', {'username': 'admin', 'password': 'rightpassword'})
        self.assertEqual(status, 200)
        self._fw = mock.patch.object(system, 'open_firewall', lambda s: None)
        self._fw.start()

    def tearDown(self):
        self._fw.stop()
        super().tearDown()

    def test_one_failed_write_then_a_retry(self):
        before = db.settings()
        real = certs._publish_pair
        calls = []

        def once(*a, **k):
            calls.append(1)
            if len(calls) == 1:
                raise OSError(28, 'No space left on device')
            return real(*a, **k)

        with mock.patch.object(certs, '_publish_pair', once):
            status, body, _ = self.req('POST', self.pp + '/api/settings',
                                       {'public_host': '203.0.113.7', 'member_notice': 'new notice'})
            self.assertEqual(status, 500, body)
            self.assertIn('certificate for the new address', json.loads(body)['error'])
            s = db.settings()
            self.assertEqual(s['public_host'], before['public_host'])
            self.assertEqual(s['member_notice'], before['member_notice'])
            with open(paths.SELF_CRT + '.host', encoding='utf-8') as f:
                self.assertEqual(f.read(), '127.0.0.1')
            # the same request again, now that the disk has room: saved, certificate for the new address
            status, body, _ = self.req('POST', self.pp + '/api/settings',
                                       {'public_host': '203.0.113.7', 'member_notice': 'new notice'})
            self.assertEqual(status, 200, body)
        s = db.settings()
        self.assertEqual((s['public_host'], s['member_notice']), ('203.0.113.7', 'new notice'))
        with open(paths.SELF_CRT + '.host', encoding='utf-8') as f:
            self.assertEqual(f.read(), '203.0.113.7')

    def test_translated(self):
        with open(os.path.join(os.path.dirname(certs.__file__), 'static', 'kit.js'), encoding='utf-8') as f:
            self.assertIn('/^certificate for the new address could not be written/', f.read())


if __name__ == '__main__':
    unittest.main()
