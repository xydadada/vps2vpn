"""0.2.51: items from the two offline review bundles (2026-11-26) that no pull request covered, reimplemented here:
python -m unittest tests.test_external_051 -v

- request bodies and cluster answers are parsed strictly: duplicate keys, NaN / Infinity / overflowing numbers,
  very deep nesting and lone surrogates are refused with a 400 (never a 500 from RecursionError)
- a cluster answer over 8 MiB is refused instead of being cut and parsed
- first-time setup runs once even when two requests with the setup link arrive together
- what an inviter handed out is computed without recursion, with the same result
"""
import base64
import http.client
import json
import random
import ssl
import threading
import unittest
from unittest import mock

from tests import test_unit as tu
from vps2vpn import cluster, members, secure


class StrictJson(unittest.TestCase):
    def test_refused(self):
        for raw in ('{"a": 1, "a": 2}', '{"a": NaN}', '{"a": Infinity}', '{"a": -Infinity}', '{"a": 1e999}',
                    '{"a": %s}' % ('9' * 5000), '[' * 100000 + ']' * 100000, '{"a": ' + '[' * 65 + ']' * 65 + '}',
                    '{"a": "x', ''):
            with self.subTest(raw=raw[:30]), self.assertRaises(secure.BadJson) as cm:
                secure.loads_json(raw)
            self.assertIsInstance(cm.exception, ValueError)          # old `except ValueError` handlers still work
            self.assertEqual(cm.exception.kind, 'json')

    def test_lone_surrogate_in_a_key_or_a_value(self):
        for raw in ('{"a": "\\ud800"}', '{"\\udc00": 1}', '{"a": [["\\ud83d"]]}'):
            with self.subTest(raw=raw), self.assertRaises(secure.BadJson) as cm:
                secure.loads_json(raw)
            self.assertEqual(cm.exception.kind, 'unicode')

    def test_accepted(self):
        deep = '[' * 63 + ']' * 63
        self.assertEqual(secure.loads_json('{"a": %s}' % deep)['a'], json.loads(deep))
        self.assertEqual(secure.loads_json(b'{"a": 1.5, "b": -2, "c": "\\ud83d\\ude00", "d": null, "e": [true]}'),
                         {'a': 1.5, 'b': -2, 'c': '\U0001f600', 'd': None, 'e': [True]})
        self.assertEqual(secure.loads_json('{"same": {"x": 1}, "other": {"x": 2}}')['other'], {'x': 2})


class _Web(tu.Web):
    """tu.Web's server and helpers without its own tests (they already run in test_unit)."""


for _name in [n for n in dir(tu.Web) if n.startswith('test')]:
    setattr(_Web, _name, None)


class StrictBodies(_Web):
    def raw(self, path, data):
        c = http.client.HTTPSConnection('127.0.0.1', self.port, context=ssl._create_unverified_context(), timeout=20)
        try:
            c.request('POST', path, data, {'X-V2V': '1', 'Content-Type': 'application/json'})
            r = c.getresponse()
            return r.status, r.read(), r
        finally:
            c.close()

    def test_panel_answers_400_not_500(self):
        for raw in (b'{"token": "a", "token": "setup-token-123", "password": "longpassword"}',
                    b'{"password": NaN}', b'[' * 200000 + b']' * 200000):
            with self.subTest(raw=raw[:30]):
                st, body, _ = self.raw(self.pp + '/api/setup', raw)
                self.assertEqual(st, 400, body)
                self.assertEqual(json.loads(body)['error'], 'invalid json')
        st, body, _ = self.raw(self.pp + '/api/setup', b'{"token": "\\ud800"}')
        self.assertEqual((st, json.loads(body)['error']), (400, 'invalid unicode'))


class _Answer:
    def __init__(self, data, status=200):
        self.data, self.status = data, status

    def read(self, n=-1):
        return self.data if n < 0 else self.data[:n]


class _Conn:
    answer = None

    def __init__(self, *a, **k):
        self.sock = mock.Mock(getpeercert=lambda binary: b'certificate')

    def connect(self):
        pass

    def request(self, *a, **k):
        pass

    def getresponse(self):
        return self.answer

    def close(self):
        pass


class ClusterAnswers(unittest.TestCase):
    SERVER = {'id': 'abcd1234', 'url': 'https://198.51.100.5:18480/p', 'key': 'k', 'pin': ''}

    def ask(self, data, status=200):
        _Conn.answer = _Answer(data, status)
        with mock.patch.object(cluster.http.client, 'HTTPSConnection', _Conn):
            return cluster._request(self.SERVER, {'users': []})

    def test_an_answer_over_8_mib_is_refused_not_cut(self):
        # cut at 8 MiB, this would still be a complete JSON object
        data = b'{"ok": true}' + b' ' * (8 << 20)
        with self.assertRaisesRegex(cluster.SyncError, 'too large'):
            self.ask(data)
        with self.assertRaisesRegex(cluster.SyncError, 'too large'):
            self.ask(data, 500)

    def test_a_broken_answer_is_a_sync_error_that_leaves_other_nodes_alone(self):
        for data in (b'[' * 300000 + b']' * 300000, b'{"ok": true, "ok": false}', b'{"x": NaN}', b'{"x": '):
            with self.subTest(data=data[:20]), self.assertRaisesRegex(cluster.SyncError, 'not valid JSON'):
                self.ask(data)
        with self.assertRaisesRegex(cluster.SyncError, 'node answered 502'):
            self.ask(b'[' * 300000, 502)

    def test_join_code_with_duplicate_keys_is_damaged(self):
        raw = b'{"u": "https://198.51.100.5:1/x", "k": "a", "k": "b"}'
        with self.assertRaisesRegex(ValueError, 'damaged'):
            cluster.parse_join_code('v2v1.' + base64.urlsafe_b64encode(raw).decode().rstrip('='))


class SetupOnce(_Web):
    def test_two_setup_requests_at_once(self):
        entered, resume, result = threading.Event(), threading.Event(), []
        real = secure.hash_password

        def slow_first(pw, *a, **k):
            if pw == 'first-password':
                entered.set()
                resume.wait(10)
            return real(pw, *a, **k)

        def setup(pw, user):
            return self.req('POST', self.pp + '/api/setup', {'token': 'setup-token-123', 'password': pw,
                                                             'username': user, 'settings': {'public_host': '127.0.0.1'}})
        with mock.patch.object(secure, 'hash_password', side_effect=slow_first):
            first = threading.Thread(target=lambda: result.append(setup('first-password', 'first')), daemon=True)
            first.start()
            try:
                self.assertTrue(entered.wait(5))
                st, body, _ = setup('second-password', 'second')
                self.assertEqual(st, 200, body)
            finally:
                resume.set()
                first.join(10)
        self.assertEqual(result[0][0], 409, result[0][1])
        s = tu.db.settings()
        self.assertEqual(s['admin_user'], 'second')
        self.assertTrue(secure.check_password('second-password', s['admin_hash']))
        self.assertEqual(len(tu.db.users()), 1)


def _given_away_recursive(uid, by_inviter, now, seen):
    """The form before 0.2.51, kept to compare against."""
    if uid in seen:
        return 0.0
    seen.add(uid)
    total = 0.0
    for u in by_inviter.get(uid, ()):
        ded = u.get('invite_deduct', 0)
        if ded <= 0:
            continue
        if members.deducting(u, now):
            total += ded
        else:
            sub = _given_away_recursive(u['id'], by_inviter, now, seen)
            if sub > 0:
                total += min(ded, sub)
    return total


class GivenAway(unittest.TestCase):
    def _rows(self, n, rnd):
        rows = []
        for i in range(2, n + 2):
            rows.append({'id': i, 'invited_by': rnd.randrange(1, i), 'invite_deduct': rnd.choice([0, 0, 5, 10, 30]),
                         'enabled': rnd.random() < .6, 'expire_at': 0, 'disabled_reason': ''})
        return rows

    def test_same_as_the_recursive_form(self):
        rnd = random.Random(51)
        for _ in range(300):
            rows = self._rows(rnd.randrange(1, 40), rnd)
            if rnd.random() < .3:                       # a cycle, from a restored or hand-edited backup
                rows[0]['invited_by'] = rows[-1]['id']
            idx = members.invitee_index(rows)
            for uid in [1] + [r['id'] for r in rows]:
                with self.subTest(uid=uid):
                    self.assertEqual(members._given_away(uid, idx, 0, set()),
                                     _given_away_recursive(uid, idx, 0, set()))

    def test_a_very_long_invite_chain(self):
        rows = [{'id': i, 'invited_by': i - 1, 'invite_deduct': 10, 'enabled': False, 'expire_at': 0,
                 'disabled_reason': 'manual'} for i in range(2, 5002)]
        rows[-1]['enabled'] = True
        rows[-1]['disabled_reason'] = ''
        self.assertEqual(members._given_away(1, members.invitee_index(rows), 0, set()), 10.0)


class FailedRestartIsOwed(tu.Base):
    """#141: the new config is on disk, the restart failed, the old process still runs. The next try must restart
    again instead of seeing "same file, service active" and calling it done."""

    def test_retry_restarts_until_it_works(self):
        import subprocess
        from vps2vpn import cores, paths, shaper, system
        tu.db.set_settings(reality_enabled=True, hy2_enabled=False, tuic_enabled=False)
        calls = []

        def systemctl(*args):
            calls.append(args)
            failed = args[0] == 'restart' and len([c for c in calls if c[0] == 'restart']) == 1
            return subprocess.CompletedProcess(args, 1 if failed else 0, '', 'job rejected' if failed else '')
        cores._restart_owed.clear()
        with mock.patch.object(cores, 'write_configs', side_effect=[[paths.XRAY_CONFIG], [], []]), \
                mock.patch.object(cores, '_xray_live_update', return_value=False), \
                mock.patch.object(cores, '_save_before_restart'), \
                mock.patch.object(system, 'unit_active', return_value=True), \
                mock.patch.object(system, 'systemctl', side_effect=systemctl), \
                mock.patch.object(system, 'port_hopping', return_value=None), \
                mock.patch.object(shaper, 'apply', return_value=True):
            with self.assertRaisesRegex(RuntimeError, 'did not start'):
                cores.apply()
            cores.apply()                                   # same file, service "active": restarts anyway
            cores.apply()                                   # and once that worked, nothing is owed any more
        restarts = [c for c in calls if c[0] == 'restart']
        self.assertEqual(len(restarts), 2, calls)
        self.assertEqual(cores._restart_owed, set())


class StalledInstallHasADeadline(unittest.TestCase):
    """#157: SSH still answers while the remote installer hangs and keeps its output open. The deployer stops
    after the deadline, says the install may still be running, and keeps nothing waiting."""

    def test_deadline(self):
        import os
        import shutil
        import subprocess
        import sys
        import tempfile
        import time
        sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'deploy'))
        import deploy                                           # the same module object test_deploy uses
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        real_popen = subprocess.Popen
        started = []

        def hanging_install(cmd, **kw):
            kw.pop('env', None)
            p = real_popen([sys.executable, '-c', 'import sys, time; print("installing", flush=True); time.sleep(120)'],
                           **kw)
            started.append(p)
            return p
        job, err = deploy.new_job('203.0.113.10', 'root', '22')
        self.assertFalse(err)
        job['key'] = os.path.join(d, 'key')
        job['no_import'] = True
        with mock.patch.object(deploy, 'RECORDS', d), \
                mock.patch.object(deploy, 'INSTALL_DEADLINE', 1), \
                mock.patch.object(deploy, 'probe', lambda cmd, env, user: subprocess.CompletedProcess(cmd, 0, 'connected Linux 0', '')), \
                mock.patch.object(deploy, 'package', return_value=b'x'), \
                mock.patch.object(deploy, 'restrict', lambda path: None), \
                mock.patch.object(deploy.shutil, 'which', return_value='ssh'), \
                mock.patch.object(deploy.subprocess, 'Popen', side_effect=hanging_install):
            t0 = time.monotonic()
            deploy.run_job(job)
            took = time.monotonic() - t0
        self.assertLess(took, 30)
        self.assertEqual(job['state'], 'error')
        self.assertIn('vps2vpn info', json.dumps(job, ensure_ascii=False))
        self.assertIsNotNone(started[0].poll())                 # the local ssh process was stopped and reaped


if __name__ == '__main__':
    unittest.main()
