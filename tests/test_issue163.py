"""#163: settings saves, IpWatch and the other writers of the address take turns with the self-signed certificate.
python -m unittest tests.test_issue163 -v

- a save whose certificate fails undoes only its own values, never a save that finished meanwhile
- two saves end with the certificate of the address saved last
- IpWatch does not replace an address the owner saved after IpWatch looked
- the `.host` marker never names a host the certificate on disk is not for
- address_lock is re-entrant, covers other processes (flock) and works without fcntl
"""
import json
import os
import ssl
import threading
import time
import unittest
from unittest import mock

from tests import test_unit as tu
from vps2vpn import certs, cores, db, jobs, notify, paths, secure, system


def _marker():
    try:
        with open(paths.SELF_CRT + '.host', encoding='utf-8') as f:
            return f.read()
    except FileNotFoundError:
        return None


def _cert_names():
    """The SAN entries of the self-signed certificate on disk."""
    info = ssl._ssl._test_decode_cert(paths.SELF_CRT)
    return [v for _, v in info.get('subjectAltName', ())]


class _Gate:
    """Stands in for certs._openssl: a request for `host` waits until released, then fails or goes on."""

    def __init__(self, host, fail):
        self.host, self.fail = host, fail
        self.entered, self.release = threading.Event(), threading.Event()
        self.real = certs._openssl

    def __call__(self, *args, **kw):
        if any(a == 'subjectAltName=IP:' + self.host for a in args):
            self.entered.set()
            assert self.release.wait(10), 'gate never released'
            if self.fail:
                raise RuntimeError('openssl req failed: simulated')
        return self.real(*args, **kw)


class _Web(tu.Web):
    """tu.Web's server and helpers without its own tests (they already run in test_unit)."""


for _name in [n for n in dir(tu.Web) if n.startswith('test')]:
    setattr(_Web, _name, None)


class ConcurrentSaves(_Web):
    def setUp(self):
        super().setUp()
        db.set_settings(setup_done=True, admin_hash=secure.hash_password('rightpassword'))
        status, _, _ = self.req('POST', self.pp + '/api/login', {'username': 'admin', 'password': 'rightpassword'})
        self.assertEqual(status, 200)
        for p in (mock.patch.object(system, 'open_firewall', lambda s: None),
                  mock.patch.object(system, 'tune_network', lambda on: None)):
            p.start()
            self.addCleanup(p.stop)

    def save(self, body, out):
        status, data, _ = self.req('POST', self.pp + '/api/settings', body)
        out.append((status, data))

    def race(self, gate, first, second):
        """`first` reaches the certificate step and waits there; `second` is sent; then `first` goes on."""
        a, b = [], []
        with mock.patch.object(certs, '_openssl', gate):
            ta = threading.Thread(target=self.save, args=(first, a))
            ta.start()
            self.assertTrue(gate.entered.wait(10))
            tb = threading.Thread(target=self.save, args=(second, b))
            tb.start()
            tb.join(1.0)              # finishes now without the fix; waits for `first` with it
            gate.release.set()
            ta.join(15)
            tb.join(15)
        self.assertFalse(ta.is_alive() or tb.is_alive())
        return a[0], b[0]

    def test_failed_save_does_not_undo_a_later_confirmed_save(self):
        (sa, da), (sb, db_) = self.race(_Gate('203.0.113.2', fail=True),
                                        {'public_host': '203.0.113.2', 'member_notice': 'from A'},
                                        {'public_host': '203.0.113.3', 'member_notice': 'from B'})
        self.assertEqual(sa, 500, da)
        self.assertIn('certificate for the new address', json.loads(da)['error'])
        self.assertEqual(sb, 200, db_)
        s = db.settings()
        self.assertEqual((s['public_host'], s['member_notice']), ('203.0.113.3', 'from B'))   # B's save stands
        self.assertEqual(_marker(), '203.0.113.3')
        self.assertEqual(_cert_names(), ['203.0.113.3'])

    def test_failed_save_does_not_undo_a_non_address_save(self):
        (sa, _), (sb, _) = self.race(_Gate('203.0.113.2', fail=True),
                                     {'public_host': '203.0.113.2', 'member_notice': 'from A'},
                                     {'member_notice': 'from B'})
        self.assertEqual((sa, sb), (500, 200))
        s = db.settings()
        self.assertEqual((s['public_host'], s['member_notice']), ('127.0.0.1', 'from B'))
        self.assertEqual(_marker(), '127.0.0.1')

    def test_two_saves_end_with_the_certificate_of_the_last_one(self):
        (sa, da), (sb, db_) = self.race(_Gate('203.0.113.2', fail=False),
                                        {'public_host': '203.0.113.2'}, {'public_host': '203.0.113.3'})
        self.assertEqual((sa, sb), (200, 200), (da, db_))
        self.assertEqual(db.settings()['public_host'], '203.0.113.3')
        self.assertEqual(_marker(), '203.0.113.3')
        self.assertEqual(_cert_names(), ['203.0.113.3'])

    def test_ip_watch_racing_a_manual_save_leaves_it_alone(self):
        db.set_settings(public_host='198.51.100.1')
        certs.ensure_self_signed('198.51.100.1')
        stale = db.settings()
        w = jobs.IpWatch()
        w.seen, w.seen_at = '198.51.100.9', time.monotonic() - w.CONFIRM_AFTER - 1
        applied, got = [], []
        gate = _Gate('203.0.113.3', fail=False)
        out = []
        with mock.patch.object(system, 'public_ip', lambda v6=False: '198.51.100.9'), \
                mock.patch.object(cores, 'apply', lambda force=False: applied.append(force)), \
                mock.patch.object(notify, 'send', lambda *a, **k: False), \
                mock.patch.object(certs, '_openssl', gate):
            tm = threading.Thread(target=self.save, args=({'public_host': '203.0.113.3'}, out))
            tm.start()
            self.assertTrue(gate.entered.wait(10))
            tw = threading.Thread(target=lambda: got.append(w.check(stale)))
            tw.start()
            tw.join(1.0)
            gate.release.set()
            tm.join(15)
            tw.join(15)
        self.assertEqual(out[0][0], 200, out[0][1])
        self.assertEqual(got, [None])
        self.assertEqual(applied, [])
        self.assertEqual(db.settings()['public_host'], '203.0.113.3')
        self.assertEqual(_marker(), '203.0.113.3')


class IpWatchUnderTheLock(tu.Base):
    def setUp(self):
        super().setUp()
        self.applied = []
        for p in (mock.patch.object(system, 'public_ip', lambda v6=False: '198.51.100.9'),
                  mock.patch.object(cores, 'apply', lambda force=False: self.applied.append(force)),
                  mock.patch.object(notify, 'send', lambda *a, **k: False)):
            p.start()
            self.addCleanup(p.stop)
        self.w = jobs.IpWatch()
        self.w.seen, self.w.seen_at = '198.51.100.9', time.monotonic() - self.w.CONFIRM_AFTER - 1

    def test_stale_reading_does_nothing(self):
        stale = db.settings()                               # IpWatch looked at 203.0.113.7 ...
        db.set_settings(public_host='203.0.113.50')         # ... then the owner saved another address
        self.assertIsNone(self.w.check(stale))
        self.assertEqual(db.settings()['public_host'], '203.0.113.50')
        self.assertEqual(self.applied, [])

    def test_follows_when_nothing_changed(self):
        self.assertEqual(self.w.check(db.settings()), '198.51.100.9')
        self.assertEqual(db.settings()['public_host'], '198.51.100.9')
        self.assertEqual(_marker(), '198.51.100.9')
        self.assertEqual(self.applied, [True])

    def test_failed_certificate_puts_the_old_address_back(self):
        real, calls = certs._publish_pair, []

        def once(*a, **k):
            calls.append(1)
            if len(calls) == 1:
                raise OSError(28, 'No space left on device')
            return real(*a, **k)

        with mock.patch.object(certs, '_publish_pair', once):
            with self.assertRaises(OSError):
                self.w.check(db.settings())
        self.assertEqual(db.settings()['public_host'], '203.0.113.7')
        self.assertEqual(_marker(), '203.0.113.7')
        self.assertEqual(_cert_names(), ['203.0.113.7'])
        self.assertEqual(self.applied, [])


class HonestMarker(tu.Base):
    def test_pair_publish_failure_leaves_no_marker(self):
        with mock.patch.object(certs, '_publish_pair', side_effect=OSError(28, 'No space left on device')):
            with self.assertRaises(OSError):
                certs.ensure_self_signed('198.51.100.5')
        self.assertIsNone(_marker())                       # not '198.51.100.5', and not a stale claim either
        self.assertEqual(_cert_names(), ['203.0.113.7'])   # _publish_pair kept the old pair
        certs.ensure_self_signed('203.0.113.7')            # no marker: built again
        self.assertEqual(_marker(), '203.0.113.7')

    def test_marker_write_failure_leaves_no_marker(self):
        real = paths.write_atomic

        def no_marker(path, *a, **k):
            if path.endswith('.host'):
                raise OSError(28, 'No space left on device')
            return real(path, *a, **k)

        with mock.patch.object(paths, 'write_atomic', no_marker):
            with self.assertRaises(OSError):
                certs.ensure_self_signed('198.51.100.5')
        self.assertIsNone(_marker())                       # the pair is for .5 now, so no '.7' marker
        self.assertEqual(_cert_names(), ['198.51.100.5'])
        certs.ensure_self_signed('198.51.100.5')
        self.assertEqual(_marker(), '198.51.100.5')

    def test_openssl_failure_keeps_the_matching_pair_and_marker(self):
        with mock.patch.object(certs, '_openssl', side_effect=RuntimeError('openssl req failed')):
            with self.assertRaises(RuntimeError):
                certs.ensure_self_signed('198.51.100.5')
        self.assertEqual(_marker(), '203.0.113.7')
        self.assertEqual(_cert_names(), ['203.0.113.7'])


class AddressLock(tu.Base):
    def _other_thread_waits(self):
        done = threading.Event()

        def take():
            with certs.address_lock():
                done.set()

        t = threading.Thread(target=take)
        with certs.address_lock():
            t.start()
            self.assertFalse(done.wait(0.3))
        self.assertTrue(done.wait(5))
        t.join(5)

    def test_reentrant_with_one_file_lock(self):
        opened = []
        real = certs._open_address_lock

        def counting():
            opened.append(1)
            return real()

        with mock.patch.object(certs, '_open_address_lock', counting):
            with certs.address_lock():
                with certs.address_lock():
                    certs.ensure_self_signed('198.51.100.6')   # takes it again inside
                    self.assertEqual(certs._address_depth, 2)
        self.assertEqual(opened, [1])
        self.assertEqual(certs._address_depth, 0)
        self.assertIsNone(certs._address_fd)
        self._other_thread_waits()

    @unittest.skipIf(getattr(certs, 'fcntl', None) is None, 'no fcntl on this system')
    def test_file_lock_holds_off_another_process(self):
        import fcntl
        with certs.address_lock():
            fd = os.open(os.path.join(paths.CERT_DIR, '.address.lock'), os.O_RDWR)
            try:
                with self.assertRaises(BlockingIOError):   # what `vps2vpn init` would wait on
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                os.close(fd)
        fd = os.open(os.path.join(paths.CERT_DIR, '.address.lock'), os.O_RDWR)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)  # released at the outermost exit
        finally:
            os.close(fd)

    def test_works_without_fcntl(self):
        with mock.patch.object(certs, 'fcntl', None):
            with certs.address_lock():
                with certs.address_lock():
                    self.assertIsNone(certs._address_fd)
                    certs.ensure_self_signed('198.51.100.6')
            self.assertEqual(_marker(), '198.51.100.6')
            self._other_thread_waits()

    def test_unopenable_lock_file_falls_back_to_the_thread_lock(self):
        with mock.patch.object(certs.os, 'open', side_effect=PermissionError(13, 'denied')):
            with certs.address_lock():
                self.assertIsNone(certs._address_fd)
        self.assertEqual(certs._address_depth, 0)


if __name__ == '__main__':
    unittest.main()
