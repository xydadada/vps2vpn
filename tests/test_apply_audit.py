"""Bounded asynchronous configuration reloads, without restarting host services."""
import threading
import unittest
from unittest import mock

from tests import test_unit as _test_environment
from vps2vpn import web


class ApplyWorker(unittest.TestCase):
    def test_burst_uses_one_worker_and_preserves_force(self):
        entered, release = threading.Event(), threading.Event()
        calls = []

        def apply(force=False):
            calls.append(force)
            if len(calls) == 1:
                entered.set()
                if not release.wait(5):
                    raise RuntimeError('test did not release apply')

        with mock.patch.object(web.cores, 'apply', side_effect=apply), \
                mock.patch.object(web.jobs, 'log'), mock.patch.object(web.cluster, 'sync_soon'):
            web.apply_async()
            worker = web._apply_thread
            try:
                self.assertTrue(entered.wait(3))
                for i in range(100):
                    web.apply_async(force=i == 50)
                    self.assertIs(web._apply_thread, worker)
            finally:
                release.set()
                worker.join(5)
            self.assertFalse(worker.is_alive())
            self.assertIsNone(web._apply_thread)
            self.assertEqual(calls, [False, True])

    def test_failed_apply_does_not_discard_changes_arriving_in_flight(self):
        entered, release = threading.Event(), threading.Event()
        calls = []

        def apply(force=False):
            calls.append(force)
            if len(calls) == 1:
                entered.set()
                if not release.wait(5):
                    raise RuntimeError('test did not release apply')
                raise RuntimeError('service rejected configuration')

        with mock.patch.object(web.cores, 'apply', side_effect=apply), \
                mock.patch.object(web.jobs, 'log') as log, \
                mock.patch.object(web.cluster, 'sync_soon'):
            web.apply_async()
            worker = web._apply_thread
            try:
                self.assertTrue(entered.wait(3))
                web.apply_async(force=True)
            finally:
                release.set()
                worker.join(5)
            self.assertFalse(worker.is_alive())
            self.assertEqual(calls, [False, True])
            self.assertIsNone(web._apply_thread)
            self.assertTrue(any('apply failed' in call.args[0] for call in log.call_args_list))

    def test_worker_start_failure_can_be_retried(self):
        with mock.patch.object(web.threading.Thread, 'start', side_effect=RuntimeError('no thread')):
            with self.assertRaisesRegex(RuntimeError, 'no thread'):
                web.apply_async(force=True)
        self.assertIsNone(web._apply_thread)
        entered, release = threading.Event(), threading.Event()

        def apply(force=False):
            self.assertTrue(force)
            entered.set()
            release.wait(5)

        with mock.patch.object(web.cores, 'apply', side_effect=apply) as apply_call, \
                mock.patch.object(web.jobs, 'log'), mock.patch.object(web.cluster, 'sync_soon'):
            web.apply_async()
            worker = web._apply_thread
            try:
                self.assertTrue(entered.wait(3))
            finally:
                release.set()
                worker.join(5)
            self.assertFalse(worker.is_alive())
            apply_call.assert_called_once_with(force=True)
            self.assertIsNone(web._apply_thread)


class ApplyLockSafety(unittest.TestCase):
    def test_nested_apply_uses_reentrant_lock(self):
        """apply() is serialized and invokes write_configs(), which takes the same lock."""
        entered, released = threading.Event(), threading.Event()

        def nested():
            with web.cores._apply_lock:
                entered.set()
                with web.cores._apply_lock:
                    released.set()

        worker = threading.Thread(target=nested, daemon=True)
        worker.start()
        self.assertTrue(entered.wait(2))
        self.assertTrue(released.wait(2), 'nested apply/write_configs deadlocked')
        worker.join(2)
        self.assertFalse(worker.is_alive())
