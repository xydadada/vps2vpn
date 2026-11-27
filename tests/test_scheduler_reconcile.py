"""Committed account changes must reach the cores even when telemetry fails."""
import time
from unittest import mock

from tests import test_unit as tu
from vps2vpn import db, jobs


class SchedulerReconcile(tu.Base):
    def test_expiry_is_applied_before_fallible_monthly_telemetry(self):
        db.set_settings(setup_done=True)
        uid = db.add_user('expired-before-telemetry', expire_at=int(time.time()) - 60)
        scheduler = jobs.Scheduler()
        with mock.patch.object(scheduler, 'due', side_effect=lambda name, _: name in ('collect', 'traffic')), \
                mock.patch.object(jobs, 'collect'), \
                mock.patch.object(jobs.system, 'health', return_value={}), \
                mock.patch.object(jobs, 'server_month', side_effect=OSError('telemetry write failed')), \
                mock.patch.object(jobs.cluster, 'sync_soon') as sync, \
                mock.patch.object(jobs.cores, 'apply') as apply:
            with self.assertRaisesRegex(OSError, 'telemetry write failed'):
                scheduler.tick()
            self.assertEqual(db.user(uid)['enabled'], 0)
            sync.assert_called_once_with()
            apply.assert_called_once_with()

    def test_failed_apply_is_retried_without_another_account_change(self):
        db.set_settings(setup_done=True)
        uid = db.add_user('expired-retry', expire_at=int(time.time()) - 60)
        scheduler = jobs.Scheduler()
        with mock.patch.object(scheduler, 'due', side_effect=lambda name, _: name in ('collect', 'traffic')), \
                mock.patch.object(jobs, 'collect'), \
                mock.patch.object(jobs.system, 'health', return_value={}), \
                mock.patch.object(jobs, 'server_month', side_effect=OSError('telemetry write failed')), \
                mock.patch.object(jobs.cluster, 'sync_soon') as sync, \
                mock.patch.object(jobs.cores, 'apply', side_effect=[OSError('core temporarily unavailable'), None]) as apply, \
                mock.patch.object(jobs.time, 'monotonic', return_value=1000):
            with self.assertRaisesRegex(OSError, 'telemetry write failed'):
                scheduler.tick()
            self.assertEqual(db.user(uid)['enabled'], 0)
            self.assertTrue(scheduler.apply_owed)
            self.assertEqual(scheduler.apply_at, 1060)
            # No second change exists to trigger another apply. The pending
            # work, including node sync, must survive the failed first tick.
            with mock.patch.object(scheduler, 'due', return_value=False), \
                    mock.patch.object(jobs.time, 'monotonic', return_value=1059):
                scheduler.tick()
                self.assertEqual(apply.call_count, 1)
            with mock.patch.object(scheduler, 'due', return_value=False), \
                    mock.patch.object(jobs.time, 'monotonic', return_value=1060):
                scheduler.tick()
            self.assertEqual(apply.call_count, 2)
            self.assertEqual(sync.call_count, 2)
            self.assertFalse(scheduler.apply_owed)
