"""A transient backup failure must not suppress backups for a whole day."""
from unittest import mock

from tests import test_unit as tu
from vps2vpn import db, jobs


class BackupSchedule(tu.Base):
    def test_failed_backup_retries_with_backoff_then_returns_to_daily_schedule(self):
        db.set_settings(setup_done=True)
        scheduler = jobs.Scheduler()
        original_due = scheduler.due
        now = [1000.0]
        with mock.patch.object(jobs.time, 'monotonic', side_effect=lambda: now[0]), \
                mock.patch.object(scheduler, 'due', side_effect=lambda name, every:
                                  original_due(name, every) if name == 'backup' else False), \
                mock.patch.object(jobs, 'backup', side_effect=[OSError('disk temporarily unavailable'),
                                                             OSError('disk still unavailable'),
                                                             'backup.json', 'backup.json']) as backup:
            scheduler.tick()
            self.assertEqual(backup.call_count, 1)
            now[0] += 59
            scheduler.tick()
            self.assertEqual(backup.call_count, 1)
            now[0] += 1
            scheduler.tick()
            self.assertEqual(backup.call_count, 2)
            now[0] += 119
            scheduler.tick()
            self.assertEqual(backup.call_count, 2)
            now[0] += 1
            scheduler.tick()
            self.assertEqual(backup.call_count, 3)
            now[0] += 86399
            scheduler.tick()
            self.assertEqual(backup.call_count, 3)
            now[0] += 1
            scheduler.tick()
            self.assertEqual(backup.call_count, 4)
