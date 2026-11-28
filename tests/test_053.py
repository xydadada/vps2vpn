"""0.2.53: the outside review of 2026-11-27 (PRs #164-#173, issues #163 / #172, offline bundle)."""
import os
import subprocess
import unittest
from unittest import mock

from tests import test_unit as tu
from vps2vpn import cores, db, jobs, paths, shaper, system

OK = subprocess.CompletedProcess([], 0, '', '')


def _quiet_apply(**extra):
    """The patches every cores.apply test needs, plus `extra` (name -> mock.patch.object args)."""
    base = {
        'live': (cores, '_xray_live_update', {'return_value': False}),
        'save': (cores, '_save_before_restart', {}),
        'active': (system, 'unit_active', {'return_value': True}),
        'hop': (system, 'port_hopping', {'return_value': None}),
        'shape': (shaper, 'apply', {'return_value': True}),
    }
    base.update(extra)
    return [mock.patch.object(obj, name, **kw) for obj, name, kw in base.values()]


class Patched:
    def __init__(self, patches):
        self.patches = patches

    def __enter__(self):
        return [p.start() for p in self.patches]

    def __exit__(self, *a):
        for p in reversed(self.patches):
            p.stop()


class InterruptedApplyOwesRestarts(tu.Base):
    """#166: a config written but not yet loaded by its core is restarted by the next apply."""

    def test_a_timeout_part_way_leaves_every_new_config_owed(self):
        for action in ('enable', 'restart'):
            with self.subTest(action=action):
                db.set_settings(reality_enabled=True, hy2_enabled=True, tuic_enabled=True)
                calls, hit = [], []

                def ctl(*args):
                    calls.append(args)
                    if args == (action, cores.XRAY_UNIT) and not hit:
                        hit.append(1)
                        raise subprocess.TimeoutExpired(['systemctl'] + list(args), 60)
                    return OK

                units = {cores.XRAY_UNIT, cores.HY2_UNIT, cores.TUIC_UNIT}
                with mock.patch.object(cores, '_restart_owed', set()), Patched(_quiet_apply(
                        w=(cores, 'write_configs', {'side_effect': [
                            [paths.XRAY_CONFIG, paths.HY2_CONFIG, paths.TUIC_CONFIG], [], []]}),
                        ctl=(system, 'systemctl', {'side_effect': ctl}))):
                    with self.assertRaises(subprocess.TimeoutExpired):
                        cores.apply()
                    self.assertEqual(cores._restart_owed, units)
                    calls.clear()
                    cores.apply()
                    self.assertEqual({a[1] for a in calls if a[0] == 'restart'}, units)
                    self.assertEqual(cores._restart_owed, set())
                    calls.clear()
                    cores.apply()
                    self.assertFalse([a for a in calls if a[0] == 'restart'])

    def test_a_later_failed_write_keeps_the_earlier_files_owed(self):
        db.set_settings(reality_enabled=True, hy2_enabled=True, tuic_enabled=True)
        real, failed = paths.write_atomic, []

        def write(path, *a, **kw):
            if path == paths.TUIC_CONFIG and not failed:
                failed.append(1)
                raise OSError('injected disk failure')
            return real(path, *a, **kw)

        with mock.patch.object(cores, '_restart_owed', set()), Patched(_quiet_apply(
                w=(paths, 'write_atomic', {'side_effect': write}),
                ctl=(system, 'systemctl', {'return_value': OK}))) as m:
            ctl = m[-1]
            with self.assertRaises(OSError):
                cores.apply()
            self.assertEqual(cores._restart_owed, {cores.XRAY_UNIT, cores.HY2_UNIT})
            ctl.assert_not_called()
            cores.apply()
            self.assertEqual({c.args[1] for c in ctl.call_args_list if c.args[0] == 'restart'},
                             {cores.XRAY_UNIT, cores.HY2_UNIT, cores.TUIC_UNIT})
            self.assertEqual(cores._restart_owed, set())

    def test_a_live_update_is_not_used_while_an_older_file_waits(self):
        db.set_settings(reality_enabled=True, hy2_enabled=False, tuic_enabled=False)
        with mock.patch.object(cores, '_restart_owed', {cores.XRAY_UNIT}), Patched(_quiet_apply(
                live=(cores, '_xray_live_update', {'return_value': True}),
                w=(cores, 'write_configs', {'return_value': [paths.XRAY_CONFIG]}),
                ctl=(system, 'systemctl', {'return_value': OK}))) as m:
            live, ctl = m[0], m[-1]
            cores.apply()
            live.assert_not_called()
            self.assertIn(mock.call('restart', cores.XRAY_UNIT), ctl.call_args_list)
            self.assertEqual(cores._restart_owed, set())

    def test_a_live_update_settles_xray(self):
        db.set_settings(reality_enabled=True, hy2_enabled=False, tuic_enabled=False)
        with mock.patch.object(cores, '_restart_owed', set()), Patched(_quiet_apply(
                live=(cores, '_xray_live_update', {'return_value': True}),
                w=(cores, 'write_configs', {'return_value': [paths.XRAY_CONFIG]}),
                ctl=(system, 'systemctl', {'return_value': OK}))) as m:
            cores.apply()
            self.assertFalse([c for c in m[-1].call_args_list if c.args[0] == 'restart'])
            self.assertEqual(cores._restart_owed, set())


class OwedRestartsSurviveAPanelRestart(tu.Base):
    """The record is on disk for this boot: a new panel process (or `vps2vpn apply`) still restarts the core."""

    def setUp(self):
        super().setUp()
        db.set_settings(reality_enabled=True, hy2_enabled=False, tuic_enabled=False)

    def run_apply(self, writes, rc):
        calls = []

        def ctl(*args):
            calls.append(args)
            return subprocess.CompletedProcess(args, rc if args[0] == 'restart' else 0, '', 'rejected')

        with Patched(_quiet_apply(w=(cores, 'write_configs', {'return_value': writes}),
                                  ctl=(system, 'systemctl', {'side_effect': ctl}))):
            try:
                cores.apply()
            except RuntimeError:
                pass
        return [a[1] for a in calls if a[0] == 'restart']

    def test_a_new_process_restarts_what_the_last_one_owed(self):
        with mock.patch.object(cores, '_restart_owed', set()), mock.patch.object(cores, '_owed_loaded', [True]):
            self.run_apply([paths.XRAY_CONFIG], 1)
        self.assertTrue(os.path.exists(cores._owed_file()))
        with mock.patch.object(cores, '_restart_owed', set()), mock.patch.object(cores, '_owed_loaded', [False]):
            self.assertTrue(cores.restart_pending())
            self.assertTrue(jobs.Scheduler().apply_owed)
            self.assertEqual(self.run_apply([], 0), [cores.XRAY_UNIT])       # files unchanged, still restarted
            self.assertFalse(os.path.exists(cores._owed_file()))
            self.assertFalse(jobs.Scheduler().apply_owed)

    def test_a_reboot_forgets_it(self):
        with mock.patch.object(cores, '_restart_owed', set()), mock.patch.object(cores, '_owed_loaded', [True]), \
                mock.patch.object(cores, '_boot_id', return_value='boot-1'):
            self.run_apply([paths.XRAY_CONFIG], 1)
        with mock.patch.object(cores, '_restart_owed', set()), mock.patch.object(cores, '_owed_loaded', [False]), \
                mock.patch.object(cores, '_boot_id', return_value='boot-2'):
            self.assertFalse(cores.restart_pending())
            self.assertEqual(self.run_apply([], 0), [])

    def test_switching_the_protocol_off_settles_it(self):
        with mock.patch.object(cores, '_restart_owed', {cores.XRAY_UNIT}), mock.patch.object(cores, '_owed_loaded', [True]):
            db.set_settings(reality_enabled=False, hy2_enabled=True)
            self.run_apply([], 0)
            self.assertEqual(cores._restart_owed, set())

    def test_a_broken_record_is_ignored(self):
        os.makedirs(paths.VAR, exist_ok=True)
        with open(cores._owed_file(), 'w') as f:
            f.write('[1, 2')
        self.assertEqual(cores._owed_on_disk(), set())


class FailedStopIsAnError(tu.Base):
    """#171: a protocol switched off whose core keeps running is reported, so apply_async tries again."""

    def test_each_protocol(self):
        fail = subprocess.CompletedProcess([], 1, '', 'injected stop failure')
        for unit, flag in cores._ENABLED.items():
            with self.subTest(unit=unit):
                db.set_settings(reality_enabled=True, hy2_enabled=True, tuic_enabled=True)
                db.set_settings(**{flag: False})
                with mock.patch.object(cores, '_restart_owed', set()), Patched(_quiet_apply(
                        w=(cores, 'write_configs', {'return_value': []}),
                        ctl=(system, 'systemctl', {'side_effect': [fail, OK]}))) as m:
                    with self.assertRaisesRegex(RuntimeError, unit + ' did not stop'):
                        cores.apply()
                    cores.apply()
                    self.assertEqual(m[-1].call_args_list, [mock.call('disable', '--now', unit)] * 2)

    def test_one_failure_does_not_skip_the_others(self):
        db.set_settings(reality_enabled=True, hy2_enabled=False, tuic_enabled=False)
        with mock.patch.object(cores, '_restart_owed', set()), Patched(_quiet_apply(
                w=(cores, 'write_configs', {'return_value': []}),
                ctl=(system, 'systemctl', {'side_effect': lambda *a: subprocess.CompletedProcess(
                    a, int(a[-1] == cores.HY2_UNIT), '', '')}))) as m:
            with self.assertRaisesRegex(RuntimeError, cores.HY2_UNIT + ' did not stop'):
                cores.apply()
            self.assertEqual(m[-1].call_args_list, [mock.call('disable', '--now', cores.HY2_UNIT),
                                                    mock.call('disable', '--now', cores.TUIC_UNIT)])

    def test_a_unit_that_is_not_running_is_not_an_error(self):
        # e.g. a unit file that is not there: nothing serves, so nothing to retry
        db.set_settings(reality_enabled=True, hy2_enabled=False, tuic_enabled=True)
        with mock.patch.object(cores, '_restart_owed', set()), Patched(_quiet_apply(
                active=(system, 'unit_active', {'side_effect': lambda u: u != cores.HY2_UNIT}),
                w=(cores, 'write_configs', {'return_value': []}),
                ctl=(system, 'systemctl', {'side_effect': lambda *a: subprocess.CompletedProcess(
                    a, int(a[0] == 'disable'), '', 'Unit file does not exist')}))):
            cores.apply()


class SchedulerKeepsAManualDisable(tu.Base):
    """#172: enforce decides from a snapshot; an admin's "off" saved meanwhile stays."""

    def run_with_admin_between(self, uid, **admin):
        def admin_saves(_settings):          # runs after enforce read the accounts, before it writes
            db.update_user(uid, **admin)
            return False
        with mock.patch.object(cores, 'can_slow_here', side_effect=admin_saves), mock.patch.object(jobs, 'log'):
            jobs.enforce()
        return db.user(uid)

    def test_auto_resume_does_not_undo_it(self):
        uid = db.add_user('synthetic', quota_gb=10)
        db.update_user(uid, enabled=0, disabled_reason='quota')      # quota available again, not resumed yet
        row = self.run_with_admin_between(uid, enabled=0, disabled_reason='manual')
        self.assertEqual((row['enabled'], row['disabled_reason']), (0, 'manual'))
        jobs.enforce()
        row = db.user(uid)
        self.assertEqual((row['enabled'], row['disabled_reason']), (0, 'manual'))

    def test_auto_pause_does_not_relabel_it(self):
        # relabelled "quota", it would be switched back on by itself after the next reset or top-up
        uid = db.add_user('synthetic', quota_gb=1)
        db.update_user(uid, used_down=2 << 30)
        row = self.run_with_admin_between(uid, enabled=0, disabled_reason='manual')
        self.assertEqual((row['enabled'], row['disabled_reason']), (0, 'manual'))

    def test_end_of_a_device_pause_does_not_undo_it(self):
        uid = db.add_user('synthetic', quota_gb=10)
        db.update_user(uid, enabled=0, disabled_reason='devices', paused_until=1)
        row = self.run_with_admin_between(uid, enabled=0, disabled_reason='manual')
        self.assertEqual((row['enabled'], row['disabled_reason']), (0, 'manual'))

    def test_without_an_admin_the_usual_transitions_still_happen(self):
        a, b = db.add_user('a', quota_gb=10), db.add_user('b', quota_gb=1)
        db.update_user(a, enabled=0, disabled_reason='quota')
        db.update_user(b, used_down=2 << 30)
        with mock.patch.object(jobs, 'log'):
            self.assertTrue(jobs.enforce())
        self.assertEqual((db.user(a)['enabled'], db.user(b)['disabled_reason']), (1, 'quota'))


if __name__ == '__main__':
    unittest.main()
