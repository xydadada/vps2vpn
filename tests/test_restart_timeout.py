import subprocess
from unittest import mock

from tests import test_unit as tu
from vps2vpn import cores, db, paths, shaper, system


class RestartTimeout(tu.Base):
    def test_interrupted_apply_retries_every_unapplied_config(self):
        for interrupted_action in ('enable', 'restart'):
            with self.subTest(action=interrupted_action):
                db.set_settings(reality_enabled=True, hy2_enabled=True, tuic_enabled=True)
                calls = []
                interrupted = []

                def systemctl(*args):
                    calls.append(args)
                    if args == (interrupted_action, cores.XRAY_UNIT) and not interrupted:
                        interrupted.append(True)
                        raise subprocess.TimeoutExpired(['systemctl', *args], 60)
                    return subprocess.CompletedProcess(args, 0, '', '')

                units = {cores.XRAY_UNIT, cores.HY2_UNIT, cores.TUIC_UNIT}
                with mock.patch.object(cores, '_restart_owed', set()), \
                        mock.patch.object(cores, 'write_configs', side_effect=[
                            [paths.XRAY_CONFIG, paths.HY2_CONFIG, paths.TUIC_CONFIG], [], []]), \
                        mock.patch.object(cores, '_xray_live_update', return_value=False), \
                        mock.patch.object(cores, '_save_before_restart'), \
                        mock.patch.object(system, 'unit_active', return_value=True), \
                        mock.patch.object(system, 'systemctl', side_effect=systemctl), \
                        mock.patch.object(system, 'port_hopping', return_value=None), \
                        mock.patch.object(shaper, 'apply', return_value=True):
                    with self.assertRaises(subprocess.TimeoutExpired):
                        cores.apply()
                    self.assertEqual(cores._restart_owed, units)
                    calls.clear()
                    cores.apply()
                    self.assertEqual({args[1] for args in calls if args[0] == 'restart'}, units)
                    self.assertEqual(cores._restart_owed, set())
                    calls.clear()
                    cores.apply()
                    self.assertFalse([args for args in calls if args[0] == 'restart'])

    def test_a_later_failed_write_keeps_earlier_configs_pending(self):
        db.set_settings(reality_enabled=True, hy2_enabled=True, tuic_enabled=True)
        real_write = paths.write_atomic
        failed = []

        def write(path, *args, **kwargs):
            if path == paths.TUIC_CONFIG and not failed:
                failed.append(True)
                raise OSError('injected disk failure')
            return real_write(path, *args, **kwargs)

        with mock.patch.object(cores, '_restart_owed', set()), \
                mock.patch.object(paths, 'write_atomic', side_effect=write), \
                mock.patch.object(cores, '_xray_live_update', return_value=False), \
                mock.patch.object(cores, '_save_before_restart'), \
                mock.patch.object(system, 'unit_active', return_value=True), \
                mock.patch.object(system, 'systemctl', return_value=subprocess.CompletedProcess([], 0, '', '')) as ctl, \
                mock.patch.object(system, 'port_hopping', return_value=None), \
                mock.patch.object(shaper, 'apply', return_value=True):
            with self.assertRaises(OSError):
                cores.apply()
            self.assertEqual(cores._restart_owed, {cores.XRAY_UNIT, cores.HY2_UNIT})
            ctl.assert_not_called()
            cores.apply()
            self.assertEqual({c.args[1] for c in ctl.call_args_list if c.args[0] == 'restart'},
                             {cores.XRAY_UNIT, cores.HY2_UNIT, cores.TUIC_UNIT})
            self.assertEqual(cores._restart_owed, set())

    def test_successful_live_update_does_not_restart_xray(self):
        db.set_settings(reality_enabled=True, hy2_enabled=False, tuic_enabled=False)
        with mock.patch.object(cores, '_restart_owed', set()), \
                mock.patch.object(cores, 'write_configs', return_value=[paths.XRAY_CONFIG]), \
                mock.patch.object(cores, '_xray_live_update', return_value=True), \
                mock.patch.object(cores, '_save_before_restart'), \
                mock.patch.object(system, 'unit_active', return_value=True), \
                mock.patch.object(system, 'systemctl') as ctl, \
                mock.patch.object(system, 'port_hopping', return_value=None), \
                mock.patch.object(shaper, 'apply', return_value=True):
            cores.apply()
            self.assertFalse([c for c in ctl.call_args_list if c.args[0] == 'restart'])
            self.assertEqual(cores._restart_owed, set())

    def test_a_new_hot_add_cannot_clear_an_older_pending_config(self):
        db.set_settings(reality_enabled=True, hy2_enabled=False, tuic_enabled=False)
        with mock.patch.object(cores, '_restart_owed', {cores.XRAY_UNIT}), \
                mock.patch.object(cores, 'write_configs', return_value=[paths.XRAY_CONFIG]), \
                mock.patch.object(cores, '_xray_live_update', return_value=True) as live_update, \
                mock.patch.object(cores, '_save_before_restart'), \
                mock.patch.object(system, 'unit_active', return_value=True), \
                mock.patch.object(system, 'systemctl', return_value=subprocess.CompletedProcess([], 0, '', '')) as ctl, \
                mock.patch.object(system, 'port_hopping', return_value=None), \
                mock.patch.object(shaper, 'apply', return_value=True):
            cores.apply()
            live_update.assert_not_called()
            self.assertIn(mock.call('restart', cores.XRAY_UNIT), ctl.call_args_list)
            self.assertEqual(cores._restart_owed, set())
