import subprocess
import unittest
from unittest import mock

from tests import test_unit as tu
from vps2vpn import cores, db, shaper, system


class CoreStopRetry(tu.Base):
    def test_failed_stop_is_reported_and_retried_for_each_protocol(self):
        for unit, flag in cores._ENABLED.items():
            with self.subTest(unit=unit):
                db.set_settings(reality_enabled=True, hy2_enabled=True, tuic_enabled=True)
                db.set_settings(**{flag: False})
                failure = subprocess.CompletedProcess([], 1, '', 'injected stop failure')
                success = subprocess.CompletedProcess([], 0, '', '')
                with mock.patch.object(cores, 'write_configs', return_value=[]), \
                        mock.patch.object(cores, '_save_before_restart'), \
                        mock.patch.object(cores, '_restart_owed', set()), \
                        mock.patch.object(system, 'unit_active', return_value=True), \
                        mock.patch.object(system, 'systemctl', side_effect=[failure, success]) as ctl, \
                        mock.patch.object(system, 'port_hopping', return_value=None), \
                        mock.patch.object(shaper, 'apply', return_value=True):
                    with self.assertRaisesRegex(RuntimeError, unit + ' did not stop'):
                        cores.apply()
                    cores.apply()
                    self.assertEqual(ctl.call_args_list, [mock.call('disable', '--now', unit)] * 2)

    def test_one_failed_stop_does_not_skip_other_disabled_protocols(self):
        db.set_settings(reality_enabled=True, hy2_enabled=False, tuic_enabled=False)

        def systemctl(*args):
            return subprocess.CompletedProcess(args, int(args[-1] == cores.HY2_UNIT), '', '')

        with mock.patch.object(cores, 'write_configs', return_value=[]), \
                mock.patch.object(cores, '_save_before_restart'), \
                mock.patch.object(cores, '_restart_owed', set()), \
                mock.patch.object(system, 'unit_active', return_value=True), \
                mock.patch.object(system, 'systemctl', side_effect=systemctl) as ctl, \
                mock.patch.object(system, 'port_hopping', return_value=None), \
                mock.patch.object(shaper, 'apply', return_value=True):
            with self.assertRaisesRegex(RuntimeError, cores.HY2_UNIT + ' did not stop'):
                cores.apply()
            self.assertEqual(ctl.call_args_list, [mock.call('disable', '--now', cores.HY2_UNIT),
                                                 mock.call('disable', '--now', cores.TUIC_UNIT)])


if __name__ == '__main__':
    unittest.main()
