"""An unsuccessful kernel limit update must keep core application retryable."""
import subprocess
from unittest import mock

from tests import test_unit as tu
from vps2vpn import cores, db, shaper, system


class ShaperApply(tu.Base):
    def test_failed_shaping_is_reported_and_same_config_can_retry(self):
        db.set_settings(reality_enabled=True, hy2_enabled=False, tuic_enabled=False)
        with mock.patch.object(cores, 'write_configs', return_value=[]), \
                mock.patch.object(cores, '_save_before_restart'), \
                mock.patch.object(cores, 'limits', return_value={1: 2.0}), \
                mock.patch.object(system, 'unit_active', return_value=True), \
                mock.patch.object(system, 'systemctl', return_value=subprocess.CompletedProcess([], 0)), \
                mock.patch.object(system, 'port_hopping', return_value=None), \
                mock.patch.object(shaper, 'apply', side_effect=[False, True]) as apply:
            with self.assertRaisesRegex(RuntimeError, 'speed limits'):
                cores.apply()
            self.assertEqual(cores.apply(), [])
            self.assertEqual(apply.call_args_list, [mock.call({1: 2.0}), mock.call({1: 2.0})])
