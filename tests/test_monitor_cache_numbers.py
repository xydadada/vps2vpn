"""Corrupt optional telemetry must not disable the monitor or discard good rows."""
import copy
import json
import unittest

from tests import test_unit as tu
from vps2vpn import monitor, paths


class MonitorCacheNumbers(tu.Base):
    def test_extreme_numeric_rows_are_skipped_and_monitor_can_append(self):
        good = {'at': 123, 'sites': {'github/4': {'ok': True, 'total': 12.5}},
                'speed': {'ok': True, 'at': 123, 'mbps': 32}}
        for field in ('total', 'mbps'):
            for invalid in (10 ** 400, -(10 ** 400), -1, float('inf'), float('nan')):
                with self.subTest(field=field, kind=type(invalid).__name__):
                    bad = copy.deepcopy(good)
                    target = bad['sites']['github/4'] if field == 'total' else bad['speed']
                    target[field] = invalid
                    paths.write_atomic(monitor.FILE, json.dumps([bad, good]), 0o600)
                    monitor._hist = None
                    self.assertEqual(monitor.history(), [good])
                    summary = monitor.summary()
                    row = next(x for x in summary['sites'] if x['id'] == 'github')
                    self.assertEqual(row['v4']['median_ms'], 12.5)
                    monitor._append(dict(good, at=124))
                    monitor._hist = None
                    self.assertEqual(len(monitor.history()), 2)

    def test_zero_and_finite_integer_or_float_measurements_are_kept(self):
        rows = [
            {'at': 123 + i, 'sites': {'github/4': {'ok': True, 'total': value}},
             'speed': {'ok': True, 'mbps': value}}
            for i, value in enumerate((0, 0.0, 12, 12.5))
        ]
        rows.append({'at': 127, 'sites': {'github/4': {'ok': False}},
                     'speed': {'ok': False, 'bytes': 0}})
        paths.write_atomic(monitor.FILE, json.dumps(rows), 0o600)
        monitor._hist = None
        self.assertEqual(monitor.history(), rows)


if __name__ == '__main__':
    unittest.main()
