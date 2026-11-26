"""A probe missing its deadline still counts as a failed availability sample."""
from unittest import mock

from tests import test_unit as tu
from vps2vpn import monitor


class MonitorDeadline(tu.Base):
    def test_late_probe_is_recorded_as_failure_without_mutating_saved_history(self):
        for v6 in (False, True):
            with self.subTest(ipv6=v6):
                monitor._hist = []
                workers = []

                class LateThread:
                    def __init__(self, target, args, daemon):
                        self.target, self.args = target, args
                        workers.append(self)

                    def start(self):
                        pass

                    def join(self, timeout):
                        pass

                with mock.patch.object(monitor, 'TARGETS', [('fixture', 'Fixture', 'example.invalid', '/')]), \
                        mock.patch.object(monitor, 'has_ipv6', return_value=v6), \
                        mock.patch.object(monitor.threading, 'Thread', LateThread), \
                        mock.patch.object(monitor, 'probe', return_value={'ok': True, 'total': 12}), \
                        mock.patch.object(monitor, 'speed', return_value={'ok': False, 'at': 1}):
                    entry = monitor.run_once()
                    self.assertEqual(set(entry['sites']), {'fixture/4', 'fixture/6'} if v6 else {'fixture/4'})
                    self.assertTrue(all(not result['ok'] for result in entry['sites'].values()))
                    for worker in workers:
                        worker.target(*worker.args)
                    self.assertTrue(all(not result['ok'] for result in monitor.history()[-1]['sites'].values()))
                    row = monitor.summary()['sites'][0]
                    self.assertEqual(row['v4']['uptime'], 0)
                    if v6:
                        self.assertEqual(row['v6']['uptime'], 0)
                    else:
                        self.assertNotIn('v6', row)
