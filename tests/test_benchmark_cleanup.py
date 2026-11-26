"""The benchmark must remove its credential-bearing config if its core cannot launch."""
import importlib.util
import json
import os
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location(
    'vps2vpn_bench_tool', os.path.join(os.path.dirname(__file__), '..', 'tools', 'bench.py'))
bench_tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bench_tool)


class LaunchCleanup(unittest.TestCase):
    def test_failed_core_launch_removes_the_private_config(self):
        with tempfile.TemporaryDirectory() as directory:
            config = os.path.join(directory, 'input.json')
            core = os.path.join(directory, 'unexecutable-core')
            with open(config, 'w', encoding='utf-8') as file:
                json.dump({'proxies': [{'name': 'synthetic', 'password': 'synthetic-test-secret'}]}, file)
            with open(core, 'w', encoding='utf-8') as file:
                file.write('not executable')
            work = os.path.join(directory, 'work')
            os.mkdir(work)

            def fail_launch(*args, **kwargs):
                with open(os.path.join(work, 'config.yaml'), encoding='utf-8') as file:
                    self.assertIn('synthetic-test-secret', file.read())
                raise PermissionError('synthetic launch failure')

            with mock.patch.object(bench_tool.sys, 'argv', ['bench.py', '--config', config, '--mihomo', core]), \
                    mock.patch.object(bench_tool.tempfile, 'mkdtemp', return_value=work), \
                    mock.patch.object(bench_tool, 'free_port', return_value=18080), \
                    mock.patch.object(bench_tool.subprocess, 'Popen', side_effect=fail_launch):
                with self.assertRaisesRegex(PermissionError, 'synthetic launch failure'):
                    bench_tool.main()
            self.assertFalse(os.path.exists(work))
            self.assertTrue(os.path.exists(config))
