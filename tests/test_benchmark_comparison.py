"""A comparison must retain its measurement source and failed samples."""
import contextlib
import copy
import http.server
import importlib.util
import io
import json
import multiprocessing
import os
import tempfile
import threading
import time
import unittest
from unittest import mock

from vps2vpn import bench, bench_compare

SPEC = importlib.util.spec_from_file_location(
    'vps2vpn_comparison_tool', os.path.join(os.path.dirname(__file__), '..', 'tools', 'bench.py'))
bench_tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bench_tool)


def successful_result():
    return {'errors': [], 'latency': {'median': 2, 'p90': 3, 'min': 1, 'fails': 0},
            'down_1': 40.0, 'down_4': 50.0, 'up_1': 20.0,
            'download_diagnostics': {key: {'warmup_complete': True, 'errors': []}
                                     for key in ('down_1', 'down_4')}}


class MeasurementProvenance(unittest.TestCase):
    def measure(self, download, origin=None, picked=None):
        with mock.patch.object(bench, 'working_download_url', return_value=picked or bench.DOWN_URL), \
                mock.patch.object(bench, 'latency', return_value={'median': 10, 'p90': 12, 'min': 9, 'fails': 0}), \
                mock.patch.object(bench, 'upload', return_value=5.0), \
                mock.patch.object(bench, 'download', side_effect=download):
            return bench.run(quick=True, origin=origin, log=lambda _: None)

    @staticmethod
    def good_download(*args, diagnostics=None, **kwargs):
        diagnostics.update(bytes=1024, warmup_complete=True, retries=0, errors=[])
        return 42.0

    def test_public_fallback_is_identified_in_each_download(self):
        result = self.measure(self.good_download, picked=bench.DOWN_FALLBACKS[0])
        self.assertEqual(result['measurement']['source_policy'], 'public-fallback')
        self.assertEqual(result['download_diagnostics']['down_1']['source_id'], 'ovh')
        self.assertEqual(result['download_diagnostics']['down_4']['source_id'], 'ovh')
        self.assertEqual((result['down_1'], result['down_4'], result['up_1']), (42.0, 42.0, 5.0))

    def test_failed_download_attempt_is_retained_when_another_source_works(self):
        def download(*args, url=None, diagnostics=None, **kwargs):
            if url == bench.DOWN_URL:
                diagnostics.update(bytes=0, warmup_complete=False, retries=2, errors=['download 1x: HTTP 503'])
                return 0.0
            return self.good_download(diagnostics=diagnostics)

        result = self.measure(download)
        attempts = result['download_diagnostics']['down_1']['attempts']
        self.assertEqual([attempt['source_id'] for attempt in attempts], ['cloudflare', 'ovh'])
        self.assertEqual([attempt['mbps'] for attempt in attempts], [0.0, 42.0])
        self.assertEqual(attempts[0]['errors'], ['download 1x: HTTP 503'])
        self.assertEqual(len(result['download_diagnostics']['down_4']['attempts']), 1)

    def test_controlled_source_has_no_host_in_results(self):
        result = self.measure(self.good_download, origin='https://private-test.example.com:8443')
        self.assertEqual(result['measurement']['source_policy'], 'controlled-no-fallback')
        self.assertEqual(result['download_diagnostics']['down_1']['source_id'], 'controlled')
        self.assertNotIn('private-test', json.dumps(result))
        self.assertNotIn('8443', json.dumps(result))

    def test_explicit_origin_failure_is_retained_without_public_fallback(self):
        def failure(*args, diagnostics=None, **kwargs):
            diagnostics.update(bytes=0, warmup_complete=False, retries=2, errors=['download 1x: HTTP 503'])
            return 0.0

        result = self.measure(failure, origin='http://example.com')
        for key in ('down_1', 'down_4'):
            self.assertEqual(result[key], 0.0)
            self.assertEqual(len(result['download_diagnostics'][key]['attempts']), 1)
            self.assertEqual(result['download_diagnostics'][key]['attempts'][0]['source_id'], 'controlled')


class ComparisonScheduling(unittest.TestCase):
    def test_each_path_occurs_in_each_position_over_one_rotation(self):
        order = bench_compare.path_order(4, 4, 8)
        self.assertEqual(order, bench_compare.path_order(4, 4, 8))
        for row in order:
            self.assertEqual(sorted(row), [0, 1, 2, 3])
        for column in zip(*order):
            self.assertEqual(sorted(column), [0, 1, 2, 3])

    def test_failed_sample_is_kept_and_does_not_change_the_plan(self):
        bad = successful_result()
        bad['down_1'] = 0.0
        paths = [{'proxy': None, 'protocol': 'direct'},
                 {'proxy': 'http://127.0.0.1:9', 'protocol': 'hysteria2'}]
        values = [bad, successful_result(), successful_result(), successful_result()]
        with mock.patch.object(bench_compare, 'bounded_sample', side_effect=[
                {'status': 'measured', 'result': value} for value in values]) as measure:
            result = bench_compare.run(paths, 'http://fixture.example.com', rounds=2, log=lambda _: None)
        self.assertFalse(result['complete'])
        self.assertEqual((result['attempted_samples'], result['successful_samples']), (4, 3))
        self.assertEqual([sample['status'] for sample in result['samples']], ['incomplete', 'ok', 'ok', 'ok'])
        self.assertEqual(result['samples'][0]['result']['down_1'], 0.0)
        self.assertEqual({call.args[2] for call in measure.call_args_list}, {'http://fixture.example.com'})
        for round_number in (1, 2):
            self.assertEqual({sample['path_id'] for sample in result['samples'] if sample['round'] == round_number},
                             {'p01', 'p02'})

    def test_budget_exhaustion_is_explicit_and_limits_the_sample_deadline(self):
        now = [0.0]

        def timeout(proxy, quick, origin, seconds):
            self.assertEqual(seconds, 1)
            now[0] += seconds
            return {'status': 'timeout'}

        with mock.patch.object(bench_compare.time, 'monotonic', side_effect=lambda: now[0]), \
                mock.patch.object(bench_compare, 'bounded_sample', side_effect=timeout) as measure:
            result = bench_compare.run([{'proxy': None, 'protocol': 'direct'}], 'http://example.com',
                                       rounds=3, budget=1, sample_timeout=120, log=lambda _: None)
        self.assertEqual(measure.call_count, 1)
        self.assertEqual(result['stopped'], 'budget-exhausted')
        self.assertEqual((result['attempted_samples'], result['scheduled_samples']), (1, 3))
        self.assertFalse(result['complete'])

    def test_incomplete_latency_or_warmup_is_not_a_success(self):
        result = successful_result()
        result['latency']['fails'] = 1
        self.assertFalse(bench_compare._complete(result))
        result = successful_result()
        result['download_diagnostics']['down_4']['warmup_complete'] = False
        self.assertFalse(bench_compare._complete(result))
        for value in (float('nan'), float('inf'), True):
            result = successful_result()
            result['up_1'] = value
            self.assertFalse(bench_compare._complete(result))

    def test_limits_and_sensitive_origin_inputs_are_rejected_before_workers(self):
        cases = [{'origin': None}, {'origin': 'https://REDACTED@example.com'},
                 {'origin': 'https://example.com/?token=REDACTED'},
                 {'origin': 'https://example.com:REDACTED'}, {'rounds': 0}, {'rounds': 21},
                 {'budget': 0}, {'budget': 3601}, {'sample_timeout': 301}, {'seed': -1}]
        with mock.patch.object(bench_compare, 'bounded_sample') as measure:
            for case in cases:
                options = dict(origin='http://example.com')
                options.update(case)
                with self.subTest(case=case), self.assertRaises(ValueError) as caught:
                    bench_compare.run([{'proxy': None}], log=lambda _: None, **options)
                self.assertNotIn('REDACTED', str(caught.exception))
                self.assertNotIn('example.com', str(caught.exception))
            with self.assertRaises(ValueError):
                bench_compare.run([{}] * 33, 'http://example.com')
        measure.assert_not_called()

    def test_output_uses_anonymous_ids_and_allowlisted_protocols(self):
        with mock.patch.object(bench_compare, 'bounded_sample', return_value={
                'status': 'measured', 'result': successful_result()}):
            result = bench_compare.run([{'proxy': 'http://REDACTED:REDACTED@example.com:80',
                                         'name': 'REDACTED', 'protocol': 'REDACTED'}],
                                       'https://fixture.example.com', rounds=1, log=lambda _: None)
        self.assertEqual(result['paths'], [{'path_id': 'p01', 'protocol': 'other'}])
        self.assertNotIn('REDACTED', json.dumps(result))
        self.assertNotIn('example.com', json.dumps(result))


class ControlledHTTP(unittest.TestCase):
    """Real loopback HTTP exercises I/O; it makes no claim about any proxy protocol."""
    def setUp(self):
        self.requests = []
        self.started = threading.Event()
        self.release = threading.Event()
        owner = self

        class Fixture(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                owner.requests.append(self.path)
                if self.path == '/stall':
                    owner.started.set()
                    owner.release.wait(10)
                    return
                if self.path == '/redirect':
                    self.send_response(302)
                    self.send_header('Location', '/unexpected')
                    self.send_header('Content-Length', '0')
                    self.end_headers()
                    return
                if self.path == '/generate_204':
                    self.send_response(204)
                    self.end_headers()
                    return
                body = b'x' * (128 << 10)
                self.send_response(200)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                try:
                    self.wfile.write(body)
                except OSError:
                    pass

            def do_POST(self):
                owner.requests.append(self.path)
                self.rfile.read(int(self.headers['Content-Length']))
                self.send_response(200)
                self.send_header('Content-Length', '0')
                self.end_headers()

            def log_message(self, *args):
                pass

        self.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Fixture)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.origin = 'http://127.0.0.1:%d' % self.server.server_address[1]

    def tearDown(self):
        self.release.set()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(2)

    def test_real_http_measurements_record_one_controlled_source(self):
        # Shorten sizes/times, but call the actual latency/download/upload I/O functions.
        latency, download, upload = bench.latency, bench.download, bench.upload
        def short_latency(proxy, **kwargs):
            kwargs['n'] = 2
            return latency(proxy, **kwargs)
        def short_download(proxy, streams, seconds, **kwargs):
            return download(proxy, streams, 0.1, size=128 << 10, **kwargs)
        def short_upload(proxy, size, **kwargs):
            return upload(proxy, 128 << 10, **kwargs)
        with mock.patch.object(bench, 'latency', side_effect=short_latency), \
                mock.patch.object(bench, 'download', side_effect=short_download), \
                mock.patch.object(bench, 'upload', side_effect=short_upload), \
                mock.patch.object(bench, 'working_download_url', side_effect=AssertionError('public probe')):
            result = bench.run(origin=self.origin, log=lambda _: None)
        self.assertTrue(bench_compare._complete(result), result)
        self.assertIn('/generate_204', self.requests)
        self.assertIn('/__up', self.requests)
        self.assertTrue(any(path.startswith('/__down?bytes=') for path in self.requests))
        self.assertNotIn(self.origin, json.dumps(result))
        self.assertEqual(result['download_diagnostics']['down_4']['source_id'], 'controlled')

    def test_controlled_redirect_is_a_recorded_failure_and_is_not_followed(self):
        errors = []
        result = bench.latency(n=1, url=self.origin + '/redirect', errors=errors, allow_redirects=False)
        self.assertEqual(result['fails'], 1)
        self.assertEqual(errors, ['latency: HTTP 302'])
        self.assertEqual(self.requests, ['/redirect'])

    def test_real_blocking_worker_is_terminated_without_leaving_a_child(self):
        # The worker's first measurement blocks on a real HTTP peer; the parent owns no core here.
        before = {child.pid for child in multiprocessing.active_children()}
        original_handler = self.server.RequestHandlerClass
        owner = self
        class StallingFixture(original_handler):
            def do_GET(self):
                owner.started.set()
                owner.release.wait(10)
        self.server.RequestHandlerClass = StallingFixture
        started = time.monotonic()
        sample = bench_compare.bounded_sample(None, True, self.origin, 1.5)
        elapsed = time.monotonic() - started
        self.assertTrue(self.started.is_set(), 'spawned worker must actually reach the fixture')
        self.assertEqual(sample, {'status': 'timeout'})
        self.assertLess(elapsed, 4.5)
        self.assertEqual({child.pid for child in multiprocessing.active_children()}, before)

    def test_real_worker_returns_failed_http_samples_without_hiding_them(self):
        original_handler = self.server.RequestHandlerClass
        class RedirectingFixture(original_handler):
            def do_GET(self):
                self.send_response(302)
                self.send_header('Location', '/unexpected')
                self.send_header('Content-Length', '0')
                self.end_headers()
        self.server.RequestHandlerClass = RedirectingFixture
        before = {child.pid for child in multiprocessing.active_children()}
        sample = bench_compare.bounded_sample(None, True, self.origin, 10)
        self.assertEqual(sample['status'], 'measured')
        self.assertFalse(bench_compare._complete(sample['result']))
        self.assertEqual(sample['result']['latency']['fails'], 5)
        self.assertEqual(sample['result']['down_1'], 0.0)
        self.assertEqual(sample['result']['download_diagnostics']['down_1']['attempts'][0]['source_id'], 'controlled')
        self.assertIn('latency: HTTP 302', sample['result']['errors'])
        self.assertNotIn(self.origin, json.dumps(sample))
        self.assertEqual({child.pid for child in multiprocessing.active_children()}, before)


class ComparisonCLI(unittest.TestCase):
    def test_missing_origin_or_unused_options_fail_before_core_launch(self):
        for arguments in (['--compare'], ['--rounds', '3'], ['--compare', '--origin', 'https://REDACTED@example.com']):
            output = io.StringIO()
            with mock.patch.object(bench_tool.sys, 'argv', ['bench.py'] + arguments), \
                    mock.patch.object(bench_tool.subprocess, 'Popen') as launch, \
                    contextlib.redirect_stderr(output), self.assertRaises(SystemExit) as caught:
                bench_tool.main()
            self.assertEqual(caught.exception.code, 2)
            self.assertNotIn('REDACTED', output.getvalue())
            launch.assert_not_called()

    def test_comparison_json_and_console_do_not_include_private_node_labels(self):
        with tempfile.TemporaryDirectory() as directory:
            config = os.path.join(directory, 'input.json')
            core = os.path.join(directory, 'core')
            output = os.path.join(directory, 'result.json')
            with open(config, 'w', encoding='utf-8') as file:
                json.dump({'proxies': [{'name': 'REDACTED', 'type': 'tuic', 'password': 'REDACTED'}]}, file)
            with open(core, 'w', encoding='utf-8'):
                pass
            capture = io.StringIO()
            process = mock.Mock()
            args = ['bench.py', '--config', config, '--mihomo', core, '--compare', '--rounds', '1',
                    '--origin', 'https://fixture.example.com', '--json', output]
            with mock.patch.object(bench_tool.sys, 'argv', args), \
                    mock.patch.object(bench_tool.subprocess, 'Popen', return_value=process), \
                    mock.patch.object(bench_tool, 'wait_port', return_value=True), \
                    mock.patch.object(bench_compare, 'bounded_sample', side_effect=lambda *args: {
                        'status': 'measured', 'result': copy.deepcopy(successful_result())}), \
                    contextlib.redirect_stdout(capture):
                bench_tool.main()
            with open(output, encoding='utf-8') as file:
                result = json.load(file)
            self.assertTrue(result['complete'])
            self.assertEqual(result['paths'], [{'path_id': 'p01', 'protocol': 'direct'},
                                               {'path_id': 'p02', 'protocol': 'tuic'}])
            public = capture.getvalue() + json.dumps(result)
            self.assertNotIn('REDACTED', public)
            self.assertNotIn('example.com', public)
            process.terminate.assert_called_once()
            process.wait.assert_called_once_with(5)


if __name__ == '__main__':
    unittest.main()
