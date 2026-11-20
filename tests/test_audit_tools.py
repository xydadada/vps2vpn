"""Regression checks for the benchmark trust boundary and the E2E harness itself."""
import ast
import http.client
import http.server
import importlib.util
import io
import json
import os
from pathlib import Path
import select
import shutil
import socket
import ssl
import sys
import tempfile
import threading
import types
import unittest
from unittest import mock
import urllib.error
import urllib.parse
import urllib.request

from tests import test_unit as tu
from vps2vpn import certs, paths

REPO = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('v2v_bench_cli', REPO / 'tools' / 'bench.py')
cli = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cli)


def e2e_function(name, **overrides):
    # Importing the standalone runner would start setup and search for real binaries.
    source = ast.parse((REPO / 'tests' / 'e2e_local.py').read_text(encoding='utf-8'))
    function = next(item for item in source.body if isinstance(item, ast.FunctionDef) and item.name == name)
    namespace = dict(http=http, os=os, shutil=shutil, socket=socket, threading=threading,
                     subprocess=__import__('subprocess'), sys=sys, time=__import__('time'))
    namespace.update(overrides)
    module = ast.Module(body=[function], type_ignores=[])
    exec(compile(module, str(REPO / 'tests' / 'e2e_local.py'), 'exec'), namespace)
    return namespace[name]


class BenchmarkTrust(unittest.TestCase):
    def response(self, payload=None):
        reply = mock.MagicMock()
        reply.__enter__.return_value = reply
        reply.read.return_value = payload if payload is not None else b'{"proxies":[{"name":"node","type":"tuic"}]}'
        opener = mock.Mock()
        opener.open.return_value = reply
        return opener, reply

    def test_plaintext_and_invalid_urls_rejected_before_network(self):
        for url in ('http://example.test/s/token', 'file:///etc/passwd', 'ftp://example.test/x',
                    'https://user:pass@example.test/s/t', 'https://example.test/s/t#fragment',
                    'https://example.test:0/x', 'https://example.test:65536/x',
                    'https://example.test/\nsecret', 'https:///missing-host'):
            with self.subTest(url=url), mock.patch.object(cli.urllib.request, 'build_opener') as opener:
                with self.assertRaises(ValueError):
                    cli.fetch_proxies(url)
                opener.assert_not_called()

    def test_default_tls_verified_and_format_replaced(self):
        opener, reply = self.response()
        with mock.patch.object(cli.urllib.request, 'build_opener', return_value=opener) as build:
            self.assertEqual(cli.fetch_proxies('https://example.test/s/token?format=singbox&x=1')[0]['name'], 'node')
        ctx = build.call_args.args[0]._context
        self.assertTrue(ctx.check_hostname)
        self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)
        request = opener.open.call_args.args[0]
        self.assertEqual(urllib.parse.parse_qs(urllib.parse.urlsplit(request.full_url).query),
                         {'format': ['clash'], 'x': ['1']})
        reply.read.assert_called_once_with(cli.MAX_SUBSCRIPTION_BYTES + 1)

    def test_explicit_insecure_opt_in_and_ca_conflict(self):
        opener, _ = self.response()
        with mock.patch.object(cli.urllib.request, 'build_opener', return_value=opener) as build:
            cli.fetch_proxies('http://example.test/s/token', insecure=True)
        ctx = build.call_args.args[0]._context
        self.assertFalse(ctx.check_hostname)
        self.assertEqual(ctx.verify_mode, ssl.CERT_NONE)
        with self.assertRaises(ValueError):
            cli.fetch_proxies('https://example.test/s/token', insecure=True, ca_file='ca.pem')

    def test_size_limit_enforced_before_parsing(self):
        opener, reply = self.response(b' ' * (cli.MAX_SUBSCRIPTION_BYTES + 1))
        with mock.patch.object(cli.urllib.request, 'build_opener', return_value=opener):
            with self.assertRaisesRegex(ValueError, '8 MiB'):
                cli.fetch_proxies('https://example.test/s/token')
        reply.read.assert_called_once_with(cli.MAX_SUBSCRIPTION_BYTES + 1)
        small = b'{"proxies":[{"name":"node"}]}'
        self.assertEqual(cli.parse_proxies(small + b' ' * (cli.MAX_SUBSCRIPTION_BYTES - len(small))),
                         [{'name': 'node'}])

    def test_subscription_shape_and_names_validated(self):
        for config in ([], {}, {'proxies': []}, {'proxies': ['node']},
                       {'proxies': [{'name': 'node'}, {'name': 'node'}]}, {'proxies': [{'name': ' '}]}):
            with self.subTest(config=config), self.assertRaises(ValueError):
                cli.parse_proxies(json.dumps(config).encode())

    def test_redirect_cannot_downgrade_or_cross_origin(self):
        request = urllib.request.Request('https://example.test/s/token')
        handler = cli._SubscriptionRedirect(('https', 'example.test', 443), False)
        for target in ('http://example.test/s/token', 'https://evil.test/s/token', 'https://example.test:444/s/token'):
            with self.subTest(target=target), self.assertRaises(ValueError):
                handler.redirect_request(request, None, 302, '', {}, target)
        result = handler.redirect_request(request, None, 302, '', {}, 'https://example.test/next')
        self.assertEqual(result.full_url, 'https://example.test/next')

    def test_local_config_benchmark_still_runs_without_fetching(self):
        with tempfile.TemporaryDirectory() as directory:
            config, binary = Path(directory) / 'subscription.json', Path(directory) / 'mihomo'
            config.write_text('{"proxies":[{"name":"node","type":"tuic"}]}', encoding='utf-8')
            binary.touch()
            argv = ['bench.py', '--config', str(config), '--mihomo', str(binary), '--no-direct', '--quick']
            with mock.patch.object(sys, 'argv', argv), mock.patch.object(cli, 'fetch_proxies') as fetch, \
                    mock.patch.object(cli, 'free_port', return_value=23456), \
                    mock.patch.object(cli, 'wait_port', return_value=True), \
                    mock.patch.object(cli.subprocess, 'Popen') as popen, \
                    mock.patch.object(cli.bench, 'run', return_value={'latency': {'median': 1}, 'down_1': 1, 'down_4': 1, 'up_1': 1}) as run, \
                    mock.patch.object(cli.bench, 'table', return_value='results'), mock.patch('builtins.print'):
                cli.main()
            fetch.assert_not_called()
            run.assert_called_once_with('http://127.0.0.1:23456', True, origin=None)
            popen.return_value.terminate.assert_called_once()
            popen.return_value.wait.assert_called_once_with(5)


    def test_failed_measurement_preserves_json_and_returns_nonzero(self):
        with tempfile.TemporaryDirectory() as directory:
            config, binary, output = (Path(directory) / name for name in ('subscription.json', 'mihomo', 'result.json'))
            config.write_text('{"proxies":[{"name":"node","type":"tuic"}]}', encoding='utf-8')
            binary.touch()
            failed = {'latency': {'median': 1}, 'down_1': 0, 'down_4': 0, 'up_1': 1}
            argv = ['bench.py', '--config', str(config), '--mihomo', str(binary), '--no-direct', '--json', str(output)]
            with mock.patch.object(sys, 'argv', argv), mock.patch.object(cli, 'free_port', return_value=23456), \
                    mock.patch.object(cli, 'wait_port', return_value=True), \
                    mock.patch.object(cli.subprocess, 'Popen'), \
                    mock.patch.object(cli.bench, 'run', return_value=failed), \
                    mock.patch.object(cli.bench, 'table', return_value='results'), mock.patch('builtins.print'):
                with self.assertRaises(SystemExit) as raised:
                    cli.main()
            self.assertEqual(raised.exception.code, 1)
            self.assertEqual(json.loads(output.read_text())['results']['node']['down_1'], 0)

    def test_measurement_origin_is_explicit_and_validated(self):
        self.assertEqual(cli.bench.measurement_urls(), (cli.bench.LATENCY_URL, cli.bench.DOWN_URL, cli.bench.UP_URL))
        self.assertEqual(cli.bench.measurement_urls('http://127.0.0.1:1234/'),
                         ('http://127.0.0.1:1234/generate_204', 'http://127.0.0.1:1234/__down?bytes=%d',
                          'http://127.0.0.1:1234/__up'))
        for origin in ('file:///etc/passwd', 'http://user:pass@example.test', 'http://example.test/path',
                       'http://example.test#fragment', 'http://example.test:0'):
            with self.subTest(origin=origin), self.assertRaises(ValueError):
                cli.bench.measurement_urls(origin)

    def test_explicit_measurement_proxy_cannot_be_bypassed_by_environment(self):
        received = []

        class Proxy(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                received.append(self.path)
                self.send_response(200)
                self.send_header('Content-Length', '7')
                self.end_headers()
                self.wfile.write(b'proxied')

            def log_message(self, *args):
                pass

        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Proxy)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        target = 'http://127.0.0.1:9/measurement'
        try:
            with mock.patch.dict(os.environ, {'NO_PROXY': '*', 'no_proxy': '*'}):
                opener = cli.bench._opener('http://127.0.0.1:%d' % server.server_address[1])
                with opener.open(target, timeout=5) as response:
                    self.assertEqual(response.read(), b'proxied')
            self.assertEqual(received, [target])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


class BenchmarkPrivateCA(tu.Base):
    def test_self_signed_rejected_by_default_but_explicit_ca_works(self):
        certs.ensure_self_signed('127.0.0.1')
        cert, key = paths.SELF_CRT, paths.SELF_KEY
        payload = b'{"proxies":[{"name":"node","type":"tuic"}]}'

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header('Content-Length', str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *args):
                pass

        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        url = 'https://127.0.0.1:%d/s/token' % server.server_address[1]
        try:
            with mock.patch.object(cli.urllib.request, 'getproxies', return_value={}):
                with self.assertRaises((OSError, urllib.error.URLError)):
                    cli.fetch_proxies(url)
                self.assertEqual(cli.fetch_proxies(url, ca_file=cert)[0]['name'], 'node')
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


class BenchmarkDiagnostics(unittest.TestCase):
    def test_http_throttle_is_reported_instead_of_an_unexplained_zero(self):
        error = urllib.error.HTTPError('https://speed.cloudflare.com/__down', 429, 'Too Many Requests',
                                       {'Retry-After': '60'}, io.BytesIO(b''))
        opener = mock.Mock()
        opener.open.side_effect = error
        diagnostic = {}
        with mock.patch.object(cli.bench, '_opener', return_value=opener), \
                mock.patch.object(cli.bench.time, 'perf_counter', return_value=0):
            self.assertEqual(cli.bench.download(streams=1, seconds=0.01, diagnostics=diagnostic), 0)
        self.assertEqual(diagnostic['bytes'], 0)
        self.assertFalse(diagnostic['warmup_complete'])
        self.assertIn('429', diagnostic['errors'][0])
        self.assertIn('Retry-After=60', diagnostic['errors'][0])

    def test_incomplete_http_body_is_a_reported_worker_failure(self):
        opener = mock.Mock()
        reply = mock.MagicMock()
        reply.__enter__.return_value = reply
        reply.read1.side_effect = http.client.IncompleteRead(b'partial', 100)
        opener.open.return_value = reply
        diagnostic = {}
        with mock.patch.object(cli.bench, '_opener', return_value=opener), \
                mock.patch.object(cli.bench.time, 'perf_counter', return_value=0):
            self.assertEqual(cli.bench.download(streams=1, seconds=0.01, diagnostics=diagnostic), 0)
        self.assertIn('IncompleteRead', diagnostic['errors'][0])


class E2EHarness(unittest.TestCase):
    def runner(self, main, results):
        cleanup = mock.Mock()
        delete = mock.Mock()
        run = e2e_function('run', main=main, results=results, procs=[], ROOT='test-logs',
                           db=types.SimpleNamespace(close=cleanup),
                           shutil=types.SimpleNamespace(rmtree=delete), print=mock.Mock())
        return run, cleanup, delete

    def test_failed_check_accepts_structured_diagnostics(self):
        results = []
        output = mock.Mock()
        check = e2e_function('check', results=results, print=output)
        check('benchmark', False, ['stdout line', 'stderr line'])
        self.assertEqual(len(results), 1)
        self.assertFalse(results[0][1])
        self.assertIn('stderr line', output.call_args.args[0])

    def test_unhandled_error_propagates_and_preserves_logs(self):
        run, cleanup, delete = self.runner(mock.Mock(side_effect=RuntimeError('unexpected core failure')), [])
        with self.assertRaisesRegex(RuntimeError, 'unexpected core failure'):
            run()
        cleanup.assert_called_once()
        delete.assert_not_called()

    def test_recorded_failure_returns_nonzero_and_preserves_logs(self):
        run, cleanup, delete = self.runner(mock.Mock(), [('denied', False, '')])
        self.assertEqual(run(), 1)
        cleanup.assert_called_once()
        delete.assert_not_called()

    def test_success_returns_zero_after_cleanup(self):
        run, cleanup, delete = self.runner(mock.Mock(), [('connected', True, '')])
        self.assertEqual(run(), 0)
        cleanup.assert_called_once()
        delete.assert_called_once_with('test-logs', ignore_errors=True)

    def test_private_probe_detects_forwarding_despite_no_proxy(self):
        requests = []
        forward = [False]

        class Proxy(http.server.BaseHTTPRequestHandler):
            def do_CONNECT(self):
                requests.append('CONNECT ' + self.path)
                if not forward[0]:
                    self.send_error(403)
                    return
                host, port = self.path.rsplit(':', 1)
                with socket.create_connection((host, int(port)), timeout=5) as upstream:
                    self.send_response(200)
                    self.end_headers()
                    self.close_connection = True
                    while True:
                        ready, _, _ = select.select([self.connection, upstream], [], [], 5)
                        if not ready:
                            return
                        for peer in ready:
                            data = peer.recv(65536)
                            if not data:
                                return
                            (upstream if peer is self.connection else self.connection).sendall(data)

            def do_GET(self):
                requests.append(self.path)
                if not forward[0]:
                    self.send_response(403)
                    self.send_header('Content-Length', '0')
                    self.end_headers()
                    return
                target = urllib.parse.urlsplit(self.path)
                connection = http.client.HTTPConnection(target.hostname, target.port, timeout=5)
                try:
                    connection.request('GET', target.path)
                    response = connection.getresponse()
                    body = response.read()
                    self.send_response(response.status)
                    self.send_header('Content-Length', str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                finally:
                    connection.close()

            def log_message(self, *args):
                pass

        proxy = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Proxy)
        thread = threading.Thread(target=proxy.serve_forever, daemon=True)
        thread.start()
        results = []
        probe = e2e_function('check_private_targets', check=lambda name, ok, detail: results.append(ok))
        client = mock.Mock()
        client.poll.return_value = None
        try:
            with mock.patch.dict(os.environ, {'NO_PROXY': '*', 'no_proxy': '*'}):
                probe(proxy.server_address[1], client, 'rejecting proxy')
                self.assertEqual(results, [True] * 4)
                results.clear()
                forward[0] = True
                probe(proxy.server_address[1], client, 'forwarding proxy')
                self.assertEqual(results, [False] * 4)
            self.assertEqual(len(requests), 8)
            self.assertTrue(all(url.startswith(('http://127.0.0.1:', 'http://localhost:',
                                                'CONNECT 127.0.0.1:', 'CONNECT localhost:'))
                                for url in requests))
        finally:
            proxy.shutdown()
            proxy.server_close()
            thread.join(timeout=5)


if __name__ == '__main__':
    unittest.main()
