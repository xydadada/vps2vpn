"""Deployment input, trust persistence and concurrent record regressions."""
import concurrent.futures
import http.client
import json
import os
import tempfile
import threading
import unittest
from unittest import mock

from tests.test_deploy import deploy


class DeployBoundary(unittest.TestCase):
    def test_rejects_ssh_option_and_invalid_port(self):
        for host, user, port in [
            ('-oProxyCommand=oops', 'root', '22'), ('host..invalid', 'root', '22'),
            ('example.com', '-root', '22'), ('example.com', 'root', '0'),
            ('example.com', 'root', '65536'), ('example.com', 'root', '9999999999999999'),
        ]:
            with self.subTest(host=host, user=user, port=port):
                job, error = deploy.new_job(host, user, port)
                self.assertIsNone(job)
                self.assertTrue(error)
        for host in ('::1', '[2001:db8::1]', '203.0.113.9', 'example.com'):
            job, error = deploy.new_job(host, 'root', '22')
            self.assertFalse(error)
            self.assertEqual(job['port'], 22)

    def test_panel_url_rejected_before_any_connection(self):
        with mock.patch.object(deploy.http.client, 'HTTPSConnection') as connection:
            for url in ('http://example.com/p/', 'ftp://example.com/p/', 'https://u:p@example.com/p/'):
                with self.assertRaises(deploy.PanelError):
                    deploy.panel_call({'panel': url}, 'login', {'password': 'secret'})
            connection.assert_not_called()

    def test_known_hosts_survives_work_directory_changes(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(deploy, 'RECORDS', directory):
            job = {'host': '203.0.113.1', 'port': 22, 'user': 'root', 'key': 'key'}
            with mock.patch.object(deploy, 'WORK', os.path.join(directory, 'work-one')):
                first, _ = deploy.ssh_base(job)
            kh = os.path.join(directory, 'known_hosts')
            with open(kh, 'w') as f:
                f.write('saved-key\n')
            with mock.patch.object(deploy, 'WORK', os.path.join(directory, 'work-two')):
                second, _ = deploy.ssh_base(job)
            self.assertIn('UserKnownHostsFile=' + kh, first)
            self.assertIn('UserKnownHostsFile=' + kh, second)
            with open(kh) as f:
                self.assertEqual(f.read(), 'saved-key\n')

    def test_concurrent_record_writers_leave_one_complete_record(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(deploy, 'RECORDS', directory):
            def save(i):
                deploy.save_record('example.com', {'writer': i, 'value': str(i) * 10000})
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                list(pool.map(save, range(24)))
            row = deploy.load_record('example.com')
            self.assertEqual(row['value'], str(row['writer']) * 10000)
            self.assertEqual(os.listdir(directory), ['example.com.json'])

    def test_local_deployer_bounds_json_and_does_not_start_invalid_jobs(self):
        server = deploy.http.server.ThreadingHTTPServer(('127.0.0.1', 0), deploy.H)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            with mock.patch.object(deploy, 'run_job') as run:
                for body in ('[]', '{broken', 'x' * 65537):
                    c = http.client.HTTPConnection('127.0.0.1', server.server_port, timeout=3)
                    c.request('POST', '/start?t=' + deploy.TOKEN, body)
                    response = c.getresponse()
                    response.read()
                    self.assertEqual(response.status, 400)
                    self.assertEqual(response.getheader('Referrer-Policy'), 'no-referrer')
                    c.close()
                run.assert_not_called()
        finally:
            server.shutdown()
            server.server_close()


if __name__ == '__main__':
    unittest.main()
