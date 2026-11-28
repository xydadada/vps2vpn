"""0.2.53 security review: python -m unittest tests.test_security_053 -v

- slow requests: a client sending its request line and headers a byte at a time (each gap shorter than the per-read
  timeout) no longer keeps a worker for ever; the headers must arrive within HEADER_SECONDS of their first byte, a
  body within BODY_SECONDS plus its length at BODY_MIN_RATE. An idle keep-alive connection still waits REQUEST_IDLE.
- header bloat: more than HEADER_MAX bytes of request line and headers is answered 431 and closed (it used to read
  ~6 MB of headers into memory per connection first).
"""
import json
import socket
import ssl
import time
import unittest
from unittest import mock

from tests import test_unit as tu
from vps2vpn import web


class _Web(tu.Web):
    """tu.Web's server and helpers without its own tests (they already run in test_unit)."""


for _name in [n for n in dir(tu.Web) if n.startswith('test')]:
    setattr(_Web, _name, None)


class _Quick(_Web):
    """Short limits so a slow client is cut off within seconds."""
    limits = {'REQUEST_IDLE': 1.5, 'HEADER_SECONDS': 1.5, 'BODY_SECONDS': 1.0}

    def setUp(self):
        super().setUp()
        for k, v in self.limits.items():
            p = mock.patch.object(web, k, v)
            p.start()
            self.addCleanup(p.stop)

    def connect(self, tls):
        s = socket.create_connection(('127.0.0.1', self.port), timeout=10)
        if tls:
            s = ssl._create_unverified_context().wrap_socket(s)
        return s

    def drip(self, s, data, gap=0.3, give_up=8.0):
        """Send `data` a byte at a time. Returns seconds until the server closed, or None if it never did."""
        t0 = time.monotonic()
        s.settimeout(0.05)
        for ch in data:
            try:
                s.send(bytes([ch]))
                if s.recv(100) == b'':
                    return time.monotonic() - t0
            except (socket.timeout, ssl.SSLWantReadError):
                pass
            except OSError:
                return time.monotonic() - t0
            time.sleep(gap)
            if time.monotonic() - t0 > give_up:
                return None
        return None


class SlowHeaders(_Quick):
    REQ = b'GET /rules/abc.list HTTP/1.1\r\nHost: x\r\nX-Pad: ' + b'a' * 200

    def test_plain_http_dribble_is_cut_off(self):
        s = self.connect(False)
        try:
            took = self.drip(s, self.REQ)
        finally:
            s.close()
        self.assertIsNotNone(took, 'a client sending a byte every 0.3 s kept the connection for 8 s')
        self.assertLess(took, 4)

    def test_tls_dribble_is_cut_off(self):
        s = self.connect(True)
        try:
            took = self.drip(s, self.REQ)
        finally:
            s.close()
        self.assertIsNotNone(took)
        self.assertLess(took, 4)

    def test_idle_keep_alive_then_a_normal_request(self):
        # waiting for the next request does not start the header clock: it starts with the first byte
        s = self.connect(True)
        try:
            f = s.makefile('rb')
            for _ in range(2):
                s.sendall(b'GET /nothing HTTP/1.1\r\nHost: x\r\n\r\n')
                self.assertIn(b' 404 ', f.readline())
                length = 0
                while True:
                    line = f.readline()
                    if line.lower().startswith(b'content-length:'):
                        length = int(line.split(b':')[1])
                    if line in (b'\r\n', b''):
                        break
                f.read(length)
                time.sleep(1.0)        # idle below REQUEST_IDLE, but together the two waits exceed HEADER_SECONDS
        finally:
            s.close()

    def test_idle_connection_still_times_out(self):
        s = self.connect(False)
        try:
            s.settimeout(5)
            t0 = time.monotonic()
            s.send(b'G')               # the first byte: from now on HEADER_SECONDS
            self.assertEqual(s.recv(10), b'')
            self.assertLess(time.monotonic() - t0, 3)
        finally:
            s.close()


class SlowHeaderBytes(_Web):
    def send_raw(self, data):
        s = socket.create_connection(('127.0.0.1', self.port), timeout=10)
        try:
            try:
                s.sendall(data)
            except OSError:
                pass                   # the server may close before reading everything
            try:
                return s.recv(200)
            except (ConnectionResetError, ConnectionAbortedError):
                return b''             # Windows: the early close resets the connection before the 431 is read
        finally:
            s.close()

    def test_too_many_header_bytes_431(self):
        big = b'GET /nothing HTTP/1.1\r\nHost: x\r\n' + b''.join(
            b'X-%d: %s\r\n' % (i, b'a' * 60000) for i in range(90)) + b'\r\n'
        r = self.send_raw(big)
        self.assertTrue(r == b'' or r.startswith(b'HTTP/1.1 431 '), r)

    def test_long_request_line_431(self):
        self.assertTrue(self.send_raw(b'GET /' + b'a' * 40000 + b' HTTP/1.1\r\n\r\n').startswith(b'HTTP/1.1 431 '))

    def test_normal_headers_pass(self):
        data = b'GET /nothing HTTP/1.1\r\nHost: x\r\nCookie: ' + b'c' * 16000 + b'\r\n\r\n'
        self.assertIn(b' 404 ', self.send_raw(data).split(b'\r\n')[0])

    def test_keep_alive_requests_each_get_a_budget(self):
        one = b'GET /nothing HTTP/1.1\r\nHost: x\r\nX-Pad: ' + b'p' * 20000 + b'\r\n\r\n'
        s = socket.create_connection(('127.0.0.1', self.port), timeout=10)
        try:
            f = s.makefile('rb')
            for _ in range(3):         # 60 KB in all, 20 KB per request
                s.sendall(one)
                self.assertIn(b' 404 ', f.readline())
                length = 0
                while True:
                    line = f.readline()
                    if line.lower().startswith(b'content-length:'):
                        length = int(line.split(b':')[1])
                    if line in (b'\r\n', b''):
                        break
                f.read(length)
        finally:
            s.close()


class SlowBody(_Quick):
    def test_dribbled_body_is_cut_off(self):
        with mock.patch.object(web, 'BODY_MIN_RATE', 1 << 30):     # the deadline is about BODY_SECONDS
            s = self.connect(True)
            try:
                s.sendall(b'POST %s/api/login HTTP/1.1\r\nHost: x\r\nX-V2V: 1\r\nContent-Type: application/json\r\n'
                          b'Content-Length: 400\r\n\r\n' % self.pp.encode())
                took = self.drip(s, b'{"username": "admin", "password": "' + b'x' * 300 + b'"}', gap=0.2)
            finally:
                s.close()
        self.assertIsNotNone(took)
        self.assertLess(took, 3)

    def test_body_time_grows_with_its_length(self):
        r = web._DeadlineReader(None)
        now = time.monotonic()
        r.body(32 << 20)            # a restore
        self.assertGreaterEqual(r.deadline - now, web.BODY_SECONDS + (32 << 20) / web.BODY_MIN_RATE - 1)
        self.assertGreater(r.deadline - now, 2000)     # at the real BODY_MIN_RATE: over half an hour
        self.assertIsNone(r.budget)

    def test_large_body_at_normal_speed(self):
        # 2 MB arrives well within the limits: the endpoint answers (bad password), not a cut connection
        tu_db = tu.db
        tu_db.set_settings(setup_done=True)
        body = {'username': 'admin', 'password': 'x', 'pad': 'p' * (2 << 20)}
        st, data, _ = self.req('POST', self.pp + '/api/login', body)
        self.assertEqual(st, 403, data)
        self.assertEqual(json.loads(data)['error'], 'wrong username or password')


if __name__ == '__main__':
    unittest.main()
