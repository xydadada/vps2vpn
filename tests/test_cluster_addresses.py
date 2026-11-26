"""Cluster endpoints must be public unicast addresses, including on older Python."""
import ipaddress
import socket
import unittest
from unittest import mock

from tests import test_unit as tu  # configures the isolated development root
from vps2vpn import cluster


class PublicNodeAddresses(unittest.TestCase):
    def test_multicast_and_non_global_special_ranges_are_refused(self):
        for address in (
            '224.0.0.1', '239.255.255.250', 'ff02::1', 'ff0e::1',
            '::ffff:224.0.0.1', '64:ff9b::e000:1', '2002:e000:1::1',
            '64:ff9b:1::1', '100::1', '100:0:0:1::1',
            '3fff::1', '3fff:fff:ffff:ffff:ffff:ffff:ffff:ffff', '5f00::1',
        ):
            with self.subTest(address=address):
                self.assertFalse(cluster._public_ip(ipaddress.ip_address(address)))

    def test_dns_answer_is_refused_before_any_endpoint_is_returned(self):
        for address in ('ff02::1', '5f00::1', '100:0:0:1::1'):
            answer = [(socket.AF_INET6, socket.SOCK_STREAM, 6, '', (address, 443, 0, 0))]
            with self.subTest(address=address), mock.patch.object(
                    cluster.socket, 'getaddrinfo', return_value=answer):
                with self.assertRaisesRegex(cluster.SyncError, 'non-public'):
                    cluster._resolve_public_node_targets('node.example', 443)


if __name__ == '__main__':
    unittest.main()
