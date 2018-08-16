import asyncio
import unittest

from aioice import turn

from .turnserver import TurnServer
from .utils import run


class DummyClientProtocol(asyncio.DatagramProtocol):
    received_addr = None
    received_data = None

    def connection_made(self, transport):
        transport.sendto(b'ping', ('8.8.8.8', 53))

    def datagram_received(self, data, addr):
        self.received_data = data
        self.received_addr = addr


class TurnClientTcpProtocolTest(unittest.TestCase):
    def test_repr(self):
        protocol = turn.TurnClientTcpProtocol(('1.2.3.4', 1234), 'foo', 'bar', 600)
        self.assertEqual(repr(protocol), 'turn/tcp')


class TurnClientUdpProtocolTest(unittest.TestCase):
    def test_repr(self):
        protocol = turn.TurnClientUdpProtocol(('1.2.3.4', 1234), 'foo', 'bar', 600)
        self.assertEqual(repr(protocol), 'turn/udp')


class TurnTest(unittest.TestCase):
    def setUp(self):
        self.server = TurnServer(realm='test', users={'foo': 'bar'})
        run(self.server.listen())

    def tearDown(self):
        run(self.server.close())

    def test_tcp_transport(self):
        self._test_transport('tcp', self.server.tcp_addr)

    def test_udp_transport(self):
        self._test_transport('udp', self.server.udp_addr)

    def _test_transport(self, transport, server_addr):
        transport, protocol = run(turn.create_turn_endpoint(
            DummyClientProtocol,
            server_addr=server_addr,
            username='foo',
            password='bar',
            lifetime=6,
            transport=transport))
        self.assertEqual(transport.get_extra_info('peername'), None)
        self.assertEqual(transport.get_extra_info('sockname'), ('1.2.3.4', 1234))
        run(asyncio.sleep(10))
        self.assertEqual(protocol.received_addr, ('8.8.8.8', 53))
        self.assertEqual(protocol.received_data, b'pong')
        transport.close()
