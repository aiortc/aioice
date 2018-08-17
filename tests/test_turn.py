import asyncio
import unittest

from aioice import turn

from .turnserver import TurnServer
from .utils import run


class DummyClientProtocol(asyncio.DatagramProtocol):
    received_addr = None
    received_data = None

    def datagram_received(self, data, addr):
        self.received_data = data
        self.received_addr = addr


class DummyServerProtocol(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.address = transport.get_extra_info('sockname')
        self.transport = transport

    def datagram_received(self, data, addr):
        if data == b'ping':
            self.transport.sendto(b'pong', addr)


class TurnClientTcpProtocolTest(unittest.TestCase):
    def test_repr(self):
        protocol = turn.TurnClientTcpProtocol(('1.2.3.4', 1234), 'foo', 'bar', 600)
        self.assertEqual(repr(protocol), 'turn/tcp')


class TurnClientUdpProtocolTest(unittest.TestCase):
    def test_junk(self):
        protocol = turn.TurnClientUdpProtocol(('1.2.3.4', 1234), 'foo', 'bar', 600)
        protocol.datagram_received(b'\x00\x00', ('1.2.3.4', 1234))

    def test_repr(self):
        protocol = turn.TurnClientUdpProtocol(('1.2.3.4', 1234), 'foo', 'bar', 600)
        self.assertEqual(repr(protocol), 'turn/udp')


class TurnTest(unittest.TestCase):
    def setUp(self):
        # start turn server
        self.turn_server = TurnServer(realm='test', users={'foo': 'bar'})
        run(self.turn_server.listen())

        # start ping server
        loop = asyncio.get_event_loop()
        _, self.ping_server = run(loop.create_datagram_endpoint(
            DummyServerProtocol,
            local_addr=('127.0.0.1', 0)))

    def tearDown(self):
        # stop turn server
        run(self.turn_server.close())

        # stop ping server
        self.ping_server.transport.close()

    def test_tcp_transport(self):
        self._test_transport('tcp', self.turn_server.tcp_addr)

    def test_udp_transport(self):
        self._test_transport('udp', self.turn_server.udp_addr)

    def _test_transport(self, transport, server_addr):
        transport, protocol = run(turn.create_turn_endpoint(
            DummyClientProtocol,
            server_addr=server_addr,
            username='foo',
            password='bar',
            lifetime=6,
            transport=transport))
        self.assertIsNone(transport.get_extra_info('peername'))
        self.assertIsNotNone(transport.get_extra_info('sockname'))

        # send ping, expect pong
        transport.sendto(b'ping', self.ping_server.address)
        run(asyncio.sleep(1))
        self.assertEqual(protocol.received_addr, self.ping_server.address)
        self.assertEqual(protocol.received_data, b'pong')

        # wait some more to allow allocation refresh
        run(asyncio.sleep(5))

        # close
        transport.close()
        run(asyncio.sleep(0))
