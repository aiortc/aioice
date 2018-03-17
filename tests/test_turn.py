import asyncio
import socket
import unittest

from aioice import turn

from .turnserver import TurnServerProtocol
from .utils import run


class DummyClientProtocol(asyncio.DatagramProtocol):
    received_addr = None
    received_data = None

    def connection_made(self, transport):
        transport.sendto(b'ping', ('8.8.8.8', 53))

    def datagram_received(self, data, addr):
        self.received_data = data
        self.received_addr = addr


class TurnTest(unittest.TestCase):
    def setUp(self):
        # create turn server
        loop = asyncio.get_event_loop()
        transport, protocol = run(loop.create_datagram_endpoint(
            lambda: TurnServerProtocol(realm='test', users={'foo': 'bar'}),
            local_addr=('127.0.0.1', 0),
            family=socket.AF_INET))
        self.server = protocol
        self.server_addr = transport.get_extra_info('sockname')

    def tearDown(self):
        self.server.transport.close()

    def test_transport(self):
        transport, protocol = run(turn.create_turn_endpoint(
            DummyClientProtocol,
            server_addr=self.server_addr,
            username='foo',
            password='bar',
            lifetime=6))
        self.assertEqual(transport.get_extra_info('peername'), None)
        self.assertEqual(transport.get_extra_info('sockname'), ('1.2.3.4', 1234))
        run(asyncio.sleep(10))
        self.assertEqual(protocol.received_addr, ('8.8.8.8', 53))
        self.assertEqual(protocol.received_data, b'pong')
        transport.close()
