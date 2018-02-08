import asyncio
import socket
import unittest

from aioice import turn

from .turnserver import TurnServerProtocol


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


class TurnTest(unittest.TestCase):
    def setUp(self):
        loop = asyncio.get_event_loop()
        transport, protocol = run(loop.create_datagram_endpoint(
            lambda: TurnServerProtocol(realm='test', users={'foo': 'bar'}),
            local_addr=('127.0.0.1', 0),
            family=socket.AF_INET))
        self.server = protocol
        self.server_addr = transport.get_extra_info('sockname')

    def tearDown(self):
        self.server.transport.close()

    def test_allocation(self):
        loop = asyncio.get_event_loop()
        transport, protocol = run(loop.create_datagram_endpoint(
            lambda: turn.TurnClientProtocol(self.server_addr, 'foo', 'bar'),
            family=socket.AF_INET))
        run(protocol.connect())
        run(protocol.refresh())
        run(protocol.close())
