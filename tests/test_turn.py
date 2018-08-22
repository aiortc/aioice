import asyncio
import ssl
import unittest

from aioice import turn

from .echoserver import EchoServer
from .turnserver import TurnServer
from .utils import read_message, run


class DummyClientProtocol(asyncio.DatagramProtocol):
    received_addr = None
    received_data = None

    def datagram_received(self, data, addr):
        self.received_data = data
        self.received_addr = addr


class TurnClientTcpProtocolTest(unittest.TestCase):
    def setUp(self):
        class MockProtocol:
            def get_extra_info(self, name):
                return ('1.2.3.4', 1234)

        self.protocol = turn.TurnClientTcpProtocol(('1.2.3.4', 1234), 'foo', 'bar', 600)
        self.protocol.connection_made(MockProtocol())

    def test_receive_stun_fragmented(self):
        data = read_message('binding_request.bin')
        self.protocol.data_received(data[0:10])
        self.protocol.data_received(data[10:])

    def test_receive_junk(self):
        self.protocol.data_received(b'\x00' * 20)

    def test_repr(self):
        self.assertEqual(repr(self.protocol), 'turn/tcp')


class TurnClientUdpProtocolTest(unittest.TestCase):
    def setUp(self):
        self.protocol = turn.TurnClientUdpProtocol(('1.2.3.4', 1234), 'foo', 'bar', 600)

    def test_receive_junk(self):
        self.protocol.datagram_received(b'\x00' * 20, ('1.2.3.4', 1234))

    def test_repr(self):
        self.assertEqual(repr(self.protocol), 'turn/udp')


class TurnTest(unittest.TestCase):
    def setUp(self):
        # start turn server
        self.turn_server = TurnServer(realm='test', users={'foo': 'bar'})
        run(self.turn_server.listen())

        # start echo server
        self.echo_server = EchoServer()
        run(self.echo_server.listen())

    def tearDown(self):
        # stop turn server
        run(self.turn_server.close())

        # stop echo server
        run(self.echo_server.close())

    def test_tcp_transport(self):
        self._test_transport('tcp', self.turn_server.tcp_address)

    def test_tls_transport(self):
        ssl_context = ssl.SSLContext()
        ssl_context.verify_mode = ssl.CERT_NONE

        self._test_transport('tcp', self.turn_server.tls_address, ssl=ssl_context)

    def test_udp_transport(self):
        self._test_transport('udp', self.turn_server.udp_address)

    def _test_transport(self, transport, server_addr, ssl=False):
        transport, protocol = run(turn.create_turn_endpoint(
            DummyClientProtocol,
            server_addr=server_addr,
            username='foo',
            password='bar',
            lifetime=6,
            ssl=ssl,
            transport=transport))
        self.assertIsNone(transport.get_extra_info('peername'))
        self.assertIsNotNone(transport.get_extra_info('sockname'))

        # send ping, expect pong
        transport.sendto(b'ping', self.echo_server.udp_address)
        run(asyncio.sleep(1))
        self.assertEqual(protocol.received_addr, self.echo_server.udp_address)
        self.assertEqual(protocol.received_data, b'ping')

        # wait some more to allow allocation refresh
        run(asyncio.sleep(5))

        # close
        transport.close()
        run(asyncio.sleep(0))
