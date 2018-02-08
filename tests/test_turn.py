import asyncio
import pprint
import socket
import unittest

from aioice import stun, turn
from aioice.compat import secrets
from aioice.utils import random_string


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


class TurnServerProtocol(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        try:
            message = stun.parse_message(data)
        except ValueError:
            return

        assert message.message_class == stun.Class.REQUEST

        if 'USERNAME' not in message.attributes:
            response = stun.Message(
                message_method=message.message_method,
                message_class=stun.Class.ERROR,
                transaction_id=message.transaction_id)
            response.attributes['ERROR-CODE'] = (401, 'Unauthorized')
            response.attributes['NONCE'] = random_string(16).encode('ascii')
            response.attributes['REALM'] = 'test'
            self.transport.sendto(bytes(response), addr)
            return

        if message.message_method == stun.Method.ALLOCATE:
            response = stun.Message(
                message_method=message.message_method,
                message_class=stun.Class.RESPONSE,
                transaction_id=message.transaction_id)
            response.attributes['LIFETIME'] = message.attributes['LIFETIME']
            response.attributes['XOR-MAPPED-ADDRESS'] = addr
            response.attributes['XOR-RELAYED-ADDRESS'] = ('1.2.3.4', 1234)
            response.add_fingerprint()
            self.transport.sendto(bytes(response), addr)
        elif message.message_method == stun.Method.REFRESH:
            response = stun.Message(
                message_method=message.message_method,
                message_class=stun.Class.RESPONSE,
                transaction_id=message.transaction_id)
            response.attributes['LIFETIME'] = message.attributes['LIFETIME']
            response.add_fingerprint()
            self.transport.sendto(bytes(response), addr)


class TurnTest(unittest.TestCase):
    def setUp(self):
        loop = asyncio.get_event_loop()
        transport, protocol = run(loop.create_datagram_endpoint(
            TurnServerProtocol,
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
