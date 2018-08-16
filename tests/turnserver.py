import asyncio
import logging
import socket
import struct

from aioice import stun
from aioice.turn import make_integrity_key
from aioice.utils import random_string

logger = logging.getLogger('turn')


class TurnServerMixin:
    def __init__(self, server):
        self.server = server

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        # demultiplex channel data
        if len(data) >= 4 and (data[0] & 0xc0) == 0x40:
            channel, length = struct.unpack('!HH', data[0:4])
            assert len(data) >= length + 4

            # echo test
            if data[4:] == b'ping':
                response = b'pong'
                self._send(struct.pack('!HH', channel, len(response)) + response, addr)

            # send back some junk too
            self._send(b'\x00\x00', addr)
            return

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
            response.attributes['REALM'] = self.server.realm
            self._send(bytes(response), addr)
            return

        # check credentials
        username = message.attributes['USERNAME']
        password = self.server.users[username]
        integrity_key = make_integrity_key(username, self.server.realm, password)
        try:
            stun.parse_message(data, integrity_key=integrity_key)
        except ValueError:
            return

        if message.message_method == stun.Method.ALLOCATE:
            response = self.handle_allocate(message, addr)
        elif message.message_method == stun.Method.REFRESH:
            response = self.handle_refresh(message, addr)
        elif message.message_method == stun.Method.CHANNEL_BIND:
            response = self.handle_channel_bind(message, addr)
        else:
            response = stun.Message(
                message_method=message.message_method,
                message_class=stun.Class.ERROR,
                transaction_id=message.transaction_id)
            response.attributes['ERROR-CODE'] = (400, 'Unsupported STUN request method')

        response.add_message_integrity(integrity_key)
        response.add_fingerprint()
        self._send(bytes(response), addr)

    def handle_allocate(self, message, addr):
        response = stun.Message(
            message_method=message.message_method,
            message_class=stun.Class.RESPONSE,
            transaction_id=message.transaction_id)
        response.attributes['LIFETIME'] = message.attributes['LIFETIME']
        response.attributes['XOR-MAPPED-ADDRESS'] = addr
        response.attributes['XOR-RELAYED-ADDRESS'] = ('1.2.3.4', 1234)
        return response

    def handle_channel_bind(self, message, addr):
        response = stun.Message(
            message_method=message.message_method,
            message_class=stun.Class.RESPONSE,
            transaction_id=message.transaction_id)
        return response

    def handle_refresh(self, message, addr):
        response = stun.Message(
            message_method=message.message_method,
            message_class=stun.Class.RESPONSE,
            transaction_id=message.transaction_id)
        response.attributes['LIFETIME'] = message.attributes['LIFETIME']
        return response


class TurnServerTcpProtocol(TurnServerMixin, asyncio.Protocol):
    def data_received(self, data):
        addr = self.transport.get_extra_info('peername')
        self.datagram_received(data, addr)

    def _send(self, data, addr):
        self.transport.write(data)


class TurnServerUdpProtocol(TurnServerMixin, asyncio.DatagramProtocol):
    def _send(self, data, addr):
        self.transport.sendto(data, addr)


class TurnServer:
    def __init__(self, realm, users):
        self.realm = realm
        self.users = users

    async def close(self):
        self.tcp_server.close()
        self.udp_server.transport.close()
        await self.tcp_server.wait_closed()

    async def listen(self, port=0):
        loop = asyncio.get_event_loop()

        # listen for TCP
        self.tcp_server = await loop.create_server(
            lambda: TurnServerTcpProtocol(server=self),
            host='127.0.0.1',
            port=port)
        self.tcp_addr = self.tcp_server.sockets[0].getsockname()

        # listen for UDP
        transport, self.udp_server = await loop.create_datagram_endpoint(
            lambda: TurnServerUdpProtocol(server=self),
            local_addr=('127.0.0.1', port),
            family=socket.AF_INET)
        self.udp_addr = transport.get_extra_info('sockname')
