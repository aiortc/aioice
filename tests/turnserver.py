import asyncio
import logging
import struct
import time

from aioice import stun
from aioice.turn import (UDP_TRANSPORT, TurnStreamMixin, is_channel_data,
                         make_integrity_key)
from aioice.utils import random_string

logger = logging.getLogger('turn')

CHANNEL_RANGE = range(0x4000, 0x7FFF)


class Allocation(asyncio.DatagramProtocol):
    def __init__(self, client_address, client_protocol, expiry, username):
        self.channel_to_peer = {}
        self.peer_to_channel = {}

        self.client_address = client_address
        self.client_protocol = client_protocol
        self.expiry = expiry
        self.username = username

    def connection_made(self, transport):
        self.relayed_address = transport.get_extra_info('sockname')
        self.transport = transport

    def datagram_received(self, data, addr):
        """
        Relay data from peer to client.
        """
        channel = self.peer_to_channel.get(addr)
        if channel:
            self.client_protocol._send(struct.pack('!HH', channel, len(data)) + data,
                                       self.client_address)


class TurnServerMixin:
    def __init__(self, server):
        self.server = server

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        # demultiplex channel data
        if len(data) >= 4 and is_channel_data(data):
            channel, length = struct.unpack('!HH', data[0:4])
            allocation = self.server.allocations.get((self, addr))

            if len(data) >= length + 4 and allocation:
                peer_address = allocation.channel_to_peer.get(channel)
                if peer_address:
                    payload = data[4:4 + length]
                    allocation.transport.sendto(payload, peer_address)

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
            asyncio.ensure_future(self.handle_allocate(message, addr, integrity_key))
            return
        elif message.message_method == stun.Method.REFRESH:
            response = self.handle_refresh(message, addr)
        elif message.message_method == stun.Method.CHANNEL_BIND:
            response = self.handle_channel_bind(message, addr)
        else:
            response = self.error_response(message, 400, 'Unsupported STUN request method')

        response.add_message_integrity(integrity_key)
        response.add_fingerprint()
        self._send(bytes(response), addr)

    async def handle_allocate(self, message, addr, integrity_key):
        key = (self, addr)
        if key in self.server.allocations:
            response = self.error_response(message, 437, 'Allocation already exists')
        elif 'REQUESTED-TRANSPORT' not in message.attributes:
            response = self.error_response(message, 400, 'Missing REQUESTED-TRANSPORT attribute')
        elif message.attributes['REQUESTED-TRANSPORT'] != UDP_TRANSPORT:
            response = self.error_response(message, 442, 'Unsupported transport protocol')
        else:
            lifetime = message.attributes.get('LIFETIME', self.server.default_lifetime)
            lifetime = min(lifetime, self.server.maximum_lifetime)

            # create allocation
            loop = asyncio.get_event_loop()
            _, allocation = await loop.create_datagram_endpoint(
                lambda: Allocation(
                    client_address=addr,
                    client_protocol=self,
                    expiry=time.time() + lifetime,
                    username=message.attributes['USERNAME']),
                local_addr=('127.0.0.1', 0))
            self.server.allocations[key] = allocation

            # build response
            response = stun.Message(
                message_method=message.message_method,
                message_class=stun.Class.RESPONSE,
                transaction_id=message.transaction_id)
            response.attributes['LIFETIME'] = lifetime
            response.attributes['XOR-MAPPED-ADDRESS'] = addr
            response.attributes['XOR-RELAYED-ADDRESS'] = allocation.relayed_address

        # send response
        response.add_message_integrity(integrity_key)
        response.add_fingerprint()
        self._send(bytes(response), addr)

    def handle_channel_bind(self, message, addr):
        try:
            key = (self, addr)
            allocation = self.server.allocations[key]
        except KeyError:
            return self.error_response(message, 437, 'Allocation does not exist')

        if message.attributes['USERNAME'] != allocation.username:
            return self.error_response(message, 441, 'Wrong credentials')

        for attr in ['CHANNEL-NUMBER', 'XOR-PEER-ADDRESS']:
            if attr not in message.attributes:
                return self.error_response(message, 400, 'Missing %s attribute' % attr)

        channel = message.attributes['CHANNEL-NUMBER']
        peer_address = message.attributes['XOR-PEER-ADDRESS']
        if channel not in CHANNEL_RANGE:
            return self.error_response(message, 400, 'Channel number is outside valid range')

        if allocation.channel_to_peer.get(channel) not in [None, peer_address]:
            return self.error_response(message, 400, 'Channel is already bound to another peer')
        if allocation.peer_to_channel.get(peer_address) not in [None, channel]:
            return self.error_response(message, 400, 'Peer is already bound to another channel')

        # register channel
        allocation.channel_to_peer[channel] = peer_address
        allocation.peer_to_channel[peer_address] = channel

        # build response
        response = stun.Message(
            message_method=message.message_method,
            message_class=stun.Class.RESPONSE,
            transaction_id=message.transaction_id)
        return response

    def handle_refresh(self, message, addr):
        try:
            key = (self, addr)
            allocation = self.server.allocations[key]
        except KeyError:
            return self.error_response(message, 437, 'Allocation does not exist')

        if message.attributes['USERNAME'] != allocation.username:
            return self.error_response(message, 441, 'Wrong credentials')

        if 'LIFETIME' not in message.attributes:
            return self.error_response(message, 400, 'Missing LIFETIME attribute')

        # refresh allocation
        lifetime = min(message.attributes['LIFETIME'], self.server.maximum_lifetime)
        allocation.expiry = time.time() + lifetime

        # build response
        response = stun.Message(
            message_method=message.message_method,
            message_class=stun.Class.RESPONSE,
            transaction_id=message.transaction_id)
        response.attributes['LIFETIME'] = lifetime
        return response

    def error_response(self, request, code, message):
        """
        Build an error response for the given request.
        """
        response = stun.Message(
            message_method=request.message_method,
            message_class=stun.Class.ERROR,
            transaction_id=request.transaction_id)
        response.attributes['ERROR-CODE'] = (code, message)
        return response


class TurnServerTcpProtocol(TurnServerMixin, TurnStreamMixin, asyncio.Protocol):
    def _send(self, data, addr):
        self.transport.write(data)


class TurnServerUdpProtocol(TurnServerMixin, asyncio.DatagramProtocol):
    def _send(self, data, addr):
        self.transport.sendto(data, addr)


class TurnServer:
    def __init__(self, realm, users):
        self.allocations = {}
        self.default_lifetime = 600
        self.maximum_lifetime = 3600
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
        self.tcp_address = self.tcp_server.sockets[0].getsockname()

        # listen for UDP
        transport, self.udp_server = await loop.create_datagram_endpoint(
            lambda: TurnServerUdpProtocol(server=self),
            local_addr=('127.0.0.1', port))
        self.udp_address = transport.get_extra_info('sockname')
