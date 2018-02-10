import asyncio
import hashlib
import logging
import struct

from aioice import stun
from aioice.utils import random_string

logger = logging.getLogger('turn')


class TurnServerProtocol(asyncio.DatagramProtocol):
    def __init__(self, realm, users={}):
        self.realm = realm
        self.users = users

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        # demultiplex channel data
        if len(data) >= 4 and (data[0]) & 0xc0 == 0x40:
            channel, length = struct.unpack('!HH', data[0:4])
            assert len(data) >= length + 4

            # echo test
            if data[4:] == b'ping':
                response = b'pong'
                self.transport.sendto(struct.pack('!HH', channel, len(response)) + response, addr)

            # send back some junk too
            self.transport.sendto(b'\x00\x00', addr)
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
            response.attributes['REALM'] = self.realm
            self.transport.sendto(bytes(response), addr)
            return

        # check credentials
        username = message.attributes['USERNAME']
        password = self.users[username]
        integrity_key = hashlib.md5(
            ':'.join([username, self.realm, password]).encode('utf8')).digest()
        try:
            stun.parse_message(data, integrity_key=integrity_key)
        except ValueError:
            return

        if message.message_method == stun.Method.ALLOCATE:
            response = stun.Message(
                message_method=message.message_method,
                message_class=stun.Class.RESPONSE,
                transaction_id=message.transaction_id)
            response.attributes['LIFETIME'] = message.attributes['LIFETIME']
            response.attributes['XOR-MAPPED-ADDRESS'] = addr
            response.attributes['XOR-RELAYED-ADDRESS'] = ('1.2.3.4', 1234)
            response.add_message_integrity(integrity_key)
            response.add_fingerprint()
            self.transport.sendto(bytes(response), addr)
        elif message.message_method == stun.Method.REFRESH:
            response = stun.Message(
                message_method=message.message_method,
                message_class=stun.Class.RESPONSE,
                transaction_id=message.transaction_id)
            response.attributes['LIFETIME'] = message.attributes['LIFETIME']
            response.add_message_integrity(integrity_key)
            response.add_fingerprint()
            self.transport.sendto(bytes(response), addr)
        elif message.message_method == stun.Method.CHANNEL_BIND:
            response = stun.Message(
                message_method=message.message_method,
                message_class=stun.Class.RESPONSE,
                transaction_id=message.transaction_id)
            response.add_message_integrity(integrity_key)
            response.add_fingerprint()
            self.transport.sendto(bytes(response), addr)
