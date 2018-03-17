import asyncio
import binascii
import enum
import hmac
import ipaddress
from collections import OrderedDict
from struct import pack, unpack

from . import exceptions
from .utils import random_transaction_id

COOKIE = 0x2112a442
FINGERPRINT_LENGTH = 8
FINGERPRINT_XOR = 0x5354554e
HEADER_LENGTH = 20
INTEGRITY_LENGTH = 24
IPV4_PROTOCOL = 1
IPV6_PROTOCOL = 2

RETRY_MAX = 6
RETRY_RTO = 0.5


def set_body_length(data, length):
    return data[0:2] + pack('!H', length) + data[4:]


def message_fingerprint(data):
    check_data = set_body_length(data, len(data) - HEADER_LENGTH + FINGERPRINT_LENGTH)
    return binascii.crc32(check_data) ^ FINGERPRINT_XOR


def message_integrity(data, key):
    check_data = set_body_length(data, len(data) - HEADER_LENGTH + INTEGRITY_LENGTH)
    return hmac.new(key, check_data, 'sha1').digest()


def xor_address(data, transaction_id):
    xpad = pack('!HI', COOKIE >> 16, COOKIE) + transaction_id
    xdata = data[0:2]
    for i in range(2, len(data)):
        xdata += int.to_bytes(data[i] ^ xpad[i - 2], 1, 'big', signed=False)
    return xdata


def pack_address(value, **kwargs):
    ip_address = ipaddress.ip_address(value[0])
    if isinstance(ip_address, ipaddress.IPv4Address):
        protocol = IPV4_PROTOCOL
    else:
        protocol = IPV6_PROTOCOL
    return pack('!BBH', 0, protocol, value[1]) + ip_address.packed


def pack_bytes(value):
    return value


def pack_error_code(value):
    return pack('!HBB', 0, value[0] // 100, value[0] % 100) + value[1].encode('utf8')


def pack_none(value):
    return b''


def pack_string(value):
    return value.encode('utf8')


def pack_unsigned(value):
    return pack('!I', value)


def pack_unsigned_short(value):
    return pack('!H', value) + b'\x00\x00'


def pack_unsigned_64(value):
    return pack('!Q', value)


def pack_xor_address(value, transaction_id):
    return xor_address(pack_address(value), transaction_id)


def unpack_address(data):
    if len(data) < 4:
        raise ValueError('STUN address length is less than 4 bytes')
    reserved, protocol, port = unpack('!BBH', data[0:4])
    address = data[4:]
    if protocol == IPV4_PROTOCOL:
        if len(address) != 4:
            raise ValueError('STUN address has invalid length for IPv4')
        return (str(ipaddress.IPv4Address(address)), port)
    elif protocol == IPV6_PROTOCOL:
        if len(address) != 16:
            raise ValueError('STUN address has invalid length for IPv6')
        return (str(ipaddress.IPv6Address(address)), port)
    else:
        raise ValueError('STUN address has unknown protocol')


def unpack_xor_address(data, transaction_id):
    return unpack_address(xor_address(data, transaction_id))


def unpack_bytes(data):
    return data


def unpack_error_code(data):
    if len(data) < 4:
        raise ValueError('STUN error code is less than 4 bytes')
    reserved, code_high, code_low = unpack('!HBB', data[0:4])
    reason = data[4:].decode('utf8')
    return (code_high * 100 + code_low, reason)


def unpack_none(data):
    return None


def unpack_string(data):
    return data.decode('utf8')


def unpack_unsigned(data):
    return unpack('!I', data)[0]


def unpack_unsigned_short(data):
    return unpack('!H', data[0:2])[0]


def unpack_unsigned_64(data):
    return unpack('!Q', data)[0]


ATTRIBUTES = [
    (0x0001, 'MAPPED-ADDRESS', pack_address, unpack_address),
    (0x0003, 'CHANGE-REQUEST', pack_unsigned, unpack_unsigned),
    (0x0004, 'SOURCE-ADDRESS', pack_address, unpack_address),
    (0x0005, 'CHANGED-ADDRESS', pack_address, unpack_address),
    (0x0006, 'USERNAME', pack_string, unpack_string),
    (0x0008, 'MESSAGE-INTEGRITY', pack_bytes, unpack_bytes),
    (0x0009, 'ERROR-CODE', pack_error_code, unpack_error_code),
    (0x000c, 'CHANNEL-NUMBER', pack_unsigned_short, unpack_unsigned_short),
    (0x000d, 'LIFETIME', pack_unsigned, unpack_unsigned),
    (0x0012, 'XOR-PEER-ADDRESS', pack_xor_address, unpack_xor_address),
    (0x0014, 'REALM', pack_string, unpack_string),
    (0x0015, 'NONCE', pack_bytes, unpack_bytes),
    (0x0016, 'XOR-RELAYED-ADDRESS', pack_xor_address, unpack_xor_address),
    (0x0019, 'REQUESTED-TRANSPORT', pack_unsigned, unpack_unsigned),
    (0x0020, 'XOR-MAPPED-ADDRESS', pack_xor_address, unpack_xor_address),
    (0x0024, 'PRIORITY', pack_unsigned, unpack_unsigned),
    (0x0025, 'USE-CANDIDATE', pack_none, unpack_none),
    (0x8022, 'SOFTWARE', pack_string, unpack_string),
    (0x8028, 'FINGERPRINT', pack_unsigned, unpack_unsigned),
    (0x8029, 'ICE-CONTROLLED', pack_unsigned_64, unpack_unsigned_64),
    (0x802a, 'ICE-CONTROLLING', pack_unsigned_64, unpack_unsigned_64),
    (0x802b, 'RESPONSE-ORIGIN', pack_address, unpack_address),
    (0x802c, 'OTHER-ADDRESS', pack_address, unpack_address),
]

ATTRIBUTES_BY_TYPE = {}
ATTRIBUTES_BY_NAME = {}
for attr in ATTRIBUTES:
    ATTRIBUTES_BY_TYPE[attr[0]] = attr
    ATTRIBUTES_BY_NAME[attr[1]] = attr


class Class(enum.IntEnum):
    REQUEST = 0x000
    INDICATION = 0x010
    RESPONSE = 0x100
    ERROR = 0x110


class Method(enum.IntEnum):
    BINDING = 0x1
    SHARED_SECRET = 0x2
    ALLOCATE = 0x3
    REFRESH = 0x4
    SEND = 0x6
    DATA = 0x7
    CREATE_PERMISSION = 0x8
    CHANNEL_BIND = 0x9


class Message(object):
    def __init__(self, message_method, message_class, transaction_id=None,
                 attributes=None):
        self.message_method = Method(message_method)
        self.message_class = Class(message_class)
        self.transaction_id = transaction_id or random_transaction_id()
        self.attributes = attributes or OrderedDict()

    def add_fingerprint(self):
        self.attributes['FINGERPRINT'] = message_fingerprint(bytes(self))

    def add_message_integrity(self, key):
        self.attributes['MESSAGE-INTEGRITY'] = message_integrity(bytes(self), key)

    def __bytes__(self):
        data = b''
        for attr_name, attr_value in self.attributes.items():
            attr_type, _, attr_pack, attr_unpack = ATTRIBUTES_BY_NAME[attr_name]
            if attr_pack == pack_xor_address:
                v = attr_pack(attr_value, self.transaction_id)
            else:
                v = attr_pack(attr_value)

            attr_len = len(v)
            pad_len = 4 * ((attr_len + 3) // 4) - attr_len
            data += pack('!HH', attr_type, attr_len) + v + (b'\x00' * pad_len)
        return pack('!HHI12s',
                    self.message_method | self.message_class,
                    len(data), COOKIE, self.transaction_id) + data

    def __repr__(self):
        return 'Message(message_method=%s, message_class=%s, transaction_id=%s)' % (
            self.message_method,
            self.message_class,
            self.transaction_id,
        )


class Transaction:
    def __init__(self, request, addr, protocol, retransmissions=None):
        self.__addr = addr
        self.__future = asyncio.Future()
        self.__request = request
        self.__timeout_delay = RETRY_RTO
        self.__timeout_handle = None
        self.__protocol = protocol
        self.__tries = 0
        self.__tries_max = 1 + (retransmissions if retransmissions is not None else RETRY_MAX)

    def response_received(self, message, addr):
        if not self.__future.done():
            if message.message_class == Class.RESPONSE:
                self.__future.set_result((message, addr))
            else:
                self.__future.set_exception(exceptions.TransactionFailed(message))

    async def run(self):
        try:
            self.__retry()
            return await self.__future
        finally:
            if self.__timeout_handle:
                self.__timeout_handle.cancel()

    def __retry(self):
        if self.__tries >= self.__tries_max:
            self.__future.set_exception(exceptions.TransactionTimeout())
            return

        self.__protocol.send_stun(self.__request, self.__addr)

        loop = asyncio.get_event_loop()
        self.__timeout_handle = loop.call_later(self.__timeout_delay, self.__retry)
        self.__timeout_delay *= 2
        self.__tries += 1


def parse_message(data, integrity_key=None):
    """
    Parses a STUN message.

    If the ``integrity_key`` parameter is given, the message's HMAC will be verified.
    """
    if len(data) < HEADER_LENGTH:
        raise ValueError('STUN message length is less than 20 bytes')
    message_type, length, cookie, transaction_id = unpack('!HHI12s', data[0:HEADER_LENGTH])
    if len(data) != HEADER_LENGTH + length:
        raise ValueError('STUN message length does not match')

    attributes = OrderedDict()
    pos = HEADER_LENGTH
    while pos <= len(data) - 4:
        attr_type, attr_len = unpack('!HH', data[pos:pos + 4])
        v = data[pos + 4:pos + 4 + attr_len]
        pad_len = 4 * ((attr_len + 3) // 4) - attr_len
        if attr_type in ATTRIBUTES_BY_TYPE:
            _, attr_name, attr_pack, attr_unpack = ATTRIBUTES_BY_TYPE[attr_type]
            if attr_unpack == unpack_xor_address:
                attributes[attr_name] = attr_unpack(v, transaction_id=transaction_id)
            else:
                attributes[attr_name] = attr_unpack(v)

            if attr_name == 'FINGERPRINT':
                if attributes[attr_name] != message_fingerprint(data[0:pos]):
                    raise ValueError('STUN message fingerprint does not match')
            elif attr_name == 'MESSAGE-INTEGRITY':
                if (integrity_key is not None and
                   attributes[attr_name] != message_integrity(data[0:pos], integrity_key)):
                    raise ValueError('STUN message integrity does not match')

        pos += 4 + attr_len + pad_len
    return Message(
        message_method=message_type & 0x3eef,
        message_class=message_type & 0x0110,
        transaction_id=transaction_id,
        attributes=attributes)
