import ipaddress
import os
import unittest
from binascii import unhexlify
from collections import OrderedDict
from ipaddress import IPv4Address, IPv6Address

from aioice import stun


def read_message(name):
    path = os.path.join(os.path.dirname(__file__), 'data', name)
    with open(path, 'rb') as fp:
        return fp.read()


class StunTest(unittest.TestCase):
    def test_unpack_xor_address_ipv4(self):
        transaction_id = unhexlify('b7e7a701bc34d686fa87dfae')
        address, port = stun.unpack_xor_address(
            unhexlify('0001a147e112a643'),
            transaction_id)
        self.assertEqual(address, IPv4Address('192.0.2.1'))
        self.assertEqual(port, 32853)

    def test_unpack_xor_address_ipv6(self):
        transaction_id = unhexlify('b7e7a701bc34d686fa87dfae')
        address, port = stun.unpack_xor_address(
            unhexlify('0002a1470113a9faa5d3f179bc25f4b5bed2b9d9'),
            transaction_id)
        self.assertEqual(address, IPv6Address('2001:db8:1234:5678:11:2233:4455:6677'))
        self.assertEqual(port, 32853)

    def test_pack_xor_address_ipv4(self):
        transaction_id = unhexlify('b7e7a701bc34d686fa87dfae')
        data = stun.pack_xor_address(
            (IPv4Address('192.0.2.1'), 32853),
            transaction_id)
        self.assertEqual(data, unhexlify('0001a147e112a643'))

    def test_pack_xor_ipv6address(self):
        transaction_id = unhexlify('b7e7a701bc34d686fa87dfae')
        data = stun.pack_xor_address(
            (IPv6Address('2001:db8:1234:5678:11:2233:4455:6677'), 32853),
            transaction_id)
        self.assertEqual(data, unhexlify('0002a1470113a9faa5d3f179bc25f4b5bed2b9d9'))

    def test_parse_binding_request(self):
        data = read_message('binding_request.bin')

        message = stun.parse_message(data)
        self.assertEqual(message.message_method, stun.Method.BINDING)
        self.assertEqual(message.message_class, stun.Class.REQUEST)
        self.assertEqual(message.transaction_id, b'Nvfx3lU7FUBF')
        self.assertEqual(message.attributes, OrderedDict())

        self.assertEqual(bytes(message), data)

    def test_parse_binding_request_ice_controlled(self):
        data = read_message('binding_request_ice_controlled.bin')

        message = stun.parse_message(data)
        self.assertEqual(message.message_method, stun.Method.BINDING)
        self.assertEqual(message.message_class, stun.Class.REQUEST)
        self.assertEqual(message.transaction_id, b'wxaNbAdXjwG3')
        self.assertEqual(message.attributes, OrderedDict([
            ('USERNAME', 'AYeZ:sw7YvCSbcVex3bhi'),
            ('PRIORITY', 1685987071),
            ('SOFTWARE', 'FreeSWITCH (-37-987c9b9 64bit)'),
            ('ICE-CONTROLLED', unhexlify('4c374149526d6179')),
            ('MESSAGE-INTEGRITY', unhexlify('1963108a4f764015a66b3fea0b1883dfde1436c8')),
            ('FINGERPRINT', 3230414530),
        ]))

        self.assertEqual(bytes(message), data)

    def test_parse_binding_request_ice_controlling(self):
        data = read_message('binding_request_ice_controlling.bin')

        message = stun.parse_message(data)
        self.assertEqual(message.message_method, stun.Method.BINDING)
        self.assertEqual(message.message_class, stun.Class.REQUEST)
        self.assertEqual(message.transaction_id, b'JEwwUxjLWaa2')
        self.assertEqual(message.attributes, OrderedDict([
            ('USERNAME', 'sw7YvCSbcVex3bhi:AYeZ'),
            ('ICE-CONTROLLING', unhexlify('527ad2e0d9120891')),
            ('USE-CANDIDATE', None),
            ('PRIORITY', 1853759231),
            ('MESSAGE-INTEGRITY', unhexlify('c87b58eccbacdbc075d497ad0c965a82937ab587')),
            ('FINGERPRINT', 1347006354),
        ]))

    def test_parse_binding_response(self):
        data = read_message('binding_response.bin')

        message = stun.parse_message(data)
        self.assertEqual(message.message_method, stun.Method.BINDING)
        self.assertEqual(message.message_class, stun.Class.RESPONSE)
        self.assertEqual(message.transaction_id, b'Nvfx3lU7FUBF')
        self.assertEqual(message.attributes, OrderedDict([
            ('XOR-MAPPED-ADDRESS', (IPv4Address('80.200.136.90'), 53054)),
            ('MAPPED-ADDRESS', (IPv4Address('80.200.136.90'), 53054)),
            ('RESPONSE-ORIGIN', (IPv4Address('52.17.36.97'), 3478)),
            ('OTHER-ADDRESS', (IPv4Address('52.17.36.97'), 3479)),
            ('SOFTWARE', "Citrix-3.2.4.5 'Marshal West'"),
        ]))

        self.assertEqual(bytes(message), data)
