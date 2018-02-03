import unittest
from ipaddress import IPv4Address

from aioice import ice


class IceTest(unittest.TestCase):
    def test_parse_candidate(self):
        candidate = ice.parse_candidate('6815297761 1 udp 659136 1.2.3.4 31102 typ host generation 0')
        self.assertEqual(candidate.foundation, '6815297761')
        self.assertEqual(candidate.component, 1)
        self.assertEqual(candidate.transport, 'udp')
        self.assertEqual(candidate.priority, 659136)
        self.assertEqual(candidate.host, '1.2.3.4')
        self.assertEqual(candidate.port, 31102)
        self.assertEqual(candidate.type, 'host')
        self.assertEqual(candidate.generation, 0)
