import asyncio
import unittest

from aioice import mdns

from .utils import run


class MdnsTest(unittest.TestCase):
    def setUp(self):
        self.querier = run(mdns.create_mdns_protocol())
        self.responder = run(mdns.create_mdns_protocol())

    def tearDown(self):
        run(self.querier.close())
        run(self.responder.close())

    def test_receive_junk(self):
        self.querier.datagram_received(b"junk", None)

    def test_resolve_bad(self):
        hostname = mdns.create_mdns_hostname()

        result = run(self.querier.resolve(hostname))
        self.assertEqual(result, None)

    def test_resolve_good_ipv4(self):
        hostaddr = "1.2.3.4"
        hostname = mdns.create_mdns_hostname()
        run(self.responder.publish(hostname, hostaddr))

        result = run(self.querier.resolve(hostname))
        self.assertEqual(result, hostaddr)

    def test_resolve_good_ipv6(self):
        hostaddr = "::ffff:1.2.3.4"
        hostname = mdns.create_mdns_hostname()
        run(self.responder.publish(hostname, hostaddr))

        result = run(self.querier.resolve(hostname))
        self.assertEqual(result, hostaddr)

    def test_resolve_simultaneous_bad(self):
        hostname = mdns.create_mdns_hostname()

        results = run(
            asyncio.gather(
                self.querier.resolve(hostname), self.querier.resolve(hostname)
            )
        )
        self.assertEqual(results, [None, None])

    def test_resolve_simultaneous_good(self):
        hostaddr = "1.2.3.4"
        hostname = mdns.create_mdns_hostname()
        run(self.responder.publish(hostname, hostaddr))

        results = run(
            asyncio.gather(
                self.querier.resolve(hostname), self.querier.resolve(hostname)
            )
        )
        self.assertEqual(results, [hostaddr, hostaddr])
