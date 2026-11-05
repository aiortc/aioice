import asyncio
import contextlib
import errno
import socket
import unittest
from collections.abc import AsyncGenerator

import dns.flags
import dns.message
import dns.name
import dns.rdata
import dns.rdatatype
import dns.rrset

from aioice import mdns

from .utils import RUNNING_ON_MAC_CI, asynctest, multicast_join_fails


def make_answer(hostname: str, hostaddr: str) -> bytes:
    """
    Build an mDNS answer giving the IPv4 address of a hostname.
    """
    rdata = dns.rdata.GenericRdata(
        rdclass=mdns.MDNS_RDCLASS,
        rdtype=dns.rdatatype.A,
        data=socket.inet_aton(hostaddr),
    )
    message = dns.message.QueryMessage(id=0)
    message.flags |= dns.flags.QR | dns.flags.AA
    message.answer.append(
        dns.rrset.from_rdata(dns.name.from_text(hostname), 120, rdata)
    )
    return message.to_wire()


@contextlib.asynccontextmanager
async def querier_and_responder() -> AsyncGenerator[
    tuple[mdns.MDnsProtocol, mdns.MDnsProtocol], None
]:
    querier = await mdns.create_mdns_protocol()
    responder = await mdns.create_mdns_protocol()

    try:
        yield querier, responder
    finally:
        await querier.close()
        await responder.close()


@unittest.skipIf(RUNNING_ON_MAC_CI, "Mac CI has issues with mDNS")
class MdnsTest(unittest.TestCase):
    @asynctest
    async def test_publish_join_failure(self) -> None:
        hostaddr = "1.2.3.4"
        hostname = mdns.create_mdns_hostname()

        async with querier_and_responder() as (querier, responder):
            # Publishing fails if the group cannot be joined.
            with multicast_join_fails():
                with self.assertRaises(OSError):
                    await responder.publish(hostname, hostaddr)
            result = await querier.resolve(hostname, timeout=0.1)
            self.assertEqual(result, None)

            # Publishing again joins the group.
            await responder.publish(hostname, hostaddr)
            result = await querier.resolve(hostname)
            self.assertEqual(result, hostaddr)

    @asynctest
    async def test_receive_junk(self) -> None:
        async with querier_and_responder() as (querier, _):
            querier.datagram_received(b"junk", ("1.2.3.4", 5353))

    @asynctest
    async def test_resolve_bad(self) -> None:
        hostname = mdns.create_mdns_hostname()

        async with querier_and_responder() as (querier, _):
            result = await querier.resolve(hostname)
            self.assertEqual(result, None)

    @asynctest
    async def test_resolve_after_close(self) -> None:
        hostname = mdns.create_mdns_hostname()

        protocol = await mdns.create_mdns_protocol()
        await protocol.close()

        # Resolving fails at once, without trying to join the group.
        with self.assertNoLogs("aioice.mdns"):
            result = await asyncio.wait_for(
                protocol.resolve(hostname, timeout=None), timeout=1
            )
        self.assertEqual(result, None)

    @asynctest
    async def test_resolve_cancelled_then_answer(self) -> None:
        hostaddr = "1.2.3.4"
        hostname = mdns.create_mdns_hostname()
        name = dns.name.from_text(hostname)

        protocol = await mdns.create_mdns_protocol()
        try:
            # Two queries for the same name are pending.
            first = asyncio.create_task(protocol.resolve(hostname))
            await asyncio.sleep(0)
            (first_future,) = protocol.queries[name]
            second = asyncio.create_task(protocol.resolve(hostname))
            await asyncio.sleep(0)

            # The first query is cancelled, as by its timeout or its task, and
            # the answer arrives before its task removes it.
            first_future.cancel()
            protocol.datagram_received(make_answer(hostname, hostaddr), ("", 5353))

            self.assertEqual(await second, hostaddr)
            with self.assertRaises(asyncio.CancelledError):
                await first
        finally:
            await protocol.close()

    @asynctest
    async def test_resolve_cancelled_then_close(self) -> None:
        hostname = mdns.create_mdns_hostname()
        name = dns.name.from_text(hostname)

        protocol = await mdns.create_mdns_protocol()

        # Two queries for the same name are pending.
        first = asyncio.create_task(protocol.resolve(hostname))
        await asyncio.sleep(0)
        (first_future,) = protocol.queries[name]
        second = asyncio.create_task(protocol.resolve(hostname))
        await asyncio.sleep(0)

        # The first query is cancelled, as by its timeout or its task, and the
        # protocol is closed before its task removes it.
        protocol.transport.close()
        first_future.cancel()
        await asyncio.wait_for(protocol.close(), timeout=1)

        self.assertEqual(await second, None)
        with self.assertRaises(asyncio.CancelledError):
            await first

    @asynctest
    async def test_resolve_close(self) -> None:
        hostname = mdns.create_mdns_hostname()

        # close the querier while the query is ongoing
        async with querier_and_responder() as (querier, _):
            result = await asyncio.gather(
                querier.resolve(hostname, timeout=None), querier.close()
            )
            self.assertEqual(result, [None, None])

    @asynctest
    async def test_resolve_good_ipv4(self) -> None:
        hostaddr = "1.2.3.4"
        hostname = mdns.create_mdns_hostname()

        async with querier_and_responder() as (querier, responder):
            await responder.publish(hostname, hostaddr)

            result = await querier.resolve(hostname)
            self.assertEqual(result, hostaddr)

    @asynctest
    async def test_resolve_good_ipv6(self) -> None:
        hostaddr = "::ffff:1.2.3.4"
        hostname = mdns.create_mdns_hostname()

        async with querier_and_responder() as (querier, responder):
            await responder.publish(hostname, hostaddr)

            result = await querier.resolve(hostname)
            self.assertEqual(result, hostaddr)

    @asynctest
    async def test_resolve_join_failure(self) -> None:
        hostaddr = "1.2.3.4"
        hostname = mdns.create_mdns_hostname()

        async with querier_and_responder() as (querier, responder):
            await responder.publish(hostname, hostaddr)

            # The query fails at once if the group cannot be joined.
            with multicast_join_fails(), self.assertLogs("aioice.mdns") as cm:
                result = await asyncio.wait_for(
                    querier.resolve(hostname, timeout=None), timeout=1
                )
            self.assertEqual(result, None)
            self.assertEqual(
                cm.output,
                [
                    "INFO:aioice.mdns:Could not join the mDNS group: "
                    f"[Errno {errno.ENODEV}] No such device"
                ],
            )

            # The next query joins the group.
            result = await querier.resolve(hostname)
            self.assertEqual(result, hostaddr)

    @asynctest
    async def test_resolve_simultaneous_bad(self) -> None:
        hostname = mdns.create_mdns_hostname()

        async with querier_and_responder() as (querier, _):
            results = await asyncio.gather(
                querier.resolve(hostname), querier.resolve(hostname)
            )
            self.assertEqual(results, [None, None])

    @asynctest
    async def test_resolve_simultaneous_good(self) -> None:
        hostaddr = "1.2.3.4"
        hostname = mdns.create_mdns_hostname()

        async with querier_and_responder() as (querier, responder):
            await responder.publish(hostname, hostaddr)

            results = await asyncio.gather(
                querier.resolve(hostname), querier.resolve(hostname)
            )
            self.assertEqual(results, [hostaddr, hostaddr])
