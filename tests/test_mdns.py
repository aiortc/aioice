import asyncio
import contextlib
import unittest
from collections.abc import AsyncGenerator
from unittest import mock

import dns.message

from aioice import mdns

from .utils import RUNNING_ON_MAC_CI, asynctest


@contextlib.asynccontextmanager
async def querier_and_responder() -> AsyncGenerator[
    tuple[mdns.MDnsProtocol, mdns.MDnsProtocol], None
]:
    querier = await mdns.create_mdns_protocol()
    responder = await mdns.create_mdns_protocol()
    assert querier is not None
    assert responder is not None

    try:
        yield querier, responder
    finally:
        await querier.close()
        await responder.close()


@unittest.skipIf(RUNNING_ON_MAC_CI, "Mac CI has issues with mDNS")
class MdnsTest(unittest.TestCase):
    @asynctest
    async def test_create_cancelled(self) -> None:
        tx_sock = mock.Mock()
        rx_sock = mock.Mock()
        tx_transport = mock.Mock()
        endpoint = mock.AsyncMock(
            side_effect=[(tx_transport, None), asyncio.CancelledError()]
        )
        with (
            mock.patch("aioice.mdns.socket.socket", side_effect=[tx_sock, rx_sock]),
            mock.patch.object(
                asyncio.get_running_loop(), "create_datagram_endpoint", endpoint
            ),
            self.assertRaises(asyncio.CancelledError),
        ):
            await mdns.create_mdns_protocol()
        tx_sock.close.assert_called_once()
        rx_sock.close.assert_called_once()
        tx_transport.close.assert_called_once()

    @asynctest
    async def test_create_failure(self) -> None:
        for failure in (
            "sender_bind",
            "sender_endpoint",
            "membership",
            "receiver_endpoint",
        ):
            with self.subTest(failure=failure):
                tx_sock = mock.Mock()
                rx_sock = mock.Mock()
                tx_transport = mock.Mock()
                endpoint = mock.AsyncMock(return_value=(tx_transport, None))
                error = OSError("No such device")
                if failure == "sender_bind":
                    tx_sock.bind.side_effect = error
                elif failure == "sender_endpoint":
                    endpoint.side_effect = error
                elif failure == "membership":
                    rx_sock.setsockopt.side_effect = error
                else:
                    endpoint.side_effect = [(tx_transport, None), error]
                with (
                    mock.patch(
                        "aioice.mdns.socket.socket", side_effect=[tx_sock, rx_sock]
                    ),
                    mock.patch.object(
                        asyncio.get_running_loop(), "create_datagram_endpoint", endpoint
                    ),
                    mock.patch("aioice.mdns.sys.platform", "win32"),
                    self.assertLogs("aioice.mdns", level="DEBUG"),
                ):
                    self.assertIsNone(await mdns.create_mdns_protocol())
                tx_sock.close.assert_called_once()
                if failure in ("membership", "receiver_endpoint"):
                    rx_sock.close.assert_called_once()
                    tx_transport.close.assert_called_once()
                else:
                    tx_transport.close.assert_not_called()

    @asynctest
    async def test_receive_junk(self) -> None:
        async with querier_and_responder() as (querier, _):
            querier.datagram_received(b"junk", ("1.2.3.4", 5353))

    @asynctest
    async def test_receive_send_failure(self) -> None:
        hostname = mdns.create_mdns_hostname()
        async with querier_and_responder() as (_, responder):
            await responder.publish(hostname, "1.2.3.4")
            query = dns.message.make_query(hostname, "A")
            with (
                mock.patch.object(
                    responder.tx_transport,
                    "sendto",
                    side_effect=OSError("No such device"),
                ) as sendto,
                self.assertLogs("aioice.mdns", level="DEBUG"),
            ):
                responder.datagram_received(query.to_wire(), ("1.2.3.4", 5353))
            sendto.assert_called_once()

    @asynctest
    async def test_resolve_bad(self) -> None:
        hostname = mdns.create_mdns_hostname()

        async with querier_and_responder() as (querier, _):
            result = await querier.resolve(hostname)
            self.assertEqual(result, None)

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
    async def test_resolve_send_failure(self) -> None:
        hostname = mdns.create_mdns_hostname()
        async with querier_and_responder() as (querier, responder):
            await responder.publish(hostname, "1.2.3.4")
            with (
                mock.patch.object(
                    querier.tx_transport,
                    "sendto",
                    side_effect=OSError("No such device"),
                ),
                self.assertLogs("aioice.mdns", level="DEBUG"),
            ):
                self.assertIsNone(
                    await asyncio.wait_for(querier.resolve(hostname, timeout=None), 1)
                )
            self.assertEqual(querier.queries, {})
            self.assertEqual(await querier.resolve(hostname), "1.2.3.4")

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
