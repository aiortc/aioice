import asyncio
import ssl
import unittest
from typing import Any, Optional
from unittest import mock

from aioice import stun, turn

from .echoserver import run_echo_server
from .turnserver import run_turn_server
from .utils import asynctest, read_message


class DummyClientProtocol(asyncio.DatagramProtocol):
    def __init__(self) -> None:
        self.errors: list[Exception] = []
        self.received: list[tuple[bytes, tuple[str, int]]] = []

    def error_received(self, exc: Exception) -> None:
        self.errors.append(exc)

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        self.received.append((data, addr))


class TurnClientTcpProtocolTest(unittest.TestCase):
    def setUp(self) -> None:
        class MockTransport(asyncio.BaseTransport):
            def get_extra_info(self, name: str, default: Any = None) -> Any:
                return ("1.2.3.4", 1234)

        self.protocol = turn.TurnClientTcpProtocol(
            ("1.2.3.4", 1234),
            username="foo",
            password="bar",
            lifetime=turn.DEFAULT_ALLOCATION_LIFETIME,
            channel_refresh_time=turn.DEFAULT_CHANNEL_REFRESH_TIME,
        )
        self.protocol.connection_made(MockTransport())

    def test_receive_stun_fragmented(self) -> None:
        data = read_message("binding_request.bin")
        self.protocol.data_received(data[0:10])
        self.protocol.data_received(data[10:])

    def test_receive_junk(self) -> None:
        self.protocol.data_received(b"\x00" * 20)

    def test_repr(self) -> None:
        self.assertEqual(repr(self.protocol), "turn/tcp")


class TurnClientUdpProtocolTest(unittest.TestCase):
    def setUp(self) -> None:
        self.protocol = turn.TurnClientUdpProtocol(
            ("1.2.3.4", 1234),
            username="foo",
            password="bar",
            lifetime=turn.DEFAULT_ALLOCATION_LIFETIME,
            channel_refresh_time=turn.DEFAULT_CHANNEL_REFRESH_TIME,
        )

    def _data_indication(
        self, peer_address: Optional[tuple[str, int]], data: Optional[bytes]
    ) -> bytes:
        message = stun.Message(
            message_method=stun.Method.DATA, message_class=stun.Class.INDICATION
        )
        if peer_address is not None:
            message.attributes["XOR-PEER-ADDRESS"] = peer_address
        if data is not None:
            message.attributes["DATA"] = data
        return bytes(message)

    def test_receive_data_indication(self) -> None:
        receiver = DummyClientProtocol()
        self.protocol.receiver = receiver
        self.protocol.peer_to_channel[("5.6.7.8", 1000)] = 0x4000

        # The permission covers the IP address of the peer, whatever its port.
        self.protocol.datagram_received(
            self._data_indication(("5.6.7.8", 2000), b"ping"), ("1.2.3.4", 1234)
        )
        self.assertEqual(receiver.received, [(b"ping", ("5.6.7.8", 2000))])

    def test_receive_data_indication_invalid(self) -> None:
        receiver = DummyClientProtocol()
        self.protocol.receiver = receiver
        self.protocol.peer_to_channel[("5.6.7.8", 1000)] = 0x4000

        # No permission for the peer.
        self.protocol.datagram_received(
            self._data_indication(("9.9.9.9", 1000), b"ping"), ("1.2.3.4", 1234)
        )

        # No DATA attribute.
        self.protocol.datagram_received(
            self._data_indication(("5.6.7.8", 1000), None), ("1.2.3.4", 1234)
        )

        # No XOR-PEER-ADDRESS attribute.
        self.protocol.datagram_received(
            self._data_indication(None, b"ping"), ("1.2.3.4", 1234)
        )

        self.assertEqual(receiver.received, [])

    def test_receive_junk(self) -> None:
        self.protocol.datagram_received(b"\x00" * 20, ("1.2.3.4", 1234))

    def test_repr(self) -> None:
        self.assertEqual(repr(self.protocol), "turn/udp")

    @asynctest
    async def test_send_data_no_channel_number(self) -> None:
        # All channel numbers are in use (RFC 8656 section 12).
        self.protocol.channel_number = turn.CHANNEL_NUMBER_MAX + 1

        with self.assertRaises(ConnectionError) as cm:
            await self.protocol.send_data(b"ping", ("5.6.7.8", 1000))
        self.assertEqual(str(cm.exception), "No TURN channel number available")
        self.assertEqual(self.protocol.peer_connect_waiters, {})


class TurnTest(unittest.TestCase):
    @asynctest
    async def test_tcp_transport(self) -> None:
        await self._test_transport("tcp", "tcp_address")

    @asynctest
    async def test_tls_transport(self) -> None:
        ssl_context = ssl.SSLContext(protocol=ssl.PROTOCOL_TLS_CLIENT)
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE

        await self._test_transport("tcp", "tls_address", ssl=ssl_context)

    @asynctest
    async def test_udp_transport(self) -> None:
        await self._test_transport("udp", "udp_address")

    async def _test_transport(
        self,
        transport: str,
        server_addr_attr: str,
        ssl: Optional[ssl.SSLContext] = None,
    ) -> None:
        await self._test_transport_ok(
            transport=transport, server_addr_attr=server_addr_attr, ssl=ssl
        )
        await self._test_transport_ok_multi(
            transport=transport, server_addr_attr=server_addr_attr, ssl=ssl
        )
        await self._test_transport_data_indication(
            transport=transport, server_addr_attr=server_addr_attr, ssl=ssl
        )
        await self._test_transport_allocate_failure(
            transport=transport, server_addr_attr=server_addr_attr, ssl=ssl
        )
        await self._test_transport_delete_failure(
            transport=transport, server_addr_attr=server_addr_attr, ssl=ssl
        )
        await self._test_transport_channel_bind_failure(
            transport=transport, server_addr_attr=server_addr_attr, ssl=ssl
        )
        await self._test_transport_close_pending_send(
            transport=transport, server_addr_attr=server_addr_attr, ssl=ssl
        )

    async def _test_transport_ok(
        self, *, transport: str, server_addr_attr: str, ssl: Optional[ssl.SSLContext]
    ) -> None:
        async with run_turn_server(users={"foo": "bar"}) as turn_server:
            turn_transport, protocol = await turn.create_turn_endpoint(
                DummyClientProtocol,
                server_addr=getattr(turn_server, server_addr_attr),
                username="foo",
                password="bar",
                channel_refresh_time=5,
                lifetime=6,
                ssl=ssl,
                transport=transport,
            )
            self.assertIsNone(turn_transport.get_extra_info("peername"))
            self.assertIsNotNone(turn_transport.get_extra_info("sockname"))

            async with run_echo_server() as echo_server:
                # bind channel, send ping, expect pong
                turn_transport.sendto(b"ping", echo_server.udp_address)
                await asyncio.sleep(1)
                self.assertEqual(
                    protocol.received, [(b"ping", echo_server.udp_address)]
                )

                # wait some more to allow allocation refresh
                protocol.received.clear()
                await asyncio.sleep(5)

                # refresh channel, send ping, expect pong
                turn_transport.sendto(b"ping", echo_server.udp_address)
                await asyncio.sleep(1)
                self.assertEqual(
                    protocol.received, [(b"ping", echo_server.udp_address)]
                )

            # close
            turn_transport.close()
            await asyncio.sleep(0)

    async def _test_transport_ok_multi(
        self, *, transport: str, server_addr_attr: str, ssl: Optional[ssl.SSLContext]
    ) -> None:
        async with run_turn_server(users={"foo": "bar"}) as turn_server:
            turn_transport, protocol = await turn.create_turn_endpoint(
                DummyClientProtocol,
                server_addr=getattr(turn_server, server_addr_attr),
                username="foo",
                password="bar",
                channel_refresh_time=5,
                lifetime=6,
                ssl=ssl,
                transport=transport,
            )
            self.assertIsNone(turn_transport.get_extra_info("peername"))
            self.assertIsNotNone(turn_transport.get_extra_info("sockname"))

            # Bind channel, send ping, expect pong.
            #
            # We use different lengths to trigger both padded an unpadded
            # ChannelData messages over TCP.
            async with run_echo_server() as echo_server1:
                async with run_echo_server() as echo_server2:
                    turn_transport.sendto(
                        b"ping", echo_server1.udp_address
                    )  # never padded
                    turn_transport.sendto(b"ping11", echo_server1.udp_address)
                    turn_transport.sendto(b"ping20", echo_server2.udp_address)
                    turn_transport.sendto(b"ping21", echo_server2.udp_address)
                    await asyncio.sleep(1)
                    self.assertEqual(
                        sorted(protocol.received),
                        [
                            (b"ping", echo_server1.udp_address),
                            (b"ping11", echo_server1.udp_address),
                            (b"ping20", echo_server2.udp_address),
                            (b"ping21", echo_server2.udp_address),
                        ],
                    )

            # close
            turn_transport.close()
            await asyncio.sleep(0)

    async def _test_transport_data_indication(
        self, *, transport: str, server_addr_attr: str, ssl: Optional[ssl.SSLContext]
    ) -> None:
        async with run_turn_server(users={"foo": "bar"}) as turn_server:
            turn_transport, protocol = await turn.create_turn_endpoint(
                DummyClientProtocol,
                server_addr=getattr(turn_server, server_addr_attr),
                username="foo",
                password="bar",
                ssl=ssl,
                transport=transport,
            )
            relayed_address = turn_transport.get_extra_info("sockname")

            async with run_echo_server() as echo_server1:
                async with run_echo_server() as echo_server2:
                    # Bind a channel, which grants a permission for the IP address.
                    turn_transport.sendto(b"ping", echo_server1.udp_address)
                    await asyncio.sleep(1)

                    # A peer with the same IP address but no channel is relayed
                    # using a Data indication.
                    echo_server2.udp_server.transport.sendto(b"hello", relayed_address)
                    await asyncio.sleep(1)
                    self.assertEqual(
                        protocol.received,
                        [
                            (b"ping", echo_server1.udp_address),
                            (b"hello", echo_server2.udp_address),
                        ],
                    )

            # close
            turn_transport.close()
            await asyncio.sleep(0)

    async def _test_transport_allocate_failure(
        self, *, transport: str, server_addr_attr: str, ssl: Optional[ssl.SSLContext]
    ) -> None:
        async with run_turn_server(users={"foo": "bar"}) as turn_server:
            # Invalid username.
            with self.assertRaises(stun.TransactionFailed) as cm:
                await turn.create_turn_endpoint(
                    DummyClientProtocol,
                    server_addr=getattr(turn_server, server_addr_attr),
                    username="unknown",
                    password="bar",
                    ssl=ssl,
                    transport=transport,
                )
            self.assertEqual(
                str(cm.exception), "STUN transaction failed (401 - Unauthorized)"
            )

            # Invalid password.
            with self.assertRaises(stun.TransactionFailed) as cm:
                await turn.create_turn_endpoint(
                    DummyClientProtocol,
                    server_addr=getattr(turn_server, server_addr_attr),
                    username="foo",
                    password="wrong",
                    ssl=ssl,
                    transport=transport,
                )
            self.assertEqual(
                str(cm.exception), "STUN transaction failed (401 - Unauthorized)"
            )

            # make the server reject the ALLOCATE request
            turn_server.simulated_failure = (403, "Forbidden")

            with self.assertRaises(stun.TransactionFailed) as cm:
                await turn.create_turn_endpoint(
                    DummyClientProtocol,
                    server_addr=getattr(turn_server, server_addr_attr),
                    username="foo",
                    password="bar",
                    ssl=ssl,
                    transport=transport,
                )
            self.assertEqual(
                str(cm.exception), "STUN transaction failed (403 - Forbidden)"
            )

    async def _test_transport_delete_failure(
        self, *, transport: str, server_addr_attr: str, ssl: Optional[ssl.SSLContext]
    ) -> None:
        async with run_turn_server(users={"foo": "bar"}) as turn_server:
            turn_transport, protocol = await turn.create_turn_endpoint(
                DummyClientProtocol,
                server_addr=getattr(turn_server, server_addr_attr),
                username="foo",
                password="bar",
                ssl=ssl,
                transport=transport,
            )
            self.assertIsNone(turn_transport.get_extra_info("peername"))
            self.assertIsNotNone(turn_transport.get_extra_info("sockname"))

            # make the server reject the final REFRESH request
            turn_server.simulated_failure = (403, "Forbidden")

            # close client
            turn_transport.close()
            await asyncio.sleep(0)

    async def _test_transport_channel_bind_failure(
        self, *, transport: str, server_addr_attr: str, ssl: Optional[ssl.SSLContext]
    ) -> None:
        async with run_turn_server(users={"foo": "bar"}) as turn_server:
            turn_transport, protocol = await turn.create_turn_endpoint(
                DummyClientProtocol,
                server_addr=getattr(turn_server, server_addr_attr),
                username="foo",
                password="bar",
                ssl=ssl,
                transport=transport,
            )

            async with run_echo_server() as echo_server:
                # Make the server reject the CHANNEL-BIND request.
                turn_server.simulated_failure = (403, "Forbidden")

                # The failure is reported to the protocol, for the send that
                # binds the channel and for the one queued behind it.
                turn_transport.sendto(b"ping", echo_server.udp_address)
                turn_transport.sendto(b"ping", echo_server.udp_address)
                await asyncio.sleep(1)
                self.assertEqual(protocol.received, [])
                self.assertEqual(
                    [str(exc) for exc in protocol.errors],
                    ["STUN transaction failed (403 - Forbidden)"] * 2,
                )

                # A later send binds the channel again, with the same number.
                turn_transport.sendto(b"ping", echo_server.udp_address)
                await asyncio.sleep(1)
                self.assertEqual(
                    protocol.received, [(b"ping", echo_server.udp_address)]
                )
                self.assertEqual(
                    [
                        allocation.channel_to_peer
                        for allocation in turn_server.allocations.values()
                    ],
                    [{0x4000: echo_server.udp_address}],
                )

            # close
            turn_transport.close()
            await asyncio.sleep(0)

    async def _test_transport_close_pending_send(
        self, *, transport: str, server_addr_attr: str, ssl: Optional[ssl.SSLContext]
    ) -> None:
        async with run_turn_server(users={"foo": "bar"}) as turn_server:
            turn_transport, protocol = await turn.create_turn_endpoint(
                DummyClientProtocol,
                server_addr=getattr(turn_server, server_addr_attr),
                username="foo",
                password="bar",
                ssl=ssl,
                transport=transport,
            )

            async with run_echo_server() as echo_server1:
                async with run_echo_server() as echo_server2:
                    # Bind a channel.
                    turn_transport.sendto(b"ping", echo_server1.udp_address)
                    await asyncio.sleep(1)

                    # Make channel bindings hang until they are cancelled.
                    bound = []
                    cancelled = []

                    async def channel_bind(channel: int, addr: tuple[str, int]) -> None:
                        bound.append(addr)
                        try:
                            await asyncio.Event().wait()
                        except asyncio.CancelledError:
                            cancelled.append(addr)
                            raise

                    with (
                        mock.patch.object(
                            turn.TurnClientMixin,
                            "channel_bind",
                            side_effect=channel_bind,
                        ),
                        mock.patch.object(
                            turn.TurnClientMixin,
                            "delete",
                            autospec=True,
                            side_effect=turn.TurnClientMixin.delete,
                        ) as delete,
                    ):
                        # Data sent before closing goes out.
                        turn_transport.sendto(b"pending", echo_server2.udp_address)
                        turn_transport.sendto(b"last", echo_server1.udp_address)
                        turn_transport.close()

                        # Data sent after closing is ignored, and binds no channel.
                        turn_transport.sendto(b"ignored", echo_server1.udp_address)
                        turn_transport.sendto(b"ignored", ("127.0.0.1", 9))

                        # Closing again does nothing.
                        turn_transport.close()
                        await asyncio.sleep(1)

                    self.assertEqual(delete.call_count, 1)
                    self.assertEqual(
                        echo_server1.udp_server.received, [b"ping", b"last"]
                    )
                    self.assertEqual(echo_server2.udp_server.received, [])
                    self.assertEqual(bound, [echo_server2.udp_address])

                    # The pending channel binding is cancelled once the allocation
                    # is deleted, without reporting an error.
                    self.assertEqual(cancelled, [echo_server2.udp_address])
                    self.assertEqual(protocol.errors, [])

    @asynctest
    async def test_udp_transport_cancelled(self) -> None:
        """
        If the allocation is cancelled while it is being set up (for instance
        when ICE candidate gathering times out and cancels the relay task),
        the underlying transport must be closed rather than leaked.
        """
        loop = asyncio.get_event_loop()
        real_create_datagram_endpoint = loop.create_datagram_endpoint
        captured: dict[str, asyncio.BaseTransport] = {}

        async def spy_create_datagram_endpoint(
            *args: Any, **kwargs: Any
        ) -> tuple[asyncio.BaseTransport, asyncio.BaseProtocol]:
            transport, protocol = await real_create_datagram_endpoint(*args, **kwargs)
            captured["transport"] = transport
            return transport, protocol

        async with run_turn_server(users={"foo": "bar"}) as turn_server:
            with (
                mock.patch.object(
                    loop,
                    "create_datagram_endpoint",
                    spy_create_datagram_endpoint,
                ),
                mock.patch.object(
                    turn.TurnClientMixin,
                    "connect",
                    side_effect=asyncio.CancelledError,
                ),
            ):
                with self.assertRaises(asyncio.CancelledError):
                    await turn.create_turn_endpoint(
                        DummyClientProtocol,
                        server_addr=turn_server.udp_address,
                        username="foo",
                        password="bar",
                        transport="udp",
                    )

        # allow the transport to finish closing
        await asyncio.sleep(0)

        self.assertIn("transport", captured)
        self.assertTrue(captured["transport"].is_closing())
