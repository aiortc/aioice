import asyncio
import ssl
import unittest
from typing import Any, Optional

from aioice import stun, turn

from .echoserver import run_echo_server
from .turnserver import run_turn_server
from .utils import asynctest, read_message


class DummyClientProtocol(asyncio.DatagramProtocol):
    def __init__(self) -> None:
        self.received: list[tuple[bytes, tuple[str, int]]] = []

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

    def test_receive_junk(self) -> None:
        self.protocol.datagram_received(b"\x00" * 20, ("1.2.3.4", 1234))

    def test_repr(self) -> None:
        self.assertEqual(repr(self.protocol), "turn/udp")


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
        await self._test_transport_allocate_failure(
            transport=transport, server_addr_attr=server_addr_attr, ssl=ssl
        )
        await self._test_transport_delete_failure(
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
