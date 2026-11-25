import asyncio
import contextlib
from collections.abc import AsyncIterator, Callable
from typing import Any, cast

from aioice import stun


class MuxTransport(asyncio.DatagramTransport):
    def __init__(
        self,
        mux: "UdpMux",
        local_username: str,
        protocol: asyncio.DatagramProtocol,
    ) -> None:
        super().__init__()
        self.closed = False
        self.local_username = local_username
        self.mux = mux
        self.protocol = protocol

    def close(self) -> None:
        if not self.closed:
            self.closed = True
            self.mux.remove(self)
            asyncio.get_running_loop().call_soon(self.protocol.connection_lost, None)

    def get_extra_info(self, name: str, default: Any = None) -> Any:
        if name == "sockname":
            return self.mux.transport.get_extra_info("sockname")
        return default

    def is_closing(self) -> bool:
        return self.closed

    def sendto(self, data: Any, addr: Any = None) -> None:
        # Replies from this address belong to this connection.
        self.mux.by_addr[addr] = self
        self.mux.transport.sendto(data, addr)


class UdpMux(asyncio.DatagramProtocol):
    """
    A UDP socket shared by several connections, which routes STUN requests by
    local username and other datagrams by remote address.
    """

    def __init__(self) -> None:
        self.by_addr: dict[tuple[str, int], MuxTransport] = {}
        self.by_username: dict[str, MuxTransport] = {}
        self.transport: asyncio.DatagramTransport

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = cast(asyncio.DatagramTransport, transport)

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        mux_transport = None
        try:
            message = stun.parse_message(data)
        except ValueError:
            pass
        else:
            if (
                message.message_class == stun.Class.REQUEST
                and "USERNAME" in message.attributes
            ):
                local_username = message.attributes["USERNAME"].split(":")[0]
                mux_transport = self.by_username.get(local_username)
                if mux_transport is not None:
                    self.by_addr[addr] = mux_transport
        if mux_transport is None:
            mux_transport = self.by_addr.get(addr)
        if mux_transport is not None:
            mux_transport.protocol.datagram_received(data, addr)

    async def create_datagram_endpoints(
        self,
        protocol_factory: Callable[[], asyncio.DatagramProtocol],
        local_username: str,
    ) -> list[tuple[asyncio.DatagramTransport, asyncio.DatagramProtocol]]:
        protocol = protocol_factory()
        transport = MuxTransport(self, local_username, protocol)
        protocol.connection_made(transport)
        self.by_username[local_username] = transport
        return [(transport, protocol)]

    def remove(self, transport: MuxTransport) -> None:
        self.by_username.pop(transport.local_username, None)
        for addr in [a for a, t in self.by_addr.items() if t is transport]:
            del self.by_addr[addr]


@contextlib.asynccontextmanager
async def run_udp_mux(address: str) -> AsyncIterator[UdpMux]:
    _, mux = await asyncio.get_running_loop().create_datagram_endpoint(
        UdpMux, local_addr=(address, 0)
    )
    try:
        yield mux
    finally:
        mux.transport.close()
