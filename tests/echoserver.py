import asyncio
import contextlib
from typing import AsyncGenerator, cast


class EchoServerProtocol(asyncio.DatagramProtocol):
    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = cast(asyncio.DatagramTransport, transport)

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        self.transport.sendto(data, addr)


class EchoServer:
    async def close(self) -> None:
        self.udp_server.transport.close()

    async def listen(self, host: str = "127.0.0.1", port: int = 0) -> None:
        loop = asyncio.get_event_loop()

        # listen for UDP
        transport, self.udp_server = await loop.create_datagram_endpoint(
            EchoServerProtocol, local_addr=(host, port)
        )
        self.udp_address = transport.get_extra_info("sockname")


@contextlib.asynccontextmanager
async def run_echo_server() -> AsyncGenerator[EchoServer, None]:
    server = EchoServer()
    await server.listen()
    try:
        yield server
    finally:
        await server.close()
