#!/usr/bin/env python
#
# Simple websocket server to perform signaling.
#

import asyncio
import binascii
import os

from websockets.asyncio.server import ServerConnection, serve

clients: dict[bytes, ServerConnection] = {}


async def echo(websocket: ServerConnection) -> None:
    client_id = binascii.hexlify(os.urandom(8))
    clients[client_id] = websocket

    try:
        async for message in websocket:
            for c in clients.values():
                if c != websocket:
                    await c.send(message)
    finally:
        clients.pop(client_id)


async def main() -> None:
    async with serve(echo, "0.0.0.0", 8765) as server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
