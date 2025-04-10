#!/usr/bin/env python
#
# Simple websocket server to perform signaling.
#

import asyncio
import binascii
import os

import websockets
from websockets.asyncio.server import ServerConnection

clients: dict[bytes, ServerConnection] = {}


async def echo(websocket):
    client_id = binascii.hexlify(os.urandom(8)).decode()
    clients[client_id] = websocket

    try:
        async for message in websocket:
            for c in clients.values():
                if c != websocket:
                    await c.send(message)
    finally:
        clients.pop(client_id)


async def main():
    async with websockets.serve(echo, "0.0.0.0", 8765):
        await asyncio.Future()


if __name__ == "__main__":
    asyncio.run(main())
