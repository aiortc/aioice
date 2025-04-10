#!/usr/bin/env python

import argparse
import asyncio
import json
import logging
import time
from typing import Optional

import websockets

import aioice

STUN_SERVER = ("stun.l.google.com", 19302)
WEBSOCKET_URI = "ws://127.0.0.1:8765"


async def offer(components: int) -> None:
    connection = aioice.Connection(
        ice_controlling=True, components=components, stun_server=STUN_SERVER
    )
    await connection.gather_candidates()

    websocket = await websockets.connect(WEBSOCKET_URI)

    start_time = time.time()
    # send offer
    await websocket.send(
        json.dumps(
            {
                "candidates": [c.to_sdp() for c in connection.local_candidates],
                "password": connection.local_password,
                "username": connection.local_username,
            }
        )
    )

    # await answer
    message = json.loads(await websocket.recv())
    print("received answer", message)
    for c in message["candidates"]:
        await connection.add_remote_candidate(aioice.Candidate.from_sdp(c))
    await connection.add_remote_candidate(None)
    connection.remote_username = message["username"]
    connection.remote_password = message["password"]

    await websocket.close()

    await connection.connect()
    elapsed = time.time() - start_time
    print(f"✅ connected in {elapsed:.2f} seconds")

    # send data
    data = b"hello"
    component = 1
    print("sending %s on component %d" % (repr(data), component))
    await connection.sendto(data, component)
    data, component = await connection.recvfrom()
    print("received %s on component %d" % (repr(data), component))

    await asyncio.sleep(5)
    await connection.close()


async def answer(components: int) -> None:
    connection = aioice.Connection(
        ice_controlling=False, components=components, stun_server=STUN_SERVER
    )
    await connection.gather_candidates()

    websocket = await websockets.connect(WEBSOCKET_URI)

    # await offer
    message = json.loads(await websocket.recv())
    print("received offer", message)
    for c in message["candidates"]:
        await connection.add_remote_candidate(aioice.Candidate.from_sdp(c))
    await connection.add_remote_candidate(None)
    connection.remote_username = message["username"]
    connection.remote_password = message["password"]

    # send answer
    await websocket.send(
        json.dumps(
            {
                "candidates": [c.to_sdp() for c in connection.local_candidates],
                "password": connection.local_password,
                "username": connection.local_username,
            }
        )
    )

    await websocket.close()

    await connection.connect()
    print("connected")

    # echo data back
    data, component = await connection.recvfrom()
    print("echoing %s on component %d" % (repr(data), component))
    await connection.sendto(data, component)

    await asyncio.sleep(5)
    await connection.close()


async def main() -> None:
    parser = argparse.ArgumentParser(description="ICE tester")
    parser.add_argument("action", choices=["offer", "answer"])
    parser.add_argument("--components", type=int, default=1)
    options = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG)

    if options.action == "offer":
        await offer(options.components)
    else:
        await answer(options.components)


if __name__ == "__main__":
    asyncio.run(main())
