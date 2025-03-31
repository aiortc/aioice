#!/usr/bin/env python

import argparse
import asyncio
import json
import logging
import time
from typing import Optional

import aioice
import websockets

STUN_SERVER = ("stun.l.google.com", 19302)
WEBSOCKET_URI = "ws://127.0.0.1:8765"


async def offer(options):
    websocket = await websockets.connect(WEBSOCKET_URI)

    connected = False
    start_time = None

    async def signal_candidate(candidate: Optional[aioice.Candidate]):
        message = {
            "type": "candidate",
            "candidate": candidate.to_sdp() if candidate else None,
        }
        await websocket.send(json.dumps(message))
        print("Sent candidate:", message["candidate"])

    connection = aioice.Connection(
        ice_controlling=True,
        components=options.components,
        stun_server=STUN_SERVER,
        signal_candidate=signal_candidate,
    )

    start_time = time.time()
    await websocket.send(
        json.dumps({
            "type": "offer",
            "username": connection.local_username,
            "password": connection.local_password,
        })
    )

    await connection.gather_candidates()

    async for raw in websocket:
        message = json.loads(raw)

        if message["type"] == "answer":
            connection.remote_username = message["username"]
            connection.remote_password = message["password"]
            print("Received answer.")
        elif message["type"] == "candidate":
            candidate = message["candidate"]
            await connection.add_remote_candidate(
                aioice.Candidate.from_sdp(candidate) if candidate else None
            )
            print("Received remote candidate:", candidate)
        else:
            print("Unknown message type:", message)

        if not connected and connection.remote_username and connection.remote_password:
            try:
                await connection.connect()
                connected = True
                elapsed = time.time() - start_time
                print(f"✅ connected in {elapsed:.2f} seconds")

                data = b"hello"
                await connection.sendto(data, 1)
                data, component = await connection.recvfrom()
                print("Received:", data)

                await asyncio.sleep(2)
                await connection.close()
                await websocket.close()
                break
            except Exception as e:
                print("Connection error:", e)


async def answer(options):
    websocket = await websockets.connect(WEBSOCKET_URI)

    connected = False

    async def signal_candidate(candidate: Optional[aioice.Candidate]):
        message = {
            "type": "candidate",
            "candidate": candidate.to_sdp() if candidate else None,
        }
        await websocket.send(json.dumps(message))
        print("Sent candidate:", message["candidate"])

    connection = aioice.Connection(
        ice_controlling=False,
        components=options.components,
        stun_server=STUN_SERVER,
        signal_candidate=signal_candidate,
    )

    async for raw in websocket:
        message = json.loads(raw)

        if message["type"] == "offer":
            connection.remote_username = message["username"]
            connection.remote_password = message["password"]

            await websocket.send(json.dumps({
                "type": "answer",
                "username": connection.local_username,
                "password": connection.local_password,
            }))

            await connection.gather_candidates()

        elif message["type"] == "candidate":
            candidate = message["candidate"]
            await connection.add_remote_candidate(
                aioice.Candidate.from_sdp(candidate) if candidate else None
            )
            print("Received remote candidate:", candidate)

            if not connected and candidate is None and connection.remote_username:
                try:
                    await connection.connect()
                    connected = True
                    print("✅ Connected via ICE.")

                    data, component = await connection.recvfrom()
                    print("Echoing:", data)
                    await connection.sendto(data, component)

                    await asyncio.sleep(2)
                    await connection.close()
                    await websocket.close()
                    break
                except Exception as e:
                    print("Connection error:", e)


parser = argparse.ArgumentParser(description="ICE trickle demo")
parser.add_argument("action", choices=["offer", "answer"])
parser.add_argument("--components", type=int, default=1)
options = parser.parse_args()

logging.basicConfig(level=logging.DEBUG)

if options.action == "offer":
    asyncio.run(offer(options))
else:
    asyncio.run(answer(options))
