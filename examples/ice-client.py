#!/usr/bin/env python

import aioice
import argparse
import asyncio
import json
import logging
import websockets


STUN_SERVER = ('stun.l.google.com', 19302)
WEBSOCKET_URI = 'ws://127.0.0.1:8765'


async def offer():
    connection = aioice.Connection(ice_controlling=True,
                                   stun_server=STUN_SERVER)
    local_candidates = await connection.get_local_candidates()

    websocket = await websockets.connect(WEBSOCKET_URI)

    # send offer
    await websocket.send(json.dumps({
        'candidates': [str(c) for c in local_candidates],
        'password': connection.local_password,
        'username': connection.local_username,
    }))

    # await answer
    message = json.loads(await websocket.recv())
    print('received answer', message)
    connection.set_remote_candidates([aioice.parse_candidate(c) for c in message['candidates']])
    connection.remote_username = message['username']
    connection.remote_password = message['password']

    await websocket.close()

    await connection.connect()
    print('connected')
    await asyncio.sleep(5)
    await connection.close()


async def answer():
    connection = aioice.Connection(ice_controlling=False,
                                   stun_server=STUN_SERVER)
    local_candidates = await connection.get_local_candidates()

    websocket = await websockets.connect(WEBSOCKET_URI)

    # await offer
    message = json.loads(await websocket.recv())
    print('received offer', message)
    connection.set_remote_candidates([aioice.parse_candidate(c) for c in message['candidates']])
    connection.remote_username = message['username']
    connection.remote_password = message['password']

    # send answer
    await websocket.send(json.dumps({
        'candidates': [str(c) for c in local_candidates],
        'password': connection.local_password,
        'username': connection.local_username,
    }))

    await websocket.close()

    await connection.connect()
    print('connected')
    await asyncio.sleep(5)
    await connection.close()


parser = argparse.ArgumentParser(description='ICE tester')
parser.add_argument('action', choices=['offer', 'answer'])
options = parser.parse_args()

logging.basicConfig(level=logging.DEBUG)

if options.action == 'offer':
    asyncio.get_event_loop().run_until_complete(offer())
else:
    asyncio.get_event_loop().run_until_complete(answer())
