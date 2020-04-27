import asyncio
import logging
import os


async def invite_accept(conn_a, conn_b):
    # invite
    await conn_a.gather_candidates()
    for candidate in conn_a.local_candidates:
        await conn_b.add_remote_candidate(candidate)
    await conn_b.add_remote_candidate(None)
    conn_b.remote_username = conn_a.local_username
    conn_b.remote_password = conn_a.local_password

    # accept
    await conn_b.gather_candidates()
    for candidate in conn_b.local_candidates:
        await conn_a.add_remote_candidate(candidate)
    await conn_a.add_remote_candidate(None)
    conn_a.remote_username = conn_b.local_username
    conn_a.remote_password = conn_b.local_password


def read_message(name):
    path = os.path.join(os.path.dirname(__file__), "data", name)
    with open(path, "rb") as fp:
        return fp.read()


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


if os.environ.get("AIOICE_DEBUG"):
    logging.basicConfig(level=logging.DEBUG)
