import asyncio
import contextlib
import errno
import functools
import logging
import os
import socket
import sys
from collections.abc import Callable, Coroutine, Iterator
from typing import Any, ParamSpec
from unittest import mock

from aioice import ice

P = ParamSpec("P")

# Multicast is blocked on macOS 15+ CI runners by Local Network Privacy.
# See https://github.com/actions/runner-images/issues/10924
RUNNING_ON_MAC_CI = (
    os.environ.get("GITHUB_ACTIONS") == "true" and sys.platform == "darwin"
)


def asynctest(
    coro: Callable[P, Coroutine[None, None, None]],
) -> Callable[P, None]:
    @functools.wraps(coro)
    def wrap(*args: P.args, **kwargs: P.kwargs) -> None:
        asyncio.run(coro(*args, **kwargs))

    return wrap


async def invite_accept(conn_a: ice.Connection, conn_b: ice.Connection) -> None:
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


@contextlib.contextmanager
def multicast_join_fails() -> Iterator[None]:
    """
    Make joining a multicast group fail, as on a host without multicast.
    """
    setsockopt = socket.socket.setsockopt

    def failing_setsockopt(
        sock: socket.socket, level: int, option: int, *args: Any
    ) -> None:
        if option == socket.IP_ADD_MEMBERSHIP:
            raise OSError(errno.ENODEV, "No such device")
        setsockopt(sock, level, option, *args)

    with mock.patch.object(socket.socket, "setsockopt", failing_setsockopt):
        yield


def read_message(name: str) -> bytes:
    path = os.path.join(os.path.dirname(__file__), "data", name)
    with open(path, "rb") as fp:
        return fp.read()


if os.environ.get("AIOICE_DEBUG"):
    logging.basicConfig(level=logging.DEBUG)
