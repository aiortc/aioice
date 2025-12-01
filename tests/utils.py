import asyncio
import functools
import logging
import os
import sys
from asyncio import AbstractEventLoop
from collections.abc import Callable, Coroutine
from contextlib import contextmanager

if sys.version_info >= (3, 10):
    from typing import ParamSpec, Any, Iterator
else:
    from typing_extensions import ParamSpec

from aioice import ice

P = ParamSpec("P")


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


def read_message(name: str) -> bytes:
    path = os.path.join(os.path.dirname(__file__), "data", name)
    with open(path, "rb") as fp:
        return fp.read()


if os.environ.get("AIOICE_DEBUG"):
    logging.basicConfig(level=logging.DEBUG)


class CollectExceptionsHandler:
    _exceptions: list[Exception] = []

    def handle_exception(self, _loop: AbstractEventLoop, context: dict[str, Any]):
        exception = context.get("exception")

        if exception and isinstance(exception, Exception):
            self._exceptions.append(exception)

    @property
    def exceptions(self) -> list[Exception]:
        return self._exceptions


@contextmanager
def new_collect_exceptions_handler() -> Iterator[CollectExceptionsHandler]:
    handler = CollectExceptionsHandler()
    loop = asyncio.get_event_loop()
    original_handler = loop.get_exception_handler()
    loop.set_exception_handler(handler.handle_exception)

    try:
        yield handler
    finally:
        loop.set_exception_handler(original_handler)


@contextmanager
def detect_exceptions_in_loop() -> Iterator[None]:
    with new_collect_exceptions_handler() as handler:
        yield

    if handler.exceptions:
        raise ExceptionGroup(
            "Exceptions were raised in the event loop",
            handler.exceptions,
        )