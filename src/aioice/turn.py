import asyncio
import hashlib
import logging
import socket
import ssl
import struct
import time
from collections.abc import Callable
from typing import Any, TypeVar, cast

from . import stun
from .utils import random_transaction_id

logger = logging.getLogger(__name__)

CHANNEL_NUMBER_MAX = 0x4FFF
DEFAULT_CHANNEL_REFRESH_TIME = 500
DEFAULT_ALLOCATION_LIFETIME = 600
TCP_TRANSPORT = 0x06000000
UDP_TRANSPORT = 0x11000000
UDP_SOCKET_BUFFER_SIZE = 262144

_ProtocolT = TypeVar("_ProtocolT", bound=asyncio.DatagramProtocol)


def is_channel_data(data: bytes) -> bool:
    return (data[0] & 0xC0) == 0x40


def make_integrity_key(username: str, realm: str, password: str) -> bytes:
    return hashlib.md5(":".join([username, realm, password]).encode("utf8")).digest()


class TurnStreamMixin:
    datagram_received: Callable[[bytes, Any], None]
    transport: asyncio.BaseTransport

    def data_received(self, data: bytes) -> None:
        if not hasattr(self, "buffer"):
            self.buffer = b""
        self.buffer += data

        while len(self.buffer) >= 4:
            _, length = struct.unpack("!HH", self.buffer[0:4])
            length += stun.padding_length(length)
            if is_channel_data(self.buffer):
                full_length = 4 + length
            else:
                full_length = 20 + length
            if len(self.buffer) < full_length:
                break

            addr = self.transport.get_extra_info("peername")
            self.datagram_received(self.buffer[0:full_length], addr)
            self.buffer = self.buffer[full_length:]

    def _padded(self, data: bytes) -> bytes:
        # TCP and TCP-over-TLS must pad messages to 4-byte boundaries.
        padding = stun.padding_length(len(data))
        if padding:
            data += bytes(padding)
        return data


class TurnClientMixin:
    _send: Callable[[bytes], None]

    def __init__(
        self,
        server: tuple[str, int],
        username: str | None,
        password: str | None,
        lifetime: int,
        channel_refresh_time: int,
    ) -> None:
        self.channel_refresh_at: dict[int, float] = {}
        self.channel_to_peer: dict[int, tuple[str, int]] = {}
        self.peer_connect_waiters: dict[
            tuple[str, int], list[asyncio.Future[None]]
        ] = {}
        self.peer_to_channel: dict[tuple[str, int], int] = {}
        self.peer_to_failed_channel: dict[tuple[str, int], int] = {}

        self.channel_number = 0x4000
        self.channel_refresh_time = channel_refresh_time
        self.integrity_key: bytes | None = None
        self.lifetime = lifetime
        self.mapped_address: tuple[str, int] | None = None
        self.nonce: bytes | None = None
        self.password = password
        self.receiver: asyncio.DatagramProtocol | None = None
        self.realm: str | None = None
        self.refresh_task: asyncio.Task[None] | None = None
        self.relayed_address: tuple[str, int] | None = None
        self.server = server
        self.transactions: dict[bytes, stun.Transaction] = {}
        self.username = username

    async def channel_bind(self, channel_number: int, addr: tuple[str, int]) -> None:
        request = stun.Message(
            message_method=stun.Method.CHANNEL_BIND, message_class=stun.Class.REQUEST
        )
        request.attributes["CHANNEL-NUMBER"] = channel_number
        request.attributes["XOR-PEER-ADDRESS"] = addr
        await self.request_with_retry(request)
        logger.info("TURN channel bound %d %s", channel_number, addr)

    async def connect(self) -> tuple[str, int]:
        """
        Create a TURN allocation.
        """
        request = stun.Message(
            message_method=stun.Method.ALLOCATE, message_class=stun.Class.REQUEST
        )
        request.attributes["LIFETIME"] = self.lifetime
        request.attributes["REQUESTED-TRANSPORT"] = UDP_TRANSPORT
        response, _ = await self.request_with_retry(request)

        # The success response contains these attributes (RFC 8656 section 7.2).
        for name in ["LIFETIME", "XOR-MAPPED-ADDRESS", "XOR-RELAYED-ADDRESS"]:
            if name not in response.attributes:
                raise ConnectionError(f"TURN allocation response is missing {name}")

        time_to_expiry = response.attributes["LIFETIME"]
        self.relayed_address = response.attributes["XOR-RELAYED-ADDRESS"]

        # The related address of the relayed candidate (RFC 8839 section 5.1).
        self.mapped_address = response.attributes["XOR-MAPPED-ADDRESS"]
        logger.info(
            "TURN allocation created %s (expires in %d seconds)",
            self.relayed_address,
            time_to_expiry,
        )

        # Periodically refresh the allocation.
        self.refresh_task = asyncio.create_task(self.refresh(time_to_expiry))

        return self.relayed_address

    def connection_lost(self, exc: Exception | None) -> None:
        logger.debug("%s connection_lost(%s)", self, exc)
        if self.receiver is not None:
            self.receiver.connection_lost(exc)

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        logger.debug("%s connection_made(%s)", self, transport)
        self.transport = transport

    def datagram_received(self, data: bytes | str, addr: tuple[str, int]) -> None:
        data = cast(bytes, data)

        # demultiplex channel data
        if len(data) >= 4 and is_channel_data(data):
            channel, length = struct.unpack("!HH", data[0:4])

            if len(data) >= length + 4 and self.receiver is not None:
                peer_address = self.channel_to_peer.get(channel)
                if peer_address:
                    payload = data[4 : 4 + length]
                    self.receiver.datagram_received(payload, peer_address)

            return

        try:
            message = stun.parse_message(data)
            logger.debug("%s < %s %s", self, addr, message)
        except ValueError:
            return

        if (
            message.message_class == stun.Class.RESPONSE
            or message.message_class == stun.Class.ERROR
        ) and message.transaction_id in self.transactions:
            transaction = self.transactions[message.transaction_id]
            transaction.response_received(message, addr)
        elif (
            message.message_method == stun.Method.DATA
            and message.message_class == stun.Class.INDICATION
            and "DATA" in message.attributes
            and "XOR-PEER-ADDRESS" in message.attributes
            and self.receiver is not None
        ):
            # Discard data from peers without a permission (RFC 8656 section 11.4).
            peer_address = message.attributes["XOR-PEER-ADDRESS"]
            if any(peer[0] == peer_address[0] for peer in self.peer_to_channel):
                self.receiver.datagram_received(
                    message.attributes["DATA"], peer_address
                )

    async def delete(self) -> None:
        """
        Delete the TURN allocation.
        """
        if self.refresh_task:
            self.refresh_task.cancel()
            self.refresh_task = None

        # The allocation was already given up, for instance if it could not be
        # refreshed.
        if self.transport.is_closing():
            return

        request = stun.Message(
            message_method=stun.Method.REFRESH, message_class=stun.Class.REQUEST
        )
        request.attributes["LIFETIME"] = 0
        try:
            await self.request_with_retry(request)
        except stun.TransactionError as exc:
            # Shut down anyway, the server frees the allocation once it expires
            # (RFC 8656 section 6).
            logger.info(
                "TURN allocation deletion failed %s: %s", self.relayed_address, exc
            )
        else:
            logger.info("TURN allocation deleted %s", self.relayed_address)
        finally:
            # Close the transport even if the deletion is cancelled, for instance
            # when the event loop shuts down, otherwise its socket leaks.
            self.transport.close()

    async def refresh(self, time_to_expiry: int) -> None:
        """
        Periodically refresh the TURN allocation.
        """
        while True:
            await asyncio.sleep(5 / 6 * time_to_expiry)

            request = stun.Message(
                message_method=stun.Method.REFRESH, message_class=stun.Class.REQUEST
            )
            request.attributes["LIFETIME"] = self.lifetime
            try:
                response, _ = await self.request_with_retry(request)

                # The success response contains LIFETIME (RFC 8656 section 8.2).
                if "LIFETIME" not in response.attributes:
                    raise ConnectionError("TURN refresh response is missing LIFETIME")
            except (ConnectionError, stun.TransactionError) as exc:
                # The allocation expires unless it is refreshed (RFC 8656 section
                # 8), so stop using it.
                logger.info(
                    "TURN allocation refresh failed %s: %s", self.relayed_address, exc
                )
                self.transport.close()
                return

            time_to_expiry = response.attributes["LIFETIME"]
            logger.info(
                "TURN allocation refreshed %s (expires in %d seconds)",
                self.relayed_address,
                time_to_expiry,
            )

    async def request(
        self, request: stun.Message
    ) -> tuple[stun.Message, tuple[str, int]]:
        """
        Execute a STUN transaction and return the response.
        """
        assert request.transaction_id not in self.transactions

        if self.integrity_key:
            self.__add_authentication(request)

        # Responses to an authenticated request must be authenticated with the
        # same key (RFC 8489 section 9.2.5).
        transaction = stun.Transaction(
            request,
            self.server,
            self,
            integrity_key=self.integrity_key,
            long_term_credential=True,
        )
        self.transactions[request.transaction_id] = transaction
        try:
            return await transaction.run()
        finally:
            del self.transactions[request.transaction_id]

    async def request_with_retry(
        self, request: stun.Message
    ) -> tuple[stun.Message, tuple[str, int]]:
        """
        Execute a STUN transaction and return the response.

        On recoverable errors it will retry the request.
        """
        try:
            response, addr = await self.request(request)
        except stun.TransactionFailed as e:
            error_code = e.response.error_code
            if (
                "NONCE" in e.response.attributes
                and self.username is not None
                and self.password is not None
                and (
                    (error_code == 401 and "REALM" in e.response.attributes)
                    or (error_code == 438 and self.realm is not None)
                )
            ):
                # Update the long-term credentials.
                self.nonce = e.response.attributes["NONCE"]
                if error_code == 401:
                    self.realm = e.response.attributes["REALM"]
                # The realm was either just received or is already known.
                assert self.realm is not None
                self.integrity_key = make_integrity_key(
                    self.username, self.realm, self.password
                )

                # Retry the request with authentication.
                request.transaction_id = random_transaction_id()
                response, addr = await self.request(request)
            else:
                raise

        return response, addr

    async def send_data(self, data: bytes, addr: tuple[str, int]) -> None:
        """
        Send data to a remote host via the TURN server.
        """
        # if a channel is being bound for the peer, wait
        if addr in self.peer_connect_waiters:
            loop = asyncio.get_running_loop()
            waiter = loop.create_future()
            self.peer_connect_waiters[addr].append(waiter)
            await waiter

        channel = self.peer_to_channel.get(addr)
        now = time.time()
        if channel is None:
            # Retry a failed binding with the same number, which is always
            # allowed for the same peer (RFC 8656 section 12).
            channel = self.peer_to_failed_channel.pop(addr, None)
            if channel is None:
                if self.channel_number > CHANNEL_NUMBER_MAX:
                    raise ConnectionError("No TURN channel number available")
                channel = self.channel_number
                self.channel_number += 1

            # bind channel
            self.peer_connect_waiters[addr] = []
            try:
                await self.channel_bind(channel, addr)
            except Exception as exc:
                # Fail the queued sends, so that a later send binds again.
                self.peer_to_failed_channel[addr] = channel
                for waiter in self.peer_connect_waiters.pop(addr):
                    waiter.set_exception(exc)
                raise

            # update state
            self.channel_refresh_at[channel] = now + self.channel_refresh_time
            self.channel_to_peer[channel] = addr
            self.peer_to_channel[addr] = channel

            # notify waiters
            for waiter in self.peer_connect_waiters.pop(addr):
                waiter.set_result(None)
        elif now > self.channel_refresh_at[channel]:
            # refresh channel
            await self.channel_bind(channel, addr)

            # update state
            self.channel_refresh_at[channel] = now + self.channel_refresh_time

        header = struct.pack("!HH", channel, len(data))
        self._send(header + data)

    def send_stun(self, message: stun.Message, addr: tuple[str, int]) -> None:
        """
        Send a STUN message to the TURN server.
        """
        logger.debug("%s > %s %s", self, addr, message)
        self._send(bytes(message))

    def __add_authentication(self, request: stun.Message) -> None:
        # Authentication is only added once credentials are known.
        assert self.integrity_key is not None
        request.attributes["USERNAME"] = self.username
        request.attributes["NONCE"] = self.nonce
        request.attributes["REALM"] = self.realm
        request.add_message_integrity(self.integrity_key)


class TurnClientTcpProtocol(TurnClientMixin, TurnStreamMixin, asyncio.Protocol):
    """
    Protocol for handling TURN over TCP.
    """

    transport: asyncio.Transport

    def _send(self, data: bytes) -> None:
        self.transport.write(self._padded(data))

    def __repr__(self) -> str:
        return "turn/tcp"


class TurnClientUdpProtocol(TurnClientMixin, asyncio.DatagramProtocol):
    """
    Protocol for handling TURN over UDP.
    """

    transport: asyncio.DatagramTransport

    def _send(self, data: bytes) -> None:
        self.transport.sendto(data)

    def __repr__(self) -> str:
        return "turn/udp"


TurnClientProtocol = TurnClientTcpProtocol | TurnClientUdpProtocol


class TurnTransport:
    """
    Behaves like a Datagram transport, but uses a TURN allocation.
    """

    def __init__(self, inner_protocol: TurnClientProtocol) -> None:
        self.__close_task: asyncio.Task[None] | None = None
        self.__inner_protocol = inner_protocol
        self.__relayed_address: tuple[str, int] | None = None
        self.__send_tasks: set[asyncio.Task[None]] = set()

    def close(self) -> None:
        """
        Close the transport.

        Data passed to `sendto()` before closing is still sent, later data is
        ignored. After the TURN allocation has been deleted, the protocol's
        `connection_lost()` method will be called with None as its argument.
        """
        if self.__close_task is not None:
            return

        self.__close_task = asyncio.create_task(self._close())

    def get_extra_info(self, name: str, default: Any = None) -> Any:
        """
        Return optional transport information.

        - `'related_address'`: the mapped address in the Allocate response
        - `'sockname'`: the relayed address
        """
        if name == "related_address":
            return self.__inner_protocol.mapped_address
        elif name == "sockname":
            return self.__relayed_address
        return default

    def sendto(self, data: bytes, addr: tuple[str, int]) -> None:
        """
        Sends the `data` bytes to the remote peer given `addr`.

        This will bind a TURN channel as necessary. If sending fails, the
        protocol's `error_received()` method is called with the exception.
        Data is ignored once the transport is closed, or the TURN allocation is
        lost.
        """
        if (
            self.__close_task is not None
            or self.__inner_protocol.transport.is_closing()
        ):
            return

        task = asyncio.create_task(self.__inner_protocol.send_data(data, addr))
        self.__send_tasks.add(task)
        task.add_done_callback(self._send_done)

    async def _close(self) -> None:
        await self.__inner_protocol.delete()

        # Sends still waiting for a channel binding are pointless now.
        for task in self.__send_tasks:
            task.cancel()

    async def _connect(self, protocol: asyncio.DatagramProtocol) -> None:
        self.__relayed_address = await self.__inner_protocol.connect()

        # Once the allocation has succeeded, notify the protocol
        # and start relaying received data.
        self.__inner_protocol.receiver = protocol
        protocol.connection_made(cast(asyncio.DatagramTransport, self))

    def _send_done(self, task: asyncio.Task[None]) -> None:
        self.__send_tasks.discard(task)
        if not task.cancelled():
            exc = task.exception()
            if exc is not None:
                assert self.__inner_protocol.receiver is not None
                self.__inner_protocol.receiver.error_received(cast(Exception, exc))


async def create_turn_endpoint(
    protocol_factory: Callable[[], _ProtocolT],
    server_addr: tuple[str, int],
    username: str | None,
    password: str | None,
    lifetime: int = DEFAULT_ALLOCATION_LIFETIME,
    channel_refresh_time: int = DEFAULT_CHANNEL_REFRESH_TIME,
    ssl: bool | ssl.SSLContext | None = None,
    transport: str = "udp",
) -> tuple[TurnTransport, _ProtocolT]:
    """
    Create datagram connection relayed over TURN.
    """
    loop = asyncio.get_running_loop()
    inner_protocol: TurnClientProtocol
    inner_transport: asyncio.BaseTransport
    if transport == "tcp":
        inner_transport, inner_protocol = await loop.create_connection(
            lambda: TurnClientTcpProtocol(
                server_addr,
                username=username,
                password=password,
                lifetime=lifetime,
                channel_refresh_time=channel_refresh_time,
            ),
            host=server_addr[0],
            port=server_addr[1],
            ssl=ssl,
        )
    else:
        inner_transport, inner_protocol = await loop.create_datagram_endpoint(
            lambda: TurnClientUdpProtocol(
                server_addr,
                username=username,
                password=password,
                lifetime=lifetime,
                channel_refresh_time=channel_refresh_time,
            ),
            remote_addr=server_addr,
        )
        sock = inner_transport.get_extra_info("socket")
        if sock is not None:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, UDP_SOCKET_BUFFER_SIZE)

    try:
        protocol = protocol_factory()
        turn_transport = TurnTransport(inner_protocol)
        await turn_transport._connect(protocol)
    except BaseException:
        # Close the transport on any error, including a CancelledError raised when
        # candidate gathering times out, otherwise its socket leaks.
        inner_transport.close()
        raise

    return turn_transport, protocol
