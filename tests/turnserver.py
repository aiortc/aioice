import argparse
import asyncio
import contextlib
import datetime
import functools
import ipaddress
import logging
import os
import ssl
import struct
import tempfile
import time
from collections.abc import AsyncGenerator, Callable
from typing import cast

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from aioice import stun
from aioice.ice import get_host_addresses
from aioice.turn import (
    DEFAULT_ALLOCATION_LIFETIME,
    UDP_TRANSPORT,
    TurnStreamMixin,
    is_channel_data,
    make_integrity_key,
)
from aioice.utils import random_string

logger = logging.getLogger("turn")

CHANNEL_RANGE = range(0x4000, 0x7FFF)

Address = tuple[str, int]


def get_server_address() -> str:
    return get_host_addresses(use_ipv4=True, use_ipv6=False)[0]


@functools.cache
def get_tls_credentials() -> tuple[str, ssl.SSLContext]:
    """
    Create a self-signed certificate for the server address, returning it in PEM
    format along with an SSL context for the servers to present it.
    """
    address = get_server_address()
    key = ed25519.Ed25519PrivateKey.generate()
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, address)])

    # The start date is truncated to the second, and OpenSSL checks it against a
    # clock which can lag behind, so start a second earlier.
    now = datetime.datetime.now(datetime.UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(seconds=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.IPAddress(ipaddress.ip_address(address))]
            ),
            critical=False,
        )
        .sign(key, None)
    )
    certificate_pem = certificate.public_bytes(serialization.Encoding.PEM).decode()
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()

    # The SSL context can only load a certificate and key from a file.
    ssl_context = ssl.SSLContext(protocol=ssl.PROTOCOL_TLS_SERVER)
    with tempfile.TemporaryDirectory() as directory:
        path = os.path.join(directory, "turnserver.pem")
        with open(path, "w") as fp:
            fp.write(certificate_pem + key_pem)
        ssl_context.load_cert_chain(path)

    return certificate_pem, ssl_context


class Allocation(asyncio.DatagramProtocol):
    def __init__(
        self,
        client_address: Address,
        client_protocol: "TurnServerMixin",
        expiry: float,
        username: str,
    ) -> None:
        self.channel_to_peer: dict[int, Address] = {}
        self.peer_to_channel: dict[Address, int] = {}

        self.client_address = client_address
        self.client_protocol = client_protocol
        self.expiry = expiry
        self.username = username

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.relayed_address = transport.get_extra_info("sockname")
        self.transport = cast(asyncio.DatagramTransport, transport)

    def datagram_received(self, data: bytes, addr: Address) -> None:
        """
        Relay data from peer to client.
        """
        channel = self.peer_to_channel.get(addr)
        if channel:
            self.client_protocol._send(
                struct.pack("!HH", channel, len(data)) + data, self.client_address
            )
        elif any(peer[0] == addr[0] for peer in self.peer_to_channel):
            # Permissions only cover the IP address (RFC 8656 section 9).
            message = stun.Message(
                message_method=stun.Method.DATA,
                message_class=stun.Class.INDICATION,
            )
            message.attributes["XOR-PEER-ADDRESS"] = addr
            message.attributes["DATA"] = data
            self.client_protocol.send_stun(message, self.client_address)


AllocationKey = tuple["TurnServerMixin", Address]


class TurnServerMixin:
    _send: Callable[[bytes, Address], None]

    def __init__(self, server: "TurnServer") -> None:
        self.server = server

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport

    def datagram_received(self, data: bytes, addr: Address) -> None:
        # Demultiplex channel data.
        if len(data) >= 4 and is_channel_data(data):
            channel, length = struct.unpack("!HH", data[0:4])
            allocation = self.server.allocations.get((self, addr))

            if len(data) >= length + 4 and allocation:
                peer_address = allocation.channel_to_peer.get(channel)
                if peer_address:
                    payload = data[4 : 4 + length]
                    allocation.transport.sendto(payload, peer_address)

            return

        try:
            message = stun.parse_message(data)
        except ValueError:
            return
        logger.debug("< %s %s", addr, message)

        assert message.message_class == stun.Class.REQUEST
        response: stun.Message | None = None

        if message.message_method == stun.Method.BINDING:
            response = self.handle_binding(message, addr)
            self.send_stun(response, addr)
            return

        # Check authentication (RFC 8489 section 9.2.4).
        integrity_key = b""
        if "MESSAGE-INTEGRITY" not in message.attributes:
            # Message is missing MESSAGE-INTEGRITY.
            response = self.error_response(message, 401, "Unauthorized")
        elif (
            "USERNAME" not in message.attributes
            or "REALM" not in message.attributes
            or "NONCE" not in message.attributes
        ):
            # Message is missing USERNAME, REALM or NONCE.
            response = self.error_response(
                message, 400, "Missing USERNAME, REALM or NONCE attribute"
            )
        elif message.attributes["USERNAME"] not in self.server.users:
            # The USERNAME is unknown.
            response = self.error_response(message, 401, "Unauthorized")
        else:
            username = message.attributes["USERNAME"]
            password = self.server.users[username]
            integrity_key = make_integrity_key(username, self.server.realm, password)
            if not message.check_message_integrity(integrity_key):
                # The password does not match.
                response = self.error_response(message, 401, "Unauthorized")
        if response is not None:
            self.send_stun(response, addr)
            return

        # Generate a failure for test purposes. Like other responses to an
        # authenticated request, it is signed, unless it is a 401 or 438 error
        # giving new credentials.
        if self.server.simulated_failure:
            response = self.error_response(message, *self.server.simulated_failure)
            self.server.simulated_failure = None
            if response.error_code not in (401, 438):
                response.add_message_integrity(integrity_key)
            self.send_stun(response, addr)
            return

        if message.message_method == stun.Method.ALLOCATE:
            asyncio.create_task(self.handle_allocate(message, addr, integrity_key))
            return
        elif message.message_method == stun.Method.REFRESH:
            response = self.handle_refresh(message, addr)
        elif message.message_method == stun.Method.CHANNEL_BIND:
            response = self.handle_channel_bind(message, addr)
        else:
            response = self.error_response(
                message, 400, "Unsupported STUN request method"
            )

        response.add_message_integrity(integrity_key)
        self.send_stun(response, addr)

    async def handle_allocate(
        self, message: stun.Message, addr: Address, integrity_key: bytes
    ) -> None:
        key = (self, addr)
        if key in self.server.allocations:
            response = self.error_response(message, 437, "Allocation already exists")
        elif "REQUESTED-TRANSPORT" not in message.attributes:
            response = self.error_response(
                message, 400, "Missing REQUESTED-TRANSPORT attribute"
            )
        elif message.attributes["REQUESTED-TRANSPORT"] != UDP_TRANSPORT:
            response = self.error_response(
                message, 442, "Unsupported transport protocol"
            )
        else:
            lifetime = message.attributes.get("LIFETIME", DEFAULT_ALLOCATION_LIFETIME)
            lifetime = min(lifetime, self.server.maximum_lifetime)

            # create allocation
            loop = asyncio.get_running_loop()
            _, allocation = await loop.create_datagram_endpoint(
                lambda: Allocation(
                    client_address=addr,
                    client_protocol=self,
                    expiry=time.time() + lifetime,
                    username=message.attributes["USERNAME"],
                ),
                local_addr=("127.0.0.1", 0),
            )
            self.server.allocations[key] = allocation

            logger.info("Allocation created %s", allocation.relayed_address)

            # build response
            response = stun.Message(
                message_method=message.message_method,
                message_class=stun.Class.RESPONSE,
                transaction_id=message.transaction_id,
            )
            response.attributes["LIFETIME"] = lifetime
            response.attributes["XOR-MAPPED-ADDRESS"] = addr
            response.attributes["XOR-RELAYED-ADDRESS"] = allocation.relayed_address

        # send response
        response.add_message_integrity(integrity_key)
        self.send_stun(response, addr)

    def handle_binding(self, message: stun.Message, addr: Address) -> stun.Message:
        response = stun.Message(
            message_method=message.message_method,
            message_class=stun.Class.RESPONSE,
            transaction_id=message.transaction_id,
        )
        response.attributes["XOR-MAPPED-ADDRESS"] = addr
        return response

    def handle_channel_bind(self, message: stun.Message, addr: Address) -> stun.Message:
        try:
            key = (self, addr)
            allocation = self.server.allocations[key]
        except KeyError:
            return self.error_response(message, 437, "Allocation does not exist")

        if message.attributes["USERNAME"] != allocation.username:
            return self.error_response(message, 441, "Wrong credentials")

        for attr in ["CHANNEL-NUMBER", "XOR-PEER-ADDRESS"]:
            if attr not in message.attributes:
                return self.error_response(message, 400, f"Missing {attr} attribute")

        channel: int = message.attributes["CHANNEL-NUMBER"]
        peer_address: Address = message.attributes["XOR-PEER-ADDRESS"]
        if channel not in CHANNEL_RANGE:
            return self.error_response(
                message, 400, "Channel number is outside valid range"
            )

        if allocation.channel_to_peer.get(channel) not in [None, peer_address]:
            return self.error_response(
                message, 400, "Channel is already bound to another peer"
            )
        if allocation.peer_to_channel.get(peer_address) not in [None, channel]:
            return self.error_response(
                message, 400, "Peer is already bound to another channel"
            )

        # register channel
        allocation.channel_to_peer[channel] = peer_address
        allocation.peer_to_channel[peer_address] = channel

        # build response
        response = stun.Message(
            message_method=message.message_method,
            message_class=stun.Class.RESPONSE,
            transaction_id=message.transaction_id,
        )
        return response

    def handle_refresh(
        self, message: stun.Message, addr: tuple[str, int]
    ) -> stun.Message:
        try:
            key = (self, addr)
            allocation = self.server.allocations[key]
        except KeyError:
            return self.error_response(message, 437, "Allocation does not exist")

        if message.attributes["USERNAME"] != allocation.username:
            return self.error_response(message, 441, "Wrong credentials")

        if "LIFETIME" not in message.attributes:
            return self.error_response(message, 400, "Missing LIFETIME attribute")

        # refresh allocation
        lifetime = min(message.attributes["LIFETIME"], self.server.maximum_lifetime)
        if lifetime:
            logger.info("Allocation refreshed %s", allocation.relayed_address)
            allocation.expiry = time.time() + lifetime
        else:
            logger.info("Allocation deleted %s", allocation.relayed_address)
            self.server._remove_allocation(key)

        # build response
        response = stun.Message(
            message_method=message.message_method,
            message_class=stun.Class.RESPONSE,
            transaction_id=message.transaction_id,
        )
        response.attributes["LIFETIME"] = lifetime
        return response

    def error_response(
        self, request: stun.Message, code: int, message: str
    ) -> stun.Message:
        """
        Build an error response for the given request.
        """
        response = stun.Message(
            message_method=request.message_method,
            message_class=stun.Class.ERROR,
            transaction_id=request.transaction_id,
        )
        response.attributes["ERROR-CODE"] = (code, message)
        if code in (401, 438):
            response.attributes["NONCE"] = random_string(16).encode("ascii")
            response.attributes["REALM"] = self.server.realm
        return response

    def send_stun(self, message: stun.Message, addr: Address) -> None:
        logger.debug("> %s %s", addr, message)
        self._send(bytes(message), addr)


class TurnServerTcpProtocol(TurnServerMixin, TurnStreamMixin, asyncio.Protocol):
    transport: asyncio.Transport

    def _send(self, data: bytes, addr: Address) -> None:
        self.transport.write(self._padded(data))


class TurnServerUdpProtocol(TurnServerMixin, asyncio.DatagramProtocol):
    transport: asyncio.DatagramTransport

    def _send(self, data: bytes, addr: Address) -> None:
        self.transport.sendto(data, addr)


class TurnServer:
    """
    STUN / TURN server.
    """

    def __init__(self, realm: str = "test", users: dict[str, str] = {}) -> None:
        self.allocations: dict[AllocationKey, Allocation] = {}
        self.maximum_lifetime = 3600
        self.realm = realm
        self.simulated_failure: tuple[int, str] | None = None
        self.users = users

        self._expire_task: asyncio.Task[None] | None = None

    async def close(self) -> None:
        # stop expiry loop
        if self._expire_task is not None:
            self._expire_task.cancel()

        # close allocations
        for key in list(self.allocations.keys()):
            self._remove_allocation(key)

        # shutdown servers
        self.tcp_server.close()
        self.tls_server.close()
        self.udp_server.transport.close()
        await asyncio.gather(
            self.tcp_server.wait_closed(), self.tls_server.wait_closed()
        )

    async def listen(self, port: int = 0, tls_port: int = 0) -> None:
        loop = asyncio.get_running_loop()
        hostaddr = get_server_address()

        # listen for TCP
        self.tcp_server = await loop.create_server(
            lambda: TurnServerTcpProtocol(server=self), host=hostaddr, port=port
        )
        self.tcp_address = self.tcp_server.sockets[0].getsockname()
        logger.info("Listening for TCP on %s", self.tcp_address)

        # listen for UDP
        transport, self.udp_server = await loop.create_datagram_endpoint(
            lambda: TurnServerUdpProtocol(server=self), local_addr=(hostaddr, port)
        )
        self.udp_address = transport.get_extra_info("sockname")
        logger.info("Listening for UDP on %s", self.udp_address)

        # listen for TLS
        _, ssl_context = get_tls_credentials()
        self.tls_server = await loop.create_server(
            lambda: TurnServerTcpProtocol(server=self),
            host=hostaddr,
            port=tls_port,
            ssl=ssl_context,
        )
        self.tls_address = self.tls_server.sockets[0].getsockname()
        logger.info("Listening for TLS on %s", self.tls_address)

        # start expiry loop
        self._expire_task = asyncio.create_task(self._expire_allocations())

    async def _expire_allocations(self) -> None:
        while True:
            now = time.time()
            for key, allocation in list(self.allocations.items()):
                if allocation.expiry < now:
                    logger.info("Allocation expired %s", allocation.relayed_address)
                    self._remove_allocation(key)

            await asyncio.sleep(1)

    def _remove_allocation(self, key: AllocationKey) -> None:
        allocation = self.allocations.pop(key)
        allocation.transport.close()


@contextlib.asynccontextmanager
async def run_turn_server(
    users: dict[str, str] = {},
) -> AsyncGenerator[TurnServer, None]:
    server = TurnServer(users=users)
    await server.listen()
    try:
        yield server
    finally:
        await server.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="STUN / TURN server")
    parser.add_argument("--verbose", "-v", action="count")
    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)

    async def main() -> None:
        srv = TurnServer(users={"foo": "bar"})
        await srv.listen(port=3478, tls_port=5349)
        await asyncio.Event().wait()

    asyncio.run(main())
