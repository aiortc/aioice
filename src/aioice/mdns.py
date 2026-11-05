import asyncio
import logging
import re
import socket
import uuid
from typing import Any, cast

import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdataset
import dns.rdatatype
import dns.zone

logger = logging.getLogger(__name__)

MDNS_ADDRESS = "224.0.0.251"
MDNS_PORT = 5353
MDNS_HOSTNAME_RE = re.compile(r"^[a-zA-Z0-9-]{1,63}\.local$")

MDNS_RDCLASS = dns.rdataclass.RdataClass.make(dns.rdataclass.IN | 0x8000)


def create_mdns_hostname() -> str:
    return str(uuid.uuid4()) + ".local"


def is_mdns_hostname(name: str) -> bool:
    return MDNS_HOSTNAME_RE.match(name) is not None


class MDnsProtocol(asyncio.DatagramProtocol):
    transport: asyncio.DatagramTransport

    def __init__(self) -> None:
        self.__closed: asyncio.Future[bool] = asyncio.Future()
        self.__joined = False
        self.zone = dns.zone.Zone("", relativize=False, rdclass=MDNS_RDCLASS)
        self.queries: dict[dns.name.Name, set[asyncio.Future[str]]] = {}

    def connection_lost(self, exc: Exception | None) -> None:
        # Abort any outstanding queries, except those which were cancelled.
        for name, futures in list(self.queries.items()):
            for future in futures:
                if not future.done():
                    future.set_exception(TimeoutError)
        self.__closed.set_result(True)

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = cast(asyncio.DatagramTransport, transport)

    def datagram_received(self, data: bytes | str, addr: tuple[Any, ...]) -> None:
        # Parse the message.
        try:
            message = dns.message.from_wire(cast(bytes, data))
        except dns.exception.FormError:
            return

        if isinstance(message, dns.message.QueryMessage):
            # Answer the questions.
            for question in message.question:
                rdtypes: list[dns.rdatatype.RdataType] = []
                if question.rdtype in (
                    dns.rdatatype.ANY,
                    dns.rdatatype.A,
                    dns.rdatatype.AAAA,
                ):
                    rdtypes += [dns.rdatatype.A, dns.rdatatype.AAAA]

                response = dns.message.QueryMessage(id=0)
                response.flags |= dns.flags.QR
                response.flags |= dns.flags.AA

                for rdtype in rdtypes:
                    try:
                        response.answer.append(
                            self.zone.find_rrset(name=question.name, rdtype=rdtype)
                        )
                    except KeyError:
                        continue
                if response.answer:
                    self.transport.sendto(response.to_wire(), (MDNS_ADDRESS, MDNS_PORT))

            # Handle the answers.
            for answer in message.answer:
                for item in answer:
                    item = item.to_generic()
                    if (
                        isinstance(item, dns.rdata.GenericRdata)
                        and item.rdclass == MDNS_RDCLASS
                        and item.rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA)
                    ):
                        if item.rdtype == dns.rdatatype.A:
                            result = socket.inet_ntop(socket.AF_INET, item.data)
                        else:
                            result = socket.inet_ntop(socket.AF_INET6, item.data)
                        # A cancelled query stays listed until its task resumes.
                        for future in self.queries.pop(answer.name, []):
                            if not future.done():
                                future.set_result(result)

    # custom

    async def close(self) -> None:
        self.transport.close()
        await self.__closed

    async def publish(self, hostname: str, addr: str) -> None:
        # Queries are only received once the group is joined.
        self.__join()

        name = dns.name.from_text(hostname)
        try:
            data = socket.inet_pton(socket.AF_INET, addr)
            rdtype = dns.rdatatype.A
        except OSError:
            data = socket.inet_pton(socket.AF_INET6, addr)
            rdtype = dns.rdatatype.AAAA

        rdata = dns.rdata.GenericRdata(rdclass=MDNS_RDCLASS, rdtype=rdtype, data=data)
        self.zone.replace_rdataset(name, dns.rdataset.from_rdata(120, rdata))

    async def resolve(self, hostname: str, timeout: float | None = 1.0) -> str | None:
        # A closed protocol can neither send queries nor receive answers.
        if self.transport.is_closing():
            return None

        # Answers are only received once the group is joined.
        try:
            self.__join()
        except OSError as exc:
            logger.info("Could not join the mDNS group: %s", exc)
            return None

        name = dns.name.from_text(hostname)
        future: asyncio.Future[str] = asyncio.get_running_loop().create_future()

        if name in self.queries:
            # A query for this name is already pending.
            self.queries[name].add(future)
        else:
            # No query for this name is pending, send a request.
            self.queries[name] = {future}
            message = dns.message.make_query(name, rdtype=dns.rdatatype.A)
            message.id = 0
            message.flags = 0
            self.transport.sendto(message.to_wire(), (MDNS_ADDRESS, MDNS_PORT))

        try:
            return await asyncio.wait_for(future, timeout=timeout)
        except TimeoutError:
            return None
        finally:
            if name in self.queries:
                self.queries[name].discard(future)
                if not self.queries[name]:
                    del self.queries[name]

    def __join(self) -> None:
        """
        Join the mDNS group, unless it is already joined.

        Joining fails on a host without multicast, which may gain it later, so
        a failed join is retried on the next call.
        """
        if not self.__joined:
            sock = self.transport.get_extra_info("socket")
            sock.setsockopt(
                socket.IPPROTO_IP,
                socket.IP_ADD_MEMBERSHIP,
                socket.inet_aton(MDNS_ADDRESS) + b"\x00\x00\x00\x00",
            )
            self.__joined = True


async def create_mdns_protocol() -> MDnsProtocol:
    """
    Create an mDNS protocol.

    A single socket, bound to the wildcard address, both sends and receives:
    a socket bound to the group address cannot send on macOS, and Windows
    does not allow binding to it. The group is joined when the protocol is
    first used.
    """
    loop = asyncio.get_running_loop()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if hasattr(socket, "SO_REUSEPORT"):
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    sock.bind(("", MDNS_PORT))

    _, protocol = await loop.create_datagram_endpoint(MDnsProtocol, sock=sock)

    return protocol
