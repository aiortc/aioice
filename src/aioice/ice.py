import asyncio
import copy
import enum
import ipaddress
import itertools
import logging
import random
import re
import secrets
import socket
import threading
from collections import deque
from collections.abc import Callable
from typing import Any, cast

import ifaddr

from . import mdns, stun, turn
from .candidate import Candidate, candidate_foundation, candidate_priority
from .utils import random_string

logger = logging.getLogger(__name__)

ICE_COMPLETED = 1
ICE_FAILED = 2

CONSENT_FAILURES = 6
CONSENT_INTERVAL = 5

# Maximum number of early checks kept until connect(). The RFCs set no such
# limit, so use the one on connectivity checks (RFC 8445 section 19.5.1).
MAX_EARLY_CHECKS = 100

connection_id = itertools.count()
protocol_id = itertools.count()

_mdns = threading.local()


class TransportPolicy(enum.Enum):
    ALL = 0
    """
    All ICE candidates will be considered.
    """

    RELAY = 1
    """
    Only ICE candidates whose IP addresses are being relayed,
    such as those being passed through a TURN server,
    will be considered.

    Candidates are only gathered from a TURN server, so none are gathered
    without one, even with a STUN server. Remote mDNS candidates are
    ignored, as they cannot be paired with relayed candidates, and the
    related address of relayed candidates is hidden.
    """


async def get_or_create_mdns_protocol(subscriber: object) -> mdns.MDnsProtocol:
    if not hasattr(_mdns, "lock"):
        _mdns.lock = asyncio.Lock()
        _mdns.protocol = None
        _mdns.subscribers = set()
    async with _mdns.lock:
        if _mdns.protocol is None:
            _mdns.protocol = await mdns.create_mdns_protocol()
        _mdns.subscribers.add(subscriber)
    return cast(mdns.MDnsProtocol, _mdns.protocol)


async def unref_mdns_protocol(subscriber: object) -> None:
    if hasattr(_mdns, "lock"):
        async with _mdns.lock:
            _mdns.subscribers.discard(subscriber)
            if _mdns.protocol and not _mdns.subscribers:
                await _mdns.protocol.close()
                _mdns.protocol = None


def candidate_pair_priority(
    local: Candidate, remote: Candidate, ice_controlling: bool
) -> int:
    """
    See RFC 5245 - 5.7.2. Computing Pair Priority and Ordering Pairs
    """
    G = ice_controlling and local.priority or remote.priority
    D = ice_controlling and remote.priority or local.priority
    return (1 << 32) * min(G, D) + 2 * max(G, D) + (G > D and 1 or 0)


def get_host_addresses(use_ipv4: bool, use_ipv6: bool) -> list[str]:
    """
    Get local IP addresses.
    """
    addresses = []
    for adapter in ifaddr.get_adapters():
        for ip in adapter.ips:
            if isinstance(ip.ip, str) and use_ipv4 and ip.ip != "127.0.0.1":
                addresses.append(ip.ip)
            elif use_ipv6 and ip.ip[0] != "::1" and ip.ip[2] == 0:
                addresses.append(ip.ip[0])
    return addresses


async def relayed_candidate(
    *,
    component: int,
    hide_related_address: bool,
    protocol_factory: Callable[[], "StunProtocol"],
    turn_server: tuple[str, int],
    turn_username: str | None,
    turn_password: str | None,
    turn_ssl: bool,
    turn_transport: str,
) -> tuple[Candidate, "StunProtocol"]:
    """
    Connect to a TURN server to obtain a relayed candidate.
    """
    # Connect to TURN server.
    _, protocol = await turn.create_turn_endpoint(
        protocol_factory,
        server_addr=turn_server,
        username=turn_username,
        password=turn_password,
        ssl=turn_ssl,
        transport=turn_transport,
    )

    # Build relayed candidate.
    candidate_address = protocol.transport.get_extra_info("sockname")
    related_address = protocol.transport.get_extra_info("related_address")
    if hide_related_address:
        # Do not expose a disallowed candidate through the related address
        # (RFC 9429 section 3.5.3), using the format of RFC 8839 section 5.1.
        if ipaddress.ip_address(candidate_address[0]).version == 4:
            related_address = ("0.0.0.0", 9)
        else:
            related_address = ("::", 9)
    protocol.local_candidate = Candidate(
        foundation=candidate_foundation("relay", "udp", candidate_address[0]),
        component=component,
        transport="udp",
        priority=candidate_priority(component, "relay"),
        host=candidate_address[0],
        port=candidate_address[1],
        type="relay",
        related_address=related_address[0],
        related_port=related_address[1],
    )
    return protocol.local_candidate, protocol


async def server_reflexive_candidate(
    protocol: "StunProtocol", stun_server: tuple[str, int]
) -> tuple[Candidate, None]:
    """
    Query STUN server to obtain a server-reflexive candidate.
    """
    # lookup address
    loop = asyncio.get_running_loop()
    stun_server = (
        await loop.run_in_executor(None, socket.gethostbyname, stun_server[0]),
        stun_server[1],
    )

    # perform STUN query
    request = stun.Message(
        message_method=stun.Method.BINDING, message_class=stun.Class.REQUEST
    )
    response, _ = await protocol.request(request, stun_server)

    local_candidate = protocol.local_candidate
    return Candidate(
        foundation=candidate_foundation("srflx", "udp", local_candidate.host),
        component=local_candidate.component,
        transport=local_candidate.transport,
        priority=candidate_priority(local_candidate.component, "srflx"),
        host=response.attributes["XOR-MAPPED-ADDRESS"][0],
        port=response.attributes["XOR-MAPPED-ADDRESS"][1],
        type="srflx",
        related_address=local_candidate.host,
        related_port=local_candidate.port,
    ), None


def sort_candidate_pairs(pairs: list["CandidatePair"], ice_controlling: bool) -> None:
    """
    Sort a list of candidate pairs.
    """

    def pair_priority(pair: CandidatePair) -> int:
        return -candidate_pair_priority(
            pair.local_candidate, pair.remote_candidate, ice_controlling
        )

    pairs.sort(key=pair_priority)


def validate_password(value: str) -> None:
    """
    Check the password is well-formed.

    See RFC 5245 - 15.4. "ice-ufrag" and "ice-pwd" Attributes
    """
    if not re.match("^[a-zA-Z0-9+/]{22,256}$", value):
        raise ValueError("Password must satisfy 22*256ice-char")


def validate_remote_candidate(candidate: Candidate, host: str) -> str:
    """
    Check the remote candidate is supported and return its canonical address.
    """
    if candidate.type not in ["host", "relay", "srflx"]:
        raise ValueError(f'Unexpected candidate type "{candidate.type}"')
    return str(ipaddress.ip_address(host))


def validate_username(value: str) -> None:
    """
    Check the username is well-formed.

    See RFC 5245 - 15.4. "ice-ufrag" and "ice-pwd" Attributes
    """
    if not re.match("^[a-zA-Z0-9+/]{4,256}$", value):
        raise ValueError("Username must satisfy 4*256ice-char")


class CandidatePair:
    def __init__(self, protocol: "StunProtocol", remote_candidate: Candidate) -> None:
        self.task: asyncio.Task[None] | None = None
        self.nominated = False
        self.protocol = protocol
        self.remote_candidate = remote_candidate
        self.remote_nominated = False
        self.state = CandidatePair.State.FROZEN

    def __repr__(self) -> str:
        return f"CandidatePair({self.local_addr} -> {self.remote_addr})"

    @property
    def component(self) -> int:
        return self.local_candidate.component

    @property
    def local_addr(self) -> tuple[str, int]:
        return (self.local_candidate.host, self.local_candidate.port)

    @property
    def local_candidate(self) -> Candidate:
        return self.protocol.local_candidate

    @property
    def remote_addr(self) -> tuple[str, int]:
        return (self.remote_candidate._network_host, self.remote_candidate.port)

    class State(enum.Enum):
        FROZEN = 0
        WAITING = 1
        IN_PROGRESS = 2
        SUCCEEDED = 3
        FAILED = 4


class StunProtocol(asyncio.DatagramProtocol):
    local_candidate: Candidate
    transport: asyncio.DatagramTransport

    def __init__(self, receiver: "Connection") -> None:
        self.__closed: asyncio.Future[bool] = asyncio.Future()
        self.id = next(protocol_id)
        self.receiver = receiver
        self.transactions: dict[bytes, stun.Transaction] = {}

    def connection_lost(self, exc: Exception | None) -> None:
        self.__log_debug("connection_lost(%s)", exc)
        if not self.__closed.done():
            self.receiver.protocol_lost(self)
            self.__closed.set_result(True)

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.__log_debug("connection_made(%s)", transport)
        self.transport = cast(asyncio.DatagramTransport, transport)

    def datagram_received(self, data: bytes | str, addr: tuple[Any, ...]) -> None:
        # Force an IPv6 four-tuple to a two-tuple.
        addr = (addr[0], addr[1])
        data = cast(bytes, data)

        try:
            message = stun.parse_message(data)
            self.__log_debug("< %s %s", addr, message)
        except ValueError:
            self.receiver.data_received(data, self.local_candidate.component)
            return

        if (
            message.message_class == stun.Class.RESPONSE
            or message.message_class == stun.Class.ERROR
        ) and message.transaction_id in self.transactions:
            transaction = self.transactions[message.transaction_id]
            transaction.response_received(message, addr)
        elif message.message_class == stun.Class.REQUEST:
            self.receiver.request_received(message, addr, self)

    def error_received(self, exc: Exception) -> None:
        self.__log_debug("error_received(%s)", exc)

    # custom

    async def close(self) -> None:
        self.transport.close()
        await self.__closed

    async def request(
        self,
        request: stun.Message,
        addr: tuple[str, int],
        integrity_key: bytes | None = None,
        retransmissions: int | None = None,
    ) -> tuple[stun.Message, tuple[str, int]]:
        """
        Execute a STUN transaction and return the response.
        """
        assert request.transaction_id not in self.transactions

        if integrity_key is not None:
            request.add_message_integrity(integrity_key)

        transaction = stun.Transaction(
            request,
            addr,
            self,
            retransmissions=retransmissions,
            integrity_key=integrity_key,
        )
        self.transactions[request.transaction_id] = transaction
        try:
            return await transaction.run()
        finally:
            del self.transactions[request.transaction_id]

    async def send_data(self, data: bytes, addr: tuple[str, int]) -> None:
        self.transport.sendto(data, addr)

    def send_stun(self, message: stun.Message, addr: tuple[str, int]) -> None:
        """
        Send a STUN message.
        """
        self.__log_debug("> %s %s", addr, message)
        self.transport.sendto(bytes(message), addr)

    def __log_debug(self, msg: str, *args: object) -> None:
        logger.debug("%s %s " + msg, self.receiver, self, *args)

    def __repr__(self) -> str:
        return f"protocol({self.id})"


class ConnectionEvent:
    pass


class ConnectionClosed(ConnectionEvent):
    pass


class Connection:
    """
    An ICE connection for a single media stream.

    :param ice_controlling: Whether the local peer has the controlling role.
    :param components: The number of components.
    :param stun_server: The address of the STUN server or `None`.
    :param turn_server: The address of the TURN server or `None`.
    :param turn_username: The username for the TURN server.
    :param turn_password: The password for the TURN server.
    :param turn_ssl: Whether to use TLS for the TURN server.
    :param turn_transport: The transport for TURN server, `"udp"` or `"tcp"`.
    :param use_ipv4: Whether to use IPv4 candidates.
    :param use_ipv6: Whether to use IPv6 candidates.
    :param transport_policy: The transport policy.
    :param local_username: An optional local username, otherwise a random one
                           will be generated.
    :param local_password: An optional local password, otherwise a random one
                           will be generated.
    """

    def __init__(
        self,
        ice_controlling: bool,
        components: int = 1,
        stun_server: tuple[str, int] | None = None,
        turn_server: tuple[str, int] | None = None,
        turn_username: str | None = None,
        turn_password: str | None = None,
        turn_ssl: bool = False,
        turn_transport: str = "udp",
        use_ipv4: bool = True,
        use_ipv6: bool = True,
        transport_policy: TransportPolicy = TransportPolicy.ALL,
        local_username: str | None = None,
        local_password: str | None = None,
    ) -> None:
        self.ice_controlling = ice_controlling

        if local_username is None:
            local_username = random_string(4)
        else:
            validate_username(local_username)

        if local_password is None:
            local_password = random_string(22)
        else:
            validate_password(local_password)

        #: Whether the remote party is an ICE Lite implementation.
        self.remote_is_lite = False
        #: Remote username, which you need to set.
        self.remote_username: str | None = None
        #: Remote password, which you need to set.
        self.remote_password: str | None = None

        self.stun_server = stun_server
        self.turn_server = turn_server
        self.turn_username = turn_username
        self.turn_password = turn_password
        self.turn_ssl = turn_ssl
        self.turn_transport = turn_transport

        # Private attributes.
        self._closed = False
        self._closing = False
        self._components = set(range(1, components + 1))
        self._check_list: list[CandidatePair] = []
        self._check_list_done = False
        self._check_list_state: asyncio.Queue[int] = asyncio.Queue()
        # Bound the memory used until connect(), dropping the oldest check.
        self._early_checks: deque[
            tuple[stun.Message, tuple[str, int], StunProtocol]
        ] = deque(maxlen=MAX_EARLY_CHECKS)
        self._early_checks_done = False
        self._event_waiter: asyncio.Future[ConnectionEvent] | None = None
        self._id = next(connection_id)
        self._local_candidates: list[Candidate] = []
        self._local_candidates_end = False
        self._local_candidates_start = False
        self._local_password = local_password
        self._local_username = local_username
        self._nominated: dict[int, CandidatePair] = {}
        self._nominating: set[int] = set()
        self._protocols: list[StunProtocol] = []
        self._remote_candidates: list[Candidate] = []
        self._remote_candidates_end = False
        self._remote_candidates_resolving = 0
        self._query_consent_task: asyncio.Task[None] | None = None
        self._queue: asyncio.Queue[tuple[bytes, int] | None] = asyncio.Queue()
        self._tie_breaker = secrets.randbits(64)
        self._use_ipv4 = use_ipv4
        self._use_ipv6 = use_ipv6

        self._transport_policy = transport_policy

    @property
    def local_candidates(self) -> list[Candidate]:
        """
        Local candidates, automatically set by :meth:`gather_candidates`.
        """
        return self._local_candidates[:]

    @property
    def local_password(self) -> str:
        """
        Local password, set at construction time.
        """
        return self._local_password

    @property
    def local_username(self) -> str:
        """
        Local username, set at construction time.
        """
        return self._local_username

    @property
    def remote_candidates(self) -> list[Candidate]:
        """
        Remote candidates, which you need to populate using
        :meth:`add_remote_candidate`.

        Remote mDNS candidates keep their hostname instead of the resolved
        address (draft-ietf-mmusic-mdns-ice-candidates section 3.3.1).
        """
        return self._remote_candidates[:]

    async def add_remote_candidate(self, remote_candidate: Candidate | None) -> None:
        """
        Add a remote candidate or signal end-of-candidates.

        To signal end-of-candidates, pass `None`. Until then, more candidates
        may be added while :meth:`connect` is running, and :meth:`connect`
        does not report an ICE negotiation failure.

        The candidate is copied, so later changes to it have no effect. A
        candidate with the same transport address as one already added is
        ignored. Once :meth:`close` has been called, remote candidates are
        ignored, including mDNS candidates still being resolved. With the relay
        transport policy, mDNS candidates are ignored without being resolved.

        :param remote_candidate: A :class:`Candidate` instance or `None`.
        """
        if self._remote_candidates_end:
            raise ValueError("Cannot add remote candidate after end-of-candidates.")

        if self._closing:
            return

        # Handle end-of-candidates.
        if remote_candidate is None:
            self._remote_candidates_end = True
            if not self._remote_candidates_resolving:
                self._end_remote_candidates()
            return

        # Keep our own copy, so changes made by either side do not affect the other.
        remote_candidate = copy.copy(remote_candidate)

        # Resolve an mDNS candidate.
        if mdns.is_mdns_hostname(remote_candidate.host):
            # Ignore mDNS candidates with the relay transport policy
            # (draft-ietf-mmusic-mdns-ice-candidates section 3.2).
            if self._transport_policy == TransportPolicy.RELAY:
                self.__log_info(
                    'Remote candidate "%s" ignored with the relay transport policy',
                    remote_candidate.host,
                )
                return

            # Keep the candidate if end-of-candidates arrives meanwhile, as only
            # newly received candidates are ignored (RFC 8838 section 14).
            self._remote_candidates_resolving += 1
            try:
                mdns_protocol = await get_or_create_mdns_protocol(self)
                remote_addr = await mdns_protocol.resolve(remote_candidate.host)
                if remote_addr is None:
                    self.__log_info(
                        'Remote candidate "%s" could not be resolved',
                        remote_candidate.host,
                    )
                elif not self._closing:
                    self.__log_info(
                        'Remote candidate "%s" resolved to %s',
                        remote_candidate.host,
                        remote_addr,
                    )
                    self._add_remote_candidate(remote_candidate, remote_addr)
            finally:
                self._remote_candidates_resolving -= 1
                if (
                    self._remote_candidates_end
                    and not self._remote_candidates_resolving
                    and not self._closing
                ):
                    self._end_remote_candidates()
            return

        self._add_remote_candidate(remote_candidate, remote_candidate.host)

    async def gather_candidates(self) -> None:
        """
        Gather local candidates.

        You **must** call this coroutine before calling :meth:`connect`.
        """
        if not self._local_candidates_start:
            self._local_candidates_start = True

            # Host and server-reflexive candidates are not used with the relay
            # transport policy (RFC 9429 section 3.5.3).
            addresses = []
            if self._transport_policy == TransportPolicy.ALL:
                addresses = get_host_addresses(
                    use_ipv4=self._use_ipv4, use_ipv6=self._use_ipv6
                )
            elif self.turn_server is None:
                self.__log_info(
                    "No candidates gathered with the relay transport policy, "
                    "as there is no TURN server"
                )
            coros = [
                self.get_component_candidates(component=component, addresses=addresses)
                for component in self._components
            ]
            for candidates in await asyncio.gather(*coros):
                self._local_candidates += candidates
            self._local_candidates_end = True

    def get_default_candidate(self, component: int) -> Candidate | None:
        """
        Get the default local candidate for the specified component.

        :param component: The component whose default candidate is requested.
        """
        for candidate in sorted(self._local_candidates, key=lambda x: x.priority):
            if candidate.component == component:
                return candidate
        return None

    async def connect(self) -> None:
        """
        Perform ICE handshake.

        This coroutine returns if a candidate pair was successfuly nominated
        and raises an exception otherwise. Failure is only reported once
        end-of-candidates has been signalled with :meth:`add_remote_candidate`,
        so until then this coroutine keeps waiting for more remote candidates.
        """
        if not self._local_candidates_end:
            raise ConnectionError("Local candidates gathering was not performed")

        if self.remote_username is None or self.remote_password is None:
            raise ConnectionError("Remote username or password is missing")

        # Forming candidate pairs (RFC 8445 section 6.1.2.2).
        for remote_candidate in self._remote_candidates:
            self._pair_remote_candidate(remote_candidate)
        self.sort_check_list()

        self._unfreeze_initial()

        # Handle the checks received before connect().
        for early_check in self._early_checks:
            self.check_incoming(*early_check)
        self._early_checks.clear()
        self._early_checks_done = True

        # Perform the checks.
        while True:
            if not self._check_periodic():
                break
            await asyncio.sleep(0.02)

        # Wait for the check list to complete or fail.
        if self._check_list:
            res = await self._check_list_state.get()
        else:
            res = ICE_FAILED

        # Cancel the remaining checks.
        for check in self._check_list:
            if check.task:
                check.task.cancel()

        if res != ICE_COMPLETED:
            raise ConnectionError("ICE negotiation failed")

        # Start consent freshness tests (RFC 7675).
        self._query_consent_task = asyncio.create_task(self.query_consent())

    async def close(self) -> None:
        """
        Close the connection.
        """
        # Ignore remote candidates from now on, including those resolved meanwhile.
        self._closing = True

        # Stop consent freshness tests.
        if self._query_consent_task and not self._query_consent_task.done():
            self._query_consent_task.cancel()
            try:
                await self._query_consent_task
            except asyncio.CancelledError:
                pass

        # Stop the check list, which also ends the checks loop in connect().
        if not self._check_list_done:
            self._check_list_state.put_nowait(ICE_FAILED)
            self._check_list_done = True

        # Stop the checks before their sockets are closed, as connect() may
        # not be running to cancel them.
        tasks = [p.task for p in self._check_list if p.task is not None]
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.wait(tasks)

        # Unreference mDNS.
        await unref_mdns_protocol(self)

        self._nominated.clear()
        for protocol in self._protocols:
            await protocol.close()
        self._protocols.clear()
        self._local_candidates.clear()

        # Wake up any pending recv().
        self._queue.put_nowait(None)

        # Emit an event.
        if not self._closed:
            self._emit_event(ConnectionClosed())
            self._closed = True

    async def get_event(self) -> ConnectionEvent | None:
        """
        Return the next `ConnectionEvent` or `None` if the connection is
        already closed.

        This method may only be called once at a time.
        """
        assert self._event_waiter is None, "already awaiting event"
        if self._closed:
            return None
        loop = asyncio.get_running_loop()
        self._event_waiter = loop.create_future()
        return await asyncio.shield(self._event_waiter)

    async def recv(self) -> bytes:
        """
        Receive the next datagram.

        The return value is a `bytes` object representing the data received.

        If the connection is not established, a `ConnectionError` is raised.
        """
        data, component = await self.recvfrom()
        return data

    async def recvfrom(self) -> tuple[bytes, int]:
        """
        Receive the next datagram.

        The return value is a `(bytes, component)` tuple where `bytes` is a
        bytes object representing the data received and `component` is the
        component on which the data was received.

        If the connection is not established, a `ConnectionError` is raised.
        """
        if not len(self._nominated):
            raise ConnectionError("Cannot receive data, not connected")

        result = await self._queue.get()
        if result is None:
            raise ConnectionError("Connection lost while receiving data")
        return result

    async def send(self, data: bytes) -> None:
        """
        Send a datagram on the first component.

        If the connection is not established, a `ConnectionError` is raised.

        :param data: The data to be sent.
        """
        await self.sendto(data, 1)

    async def sendto(self, data: bytes, component: int) -> None:
        """
        Send a datagram on the specified component.

        If the connection is not established, a `ConnectionError` is raised.

        :param data: The data to be sent.
        :param component: The component on which to send the data.
        """
        active_pair = self._nominated.get(component)
        if active_pair:
            await active_pair.protocol.send_data(data, active_pair.remote_addr)
        else:
            raise ConnectionError("Cannot send data, not connected")

    def set_selected_pair(
        self, component: int, local_foundation: str, remote_foundation: str
    ) -> None:
        """
        Force the selected candidate pair.

        If the remote party does not support ICE, you should using this
        instead of calling :meth:`connect`.
        """
        # find local candidate
        protocol = None
        for p in self._protocols:
            if (
                p.local_candidate.component == component
                and p.local_candidate.foundation == local_foundation
            ):
                protocol = p
                break

        # find remote candidate
        remote_candidate = None
        for c in self._remote_candidates:
            if c.component == component and c.foundation == remote_foundation:
                remote_candidate = c

        assert protocol and remote_candidate
        self._nominated[component] = CandidatePair(protocol, remote_candidate)

    # private

    def _add_remote_candidate(
        self, remote_candidate: Candidate, network_host: str
    ) -> None:
        """
        Add a remote candidate, reached at the given address.
        """
        # Validate the remote candidate.
        try:
            remote_candidate._network_host = validate_remote_candidate(
                remote_candidate, network_host
            )
        except ValueError as e:
            self.__log_info(
                f'Remote candidate "{remote_candidate.host}" is not valid: {e}'
            )
            return

        known_candidate = self._find_remote_candidate(remote_candidate)
        if known_candidate is None:
            self._remote_candidates.append(remote_candidate)
        elif known_candidate.type == "prflx":
            # Update a candidate learned as peer-reflexive, keeping its pair
            # (RFC 8445 section 7.3.1.3, RFC 8838 section 11).
            self.__log_info(
                "Peer reflexive candidate %s signalled as %s",
                known_candidate,
                remote_candidate,
            )
            known_candidate.host = remote_candidate.host
            known_candidate.foundation = remote_candidate.foundation
            known_candidate.priority = remote_candidate.priority
            known_candidate.type = remote_candidate.type
            known_candidate.related_address = remote_candidate.related_address
            known_candidate.related_port = remote_candidate.related_port
            known_candidate.tcptype = remote_candidate.tcptype
            known_candidate.generation = remote_candidate.generation
            remote_candidate = known_candidate
        else:
            # A peer eliminates redundant candidates (RFC 8445 section 5.1.3), so
            # this is the same candidate signalled again (RFC 8838 section 9).
            self.__log_info(
                "Remote candidate %s is ignored, as it has the same address as %s",
                remote_candidate,
                known_candidate,
            )
            return

        # Pair the remote candidate.
        self._pair_remote_candidate(remote_candidate)
        self.sort_check_list()

    def build_request(self, pair: CandidatePair, nominate: bool) -> stun.Message:
        tx_username = f"{self.remote_username}:{self.local_username}"
        request = stun.Message(
            message_method=stun.Method.BINDING, message_class=stun.Class.REQUEST
        )
        request.attributes["USERNAME"] = tx_username
        request.attributes["PRIORITY"] = candidate_priority(pair.component, "prflx")
        if self.ice_controlling:
            request.attributes["ICE-CONTROLLING"] = self._tie_breaker
            if nominate:
                request.attributes["USE-CANDIDATE"] = None
        else:
            request.attributes["ICE-CONTROLLED"] = self._tie_breaker
        return request

    def check_complete(self, pair: CandidatePair) -> None:
        pair.task = None

        if pair.state == CandidatePair.State.SUCCEEDED:
            if pair.nominated:
                self._nominated[pair.component] = pair

                # Remove the component's pairs which have not been checked yet,
                # cancelling any check already scheduled for them (RFC 8445
                # section 8.1.2).
                unchecked = [
                    p
                    for p in self._check_list
                    if p.component == pair.component
                    and p.state
                    in [CandidatePair.State.WAITING, CandidatePair.State.FROZEN]
                ]
                for p in unchecked:
                    self.__log_info("Check %s %s -> removed", p, p.state)
                    if p.task is not None:
                        p.task.cancel()
                    self._check_list.remove(p)

            if self._check_list_maybe_complete():
                return

            # Updating candidate pair states (RFC 8445 section 7.2.5.3.3).
            for p in self._check_list:
                if (
                    p.local_candidate.foundation == pair.local_candidate.foundation
                    and p.state == CandidatePair.State.FROZEN
                ):
                    self.check_state(p, CandidatePair.State.WAITING)

        self._check_list_maybe_fail()

    def check_incoming(
        self, message: stun.Message, addr: tuple[str, int], protocol: StunProtocol
    ) -> None:
        """
        Handle a succesful incoming check.
        """
        component = protocol.local_candidate.component

        # find remote candidate
        remote_candidate = None
        for c in self._remote_candidates:
            if c._network_host == addr[0] and c.port == addr[1]:
                remote_candidate = c
                assert remote_candidate.component == component
                break
        if remote_candidate is None:
            # Learning peer-reflexive candidates (RFC 8445 section 7.3.1.3).
            remote_candidate = Candidate(
                foundation=random_string(10),
                component=component,
                transport="udp",
                priority=message.attributes["PRIORITY"],
                host=addr[0],
                port=addr[1],
                type="prflx",
            )
            self._remote_candidates.append(remote_candidate)
            self.__log_info("Discovered peer reflexive candidate %s", remote_candidate)

        # find pair
        pair = self._find_pair(protocol, remote_candidate)
        if pair is None:
            pair = CandidatePair(protocol, remote_candidate)
            pair.state = CandidatePair.State.WAITING
            self._check_list.append(pair)
            self.sort_check_list()

        # Triggered check (RFC 8445 section 7.3.1.4).
        if pair.state in [CandidatePair.State.FROZEN, CandidatePair.State.FAILED]:
            self.check_state(pair, CandidatePair.State.WAITING)
        if pair.state == CandidatePair.State.WAITING:
            self.check_start_task(pair)

        # Updating the nominated flag (RFC 8445 section 7.3.1.5).
        if "USE-CANDIDATE" in message.attributes and not self.ice_controlling:
            pair.remote_nominated = True

            if pair.state == CandidatePair.State.SUCCEEDED:
                pair.nominated = True
                self.check_complete(pair)

    def _check_list_maybe_complete(self) -> bool:
        """
        Mark the check list as completed if every component has a nominated pair.
        """
        # Once there is at least one nominated pair in the valid list for
        # every component of at least one media stream and the state of the
        # check list is Running:
        if self._nominated and len(self._nominated) == len(self._components):
            if not self._check_list_done:
                self.__log_info("ICE completed")
                self._check_list_state.put_nowait(ICE_COMPLETED)
                self._check_list_done = True
            return True
        return False

    def _check_list_maybe_fail(self) -> None:
        """
        Mark the check list as failed if no further progress can be made.
        """
        # More remote candidates may still be trickled (RFC 8838 section 8).
        if self._remote_candidates_expected():
            return

        for p in self._check_list:
            if p.state not in [
                CandidatePair.State.SUCCEEDED,
                CandidatePair.State.FAILED,
            ]:
                return

        if not self.ice_controlling:
            for p in self._check_list:
                if p.state == CandidatePair.State.SUCCEEDED:
                    return

        if not self._check_list_done:
            self.__log_info("ICE failed")
            self._check_list_state.put_nowait(ICE_FAILED)
            self._check_list_done = True

    def _check_periodic(self) -> bool:
        """
        Start a check for the highest-priority Waiting pair, or else Frozen pair.

        connect() calls this every 20 ms to pace the checks, like the Ta timer
        of RFC 8445 section 6.1.4.2, for as long as this returns True.
        """
        # Start no more checks once the check list is completed, failed or closed.
        if self._check_list_done:
            return False

        # Start the highest-priority pair in the Waiting state.
        for pair in self._check_list:
            if pair.state == CandidatePair.State.WAITING:
                self.check_start_task(pair)
                return True

        # Otherwise start the highest-priority pair in the Frozen state.
        for pair in self._check_list:
            if pair.state == CandidatePair.State.FROZEN:
                self.check_start_task(pair)
                return True

        # Keep going if more remote candidates are expected.
        return self._remote_candidates_expected()

    async def check_start(self, pair: CandidatePair) -> None:
        """
        Starts a check.
        """
        # Checks only start once connect() has the remote password.
        assert self.remote_password is not None
        self.check_state(pair, CandidatePair.State.IN_PROGRESS)

        nominate = self.ice_controlling and not self.remote_is_lite
        request = self.build_request(pair, nominate=nominate)
        try:
            response, addr = await pair.protocol.request(
                request,
                pair.remote_addr,
                integrity_key=self.remote_password.encode("utf8"),
            )
        except stun.TransactionError as exc:
            # Role conflict or failure (RFC 8445 sections 7.2.5.1 and 7.2.5.2).
            if exc.response and exc.response.error_code == 487:
                if "ICE-CONTROLLING" in request.attributes:
                    self.switch_role(ice_controlling=False)
                elif "ICE-CONTROLLED" in request.attributes:
                    self.switch_role(ice_controlling=True)
                return await self.check_start(pair)
            else:
                self.check_state(pair, CandidatePair.State.FAILED)
                self.check_complete(pair)
                return

        # Check that the remote address matches (RFC 8445 section 7.2.5.2.1).
        if addr != pair.remote_addr:
            self.__log_info("Check %s failed : source address mismatch", pair)
            self.check_state(pair, CandidatePair.State.FAILED)
            self.check_complete(pair)
            return

        # Success (RFC 8445 section 7.2.5.3).
        if nominate or pair.remote_nominated:
            # Nominated by aggressive nomination or by the remote party.
            pair.nominated = True
        elif self.ice_controlling and pair.component not in self._nominating:
            # Perform regular nomination (RFC 8445 section 8.1.1).
            self.__log_info("Check %s nominating pair", pair)
            self._nominating.add(pair.component)
            request = self.build_request(pair, nominate=True)
            try:
                await pair.protocol.request(
                    request,
                    pair.remote_addr,
                    integrity_key=self.remote_password.encode("utf8"),
                )
            except stun.TransactionError:
                self.__log_info("Check %s failed : could not nominate pair", pair)
                self.check_state(pair, CandidatePair.State.FAILED)
                self.check_complete(pair)
                return
            pair.nominated = True
        self.check_state(pair, CandidatePair.State.SUCCEEDED)
        self.check_complete(pair)

    def check_start_task(self, pair: CandidatePair) -> None:
        """
        Starts a check in a task, unless already started.
        """
        if pair.task is None:
            pair.task = asyncio.create_task(self.check_start(pair))

    def check_state(self, pair: CandidatePair, state: CandidatePair.State) -> None:
        """
        Updates the state of a check.
        """
        self.__log_info("Check %s %s -> %s", pair, pair.state, state)
        pair.state = state

    def _emit_event(self, event: ConnectionEvent) -> None:
        if self._event_waiter is not None:
            waiter = self._event_waiter
            self._event_waiter = None
            waiter.set_result(event)

    def _end_remote_candidates(self) -> None:
        """
        Handle end-of-candidates once all remote candidates have been processed.
        """
        self._prune_components()

        # Removing components may leave all the remaining ones nominated, or
        # the pairs may all have failed meanwhile (RFC 8838 section 14).
        if self._early_checks_done and not self._check_list_maybe_complete():
            self._check_list_maybe_fail()

    def _find_pair(
        self, protocol: StunProtocol, remote_candidate: Candidate
    ) -> CandidatePair | None:
        """
        Find a candidate pair in the check list.
        """
        for pair in self._check_list:
            if pair.protocol == protocol and pair.remote_candidate == remote_candidate:
                return pair
        return None

    def _find_remote_candidate(self, remote_candidate: Candidate) -> Candidate | None:
        """
        Find a remote candidate with the same transport address.
        """
        for c in self._remote_candidates:
            if (
                c.component == remote_candidate.component
                and c.transport.lower() == remote_candidate.transport.lower()
                and c._network_host == remote_candidate._network_host
                and c.port == remote_candidate.port
            ):
                return c
        return None

    async def get_component_candidates(
        self, component: int, addresses: list[str], timeout: int = 5
    ) -> list[Candidate]:
        candidates = []
        loop = asyncio.get_running_loop()

        # Gather host candidates.
        host_protocols = []
        for address in addresses:
            # Create the transport.
            try:
                transport, protocol = await loop.create_datagram_endpoint(
                    lambda: StunProtocol(self), local_addr=(address, 0)
                )
                sock = transport.get_extra_info("socket")
                if sock is not None:
                    sock.setsockopt(
                        socket.SOL_SOCKET, socket.SO_RCVBUF, turn.UDP_SOCKET_BUFFER_SIZE
                    )
            except OSError as exc:
                self.__log_info("Could not bind to %s - %s", address, exc)
                continue
            host_protocols.append(protocol)

            # Add the host candidate.
            candidate_address = protocol.transport.get_extra_info("sockname")
            protocol.local_candidate = Candidate(
                foundation=candidate_foundation("host", "udp", candidate_address[0]),
                component=component,
                transport="udp",
                priority=candidate_priority(component, "host"),
                host=candidate_address[0],
                port=candidate_address[1],
                type="host",
            )
            candidates.append(protocol.local_candidate)
        self._protocols += host_protocols

        tasks: list[asyncio.Task[tuple[Candidate, StunProtocol | None]]] = []

        # Query STUN server for server-reflexive candidates (IPv4 only).
        if self.stun_server:
            for protocol in host_protocols:
                if ipaddress.ip_address(protocol.local_candidate.host).version == 4:
                    tasks.append(
                        asyncio.create_task(
                            server_reflexive_candidate(protocol, self.stun_server)
                        )
                    )

        # Connect to TURN server.
        if self.turn_server:
            tasks.append(
                asyncio.create_task(
                    relayed_candidate(
                        component=component,
                        hide_related_address=(
                            self._transport_policy == TransportPolicy.RELAY
                        ),
                        protocol_factory=lambda: StunProtocol(self),
                        turn_server=self.turn_server,
                        turn_username=self.turn_username,
                        turn_password=self.turn_password,
                        turn_ssl=self.turn_ssl,
                        turn_transport=self.turn_transport,
                    )
                )
            )

        # Run tasks in parallel and handle exceptions.
        if len(tasks):
            done, pending = await asyncio.wait(tasks, timeout=timeout)
            for task in done:
                if task.exception() is None:
                    candidate, relay_protocol = task.result()
                    candidates.append(candidate)
                    if relay_protocol is not None:
                        self._protocols.append(relay_protocol)
            for task in pending:
                task.cancel()

        return candidates

    def _pair_remote_candidate(self, remote_candidate: Candidate) -> None:
        """
        Pair a remote candidate with the local candidates it can pair with.
        """
        is_mdns = mdns.is_mdns_hostname(remote_candidate.host)
        for protocol in self._protocols:
            # Relaying to an mDNS candidate would reveal its address to the TURN
            # server (draft-ietf-mmusic-mdns-ice-candidates section 3.3.2).
            if is_mdns and protocol.local_candidate.type == "relay":
                continue

            if protocol.local_candidate.can_pair_with(
                remote_candidate
            ) and not self._find_pair(protocol, remote_candidate):
                pair = CandidatePair(protocol, remote_candidate)
                self._check_list.append(pair)

    def _prune_components(self) -> None:
        """
        Remove components for which the remote party did not provide any candidates.

        This can only be determined after end-of-candidates.
        """
        seen_components = set(map(lambda x: x.component, self._remote_candidates))
        missing_components = self._components - seen_components
        if missing_components:
            self.__log_info("Components %s have no candidate pairs", missing_components)
            self._components = seen_components

    async def query_consent(self) -> None:
        """
        Periodically check consent (RFC 7675).
        """
        # Consent checks only start once connect() has the remote password.
        assert self.remote_password is not None
        failures = 0
        while True:
            # randomize between 0.8 and 1.2 times CONSENT_INTERVAL
            await asyncio.sleep(CONSENT_INTERVAL * (0.8 + 0.4 * random.random()))

            for pair in self._nominated.values():
                request = self.build_request(pair, nominate=False)
                try:
                    await pair.protocol.request(
                        request,
                        pair.remote_addr,
                        integrity_key=self.remote_password.encode("utf8"),
                        retransmissions=0,
                    )
                    failures = 0
                except stun.TransactionError:
                    failures += 1
                if failures >= CONSENT_FAILURES:
                    self.__log_info("Consent to send expired")
                    self._query_consent_task = None
                    return await self.close()

    def data_received(self, data: bytes, component: int) -> None:
        self._queue.put_nowait((data, component))

    def protocol_lost(self, protocol: StunProtocol) -> None:
        # Only a nominated pair carries data, so losing any other
        # protocol must not abort a pending recv().
        for pair in self._nominated.values():
            if pair.protocol is protocol:
                self._queue.put_nowait(None)
                return

    def _remote_candidates_expected(self) -> bool:
        """
        Whether more remote candidates may still be added.
        """
        return not self._remote_candidates_end or self._remote_candidates_resolving > 0

    def request_received(
        self,
        message: stun.Message,
        addr: tuple[str, int],
        protocol: StunProtocol,
    ) -> None:
        # Ignore incoming checks once closing, as they would start new checks.
        if self._closing:
            return

        if message.message_method != stun.Method.BINDING:
            self.respond_error(message, addr, protocol, (400, "Bad Request"))
            return

        # Authenticate the request (RFC 8489 section 9.1.3).
        if (
            "MESSAGE-INTEGRITY" not in message.attributes
            or "USERNAME" not in message.attributes
        ):
            self.respond_error(message, addr, protocol, (400, "Bad Request"))
            return
        if not (
            self._valid_username(message.attributes["USERNAME"])
            and message.check_message_integrity(self.local_password.encode("utf8"))
        ):
            self.respond_error(message, addr, protocol, (401, "Unauthenticated"))
            return

        # Detecting and repairing role conflicts (RFC 8445 section 7.3.1.1).
        if self.ice_controlling and "ICE-CONTROLLING" in message.attributes:
            self.__log_info("Role conflict, expected to be controlling")
            if self._tie_breaker >= message.attributes["ICE-CONTROLLING"]:
                self.respond_error(message, addr, protocol, (487, "Role Conflict"))
                return
            self.switch_role(ice_controlling=False)
        elif not self.ice_controlling and "ICE-CONTROLLED" in message.attributes:
            self.__log_info("Role conflict, expected to be controlled")
            if self._tie_breaker < message.attributes["ICE-CONTROLLED"]:
                self.respond_error(message, addr, protocol, (487, "Role Conflict"))
                return
            self.switch_role(ice_controlling=True)

        # Send a Binding response.
        response = stun.Message(
            message_method=stun.Method.BINDING,
            message_class=stun.Class.RESPONSE,
            transaction_id=message.transaction_id,
        )
        response.attributes["XOR-MAPPED-ADDRESS"] = addr
        response.add_message_integrity(self.local_password.encode("utf8"))
        protocol.send_stun(response, addr)

        # Defer incoming checks until connect() has the remote password, even
        # if trickled candidates already formed pairs (RFC 8445 section 7.3).
        if not self._early_checks_done:
            self._early_checks.append((message, addr, protocol))
        else:
            self.check_incoming(message, addr, protocol)

    def respond_error(
        self,
        request: stun.Message,
        addr: tuple[str, int],
        protocol: StunProtocol,
        error_code: tuple[int, str],
    ) -> None:
        response = stun.Message(
            message_method=request.message_method,
            message_class=stun.Class.ERROR,
            transaction_id=request.transaction_id,
        )
        response.attributes["ERROR-CODE"] = error_code

        # 400 and 401 errors report a request which was not authenticated, so
        # they are not signed (RFC 8489 section 9.1.3). FINGERPRINT is always
        # added (RFC 8445 section 7.3).
        if error_code[0] in (400, 401):
            response.add_fingerprint()
        else:
            response.add_message_integrity(self.local_password.encode("utf8"))
        protocol.send_stun(response, addr)

    def sort_check_list(self) -> None:
        sort_candidate_pairs(self._check_list, self.ice_controlling)

    def switch_role(self, ice_controlling: bool) -> None:
        self.__log_info(
            "Switching to %s role", ice_controlling and "controlling" or "controlled"
        )
        self.ice_controlling = ice_controlling
        self.sort_check_list()

    def _unfreeze_initial(self) -> None:
        # unfreeze first pair for the first component
        first_pair = None
        for pair in self._check_list:
            if pair.component == min(self._components):
                first_pair = pair
                break
        if first_pair is None:
            return
        if first_pair.state == CandidatePair.State.FROZEN:
            self.check_state(first_pair, CandidatePair.State.WAITING)

        # unfreeze pairs with same component but different foundations
        seen_foundations = set(first_pair.local_candidate.foundation)
        for pair in self._check_list:
            if (
                pair.component == first_pair.component
                and pair.local_candidate.foundation not in seen_foundations
                and pair.state == CandidatePair.State.FROZEN
            ):
                self.check_state(pair, CandidatePair.State.WAITING)
                seen_foundations.add(pair.local_candidate.foundation)

    def _valid_username(self, username: str) -> bool:
        """
        Check the USERNAME of an incoming request.

        It consists of the local and remote username fragments, separated by
        a colon. The remote username fragment can only be checked once it is
        known (RFC 8445 section 7.3).
        """
        local_username, colon, remote_username = username.partition(":")
        return (
            colon == ":"
            and local_username == self.local_username
            and self.remote_username in (None, remote_username)
        )

    def __log_info(self, msg: str, *args: object) -> None:
        logger.info("%s " + msg, self, *args)

    def __repr__(self) -> str:
        return f"Connection({self._id})"
