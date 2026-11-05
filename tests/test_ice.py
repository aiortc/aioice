import asyncio
import contextlib
import copy
import errno
import functools
import os
import unittest
from collections.abc import Callable, Coroutine, Iterator
from typing import Any, cast
from unittest import mock

import ifaddr

from aioice import Candidate, TransportPolicy, ice, mdns, stun

from .turnserver import run_turn_server
from .utils import (
    RUNNING_ON_MAC_CI,
    asynctest,
    invite_accept,
    multicast_join_fails,
)

RUNNING_ON_CI = os.environ.get("GITHUB_ACTIONS") == "true"


async def add_mdns_candidates(
    publisher: mdns.MDnsProtocol, conn: ice.Connection, candidates: list[Candidate]
) -> None:
    """
    Signal candidates to a connection under new mDNS hostnames, followed by
    end-of-candidates.
    """
    for candidate in candidates:
        hostname = mdns.create_mdns_hostname()
        await publisher.publish(hostname, candidate.host)
        await conn.add_remote_candidate(
            Candidate(
                foundation=candidate.foundation,
                component=candidate.component,
                transport=candidate.transport,
                priority=candidate.priority,
                host=hostname,
                port=candidate.port,
                type=candidate.type,
            )
        )
    await conn.add_remote_candidate(None)


async def delay(coro: Callable[[], Coroutine[None, None, None]]) -> None:
    await asyncio.sleep(1)
    await coro()


@contextlib.contextmanager
def spy_send_stun() -> Iterator[mock.Mock]:
    """
    Record the STUN messages sent by all protocols, while still sending them.
    """
    with mock.patch.object(
        ice.StunProtocol,
        "send_stun",
        autospec=True,
        side_effect=ice.StunProtocol.send_stun,
    ) as send_stun:
        yield send_stun


class ProtocolMock(ice.StunProtocol):
    def __init__(
        self, receiver: ice.Connection, response_addr: tuple[str, int]
    ) -> None:
        super().__init__(receiver)
        self.local_candidate = Candidate(
            foundation="some-foundation",
            component=1,
            transport="udp",
            priority=1234,
            host="1.2.3.4",
            port=1234,
            type="host",
        )

        self.response_addr = response_addr
        self.sent_message: stun.Message | None = None

    async def request(
        self,
        message: stun.Message,
        addr: tuple[str, int],
        integrity_key: bytes | None = None,
        retransmissions: int | None = None,
    ) -> tuple[stun.Message, tuple[str, int]]:
        response_message = stun.Message(
            message_method=message.message_method,
            message_class=stun.Class.RESPONSE,
            transaction_id=message.transaction_id,
        )
        return (response_message, self.response_addr)

    def send_stun(self, message: stun.Message, addr: tuple[str, int]) -> None:
        self.sent_message = message


class IceComponentTest(unittest.TestCase):
    @asynctest
    async def test_peer_reflexive(self) -> None:
        connection = ice.Connection(ice_controlling=True)
        connection.remote_password = "remote-password"
        connection.remote_username = "remote-username"

        protocol = ProtocolMock(connection, response_addr=("2.3.4.5", 2345))

        request = stun.Message(
            message_method=stun.Method.BINDING, message_class=stun.Class.REQUEST
        )
        request.attributes["PRIORITY"] = 456789

        connection.check_incoming(request, ("2.3.4.5", 2345), protocol)
        self.assertIsNone(protocol.sent_message)

        # check we have discovered a peer-reflexive candidate
        self.assertEqual(len(connection.remote_candidates), 1)
        candidate = connection.remote_candidates[0]
        self.assertEqual(candidate.component, 1)
        self.assertEqual(candidate.transport, "udp")
        self.assertEqual(candidate.priority, 456789)
        self.assertEqual(candidate.host, "2.3.4.5")
        self.assertEqual(candidate.port, 2345)
        self.assertEqual(candidate.type, "prflx")
        self.assertEqual(candidate.generation, None)

        # check a new pair was formed
        self.assertEqual(len(connection._check_list), 1)
        pair = connection._check_list[0]
        self.assertEqual(pair.protocol, protocol)
        self.assertEqual(pair.remote_candidate, candidate)

        # check a triggered check was scheduled
        assert pair.task is not None
        await pair.task

    @asynctest
    async def test_peer_reflexive_non_canonical_address(self) -> None:
        """
        A check from a candidate signalled with a non-canonical IPv6 address
        does not create a peer-reflexive candidate.
        """
        connection = ice.Connection(ice_controlling=True)
        connection.remote_password = "remote-password"
        connection.remote_username = "remote-username"

        protocol = ProtocolMock(connection, response_addr=("2001:db8::1", 2345))
        protocol.local_candidate = Candidate(
            foundation="some-foundation",
            component=1,
            transport="udp",
            priority=1234,
            host="2001:db8::2",
            port=1234,
            type="host",
        )
        connection._protocols.append(protocol)

        candidate = Candidate(
            foundation="some-foundation",
            component=1,
            transport="udp",
            priority=1234,
            host="2001:DB8:0::1",
            port=2345,
            type="host",
        )
        await connection.add_remote_candidate(candidate)

        # Check the candidate was copied, leaving the caller's object untouched.
        self.assertEqual(len(connection.remote_candidates), 1)
        remote_candidate = connection.remote_candidates[0]
        self.assertIsNot(remote_candidate, candidate)
        self.assertEqual(candidate._network_host, "2001:DB8:0::1")

        # Check a pair was formed using the canonical address.
        self.assertEqual(len(connection._check_list), 1)
        pair = connection._check_list[0]
        self.assertEqual(pair.remote_candidate, remote_candidate)
        self.assertEqual(pair.remote_addr, ("2001:db8::1", 2345))

        request = stun.Message(
            message_method=stun.Method.BINDING, message_class=stun.Class.REQUEST
        )
        request.attributes["PRIORITY"] = 456789
        connection.check_incoming(request, ("2001:db8::1", 2345), protocol)

        # Check the signalled candidate was matched and kept as signalled.
        self.assertEqual(connection.remote_candidates, [remote_candidate])
        self.assertEqual(remote_candidate.host, "2001:DB8:0::1")

        # Check the existing pair was used for the triggered check.
        self.assertEqual(connection._check_list, [pair])
        assert pair.task is not None
        await pair.task

    @asynctest
    async def test_peer_reflexive_then_signalled(self) -> None:
        """
        A candidate signalled after it was learned as peer-reflexive updates
        the peer-reflexive candidate instead of forming a duplicate pair.
        """
        connection = ice.Connection(ice_controlling=True)
        connection.remote_password = "remote-password"
        connection.remote_username = "remote-username"

        protocol = ProtocolMock(connection, response_addr=("2.3.4.5", 2345))
        connection._protocols.append(protocol)

        request = stun.Message(
            message_method=stun.Method.BINDING, message_class=stun.Class.REQUEST
        )
        request.attributes["PRIORITY"] = 456789

        connection.check_incoming(request, ("2.3.4.5", 2345), protocol)
        self.assertEqual(len(connection._check_list), 1)
        pair = connection._check_list[0]
        candidate = pair.remote_candidate
        self.assertEqual(candidate.type, "prflx")
        assert pair.task is not None
        await pair.task

        # The peer signals the candidate.
        await connection.add_remote_candidate(
            Candidate(
                foundation="signalled-foundation",
                component=1,
                transport="udp",
                priority=2130706431,
                host="2.3.4.5",
                port=2345,
                type="host",
            )
        )

        # Check the peer-reflexive candidate was updated.
        self.assertEqual(connection.remote_candidates, [candidate])
        self.assertEqual(candidate.foundation, "signalled-foundation")
        self.assertEqual(candidate.priority, 2130706431)
        self.assertEqual(candidate.type, "host")

        # Check the existing pair was kept.
        self.assertEqual(connection._check_list, [pair])
        self.assertEqual(pair.remote_candidate, candidate)

    @asynctest
    async def test_nomination_removes_waiting_and_frozen_pairs(self) -> None:
        connection = ice.Connection(ice_controlling=True, components=2)

        def create_pair(
            *, component: int, port: int, state: ice.CandidatePair.State
        ) -> ice.CandidatePair:
            # The pair's component is that of its local candidate.
            protocol = ProtocolMock(connection, response_addr=("2.3.4.5", 2345))
            protocol.local_candidate.component = component
            pair = ice.CandidatePair(
                protocol,
                Candidate(
                    foundation="some-foundation",
                    component=component,
                    transport="udp",
                    priority=2345,
                    host="2.3.4.5",
                    port=port,
                    type="host",
                ),
            )
            pair.state = state
            return pair

        nominated = create_pair(
            component=1, port=1000, state=ice.CandidatePair.State.SUCCEEDED
        )
        nominated.nominated = True
        succeeded = create_pair(
            component=1, port=1001, state=ice.CandidatePair.State.SUCCEEDED
        )
        waiting = create_pair(
            component=1, port=1002, state=ice.CandidatePair.State.WAITING
        )
        frozen = create_pair(
            component=1, port=1003, state=ice.CandidatePair.State.FROZEN
        )
        in_progress = create_pair(
            component=1, port=1004, state=ice.CandidatePair.State.IN_PROGRESS
        )
        failed = create_pair(
            component=1, port=1005, state=ice.CandidatePair.State.FAILED
        )
        other_component = [
            create_pair(component=2, port=2000 + i, state=state)
            for i, state in enumerate(ice.CandidatePair.State)
        ]
        connection._check_list = [
            nominated,
            succeeded,
            waiting,
            frozen,
            in_progress,
            failed,
            *other_component,
        ]

        # A check scheduled but not yet started must be cancelled.
        connection.check_start_task(waiting)
        task = waiting.task
        assert task is not None

        connection.check_complete(nominated)
        self.assertEqual(
            connection._check_list,
            [nominated, succeeded, in_progress, failed, *other_component],
        )
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertEqual(waiting.state, ice.CandidatePair.State.WAITING)

        # No check is left running.
        self.assertEqual(asyncio.all_tasks(), {asyncio.current_task()})

    @asynctest
    async def test_request_before_remote_credentials(self) -> None:
        connection = ice.Connection(ice_controlling=True)

        # A trickled candidate formed a pair before the remote credentials
        # are known.
        protocol = ProtocolMock(connection, response_addr=("2.3.4.5", 2345))
        remote_candidate = Candidate(
            foundation="some-foundation",
            component=1,
            transport="udp",
            priority=2345,
            host="2.3.4.5",
            port=2345,
            type="host",
        )
        connection._remote_candidates.append(remote_candidate)
        pair = ice.CandidatePair(protocol, remote_candidate)
        connection._check_list.append(pair)

        request = stun.Message(
            message_method=stun.Method.BINDING, message_class=stun.Class.REQUEST
        )
        request.attributes["USERNAME"] = f"{connection.local_username}:remote-username"
        request.add_message_integrity(connection.local_password.encode("utf8"))
        connection.request_received(request, ("2.3.4.5", 2345), protocol)

        # The request is answered, but the triggered check is deferred.
        assert protocol.sent_message is not None
        self.assertEqual(protocol.sent_message.message_method, stun.Method.BINDING)
        self.assertEqual(protocol.sent_message.message_class, stun.Class.RESPONSE)
        self.assertEqual(
            list(connection._early_checks), [(request, ("2.3.4.5", 2345), protocol)]
        )
        self.assertIsNone(pair.task)
        self.assertEqual(pair.state, ice.CandidatePair.State.FROZEN)

    @asynctest
    async def test_request_before_remote_credentials_limit(self) -> None:
        connection = ice.Connection(ice_controlling=True)
        protocol = ProtocolMock(connection, response_addr=("2.3.4.5", 2345))

        requests = []
        for _ in range(ice.MAX_EARLY_CHECKS + 1):
            request = stun.Message(
                message_method=stun.Method.BINDING, message_class=stun.Class.REQUEST
            )
            request.attributes["USERNAME"] = (
                f"{connection.local_username}:remote-username"
            )
            request.add_message_integrity(connection.local_password.encode("utf8"))
            connection.request_received(request, ("2.3.4.5", 2345), protocol)
            requests.append(request)

        # Only the most recent checks are kept.
        self.assertEqual(
            [early_check[0] for early_check in connection._early_checks],
            requests[1:],
        )

    @asynctest
    async def test_request_role_conflict(self) -> None:
        """
        A role conflict is reported with a 487 error, signed with the local
        password as the request was authenticated (RFC 8489 section 9.1.3).
        """
        connection = ice.Connection(ice_controlling=True)
        connection.remote_username = "remote-username"
        connection._tie_breaker = 2

        protocol = ProtocolMock(connection, response_addr=("2.3.4.5", 2345))

        request = stun.Message(
            message_method=stun.Method.BINDING, message_class=stun.Class.REQUEST
        )
        request.attributes["USERNAME"] = f"{connection.local_username}:remote-username"
        request.attributes["ICE-CONTROLLING"] = 1
        request.add_message_integrity(connection.local_password.encode("utf8"))
        connection.request_received(request, ("2.3.4.5", 2345), protocol)
        assert protocol.sent_message is not None
        self.assertEqual(protocol.sent_message.message_class, stun.Class.ERROR)
        self.assertEqual(
            protocol.sent_message.attributes["ERROR-CODE"], (487, "Role Conflict")
        )
        self.assertTrue(
            protocol.sent_message.check_message_integrity(
                connection.local_password.encode("utf8")
            )
        )

    @asynctest
    async def test_request_unauthenticated(self) -> None:
        """
        A request which cannot be authenticated is rejected with an error
        which is not signed (RFC 8489 section 9.1.3). The username must start
        with the local username fragment (RFC 8445 section 7.3).
        """
        local_password = "local+password+long+enough"
        local_key = local_password.encode("utf8")

        for remote_username, username, integrity_key, error_code in [
            # Missing MESSAGE-INTEGRITY.
            (None, "local:remote", None, (400, "Bad Request")),
            ("remote", "local:remote", None, (400, "Bad Request")),
            # Missing USERNAME.
            (None, None, local_key, (400, "Bad Request")),
            ("remote", None, local_key, (400, "Bad Request")),
            # Wrong local username fragment.
            (None, "wrong:remote", local_key, (401, "Unauthenticated")),
            # Missing remote username fragment.
            (None, "local", local_key, (401, "Unauthenticated")),
            # Wrong remote username fragment.
            ("remote", "local:wrong", local_key, (401, "Unauthenticated")),
            # Wrong MESSAGE-INTEGRITY.
            (None, "local:remote", b"wrong-password", (401, "Unauthenticated")),
            ("remote", "local:remote", b"wrong-password", (401, "Unauthenticated")),
        ]:
            with self.subTest(
                remote_username=remote_username,
                username=username,
                integrity_key=integrity_key,
            ):
                connection = ice.Connection(
                    ice_controlling=True,
                    local_username="local",
                    local_password=local_password,
                )
                connection.remote_username = remote_username

                protocol = ProtocolMock(connection, response_addr=("2.3.4.5", 2345))

                request = stun.Message(
                    message_method=stun.Method.BINDING,
                    message_class=stun.Class.REQUEST,
                )
                if username is not None:
                    request.attributes["USERNAME"] = username
                if integrity_key is not None:
                    request.add_message_integrity(integrity_key)
                connection.request_received(
                    stun.parse_message(bytes(request)), ("2.3.4.5", 2345), protocol
                )
                assert protocol.sent_message is not None
                self.assertEqual(protocol.sent_message.message_class, stun.Class.ERROR)
                self.assertEqual(
                    protocol.sent_message.attributes["ERROR-CODE"], error_code
                )
                self.assertNotIn("MESSAGE-INTEGRITY", protocol.sent_message.attributes)
                self.assertIn("FINGERPRINT", protocol.sent_message.attributes)

    @asynctest
    async def test_request_with_invalid_method(self) -> None:
        connection = ice.Connection(ice_controlling=True)

        protocol = ProtocolMock(connection, response_addr=("2.3.4.5", 2345))

        request = stun.Message(
            message_method=stun.Method.ALLOCATE, message_class=stun.Class.REQUEST
        )

        connection.request_received(request, ("2.3.4.5", 2345), protocol)
        assert protocol.sent_message is not None
        self.assertEqual(protocol.sent_message.message_method, stun.Method.ALLOCATE)
        self.assertEqual(protocol.sent_message.message_class, stun.Class.ERROR)
        self.assertEqual(
            protocol.sent_message.attributes["ERROR-CODE"], (400, "Bad Request")
        )
        self.assertNotIn("MESSAGE-INTEGRITY", protocol.sent_message.attributes)

    @asynctest
    async def test_response_with_invalid_address(self) -> None:
        connection = ice.Connection(ice_controlling=True)
        connection.remote_password = "remote-password"
        connection.remote_username = "remote-username"

        protocol = ProtocolMock(connection, response_addr=("3.4.5.6", 3456))

        pair = ice.CandidatePair(
            protocol,
            Candidate(
                foundation="some-foundation",
                component=1,
                transport="udp",
                priority=2345,
                host="2.3.4.5",
                port=2345,
                type="host",
            ),
        )
        self.assertEqual(
            repr(pair), "CandidatePair(('1.2.3.4', 1234) -> ('2.3.4.5', 2345))"
        )

        await connection.check_start(pair)
        self.assertEqual(pair.state, ice.CandidatePair.State.FAILED)

    @asynctest
    async def test_triggered_check(self) -> None:
        expected = {
            ice.CandidatePair.State.FROZEN: True,
            ice.CandidatePair.State.WAITING: True,
            ice.CandidatePair.State.IN_PROGRESS: False,
            ice.CandidatePair.State.SUCCEEDED: False,
            ice.CandidatePair.State.FAILED: True,
        }
        for state, triggered in expected.items():
            with self.subTest(state=state):
                connection = ice.Connection(ice_controlling=True)
                connection.remote_password = "remote-password"
                connection.remote_username = "remote-username"

                protocol = ProtocolMock(connection, response_addr=("2.3.4.5", 2345))
                remote_candidate = Candidate(
                    foundation="some-foundation",
                    component=1,
                    transport="udp",
                    priority=2345,
                    host="2.3.4.5",
                    port=2345,
                    type="host",
                )
                connection._remote_candidates.append(remote_candidate)
                pair = ice.CandidatePair(protocol, remote_candidate)
                pair.state = state
                connection._check_list.append(pair)

                request = stun.Message(
                    message_method=stun.Method.BINDING,
                    message_class=stun.Class.REQUEST,
                )
                request.attributes["PRIORITY"] = 456789
                connection.check_incoming(request, ("2.3.4.5", 2345), protocol)

                # No new pair is formed.
                self.assertEqual(connection._check_list, [pair])

                if triggered:
                    self.assertEqual(pair.state, ice.CandidatePair.State.WAITING)
                    assert pair.task is not None
                    await pair.task
                    self.assertEqual(pair.state, ice.CandidatePair.State.SUCCEEDED)
                else:
                    self.assertIsNone(pair.task)
                    self.assertEqual(pair.state, state)


class IceConnectionTest(unittest.TestCase):
    def assertCandidateTypes(self, conn: ice.Connection, expected: set[str]) -> None:
        types = {c.type for c in conn.local_candidates}
        self.assertEqual(types, expected)

    def tearDown(self) -> None:
        ice.CONSENT_FAILURES = 6
        ice.CONSENT_INTERVAL = 5
        stun.RETRY_MAX = 6
        stun.RETRY_RTO = 0.5

    async def connect_and_exchange_data(
        self, conn_a: ice.Connection, conn_b: ice.Connection
    ) -> None:
        try:
            # connect
            await asyncio.gather(conn_a.connect(), conn_b.connect())

            # send data a -> b
            await conn_a.send(b"howdee")
            data = await conn_b.recv()
            self.assertEqual(data, b"howdee")

            # send data b -> a
            await conn_b.send(b"gotcha")
            data = await conn_a.recv()
            self.assertEqual(data, b"gotcha")
        finally:
            # close
            await conn_a.close()
            await conn_b.close()

    @asynctest
    async def test_local_username_and_password(self) -> None:
        # No username or password.
        connection = ice.Connection(ice_controlling=True)
        self.assertEqual(len(connection.local_username), 4)
        self.assertEqual(len(connection.local_password), 22)

        # Valid username and password.
        connection = ice.Connection(
            ice_controlling=True,
            local_username="test+User1",
            local_password="some+password/that+is/Long+en0ugh",
        )
        self.assertEqual(connection.local_username, "test+User1")
        self.assertEqual(connection.local_password, "some+password/that+is/Long+en0ugh")

        # Invalid username.
        with self.assertRaises(ValueError) as cm:
            ice.Connection(ice_controlling=True, local_username="a")
        self.assertEqual(str(cm.exception), "Username must satisfy 4*256ice-char")

        # Invalid password.
        with self.assertRaises(ValueError) as cm:
            ice.Connection(ice_controlling=True, local_password="aaaaaa")
        self.assertEqual(str(cm.exception), "Password must satisfy 22*256ice-char")

    @mock.patch("ifaddr.get_adapters")
    def test_get_host_addresses(self, mock_get_adapters: mock.MagicMock) -> None:
        mock_get_adapters.return_value = [
            ifaddr.Adapter(
                ips=[
                    ifaddr.IP(ip="127.0.0.1", network_prefix=8, nice_name="lo"),
                    ifaddr.IP(ip=("::1", 0, 0), network_prefix=128, nice_name="lo"),
                ],
                name="lo",
                nice_name="lo",
            ),
            ifaddr.Adapter(
                ips=[
                    ifaddr.IP(
                        ip="1.2.3.4",
                        network_prefix=24,
                        nice_name="eth0",
                    ),
                    ifaddr.IP(
                        ip=("2a02:0db8:85a3:0000:0000:8a2e:0370:7334", 0, 0),
                        network_prefix=64,
                        nice_name="eth0",
                    ),
                    ifaddr.IP(
                        ip=("fe80::1234:5678:9abc:def0", 0, 2),
                        network_prefix=64,
                        nice_name="eth0",
                    ),
                ],
                name="eth0",
                nice_name="eth0",
            ),
        ]

        # IPv4 only
        addresses = ice.get_host_addresses(use_ipv4=True, use_ipv6=False)
        self.assertEqual(addresses, ["1.2.3.4"])

        # IPv6 only
        addresses = ice.get_host_addresses(use_ipv4=False, use_ipv6=True)
        self.assertEqual(addresses, ["2a02:0db8:85a3:0000:0000:8a2e:0370:7334"])

        # both
        addresses = ice.get_host_addresses(use_ipv4=True, use_ipv6=True)
        self.assertEqual(
            addresses, ["1.2.3.4", "2a02:0db8:85a3:0000:0000:8a2e:0370:7334"]
        )

    @asynctest
    async def test_close(self) -> None:
        conn_a = ice.Connection(ice_controlling=True)

        # close
        event, _ = await asyncio.gather(conn_a.get_event(), conn_a.close())
        self.assertTrue(isinstance(event, ice.ConnectionClosed))

        # no more events
        event = await conn_a.get_event()
        self.assertIsNone(event)

        # close again
        await conn_a.close()

    @asynctest
    async def test_connect(self) -> None:
        conn_a = ice.Connection(ice_controlling=True)
        conn_b = ice.Connection(ice_controlling=False)

        # invite / accept
        await invite_accept(conn_a, conn_b)

        # we should only have host candidates
        self.assertCandidateTypes(conn_a, {"host"})
        self.assertCandidateTypes(conn_b, {"host"})

        # there should be a default candidate for component 1
        candidate = conn_a.get_default_candidate(1)
        assert candidate is not None
        self.assertEqual(candidate.type, "host")

        # there should not be a default candidate for component 2
        candidate = conn_a.get_default_candidate(2)
        self.assertIsNone(candidate)

        await self.connect_and_exchange_data(conn_a, conn_b)

    @asynctest
    async def test_connect_nomination_removes_unchecked_pairs(self) -> None:
        conn_a = ice.Connection(ice_controlling=True)
        conn_b = ice.Connection(ice_controlling=False)

        # Add a lowest-priority candidate which is never checked.
        unchecked = Candidate(
            foundation="unchecked",
            component=1,
            transport="udp",
            priority=1,
            host="192.0.2.1",
            port=1234,
            type="host",
        )
        await conn_a.add_remote_candidate(unchecked)
        await invite_accept(conn_a, conn_b)

        await self.connect_and_exchange_data(conn_a, conn_b)
        self.assertNotIn(unchecked, [p.remote_candidate for p in conn_a._check_list])

    @asynctest
    async def test_connect_close(self) -> None:
        conn_a = ice.Connection(ice_controlling=True)
        conn_b = ice.Connection(ice_controlling=False)

        # invite / accept
        await invite_accept(conn_a, conn_b)

        # close while connecting
        await conn_b.close()
        done, pending = await asyncio.wait(
            [
                asyncio.create_task(conn_a.connect()),
                asyncio.create_task(delay(conn_a.close)),
            ]
        )
        for task in pending:
            task.cancel()
        self.assertEqual(len(done), 2)

        exceptions = [x.exception() for x in done if x.exception()]
        self.assertEqual(len(exceptions), 1)
        self.assertTrue(isinstance(exceptions[0], ConnectionError))

    async def start_connect_with_check_in_progress(
        self, conn: ice.Connection
    ) -> asyncio.Task[None]:
        """
        Start connecting to several unreachable remote candidates, without
        end-of-candidates, and wait for the first check to be in progress.
        """
        await conn.gather_candidates()
        conn.remote_username = "foo"
        conn.remote_password = "bar"
        for port in range(31102, 31112):
            await conn.add_remote_candidate(
                Candidate.from_sdp(
                    f"6815297761 1 udp 659136 1.2.3.4 {port} typ host generation 0"
                )
            )
        connect_task = asyncio.create_task(conn.connect())
        async with asyncio.timeout(1):
            while not any(
                p.state == ice.CandidatePair.State.IN_PROGRESS for p in conn._check_list
            ):
                await asyncio.sleep(0.01)
        return connect_task

    @asynctest
    async def test_connect_close_without_end_of_candidates(self) -> None:
        stun.RETRY_RTO = 0.1

        conn = ice.Connection(ice_controlling=True)
        with spy_send_stun() as send_stun:
            connect_task = await self.start_connect_with_check_in_progress(conn)
            await conn.close()
            call_count = send_stun.call_count

            # Closing ends connect() although more candidates may be trickled.
            with self.assertRaises(ConnectionError) as cm:
                await asyncio.wait_for(connect_task, timeout=1)
            self.assertEqual(str(cm.exception), "ICE negotiation failed")

            # No check is started or retransmitted after closing.
            await asyncio.sleep(stun.RETRY_RTO * 3)
            self.assertEqual(send_stun.call_count, call_count)

    @asynctest
    async def test_connect_cancel_then_close(self) -> None:
        stun.RETRY_RTO = 0.1

        conn = ice.Connection(ice_controlling=True)
        with spy_send_stun() as send_stun:
            connect_task = await self.start_connect_with_check_in_progress(conn)
            connect_task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await connect_task

            # Closing stops the checks connect() left running.
            await conn.close()
            call_count = send_stun.call_count
            await asyncio.sleep(stun.RETRY_RTO * 3)
            self.assertEqual(send_stun.call_count, call_count)

    @asynctest
    async def test_connect_cancel_then_close_with_incoming_check(self) -> None:
        stun.RETRY_RTO = 0.1

        conn = ice.Connection(ice_controlling=True)
        connect_task = await self.start_connect_with_check_in_progress(conn)
        connect_task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await connect_task

        # Checks arrive on the socket of the pair being checked.
        pair = next(
            p
            for p in conn._check_list
            if p.state == ice.CandidatePair.State.IN_PROGRESS
        )
        protocols = list(conn._protocols)

        def receive_check(addr: tuple[str, int]) -> None:
            request = stun.Message(
                message_method=stun.Method.BINDING, message_class=stun.Class.REQUEST
            )
            request.attributes["USERNAME"] = f"{conn.local_username}:foo"
            request.attributes["PRIORITY"] = 456789
            request.attributes["ICE-CONTROLLED"] = 1
            request.add_message_integrity(conn.local_password.encode("utf8"))
            pair.protocol.datagram_received(bytes(request), addr)

        with spy_send_stun() as send_stun:

            def sent_to(addr: tuple[str, int]) -> list[stun.Class]:
                return [
                    call.args[1].message_class
                    for call in send_stun.call_args_list
                    if call.args[2] == addr
                ]

            def requests_sent() -> int:
                return sum(
                    1
                    for call in send_stun.call_args_list
                    if call.args[1].message_class == stun.Class.REQUEST
                )

            # A check from an unknown address is answered before closing.
            receive_check(("2.3.4.6", 2345))
            self.assertEqual(sent_to(("2.3.4.6", 2345)), [stun.Class.RESPONSE])

            # A check arriving while the connection closes its sockets does not
            # start a check.
            close_task = asyncio.create_task(conn.close())
            async with asyncio.timeout(1):
                while not protocols[0].transport.is_closing():
                    await asyncio.sleep(0)
            request_count = requests_sent()
            receive_check(("2.3.4.5", 2345))
            await close_task
            await asyncio.sleep(stun.RETRY_RTO * 3)
            self.assertEqual(requests_sent(), request_count)

    @asynctest
    async def test_connect_early_checks(self) -> None:
        conn_a = ice.Connection(ice_controlling=True)
        conn_b = ice.Connection(ice_controlling=False)

        # invite / accept
        await invite_accept(conn_a, conn_b)

        # connect
        await conn_a.connect()
        await asyncio.sleep(1)
        await conn_b.connect()

        # send data a -> b
        await conn_a.send(b"howdee")
        data = await conn_b.recv()
        self.assertEqual(data, b"howdee")

        # send data b -> a
        await conn_b.send(b"gotcha")
        data = await conn_a.recv()
        self.assertEqual(data, b"gotcha")

        # close
        await conn_a.close()
        await conn_b.close()

    @asynctest
    async def test_connect_early_checks_2(self) -> None:
        conn_a = ice.Connection(ice_controlling=True)
        conn_b = ice.Connection(ice_controlling=False)

        # both sides gather local candidates and exchange credentials
        await conn_a.gather_candidates()
        await conn_b.gather_candidates()
        conn_a.remote_username = conn_b.local_username
        conn_a.remote_password = conn_b.local_password
        conn_b.remote_username = conn_a.local_username
        conn_b.remote_password = conn_a.local_password

        async def connect_b() -> None:
            # side B receives offer and connects
            for candidate in conn_a.local_candidates:
                await conn_b.add_remote_candidate(candidate)
            await conn_b.add_remote_candidate(None)
            await conn_b.connect()

            # side A receives candidates
            for candidate in conn_b.local_candidates:
                await conn_a.add_remote_candidate(candidate)
            await conn_a.add_remote_candidate(None)

        # The sequence is:
        # - side A starts connecting immediately, but has no candidates
        # - side B receives candidates and connects
        # - side A receives candidates, and connection completes
        await asyncio.gather(conn_a.connect(), connect_b())

        # send data a -> b
        await conn_a.send(b"howdee")
        data = await conn_b.recv()
        self.assertEqual(data, b"howdee")

        # send data b -> a
        await conn_b.send(b"gotcha")
        data = await conn_a.recv()
        self.assertEqual(data, b"gotcha")

        # close
        await conn_a.close()
        await conn_b.close()

    @asynctest
    async def test_connect_two_components(self) -> None:
        conn_a = ice.Connection(ice_controlling=True, components=2)
        conn_b = ice.Connection(ice_controlling=False, components=2)

        # invite / accept
        await invite_accept(conn_a, conn_b)

        # we should only have host candidates
        self.assertCandidateTypes(conn_a, {"host"})
        self.assertCandidateTypes(conn_b, {"host"})

        # there should be a default candidate for component 1
        candidate = conn_a.get_default_candidate(1)
        assert candidate is not None
        self.assertEqual(candidate.type, "host")

        # there should be a default candidate for component 2
        candidate = conn_a.get_default_candidate(2)
        assert candidate is not None
        self.assertEqual(candidate.type, "host")

        # connect
        await asyncio.gather(conn_a.connect(), conn_b.connect())
        self.assertEqual(conn_a._components, {1, 2})
        self.assertEqual(conn_b._components, {1, 2})

        # send data a -> b (component 1)
        await conn_a.sendto(b"howdee", 1)
        data, component = await conn_b.recvfrom()
        self.assertEqual(data, b"howdee")
        self.assertEqual(component, 1)

        # send data b -> a (component 1)
        await conn_b.sendto(b"gotcha", 1)
        data, component = await conn_a.recvfrom()
        self.assertEqual(data, b"gotcha")
        self.assertEqual(component, 1)

        # send data a -> b (component 2)
        await conn_a.sendto(b"howdee 2", 2)
        data, component = await conn_b.recvfrom()
        self.assertEqual(data, b"howdee 2")
        self.assertEqual(component, 2)

        # send data b -> a (component 2)
        await conn_b.sendto(b"gotcha 2", 2)
        data, component = await conn_a.recvfrom()
        self.assertEqual(data, b"gotcha 2")
        self.assertEqual(component, 2)

        # close
        await conn_a.close()
        await conn_b.close()

    @asynctest
    async def test_connect_two_components_vs_one_component(self) -> None:
        """
        It is possible that some of the local candidates won't get paired with
        remote candidates, and some of the remote candidates won't get paired
        with local candidates.  This can happen if one agent doesn't include
        candidates for the all of the components for a media stream.  If this
        happens, the number of components for that media stream is effectively
        reduced, and considered to be equal to the minimum across both agents
        of the maximum component ID provided by each agent across all
        components for the media stream.
        """
        conn_a = ice.Connection(ice_controlling=True, components=2)
        conn_b = ice.Connection(ice_controlling=False, components=1)

        # invite / accept
        await invite_accept(conn_a, conn_b)
        self.assertTrue(len(conn_a.local_candidates) > 0)
        for candidate in conn_a.local_candidates:
            self.assertEqual(candidate.type, "host")

        # connect
        await asyncio.gather(conn_a.connect(), conn_b.connect())
        self.assertEqual(conn_a._components, {1})
        self.assertEqual(conn_b._components, {1})

        # send data a -> b (component 1)
        await conn_a.sendto(b"howdee", 1)
        data, component = await conn_b.recvfrom()
        self.assertEqual(data, b"howdee")
        self.assertEqual(component, 1)

        # send data b -> a (component 1)
        await conn_b.sendto(b"gotcha", 1)
        data, component = await conn_a.recvfrom()
        self.assertEqual(data, b"gotcha")
        self.assertEqual(component, 1)

        # close
        await conn_a.close()
        await conn_b.close()

    @asynctest
    async def test_connect_to_ice_lite(self) -> None:
        conn_a = ice.Connection(ice_controlling=True)
        conn_a.remote_is_lite = True
        conn_b = ice.Connection(ice_controlling=False)

        # invite / accept
        await invite_accept(conn_a, conn_b)

        # we should only have host candidates
        self.assertCandidateTypes(conn_a, {"host"})
        self.assertCandidateTypes(conn_b, {"host"})

        # there should be a default candidate for component 1
        candidate = conn_a.get_default_candidate(1)
        assert candidate is not None
        self.assertEqual(candidate.type, "host")

        # there should not be a default candidate for component 2
        candidate = conn_a.get_default_candidate(2)
        self.assertIsNone(candidate)

        await self.connect_and_exchange_data(conn_a, conn_b)

    @asynctest
    async def test_connect_to_ice_lite_nomination_fails(self) -> None:
        def mock_request_received(
            self: ice.Connection,
            message: stun.Message,
            addr: tuple[str, int],
            protocol: ice.StunProtocol,
        ) -> None:
            if "USE-CANDIDATE" in message.attributes:
                self.respond_error(message, addr, protocol, (500, "Internal Error"))
            else:
                self.real_request_received(message, addr, protocol)  # type: ignore

        conn_a = ice.Connection(ice_controlling=True)
        conn_a.remote_is_lite = True
        conn_b = ice.Connection(ice_controlling=False)
        conn_b.real_request_received = conn_b.request_received  # type: ignore
        conn_b.request_received = functools.partial(mock_request_received, conn_b)  # type: ignore

        # Exchange candidates and credentials.
        await invite_accept(conn_a, conn_b)

        # Connect.
        with self.assertRaises(ConnectionError) as cm:
            await asyncio.gather(conn_a.connect(), conn_b.connect())
        self.assertEqual(str(cm.exception), "ICE negotiation failed")

        # Close.
        await conn_a.close()
        await conn_b.close()

    @unittest.skipIf(RUNNING_ON_CI, "CI lacks ipv6")
    @asynctest
    async def test_connect_ipv6(self) -> None:
        conn_a = ice.Connection(ice_controlling=True, use_ipv4=False, use_ipv6=True)
        conn_b = ice.Connection(ice_controlling=False, use_ipv4=False, use_ipv6=True)

        # invite / accept
        await invite_accept(conn_a, conn_b)
        self.assertTrue(len(conn_a.local_candidates) > 0)
        for candidate in conn_a.local_candidates:
            self.assertEqual(candidate.type, "host")

        await self.connect_and_exchange_data(conn_a, conn_b)

    @asynctest
    async def test_connect_reverse_order(self) -> None:
        conn_a = ice.Connection(ice_controlling=True)
        conn_b = ice.Connection(ice_controlling=False)

        # invite / accept
        await invite_accept(conn_a, conn_b)

        # introduce a delay so that B's checks complete before A's
        await asyncio.gather(delay(conn_a.connect), conn_b.connect())

        # send data a -> b
        await conn_a.send(b"howdee")
        data = await conn_b.recv()
        self.assertEqual(data, b"howdee")

        # send data b -> a
        await conn_b.send(b"gotcha")
        data = await conn_a.recv()
        self.assertEqual(data, b"gotcha")

        # close
        await conn_a.close()
        await conn_b.close()

    @asynctest
    async def test_connect_invalid_password(self) -> None:
        conn_a = ice.Connection(ice_controlling=True)
        conn_b = ice.Connection(ice_controlling=False)

        # Lower STUN retries, as the errors rejecting the checks of A are not
        # signed, so they are discarded and the checks time out.
        stun.RETRY_MAX = 1

        # Send the candidates and credentials of A to B.
        await conn_a.gather_candidates()
        for candidate in conn_a.local_candidates:
            await conn_b.add_remote_candidate(candidate)
        await conn_b.add_remote_candidate(None)
        conn_b.remote_username = conn_a.local_username
        conn_b.remote_password = conn_a.local_password

        # Send the candidates and credentials of B to A, with a wrong password.
        await conn_b.gather_candidates()
        for candidate in conn_b.local_candidates:
            await conn_a.add_remote_candidate(candidate)
        await conn_a.add_remote_candidate(None)
        conn_a.remote_username = conn_b.local_username
        conn_a.remote_password = "wrong-password"

        # Connect.
        done, pending = await asyncio.wait(
            [
                asyncio.create_task(conn_a.connect()),
                asyncio.create_task(conn_b.connect()),
            ],
            return_when=asyncio.FIRST_EXCEPTION,
        )
        for task in pending:
            task.cancel()
        self.assertEqual(len(done), 1)
        self.assertTrue(isinstance(done.pop().exception(), ConnectionError))

        # Close.
        await conn_a.close()
        await conn_b.close()

    @asynctest
    async def test_connect_invalid_username(self) -> None:
        conn_a = ice.Connection(ice_controlling=True)
        conn_b = ice.Connection(ice_controlling=False)

        # Lower STUN retries, as the errors rejecting the checks are not signed,
        # so they are discarded and the checks time out.
        stun.RETRY_MAX = 1

        # Send the candidates and credentials of A to B.
        await conn_a.gather_candidates()
        for candidate in conn_a.local_candidates:
            await conn_b.add_remote_candidate(candidate)
        await conn_b.add_remote_candidate(None)
        conn_b.remote_username = conn_a.local_username
        conn_b.remote_password = conn_a.local_password

        # Send the candidates and credentials of B to A, with a wrong username.
        await conn_b.gather_candidates()
        for candidate in conn_b.local_candidates:
            await conn_a.add_remote_candidate(candidate)
        await conn_a.add_remote_candidate(None)
        conn_a.remote_username = "wrong-username"
        conn_a.remote_password = conn_b.local_password

        # Connect.
        done, pending = await asyncio.wait(
            [
                asyncio.create_task(conn_a.connect()),
                asyncio.create_task(conn_b.connect()),
            ]
        )
        for task in pending:
            task.cancel()
        self.assertEqual(len(done), 2)
        self.assertTrue(isinstance(done.pop().exception(), ConnectionError))
        self.assertTrue(isinstance(done.pop().exception(), ConnectionError))

        # Close.
        await conn_a.close()
        await conn_b.close()

    @asynctest
    async def test_connect_no_gather(self) -> None:
        """
        If local candidates gathering was not performed, connect fails.
        """
        conn = ice.Connection(ice_controlling=True)
        await conn.add_remote_candidate(
            Candidate.from_sdp(
                "6815297761 1 udp 659136 1.2.3.4 31102 typ host generation 0"
            )
        )
        await conn.add_remote_candidate(None)
        conn.remote_username = "foo"
        conn.remote_password = "bar"
        with self.assertRaises(ConnectionError) as cm:
            await conn.connect()
        self.assertEqual(
            str(cm.exception), "Local candidates gathering was not performed"
        )
        await conn.close()

    @asynctest
    async def test_connect_no_local_candidates(self) -> None:
        """
        If local candidates gathering yielded no candidates, connect fails.
        """
        conn = ice.Connection(ice_controlling=True)
        conn._local_candidates_end = True
        await conn.add_remote_candidate(
            Candidate.from_sdp(
                "6815297761 1 udp 659136 1.2.3.4 31102 typ host generation 0"
            )
        )
        await conn.add_remote_candidate(None)
        conn.remote_username = "foo"
        conn.remote_password = "bar"
        with self.assertRaises(ConnectionError) as cm:
            await conn.connect()
        self.assertEqual(str(cm.exception), "ICE negotiation failed")
        await conn.close()

    @asynctest
    async def test_connect_no_remote_candidates(self) -> None:
        """
        If no remote candidates were provided, connect fails.
        """
        conn = ice.Connection(ice_controlling=True)
        await conn.gather_candidates()
        await conn.add_remote_candidate(None)
        conn.remote_username = "foo"
        conn.remote_password = "bar"
        with self.assertRaises(ConnectionError) as cm:
            await conn.connect()
        self.assertEqual(str(cm.exception), "ICE negotiation failed")
        await conn.close()

    @asynctest
    async def test_connect_no_remote_candidates_trickled(self) -> None:
        """
        If end-of-candidates arrives during connect without any remote
        candidates, connect fails.
        """
        conn = ice.Connection(ice_controlling=True)
        await conn.gather_candidates()
        conn.remote_username = "foo"
        conn.remote_password = "bar"
        connect_task = asyncio.create_task(conn.connect())
        await asyncio.sleep(0.1)
        self.assertFalse(connect_task.done())

        with self.assertLogs("aioice.ice", level="INFO") as logs:
            await conn.add_remote_candidate(None)
            with self.assertRaises(ConnectionError) as cm:
                await connect_task
        self.assertEqual(str(cm.exception), "ICE negotiation failed")
        self.assertFalse(any("ICE completed" in line for line in logs.output))
        await conn.close()

    @asynctest
    async def test_connect_no_remote_credentials(self) -> None:
        """
        If remote credentials have not been provided, connect fails.
        """
        conn = ice.Connection(ice_controlling=True)
        await conn.gather_candidates()
        await conn.add_remote_candidate(
            Candidate.from_sdp(
                "6815297761 1 udp 659136 1.2.3.4 31102 typ host generation 0"
            )
        )
        await conn.add_remote_candidate(None)
        with self.assertRaises(ConnectionError) as cm:
            await conn.connect()
        self.assertEqual(str(cm.exception), "Remote username or password is missing")
        await conn.close()

    @asynctest
    async def test_connect_role_conflict_both_controlling(self) -> None:
        conn_a = ice.Connection(ice_controlling=True)
        conn_b = ice.Connection(ice_controlling=True)

        # set tie breaker for a deterministic outcome
        conn_a._tie_breaker = 1
        conn_b._tie_breaker = 2

        # invite / accept
        await invite_accept(conn_a, conn_b)

        # connect
        await asyncio.gather(conn_a.connect(), conn_b.connect())
        self.assertFalse(conn_a.ice_controlling)
        self.assertTrue(conn_b.ice_controlling)

        # close
        await conn_a.close()
        await conn_b.close()

    @asynctest
    async def test_connect_role_conflict_both_controlled(self) -> None:
        conn_a = ice.Connection(ice_controlling=False)
        conn_b = ice.Connection(ice_controlling=False)

        # set tie breaker for a deterministic outcome
        conn_a._tie_breaker = 1
        conn_b._tie_breaker = 2

        # invite / accept
        await invite_accept(conn_a, conn_b)

        # connect
        await asyncio.gather(conn_a.connect(), conn_b.connect())
        self.assertFalse(conn_a.ice_controlling)
        self.assertTrue(conn_b.ice_controlling)

        # close
        await conn_a.close()
        await conn_b.close()

    @asynctest
    async def test_connect_timeout(self) -> None:
        # lower STUN retries
        stun.RETRY_MAX = 1

        conn = ice.Connection(ice_controlling=True)
        await conn.gather_candidates()
        await conn.add_remote_candidate(
            Candidate.from_sdp(
                "6815297761 1 udp 659136 1.2.3.4 31102 typ host generation 0"
            )
        )
        await conn.add_remote_candidate(None)
        conn.remote_username = "foo"
        conn.remote_password = "bar"
        with self.assertRaises(ConnectionError) as cm:
            await conn.connect()
        self.assertEqual(str(cm.exception), "ICE negotiation failed")
        await conn.close()

    @asynctest
    async def test_connect_unauthenticated_response(self) -> None:
        """
        A check response, success or error, which is not authenticated with
        the remote password must be discarded (RFC 8489 section 9.1.4).
        """
        # Lower STUN retries.
        stun.RETRY_MAX = 1

        class Responder(asyncio.DatagramProtocol):
            """
            Answer the first Binding request without knowing the remote password.
            """

            def __init__(
                self, message_class: stun.Class, integrity_key: bytes | None
            ) -> None:
                self.answered = False
                self.integrity_key = integrity_key
                self.message_class = message_class

            def connection_made(self, transport: asyncio.BaseTransport) -> None:
                self.transport = cast(asyncio.DatagramTransport, transport)

            def datagram_received(
                self, data: bytes | str, addr: tuple[Any, ...]
            ) -> None:
                # Leave retransmissions unanswered, so that checks end.
                if self.answered:
                    return
                self.answered = True

                request = stun.parse_message(cast(bytes, data))
                response = stun.Message(
                    message_method=stun.Method.BINDING,
                    message_class=self.message_class,
                    transaction_id=request.transaction_id,
                )
                if self.message_class == stun.Class.ERROR:
                    response.attributes["ERROR-CODE"] = (487, "Role Conflict")
                else:
                    response.attributes["XOR-MAPPED-ADDRESS"] = (addr[0], addr[1])
                if self.integrity_key is not None:
                    response.add_message_integrity(self.integrity_key)
                self.transport.sendto(bytes(response), addr)

        loop = asyncio.get_running_loop()
        for message_class, integrity_key in [
            (stun.Class.RESPONSE, None),
            (stun.Class.RESPONSE, b"wrong-password"),
            (stun.Class.ERROR, None),
        ]:
            with self.subTest(message_class=message_class, integrity_key=integrity_key):
                conn = ice.Connection(ice_controlling=True, use_ipv6=False)
                await conn.gather_candidates()

                # Answer checks from an address the remote candidate points to.
                local_host = conn.local_candidates[0].host
                transport, _ = await loop.create_datagram_endpoint(
                    lambda: Responder(message_class, integrity_key),
                    local_addr=(local_host, 0),
                )
                remote_port = transport.get_extra_info("sockname")[1]
                await conn.add_remote_candidate(
                    Candidate.from_sdp(
                        f"1 1 udp 2130706431 {local_host} {remote_port} typ host"
                    )
                )
                await conn.add_remote_candidate(None)
                conn.remote_username = "foo"
                conn.remote_password = "bar"

                try:
                    with self.assertRaises(ConnectionError) as cm:
                        await conn.connect()
                    self.assertEqual(str(cm.exception), "ICE negotiation failed")

                    # A forged role conflict must not switch roles.
                    self.assertTrue(conn.ice_controlling)
                finally:
                    await conn.close()
                    transport.close()

    async def start_trickle_with_failed_pairs(
        self, conn: ice.Connection
    ) -> asyncio.Task[None]:
        """
        Start connecting with a single unreachable remote candidate, without
        end-of-candidates, and wait for its pairs to fail.
        """
        await conn.add_remote_candidate(
            Candidate.from_sdp(
                "6815297761 1 udp 659136 1.2.3.4 31102 typ host generation 0"
            )
        )
        connect_task = asyncio.create_task(conn.connect())
        while not conn._check_list or any(
            p.state != ice.CandidatePair.State.FAILED for p in conn._check_list
        ):
            await asyncio.sleep(0.1)

        # More candidates may still be trickled, so ICE has not failed.
        await asyncio.sleep(0.1)
        self.assertFalse(connect_task.done())
        return connect_task

    @asynctest
    async def test_connect_trickle_after_failed_pairs(self) -> None:
        # lower STUN retries
        stun.RETRY_MAX = 1

        conn_a = ice.Connection(ice_controlling=False)
        conn_b = ice.Connection(ice_controlling=True)
        await conn_a.gather_candidates()
        await conn_b.gather_candidates()
        conn_a.remote_username = conn_b.local_username
        conn_a.remote_password = conn_b.local_password
        conn_b.remote_username = conn_a.local_username
        conn_b.remote_password = conn_a.local_password

        connect_task = await self.start_trickle_with_failed_pairs(conn_a)

        # Working candidates are trickled after the first pairs failed.
        for candidate in conn_b.local_candidates:
            await conn_a.add_remote_candidate(candidate)
        await conn_a.add_remote_candidate(None)
        for candidate in conn_a.local_candidates:
            await conn_b.add_remote_candidate(candidate)
        await conn_b.add_remote_candidate(None)
        await asyncio.gather(connect_task, conn_b.connect())

        await conn_a.close()
        await conn_b.close()

    @asynctest
    async def test_connect_trickle_fails_after_end_of_candidates(self) -> None:
        # lower STUN retries
        stun.RETRY_MAX = 1

        conn = ice.Connection(ice_controlling=True)
        await conn.gather_candidates()
        conn.remote_username = "foo"
        conn.remote_password = "bar"

        connect_task = await self.start_trickle_with_failed_pairs(conn)

        # ICE fails once end-of-candidates is received.
        await conn.add_remote_candidate(None)
        with self.assertRaises(ConnectionError) as cm:
            await connect_task
        self.assertEqual(str(cm.exception), "ICE negotiation failed")
        await conn.close()

    @asynctest
    async def test_connect_trickle_prunes_component(self) -> None:
        conn_a = ice.Connection(ice_controlling=True, components=2)
        conn_b = ice.Connection(ice_controlling=False, components=1)
        await conn_a.gather_candidates()
        await conn_b.gather_candidates()
        conn_a.remote_username = conn_b.local_username
        conn_a.remote_password = conn_b.local_password
        conn_b.remote_username = conn_a.local_username
        conn_b.remote_password = conn_a.local_password

        # Side B only has candidates for the first component.
        for candidate in conn_a.local_candidates:
            await conn_b.add_remote_candidate(candidate)
        await conn_b.add_remote_candidate(None)
        for candidate in conn_b.local_candidates:
            await conn_a.add_remote_candidate(candidate)
        connect_task = asyncio.gather(conn_a.connect(), conn_b.connect())

        async def wait_nominated() -> None:
            while 1 not in conn_a._nominated:
                await asyncio.sleep(0.1)

        await asyncio.wait_for(wait_nominated(), timeout=5)
        self.assertFalse(connect_task.done())

        # Side A completes once end-of-candidates removes the second component.
        await conn_a.add_remote_candidate(None)
        await asyncio.wait_for(connect_task, timeout=5)
        self.assertEqual(conn_a._components, {1})

        await conn_a.close()
        await conn_b.close()

    @asynctest
    async def test_connect_with_stun_server(self) -> None:
        async with run_turn_server() as stun_server:
            conn_a = ice.Connection(
                ice_controlling=True, stun_server=stun_server.udp_address
            )
            conn_b = ice.Connection(ice_controlling=False)

            # invite / accept
            await invite_accept(conn_a, conn_b)

            # we whould have both host and server-reflexive candidates
            self.assertCandidateTypes(conn_a, {"host", "srflx"})
            self.assertCandidateTypes(conn_b, {"host"})

            # the default candidate should be server-reflexive
            candidate = conn_a.get_default_candidate(1)
            assert candidate is not None
            self.assertEqual(candidate.type, "srflx")
            self.assertIsNotNone(candidate.related_address)
            self.assertIsNotNone(candidate.related_port)

            await self.connect_and_exchange_data(conn_a, conn_b)

    @asynctest
    async def test_connect_with_stun_server_dns_lookup_error(self) -> None:
        conn_a = ice.Connection(ice_controlling=True, stun_server=("invalid.", 1234))
        conn_b = ice.Connection(ice_controlling=False)

        # invite / accept
        await invite_accept(conn_a, conn_b)

        # we whould have only host candidates
        self.assertCandidateTypes(conn_a, {"host"})
        self.assertCandidateTypes(conn_b, {"host"})

        await self.connect_and_exchange_data(conn_a, conn_b)

    @asynctest
    async def test_connect_with_stun_server_timeout(self) -> None:
        async with run_turn_server() as stun_server:
            # immediately stop turn server
            await stun_server.close()

            conn_a = ice.Connection(
                ice_controlling=True, stun_server=stun_server.udp_address
            )
            conn_b = ice.Connection(ice_controlling=False)

            # invite / accept
            await invite_accept(conn_a, conn_b)

            # we whould have only host candidates
            self.assertCandidateTypes(conn_a, {"host"})
            self.assertCandidateTypes(conn_b, {"host"})

            await self.connect_and_exchange_data(conn_a, conn_b)

    @unittest.skipIf(RUNNING_ON_CI, "CI lacks ipv6")
    @asynctest
    async def test_connect_with_stun_server_ipv6(self) -> None:
        async with run_turn_server() as stun_server:
            conn_a = ice.Connection(
                ice_controlling=True,
                stun_server=stun_server.udp_address,
                use_ipv4=False,
                use_ipv6=True,
            )
            conn_b = ice.Connection(
                ice_controlling=False, use_ipv4=False, use_ipv6=True
            )

            # invite / accept
            await invite_accept(conn_a, conn_b)

            # we only want host candidates : no STUN for IPv6
            self.assertTrue(len(conn_a.local_candidates) > 0)
            for candidate in conn_a.local_candidates:
                self.assertEqual(candidate.type, "host")

            await self.connect_and_exchange_data(conn_a, conn_b)

    @asynctest
    async def test_connect_relay_only(self) -> None:
        """
        Connect using only the relayed candidate, with the relay transport policy.
        """
        async with run_turn_server(users={"foo": "bar"}) as turn_server:
            conn_a = ice.Connection(
                ice_controlling=True,
                turn_server=turn_server.udp_address,
                turn_username="foo",
                turn_password="bar",
                transport_policy=TransportPolicy.RELAY,
            )
            conn_b = ice.Connection(ice_controlling=False)

            # Exchange candidates and credentials. Connection B only uses the loopback
            # address, which Windows requires to reach the test TURN server's relay.
            with mock.patch(
                "aioice.ice.get_host_addresses", return_value=["127.0.0.1"]
            ):
                await invite_accept(conn_a, conn_b)

            # Connect, and check the nominated pair uses the relayed candidate.
            await asyncio.gather(conn_a.connect(), conn_b.connect())
            self.assertEqual(conn_a._nominated[1].local_candidate.type, "relay")

            # Send data both ways.
            await conn_a.send(b"howdee")
            self.assertEqual(await conn_b.recv(), b"howdee")
            await conn_b.send(b"gotcha")
            self.assertEqual(await conn_a.recv(), b"gotcha")

            # Close the connections.
            await conn_a.close()
            await conn_b.close()

    @asynctest
    async def test_connect_with_turn_server_tcp(self) -> None:
        async with run_turn_server(users={"foo": "bar"}) as turn_server:
            # Create the connections.
            conn_a = ice.Connection(
                ice_controlling=True,
                turn_server=turn_server.tcp_address,
                turn_username="foo",
                turn_password="bar",
                turn_transport="tcp",
            )
            conn_b = ice.Connection(ice_controlling=False)

            # Exchange candidates and credentials.
            await invite_accept(conn_a, conn_b)

            # Check both host and relayed candidates were gathered.
            self.assertCandidateTypes(conn_a, {"host", "relay"})
            self.assertCandidateTypes(conn_b, {"host"})

            # Check the default candidate is relayed, and does not hide its related
            # address.
            candidate = conn_a.get_default_candidate(1)
            assert candidate is not None
            self.assertEqual(candidate.type, "relay")
            self.assertIsNotNone(candidate.related_address)
            self.assertNotEqual(candidate.related_address, "0.0.0.0")
            self.assertIsNotNone(candidate.related_port)

            await self.connect_and_exchange_data(conn_a, conn_b)

    @asynctest
    async def test_connect_with_turn_server_udp(self) -> None:
        async with run_turn_server(users={"foo": "bar"}) as turn_server:
            # Create the connections.
            conn_a = ice.Connection(
                ice_controlling=True,
                turn_server=turn_server.udp_address,
                turn_username="foo",
                turn_password="bar",
            )
            conn_b = ice.Connection(ice_controlling=False)

            # Exchange candidates and credentials.
            await invite_accept(conn_a, conn_b)

            # Check both host and relayed candidates were gathered.
            self.assertCandidateTypes(conn_a, {"host", "relay"})
            self.assertCandidateTypes(conn_b, {"host"})

            # Check the default candidate is relayed, and does not hide its related
            # address.
            candidate = conn_a.get_default_candidate(1)
            assert candidate is not None
            self.assertEqual(candidate.type, "relay")
            self.assertIsNotNone(candidate.related_address)
            self.assertNotEqual(candidate.related_address, "0.0.0.0")
            self.assertIsNotNone(candidate.related_port)

            await self.connect_and_exchange_data(conn_a, conn_b)

    @asynctest
    async def test_connect_with_turn_server_udp_auth_failed(self) -> None:
        async with run_turn_server(users={"foo": "bar"}) as turn_server:
            # create connections
            conn_a = ice.Connection(
                ice_controlling=True,
                turn_server=turn_server.udp_address,
                turn_username="foo",
                turn_password="incorrect",
            )
            conn_b = ice.Connection(ice_controlling=False)

            # invite / accept
            await invite_accept(conn_a, conn_b)

            # we should only have host candidates
            self.assertCandidateTypes(conn_a, {"host"})
            self.assertCandidateTypes(conn_b, {"host"})

            # the default candidate should be host
            candidate = conn_a.get_default_candidate(1)
            assert candidate is not None
            self.assertEqual(candidate.type, "host")
            self.assertIsNone(candidate.related_address)
            self.assertIsNone(candidate.related_port)

            await self.connect_and_exchange_data(conn_a, conn_b)

    @asynctest
    async def test_connect_with_turn_server_udp_timeout(self) -> None:
        async with run_turn_server(users={"foo": "bar"}) as turn_server:
            # immediately stop turn server
            await turn_server.close()

            # create connections
            conn_a = ice.Connection(
                ice_controlling=True,
                turn_server=turn_server.udp_address,
                turn_username="foo",
                turn_password="bar",
            )
            conn_b = ice.Connection(ice_controlling=False)

            # invite / accept
            await invite_accept(conn_a, conn_b)

            # we should only have host candidates
            self.assertCandidateTypes(conn_a, {"host"})
            self.assertCandidateTypes(conn_b, {"host"})

            # the default candidate should be host
            candidate = conn_a.get_default_candidate(1)
            assert candidate is not None
            self.assertEqual(candidate.type, "host")
            self.assertIsNone(candidate.related_address)
            self.assertIsNone(candidate.related_port)

            await self.connect_and_exchange_data(conn_a, conn_b)

    @asynctest
    async def test_consent_expired(self) -> None:
        # lower consent timer
        ice.CONSENT_FAILURES = 1
        ice.CONSENT_INTERVAL = 1

        conn_a = ice.Connection(ice_controlling=True)
        conn_b = ice.Connection(ice_controlling=False)

        # invite / accept
        await invite_accept(conn_a, conn_b)

        # connect
        await asyncio.gather(conn_a.connect(), conn_b.connect())
        self.assertEqual(len(conn_a._nominated), 1)

        # let consent expire
        await conn_b.close()
        await asyncio.sleep(2)
        self.assertEqual(len(conn_a._nominated), 0)

        # close
        await conn_a.close()

    @asynctest
    async def test_consent_valid(self) -> None:
        # lower consent timer
        ice.CONSENT_FAILURES = 1
        ice.CONSENT_INTERVAL = 1

        conn_a = ice.Connection(ice_controlling=True)
        conn_b = ice.Connection(ice_controlling=False)

        # invite / accept
        await invite_accept(conn_a, conn_b)

        # connect
        await asyncio.gather(conn_a.connect(), conn_b.connect())
        self.assertEqual(len(conn_a._nominated), 1)

        # check consent
        await asyncio.sleep(2)
        self.assertEqual(len(conn_a._nominated), 1)

        # close
        await conn_a.close()
        await conn_b.close()

    @asynctest
    async def test_set_selected_pair(self) -> None:
        conn_a = ice.Connection(ice_controlling=True)
        conn_b = ice.Connection(ice_controlling=False)

        # invite / accept
        await invite_accept(conn_a, conn_b)

        # we should only have host candidates
        self.assertCandidateTypes(conn_a, {"host"})
        self.assertCandidateTypes(conn_b, {"host"})

        # force selected pair
        default_a = conn_a.get_default_candidate(1)
        default_b = conn_b.get_default_candidate(1)
        assert default_a is not None and default_b is not None
        conn_a.set_selected_pair(1, default_a.foundation, default_b.foundation)
        conn_b.set_selected_pair(1, default_b.foundation, default_a.foundation)

        # send data a -> b
        await conn_a.send(b"howdee")
        data = await conn_b.recv()
        self.assertEqual(data, b"howdee")

        # send data b -> a
        await conn_b.send(b"gotcha")
        data = await conn_a.recv()
        self.assertEqual(data, b"gotcha")

        # close
        await conn_a.close()
        await conn_b.close()

    @asynctest
    async def test_recv_not_connected(self) -> None:
        conn_a = ice.Connection(ice_controlling=True)
        with self.assertRaises(ConnectionError) as cm:
            await conn_a.recv()
        self.assertEqual(str(cm.exception), "Cannot receive data, not connected")

    @asynctest
    async def test_recv_connection_lost(self) -> None:
        conn_a = ice.Connection(ice_controlling=True)
        conn_b = ice.Connection(ice_controlling=False)

        # invite / accept
        await invite_accept(conn_a, conn_b)

        # connect
        await asyncio.gather(conn_a.connect(), conn_b.connect())

        # disconnect while receiving
        with self.assertRaises(ConnectionError) as cm:
            await asyncio.gather(conn_a.recv(), delay(conn_a.close))
        self.assertEqual(str(cm.exception), "Connection lost while receiving data")

        # close
        await conn_b.close()

    @asynctest
    async def test_recv_nominated_protocol_lost(self) -> None:
        conn_a = ice.Connection(ice_controlling=True)
        conn_b = ice.Connection(ice_controlling=False)

        # Exchange candidates and credentials.
        await invite_accept(conn_a, conn_b)

        # Connect.
        await asyncio.gather(conn_a.connect(), conn_b.connect())

        # Lose the nominated protocol.
        await conn_a._nominated[1].protocol.close()

        with self.assertRaises(ConnectionError) as cm:
            await conn_a.recv()
        self.assertEqual(str(cm.exception), "Connection lost while receiving data")

        # Close.
        await conn_a.close()
        await conn_b.close()

    @asynctest
    async def test_recv_unnominated_protocol_lost(self) -> None:
        conn_a = ice.Connection(ice_controlling=True)
        conn_b = ice.Connection(ice_controlling=False)

        # Exchange candidates and credentials.
        await invite_accept(conn_a, conn_b)

        # Connect.
        await asyncio.gather(conn_a.connect(), conn_b.connect())

        # Lose a protocol which is not nominated.
        loop = asyncio.get_running_loop()
        _, protocol = await loop.create_datagram_endpoint(
            lambda: ice.StunProtocol(conn_a), local_addr=("127.0.0.1", 0)
        )
        conn_a._protocols.append(protocol)
        await protocol.close()

        # Data is still received on the nominated pair.
        await conn_b.send(b"howdee")
        data = await conn_a.recv()
        self.assertEqual(data, b"howdee")

        # Close.
        await conn_a.close()
        await conn_b.close()

    @asynctest
    async def test_send_not_connected(self) -> None:
        conn_a = ice.Connection(ice_controlling=True)
        with self.assertRaises(ConnectionError) as cm:
            await conn_a.send(b"howdee")
        self.assertEqual(str(cm.exception), "Cannot send data, not connected")

    @asynctest
    async def test_add_remote_candidate(self) -> None:
        conn_a = ice.Connection(ice_controlling=True)

        remote_candidate = Candidate(
            foundation="some-foundation",
            component=1,
            transport="udp",
            priority=1234,
            host="1.2.3.4",
            port=1234,
            type="host",
        )

        # add candidate
        await conn_a.add_remote_candidate(remote_candidate)
        self.assertEqual(len(conn_a.remote_candidates), 1)
        self.assertEqual(conn_a.remote_candidates[0].host, "1.2.3.4")
        self.assertEqual(conn_a._remote_candidates_end, False)

        # end-of-candidates
        await conn_a.add_remote_candidate(None)
        self.assertEqual(len(conn_a.remote_candidates), 1)
        self.assertEqual(conn_a._remote_candidates_end, True)

        # try adding another candidate
        with self.assertRaises(ValueError) as cm:
            await conn_a.add_remote_candidate(remote_candidate)
        self.assertEqual(
            str(cm.exception), "Cannot add remote candidate after end-of-candidates."
        )
        self.assertEqual(len(conn_a.remote_candidates), 1)
        self.assertEqual(conn_a._remote_candidates_end, True)

    @unittest.skipIf(RUNNING_ON_MAC_CI, "Mac CI has issues with mDNS")
    @asynctest
    async def test_add_remote_candidate_mdns_bad(self) -> None:
        """
        Add an mDNS candidate which cannot be resolved.
        """
        conn_a = ice.Connection(ice_controlling=True)

        await conn_a.add_remote_candidate(
            Candidate(
                foundation="some-foundation",
                component=1,
                transport="udp",
                priority=1234,
                host=mdns.create_mdns_hostname(),
                port=1234,
                type="host",
            )
        )
        self.assertEqual(len(conn_a.remote_candidates), 0)
        self.assertEqual(conn_a._remote_candidates_end, False)

        # close
        await conn_a.close()

    @asynctest
    async def test_add_remote_candidate_mdns_without_multicast(self) -> None:
        """
        Add an mDNS candidate when the mDNS group cannot be joined.
        """
        conn_a = ice.Connection(ice_controlling=True)

        with multicast_join_fails(), self.assertLogs("aioice.mdns") as cm:
            await conn_a.add_remote_candidate(
                Candidate(
                    foundation="some-foundation",
                    component=1,
                    transport="udp",
                    priority=1234,
                    host=mdns.create_mdns_hostname(),
                    port=1234,
                    type="host",
                )
            )
        self.assertEqual(len(conn_a.remote_candidates), 0)
        self.assertEqual(
            cm.output,
            [
                "INFO:aioice.mdns:Could not join the mDNS group: "
                f"[Errno {errno.ENODEV}] No such device"
            ],
        )

        # Close.
        await conn_a.close()

    @unittest.skipIf(RUNNING_ON_MAC_CI, "Mac CI has issues with mDNS")
    @asynctest
    async def test_add_remote_candidate_mdns_good(self) -> None:
        """
        Add an mDNS candidate which can be resolved.
        """
        hostname = mdns.create_mdns_hostname()
        publisher = await mdns.create_mdns_protocol()
        await publisher.publish(hostname, "1.2.3.4")

        conn_a = ice.Connection(ice_controlling=True)

        await conn_a.add_remote_candidate(
            Candidate(
                foundation="some-foundation",
                component=1,
                transport="udp",
                priority=1234,
                host=hostname,
                port=1234,
                type="host",
            )
        )
        self.assertEqual(len(conn_a.remote_candidates), 1)
        self.assertEqual(conn_a.remote_candidates[0].host, hostname)
        self.assertEqual(conn_a.remote_candidates[0]._network_host, "1.2.3.4")
        self.assertEqual(conn_a._remote_candidates_end, False)

        # close
        await conn_a.close()
        await publisher.close()

    @unittest.skipIf(RUNNING_ON_MAC_CI, "Mac CI has issues with mDNS")
    @asynctest
    async def test_add_remote_candidate_mdns_after_checks(self) -> None:
        """
        Add mDNS candidates after the peer's checks have arrived.
        """
        conn_a = ice.Connection(ice_controlling=True)
        conn_b = ice.Connection(ice_controlling=False)
        publisher = await mdns.create_mdns_protocol()

        # Exchange credentials.
        await conn_a.gather_candidates()
        await conn_b.gather_candidates()
        conn_a.remote_username = conn_b.local_username
        conn_a.remote_password = conn_b.local_password
        conn_b.remote_username = conn_a.local_username
        conn_b.remote_password = conn_a.local_password

        # Connection B knows connection A's candidates.
        for candidate in conn_a.local_candidates:
            await conn_b.add_remote_candidate(candidate)
        await conn_b.add_remote_candidate(None)

        # Connection B's candidates are only signalled once its checks arrived.
        async def add_mdns_candidates_later() -> None:
            await asyncio.sleep(0.5)

            # Check connection B's checks were learned as peer-reflexive.
            self.assertEqual({c.type for c in conn_a.remote_candidates}, {"prflx"})

            await add_mdns_candidates(publisher, conn_a, conn_b.local_candidates)

        await asyncio.gather(
            conn_a.connect(), conn_b.connect(), add_mdns_candidates_later()
        )

        # Check the signalled candidates replaced the peer-reflexive ones.
        self.assertEqual(
            {c.type for c in conn_a.remote_candidates},
            {c.type for c in conn_b.local_candidates},
        )

        # Check the updated candidates show their mDNS name.
        for candidate in conn_a.remote_candidates:
            self.assertTrue(mdns.is_mdns_hostname(candidate.host))

        # Check no duplicate pair was formed.
        pairs = [(p.protocol, p.remote_addr) for p in conn_a._check_list]
        self.assertEqual(len(pairs), len(set(pairs)))

        # Close the connections and the mDNS publisher.
        await conn_a.close()
        await conn_b.close()
        await publisher.close()

    @unittest.skipIf(RUNNING_ON_MAC_CI, "Mac CI has issues with mDNS")
    @asynctest
    async def test_connect_mdns(self) -> None:
        """
        Connect using the peer's mDNS candidates.
        """
        conn_a = ice.Connection(ice_controlling=True)
        conn_b = ice.Connection(ice_controlling=False)
        publisher = await mdns.create_mdns_protocol()

        # Exchange credentials.
        await conn_a.gather_candidates()
        await conn_b.gather_candidates()
        conn_a.remote_username = conn_b.local_username
        conn_a.remote_password = conn_b.local_password
        conn_b.remote_username = conn_a.local_username
        conn_b.remote_password = conn_a.local_password

        # Connection A's candidates are signalled as is.
        for candidate in conn_a.local_candidates:
            await conn_b.add_remote_candidate(candidate)
        await conn_b.add_remote_candidate(None)

        # Connection B's candidates are signalled as mDNS candidates.
        await add_mdns_candidates(publisher, conn_a, conn_b.local_candidates)

        await asyncio.gather(conn_a.connect(), conn_b.connect())

        # Check the remote candidates keep their name and no peer-reflexive
        # candidate was learned.
        self.assertEqual(len(conn_a.remote_candidates), len(conn_b.local_candidates))
        for candidate in conn_a.remote_candidates:
            self.assertTrue(mdns.is_mdns_hostname(candidate.host))
            self.assertEqual(candidate.type, "host")

        # Check the pairs use the resolved addresses.
        local_hosts = {c.host for c in conn_b.local_candidates}
        for pair in conn_a._check_list:
            self.assertIn(pair.remote_addr[0], local_hosts)

        # Send data a -> b.
        await conn_a.send(b"howdee")
        data = await conn_b.recv()
        self.assertEqual(data, b"howdee")

        # Close the connections and the mDNS publisher.
        await conn_a.close()
        await conn_b.close()
        await publisher.close()

    @unittest.skipIf(RUNNING_ON_MAC_CI, "Mac CI has issues with mDNS")
    @asynctest
    async def test_add_remote_candidate_mdns_then_end_of_candidates(self) -> None:
        """
        Signal end-of-candidates while an mDNS candidate is being resolved.
        """
        hostname = mdns.create_mdns_hostname()
        publisher = await mdns.create_mdns_protocol()
        await publisher.publish(hostname, "1.2.3.4")

        conn_a = ice.Connection(ice_controlling=True)

        task = asyncio.create_task(
            conn_a.add_remote_candidate(
                Candidate(
                    foundation="some-foundation",
                    component=1,
                    transport="udp",
                    priority=1234,
                    host=hostname,
                    port=1234,
                    type="host",
                )
            )
        )
        await asyncio.sleep(0)
        await conn_a.add_remote_candidate(None)
        await task

        # Check the candidate was added and its component was kept.
        self.assertEqual(len(conn_a.remote_candidates), 1)
        self.assertEqual(conn_a.remote_candidates[0].host, hostname)
        self.assertEqual(conn_a.remote_candidates[0]._network_host, "1.2.3.4")
        self.assertEqual(conn_a._components, {1})
        self.assertEqual(conn_a._remote_candidates_end, True)

        # Close the connection and the mDNS publisher.
        await conn_a.close()
        await publisher.close()

    @asynctest
    async def test_add_remote_candidate_mdns_after_close(self) -> None:
        """
        Add an mDNS candidate once the connection is closed.
        """
        conn_a = ice.Connection(ice_controlling=True)
        await conn_a.close()

        with mock.patch("aioice.ice.get_or_create_mdns_protocol") as mock_get:
            await conn_a.add_remote_candidate(
                Candidate(
                    foundation="some-foundation",
                    component=1,
                    transport="udp",
                    priority=1234,
                    host=mdns.create_mdns_hostname(),
                    port=1234,
                    type="host",
                )
            )

        # Check the candidate was ignored, without subscribing to mDNS again.
        self.assertEqual(conn_a.remote_candidates, [])
        mock_get.assert_not_called()

    @asynctest
    async def test_add_remote_candidate_mdns_relay_only(self) -> None:
        """
        Add an mDNS candidate with the relay transport policy.
        """
        conn_a = ice.Connection(
            ice_controlling=True, transport_policy=TransportPolicy.RELAY
        )

        with mock.patch("aioice.ice.get_or_create_mdns_protocol") as mock_get:
            await conn_a.add_remote_candidate(
                Candidate(
                    foundation="some-foundation",
                    component=1,
                    transport="udp",
                    priority=1234,
                    host=mdns.create_mdns_hostname(),
                    port=1234,
                    type="host",
                )
            )

        # Check the candidate was ignored, without resolving it.
        self.assertEqual(conn_a.remote_candidates, [])
        mock_get.assert_not_called()

        # Close the connection.
        await conn_a.close()

    @unittest.skipIf(RUNNING_ON_MAC_CI, "Mac CI has issues with mDNS")
    @asynctest
    async def test_add_remote_candidate_mdns_then_close(self) -> None:
        """
        Close the connection while an mDNS candidate is being resolved.
        """
        hostname = mdns.create_mdns_hostname()
        publisher = await mdns.create_mdns_protocol()
        await publisher.publish(hostname, "1.2.3.4")

        conn_a = ice.Connection(ice_controlling=True)

        # Another connection keeps the mDNS protocol open, so the name resolves.
        conn_b = ice.Connection(ice_controlling=False)
        await ice.get_or_create_mdns_protocol(conn_b)

        task = asyncio.create_task(
            conn_a.add_remote_candidate(
                Candidate(
                    foundation="some-foundation",
                    component=1,
                    transport="udp",
                    priority=1234,
                    host=hostname,
                    port=1234,
                    type="host",
                )
            )
        )
        await asyncio.sleep(0)
        await conn_a.add_remote_candidate(None)
        await conn_a.close()
        await task

        # Check the resolved candidate and end-of-candidates were ignored.
        self.assertEqual(conn_a.remote_candidates, [])
        self.assertEqual(conn_a._components, {1})
        self.assertNotIn(conn_a, ice._mdns.subscribers)

        # Close the other connection and the mDNS publisher.
        await conn_b.close()
        await publisher.close()

    @unittest.skipIf(RUNNING_ON_MAC_CI, "Mac CI has issues with mDNS")
    @asynctest
    async def test_connect_mdns_bad_then_end_of_candidates(self) -> None:
        """
        ICE only fails once the last mDNS candidate could not be resolved.
        """
        conn_a = ice.Connection(ice_controlling=True)
        conn_b = ice.Connection(ice_controlling=False)
        await conn_a.gather_candidates()
        conn_a.remote_username = conn_b.local_username
        conn_a.remote_password = conn_b.local_password

        connect_task = asyncio.create_task(conn_a.connect())
        add_task = asyncio.create_task(
            conn_a.add_remote_candidate(
                Candidate(
                    foundation="some-foundation",
                    component=1,
                    transport="udp",
                    priority=1234,
                    host=mdns.create_mdns_hostname(),
                    port=1234,
                    type="host",
                )
            )
        )
        await asyncio.sleep(0)
        await conn_a.add_remote_candidate(None)

        # Check ICE does not fail while the candidate is being resolved.
        await asyncio.sleep(0.5)
        self.assertFalse(connect_task.done())

        # Check ICE fails once the resolution failed.
        await add_task
        with self.assertRaises(ConnectionError) as cm:
            await connect_task
        self.assertEqual(str(cm.exception), "ICE negotiation failed")

        # Close the connections.
        await conn_a.close()
        await conn_b.close()

    @unittest.skipIf(RUNNING_ON_MAC_CI, "Mac CI has issues with mDNS")
    @asynctest
    async def test_add_remote_candidate_mdns_with_turn_server(self) -> None:
        """
        An mDNS candidate is not paired with a relayed candidate.
        """
        hostname = mdns.create_mdns_hostname()
        publisher = await mdns.create_mdns_protocol()
        await publisher.publish(hostname, "1.2.3.4")

        async with run_turn_server(users={"foo": "bar"}) as turn_server:
            conn_a = ice.Connection(
                ice_controlling=True,
                turn_server=turn_server.udp_address,
                turn_username="foo",
                turn_password="bar",
            )
            await conn_a.gather_candidates()
            self.assertIn("relay", {c.type for c in conn_a.local_candidates})

            # Check an mDNS candidate is only paired with host candidates.
            await conn_a.add_remote_candidate(
                Candidate(
                    foundation="some-foundation",
                    component=1,
                    transport="udp",
                    priority=1234,
                    host=hostname,
                    port=1234,
                    type="host",
                )
            )
            self.assertEqual(
                {p.local_candidate.type for p in conn_a._check_list}, {"host"}
            )

            # Check an IP candidate is also paired with the relayed candidate.
            await conn_a.add_remote_candidate(
                Candidate(
                    foundation="other-foundation",
                    component=1,
                    transport="udp",
                    priority=1234,
                    host="1.2.3.5",
                    port=1234,
                    type="host",
                )
            )
            self.assertEqual(
                {
                    p.local_candidate.type
                    for p in conn_a._check_list
                    if p.remote_candidate.host == "1.2.3.5"
                },
                {"host", "relay"},
            )

            # Close the connection.
            await conn_a.close()

        # Close the mDNS publisher.
        await publisher.close()

    @unittest.skipIf(RUNNING_ON_MAC_CI, "Mac CI has issues with mDNS")
    @asynctest
    async def test_connect_mdns_with_turn_server(self) -> None:
        """
        Connect using the peer's mDNS candidates, signalled before gathering,
        while using a TURN server.
        """
        async with run_turn_server(users={"foo": "bar"}) as turn_server:
            conn_a = ice.Connection(
                ice_controlling=True,
                turn_server=turn_server.udp_address,
                turn_username="foo",
                turn_password="bar",
            )
            conn_b = ice.Connection(ice_controlling=False)
            publisher = await mdns.create_mdns_protocol()

            # Connection B's candidates are signalled as mDNS candidates, before
            # connection A gathers its candidates.
            await conn_b.gather_candidates()
            await add_mdns_candidates(publisher, conn_a, conn_b.local_candidates)

            # Exchange credentials and connection A's candidates.
            await conn_a.gather_candidates()
            self.assertIn("relay", {c.type for c in conn_a.local_candidates})
            conn_a.remote_username = conn_b.local_username
            conn_a.remote_password = conn_b.local_password
            conn_b.remote_username = conn_a.local_username
            conn_b.remote_password = conn_a.local_password
            for candidate in conn_a.local_candidates:
                await conn_b.add_remote_candidate(candidate)
            await conn_b.add_remote_candidate(None)

            # Check connect() formed no pair with the relayed candidate, before
            # unchecked pairs are removed on nomination.
            connect_task = asyncio.create_task(conn_a.connect())
            await asyncio.sleep(0)
            self.assertEqual(
                {p.local_candidate.type for p in conn_a._check_list}, {"host"}
            )

            await asyncio.gather(connect_task, conn_b.connect())

            # Send data a -> b.
            await conn_a.send(b"howdee")
            data = await conn_b.recv()
            self.assertEqual(data, b"howdee")

            # Close the connections and the mDNS publisher.
            await conn_a.close()
            await conn_b.close()
            await publisher.close()

    @asynctest
    async def test_add_remote_candidate_same_address(self) -> None:
        """
        Add candidates with the same transport address as an existing one.
        """
        conn_a = ice.Connection(ice_controlling=True)
        await conn_a.gather_candidates()

        remote_candidate = Candidate(
            foundation="some-foundation",
            component=1,
            transport="udp",
            priority=2130706431,
            host="1.2.3.4",
            port=1234,
            type="host",
        )
        await conn_a.add_remote_candidate(remote_candidate)
        await conn_a.add_remote_candidate(
            Candidate(
                foundation="ipv6-foundation",
                component=1,
                transport="udp",
                priority=2130706431,
                host="2001:db8::1",
                port=1234,
                type="host",
            )
        )
        check_list = list(conn_a._check_list)
        self.assertGreater(len(check_list), 0)

        # The same candidate, an equal candidate, a server-reflexive candidate
        # with the same address and an address written differently are ignored.
        await conn_a.add_remote_candidate(remote_candidate)
        await conn_a.add_remote_candidate(copy.copy(remote_candidate))
        await conn_a.add_remote_candidate(
            Candidate(
                foundation="other-foundation",
                component=1,
                transport="UDP",
                priority=1694498815,
                host="1.2.3.4",
                port=1234,
                type="srflx",
                related_address="192.168.1.2",
                related_port=1234,
            )
        )
        await conn_a.add_remote_candidate(
            Candidate(
                foundation="other-ipv6-foundation",
                component=1,
                transport="udp",
                priority=2130706431,
                host="2001:DB8:0::1",
                port=1234,
                type="host",
            )
        )

        # Check the first candidates and their pairs were kept.
        self.assertEqual(
            [(c.foundation, c.host) for c in conn_a.remote_candidates],
            [("some-foundation", "1.2.3.4"), ("ipv6-foundation", "2001:db8::1")],
        )
        self.assertEqual(conn_a._check_list, check_list)

        # Close the connection.
        await conn_a.close()

    @asynctest
    async def test_add_remote_candidate_unknown_type(self) -> None:
        conn_a = ice.Connection(ice_controlling=True)

        await conn_a.add_remote_candidate(
            Candidate(
                foundation="some-foundation",
                component=1,
                transport="udp",
                priority=1234,
                host="1.2.3.4",
                port=1234,
                type="bogus",
            )
        )
        self.assertEqual(len(conn_a.remote_candidates), 0)
        self.assertEqual(conn_a._remote_candidates_end, False)

    @mock.patch("asyncio.base_events.BaseEventLoop.create_datagram_endpoint")
    @asynctest
    async def test_gather_candidates_oserror(self, mock_create: mock.MagicMock) -> None:
        exc = OSError()
        exc.errno = 99
        exc.strerror = "Cannot assign requested address"
        mock_create.side_effect = exc

        conn = ice.Connection(ice_controlling=True)
        await conn.gather_candidates()
        self.assertEqual(conn.local_candidates, [])

    @asynctest
    async def test_gather_candidates_relay_only_no_servers(self) -> None:
        conn = ice.Connection(
            ice_controlling=True, transport_policy=TransportPolicy.RELAY
        )

        # Check no candidates were gathered, and the reason was logged.
        with self.assertLogs("aioice.ice", level="INFO") as logs:
            await conn.gather_candidates()
        self.assertEqual(conn.local_candidates, [])
        self.assertTrue(any("no TURN server" in line for line in logs.output))

        # Close the connection.
        await conn.close()

    @asynctest
    async def test_gather_candidates_relay_only_with_stun_server(self) -> None:
        async with run_turn_server() as stun_server:
            conn = ice.Connection(
                ice_controlling=True,
                stun_server=stun_server.udp_address,
                transport_policy=TransportPolicy.RELAY,
            )

            # Check no candidates were gathered, and no host socket was created
            # to query the STUN server.
            with self.assertLogs("aioice.ice", level="INFO") as logs:
                await conn.gather_candidates()
            self.assertEqual(conn.local_candidates, [])
            self.assertEqual(conn._protocols, [])
            self.assertTrue(any("no TURN server" in line for line in logs.output))

            # Close the connection.
            await conn.close()

    @asynctest
    async def test_gather_candidates_relay_only_with_turn_server(self) -> None:
        async with run_turn_server(users={"foo": "bar"}) as turn_server:
            conn_a = ice.Connection(
                ice_controlling=True,
                turn_server=turn_server.udp_address,
                turn_username="foo",
                turn_password="bar",
                transport_policy=TransportPolicy.RELAY,
            )
            conn_b = ice.Connection(ice_controlling=False)

            # Exchange candidates and credentials.
            await invite_accept(conn_a, conn_b)

            # Check connection A only has a relayed candidate, and no host socket
            # which could send checks.
            self.assertCandidateTypes(conn_a, {"relay"})
            self.assertEqual(
                [p.local_candidate.type for p in conn_a._protocols], ["relay"]
            )

            # Check the relayed candidate hides the address used to reach the
            # TURN server.
            candidate = conn_a.local_candidates[0]
            self.assertEqual(candidate.related_address, "0.0.0.0")
            self.assertEqual(candidate.related_port, 9)

            # Close the connections.
            await conn_a.close()
            await conn_b.close()

    @asynctest
    async def test_gather_candidates_relay_only_with_turn_server_ipv6(self) -> None:
        """
        An IPv6 relayed candidate hides its related address with "::".
        """

        async def create_turn_endpoint(
            protocol_factory: Callable[[], ice.StunProtocol], **kwargs: object
        ) -> tuple[mock.Mock, ice.StunProtocol]:
            protocol = protocol_factory()
            extra_info = {
                "related_address": ("2001:db8::1", 1234),
                "sockname": ("2001:db8::2", 5678),
            }
            transport = mock.Mock()
            transport.get_extra_info.side_effect = extra_info.get
            transport.close.side_effect = lambda: protocol.connection_lost(None)
            protocol.connection_made(transport)
            return transport, protocol

        conn = ice.Connection(
            ice_controlling=True,
            turn_server=("2001:db8::3", 3478),
            turn_username="foo",
            turn_password="bar",
            transport_policy=TransportPolicy.RELAY,
        )

        # Check the relayed candidate hides the address used to reach the TURN
        # server.
        with mock.patch("aioice.turn.create_turn_endpoint", create_turn_endpoint):
            await conn.gather_candidates()
        self.assertEqual(len(conn.local_candidates), 1)
        candidate = conn.local_candidates[0]
        self.assertEqual(candidate.host, "2001:db8::2")
        self.assertEqual(candidate.related_address, "::")
        self.assertEqual(candidate.related_port, 9)

        # Close the connection.
        await conn.close()

    @asynctest
    async def test_repr(self) -> None:
        conn = ice.Connection(ice_controlling=True)
        conn._id = 1
        self.assertEqual(repr(conn), "Connection(1)")


class StunProtocolTest(unittest.TestCase):
    @asynctest
    async def test_error_received(self) -> None:
        protocol = ice.StunProtocol(ice.Connection(ice_controlling=True))
        protocol.error_received(OSError("foo"))

    @asynctest
    async def test_repr(self) -> None:
        protocol = ice.StunProtocol(ice.Connection(ice_controlling=True))
        protocol.id = 1
        self.assertEqual(repr(protocol), "protocol(1)")
