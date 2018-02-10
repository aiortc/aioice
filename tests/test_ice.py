import asyncio
import os
import pprint
import socket
import unittest
from unittest import mock

from aioice import exceptions, ice, stun

from .turnserver import TurnServerProtocol


async def delay(coro):
    await asyncio.sleep(1)
    await coro()


async def invite_accept(conn_a, conn_b):
    # invite
    candidates_a = await conn_a.get_local_candidates()
    print('CANDIDATES A')
    pprint.pprint(candidates_a)
    conn_b.remote_username = conn_a.local_username
    conn_b.remote_password = conn_a.local_password
    conn_b.set_remote_candidates(candidates_a)

    # accept
    candidates_b = await conn_b.get_local_candidates()
    print('CANDIDATES B')
    pprint.pprint(candidates_b)
    conn_a.remote_username = conn_b.local_username
    conn_a.remote_password = conn_b.local_password
    conn_a.set_remote_candidates(candidates_b)

    return candidates_a, candidates_b


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


class ProtocolMock:
    local_candidate = ice.Candidate(
        foundation='some-foundation',
        component=1,
        transport='udp',
        priority=1234,
        host='1.2.3.4',
        port=1234,
        type='host')

    sent_message = None

    async def request(self, message, addr, integrity_key=None):
        return (self.response_message, self.response_addr)

    def send_stun(self, message, addr):
        self.sent_message = message


class IceComponentTest(unittest.TestCase):
    def test_request_with_invalid_method(self):
        connection = ice.Connection(ice_controlling=True)
        protocol = ProtocolMock()

        request = stun.Message(
            message_method=stun.Method.ALLOCATE,
            message_class=stun.Class.REQUEST)

        connection.request_received(request, ('2.3.4.5', 2345), protocol, bytes(request))
        self.assertIsNotNone(protocol.sent_message)
        self.assertEqual(protocol.sent_message.message_method, stun.Method.ALLOCATE)
        self.assertEqual(protocol.sent_message.message_class, stun.Class.ERROR)
        self.assertEqual(protocol.sent_message.attributes['ERROR-CODE'], (400, 'Bad Request'))

    def test_response_with_invalid_address(self):
        connection = ice.Connection(ice_controlling=True)
        connection.remote_password = 'remote-password'
        connection.remote_username = 'remote-username'

        protocol = ProtocolMock()
        protocol.response_addr = ('3.4.5.6', 3456)
        protocol.response_message = 'zob'

        pair = ice.CandidatePair(protocol, ice.Candidate(
            foundation='some-foundation',
            component=1,
            transport='udp',
            priority=2345,
            host='2.3.4.5',
            port=2345,
            type='host'))

        run(connection.check_start(pair))
        self.assertEqual(pair.state, ice.CandidatePair.State.FAILED)


class IceConnectionTest(unittest.TestCase):
    def setUp(self):
        stun.RETRY_MAX = 2

    def tearDown(self):
        stun.RETRY_MAX = 7

    def test_can_pair_ipv4(self):
        candidate_a = ice.parse_candidate(
            '6815297761 1 udp 659136 1.2.3.4 31102 typ host generation 0')
        candidate_b = ice.parse_candidate(
            '6815297761 1 udp 659136 1.2.3.4 12345 typ host generation 0')
        self.assertTrue(candidate_a.can_pair_with(candidate_b))

    def test_can_pair_ipv6(self):
        candidate_a = ice.parse_candidate(
            '6815297761 1 udp 659136 2a02:0db8:85a3:0000:0000:8a2e:0370:7334 31102'
            ' typ host generation 0')
        candidate_b = ice.parse_candidate(
            '6815297761 1 udp 659136 2a02:0db8:85a3:0000:0000:8a2e:0370:7334 12345'
            ' typ host generation 0')
        self.assertTrue(candidate_a.can_pair_with(candidate_b))

    def test_cannot_pair_ipv4_ipv6(self):
        candidate_a = ice.parse_candidate(
            '6815297761 1 udp 659136 1.2.3.4 31102 typ host generation 0')
        candidate_b = ice.parse_candidate(
            '6815297761 1 udp 659136 2a02:0db8:85a3:0000:0000:8a2e:0370:7334 12345'
            ' typ host generation 0')
        self.assertFalse(candidate_a.can_pair_with(candidate_b))

    def test_cannot_pair_different_components(self):
        candidate_a = ice.parse_candidate(
            '6815297761 1 udp 659136 1.2.3.4 31102 typ host generation 0')
        candidate_b = ice.parse_candidate(
            '6815297761 2 udp 659136 1.2.3.4 12345 typ host generation 0')
        self.assertFalse(candidate_a.can_pair_with(candidate_b))

    @mock.patch('netifaces.interfaces')
    @mock.patch('netifaces.ifaddresses')
    def test_get_host_addresses(self, mock_ifaddresses, mock_interfaces):
        mock_interfaces.return_value = ['eth0']
        mock_ifaddresses.return_value = {
            socket.AF_INET: [
                {'addr': '127.0.0.1'},
                {'addr': '1.2.3.4'},
            ],
            socket.AF_INET6: [
                {'addr': '::1'},
                {'addr': '2a02:0db8:85a3:0000:0000:8a2e:0370:7334'},
                {'addr': 'fe80::1234:5678:9abc:def0%eth0'},
            ]
        }

        # IPv4 only
        addresses = ice.get_host_addresses(use_ipv4=True, use_ipv6=False)
        self.assertEqual(addresses, [
            '1.2.3.4',
        ])

        # IPv6 only
        addresses = ice.get_host_addresses(use_ipv4=False, use_ipv6=True)
        self.assertEqual(addresses, [
            '2a02:0db8:85a3:0000:0000:8a2e:0370:7334',
        ])

        # both
        addresses = ice.get_host_addresses(use_ipv4=True, use_ipv6=True)
        self.assertEqual(addresses, [
            '1.2.3.4',
            '2a02:0db8:85a3:0000:0000:8a2e:0370:7334',
        ])

    def test_parse_candidate(self):
        candidate = ice.parse_candidate(
            '6815297761 1 udp 659136 1.2.3.4 31102 typ host generation 0')
        self.assertEqual(candidate.foundation, '6815297761')
        self.assertEqual(candidate.component, 1)
        self.assertEqual(candidate.transport, 'udp')
        self.assertEqual(candidate.priority, 659136)
        self.assertEqual(candidate.host, '1.2.3.4')
        self.assertEqual(candidate.port, 31102)
        self.assertEqual(candidate.type, 'host')
        self.assertEqual(candidate.generation, 0)

    def test_connect(self):
        conn_a = ice.Connection(ice_controlling=True)
        conn_b = ice.Connection(ice_controlling=False)

        # invite / accept
        candidates_a, _ = run(invite_accept(conn_a, conn_b))
        self.assertTrue(len(candidates_a) > 0)
        for candidate in candidates_a:
            self.assertEqual(candidate.type, 'host')

        # connect
        run(asyncio.gather(conn_a.connect(), conn_b.connect()))

        # send data a -> b
        run(conn_a.send(b'howdee'))
        data = run(conn_b.recv())
        self.assertEqual(data, b'howdee')

        # send data b -> a
        run(conn_b.send(b'gotcha'))
        data = run(conn_a.recv())
        self.assertEqual(data, b'gotcha')

        # close
        run(conn_a.close())
        run(conn_b.close())

    def test_connect_two_components(self):
        conn_a = ice.Connection(ice_controlling=True)
        conn_a.components.add(2)
        conn_b = ice.Connection(ice_controlling=False)
        conn_b.components.add(2)

        # invite / accept
        candidates_a, _ = run(invite_accept(conn_a, conn_b))
        self.assertTrue(len(candidates_a) > 0)
        for candidate in candidates_a:
            self.assertEqual(candidate.type, 'host')

        # connect
        run(asyncio.gather(conn_a.connect(), conn_b.connect()))

        # send data a -> b
        run(conn_a.send(b'howdee'))
        data = run(conn_b.recv())
        self.assertEqual(data, b'howdee')

        # send data b -> a
        run(conn_b.send(b'gotcha'))
        data = run(conn_a.recv())
        self.assertEqual(data, b'gotcha')

        # close
        run(conn_a.close())

    @unittest.skipIf(os.environ.get('TRAVIS') == 'true', 'travis lacks ipv6')
    def test_connect_ipv6(self):
        conn_a = ice.Connection(ice_controlling=True, use_ipv4=False, use_ipv6=True)
        conn_b = ice.Connection(ice_controlling=False, use_ipv4=False, use_ipv6=True)

        # invite / accept
        candidates_a, _ = run(invite_accept(conn_a, conn_b))
        self.assertTrue(len(candidates_a) > 0)
        for candidate in candidates_a:
            self.assertEqual(candidate.type, 'host')

        # connect
        run(asyncio.gather(conn_a.connect(), conn_b.connect()))

        # send data a -> b
        run(conn_a.send(b'howdee'))
        data = run(conn_b.recv())
        self.assertEqual(data, b'howdee')

        # send data b -> a
        run(conn_b.send(b'gotcha'))
        data = run(conn_a.recv())
        self.assertEqual(data, b'gotcha')

        # close
        run(conn_a.close())
        run(conn_b.close())

    def test_connect_reverse_order(self):
        conn_a = ice.Connection(ice_controlling=True)
        conn_b = ice.Connection(ice_controlling=False)

        # invite / accept
        run(invite_accept(conn_a, conn_b))

        # introduce a delay so that B's checks complete before A's
        run(asyncio.gather(delay(conn_a.connect), conn_b.connect()))

        # send data a -> b
        run(conn_a.send(b'howdee'))
        data = run(conn_b.recv())
        self.assertEqual(data, b'howdee')

        # send data b -> a
        run(conn_b.send(b'gotcha'))
        data = run(conn_a.recv())
        self.assertEqual(data, b'gotcha')

        # close
        run(conn_a.close())
        run(conn_b.close())

    def test_connect_invalid_password(self):
        conn_a = ice.Connection(ice_controlling=True)
        conn_b = ice.Connection(ice_controlling=False)

        # invite / accept
        candidates_a, _ = run(invite_accept(conn_a, conn_b))
        self.assertTrue(len(candidates_a) > 0)
        for candidate in candidates_a:
            self.assertEqual(candidate.type, 'host')

        # invite
        candidates_a = run(conn_a.get_local_candidates())
        conn_b.remote_username = conn_a.local_username
        conn_b.remote_password = conn_a.local_password
        conn_b.set_remote_candidates(candidates_a)

        # accept
        candidates_b = run(conn_b.get_local_candidates())
        conn_a.remote_username = conn_b.local_username
        conn_a.remote_password = 'wrong-password'
        conn_a.set_remote_candidates(candidates_b)

        # connect
        done, pending = run(asyncio.wait([conn_a.connect(), conn_b.connect()],
                                         return_when=asyncio.FIRST_EXCEPTION))
        for task in pending:
            task.cancel()
        self.assertEqual(len(done), 1)
        self.assertTrue(isinstance(done.pop().exception(), exceptions.ConnectionError))

        # close
        run(conn_a.close())
        run(conn_b.close())

    def test_connect_invalid_username(self):
        conn_a = ice.Connection(ice_controlling=True)
        conn_b = ice.Connection(ice_controlling=False)

        # invite / accept
        candidates_a, _ = run(invite_accept(conn_a, conn_b))
        self.assertTrue(len(candidates_a) > 0)
        for candidate in candidates_a:
            self.assertEqual(candidate.type, 'host')

        # invite
        candidates_a = run(conn_a.get_local_candidates())
        conn_b.remote_username = conn_a.local_username
        conn_b.remote_password = conn_a.local_password
        conn_b.set_remote_candidates(candidates_a)

        # accept
        candidates_b = run(conn_b.get_local_candidates())
        conn_a.remote_username = 'wrong-username'
        conn_a.remote_password = conn_b.local_password
        conn_a.set_remote_candidates(candidates_b)

        # connect
        done, pending = run(asyncio.wait([conn_a.connect(), conn_b.connect()],
                            return_when=asyncio.FIRST_EXCEPTION))
        for task in pending:
            task.cancel()
        self.assertEqual(len(done), 2)
        self.assertTrue(isinstance(done.pop().exception(), exceptions.ConnectionError))
        self.assertTrue(isinstance(done.pop().exception(), exceptions.ConnectionError))

        # close
        run(conn_a.close())
        run(conn_b.close())

    def test_connect_no_local_candidates(self):
        """
        If local candidates have not been gathered, connect fails.
        """
        conn = ice.Connection(ice_controlling=True)
        conn.remote_username = 'foo'
        conn.remote_password = 'bar'
        conn.set_remote_candidates([ice.parse_candidate(
            '6815297761 1 udp 659136 1.2.3.4 31102 typ host generation 0')])
        with self.assertRaises(exceptions.ConnectionError):
            run(conn.connect())
        run(conn.close())

    def test_connect_no_remote_candidates(self):
        """
        If remote candidates have not been provided, connect fails.
        """
        conn = ice.Connection(ice_controlling=True)
        run(conn.get_local_candidates())
        conn.remote_username = 'foo'
        conn.remote_password = 'bar'
        with self.assertRaises(exceptions.ConnectionError):
            run(conn.connect())
        run(conn.close())

    def test_connect_no_remote_credentials(self):
        """
        If remote credentials have not been provided, connect fails.
        """
        conn = ice.Connection(ice_controlling=True)
        run(conn.get_local_candidates())
        conn.set_remote_candidates([ice.parse_candidate(
            '6815297761 1 udp 659136 1.2.3.4 31102 typ host generation 0')])
        with self.assertRaises(exceptions.ImproperlyConfigured):
            run(conn.connect())
        run(conn.close())

    def test_connect_role_conflict_both_controlling(self):
        conn_a = ice.Connection(ice_controlling=True)
        conn_b = ice.Connection(ice_controlling=True)

        # set tie breaker for a deterministic outcome
        conn_a.tie_breaker = 1
        conn_b.tie_breaker = 2

        # invite / accept
        run(invite_accept(conn_a, conn_b))

        # connect
        run(asyncio.gather(conn_a.connect(), conn_b.connect()))
        self.assertFalse(conn_a.ice_controlling)
        self.assertTrue(conn_b.ice_controlling)

        # close
        run(conn_a.close())
        run(conn_b.close())

    def test_connect_role_conflict_both_controlled(self):
        conn_a = ice.Connection(ice_controlling=False)
        conn_b = ice.Connection(ice_controlling=False)

        # set tie breaker for a deterministic outcome
        conn_a.tie_breaker = 1
        conn_b.tie_breaker = 2

        # invite / accept
        run(invite_accept(conn_a, conn_b))

        # connect
        run(asyncio.gather(conn_a.connect(), conn_b.connect()))
        self.assertFalse(conn_a.ice_controlling)
        self.assertTrue(conn_b.ice_controlling)

        # close
        run(conn_a.close())
        run(conn_b.close())

    def test_connect_timeout(self):
        conn = ice.Connection(ice_controlling=True)
        run(conn.get_local_candidates())
        conn.remote_username = 'foo'
        conn.remote_password = 'bar'
        conn.set_remote_candidates([ice.parse_candidate(
            '6815297761 1 udp 659136 1.2.3.4 31102 typ host generation 0')])
        with self.assertRaises(exceptions.ConnectionError):
            run(conn.connect())
        run(conn.close())

    def test_connect_with_stun_server(self):
        stun_server = ('stun.l.google.com', 19302)

        conn_a = ice.Connection(ice_controlling=True, stun_server=stun_server)
        conn_b = ice.Connection(ice_controlling=False)

        # invite / accept
        candidates_a, _ = run(invite_accept(conn_a, conn_b))
        self.assertTrue(len(candidates_a) > 1)
        self.assertEqual(candidates_a[-1].type, 'srflx')

        # connect
        run(asyncio.gather(conn_a.connect(), conn_b.connect()))

        # send data a -> b
        run(conn_a.send(b'howdee'))
        data = run(conn_b.recv())
        self.assertEqual(data, b'howdee')

        # send data b -> a
        run(conn_b.send(b'gotcha'))
        data = run(conn_a.recv())
        self.assertEqual(data, b'gotcha')

        # close
        run(conn_a.close())
        run(conn_b.close())

    def test_connect_with_stun_server_timeout(self):
        stun_server = ('1.2.3.4', 19302)

        conn_a = ice.Connection(ice_controlling=True, stun_server=stun_server)
        conn_b = ice.Connection(ice_controlling=False)

        # invite / accept
        candidates_a, _ = run(invite_accept(conn_a, conn_b))
        self.assertTrue(len(candidates_a) > 0)
        for candidate in candidates_a:
            self.assertEqual(candidate.type, 'host')

        # connect
        run(asyncio.gather(conn_a.connect(), conn_b.connect()))

        # send data a -> b
        run(conn_a.send(b'howdee'))
        data = run(conn_b.recv())
        self.assertEqual(data, b'howdee')

        # send data b -> a
        run(conn_b.send(b'gotcha'))
        data = run(conn_a.recv())
        self.assertEqual(data, b'gotcha')

        # close
        run(conn_a.close())
        run(conn_b.close())

    @unittest.skipIf(os.environ.get('TRAVIS') == 'true', 'travis lacks ipv6')
    def test_connect_with_stun_server_ipv6(self):
        stun_server = ('stun.l.google.com', 19302)

        conn_a = ice.Connection(ice_controlling=True, stun_server=stun_server,
                                use_ipv4=False, use_ipv6=True)
        conn_b = ice.Connection(ice_controlling=False, use_ipv4=False, use_ipv6=True)

        # invite / accept
        candidates_a, _ = run(invite_accept(conn_a, conn_b))

        # we only want host candidates : no STUN for IPv6
        self.assertTrue(len(candidates_a) > 0)
        for candidate in candidates_a:
            self.assertEqual(candidate.type, 'host')

        # connect
        run(asyncio.gather(conn_a.connect(), conn_b.connect()))

        # send data a -> b
        run(conn_a.send(b'howdee'))
        data = run(conn_b.recv())
        self.assertEqual(data, b'howdee')

        # send data b -> a
        run(conn_b.send(b'gotcha'))
        data = run(conn_a.recv())
        self.assertEqual(data, b'gotcha')

        # close
        run(conn_a.close())
        run(conn_b.close())

    def test_connect_with_turn_server(self):
        # start turn server
        loop = asyncio.get_event_loop()
        transport, turn_server = run(loop.create_datagram_endpoint(
            lambda: TurnServerProtocol(realm='test', users={'foo': 'bar'}),
            local_addr=('127.0.0.1', 0),
            family=socket.AF_INET))
        turn_server_addr = transport.get_extra_info('sockname')

        # create connections
        conn_a = ice.Connection(ice_controlling=True,
                                turn_server=turn_server_addr,
                                turn_username='foo',
                                turn_password='bar')
        conn_b = ice.Connection(ice_controlling=False)

        # invite / accept
        candidates_a, _ = run(invite_accept(conn_a, conn_b))
        self.assertTrue(len(candidates_a) > 1)
        self.assertEqual(candidates_a[-1].type, 'relay')

        # connect
        run(asyncio.gather(conn_a.connect(), conn_b.connect()))

        # send data a -> b
        run(conn_a.send(b'howdee'))
        data = run(conn_b.recv())
        self.assertEqual(data, b'howdee')

        # send data b -> a
        run(conn_b.send(b'gotcha'))
        data = run(conn_a.recv())
        self.assertEqual(data, b'gotcha')

        # close
        run(conn_a.close())
        run(conn_b.close())
        turn_server.transport.close()
