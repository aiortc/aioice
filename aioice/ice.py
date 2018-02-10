import asyncio
import enum
import hashlib
import ipaddress
import logging
import socket

import netifaces

from . import exceptions, stun, turn
from .compat import secrets
from .utils import random_string

logger = logging.getLogger('ice')

ICE_COMPLETED = 1
ICE_FAILED = 2


def candidate_foundation(candidate_type, candidate_transport, base_address):
    """
    See RFC 5245 - 4.1.1.3. Computing Foundations
    """
    key = '%s|%s|%s' % (type, candidate_transport, base_address)
    return hashlib.md5(key.encode('ascii')).hexdigest()


def candidate_priority(candidate_component, candidate_type, local_pref=65535):
    """
    See RFC 5245 - 4.1.2.1. Recommended Formula
    """
    if candidate_type == 'host':
        type_pref = 126
    elif candidate_type == 'prflx':
        type_pref = 110
    elif candidate_type == 'srflx':
        type_pref = 100
    else:
        type_pref = 0

    return (1 << 24) * type_pref + \
           (1 << 8) * local_pref + \
           (256 - candidate_component)


def candidate_pair_priority(local, remote, ice_controlling):
    """
    See RFC 5245 - 5.7.2. Computing Pair Priority and Ordering Pairs
    """
    G = ice_controlling and local.priority or remote.priority
    D = ice_controlling and remote.priority or local.priority
    return (1 << 32) * min(G, D) + 2 * max(G, D) + (G > D and 1 or 0)


def get_host_addresses(use_ipv4, use_ipv6):
    """
    Get local IP addresses.
    """
    addresses = []
    for interface in netifaces.interfaces():
        ifaddresses = netifaces.ifaddresses(interface)
        for address in ifaddresses.get(socket.AF_INET, []):
            if use_ipv4 and address['addr'] != '127.0.0.1':
                addresses.append(address['addr'])
        for address in ifaddresses.get(socket.AF_INET6, []):
            if use_ipv6 and address['addr'] != '::1' and '%' not in address['addr']:
                addresses.append(address['addr'])
    return addresses


async def server_reflexive_candidate(protocol, stun_server):
    """
    Query STUN server to obtain a server-reflexive candidate.
    """
    request = stun.Message(message_method=stun.Method.BINDING,
                           message_class=stun.Class.REQUEST)
    response, _ = await protocol.request(request, stun_server)

    local_candidate = protocol.local_candidate
    return Candidate(
        foundation=candidate_foundation('srflx', 'udp', local_candidate.host),
        component=local_candidate.component,
        transport=local_candidate.transport,
        priority=candidate_priority(local_candidate.component, 'srflx'),
        host=response.attributes['XOR-MAPPED-ADDRESS'][0],
        port=response.attributes['XOR-MAPPED-ADDRESS'][1],
        type='srflx')


def sort_candidate_pairs(pairs, ice_controlling):
    """
    Sort a list of candidate pairs.
    """
    def pair_priority(pair):
        return -candidate_pair_priority(pair.local_candidate,
                                        pair.remote_candidate,
                                        ice_controlling)

    pairs.sort(key=pair_priority)


class Candidate:
    """
    An ICE candidate.
    """
    def __init__(self, foundation, component, transport, priority, host, port,
                 type='host', generation=0):
        self.foundation = foundation
        self.component = component
        self.transport = transport
        self.priority = priority
        self.host = host
        self.port = port
        self.type = type
        self.generation = generation

    def __repr__(self):
        return 'Candidate(%s)' % self

    def __str__(self):
        return '%s %d %s %d %s %d typ %s generation %d' % (
            self.foundation,
            self.component,
            self.transport,
            self.priority,
            self.host,
            self.port,
            self.type,
            self.generation)

    def can_pair_with(self, other):
        """
        A local candidate is paired with a remote candidate if and only if
        the two candidates have the same component ID and have the same IP
        address version.
        """
        a = ipaddress.ip_address(self.host)
        b = ipaddress.ip_address(other.host)
        return self.component == other.component and a.version == b.version


class CandidatePair:
    def __init__(self, protocol, remote_candidate):
        self.handle = None
        self.nominated = False
        self.protocol = protocol
        self.remote_candidate = remote_candidate
        self.remote_nominated = False
        self.state = CandidatePair.State.FROZEN

    def __repr__(self):
        return 'CandidatePair(%s -> %s)' % (self.local_addr, self.remote_addr)

    @property
    def component(self):
        return self.local_candidate.component

    @property
    def local_addr(self):
        return (self.local_candidate.host, self.local_candidate.port)

    @property
    def local_candidate(self):
        return self.protocol.local_candidate

    @property
    def remote_addr(self):
        return (self.remote_candidate.host, self.remote_candidate.port)

    class State(enum.Enum):
        FROZEN = 0
        WAITING = 1
        IN_PROGRESS = 2
        SUCCEEDED = 3
        FAILED = 4


def parse_candidate(value):
    bits = value.split()
    return Candidate(
        foundation=bits[0],
        component=int(bits[1]),
        transport=bits[2],
        priority=int(bits[3]),
        host=bits[4],
        port=int(bits[5]),
        type=bits[7],
        generation=int(bits[9]))


def next_protocol_id():
    protocol_id = next_protocol_id.counter
    next_protocol_id.counter += 1
    return protocol_id


next_protocol_id.counter = 0


class StunProtocol(asyncio.DatagramProtocol):
    def __init__(self, receiver):
        self.__closed = asyncio.Future()
        self.id = next_protocol_id()
        self.queue = asyncio.Queue()
        self.receiver = receiver
        self.transport = None
        self.transactions = {}

    def connection_lost(self, exc):
        self.__log_debug('connection_lost(%s)', exc)
        self.__closed.set_result(True)

    def connection_made(self, transport):
        self.__log_debug('connection_made(%s)', transport)
        self.transport = transport

    def datagram_received(self, data, addr):
        # force IPv6 four-tuple to a two-tuple
        addr = (addr[0], addr[1])

        try:
            message = stun.parse_message(data)
            self.__log_debug('< %s %s', addr, repr(message))
        except ValueError:
            self.__log_debug('< %s DATA %d', addr, len(data))
            coro = self.queue.put(data)
            asyncio.ensure_future(coro)
            return

        if ((message.message_class == stun.Class.RESPONSE or
             message.message_class == stun.Class.ERROR) and
           message.transaction_id in self.transactions):
            transaction = self.transactions[message.transaction_id]
            transaction.response_received(message, addr)
        elif message.message_class == stun.Class.REQUEST:
            self.receiver.request_received(message, addr, self, data)

    def error_received(self, exc):
        self.__log_debug('error_received(%s)', exc)

    # custom

    async def close(self):
        self.transport.close()
        await self.__closed

    async def recv_data(self):
        return await self.queue.get(), self.local_candidate.component

    async def send_data(self, data, addr):
        self.__log_debug('%s DATA %d', addr, len(data))
        self.transport.sendto(data, addr)

    async def request(self, request, addr, integrity_key=None):
        """
        Execute a STUN transaction and return the response.
        """
        assert request.transaction_id not in self.transactions

        if integrity_key is not None:
            request.add_message_integrity(integrity_key)
            request.add_fingerprint()

        transaction = stun.Transaction(request, addr, self)
        transaction.integrity_key = integrity_key
        self.transactions[request.transaction_id] = transaction
        try:
            return await transaction.run()
        finally:
            del self.transactions[request.transaction_id]

    def send_stun(self, message, addr):
        """
        Send a STUN message.
        """
        self.__log_debug('> %s %s', addr, repr(message))
        self.transport.sendto(bytes(message), addr)

    def __log_debug(self, msg, *args):
        logger.debug(repr(self.receiver) + ' ' + repr(self) + ' ' + msg, *args)

    def __repr__(self):
        return 'protocol(%s)' % self.id


def next_connection_id():
    connection_id = next_connection_id.counter
    next_connection_id.counter += 1
    return connection_id


next_connection_id.counter = 0


class Connection:
    """
    An ICE connection.
    """
    def __init__(self, ice_controlling, stun_server=None,
                 turn_server=None, turn_username=None, turn_password=None,
                 use_ipv4=True, use_ipv6=False):
        self.components = set([1])
        self.ice_controlling = ice_controlling
        self.id = next_connection_id()
        self.local_username = random_string(4)
        self.local_password = random_string(22)
        self.remote_candidates = []
        self.remote_username = None
        self.remote_password = None
        self.stun_server = stun_server
        self.tie_breaker = secrets.randbits(64)
        self.turn_server = turn_server
        self.turn_username = turn_username
        self.turn_password = turn_password

        # private
        self.__nominated = {}
        self.addresses = get_host_addresses(use_ipv4=use_ipv4, use_ipv6=use_ipv6)
        self.check_list = []
        self.check_list_state = asyncio.Queue()
        self.early_checks = []
        self.protocols = []

    async def get_local_candidates(self):
        """
        Gather local candidates.
        """
        candidates = []
        for component in self.components:
            candidates += await self.get_component_candidates(component)
        return candidates

    def set_remote_candidates(self, candidates):
        """
        Set remote candidates.
        """
        self.remote_candidates = candidates

    async def connect(self):
        """
        Perform ICE handshake.

        This coroutine returns if a candidate pair was successfuly nominated
        and raises an exception otherwise.
        """
        if (self.remote_username is None or
           self.remote_password is None):
            raise exceptions.ImproperlyConfigured('Remote username or password is missing')

        # 5.7.1. Forming Candidate Pairs
        for remote_candidate in self.remote_candidates:
            for protocol in self.protocols:
                if protocol.local_candidate.can_pair_with(remote_candidate):
                    pair = CandidatePair(protocol, remote_candidate)
                    self.check_list.append(pair)
        self.sort_check_list()
        if not self.check_list:
            raise exceptions.ConnectionError('No candidate pairs formed')

        # unfreeze first pair for component 1
        first_pair = None
        for pair in self.check_list:
            if pair.component == 1:
                first_pair = pair
                break
        assert first_pair is not None
        if first_pair.state == CandidatePair.State.FROZEN:
            self.check_state(first_pair, CandidatePair.State.WAITING)

        # unfreeze pairs with same component but different foundations
        seen_foundations = set(first_pair.local_candidate.foundation)
        for pair in self.check_list:
            if (pair.component == first_pair.component and
               pair.local_candidate.foundation not in seen_foundations and
               pair.state == CandidatePair.State.FROZEN):
                self.check_state(pair, CandidatePair.State.WAITING)
                seen_foundations.add(pair.local_candidate.foundation)

        # handle early checks
        for check in self.early_checks:
            self.check_incoming(*check)
        self.early_checks = []

        # perform checks
        while True:
            if not self.check_periodic():
                break
            await asyncio.sleep(0.02)

        # wait for completion
        res = await self.check_list_state.get()

        # cancel remaining checks
        for check in self.check_list:
            if check.handle:
                check.handle.cancel()

        if res != ICE_COMPLETED:
            raise exceptions.ConnectionError

    async def close(self):
        """
        Close the connection.
        """
        for protocol in self.protocols:
            await protocol.close()
        self.protocols = []

    async def recv(self):
        """
        Receive the next datagram.

        The return value is a `bytes` object representing the data received.
        """
        data, component = await self.recvfrom()
        return data

    async def recvfrom(self):
        """
        Receive the next datagram.

        The return value is a `(bytes, component)` tuple where `bytes` is a
        bytes object representing the data received and `component` is the
        component on which the data was received.
        """
        fs = [protocol.recv_data() for protocol in self.protocols]
        done, pending = await asyncio.wait(fs, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
        assert len(done) == 1
        return done.pop().result()

    async def send(self, data):
        """
        Send a datagram on the first component.
        """
        await self.sendto(data, 1)

    async def sendto(self, data, component):
        """
        Send a datagram on the specified component.
        """
        active_pair = self.__nominated.get(component)
        if active_pair:
            await active_pair.protocol.send_data(data, active_pair.remote_addr)

    # private

    def check_complete(self, pair):
        pair.handle = None

        if pair.state == CandidatePair.State.SUCCEEDED:
            if pair.nominated:
                self.__nominated[pair.component] = pair

                # 8.1.2.  Updating States
                #
                # The agent MUST remove all Waiting and Frozen pairs in the check
                # list and triggered check queue for the same component as the
                # nominated pairs for that media stream.
                for p in self.check_list:
                    if (p.component == pair.component and
                       p.state in [CandidatePair.State.WAITING, CandidatePair.State.FROZEN]):
                        self.check_state(p, CandidatePair.State.FAILED)

            # Once there is at least one nominated pair in the valid list for
            # every component of at least one media stream and the state of the
            # check list is Running:
            if len(self.__nominated) == len(self.components):
                self.__log_info('ICE completed')
                asyncio.ensure_future(self.check_list_state.put(ICE_COMPLETED))
                return

            # 7.1.3.2.3.  Updating Pair States
            for p in self.check_list:
                if (p.local_candidate.foundation == pair.local_candidate.foundation and
                   p.state == CandidatePair.State.FROZEN):
                    self.check_state(p, CandidatePair.State.WAITING)

        for p in self.check_list:
            if p.state not in [CandidatePair.State.SUCCEEDED, CandidatePair.State.FAILED]:
                return

        if not self.ice_controlling:
            for p in self.check_list:
                if p.state == CandidatePair.State.SUCCEEDED:
                    return

        self.__log_info('ICE failed')
        asyncio.ensure_future(self.check_list_state.put(ICE_FAILED))

    def check_incoming(self, message, addr, protocol):
        """
        Handle a succesful incoming check.
        """
        component = protocol.local_candidate.component

        # find remote candidate
        remote_candidate = None
        for c in self.remote_candidates:
            if c.host == addr[0] and c.port == addr[1]:
                remote_candidate = c
                assert remote_candidate.component == component
                break
        if remote_candidate is None:
            # 7.2.1.3. Learning Peer Reflexive Candidates
            remote_candidate = Candidate(
                foundation=random_string(10),
                component=component,
                transport='udp',
                priority=message.attributes['PRIORITY'],
                host=addr[0],
                port=addr[1],
                type='prflx')
            self.remote_candidates.append(remote_candidate)
            self.__log_info('Discovered peer reflexive candidate %s' % repr(remote_candidate))

        # find pair
        pair = None
        for p in self.check_list:
            if (p.protocol == protocol and p.remote_candidate == remote_candidate):
                pair = p
                break
        if pair is None:
            pair = CandidatePair(protocol, remote_candidate)
            pair.state = CandidatePair.State.WAITING
            self.check_list.append(pair)
            self.sort_check_list()

        # triggered check
        if pair.state in [CandidatePair.State.WAITING, CandidatePair.State.FAILED]:
            pair.handle = asyncio.ensure_future(self.check_start(pair))

        # 7.2.1.5. Updating the Nominated Flag
        if 'USE-CANDIDATE' in message.attributes and not self.ice_controlling:
            pair.remote_nominated = True

            if pair.state == CandidatePair.State.SUCCEEDED:
                pair.nominated = True
                self.check_complete(pair)

    def check_periodic(self):
        # find the highest-priority pair that is in the waiting state
        for pair in self.check_list:
            if pair.state == CandidatePair.State.WAITING:
                pair.handle = asyncio.ensure_future(self.check_start(pair))
                return True

        # find the highest-priority pair that is in the frozen state
        for pair in self.check_list:
            if pair.state == CandidatePair.State.FROZEN:
                pair.handle = asyncio.ensure_future(self.check_start(pair))
                return True

        return False

    async def check_start(self, pair):
        """
        Starts a check.
        """
        self.check_state(pair, CandidatePair.State.IN_PROGRESS)

        tx_username = '%s:%s' % (self.remote_username, self.local_username)
        request = stun.Message(message_method=stun.Method.BINDING,
                               message_class=stun.Class.REQUEST)
        request.attributes['USERNAME'] = tx_username
        request.attributes['PRIORITY'] = candidate_priority(pair.component, 'prflx')
        if self.ice_controlling:
            request.attributes['ICE-CONTROLLING'] = self.tie_breaker
            request.attributes['USE-CANDIDATE'] = None
        else:
            request.attributes['ICE-CONTROLLED'] = self.tie_breaker

        try:
            response, addr = await pair.protocol.request(
                request, pair.remote_addr,
                integrity_key=self.remote_password.encode('utf8'))
        except exceptions.TransactionError as exc:
            # 7.1.3.1. Failure Cases
            if exc.response and exc.response.attributes.get('ERROR-CODE', (None, None))[0] == 487:
                if 'ICE-CONTROLLING' in request.attributes:
                    self.switch_role(ice_controlling=False)
                elif 'ICE-CONTROLLED' in request.attributes:
                    self.switch_role(ice_controlling=True)
                return await self.check_start(pair)
            else:
                self.check_state(pair, CandidatePair.State.FAILED)
                self.check_complete(pair)
                return

        # check remote address matches
        if addr != pair.remote_addr:
            self.__log_info('Check %s failed : source address mismatch' % repr(pair))
            self.check_state(pair, CandidatePair.State.FAILED)
            self.check_complete(pair)
            return

        # success
        self.check_state(pair, CandidatePair.State.SUCCEEDED)
        if self.ice_controlling or pair.remote_nominated:
            pair.nominated = True
        self.check_complete(pair)

    def check_state(self, pair, state):
        """
        Updates the state of a check.
        """
        self.__log_info('Check %s %s -> %s' % (repr(pair), pair.state, state))
        pair.state = state

    async def get_component_candidates(self, component, timeout=5):
        candidates = []

        loop = asyncio.get_event_loop()
        for address in self.addresses:
            # create transport
            _, protocol = await loop.create_datagram_endpoint(
                lambda: StunProtocol(self),
                local_addr=(address, 0))
            self.protocols.append(protocol)

            # add host candidate
            candidate_address = protocol.transport.get_extra_info('sockname')
            protocol.local_candidate = Candidate(
                foundation=candidate_foundation('host', 'udp', candidate_address[0]),
                component=component,
                transport='udp',
                priority=candidate_priority(component, 'host'),
                host=candidate_address[0],
                port=candidate_address[1],
                type='host')
            candidates.append(protocol.local_candidate)

        # query STUN server for server-reflexive candidates
        if self.stun_server:
            # we query STUN server for IPv4
            fs = []
            for protocol in self.protocols:
                if ipaddress.ip_address(protocol.local_candidate.host).version == 4:
                    fs.append(server_reflexive_candidate(protocol, self.stun_server))
            if len(fs):
                done, pending = await asyncio.wait(fs, timeout=timeout)
                candidates += [task.result() for task in done if task.exception() is None]
                for task in pending:
                    task.cancel()

        # connect to TURN server
        if self.turn_server:
            # create transport
            _, protocol = await turn.create_turn_endpoint(
                lambda: StunProtocol(self),
                server_addr=self.turn_server,
                username=self.turn_username,
                password=self.turn_password)
            self.protocols.append(protocol)

            # add relayed candidate
            candidate_address = protocol.transport.get_extra_info('sockname')
            protocol.local_candidate = Candidate(
                foundation=candidate_foundation('relay', 'udp', candidate_address[0]),
                component=component,
                transport='udp',
                priority=candidate_priority(component, 'relay'),
                host=candidate_address[0],
                port=candidate_address[1],
                type='relay')
            candidates.append(protocol.local_candidate)

        return candidates

    def request_received(self, message, addr, protocol, raw_data):
        if message.message_method != stun.Method.BINDING:
            self.respond_error(message, addr, protocol, (400, 'Bad Request'))
            return

        # authenticate request
        try:
            stun.parse_message(raw_data,
                               integrity_key=self.local_password.encode('utf8'))
            rx_username = '%s:%s' % (self.local_username, self.remote_username)
            if message.attributes.get('USERNAME') != rx_username:
                raise ValueError('Wrong username')
        except ValueError as exc:
            self.respond_error(message, addr, protocol, (400, 'Bad Request'))
            return

        # 7.2.1.1. Detecting and Repairing Role Conflicts
        if self.ice_controlling and 'ICE-CONTROLLING' in message.attributes:
            self.__log_info('Role conflict, expected to be controlling')
            if self.tie_breaker >= message.attributes['ICE-CONTROLLING']:
                self.respond_error(message, addr, protocol, (487, 'Role Conflict'))
                return
            self.switch_role(ice_controlling=False)
        elif not self.ice_controlling and 'ICE-CONTROLLED' in message.attributes:
            self.__log_info('Role conflict, expected to be controlled')
            if self.tie_breaker < message.attributes['ICE-CONTROLLED']:
                self.respond_error(message, addr, protocol, (487, 'Role Conflict'))
                return
            self.switch_role(ice_controlling=True)

        # send binding response
        response = stun.Message(
            message_method=stun.Method.BINDING,
            message_class=stun.Class.RESPONSE,
            transaction_id=message.transaction_id)
        response.attributes['XOR-MAPPED-ADDRESS'] = addr
        response.add_message_integrity(self.local_password.encode('utf8'))
        response.add_fingerprint()
        protocol.send_stun(response, addr)

        if not self.check_list:
            self.early_checks.append((message, addr, protocol))
        else:
            self.check_incoming(message, addr, protocol)

    def respond_error(self, request, addr, protocol, error_code):
        response = stun.Message(
            message_method=request.message_method,
            message_class=stun.Class.ERROR,
            transaction_id=request.transaction_id)
        response.attributes['ERROR-CODE'] = error_code
        response.add_message_integrity(self.local_password.encode('utf8'))
        response.add_fingerprint()
        protocol.send_stun(response, addr)

    def sort_check_list(self):
        sort_candidate_pairs(self.check_list, self.ice_controlling)

    def switch_role(self, ice_controlling):
        self.__log_info('Switching to %s role', ice_controlling and 'controlling' or 'controlled')
        self.ice_controlling = ice_controlling
        self.sort_check_list()

    def __log_info(self, msg, *args):
        logger.info(repr(self) + ' ' + msg, *args)

    def __repr__(self):
        return 'Connection(%s)' % self.id
