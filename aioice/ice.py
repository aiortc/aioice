import asyncio
import enum
import hashlib
import ipaddress
import logging
import socket
import string

import netifaces

from . import exceptions, stun
from .compat import secrets

logger = logging.getLogger('ice')


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


def random_string(length):
    allchar = string.ascii_letters + string.digits
    return ''.join(secrets.choice(allchar) for x in range(length))


async def server_reflexive_candidate(protocol, stun_server):
    """
    Query STUN server to obtain a server-reflexive candidate.
    """
    request = stun.Message(message_method=stun.Method.BINDING,
                           message_class=stun.Class.REQUEST,
                           transaction_id=random_string(12).encode('ascii'))
    response = await protocol.request(request, stun_server)

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
        return -candidate_pair_priority(pair.protocol.local_candidate,
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
        a = ipaddress.ip_address(self.host)
        b = ipaddress.ip_address(other.host)
        if a.version != b.version:
            return False

        if a.version == 6 and a.is_global != b.is_global:
            return False

        return True


class CandidatePair:
    def __init__(self, protocol, remote_candidate):
        self.nominated = False
        self.protocol = protocol
        self.remote_candidate = remote_candidate
        self.remote_nominated = False
        self.state = CandidatePair.State.WAITING

    def __repr__(self):
        return 'CandidatePair(%s -> %s)' % (self.local_addr, self.remote_addr)

    @property
    def local_addr(self):
        return (self.protocol.local_candidate.host, self.protocol.local_candidate.port)

    @property
    def remote_addr(self):
        return (self.remote_candidate.host, self.remote_candidate.port)

    class State(enum.Enum):
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


class StunProtocol:
    def __init__(self, receiver):
        self.id = next_protocol_id()
        self.queue = asyncio.Queue()
        self.receiver = receiver
        self.transport = None
        self.transactions = {}

    def connection_lost(self, exc):
        logger.debug('%s connection_lost(%s)', repr(self), exc)

    def connection_made(self, transport):
        logger.debug('%s connection_made(%s)', repr(self), transport)
        self.transport = transport

    def datagram_received(self, data, addr):
        try:
            message = stun.parse_message(data)
            logger.debug('%s < %s %s', repr(self), addr, repr(message))
        except ValueError:
            logger.debug('%s < %s DATA %d', repr(self), addr, len(data))
            coro = self.queue.put(data)
            asyncio.ensure_future(coro)
            return

        if ((message.message_class == stun.Class.RESPONSE or
             message.message_class == stun.Class.ERROR) and
           message.transaction_id in self.transactions):
            transaction = self.transactions[message.transaction_id]
            transaction.message_received(message, addr)
        self.receiver.stun_message_received(message, addr, self)

    def error_received(self, exc):
        logger.debug('%s error_received(%s)', repr(self), exc)

    # custom

    async def recv_data(self):
        return await self.queue.get()

    async def send_data(self, data, addr):
        logger.debug('%s > %s DATA %d', repr(self), addr, len(data))
        self.transport.sendto(data, addr)

    async def request(self, request, addr):
        """
        Execute a STUN transaction and return the response.
        """
        assert request.transaction_id not in self.transactions

        transaction = stun.Transaction(request, addr, self)
        self.transactions[request.transaction_id] = transaction
        response = await transaction.run()
        del self.transactions[request.transaction_id]

        return response

    def send_stun(self, message, addr):
        """
        Send a STUN message.
        """
        logger.debug('%s > %s %s', repr(self), addr, repr(message))
        self.transport.sendto(bytes(message), addr)

    def __repr__(self):
        return 'client(%s)' % self.id


class Component:
    """
    An ICE component.
    """
    def __init__(self, component, addresses, connection):
        self.__active_pair = None
        self.__active_queue = asyncio.Queue()
        self.__addresses = addresses
        self.__connection = connection
        self.__component = component
        self.__pairs = []
        self.__protocols = []
        self.__remote_candidates = []

    async def close(self):
        for protocol in self.__protocols:
            protocol.transport.close()
        self.__protocols = []

    async def get_local_candidates(self, timeout=5):
        candidates = []

        loop = asyncio.get_event_loop()
        for address in self.__addresses:
            # create transport
            _, protocol = await loop.create_datagram_endpoint(
                lambda: StunProtocol(self),
                local_addr=(address, 0))
            port = protocol.transport.get_extra_info('socket').getsockname()[1]
            self.__protocols.append(protocol)

            # add host candidate
            protocol.local_candidate = Candidate(
                foundation=candidate_foundation('host', 'udp', address),
                component=self.__component,
                transport='udp',
                priority=candidate_priority(self.__component, 'host'),
                host=address,
                port=port,
                type='host')
            candidates.append(protocol.local_candidate)

        # query STUN server for server-reflexive candidates
        if self.__connection.stun_server:
            fs = map(lambda x: server_reflexive_candidate(x, self.__connection.stun_server),
                     self.__protocols)
            done, pending = await asyncio.wait(fs, timeout=timeout)
            candidates += [task.result() for task in done if task.exception() is None]
            for task in pending:
                task.cancel()

        return candidates

    def set_remote_candidates(self, candidates):
        self.__remote_candidates = candidates

    def stun_message_received(self, message, addr, protocol):
        if (message.message_method == stun.Method.BINDING and
           message.message_class == stun.Class.REQUEST and
           message.attributes['USERNAME'] == self.__incoming_username()):

            # check for role conflict
            ice_controlling = self.__connection.ice_controlling
            if ice_controlling and 'ICE-CONTROLLING' in message.attributes:
                logger.warning('Role conflict, expected to be controlling')
                if self.__connection.tie_breaker >= message.attributes['ICE-CONTROLLING']:
                    response = stun.Message(
                        message_method=stun.Method.BINDING,
                        message_class=stun.Class.ERROR,
                        transaction_id=message.transaction_id)
                    response.attributes['ERROR-CODE'] = (487, 'Role Conflict')
                    response.add_message_integrity(self.__connection.local_password.encode('utf8'))
                    response.add_fingerprint()
                    protocol.send_stun(response, addr)
                else:
                    logger.warning('Switching to controlled role is not implemented')
                return
            elif not ice_controlling and 'ICE-CONTROLLED' in message.attributes:
                logger.warning("Role conflict, expected to be controlled")
                if self.__connection.tie_breaker >= message.attributes['ICE-CONTROLLED']:
                    logger.warning('Switching to controlling role is not implemented')
                else:
                    response = stun.Message(
                        message_method=stun.Method.BINDING,
                        message_class=stun.Class.ERROR,
                        transaction_id=message.transaction_id)
                    response.attributes['ERROR-CODE'] = (487, 'Role Conflict')
                    response.add_message_integrity(self.__connection.local_password.encode('utf8'))
                    response.add_fingerprint()
                    protocol.send_stun(response, addr)
                return

            # send binding response
            response = stun.Message(
                message_method=stun.Method.BINDING,
                message_class=stun.Class.RESPONSE,
                transaction_id=message.transaction_id)
            response.attributes['XOR-MAPPED-ADDRESS'] = addr
            response.add_message_integrity(self.__connection.local_password.encode('utf8'))
            response.add_fingerprint()
            protocol.send_stun(response, addr)

            # find remote candidate
            remote_candidate = None
            for c in self.__remote_candidates:
                if c.host == addr[0] and c.port == addr[1]:
                    remote_candidate = c
                    break
            if remote_candidate is None:
                # 7.2.1.3. Learning Peer Reflexive Candidates
                remote_candidate = Candidate(
                    foundation=random_string(10),
                    component=self.__component,
                    transport='udp',
                    priority=message['PRIORITY'],
                    host=addr[0],
                    port=addr[1],
                    type='prflx')
                self.__remote_candidates.append(remote_candidate)

            # find pair
            pair = None
            for p in self.__pairs:
                if (p.protocol == protocol and p.remote_addr == addr):
                    pair = p
                    break
            if pair is None:
                pair = CandidatePair(protocol, remote_candidate)
                self.__pairs.append(pair)
                sort_candidate_pairs(self.__pairs, self.__connection.ice_controlling)

            if 'USE-CANDIDATE' in message.attributes and not self.__connection.ice_controlling:
                pair.remote_nominated = True

                if pair.state == CandidatePair.State.SUCCEEDED:
                    self.nominate_pair(pair)

    async def connect(self):
        # create candidate pairs
        candidate_pairs = []
        for remote_candidate in self.__remote_candidates:
            for protocol in self.__protocols:
                if protocol.local_candidate.can_pair_with(remote_candidate):
                    pair = CandidatePair(protocol, remote_candidate)
                    candidate_pairs.append(pair)
        sort_candidate_pairs(candidate_pairs, self.__connection.ice_controlling)
        self.__pairs = candidate_pairs

        # perform checks
        succeeded = False
        for pair in self.__pairs[:]:
            await self.check_pair(pair)
            if pair.state == CandidatePair.State.SUCCEEDED:
                succeeded = True
        if not succeeded:
            raise exceptions.ConnectionError('No validate candidate pairs')

        # wait for a pair to be active
        await self.__active_queue.get()

    async def check_pair(self, pair):
        logger.info('Checking pair %s' % repr(pair))
        pair.state = CandidatePair.State.IN_PROGRESS

        request = stun.Message(message_method=stun.Method.BINDING,
                               message_class=stun.Class.REQUEST,
                               transaction_id=random_string(12).encode('ascii'))
        request.attributes['USERNAME'] = self.__outgoing_username()
        request.attributes['PRIORITY'] = candidate_priority(self.__component, 'prflx')
        if self.__connection.ice_controlling:
            request.attributes['ICE-CONTROLLING'] = self.__connection.tie_breaker
            request.attributes['USE-CANDIDATE'] = None
        else:
            request.attributes['ICE-CONTROLLED'] = self.__connection.tie_breaker
        request.add_message_integrity(self.__connection.remote_password.encode('utf8'))
        request.add_fingerprint()

        try:
            await pair.protocol.request(request, pair.remote_addr)
            pair.state = CandidatePair.State.SUCCEEDED
            if self.__connection.ice_controlling or pair.remote_nominated:
                self.nominate_pair(pair)
        except exceptions.TransactionError as e:
            pair.state = CandidatePair.State.FAILED

    def nominate_pair(self, pair):
        logger.info('Nominated pair %s' % repr(pair))
        pair.nominated = True

        nominated_pairs = [x for x in self.__pairs if x.nominated]
        sort_candidate_pairs(nominated_pairs, self.__connection.ice_controlling)
        active_pair = nominated_pairs[0]

        if active_pair != self.__active_pair:
            logger.info('Activated pair %s' % repr(active_pair))
            self.__active_pair = active_pair
            asyncio.ensure_future(self.__active_queue.put(active_pair))

    async def recv(self):
        fs = [protocol.recv_data() for protocol in self.__protocols]
        done, pending = await asyncio.wait(fs, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
        assert len(done) == 1
        return done.pop().result()

    async def send(self, data):
        if self.__active_pair:
            await self.__active_pair.protocol.send_data(data, self.__active_pair.remote_addr)

    def __incoming_username(self):
        return '%s:%s' % (self.__connection.local_username, self.__connection.remote_username)

    def __outgoing_username(self):
        return '%s:%s' % (self.__connection.remote_username, self.__connection.local_username)


class Connection:
    """
    An ICE connection.
    """
    def __init__(self, ice_controlling, stun_server=None):
        self.ice_controlling = ice_controlling
        self.local_username = random_string(4)
        self.local_password = random_string(22)
        self.remote_username = None
        self.remote_password = None
        self.stun_server = stun_server
        self.tie_breaker = secrets.token_bytes(8)

        # get host addresses
        addresses = []
        for interface in netifaces.interfaces():
            ifaddresses = netifaces.ifaddresses(interface)
            for address in ifaddresses.get(socket.AF_INET, []):
                if address['addr'] != '127.0.0.1':
                    addresses.append(address['addr'])

        self.__component = Component(1, addresses, self)

    async def get_local_candidates(self):
        """
        Gather local candidates.
        """
        return await self.__component.get_local_candidates()

    def set_remote_candidates(self, candidates):
        """
        Set remote candidates.
        """
        self.__component.set_remote_candidates(candidates)

    async def connect(self):
        """
        Perform ICE handshake.

        This coroutine returns if a candidate pair was successfuly nominated
        and raises an exception otherwise.
        """
        if (self.remote_username is None or
           self.remote_password is None):
            raise exceptions.ImproperlyConfigured('Remote username or password is missing')
        await self.__component.connect()

    async def close(self):
        """
        Close the connection.
        """
        await self.__component.close()

    async def recv(self):
        """
        Receive the next datagram.
        """
        return await self.__component.recv()

    async def send(self, data):
        """
        Send a datagram.
        """
        return await self.__component.send(data)
