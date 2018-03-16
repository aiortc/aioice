import hashlib
import ipaddress


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


class Candidate:
    """
    An ICE candidate.
    """
    def __init__(self, foundation, component, transport, priority, host, port, type,
                 tcptype=None, generation=None):
        self.foundation = foundation
        self.component = component
        self.transport = transport
        self.priority = priority
        self.host = host
        self.port = port
        self.type = type
        self.tcptype = tcptype
        self.generation = generation

    @classmethod
    def from_sdp(cls, sdp):
        """
        Parse a :class:`Candidate` from SDP.

        .. code-block:: python

           Candidate.from_sdp(
            '6815297761 1 udp 659136 1.2.3.4 31102 typ host generation 0')
        """
        bits = sdp.split()
        if len(bits) < 8:
            raise ValueError('SDP does not have enough properties')

        kwargs = {
            'foundation': bits[0],
            'component': int(bits[1]),
            'transport': bits[2],
            'priority': int(bits[3]),
            'host': bits[4],
            'port': int(bits[5]),
            'type': bits[7],
        }

        for i in range(8, len(bits) - 1, 2):
            if bits[i] == 'tcptype':
                kwargs['tcptype'] = bits[i + 1]
            elif bits[i] == 'generation':
                kwargs['generation'] = int(bits[i + 1])

        return Candidate(**kwargs)

    def to_sdp(self):
        """
        Return a string representation suitable for SDP.
        """
        sdp = '%s %d %s %d %s %d typ %s' % (
            self.foundation,
            self.component,
            self.transport,
            self.priority,
            self.host,
            self.port,
            self.type)
        if self.tcptype is not None:
            sdp += ' tcptype %s' % self.tcptype
        if self.generation is not None:
            sdp += ' generation %d' % self.generation
        return sdp

    def can_pair_with(self, other):
        """
        A local candidate is paired with a remote candidate if and only if
        the two candidates have the same component ID and have the same IP
        address version.
        """
        a = ipaddress.ip_address(self.host)
        b = ipaddress.ip_address(other.host)
        return self.component == other.component and a.version == b.version

    def __repr__(self):
        return 'Candidate(%s)' % self.to_sdp()
