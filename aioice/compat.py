import os
import random
import struct

try:
    import secrets
except ImportError:
    secrets = None


_system_random = random.SystemRandom()


class CompatSecrets:
    def choice(self, sequence):
        return _system_random.choice(sequence)

    def randbits(self, k):
        assert k == 64
        return struct.unpack('Q', self.token_bytes(8))[0]

    def token_bytes(self, length):
        return os.urandom(length)


if secrets is None:
    secrets = CompatSecrets()
