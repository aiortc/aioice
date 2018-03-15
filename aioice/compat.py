import os
import random

try:
    import secrets
except ImportError:
    secrets = None


_system_random = random.SystemRandom()


class CompatSecrets:
    def choice(self, sequence):
        return _system_random.choice(sequence)

    def randbits(self, k):
        return _system_random.getrandbits(k)

    def token_bytes(self, length):
        return os.urandom(length)


if secrets is None:
    secrets = CompatSecrets()
