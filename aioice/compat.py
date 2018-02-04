import os
import random
try:
    import secrets
except ImportError:
    secrets = None


class CompatSecrets:
    def choice(self, *args):
        return random.choice(*args)

    def token_bytes(self, length):
        return os.urandom(length)


if secrets is None:
    secrets = CompatSecrets()
