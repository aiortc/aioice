import os
import string

from .compat import secrets


def random_string(length: int) -> str:
    allchar = string.ascii_letters + string.digits
    return "".join(secrets.choice(allchar) for x in range(length))


def random_transaction_id() -> bytes:
    return os.urandom(12)
