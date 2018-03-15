import os
import string

from .compat import secrets


def random_string(length):
    allchar = string.ascii_letters + string.digits
    return ''.join(secrets.choice(allchar) for x in range(length))


def random_transaction_id():
    return os.urandom(12)
