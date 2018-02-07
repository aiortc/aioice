class ConnectionError(Exception):
    pass


class ImproperlyConfigured(Exception):
    pass


class TransactionError(Exception):
    pass


class TransactionFailed(TransactionError):
    def __str__(self):
        return 'STUN transaction failed'


class TransactionTimeout(TransactionError):
    def __str__(self):
        return 'STUN transaction timed out'
