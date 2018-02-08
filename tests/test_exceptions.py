import unittest

from aioice import exceptions, stun


class ExceptionTest(unittest.TestCase):
    def test_transaction_failed(self):
        response = stun.Message(
            message_method=stun.Method.BINDING,
            message_class=stun.Class.RESPONSE)
        response.attributes['ERROR-CODE'] = (487, 'Role Conflict')

        exc = exceptions.TransactionFailed(response)
        self.assertEqual(str(exc), 'STUN transaction failed (487 - Role Conflict)')

    def test_transaction_timeout(self):
        exc = exceptions.TransactionTimeout()
        self.assertEqual(str(exc), 'STUN transaction timed out')
