class TransactionError(Exception):
    response = None


class TransactionFailed(TransactionError):
    def __init__(self, response) -> None:
        self.response = response

    def __str__(self) -> str:
        out = "STUN transaction failed"
        if "ERROR-CODE" in self.response.attributes:
            out += " (%s - %s)" % self.response.attributes["ERROR-CODE"]
        return out


class TransactionTimeout(TransactionError):
    def __str__(self) -> str:
        return "STUN transaction timed out"
