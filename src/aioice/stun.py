import asyncio
import binascii
import enum
import hmac
import ipaddress
from collections.abc import Callable
from struct import pack, unpack
from typing import Any, Protocol

from .utils import random_transaction_id

COOKIE = 0x2112A442
FINGERPRINT_LENGTH = 8
FINGERPRINT_XOR = 0x5354554E
HEADER_LENGTH = 20
INTEGRITY_LENGTH = 24
IPV4_PROTOCOL = 1
IPV6_PROTOCOL = 2

RETRY_MAX = 6
RETRY_RTO = 0.5


def set_body_length(data: bytes, length: int) -> bytes:
    return data[0:2] + pack("!H", length) + data[4:]


def message_fingerprint(data: bytes) -> int:
    check_data = set_body_length(data, len(data) - HEADER_LENGTH + FINGERPRINT_LENGTH)
    return binascii.crc32(check_data) ^ FINGERPRINT_XOR


def message_integrity(data: bytes, key: bytes) -> bytes:
    check_data = set_body_length(data, len(data) - HEADER_LENGTH + INTEGRITY_LENGTH)
    return hmac.new(key, check_data, "sha1").digest()


def xor_data(data: bytes, transaction_id: bytes) -> bytes:
    xpad = pack("!HI", COOKIE >> 16, COOKIE) + transaction_id
    xdata = b""
    for i in range(len(data)):
        xdata += int.to_bytes(data[i] ^ xpad[i], 1, "big", signed=False)
    return xdata


def pack_address(
    value: tuple[str, int],
    xor: Callable[[bytes], bytes] = lambda x: x,
) -> bytes:
    ip_address = ipaddress.ip_address(value[0])
    if isinstance(ip_address, ipaddress.IPv4Address):
        protocol = IPV4_PROTOCOL
    else:
        protocol = IPV6_PROTOCOL
    return pack("!BB", 0, protocol) + xor(pack("!H", value[1]) + ip_address.packed)


def pack_bytes(value: bytes) -> bytes:
    return value


def pack_error_code(value: tuple[int, str]) -> bytes:
    return pack("!HBB", 0, value[0] // 100, value[0] % 100) + value[1].encode("utf8")


def pack_none(value: None) -> bytes:
    return b""


def pack_string(value: str) -> bytes:
    return value.encode("utf8")


def pack_unsigned(value: int) -> bytes:
    return pack("!I", value)


def pack_unsigned_short(value: int) -> bytes:
    return pack("!H", value) + b"\x00\x00"


def pack_unsigned_64(value: int) -> bytes:
    return pack("!Q", value)


def pack_xor_address(value: tuple[str, int], transaction_id: bytes) -> bytes:
    return pack_address(value, lambda x: xor_data(x, transaction_id))


def unpack_address(
    data: bytes,
    xor: Callable[[bytes], bytes] = lambda x: x,
) -> tuple[str, int]:
    if len(data) < 4:
        raise ValueError("STUN address length is less than 4 bytes")

    # The first two bytes are a reserved byte and the protocol family.
    reserved, protocol = unpack("!BB", data[0:2])

    # The remaining data represents a port and an address.
    port_address = data[2:]
    if protocol == IPV4_PROTOCOL:
        # For IPv4 we expect 2 bytes for the port, 4 bytes for the address.
        if len(port_address) != 6:
            raise ValueError("STUN address has invalid length for IPv4")
        port_address = xor(port_address)
        return (
            str(ipaddress.IPv4Address(port_address[2:])),
            unpack("!H", port_address[0:2])[0],
        )
    elif protocol == IPV6_PROTOCOL:
        # For IPv6 we expect 2 bytes for the port, 16 bytes for the address.
        if len(port_address) != 18:
            raise ValueError("STUN address has invalid length for IPv6")
        port_address = xor(port_address)
        return (
            str(ipaddress.IPv6Address(port_address[2:])),
            unpack("!H", port_address[0:2])[0],
        )
    else:
        raise ValueError("STUN address has unknown protocol")


def unpack_xor_address(data: bytes, transaction_id: bytes) -> tuple[str, int]:
    return unpack_address(data, lambda x: xor_data(x, transaction_id))


def unpack_bytes(data: bytes) -> bytes:
    return data


def unpack_error_code(data: bytes) -> tuple[int, str]:
    if len(data) < 4:
        raise ValueError("STUN error code is less than 4 bytes")
    reserved, code_high, code_low = unpack("!HBB", data[0:4])
    reason = data[4:].decode("utf8")
    return (code_high * 100 + code_low, reason)


def unpack_none(data: bytes) -> None:
    return None


def unpack_string(data: bytes) -> str:
    return data.decode("utf8")


def unpack_unsigned(data: bytes) -> int:
    value: int = unpack("!I", data)[0]
    return value


def unpack_unsigned_short(data: bytes) -> int:
    value: int = unpack("!H", data[0:2])[0]
    return value


def unpack_unsigned_64(data: bytes) -> int:
    value: int = unpack("!Q", data)[0]
    return value


AttributeEntry = tuple[int, str, Callable[..., bytes], Callable[..., Any]]

ATTRIBUTES: list[AttributeEntry] = [
    (0x0001, "MAPPED-ADDRESS", pack_address, unpack_address),
    (0x0003, "CHANGE-REQUEST", pack_unsigned, unpack_unsigned),
    (0x0004, "SOURCE-ADDRESS", pack_address, unpack_address),
    (0x0005, "CHANGED-ADDRESS", pack_address, unpack_address),
    (0x0006, "USERNAME", pack_string, unpack_string),
    (0x0008, "MESSAGE-INTEGRITY", pack_bytes, unpack_bytes),
    (0x0009, "ERROR-CODE", pack_error_code, unpack_error_code),
    (0x000C, "CHANNEL-NUMBER", pack_unsigned_short, unpack_unsigned_short),
    (0x000D, "LIFETIME", pack_unsigned, unpack_unsigned),
    (0x0012, "XOR-PEER-ADDRESS", pack_xor_address, unpack_xor_address),
    (0x0013, "DATA", pack_bytes, unpack_bytes),
    (0x0014, "REALM", pack_string, unpack_string),
    (0x0015, "NONCE", pack_bytes, unpack_bytes),
    (0x0016, "XOR-RELAYED-ADDRESS", pack_xor_address, unpack_xor_address),
    (0x0019, "REQUESTED-TRANSPORT", pack_unsigned, unpack_unsigned),
    (0x0020, "XOR-MAPPED-ADDRESS", pack_xor_address, unpack_xor_address),
    (0x0024, "PRIORITY", pack_unsigned, unpack_unsigned),
    (0x0025, "USE-CANDIDATE", pack_none, unpack_none),
    (0x8022, "SOFTWARE", pack_string, unpack_string),
    (0x8028, "FINGERPRINT", pack_unsigned, unpack_unsigned),
    (0x8029, "ICE-CONTROLLED", pack_unsigned_64, unpack_unsigned_64),
    (0x802A, "ICE-CONTROLLING", pack_unsigned_64, unpack_unsigned_64),
    (0x802B, "RESPONSE-ORIGIN", pack_address, unpack_address),
    (0x802C, "OTHER-ADDRESS", pack_address, unpack_address),
]

ATTRIBUTES_BY_TYPE: dict[int, AttributeEntry] = {}
ATTRIBUTES_BY_NAME: dict[str, AttributeEntry] = {}
for attr in ATTRIBUTES:
    ATTRIBUTES_BY_TYPE[attr[0]] = attr
    ATTRIBUTES_BY_NAME[attr[1]] = attr


class Class(enum.IntEnum):
    REQUEST = 0x000
    INDICATION = 0x010
    RESPONSE = 0x100
    ERROR = 0x110


class Method(enum.IntEnum):
    BINDING = 0x1
    SHARED_SECRET = 0x2
    ALLOCATE = 0x3
    REFRESH = 0x4
    SEND = 0x6
    DATA = 0x7
    CREATE_PERMISSION = 0x8
    CHANNEL_BIND = 0x9


class Message:
    def __init__(
        self,
        message_method: Method,
        message_class: Class,
        transaction_id: bytes | None = None,
        attributes: dict[str, Any] | None = None,
    ) -> None:
        self.message_method = message_method
        self.message_class = message_class
        self.transaction_id = transaction_id or random_transaction_id()
        self.attributes = attributes or {}

        # The data covered by MESSAGE-INTEGRITY, if present.
        self._integrity_data: bytes | None = None

    def add_fingerprint(self) -> None:
        """
        Add the FINGERPRINT attribute to the message.

        This must be the last step before sending out the message.
        """
        self.attributes.pop("FINGERPRINT", None)
        self.attributes["FINGERPRINT"] = message_fingerprint(bytes(self))

    def add_message_integrity(self, key: bytes) -> None:
        """
        Add MESSAGE-INTEGRITY and FINGERPRINT attributes to the message.

        This must be the last step before sending out the message.
        """
        self.attributes.pop("MESSAGE-INTEGRITY", None)
        self.attributes.pop("FINGERPRINT", None)
        self._integrity_data = bytes(self)
        self.attributes["MESSAGE-INTEGRITY"] = message_integrity(
            self._integrity_data, key
        )
        self.add_fingerprint()

    def check_message_integrity(self, key: bytes) -> bool:
        """
        Check the MESSAGE-INTEGRITY attribute of the message against `key`.

        A message without MESSAGE-INTEGRITY fails the check.
        """
        if self._integrity_data is None:
            return False
        return hmac.compare_digest(
            self.attributes["MESSAGE-INTEGRITY"],
            message_integrity(self._integrity_data, key),
        )

    @property
    def error_code(self) -> int | None:
        """
        The code of the ERROR-CODE attribute, or `None` if it is absent.
        """
        error_code = self.attributes.get("ERROR-CODE")
        return error_code[0] if error_code is not None else None

    def __bytes__(self) -> bytes:
        data = b""
        for attr_name, attr_value in self.attributes.items():
            attr_type, _, attr_pack, attr_unpack = ATTRIBUTES_BY_NAME[attr_name]
            if attr_pack == pack_xor_address:
                v = attr_pack(attr_value, self.transaction_id)
            else:
                v = attr_pack(attr_value)

            attr_len = len(v)
            pad_len = padding_length(attr_len)
            data += pack("!HH", attr_type, attr_len) + v + bytes(pad_len)
        return (
            pack(
                "!HHI12s",
                self.message_method | self.message_class,
                len(data),
                COOKIE,
                self.transaction_id,
            )
            + data
        )

    def __repr__(self) -> str:
        return (
            f"Message(message_method=Method.{self.message_method.name}, "
            f"message_class=Class.{self.message_class.name}, "
            f"transaction_id={self.transaction_id.hex()}, "
            f"attributes={self.attributes})"
        )


class TransactionError(Exception):
    response: Message | None = None


class TransactionFailed(TransactionError):
    response: Message

    def __init__(self, response: Message) -> None:
        self.response = response

    def __str__(self) -> str:
        out = "STUN transaction failed"
        if "ERROR-CODE" in self.response.attributes:
            code, reason = self.response.attributes["ERROR-CODE"]
            out += f" ({code} - {reason})"
        return out


class TransactionTimeout(TransactionError):
    def __str__(self) -> str:
        return "STUN transaction timed out"


class TransactionSender(Protocol):
    def send_stun(self, message: Message, addr: tuple[str, int]) -> None: ...


class Transaction:
    def __init__(
        self,
        request: Message,
        addr: tuple[str, int],
        protocol: TransactionSender,
        retransmissions: int | None = None,
        integrity_key: bytes | None = None,
        long_term_credential: bool = False,
    ) -> None:
        self.__addr = addr
        self.__integrity_key = integrity_key
        self.__long_term_credential = long_term_credential
        self.__future: asyncio.Future[tuple[Message, tuple[str, int]]] = (
            asyncio.Future()
        )
        self.__request = request
        self.__timeout_delay = RETRY_RTO
        self.__timeout_handle: asyncio.TimerHandle | None = None
        self.__protocol = protocol
        self.__tries = 0
        self.__tries_max = 1 + (
            retransmissions if retransmissions is not None else RETRY_MAX
        )

    def response_received(self, message: Message, addr: tuple[str, int]) -> None:
        # Discard a response which is not authenticated with the key of the
        # request, so retransmissions continue (RFC 8489 sections 9.1.4 and
        # 9.2.5).
        if self.__integrity_key is not None:
            if not self.__authenticated(message, self.__integrity_key):
                return

        if not self.__future.done():
            if message.message_class == Class.RESPONSE:
                self.__future.set_result((message, addr))
            else:
                self.__future.set_exception(TransactionFailed(message))

    def __authenticated(self, message: Message, integrity_key: bytes) -> bool:
        # With long-term credentials, a 401 or 438 error gives the realm and
        # nonce to retry with, and need not be signed (RFC 8489 sections 9.2.4
        # and 9.2.5).
        if (
            self.__long_term_credential
            and message.message_class == Class.ERROR
            and message.error_code in (401, 438)
        ):
            return True
        return message.check_message_integrity(integrity_key)

    async def run(self) -> tuple[Message, tuple[str, int]]:
        try:
            self.__retry()
            return await self.__future
        finally:
            if self.__timeout_handle:
                self.__timeout_handle.cancel()

    def __retry(self) -> None:
        # Retransmissions stop once a response is received (RFC 5389 section 7.2.1),
        # which may have happened before run() could cancel the timer.
        if self.__future.done():
            return

        if self.__tries >= self.__tries_max:
            self.__future.set_exception(TransactionTimeout())
            return

        self.__protocol.send_stun(self.__request, self.__addr)

        loop = asyncio.get_running_loop()
        self.__timeout_handle = loop.call_later(self.__timeout_delay, self.__retry)
        self.__timeout_delay *= 2
        self.__tries += 1


def padding_length(length: int) -> int:
    """
    STUN message attributes are padded to a 4-byte boundary.
    """
    rest = length % 4
    if rest == 0:
        return 0
    else:
        return 4 - rest


def parse_message(data: bytes) -> Message:
    """
    Parses a STUN message.

    The MESSAGE-INTEGRITY attribute is verified separately, by
    `Message.check_message_integrity()`.
    """
    if len(data) < HEADER_LENGTH:
        raise ValueError("STUN message length is less than 20 bytes")
    message_type, length, cookie, transaction_id = unpack(
        "!HHI12s", data[0:HEADER_LENGTH]
    )
    if len(data) != HEADER_LENGTH + length:
        raise ValueError("STUN message length does not match")

    attributes = {}
    integrity_data = None
    pos = HEADER_LENGTH
    while pos <= len(data) - 4:
        attr_type, attr_len = unpack("!HH", data[pos : pos + 4])
        v = data[pos + 4 : pos + 4 + attr_len]
        pad_len = padding_length(attr_len)
        if attr_type in ATTRIBUTES_BY_TYPE:
            _, attr_name, attr_pack, attr_unpack = ATTRIBUTES_BY_TYPE[attr_type]

            # Ignore the attributes which follow MESSAGE-INTEGRITY, except
            # FINGERPRINT, as they are not authenticated (RFC 8489 section 9).
            if integrity_data is None or attr_name == "FINGERPRINT":
                if attr_unpack == unpack_xor_address:
                    attributes[attr_name] = attr_unpack(
                        v, transaction_id=transaction_id
                    )
                else:
                    attributes[attr_name] = attr_unpack(v)

                if attr_name == "FINGERPRINT":
                    if attributes[attr_name] != message_fingerprint(data[0:pos]):
                        raise ValueError("STUN message fingerprint does not match")
                elif attr_name == "MESSAGE-INTEGRITY":
                    integrity_data = data[0:pos]

        pos += 4 + attr_len + pad_len

    message = Message(
        # An unknown method raises a `ValueError`.
        message_method=Method(message_type & 0x3EEF),
        # This cast cannot fail, as all 4 possible classes are defined.
        message_class=Class(message_type & 0x0110),
        transaction_id=transaction_id,
        attributes=attributes,
    )
    message._integrity_data = integrity_data
    return message
