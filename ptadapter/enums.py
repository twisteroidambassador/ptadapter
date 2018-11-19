import enum


class BytesEnum(bytes, enum.Enum):
    pass


class SOCKS5AuthType(BytesEnum):
    NO_AUTH = b'\x00'
    GSSAPI = b'\x01'
    USERNAME_PASSWORD = b'\x02'
    NO_OFFERS_ACCEPTABLE = b'\xff'


class SOCKS5Command(BytesEnum):
    CONNECT = b'\x01'
    BIND = b'\x02'
    UDP_ASSOCIATE = b'\x03'


class SOCKS5AddressType(BytesEnum):
    IPV4_ADDRESS = b'\x01'
    DOMAIN_NAME = b'\x03'
    IPV6_ADDRESS = b'\x04'


class SOCKS5Reply(BytesEnum):
    """Command reply from SOCKS5 server to client."""
    SUCCESS = b'\x00'
    GENERAL_FAILURE = b'\x01'
    CONNECTION_NOT_ALLOWED_BY_RULESET = b'\x02'
    NETWORK_UNREACHABLE = b'\x03'
    HOST_UNREACHABLE = b'\x04'
    CONNECTION_REFUSED = b'\x05'
    TTL_EXPIRED = b'\x06'
    COMMAND_NOT_SUPPORTED = b'\x07'
    ADDRESS_TYPE_NOT_SUPPORTED = b'\x08'


class SOCKS4Command(BytesEnum):
    CONNECT = b'\x01'
    BIND = b'\x02'


class SOCKS4Reply(BytesEnum):
    """Command reply from SOCKS4 server to client."""
    GRANTED = b'\x5A'
    REJECTED_OR_FAILED = b'\x5B'
    NO_IDENTD = b'\x5C'
    USER_ID_MISMATCH = b'\x5D'


class ExtOrPortAuthTypes(BytesEnum):
    END_AUTH_TYPES = b'\x00'
    SAFE_COOKIE = b'\x01'


class ExtOrPortCommand(BytesEnum):
    DONE = b'\x00\x00'
    USERADDR = b'\x00\x01'
    TRANSPORT = b'\x00\x02'


class ExtOrPortReply(BytesEnum):
    OKAY = b'\x10\x00'
    DENY = b'\x10\x01'
    CONTROL = b'\x10\x02'
