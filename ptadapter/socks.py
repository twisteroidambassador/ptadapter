"""SOCKS proxy-related features.

Some constants / enumerations are exposed in __all__ and documented. Other
members of this module should be considered implementation detail.
"""

import asyncio
import ipaddress
from typing import Union, Dict, Optional

from . import enums
from . import str_utils
from . import exceptions


ARGS_ENCODING = 'ascii'


def encode_args(args: Dict[str, str]) -> bytes:
    return b';'.join(
            b'='.join((
                str_utils.escape_per_connection_args(key).encode(
                    ARGS_ENCODING),
                str_utils.escape_per_connection_args(value).encode(
                    ARGS_ENCODING),
            ))
            for key, value in args.items()
        )


async def negotiate_socks5_userpass(
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        host: Union[str, ipaddress.IPv4Address, ipaddress.IPv6Address],
        port: int,
        args: Optional[Dict[str, str]],
) -> None:
    if args:
        args_bytes = encode_args(args)
        if len(args_bytes) > 255 * 2:
            raise ValueError('Encoded args too long')
        username = args_bytes[:255]
        password = args_bytes[255:]
        if not password:
            password = b'\0'
        writer.write(b'\x05\x01'  # SOCKS5, 1 auth method
                     + enums.SOCKS5AuthType.USERNAME_PASSWORD)
        buf = await reader.readexactly(2)
        assert buf[0] == 5, 'Invalid server SOCKS version'
        if buf[1:2] != enums.SOCKS5AuthType.USERNAME_PASSWORD:
            raise RuntimeError(
                f'PT rejected userpass auth method, returned {buf[1:2]!r}')
        writer.write(b''.join((
            b'\x01',  # userpass sub-negotiation version 1
            len(username).to_bytes(1, 'big'),
            username,
            len(password).to_bytes(1, 'big'),
            password,
        )))
        buf = await reader.readexactly(2)
        assert buf[0] == 1, 'Invalid server USERPASS sub-negotiation version'
        if buf[1] != 0:
            raise RuntimeError(
                f'PT rejected username/password, returned {buf[1:2]!r}')
    else:
        writer.write(b'\x05\x01'  # SOCKS5, 1 auth method
                     + enums.SOCKS5AuthType.NO_AUTH)
        buf = await reader.readexactly(2)
        assert buf[0] == 5, 'Invalid server SOCKS version'
        if buf[1:2] != enums.SOCKS5AuthType.NO_AUTH:
            raise RuntimeError(
                f'PT rejected noauth auth method, returned {buf[1:2]!r}')

    try:
        host = ipaddress.ip_address(host)
    except ValueError:
        host_type = enums.SOCKS5AddressType.DOMAIN_NAME
        host_bytes = host.encode('idna')
        host_len = len(host_bytes)
        if host_len > 255:
            raise ValueError('Hostname too long')
        host_bytes = host_len.to_bytes(1, 'big') + host_bytes
    else:
        if host.version == 6:
            host_type = enums.SOCKS5AddressType.IPV6_ADDRESS
        else:
            host_type = enums.SOCKS5AddressType.IPV4_ADDRESS
        host_bytes = host.packed
    writer.write(b''.join((
        b'\x05',  # SOCKS5
        enums.SOCKS5Command.CONNECT,
        b'\0',  # reserved
        host_type,
        host_bytes,
        port.to_bytes(2, 'big'),
    )))
    # buf = version, reply, reserved, addr_type, 1st byte of address
    buf = await reader.readexactly(5)
    assert buf[0] == 5, 'Invalid server SOCKS version'
    reply = enums.SOCKS5Reply(buf[1:2])
    if reply is not enums.SOCKS5Reply.SUCCESS:
        raise exceptions.PTSOCKS5ConnectError(reply)
    assert buf[2] == 0, 'Invalid RSV field'
    bind_addr_type = enums.SOCKS5AddressType(buf[3:4])
    if bind_addr_type is enums.SOCKS5AddressType.IPV4_ADDRESS:
        # consume remaining address and port in one call to readexactly()
        await reader.readexactly(-1 + 4 + 2)
    elif bind_addr_type is enums.SOCKS5AddressType.IPV6_ADDRESS:
        await reader.readexactly(-1 + 16 + 2)
    else:
        await reader.readexactly(buf[4] + 2)


async def negotiate_socks4_userid(
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        host: Union[str, ipaddress.IPv4Address, ipaddress.IPv6Address],
        port: int,
        args: Optional[Dict[str, str]],
) -> None:
    try:
        host = ipaddress.IPv4Address(host)
    except ValueError:
        raise ValueError('SOCKS4 only supports IPv4 address')
    if args:
        args_bytes = encode_args(args)
    else:
        args_bytes = b''
    writer.write(b''.join((
        b'\x04',  # ver
        enums.SOCKS4Command.CONNECT,
        port.to_bytes(2, 'big'),
        host.packed,
        args_bytes,
        b'\0',
    )))
    buf = await reader.readexactly(8)
    assert buf[0] == 0, 'Invalid SOCKS4 reply version'
    reply = enums.SOCKS4Reply(buf[1:2])
    if reply is not enums.SOCKS4Reply.GRANTED:
        raise exceptions.PTSOCKS4ConnectError(reply)
