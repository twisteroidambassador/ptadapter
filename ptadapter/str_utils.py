import ipaddress
import string
import re
import urllib.parse
from typing import Dict, Tuple, Union, List

ASCII_LETTERS_UNDERSCORE = set(string.ascii_letters + '_')
ASCII_ALPHANUMERIC_UNDERSCORE = set(string.ascii_letters + string.digits + '_')


def validate_transport_name(transport_name: str) -> None:
    """Validate name of transports.

    pt-spec Section 3.1:
    PT names MUST be valid C identifiers.  PT names MUST begin with
    a letter or underscore, and the remaining characters MUST be
    ASCII letters, numbers or underscores.  No length limit is
    imposed.

    Raises:
        ValueError: if the transport name is invalid.
    """
    if not (transport_name[0] in ASCII_LETTERS_UNDERSCORE
            and all(c in ASCII_ALPHANUMERIC_UNDERSCORE
                    for c in transport_name[1:])):
        raise ValueError(f'Invalid transport name {transport_name!r}')


PER_CONNECTION_TRANS_TABLE = str.maketrans({
    # raw strings can’t end with an odd number of backslashes!
    '\\': r'\\',
    '=': r'\=',
    ';': r'\;',
})


def escape_per_connection_args(in_str: str) -> str:
    """Escape keys and values used in client per-connection arguments.

    pt-spec Section 3.5:
    First the "<Key>=<Value>" formatted arguments MUST be escaped,
    such that all backslash, equal sign, and semicolon characters
    are escaped with a backslash.
    """
    return in_str.translate(PER_CONNECTION_TRANS_TABLE)


SERVER_OPTS_TRANS_TABLE = str.maketrans({
    ':': r'\:',
    ';': r'\;',
    '\\': r'\\',
})


def escape_server_options(in_str: str) -> str:
    """Escape keys and values used in TOR_PT_SERVER_TRANSPORT_OPTIONS.

    pt-spec Section 3.2.3:
    Colons, semicolons, and backslashes MUST be
    escaped with a backslash.

    It's weird that equal signs are not required to be escaped, but I'm
    going to follow the specs to the letter here.
    """
    return in_str.translate(SERVER_OPTS_TRANS_TABLE)


RE_UNESCAPED_COMMA = re.compile(r'(?<!\\),')
RE_UNESCAPED_EQUAL = re.compile(r'(?<!\\)=')


def parse_smethod_args(in_str: str) -> Dict[str, str]:
    """Parse an SMETHOD options ARGS: line into a dict.

    pt-spec Section 3.3.3:

    The currently recognized 'options' are:

    ARGS:[<Key>=<Value>,]+[<Key>=<Value>]

    The "ARGS" option is used to pass additional key/value
    formatted information that clients will require to use
    the reverse proxy.

    Equal signs and commas MUST be escaped with a backslash.

    Note: it's weird that backslashes themselves are not escaped.

    Args:
        in_str: the ARGS line, excluding the "ARGS:" header.

    Returns:
         A dict in the form {key1: value1, key2: value2}.
    """
    return dict(RE_UNESCAPED_EQUAL.split(p)
                for p in RE_UNESCAPED_COMMA.split(in_str))


def parse_hostport(hostport: str) -> Tuple[str, int]:
    """Parse a string "host:port" into separate host and port.

    Host can be an IPv4 address, IPv6 address (enclosed in square brackets)
    or host name. Port is required to be present.
    """
    # urlsplit insists that absolute URLs start with "//"
    split_result = urllib.parse.urlsplit('//' + hostport)
    if split_result.port is None:
        raise ValueError('Missing port')
    return split_result.hostname, split_result.port


def join_hostport(
        host: Union[str, ipaddress.IPv4Address, ipaddress.IPv6Address],
        port: int,
) -> str:
    """Combine host and port into a string of the form host:port."""
    try:
        host = ipaddress.ip_address(host)
    except ValueError:
        return f'{host}:{port:d}'
    else:
        if host.version == 6:
            return f'[{host.compressed}]:{port:d}'
        else:
            return f'{host.compressed}:{port:d}'

