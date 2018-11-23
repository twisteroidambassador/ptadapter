"""Exceptions raised by this package.

Two Enums used in these exceptions are also imported in this module for
convenience.
"""

from .enums import SOCKS5Reply, SOCKS4Reply

__all__ = [
    'PTConnectError',
    'PTSOCKS5ConnectError',
    'PTSOCKS4ConnectError',
    'SOCKS5Reply',
    'SOCKS4Reply',
]


class PTConnectError(ConnectionError):
    """Error while PT tries to connect to destination.

    This is the base class of some other connection errors.
    To make catching connectivity-related exceptions easier, this inherits
    from the built-in :class:`ConnectionError`.
    """
    pass


class PTSOCKS5ConnectError(PTConnectError):
    """Error reported by client PT using SOCKS5 connecting to destination.

    The *args* of this exception contains the reason of failure returned
    by the PT, as an instance of :class:`ptadapter.socks.SOCKS5Reply`.
    This may or may not be useful; do not be surprised if PTs only ever
    return GENERAL_FAILURE.
    """
    pass


class PTSOCKS4ConnectError(PTConnectError):
    """Error reported by client PT using SOCKS4 connecting to destination.

    The *args* of this exception contains the reason of failure returned
    by the PT, as an instance of :class:`ptadapter.socks.SOCKS4Reply`.
    This is likely to be even less useful than a SOCKS5 reply, since the
    specific errors are all related to ``identd``, which we are not using.
    """
    pass
