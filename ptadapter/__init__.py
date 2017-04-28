"""Implements Tor's "managed proxy protocol".

This package implements classes used to run a Tor Pluggable Transport
as server or client. The primary goal is to run Pluggable Transports
as standalone TCP tunnels.

For more information on the managed proxy protocol, see Tor's official
implementation of Pluggable Transport interface:
https://gitweb.torproject.org/pluggable-transports/goptlib.git/tree/
https://godoc.org/git.torproject.org/pluggable-transports/goptlib.git
and any torspec documents linked from the above documentations.
"""

from .adapters import *
from .helpers import *
from .exceptions import *

__all__ = adapters.__all__ + helpers.__all__ + exceptions.__all__
