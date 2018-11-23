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

__all__ = adapters.__all__

__version__ = '3.0.0b1'
# Note: since ptadapter does not have any 3rd-party dependencies,
# it should be safe for setup.py to import this.
