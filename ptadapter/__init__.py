"""Python interface for Pluggable Transports

The main module exports the adapter classes, as well as several Named Tuple
classes used as return values of adapter class methods.
"""

from .adapters import *

__all__ = adapters.__all__

__version__ = '3.0.0rc1'
# Note: since ptadapter does not have any 3rd-party dependencies,
# it should be safe for setup.py to import this.
