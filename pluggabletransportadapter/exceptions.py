"""Exceptions raised by the package."""

__all__ = ['Error', 'PTExecError', 'PTExecSMethodError', 'PTExecCMethodError',
           'ProxyError', 'ProxyConfigError', 'ProxyNegotiationError']

class Error(Exception):
    """Base exception for this package."""
    pass

class PTExecError(Error, RuntimeError):
    """Runtime Errors related to the PT executable."""
    pass

class PTExecSMethodError(PTExecError):
    """PT SMETHOD-ERROR messages."""
    pass

class PTExecCMethodError(PTExecError):
    """PT CMETHOD-ERROR messages."""
    pass

class ProxyError(Error):
    """Errors related to proxies."""
    pass
    
class ProxyConfigError(ProxyError, ValueError):
    """Configuration errors with a proxy."""
    pass

class ProxyNegotiationError(ProxyError, RuntimeError):
    """Errors during proxy negotiation."""
    pass