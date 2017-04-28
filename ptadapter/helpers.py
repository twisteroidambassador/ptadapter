import asyncio
import sys

__all__ = ['get_event_loop', 'new_event_loop', 'windows_async_signal_helper']


def get_event_loop():
    """Return an appropriate event loop.
    
    On Windows, only ProactorEventLoop support subprocess pipes, so if 
    the current loop is not a ProactorEventLoop, a new one is created 
    and returned. 
    """
    loop = asyncio.get_event_loop()
    if (sys.platform == 'win32' and 
            not isinstance(loop, asyncio.ProactorEventLoop)):
        loop = asyncio.ProactorEventLoop()
    return loop


def new_event_loop():
    """Create an appropriate event loop.
    
    On Windows, create a new ProactorEventLoop since only 
    ProactorEventLoop support subprocess pipes.
    """
    if sys.platform != 'win32':
        return asyncio.new_event_loop()
    else:
        return asyncio.ProactorEventLoop()


def windows_async_signal_helper(loop, interval=0.2):
    """Schedule a do-nothing regular callback on Windows only.
    
    This is a workaround for Python Issue 23057 in Windows 
    ( https://bugs.python.org/issue23057 ), where signals like 
    KeyboardInterrupt will not be delivered in an event loop if nothing 
    is happening. A regular callback allows such signals to be 
    delivered. 
    """
    
    if sys.platform == 'win32':
        noop_callback(loop, interval)


def noop_callback(loop, delay):
    """Do nothing and schedule to do nothing later."""
    
    loop.call_later(delay, noop_callback, loop, delay)