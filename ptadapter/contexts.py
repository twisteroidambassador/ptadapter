import asyncio
import contextlib
import logging

from . import log


logger = log.pkg_logger.getChild('context')


@contextlib.asynccontextmanager
async def aclosing_multiple_writers(*writers: asyncio.StreamWriter):
    """Closes StreamWriters on clean exits, aborts them on exceptions.

    The "as" clause returns a set, and more StreamWriters can be added to the
    set.
    """
    writers = set(writers)
    try:
        yield writers
    except:
        for w in writers:
            w.transport.abort()
        raise
    else:
        for w in writers:
            w.close()
    finally:
        close_tasks, _ = await asyncio.wait([w.wait_closed() for w in writers])
        for t in close_tasks:
            if t.exception():
                logger.debug(
                    'wait_closed() raised exception: %r', t.exception())


@contextlib.asynccontextmanager
async def log_unhandled_exc(logger: logging.Logger):
    """Log and suppress any unhandled exception.

    This can be used as the outermost layer of a handler, so that unhandled
    errors are logged explicitly, instead of being left to the "Task exception
    was never retrieved" handler.
    """
    try:
        yield
    except asyncio.CancelledError:
        raise
    except Exception:
        logger.error('Unexpected error', exc_info=True)
