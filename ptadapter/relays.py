import asyncio

from . import contexts
from . import log

BUF_SIZE = 2**13

_logger = log.pkg_logger.getChild('relay')


async def _relay_data_side(
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
) -> None:
    """Pass data and EOF from reader to writer."""
    while True:
        buf = await reader.read(BUF_SIZE)
        if not buf:  # EOF
            break
        writer.write(buf)
        await writer.drain()
    writer.write_eof()
    await writer.drain()


async def relay(
        dreader: asyncio.StreamReader,
        dwriter: asyncio.StreamWriter,
        ureader: asyncio.StreamReader,
        uwriter: asyncio.StreamWriter,
) -> None:
    """Pass data/EOF from dreader to uwriter, and ureader to dwriter.

    Both writers are ensured to be closed upon exiting this function.
    """
    _logger.debug(
        'Relaying %r <=> %r', dwriter.get_extra_info('peername'),
        uwriter.get_extra_info('peername'))
    utask = asyncio.create_task(_relay_data_side(dreader, uwriter))
    dtask = asyncio.create_task(_relay_data_side(ureader, dwriter))
    async with contexts.aclosing_multiple_writers(dwriter, uwriter):
        try:
            await asyncio.gather(utask, dtask)
            _logger.debug(
                'Relay %r <=> %r ended normally',
                dwriter.get_extra_info('peername'),
                uwriter.get_extra_info('peername'))
        except:
            dtask.cancel()
            utask.cancel()
            raise
        finally:
            await asyncio.wait({dtask, utask})
            for t in (dtask, utask):
                if t.exception():
                    _logger.debug(
                        'Relay task %r caught exception %r', t, t.exception())
