import argparse
import asyncio
import configparser
import contextlib
import functools
import logging
import shlex
import sys
from typing import Dict, List, Optional, Tuple

from . import adapters
from . import str_utils
from . import relays
from . import exceptions
from . import contexts

WINDOWS = (sys.platform == 'win32')

rootlogger = logging.getLogger()
handler_logger = logging.getLogger('handler')


def win_CommandLineToArgvW(cmd):
    """Use a Windows API to turn a command line string into list of parts.

    Taken from https://stackoverflow.com/a/35900070/4472899
    """
    import ctypes
    nargs = ctypes.c_int()
    ctypes.windll.shell32.CommandLineToArgvW.restype = ctypes.POINTER(
        ctypes.c_wchar_p)
    lpargs = ctypes.windll.shell32.CommandLineToArgvW(cmd, ctypes.byref(nargs))
    args = [lpargs[i] for i in range(nargs.value)]
    if ctypes.windll.kernel32.LocalFree(lpargs):
        raise AssertionError
    return args


async def handle_client_connection(
        adapter: adapters.ClientAdapter,
        transport: str,
        upstream_host: str,
        upstream_port: int,
        args: Dict[str, str],
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
) -> None:
    handler_logger.debug(
        'Accepted connection for transport %s from %r on %r',
        transport,
        writer.get_extra_info('peername'), writer.get_extra_info('sockname'))
    async with contexts.log_unhandled_exc(handler_logger), \
               contexts.aclosing_multiple_writers(writer) as writers:
        try:
            ureader, uwriter = await adapter.open_transport_connection(
                transport, upstream_host, upstream_port, args)
        except exceptions.PTConnectError as e:
            handler_logger.warning(
                'PT reported error while connecting to upstream '
                '(%r, %r): %r', upstream_host, upstream_port, e)
            writer.transport.abort()
            return
        writers.add(uwriter)
        logname = (f'{writer.get_extra_info("peername")!r} ==> '
                   f'({upstream_host!r}, {upstream_port})')
        handler_logger.info('[%s] %s', transport, logname)
        try:
            await relays.relay(reader, writer, ureader, uwriter)
        except OSError as e:
            handler_logger.warning(
                '[%s] %s caught %r', transport, logname, e)


async def handle_ext_server_connection(
        upstream_host: str,
        upstream_port: int,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        info: adapters.ExtOrPortClientConnection,
) -> None:
    handler_logger.info('Connection received from %r', info)
    async with contexts.log_unhandled_exc(handler_logger), \
               contexts.aclosing_multiple_writers(writer) as writers:
        try:
            ureader, uwriter = await asyncio.open_connection(
                upstream_host, upstream_port)
        except OSError as e:
            handler_logger.warning(
                'Error while connecting to upstream: %r', e)
            return
        writers.add(writer)
        try:
            await relays.relay(reader, writer, ureader, uwriter)
        except OSError as e:
            handler_logger.warning('Connection from %r caught %r', info, e)


def get_common_options_from_section(
        section,
) -> Tuple[List[str], Optional[str], List[str]]:
    pt_exec = section['exec']
    if WINDOWS:
        pt_exec = win_CommandLineToArgvW(pt_exec)
    else:
        pt_exec = shlex.split(pt_exec)
    state = section.get('state', None)
    if not state:  # Take care of empty values
        state = None
    tunnels = section['tunnels'].split()
    return pt_exec, state, tunnels


async def run_client(conf: configparser.ConfigParser) -> None:
    pt_exec, state, tunnels = get_common_options_from_section(conf['client'])
    proxy = conf['client'].get('proxy', None)
    if not proxy:
        proxy = None
    transports = set()
    handler_confs = []

    for t in tunnels:
        section = conf[t]
        transport = section['transport']
        listen_host, listen_port = str_utils.parse_hostport(section['listen'])
        upstream_host, upstream_port = str_utils.parse_hostport(
            section['upstream'])
        args = {key[8:]: value
                for key, value in section.items()
                if key.startswith('options-')}
        transports.add(transport)
        handler_confs.append((
            (listen_host, listen_port),
            (transport, upstream_host, upstream_port, args),
        ))

    adapter = adapters.ClientAdapter(
        pt_exec, state, list(transports), proxy)

    async with contextlib.AsyncExitStack() as stack:
        await stack.enter_async_context(adapter)
        for listen_args, handler_args in handler_confs:
            handler = functools.partial(
                handle_client_connection, adapter, *handler_args)
            server = await asyncio.start_server(handler, *listen_args)
            await stack.enter_async_context(server)

        await adapter.wait()
        raise RuntimeError('PT process exited unexpectedly')


async def run_server(
        conf: configparser.ConfigParser,
        use_extorport: bool,
) -> None:
    pt_exec, state, tunnels = get_common_options_from_section(conf['server'])
    forward_host, forward_port = str_utils.parse_hostport(
        conf['server']['forward'])
    if use_extorport:
        adapter = adapters.ExtServerAdapter(
            pt_exec, state,
            functools.partial(
                handle_ext_server_connection, forward_host, forward_port),
        )
    else:
        adapter = adapters.ServerAdapter(
            pt_exec, state, forward_host, forward_port)

    for t in tunnels:
        section = conf[t]
        transport = section['transport']
        listen_host, listen_port = str_utils.parse_hostport(section['listen'])
        options = {key[8:]: value
                   for key, value in section.items()
                   if key.startswith('options-')}
        adapter.add_transport(transport, listen_host, listen_port, options)

    async with adapter:
        await adapter.wait()
        raise RuntimeError('PT process exited unexpectedly')


async def amain():
    if WINDOWS:
        loop: asyncio.AbstractEventLoop = asyncio.get_running_loop()

        def noop_callback():
            loop.call_later(0.2, noop_callback)

        noop_callback()

    parser = argparse.ArgumentParser(
        description='''Run a Pluggable Transport as a standalone tunnel server
        or client.''',
        epilog='''Note: the logging output of this script may log client and
        server IP addresses. Do not use this script if such addresses may be
        sensitive.'''
    )

    role_group = parser.add_mutually_exclusive_group(required=True)
    role_group.add_argument(
        '-S', '--server', action='store_true',
        help='''Run as server end of tunnel. Since the PT directly forwards
        unobfuscated traffic upstream, no client information will be logged
        even if verbosity is turned up.'''
    )
    role_group.add_argument(
        '-E', '--ext-server', action='store_true',
        help='''Run as server end of tunnel using ExtOrPort. Compared with -S, 
        running ptadapter with this option allows client addresses and 
        transport names to be logged, but also increases connection
        overhead.'''
    )
    role_group.add_argument(
        '-C', '--client', action='store_true',
        help='''Run as client end of tunnel.'''
    )

    parser.add_argument(
        'configfile', type=argparse.FileType('rt'),
        help='''Configuration file.'''
    )
    parser.add_argument(
        '-v', '--verbose', action='count',
        help='''Increase verbosity level. Specify once to see INFO logs, twice
        to see DEBUG.'''
    )
    parser.add_argument(
        '-t', '--log-no-time', action='store_true',
        help='''Suppress timestamps in logging output.'''
    )

    args = parser.parse_args()

    if not args.verbose:
        loglevel = logging.WARNING
    elif args.verbose == 1:
        loglevel = logging.INFO
    else:
        loglevel = logging.DEBUG

    rootlogger.setLevel(loglevel)

    if args.log_no_time:
        formatter = logging.Formatter('%(levelname)-8s %(name)s %(message)s')
    else:
        formatter = logging.Formatter(
            '[%(asctime)s] %(levelname)-8s %(name)s %(message)s')
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    rootlogger.addHandler(stream_handler)

    rootlogger.debug('Command line arguments: %r', args)

    conf = configparser.ConfigParser(empty_lines_in_values=False)
    conf.read_file(args.configfile)
    args.configfile.close()
    rootlogger.debug('Read config file')

    if args.client:
        await run_client(conf)
    elif args.server:
        await run_server(conf, False)
    else:
        await run_server(conf, True)


def main():
    if WINDOWS:
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

    try:
        asyncio.run(amain())
    except (KeyboardInterrupt, SystemExit) as e:
        rootlogger.info('Received %r', e)
