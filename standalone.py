#!/usr/bin/env python3

"""Client end of a pluggable transport tunnel.

This script takes a pluggable transport binary and run it as a standalone
client, accepting plaintext traffic, scrambles it and forwards obfuscated
traffic."""

import logging
import argparse
import configparser
import signal, sys
import asyncio

import ptadapter

def main_cli():
    parser = argparse.ArgumentParser(description='Run a Tor pluggable '
              'transport as standalone server or client.')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--server', '-S', action='store_true', help='Run as the '
            'server end of a tunnel. Does not support --access-log yet.')
    group.add_argument('--client', '-C', action='store_true', help='Run as the '
            'client end of a tunnel.')
    parser.add_argument('configfile', type=argparse.FileType('r'), help=
            'Configuration file. See the example config file for details.')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--verbose', '-v', action='count', help='Increase ' 
            'verbosity level. Specify once to see logging.INFO, twice to see '
            'logging.DEBUG. Cannot be used with --quiet.')
    group.add_argument('--quiet', '-q', action='store_true', help='Suppress '
            'all logger output to STDERR. Cannot be used with --verbose.')
    parser.add_argument('--access-log', '-l', help='Save access log to the '
            'specified file.')
    
    args = parser.parse_args()
    
    # Logging
    if args.verbose is None:
        root_loglevel = logging.WARNING
    elif args.verbose == 1:
        root_loglevel = logging.INFO
    else:
        root_loglevel = logging.DEBUG
    logger = logging.getLogger()
    logger.setLevel(root_loglevel)
    
    if not args.quiet:
        logconsole = logging.StreamHandler()
        #logconsoleformatter = logging.Formatter('[%(asctime)s] %(name)-6s '
        #        '%(levelname)-8s %(message)s')
        logconsoleformatter = logging.Formatter('[%(asctime)s] %(name)s '
                '%(levelname)s %(message)s')
        logconsole.setFormatter(logconsoleformatter)
        logconsole.setLevel(root_loglevel)
    else:
        logconsole = logging.NullHandler()
    logger.addHandler(logconsole)
    
    if args.access_log is not None:
        access_log_handler = logging.FileHandler(args.access_log)
        access_log_formatter = logging.Formatter('%(asctime)s %(message)s')
        access_log_handler.setFormatter(access_log_formatter)
        access_log_handler.setLevel(logging.WARNING)
        access_logger = logging.getLogger('ptadapter.access')
        access_logger.addHandler(access_log_handler)
    
    logger.debug('Logging options set')
    logger.debug('Arguments:')
    logger.debug(args)
    
    # Read config file
    config = configparser.ConfigParser(empty_lines_in_values=False)
    config.read_file(args.configfile)
    args.configfile.close()
    
    logger.info('Read config file')
    
    loop = ptadapter.get_event_loop()
    asyncio.set_event_loop(loop)
    
    if args.client:
        pt = get_client(config, loop)
    else:
        pt = get_server(config, loop)
    
    pt.start()
    
    ptadapter.windows_async_signal_helper(loop)
    
    # Wait until PT terminates, or terminate on Ctrl+C / SIGTERM
    try:
        signal.signal(signal.SIGTERM, sigterm_handler)
        pt.wait()
        logger.warning('PT exited unexpectedly')
    except (KeyboardInterrupt, SystemExit) as e:
        logger.info('Received {}'.format(repr(e)))
        pt.stop()
        loop.run_forever()
    finally:
        logger.info('Terminating')
        loop.close()

def get_client(config, loop):
    # Build client configuration
    ptexec = config['common']['exec']
    statedir = config['common']['statedir']
    if config.has_option('common', 'upstream-proxy'):
        upstream_proxy = config['common']['upstream-proxy']
    else:
        upstream_proxy = None
    
    transports = {}
    for s, t in config.items('transports'):
        tr = {
            'listen_host': config[s]['listen-addr'],
            'listen_port': int(config[s]['listen-port']),
            'remote_host': config[s]['server-addr'],
            'remote_port': int(config[s]['server-port'])
            }
        opt = {o[8:]:v for (o,v) in config.items(s) if o.startswith('options-')}
        if opt: tr['options'] = opt
        
        if not t in transports:
            transports[t] = {}
        transports[t][s] = tr
    
    return ptadapter.PTClientListeningAdapter(loop, ptexec, statedir, 
                                              transports, upstream_proxy)

def get_server(config, loop):
    # Build server configuration
    ptexec = config["common"]["exec"]
    statedir = config["common"]["statedir"]
    orport = config["common"]["forward"]
    
    transports = {}
    for t, b in config.items("transports"):
        transports[t] = {"bindaddr": b}
        if config.has_section(t + "-options"):
            transports[t]["options"] = dict(config.items(t + "-options"))
    
    return ptadapter.PTServerAdapter(loop, ptexec, statedir, orport, transports)
    
def sigterm_handler(signal, frame):
    sys.exit(0)

if __name__ == '__main__':
    main_cli()
