#!/usr/bin/env python3

'''Standalone server for obfs4proxy and other pluggable transports.

This script takes a pluggable transport binary and run it as a standalone
server, accepting obfuscated traffic, decodes it and forwards plaintext
traffic.'''

import logging
import argparse
import configparser
import signal, sys
import asyncio

import pluggabletransportadapter
#from pluggabletransportadapter import PTServerAdapter


def main_cli():
    # Argument Parsing
    parser = argparse.ArgumentParser(description="Run a Tor pluggable "
              "transport as standalone server.")
    
    parser.add_argument("configfile", type=argparse.FileType("r"), help=
            "Configuration file. See the example config file for details.")
    parser.add_argument("--verbose", "-v", action="count", help="Increase " 
        "verbosity level. Specify once to see logging.INFO, twice to see "
        "logging.DEBUG.")
    
    args = parser.parse_args()
    
    # Logging
    logger = logging.getLogger("")
    logger.setLevel(logging.DEBUG)
    
    logconsole = logging.StreamHandler()
    logconsoleformatter = logging.Formatter('[%(asctime)s] %(name)-6s '
            '%(levelname)-8s %(message)s')
    logconsole.setFormatter(logconsoleformatter)
    if args.verbose is None:
        logconsole.setLevel(logging.WARNING)
    elif args.verbose == 1:
        logconsole.setLevel(logging.INFO)
    else:
        logconsole.setLevel(logging.DEBUG)

    logger.addHandler(logconsole)
    
    logger.debug("Verbosity level set")
    logger.debug("Arguments:")
    logger.debug(args)
    
    # Read config file
    config = configparser.ConfigParser(empty_lines_in_values=False)
    config.read_file(args.configfile)
    args.configfile.close()
    
    logger.debug("Config file loaded")
    
    ptexec = config["common"]["exec"]
    statedir = config["common"]["statedir"]
    orport = config["common"]["forward"]
    
    # Build server config
    transports = {}
    for t, b in config.items("transports"):
        transports[t] = {"bindaddr": b}
        if config.has_section(t + "-options"):
            transports[t]["options"] = dict(config.items(t + "-options"))
    
    logger.debug("Transports:")
    logger.debug(transports)
    
    # Start PT
    loop = pluggabletransportadapter.get_event_loop()
    asyncio.set_event_loop(loop)
    server = pluggabletransportadapter.PTServerAdapter(loop, ptexec, statedir, orport, transports)
    #loop.set_debug(True)
    
    server.start()
    
    pluggabletransportadapter.windows_async_signal_helper(loop)
    
    # Wait until PT terminates, or terminate on Ctrl+C / SIGTERM
    try:
        signal.signal(signal.SIGTERM, sigterm_handler)
        server.wait()
        logger.warning('PT exited unexpectedly')
    except (KeyboardInterrupt, SystemExit) as e:
        logger.info("%s was raised", repr(e))
        logger.debug('server.stop()')
        server.stop()
        loop.run_forever() # Event loop will stop anyways when server run_task is complete
    finally:
        #loop.run_until_complete(server.run_task)
        logger.info("server script terminated")
        loop.close()
    
    
def sigterm_handler(signal, frame):
    logger.info('Received %s', signal)
    sys.exit(0)

if __name__ == "__main__":
    main_cli()
