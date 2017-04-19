#!/usr/bin/env python3

'''Standalone client for obfs4proxy and other pluggable transports.

This script takes a pluggable transport binary and run it as a standalone
client, accepting plaintext traffic, scrambles it and forwards obfuscated
traffic.'''

import logging
import argparse
import configparser
import signal, sys
import asyncio

import pluggabletransportadapter
#from pluggabletransportadapter import PluggableTransportClientTCPAdapter

def main_cli():
    # Argument Parsing
    parser = argparse.ArgumentParser(description="Run a Tor pluggable "
              "transport as standalone client.")
    
    parser.add_argument("configfile", type=argparse.FileType("r"), help=
            "Configuration file. See the example config file for details.")
    parser.add_argument("--verbose", "-v", action="count", help="Increase " 
        "verbosity level. Specify once to see logging.INFO, twice to see "
        "logging.DEBUG.")
    
    args = parser.parse_args()
    
    # Logging
    logger = logging.getLogger()
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
    
    logger.info("Read config file")
    
    # Build client configuration
    ptexec = config["common"]["exec"]
    statedir = config["common"]["statedir"]
    if config.has_option("common", "upstream-proxy"):
        upstream_proxy = config["common"]["upstream-proxy"]
    else:
        upstream_proxy = None
    
    transports = {}
    for s, t in config.items("transports"):
        tr = {
            "listen_host": config[s]["listen-addr"],
            "listen_port": int(config[s]["listen-port"]),
            "remote_host": config[s]["server-addr"],
            "remote_port": int(config[s]["server-port"])
            }
        opt = {o[8:]:v for (o,v) in config.items(s) if o[:8] == "options-"}
        if opt: tr["options"] = opt
        
        if not t in transports:
            transports[t] = {}
        transports[t][s] = tr
    
    logger.debug("Transports:")
    logger.debug(transports)
    
    # Start PT executable
    loop = pluggabletransportadapter.get_event_loop()
    asyncio.set_event_loop(loop)
    client = pluggabletransportadapter.PTClientListeningAdapter(loop, ptexec, statedir, transports, upstream_proxy)
    client.start()
    
    pluggabletransportadapter.windows_async_signal_helper(loop)
    
    # Wait until PT terminates, or terminate on Ctrl+C / SIGTERM
    try:
        signal.signal(signal.SIGTERM, sigterm_handler)
        client.wait()
        logger.warning('PT exited unexpectedly')
    except (KeyboardInterrupt, SystemExit) as e:
        logger.info("Received {}".format(repr(e)))
        client.stop()
        loop.run_forever()
    finally:
        logger.info("Terminating")
        loop.close()
        
    
def sigterm_handler(signal, frame):
    sys.exit(0)

if __name__ == "__main__":
    main_cli()
