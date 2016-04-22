#!/usr/bin/env python3

'''Standalone client for obfs4proxy and other pluggable transports.

This script takes a pluggable transport binary and run it as a standalone
client, accepting plaintext traffic, scrambles it and forwards obfuscated
traffic.'''

import logging
import argparse
import configparser
#import threading

from pluggabletransportadapter import PluggableTransportClientTCPAdapter

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
    
    logger.info("Read config file")
    
    # Suppress rsocks's logger
    #rsockslogger = logging.getLogger("rsocks")
    #rsockslogger.addHandler(logging.NullHandler())
    
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
            "listenaddr": (config[s]["listen-addr"], int(config[s]["listen-port"])),
            "remoteaddr": (config[s]["server-addr"], int(config[s]["server-port"]))
            }
        opt = {o[8:]:v for (o,v) in config.items(s) if o[:8] == "options-"}
        if opt: tr["options"] = opt
        
        if not t in transports:
            transports[t] = []
        transports[t].append(tr)
    
    logger.debug("Transports:")
    logger.debug(transports)
    
    # Start PT executable
    client = PluggableTransportClientTCPAdapter(ptexec, statedir, transports, upstream_proxy)
    client.start()
    logger.debug("Available transports:")
    logger.debug(client.transports)
    #client.loop.run_forever()
    
    # Start rsocks server loop
    #t = threading.Thread(target = client.rsocksloop, daemon=True)
    #t.start()
    
    # Wait until PT terminates, or terminate on Ctrl+C / SIGTERM
    try:
        client.wait()
    except (KeyboardInterrupt, SystemExit) as e:
        logger.info("Received {}".format(repr(e)))
    finally:
        logger.info("Terminating")
        client.terminate()
    

if __name__ == "__main__":
    main_cli()
