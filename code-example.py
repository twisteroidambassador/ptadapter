#! usr/bin/env python3

import logging
import argparse
import json
import threading

from pluggabletransportadapter import PluggableTransportServerAdapter, PluggableTransportClientTCPAdapter

def main_cli():
    
    def server_thread(config):
        logger = logging.getLogger("")
        s = PluggableTransportServerAdapter(**config)
        s.start()
        logger.debug("Available transports:")
        logger.debug(s.transports)
        s.wait()
    
    def client_thread(config):
        logger = logging.getLogger("")
        c = PluggableTransportClientTCPAdapter(**config)
        c.start()
        logger.debug("Available transports:")
        logger.debug(c.transports)
        c.rsocksloop()
    
    parser = argparse.ArgumentParser(description="Run a Tor pluggable "
            "transport (PT) as a standalone TCP tunnel.",
            epilog="If no -S, -s, -C or -c "
            "arguments are specified, all servers and clients present in the "
            "config file are enabled.")
    
    parser.add_argument("configfile", type=argparse.FileType("r"), help=
            "Configuration file. See the example config file for details.")
    parser.add_argument("-v", "--verbose", action="store_true", help=
            "Set log level to DEBUG.")
    parser.add_argument("-s", "--server", action="append", help=
            "Server PTs to enable.")
    parser.add_argument("-S", "--all-servers", action="store_true", help=
            "Enable all server PTs.")
    parser.add_argument("-c", "--client", action="append", help=
            "Client PTs to enable.")
    parser.add_argument("-C", "--all-clients", action="store_true", help=
            "Enable all client PTs.")
    
    args = parser.parse_args()
    
    logconsole = logging.StreamHandler()
    logconsoleformatter = logging.Formatter('[%(asctime)s] %(threadName)-10s '
            '%(name)-3s %(levelname)-8s %(message)s',
            '%H:%M:%S')
    #('%(threadName)s %(levelname)s: %(message)s')
    logconsole.setFormatter(logconsoleformatter)
    if args.verbose:
        logconsole.setLevel(logging.DEBUG)
    else:
        logconsole.setLevel(logging.INFO)
    
    logger = logging.getLogger("")
    logger.setLevel(logging.DEBUG)
    logger.addHandler(logconsole)
    
    #ptlogger = logging.getLogger("pluggabletransportadapter")
    #ptlogger.setLevel(logging.DEBUG)
    #ptlogger.addHandler(logconsole)
    
    # Suppress rsocks's logger
    rsockslogger = logging.getLogger("rsocks")
    rsockslogger.addHandler(logging.NullHandler())
    
    logger.debug("Verbosity level set")
    
    logger.debug("Arguments:")
    logger.debug(args)
    
    config = json.load(args.configfile)
    args.configfile.close()
    
    logger.debug("Config:")
    logger.debug(config)
    
    if args.server is None:
        args.server = []
    if args.client is None:
        args.client = []
    
    if args.all_servers or args.all_clients or args.server or args.client:
        if not args.all_servers:
            config["servers"] = {k:config["servers"][k] for k in args.server}
        if not args.all_clients:
            config["clients"] = {k:config["clients"][k] for k in args.client}
    
    # TypeError: getsockaddrarg: AF_INET address must be tuple, not list
    for c, r in config["clients"].items():
        for t, v in r["transports"].items():
            for a in v:
                a["listenaddr"] = tuple(a["listenaddr"])
                a["remoteaddr"] = tuple(a["remoteaddr"])
    
    logger.debug("Pruned config:")
    logger.debug(config)
    logger.info("{} server and {} client executable(s) enabled".format(
            len(config["servers"]), len(config["clients"])))
    
    threadlist = []
    for s, r in config["servers"].items():
        t = threading.Thread(target=server_thread, args=(r,),
                name="S-"+s, daemon=True)
        t.start()
        threadlist.append(t)
    for c, r in config["clients"].items():
        t = threading.Thread(target=client_thread, args=(r,),
                name="C-"+c, daemon=True)
        t.start()
        threadlist.append(t)
    
    try:
        for t in threadlist:
            t.join()
    except (KeyboardInterrupt, SystemExit) as e:
        logger.info("Main thread received {}".format(repr(e)))
    finally:
        logger.info("Main thread finished")
    
if __name__ == "__main__":
    main_cli()