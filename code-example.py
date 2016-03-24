#! usr/bin/env python3

'''This is example showcasing how to implement both sides of a pluggable 
transport tunnel, without using an external SOCKS reverse proxy.

To test the setup, make a directory ./state and ensure it's writable, put a 
binary of obfs4proxy in the current directory and run:

$ code-example.py config-example.json

Listen on TCP port 7000 (with netcat, socat, etc.) and connect to 
localhost:8000/8001/8002, and you should be able to talk through the tunnel.'''

import logging
import argparse
import json
import threading

from rsocks.pool import ServerPool
from rsocks.server import ReverseProxyServer

from pluggabletransportadapter import PluggableTransportServerAdapter, PluggableTransportClientSOCKSAdapter

class PluggableTransportClientTCPAdapter(PluggableTransportClientSOCKSAdapter):
    '''Adapter for pluggable transport running as "complete" client.
    
    Listens for TCP connections on user-specified address:port, connect to 
    destination address:port, and forwards obfuscated traffic.'''
    
    def __init__(self, ptexec, statedir, transports, upstream_proxy=None):
        '''Initialize class.
        
        Arguments:
        ptexec: either string or sequence of of the pluggable transport
            executable. This is passed directly to Popen(), so check its
            documentation for details.
        statedir: string "TOR_PT_STATE_LOCATION". From pt-spec:
            A filesystem directory path where the
            PT is allowed to store permanent state if required. This
            directory is not required to exist, but the proxy SHOULD be able
            to create it if it does not.
        transports: a dictionary of transports to support. Example:
            {
                "trebuchet":[
                    {
                        "listenaddr": ("127.0.0.1", 2012),
                        "remoteaddr": ("192.168.0.1", 1984),
                        "options":{
                            "rocks": "20",
                            "height": "5.6m"
                        }
                    }
                    {
                        "listenaddr": ("127.0.0.1", 2013),
                        "remoteaddr": ("192.168.100.101", 1984),
                        "options":{
                            "rocks": "10",
                            "height": "2.8m"
                        }
                    }
                ],
                "ballista":[
                    {
                        "listenaddr": ("127.0.0.1", 2014)
                        "remoteaddr": ("192.168.0.1", 4891)
                    }
                ]
            }
            transports[] should contain one or more keys corresponding to the 
            transports supported by the PT executable.
            transports["transport-name"] is a list of dictionaries, where each
            dictionary is a connection to be relayed with that transport.
            transports["transport-name"][i]["listenaddr"] and ["remoteaddr"]
            are tuples of (str address, int port). "listenaddr" is where to
            listen for incoming plaintext TCP traffic, and "remoteaddr" is
            where to forward obfuscated traffic.
            transports["transport-name"][i]['options'] is an (optional)
            dictionary of <k>=<v> options to be passed to PT. <k> and <v>
            should be strings. Semicolons and backslashes MUST be escaped with
            a backslash.
        upstream_proxy: string indicating the upstream proxy PT must use.
            Format: <proxy_type>://[<user_name>][:<password>][@]<ip>:<port>
            Example: socks5://tor:test1234@198.51.100.1:8000
                     socks4a://198.51.100.2:8001
        '''
        
        super().__init__(ptexec, statedir, transports, upstream_proxy)
        
        for t, o in transports.items():
            self.transports[t]["listeners"] = []
            for a in o:
                listener = {"listenaddr":a["listenaddr"],
                            "remoteaddr":a["remoteaddr"]}
                if "options" in a:
                    listener["options"] = a["options"]
                self.transports[t]["listeners"].append(listener)
    
    def start(self):
        '''Start the pluggable transport client.
        
        Once complete, PT executable should be listening for SOCKS4/5 requests,
        and rsocks should set up for listening to plaintext TCP traffic and
        relaying to PT. However, you still need to call self.rsocksloop() 
        (which is blocking) to actually relay traffic!'''
        
        super().start()
        
        self.rsockspool = ServerPool()
        
        for t, o in self.transports.items():
            if not o["ready"]: 
                continue
            
            i = 0
            ptproxy = "{}://{}".format(o["protocol"], o["bindaddr"])
            for a in o["listeners"]:
                i += 1
                with self.rsockspool.new_server(
                        name = "{}:{}".format(t, i),
                        server_class = ReverseProxyServer,
                        upstream = a["remoteaddr"]) as server:
                    server.set_proxy(ptproxy)
                    # This is pretty ugly, but I haven't found another way to
                    # unset timeout for rsocks.
                    server.proxy_timeout = None
                    if "options" in a:
                        listeneroptions = ";".join(
                                ("=".join(s) for s in a["options"].items()))
                        # rsocks uses urllib.parse.urlparse() to extract
                        # username and passwords from proxy address. It doesn't
                        # work if username/password contains "/".
                        server.proxy_server["username"] = listeneroptions[:1]
                        server.proxy_server["password"] = listeneroptions[1:]
                    server.listen(a["listenaddr"])
    
    def rsocksloop(self):
        '''Run rsocks's server loop so it actually relays TCP traffic to PT.
        
        This function blocks.'''
        
        self.rsockspool.loop()
        


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