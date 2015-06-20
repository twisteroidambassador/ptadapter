'''This file implements Tor's "managed proxy protocol", used for communication
between Tor and pluggable transports. The aim is to make it easy to use 
the various pluggable transports, either as standalone tunnels or as parts of 
other projects.'''


import logging
import subprocess

from rsocks.pool import ServerPool
from rsocks.server import ReverseProxyServer

# imports specific to running as CLI script are inside main_cli()

class PluggableTransportBaseAdapter(object):
    '''Base class for pluggable transport adapters.'''
    
    def __init__(self, ptexec, statedir):
        '''
        Arguments:
        ptexec: either string or sequence of of the pluggable transport
            executable. This is passed directly to Popen()'s 'args', so check its
            documentation for details.
        statedir: string "TOR_PT_STATE_LOCATION". From pt-spec:
            A filesystem directory path where the
            PT is allowed to store permanent state if required. This
            directory is not required to exist, but the proxy SHOULD be able
            to create it if it does not.'''
        
        self.ptexec = ptexec
        
        # environment variables for PT
        self.env = {"TOR_PT_MANAGED_TRANSPORT_VER": "1",
                    "TOR_PT_STATE_LOCATION": statedir}
        
        self.logger = logging.getLogger("pluggabletransportadapter")
    
    def run_ptexec(self):
        '''Run PT executable.
        
        Provides the appropriate enviroment variables.
        Stores the Popen object of the subprocess so its stdout can be read.'''
        
        self.p = subprocess.Popen(self.ptexec, stdout=subprocess.PIPE,
                                  env=self.env, universal_newlines=True)
    
    def terminate(self):
        '''Terminate the PT executable.
        
        The rest of the code isn't really written with stopping the server in
        mind; terminating the main process / thread should 
        bring down all child processes. But here it is anyways.'''
        
        try:
            if self.p.poll() is None:
                self.p.terminate()
        except NameError:
            # self.p does not exist
            pass
    
    def wait(self):
        '''Block until PT executable exits. Terminates PT executable on
        KeyboardInterrupt or SystemExit.
        
        This method is intended to be used to keep the process/thread alive 
        when it has nothing else to do.'''
        
        try:
            self.p.wait()
        except (KeyboardInterrupt, SystemExit):
            self.terminate()
    
    def _parse_stdout_common(self, line):
        '''Parse data coming from PT executable's stdout.
        
        This method takes care of the common messages that apply to both servers
        and clients, and returns False if the message is understood and True
        otherwise (so subclasses can continue to parse it).'''
        
        stillneedwork = False
        
        self.logger.debug("PT executable says: " + line)
        
        if line.startswith("ENV-ERROR"):
            self.logger.error("PT environment variable error, " 
                              "Error message: " + line[10:])
            # PT executable should terminate, not raising exception
        elif line.startswith("VERSION"):
            if line == "VERSION 1":
                self.logger.debug("Using protocol version 1 as expected")
            elif line.startswith("VERSION-ERROR"):
                self.logger.error("PT managed proxy protocol version error")
                # PT executable should terminate, not raising exception
        else:
            stillneedwork = True
        
        return stillneedwork
 
class PluggableTransportServerAdapter(PluggableTransportBaseAdapter):
    '''Adapter for pluggable transport running as server: accepts obfuscated
    TCP traffic and forwards plaintext traffic.'''
    
    def __init__(self, ptexec, statedir, orport, transports):
        '''
        ptexec: either string or sequence of of the pluggable transport
            executable. This is passed directly to Popen(), so check its
            documentation for details.
        statedir: string "TOR_PT_STATE_LOCATION". From pt-spec:
            A filesystem directory path where the
            PT is allowed to store permanent state if required. This
            directory is not required to exist, but the proxy SHOULD be able
            to create it if it does not.
        orport: string "TOR_PT_ORPORT". 
            The <address>:<port> of the ORPort of the
            bridge where the PT is supposed to send the deobfuscated
            traffic.
        transports: a dictionary of server transports to support. Example:
            {
                "trebuchet":{
                    "bindaddr": "127.0.0.1:1984",
                    "options":{
                        "rocks": "20",
                        "height": "5.6m"
                    }
                },
                "ballista":{
                    "bindaddr": "127.0.0.1:4891"
                }
            }
            transports[] should contain one or more keys corresponding to the 
            transports supported by the PT executable.
            transports["transport-name"]["bindaddr"] is the <address>:<port>
            where PT should listen for client connections.
            (optional) transports["transport-name"]["options"] is a dictionary 
            of <k>=<v> options to be passed to PT. <k> and <v> should all be 
            strings. Colons, semicolons, equal signs and backslashes MUST 
            already be escaped with a backslash: this code does not do any
            escaping!
        
        Examples of Tor server PT configuration that corresponds to above:
            ServerTransportPlugin trebuchet,ballista exec <ptexec>
            ServerTransportListenAddr trebuchet 127.0.0.1:1984
            ServerTransportListenAddr ballista 127.0.0.1:4891
            ServerTransportOptions trebuchet rocks=20 height=5.6m
        '''
        
        # Python 2 compatibility note: specify parameters for super()
        super().__init__(ptexec, statedir)
        self.env["TOR_PT_ORPORT"] = orport
        
        self.transports = {}
        
        transportlist = []
        optionlist = []
        bindaddrlist = []
        try:
            for t, o in transports.items():
                self.transports[t] = {"ready": False, "error": False}
                transportlist.append(t)
                bindaddrlist.append(t + "-" + o["bindaddr"])
                if "options" in o:
                    for k, v in o["options"].items():
                        optionlist.append("{}:{}={}".format(t, k, v))
        except KeyError:
            self.logger.error("Error while parsing PT server transports{}. "
                              "Did you include all required info?")
            raise
        
        self.env["TOR_PT_SERVER_TRANSPORTS"] = ",".join(transportlist)
        self.env["TOR_PT_SERVER_BINDADDR"] = ",".join(bindaddrlist)
        if any(optionlist):
            self.env["TOR_PT_SERVER_TRANSPORT_OPTIONS"] = ";".join(optionlist)
        
        self.logger.info("Environment variables prepared for server " + 
                         self.ptexec)
        self.logger.debug("Environment variables:")
        self.logger.debug(self.env)
    
    def start(self):
        '''Start the pluggable transport server.
        
        Once complete, PT executable should be listening for incoming 
        obfuscated TCP traffic on the requested bindaddr(s), and forwarding 
        plaintext TCP traffic to orport. self.transports reflects the status 
        and bound address/port of activated transports.'''
        
        self.run_ptexec()
        
        # Python 2 compatibility note: Python 2 gets stuck at the following 
        # loop, and presumably at corresponding location in Client*Adapters.
        # Not sure why. Rewriting loop with explicit readline() should help.
        for line in self.p.stdout:
            if self.parse_stdout(line.strip()): break
        else:
            # fell through the loop: PT executable terminated
            self.logger.error("PT executable terminated")
            return False
        
        for t, o in self.transports.items():
            if not o["ready"] and not o["error"]:
                # PT ignored this transport: not supported?
                self.logger.warning("PT ignored transport " + t)
        
        # The PT executable should not generate any more output, so closing or
        # not shouldn't make any difference
        self.p.stdout.close()
        
        return True
    
    def parse_stdout(self, line):
        '''Parse data coming from PT executable's stdout.
        
        This method parses common and server-specific messages. Returns True if
        a "SMETHOD DONE" message signalling completion is received, and False 
        otherwise.'''
        
        done = False
        
        if self._parse_stdout_common(line):
            if line.startswith("SMETHOD-ERROR"):
                e = line[14:].split(" ", 1)
                self.transports[e[0]]["error"] = True
                self.transports[e[0]]["errormessage"] = e[1]
                self.logger.error("PT server transport '{}' error, "
                                  "error message: {}".format(*e))
            elif line.startswith("SMETHODS DONE"):
                self.logger.info("PT server configuration complete")
                done = True
            elif line.startswith("SMETHOD "):
                e = line[8:].split(" ", 2)
                self.transports[e[0]]["ready"] = True
                self.transports[e[0]]["bindaddr"] = e[1]
                self.transports[e[0]]["options"] = e[2]
                self.logger.info("PT server transport '{}' configured, "
                                 "listening on {}".format(e[0], e[1]))
            else:
                self.logger.info("PT communication not understood\n" + line)
        
        return done

class PluggableTransportClientSOCKSAdapter(PluggableTransportBaseAdapter):
    '''Adapter for pluggable transport running as "bare" client: accepts SOCKS
    proxy requests (with destination address and parameters) and forwards
    obfuscated traffic.'''
    
    def __init__(self, ptexec, statedir, transports, upstream_proxy=None):
        '''
        ptexec: either string or sequence of of the pluggable transport
            executable. This is passed directly to Popen(), so check its
            documentation for details.
        statedir: string "TOR_PT_STATE_LOCATION". From pt-spec:
            A filesystem directory path where the
            PT is allowed to store permanent state if required. This
            directory is not required to exist, but the proxy SHOULD be able
            to create it if it does not.
        transports: either a list of transport names, or a dictionary
            where the keys are transport names.
        upstream_proxy: string indicating the upstream proxy PT must use.
            Format: <proxy_type>://[<user_name>][:<password>][@]<ip>:<port>
            Example: socks5://tor:test1234@198.51.100.1:8000
                     socks4a://198.51.100.2:8001
        '''
        
        # Python 2 compatibility note: specify parameters for super()
        super().__init__(ptexec, statedir)
        
        self.transports = {}
        
        for t in transports:
            self.transports[t] = {"ready": False, "error": False}
        self.env["TOR_PT_CLIENT_TRANSPORTS"] = ",".join(transports)
        if upstream_proxy is not None:
            self.env["TOR_PT_PROXY"] = upstream_proxy
        
        self.logger.info("Environment variables prepared for client " + 
                         self.ptexec)
        self.logger.debug("Environment variables:")
        self.logger.debug(self.env)
    
    def start(self):
        '''Start the pluggable transport client.
        
        Once complete, PT executable should be listening for SOCKS4/5 requests
        on port(s) it chose. PT server address/port and connection parameters
        should be provided in the SOCKS request. self.transports reflects the
        status, specific SOCKS protocol, and bound address/port of activated 
        transports.'''
        
        self.run_ptexec()
        
        #while self.p.poll() is None:
        for line in self.p.stdout:
            #line = self.p.stdout.readline().strip()
            if self.parse_stdout(line.strip()): break
        else:
            # fell through the loop: PT executable terminated
            self.logger.error("PT executable terminated")
            return False
        
        for t, o in self.transports.items():
            if not o["ready"] and not o["error"]:
                # PT ignored this transport: not supported?
                self.logger.warning("PT ignored transport " + t)
        
        # The PT executable should not generate any more output, so closing or
        # not shouldn't make any difference
        self.p.stdout.close()
        
        return True
    
    def parse_stdout(self, line):
        '''Parse data coming from PT executable's stdout.
        
        This method parses common and client-specific messages. Returns True if
        a "CMETHOD DONE" message signalling completion is received, and False 
        otherwise.'''
        
        done = False
        
        if self._parse_stdout_common(line):
            if line.startswith("PROXY-ERROR"):
                self.logger.error("PT client proxy error, "
                                  "error message: " + line[12:])
                # PT executable should terminate, not raising exception
            elif line.startswith("PROXY DONE"):
                self.logger.info("PT client proxy configuration done")
            elif line.startswith("CMETHOD-ERROR"):
                e = line[14:].split(" ", 1)
                self.transports[e[0]]["error"] = True
                self.transports[e[0]]["errormessage"] = e[1]
                self.logger.error("PT client transport '{}' error, "
                                  "error message: {}".format(*e))
            elif line.startswith("CMETHODS DONE"):
                self.logger.info("PT client configuration complete")
                done = True
            elif line.startswith("CMETHOD "):
                e = line[8:].split(" ", 2)
                self.transports[e[0]]["ready"] = True
                self.transports[e[0]]["protocol"] = e[1]
                self.transports[e[0]]["bindaddr"] = e[2]
                self.logger.info("PT client transport {} configured, protocol"\
                                 " {} listening on {}".format(*e))
            else:
                self.logger.info("PT communication not understood: " + line)
        
        return done

class PluggableTransportClientTCPAdapter(PluggableTransportClientSOCKSAdapter):
    '''Adapter for pluggable transport running as "complete" client: accepts
    TCP connections on user-chosen address:port and forwards obfuscated 
    traffic.'''
    
    def __init__(self, ptexec, statedir, transports, upstream_proxy=None):
        '''
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
    import argparse
    import json
    import threading
    
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