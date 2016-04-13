'''This module implements Tor's "managed proxy protocol", used for communication
between Tor and pluggable transports.'''

import logging
import subprocess
import os

class PluggableTransportBaseAdapter(object):
    '''Base class for pluggable transport adapters.'''
    
    def __init__(self, ptexec, statedir):
        '''Initialize class.
        
        Arguments:
        ptexec: either string or sequence of the pluggable transport
            executable. This is passed directly to Popen()'s 'args', so check its
            documentation for details.
        statedir: string "TOR_PT_STATE_LOCATION". From pt-spec:
            A filesystem directory path where the
            PT is allowed to store permanent state if required. This
            directory is not required to exist, but the proxy SHOULD be able
            to create it if it does not.'''
        
        self.ptexec = ptexec
        
        # environment variables for PT
        self.env = {}
        # Under Windows, obfs4proxy requires some environment variables to be 
        # set, otherwise it throws cryptic error messages like "The requested 
        # service provider could not be loaded or initialized".
        if "SystemRoot" in os.environ: 
            self.env["SystemRoot"] = os.environ["SystemRoot"]
            
        self.env["TOR_PT_MANAGED_TRANSPORT_VER"] = "1"
        self.env["TOR_PT_STATE_LOCATION"] = statedir
        
        self.logger = logging.getLogger("pluggabletransportadapter")
    
    def run_ptexec(self):
        '''Run PT executable.
        
        Provides the appropriate enviroment variables.
        Stores the Popen object of the subprocess so its stdout can be read.'''
        
        self.p = subprocess.Popen(self.ptexec, stdout=subprocess.PIPE,
                                  env=self.env, universal_newlines=True)
    
    def terminate(self):
        '''Terminate the PT executable.'''
        
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
    '''Adapter for pluggable transport running as server.
    
    Listens on one or more TCP port(s), accepts obfuscated traffic on each port
    (optionally with different protocols on each port), and forwards plaintext 
    traffic to one TCP address:port.'''
    
    def __init__(self, ptexec, statedir, orport, transports):
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
        
        The following snippet is the Tor server PT configuration equivalent to 
        above example:
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
        for t, o in transports.items():
            self.transports[t] = {"ready": False, "error": False}
            transportlist.append(t)
            if "bindaddr" in o:
                bindaddrlist.append(t + "-" + o["bindaddr"])
            if "options" in o:
                for k, v in o["options"].items():
                    optionlist.append("{}:{}={}".format(t, k, v))
        
        self.env["TOR_PT_SERVER_TRANSPORTS"] = ",".join(transportlist)
        if bindaddrlist:
            self.env["TOR_PT_SERVER_BINDADDR"] = ",".join(bindaddrlist)
        if optionlist:
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
                self.logger.warning("PT communication not understood\n" + line)
        
        return done

class PluggableTransportClientSOCKSAdapter(PluggableTransportBaseAdapter):
    '''Adapter for pluggable transport running as "bare" SOCKS client.
    
    Listens for SOCKS proxy requests on (PT-chosen) TCP port, reads destination
    address:port and other parameters from SOCKS user:pass, connect to 
    destination and forwards obfuscated traffic.'''
    
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
                if e[1].lower() not in ('socks4', 'socks5'):
                    self.logger.warning("Unexpected PT client transport protocol:")
                    self.logger.warning(e)
            else:
                self.logger.warning("PT communication not understood: " + line)
        
        return done

