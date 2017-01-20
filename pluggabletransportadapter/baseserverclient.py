'''This module implements Tor's "managed proxy protocol", used for communication
between Tor and pluggable transports.'''

import logging
import subprocess
import shlex
import os
import sys
import asyncio
import ipaddress

class PluggableTransportBaseAdapter(object):
    '''Base class for pluggable transport adapters.'''
    
    def __init__(self, ptexec, statedir):
        '''Initialize class.
        
        Arguments:
        ptexec: either string or list specifying the pluggable transport
            executable and optionally command line arguments.
            If ptexec is a string, then:
                On Windows, the string is passed directly to Popen().
                On any other OS, the string is passed to shlex.split() first, 
                then to Popen().
            If ptexec is not a string (could be a list or tuple), then it is
            always passed directly to Popen().
        statedir: string "TOR_PT_STATE_LOCATION". From pt-spec:
            A filesystem directory path where the
            PT is allowed to store permanent state if required. This
            directory is not required to exist, but the proxy SHOULD be able
            to create it if it does not.'''
        
        if isinstance(ptexec, str) and sys.platform != 'win32':
            # The subprocess module also checks for Windows using sys.platform
            self.ptexec = shlex.split(ptexec)
        else:
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
                self.logger.info("Terminating PT executable")
                self.p.terminate()
        except NameError:
            # self.p does not exist
            pass
    
    def wait(self):
        '''Block until PT executable exits.
        
        This method is intended to be used to keep the process/thread alive 
        when it has nothing else to do.'''
        
        self.p.wait()
    
    def _parse_stdout_common(self, line):
        '''Parse data coming from PT executable's stdout.
        
        This method takes care of the common messages that apply to both servers
        and clients, and returns False if the message is understood and True
        otherwise (so subclasses can continue to parse it).'''
        
        stillneedwork = False
        
        self.logger.debug("PT executable says: {}".format(line))
        
        if line.startswith("ENV-ERROR"):
            self.logger.error("PT environment variable error, " 
                              "Error message: {}".format(line[10:]))
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
        
        self.logger.info("Environment variables prepared for server {}".format(
                         self.ptexec))
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
                self.logger.warning("PT ignored transport {}".format(t))
        
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
                try:
                    self.transports[e[0]]["options"] = e[2]
                except IndexError:
                    self.transports[e[0]]["options"] = None
                self.logger.info("PT server transport '{}' configured, "
                                 "listening on {}".format(e[0], e[1]))
            else:
                self.logger.warning("PT communication not understood: {}".
                        format(line))
        
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
        
        self.logger.info("Environment variables prepared for client {}".format(
                         self.ptexec))
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
                self.logger.warning("PT ignored transport {}".format(t))
        
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
                                  "error message: {}".format(line[12:]))
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
                self.logger.warning("PT communication not understood: {}".
                        format(line))
        
        return done


class PluggableTransportClientTCPAdapter(PluggableTransportClientSOCKSAdapter):
    '''Adapter for pluggable transport running as "complete" client.
    
    Listens for TCP connections on user-specified address:port, connect to 
    destination address:port, and forwards obfuscated traffic.'''
    
    RELAY_BUFFER_SIZE = 65535
    PT_CONNECT_TIMEOUT = 10
    
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
    
    @asyncio.coroutine
    def handle_relay_data(self, reader, writer, relay_name):
        '''Relay incoming data on reader to writer.'''
        self.logger.info("Relay {} started".format(relay_name))
        try:
            while True:
                buf = yield from reader.read(self.RELAY_BUFFER_SIZE)
                if not buf:
                    break
                self.logger.debug("Relay {} received data".format(relay_name))
                writer.write(buf)
                yield from writer.drain()
        except asyncio.CancelledError:
            self.logger.debug("Relay {} cancelled".format(relay_name))
        except Exception as e:
            self.logger.warning("Relay {} exception: {}".format(relay_name, e))
        finally:
            writer.close()
            self.tasks.remove(asyncio.Task.current_task())
            self.logger.info("Relay {} closed".format(relay_name))
    
    @asyncio.coroutine
    def handle_reverse_proxy_connection(self, client_reader, client_writer, 
            socks_protocol, socks_bindaddr, remote_addr, remote_port, 
            pt_param = None):
        '''Accept incoming connection, negotiate SOCKS and start relays.'''
        
        self.tasks.add(asyncio.Task.current_task())
        client_conn_string = "{} -> {}".format(
                client_writer.get_extra_info("peername"), 
                client_writer.get_extra_info("sockname"))
        self.logger.info("Accepted connection {}".format(client_conn_string))
        
        try:
            socks_addrport = socks_bindaddr.rsplit(":", maxsplit=1)
            
            socks_writer = None
            
            # Parse remote_addr into IP address or domain name
            if socks_protocol.lower() == "socks4":
                # SOCKS4 proxies only accept IPv4 addresses
                try:
                    remote_ip = ipaddress.IPv4Address(remote_addr)
                except AddressValueError:
                    raise RuntimeError("PT SOCKS4 proxy only accepts IPv4 "
                            "remote addresses, and {} is not a valid IPv4 "
                            "address".format(remote_addr))
            elif socks_protocol.lower() == "socks5":
                try:
                    remote_ip = ipaddress.ip_address(remote_addr)
                except ValueError:
                    # remote_addr is not a valid IPv4 or IPv6 address, hence
                    # treat as domain name
                    remote_ip = None
                    remote_addr_b = remote_addr.encode()
                    if len(remote_addr_b) > 255:
                        raise RuntimeError("Remote domain name too long at {} "
                                "bytes; SOCKS5 only supports up to 255".format(
                                len(remote_addr_b)))
            else:
                raise RuntimeError("Unexpected PT proxy protocol {}".format(
                            socks_protocol))
            
            # Connect to PT SOCKS server
            try:
                socks_reader, socks_writer = yield from asyncio.wait_for(
                        asyncio.open_connection(socks_addrport[0], 
                            int(socks_addrport[1]), loop=self.loop),
                        timeout = self.PT_CONNECT_TIMEOUT)
            except asyncio.TimeoutError:
                raise RuntimeError("Connecting to PT timed out.")
            
            socks_conn_string = "{} -> {}".format(
                    socks_writer.get_extra_info("sockname"), 
                    socks_writer.get_extra_info("peername"))
            self.logger.debug("Connection established to SOCKS server {} for "
                    "client connection {}".
                    format(socks_conn_string, client_conn_string))
            
            # Negotiate SOCKS parameters
            if socks_protocol.lower() == "socks4":
                socks_writer.write(b"\x04\x01" + 
                        remote_port.to_bytes(2, "big") +
                        remote_ip.packed + 
                        (b"" if pt_param is None else pt_param.encode()) + 
                        b"\x00")
                
                buf = yield from socks_reader.readexactly(8)
                if buf[0] != 0:
                    raise RuntimeError("Malformed SOCKS4 reply {}".format(buf))
                if buf[1] != 90:
                    if buf[1] == 91:
                        raise RuntimeError("SOCKS4 connection rejected or failed")
                    else:
                        raise RuntimeError("SOCKS4 connection failed, "
                                "status code {}".format(buf[1]))
                
                self.logger.info("SOCKS4 negotiation to server {} successful "
                        "for client connection {}".format(
                        socks_conn_string, client_conn_string))
                
            elif socks_protocol.lower() == "socks5":
                # Authentication
                if pt_param is None:
                    # No authentication
                    socks_writer.write(b"\x05\x01\x00")
                    buf = yield from socks_reader.readexactly(2)
                    if buf[1] != 0:
                        raise RuntimeError("SOCKS5 server rejected "
                                "authentication method 0, returned {}".
                                format(buf[1]))
                else:
                    # Username / password authentication
                    pt_param_b = pt_param.encode()
                    username = pt_param_b[:255]
                    password = pt_param_b[255:] or b"\x00"
                    
                    socks_writer.write(b"\x05\x01\x02")
                    buf = yield from socks_reader.readexactly(2)
                    if buf[1] != 2:
                        raise RuntimeError("SOCKS5 server rejected "
                                "authentication method 2, returned {}".
                                format(buf[1]))
                    
                    socks_writer.write(b"\x01" + 
                            len(username).to_bytes(1, "big") + username + 
                            len(password).to_bytes(1, "big") + password)
                    buf = yield from socks_reader.readexactly(2)
                    if buf[1] != 0:
                        raise RuntimeError("SOCKS5 server rejected username / "
                                "password, returned status code {}".
                                format(buf[1]))
                self.logger.debug("SOCKS5 authentication to server {} "
                        "successful for client connection {}".format(
                        socks_conn_string, client_conn_string))
                
                # Connection request
                if remote_ip is None:
                    # domain name
                    socks_writer.write(b"\x05\x01\x00\x03" + 
                            len(remote_addr_b).to_bytes(1, "big") + 
                            remote_addr_b + remote_port.to_bytes(2, "big"))
                else:
                    # IPv4 / IPv6 address
                    socks_writer.write(b"\x05\x01\x00" + 
                            (b"\x01" if remote_ip.version == 4 else b"\x04") + 
                            remote_ip.packed + remote_port.to_bytes(2, "big"))
                buf = yield from socks_reader.readexactly(4)
                if buf[3] == 1:
                    yield from socks_reader.readexactly(4 + 2)
                elif buf[3] == 3:
                    buf2 = yield from socks_reader.readexactly(1)
                    yield from socks_reader.readexactly(buf2[0] + 2)
                elif buf[3] == 4:
                    yield from socks_reader.readexactly(16 + 2)
                else:
                    raise RuntimeError("Malformed SOCKS5 connect reply {}".
                            format(buf))
                if buf[1] != 0:
                    raise RuntimeError("SOCKS5 server rejected connection, "
                            "reply code {}".format(buf[1]))
            
            # At this point, all SOCKS negotiations are complete
            
        except asyncio.CancelledError as e:
            self.logger.info("Received {}, aborting connection {}".format(
                    e, client_conn_string))
            client_writer.close()
            if socks_writer is not None: socks_writer.close()
        except RuntimeError as e:
            self.logger.error("Error while handling client connection {}: {}".
                    format(client_conn_string, e))
            client_writer.close()
            if socks_writer is not None: socks_writer.close()
        except Exception as e:
            self.logger.error("Exception while handling client connection {}: {}".
                    format(client_conn_string, e))
            client_writer.close()
            if socks_writer is not None: socks_writer.close()
            raise
        else:
            # Start relaying data
            self.tasks.add(asyncio.async(self.handle_relay_data(
                    client_reader, socks_writer, 
                    "{} => {}".format(client_writer.get_extra_info("peername"),
                            socks_writer.get_extra_info("peername")))))
            self.tasks.add(asyncio.async(self.handle_relay_data(
                    socks_reader, client_writer, 
                    "{} => {}".format(socks_writer.get_extra_info("peername"),
                            client_writer.get_extra_info("peername")))))
        finally:
            self.tasks.remove(asyncio.Task.current_task())
    
    def start(self):
        '''Start the pluggable transport client.
        
        Once complete, PT executable should be listening for SOCKS4/5 requests,
        and the reverse proxy should set up for listening to plaintext TCP 
        traffic and relaying to PT. However, you have to make sure the asyncio
        event loop is running in order to actually relay traffic. Calling 
        self.wait() will do that for you.'''
        
        super().start()
        
        self.loop = asyncio.get_event_loop()
        self.servers = []
        self.tasks = set()
        
        for t, o in self.transports.items():
            if not o["ready"]: 
                continue
            
            for a in o["listeners"]:
                if "options" in a:
                    listeneroptions = ";".join(
                            ("=".join(s) for s in a["options"].items()))
                else:
                    listeneroptions = None
                
                lambda_handler = (lambda r, w: 
                        self.handle_reverse_proxy_connection(r, w, 
                            o["protocol"], o["bindaddr"], a["remoteaddr"][0],
                            a["remoteaddr"][1], listeneroptions))
                self.servers.append(self.loop.run_until_complete(
                        asyncio.start_server(lambda_handler, 
                            a["listenaddr"][0], a["listenaddr"][1],
                            loop = self.loop)))
                        
                self.logger.info("Server for listenaddr {} created".format(
                        a["listenaddr"]))

    def terminate(self):
        '''Terminate the PT executable, reverse proxies and active relays.'''
        
        # Close all servers
        self.logger.info("Closing all reverse proxy servers")
        for s in self.servers:
            s.close()
        for s in self.servers:
            s.wait_closed()
        # Cancel all active tasks
        self.logger.info("Cancelling all active tasks")
        for r in self.tasks:
            r.cancel()
        self.loop.run_until_complete(asyncio.gather(*self.tasks))
        # Terminate PT executable
        super().terminate()
    
    def wait(self):
        '''Block until PT executable exits, while keeping asyncio loop running.
        
        This method is intended to be used to keep the process/thread alive 
        when it has nothing else to do.'''
        
        while self.p.poll() is None:
            self.loop.run_until_complete(asyncio.sleep(0.2))

