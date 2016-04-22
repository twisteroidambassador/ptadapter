'''This module implements Tor's "managed proxy protocol", used for communication
between Tor and pluggable transports.'''

#from rsocks.pool import ServerPool
#from rsocks.server import ReverseProxyServer

import asyncio
import ipaddress
from functools import partialmethod

from . import PluggableTransportClientSOCKSAdapter

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
        
        self.tasks.add(asyncio.Task.current_task())
        client_conn_string = "{} -> {}".format(
                client_writer.get_extra_info("peername"), 
                client_writer.get_extra_info("sockname"))
        self.logger.info("Accepted connection " + client_conn_string)
        
        try:
            socks_addrport = socks_bindaddr.rsplit(":", maxsplit=1)
            
            socks_writer = None
            
            # Parse remote_addr into IP address or host name
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
                    # treat as host name
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
                #yield from socks_writer.drain()
                
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
                    #yield from socks_writer.drain()
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
                    # host name
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
            self.logger.error("Exception handling client connection {}: {}".
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
        and rsocks should set up for listening to plaintext TCP traffic and
        relaying to PT. However, you still need to call self.rsocksloop() 
        (which is blocking) to actually relay traffic!'''
        
        super().start()
        
        self.loop = asyncio.get_event_loop()
        self.servers = []
        self.tasks = set()
        
        #self.rsockspool = ServerPool()
        
        for t, o in self.transports.items():
            if not o["ready"]: 
                continue
            
            #i = 0
            #ptproxy = "{}://{}".format(o["protocol"], o["bindaddr"])
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
