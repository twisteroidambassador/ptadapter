'''This module implements Tor's "managed proxy protocol", used for communication
between Tor and pluggable transports.'''

#from rsocks.pool import ServerPool
#from rsocks.server import ReverseProxyServer

import asyncio
import ipaddress
from struct import pack, unpack

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
    def handle_relay_data(self, reader, writer):
        '''Relay incoming data on reader to writer.'''
        try:
            while True:
                buf = yield from reader.read(RELAY_BUFFER_SIZE)
                if not buf:
                    break
                writer.write(buf)
                yield from writer.drain()
        except Exception as e:
            self.logger.warning("relay data exception: {}".format(e))
        finally:
            writer.close()
    
    @asyncio.coroutine
    def handle_reverse_proxy_connection(self, client_reader, client_writer, 
            socks_protocol, socks_bindaddr, remote_addr, remote_port, 
            pt_param = None):
        
        client_conn_string = "from {} on {}".format(
                client_writer.get_extra_info("peername"), 
                client_writer.get_extra_info("sockname"))
        self.logger.info("Accepted connection " + client_conn_string)
        
        try:
            socks_addrport = socks_bindaddr.rsplit(":", maxsplit=1)
            
            socks_writer = None
            
            if socks_protocol.lower() = "socks4":
                # SOCKS4 proxies only accept IPv4 addresses
                try:
                    remote_ip = ipaddress.IPv4Address(remote_addr)
                except AddressValueError:
                    raise RuntimeError("PT SOCKS4 proxy only accepts IPv4 "
                            "remote addresses, and {} is not a valid IPv4 "
                            "address".format(remote_addr))
            elif socks_protocol.lower() = "socks5":
                try:
                    remote_ip = ipaddress.ip_address(remote_addr)
                except ValueError:
                    # remote_addr is not a valid IPv4 or IPv6 address
                    remote_ip = None
            else:
                raise RuntimeError("Unexpected PT proxy protocol {}".format(
                            socks_protocol))
            
            try:
                socks_reader, socks_writer = yield from asyncio.wait_for(
                        asyncio.open_connection(socks_addrport[0], 
                            int(socks_addrport[1]), loop=self.loop),
                        timeout = PT_CONNECT_TIMEOUT)
            except asyncio.TimeoutError:
                raise RuntimeError("Connecting to PT timed out.")
            
            if socks_protocol.lower() = "socks4":
                socks_writer.write(pack("!BBH", 4, 1, remote_port) + 
                        remote_ip.packed + 
                        (b"" if pt_param is None else pt_param.encode()) + 
                        b"\x00")
                yield from socks_writer.drain()
                
                buf = yield from socks_reader.readexactly(8)
                if buf[0] != 0:
                    raise RuntimeError("Malformed SOCKS4 reply {}".format(buf))
                if buf[1] != 90:
                    if buf[1] == 91:
                        raise RuntimeError("SOCKS4 connection rejected or failed")
                    else:
                        raise RuntimeError("SOCKS4 connection failed, "
                                "status code {}".format(buf[1]))
                
                self.logger.info("SOCKS4 negotiation successful for client "
                        "connection " + client_conn_string)
                
            elif socks_protocol.lower() = "socks5":
                if pt_param is None:
                    socks_writer.write(b"\x05\x01\x00")
                    yield from socks_writer.drain()
                    buf = yield from socks_reader.readexactly(2)
                    if buf[1] != 0:
                        raise 
    
    def start(self):
        '''Start the pluggable transport client.
        
        Once complete, PT executable should be listening for SOCKS4/5 requests,
        and rsocks should set up for listening to plaintext TCP traffic and
        relaying to PT. However, you still need to call self.rsocksloop() 
        (which is blocking) to actually relay traffic!'''
        
        super().start()
        
        self.loop = asyncio.get_event_loop()
        
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
                        if o["protocol"].lower() == "socks4":
                            server.proxy_server["username"] = listeneroptions
                        elif o["protocol"].lower() == "socks5":
                            server.proxy_server["username"] = listeneroptions[:255]
                            server.proxy_server["password"] = listeneroptions[255:] or '\0'
                        
                    server.listen(a["listenaddr"])
    
    def rsocksloop(self):
        '''Run rsocks's server loop so it actually relays TCP traffic to PT.
        
        This function blocks.'''
        
        self.rsockspool.loop()
        
