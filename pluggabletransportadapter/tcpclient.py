'''This module implements Tor's "managed proxy protocol", used for communication
between Tor and pluggable transports.'''

from rsocks.pool import ServerPool
from rsocks.server import ReverseProxyServer

from . import PluggableTransportClientSOCKSAdapter

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
        
