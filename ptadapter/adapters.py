"""Adapter classes that run and control Pluggable Transports."""


import logging
import shlex
import os
import asyncio
import functools

from .relays import StreamRelay, SOCKS4Negotiator, SOCKS5Negotiator
from .exceptions import PTExecError, PTExecSMethodError, PTExecCMethodError

__all__ = ['PTServerAdapter', 
           'PTClientSOCKSAdapter', 
           'PTClientStreamAdapter',
           'PTClientListeningAdapter']


class PTBaseAdapter():
    """Base class for pluggable transport adapters."""
    
    def __init__(self, loop, ptexec, statedir):
        """Initialize class.
        
        loop: asyncio event loop to use. Must use ProactorEventLoop on
        Windows.
        
        ptexec: pluggable transport executable and command line args.
        Can be a string (will go through shlex.split() first) or a list.
        
        statedir: "A filesystem directory path where the PT is allowed
        to store permanent state if required. This directory is not
        required to exist, but the proxy SHOULD be able to create it if
        it does not."
        """
        self._loop = loop
        self._logger = logging.getLogger('ptadapter.Adapter')
        if isinstance(ptexec, str):
            self._ptexec = shlex.split(ptexec)
        else:
            self._ptexec = ptexec
        
        # environment variables for PT
        self._env = {}
        # Python docs on subprocess.Popen:
        # If specified, env must provide any variables required for
        # the program to execute. On Windows, in order to run a
        # side-by-side assembly the specified env must include a valid
        # SystemRoot. 
        if 'SystemRoot' in os.environ: 
            self._env['SystemRoot'] = os.environ['SystemRoot']
        self._env['TOR_PT_MANAGED_TRANSPORT_VER'] = '1'
        self._env['TOR_PT_STATE_LOCATION'] = statedir
        self._env['TOR_PT_EXIT_ON_STDIN_CLOSE'] = '1'
        
    @property
    def loop(self):
        return self._loop
    
    def start(self):
        """Start the PT executable asynchronously."""
        self._run_task = self._loop.create_task(self._run())
    
    def stop(self):
        """Terminate the PT executable asynchronously."""
        self._run_task.cancel()
    
    def wait(self):
        """Run the event loop until PT terminates."""
        self._loop.run_until_complete(self._run_task)
    
    def _cleanup_all_awaitables(self):
        """Stop everything and return a list of awaitables.
        
        This method is called when terminating PT, and anything
        returned is waited for. Intended for cleanup at exit.
        
        Subclasses are expected to extend this method.
        """
        return []
        
    @asyncio.coroutine
    def _run(self):
        """Run and respond to the PT executable.
        
        Creates the PT subprocess asynchronously, read its STDOUT, 
        parse and react accordingly, and terminate the process upon
        task cancellation.
        """
        self._logger.debug('Starting PT executable, environment variables: %r',
                           self._env)
        p = None
        try:
            p = yield from asyncio.create_subprocess_exec(
                    *self._ptexec, loop=self._loop, 
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE, env=self._env)
            self._logger.info('PT executable started')
            
            while True:
                s = (yield from p.stdout.readline()).decode(
                        'utf-8',errors='backslashreplace').rstrip()
                self._logger.debug('PT stdout: %s', s)
                if not s:
                    raise PTExecError('PT exec closed STDOUT', '')
                self._pt_stdout_line(s)
        except asyncio.CancelledError as e:
            self._logger.debug('PT run task cancelled')
            raise
        except PTExecError:
            self._logger.error('PT encountered an error', exc_info=True)
        finally:
            awaitables = self._cleanup_all_awaitables()
            if p:
                # first try terminating via closing STDIN
                self._logger.debug(
                        'Attempting to terminate PT by closing STDIN')
                p.stdin.close()
                # wait 5 seconds for the process to shut down
                try:
                    yield from asyncio.wait_for(p.wait(), 5, loop=self._loop)
                except asyncio.TimeoutError:
                    self._logger.debug(
                            'PT did not terminate after closing STDIN, '
                            'attempting to to call terminate() on PT')
                    p.terminate()
                    yield from p.wait()
                finally:
                    self._logger.info('PT terminated')
            yield from asyncio.gather(*awaitables, loop=self._loop,
                                      return_exceptions=True)
            self._logger.debug('Adapter stopped everything')
    
    def _pt_stdout_line(self, line):
        """Parse and react to one line from PT's STDOUT.
        
        Subclasses are expected to extend this method to parse 
        additional keywords. See PT specs.
        """
        kw, _, args = line.partition(' ')
        if kw == 'VERSION-ERROR':
            self._logger.error('PT spec version error')
            raise PTExecError(line)
        elif kw == 'VERSION':
            self._logger.debug('PT using spec version %s', args)
        elif kw == 'ENV-ERROR':
            self._logger.error('PT environment variables error: %s', line)
            raise PTExecError(line)
        else:
            self._logger.warning('Unexpected PT STDOUT communication: %s',line)
 
class PTServerAdapter(PTBaseAdapter):
    """Run a pluggable transport as the server end of a tunnel.
    
    Listens on one or more TCP port(s) (different protocols for each),
    accepts obfuscated traffic, and forwards plaintext traffic to one
    TCP address:port (the ORPort).
    
    Future objects are provided for each transport protocol and for the
    overall server, which can be awaited or have callbacks attached to.
    """
    
    def __init__(self, loop, ptexec, statedir, orport, transports):
        """Initialize class.
        
        loop, ptexec, statedir: See PluggableTransportBaseAdapters.
        
        orport: "The <address>:<port> of the ORPort of the bridge where
        the PT is supposed to send the deobfuscated traffic."
        
        transports: a dictionary of server transports to support.
        Example:
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
        transports[] should contain one or more keys corresponding to
        the transports supported by the PT executable.
        transports[transport-name][bindaddr] is the <address>:<port>
        where PT should listen for client connections.
        (optional) transports[transport-name][options] is a dictionary
        of <k>=<v> options to be passed to PT. <k> and <v> should all
        be strings. Colons, semicolons, equal signs and backslashes
        MUST be escaped with a backslash.
        
        The following snippet is the Tor server PT configuration 
        equivalent to the example above:
            ServerTransportPlugin trebuchet,ballista exec <ptexec>
            ServerTransportListenAddr trebuchet 127.0.0.1:1984
            ServerTransportListenAddr ballista 127.0.0.1:4891
            ServerTransportOptions trebuchet rocks=20 height=5.6m
        """
        super().__init__(loop, ptexec, statedir)        
        self._transports = {}
        self._server_ready = asyncio.Future()
        
        transportlist = []
        optionlist = []
        bindaddrlist = []
        for trans, opt in transports.items():
            self._transports[trans] = asyncio.Future()
            transportlist.append(trans)
            if 'bindaddr' in opt:
                bindaddrlist.append('{}-{}'.format(trans, opt['bindaddr']))
            if 'options' in opt:
                for k, v in opt['options'].items():
                    optionlist.append('{}:{}={}'.format(trans, k, v))
        self._env['TOR_PT_SERVER_TRANSPORTS'] = ','.join(transportlist)
        if bindaddrlist:
            self._env['TOR_PT_SERVER_BINDADDR'] = ','.join(bindaddrlist)
        if optionlist:
            self._env['TOR_PT_SERVER_TRANSPORT_OPTIONS'] = ';'.join(optionlist)
        self._env['TOR_PT_ORPORT'] = orport
    
    @property
    def transports(self):
        return self._transports
    
    @property
    def server_ready(self):
        return self._server_ready
    
    def _cleanup_all_awaitables(self):
        s = super()._cleanup_all_awaitables()
        # These Future() objects don't need to be waited for.
        for fut in self._transports.values():
            fut.cancel()
        self._server_ready.cancel()
        return s
    
    def _pt_stdout_line(self, line):
        kw, _, args = line.partition(' ')
        if kw == 'SMETHOD':
            args_l = args.split(' ', maxsplit=2)
            trans = args_l[0]
            res = {'address': args_l[1], 'options': None}
            try:
                res['options'] = args_l[2]
            except IndexError:
                pass
            self._transports[trans].set_result(res)
            self._logger.info('PT server transport %s ready, listening on %s, '
                    'options %s', trans, res['address'], res['options'])
        elif kw == 'SMETHOD-ERROR':
            trans = args.partition(' ')[0]
            self._logger.warning(
                    'PT server transport %s error: %s', trans, line)
            self._transports[trans].set_exception(PTExecSMethodError(line))
        elif kw == 'SMETHODS' and args == 'DONE':
            self._logger.info('PT server initialization complete')
            for trans,fut in self._transports.items():
                if not fut.done():
                    self._logger.warning('PT server transport %s still not '
                            'ready, possibly ignored', trans)
                    fut.cancel()
            self._server_ready.set_result(True)
        else:
            super()._pt_stdout_line(line)
    

class PTServerStreamAdapter(PTServerAdapter):
    """XXX: work in progress.
    
    Run a pluggable transport as server and receive data from it.
    
    Listens on one or more TCP port(s) (different protocols for each),
    and provides a StreamReader/Writer pair to a callback for incoming
    connections. Optionally an access control callback can also be
    used.
    
    Information about the connecting client will be made available
    """
    
    def __init__(self, loop, ptexec, statedir, transports, cookie_file,
                 extorport=None):
        """Initialize class.
        
        loop, ptexec, statedir: See PTBaseAdapter.
        
        transports: see PTServerAdapter.
        
        cookie_file: full path+filename of a writable location, where
        an authentication cookie file will be generated. This location
        should only be readable by `self` and PT.
        
        extorport: optional, the <address>:<port> where unobfuscated 
        traffic and client information will be sent from PT, and where
        `self` will listen for said traffic. It's a bad idea to set this
        to a non-localhost address. If unspecified, defaults to 
        127.0.0.1:<random available port>, which is the correct choice
        in most cases.
        """
        super().__init__(self, loop, ptexec, statedir, 0, transports)
        del self._env['TOR_PT_ORPORT']
        self._extorport = extorport
        if extorport is not None:
            host, port = extorport.rpartition(':')
            self._ext_host = host
            self._ext_port = int(port)
        else:
            self._ext_host = '127.0.0.1'
            self._ext_port = 0
    
class PTClientSOCKSAdapter(PTBaseAdapter):
    """Run a pluggable transport as a bare SOCKS proxy.
    
    Listen for SOCKS proxy requests on (PT-chosen) TCP port. Clients
    should encode destination host:port and other options into the 
    username / password fields as specified by PT spec, and negotiate
    the connection with PT.
    """
    
    def __init__(self, loop, ptexec, statedir, transports, upstream_proxy=None):
        """Initialize class.
        
        loop, ptexec, statedir: See PluggableTransportBaseAdapters.
        
        transports: either a list of transport names, or a dictionary
        where the keys are transport names.
        
        upstream_proxy: string indicating the upstream proxy PT must use.
        Format: <proxy_type>://[<user_name>][:<password>][@]<ip>:<port>
        Accepted proxy_type are "http", "socks5", "socks4a".
        
        Example: socks5://tor:test1234@198.51.100.1:8000
                 socks4a://198.51.100.2:8001
        """
        super().__init__(loop, ptexec, statedir)
        self._transports = {}
        self._client_ready = asyncio.Future()
        
        for t in transports:
            self._transports[t] = asyncio.Future()
        self._env['TOR_PT_CLIENT_TRANSPORTS'] = ','.join(transports)
        if upstream_proxy is not None:
            self._env['TOR_PT_PROXY'] = upstream_proxy
    
    @property
    def transports(self):
        return self._transports
    
    @property
    def client_ready(self):
        return self._client_ready
    
    def _pt_stdout_line(self, line):
        kw, _, args = line.partition(' ')
        if kw == 'PROXY' and args == 'DONE':
            self._logger.debug('PT accepted upstream proxy')
        elif kw == 'PROXY-ERROR':
            self._logger.error('PT upstream proxy error: %s', line)
            raise PTExecError(line)
        elif kw == 'CMETHOD':
            args_l = args.split(' ', maxsplit=2)
            trans = args_l[0]
            res = {'protocol': args_l[1], 'address': args_l[2]}
            self._transports[trans].set_result(res)
            self._logger.info('PT client transport %s ready, protocol %s, '
                    'listening on %s', trans, res['protocol'], res['address'])
        elif kw == 'CMETHOD-ERROR':
            trans = args.partition(' ')[0]
            self._logger.warning(
                    'PT client transport %s error: %s', trans, line)
            self._transports[trans].set_exception(PTExecCMethodError(line))
        elif kw == 'CMETHODS' and args == 'DONE':
            self._logger.info('PT client initialization complete')
            for trans,fut in self._transports.items():
                if not fut.done():
                    self._logger.warning('PT client transport %s still not '
                            'ready, possibly ignored', trans)
                    fut.cancel()
            self._client_ready.set_result(True)
        else:
            super()._pt_stdout_line(line)

    def _cleanup_all_awaitables(self):
        s = super()._cleanup_all_awaitables()
        for fut in self._transports.values():
            fut.cancel()
        self._client_ready.cancel()
        return s

class PTClientStreamAdapter(PTClientSOCKSAdapter):
    """Use StreamReader/Writers through pluggable transports.
    
    Specify destination host:port and options ahead of time. Use the
    open_connection() coroutine method to get a StreamReader / 
    StreamWriter pair through the PT.
    """
    
    def __init__(self, loop, ptexec, statedir, transports, upstream_proxy=None):
        """Initialize class.
        
        loop, ptexec, statedir, upstream_proxy: 
        See PluggableTransportBaseAdapters.
        
        transports: a dictionary of transports to support. Example:
            {
                "trebuchet":{
                    "tr1":{
                        "remote_host": "192.168.0.1",
                        "remote_port": 1984,
                        "options":{
                            "rocks": "20",
                            "height": "5.6m"
                        }
                    },
                    "tr2":{
                        "remote_host": "192.168.100.101",
                        "remote_port": 1984,
                        "options":{
                            "rocks": "10",
                            "height": "2.8m"
                        }
                    }
                },
                "ballista":{
                    "ballista":{
                        "remote_host": "192.168.0.1",
                        "remote_port": 4891)
                    }
                }
            }
        transports should contain one or more keys corresponding to the
        transports supported by the PT.
        
        Each transports[transport-name][destination-name] is a dict 
        describing one destination to be tunnelled using the specified
        transport. There should be a PT server listening at that
        destination.
        
        transports[][]['options'] is an (optional) dictionary of
        <k>=<v> options to be passed to PT. <k> and <v> should be
        strings. Semicolons and backslashes MUST be escaped with
        a backslash.
        """
        super().__init__(loop, ptexec, statedir, transports, upstream_proxy)
        self._negotiators = {}
        for trans, dests in transports.items():
            self._negotiators[trans] = {}
            for dest_name, dest_conf in dests.items():
                if 'options' in dest_conf:
                    if isinstance(dest_conf['options'], str):
                        opt = dest_conf['options']
                    else:
                        opt = ';'.join('='.join(s) 
                                    for s in dest_conf['options'].items())
                else:
                    opt = None
                self._negotiators[trans][dest_name] = self._loop.create_task(
                        self._create_negotiator(self._transports[trans],
                            dest_conf['remote_host'], dest_conf['remote_port'],
                            opt))
    
    @property
    def negotiators_ready(self):
        return self._negotiators
        
    @asyncio.coroutine
    def _create_negotiator(self, trans_fut, remote_host, remote_port, options):
        trans = yield from trans_fut
        proxy_host, _, proxy_port = trans['address'].rpartition(':')
        proxy_port = int(proxy_port)
        if trans['protocol'] == 'socks4':
            return SOCKS4Negotiator(self._loop, proxy_host, proxy_port, 
                                    remot_host, remote_port, options)
        elif trans['protocol'] == 'socks5':
            return SOCKS5Negotiator(self._loop, proxy_host, proxy_port,
                                    remote_host, remote_port, options)
        else:
            raise PTExecError('Unexpected proxy protocol %s', trans['protocol'])
    
    @asyncio.coroutine
    def open_connection(self, transport, destination, **kwargs):
        """Open a connection through the PT.
        
        Returns (StreamReader, StreamWriter).
        
        Instead of specifying host and port like
        asyncio.open_connection(), the required arguments are transport
        and destination as specified in __init__'s transports. Other 
        keyword arguments are passed to asyncio.open_connection().
        
        If PT client transport is not ready yet, wait until it's ready.
        """
        negotiator = yield from self._negotiators[transport][destination]
        return (yield from negotiator.open_connection(**kwargs))
    
    def _cleanup_all_awaitables(self):
        s = super()._cleanup_all_awaitables()
        for n in self._negotiators.values():
            for task in n.values():
                task.cancel()
        return s

class PTClientListeningAdapter(PTClientStreamAdapter):
    """Run a pluggable transport as the client end of a tunnel.
    
    Listen for TCP connections on specified host:port, and forward 
    obfuscated traffic to destination host:port.
    """
    
    def __init__(self, loop, ptexec, statedir, transports, upstream_proxy=None,
            access_control_cb=None):
        """Initialize class.
        
        loop, ptexec, statedir, upstream_proxy: 
        See PluggableTransportBaseAdapters.
        
        transports: a dictionary of transports to support. Example:
            {
                "trebuchet":{
                    "tr1":{
                        "listen_host": "127.0.0.1",
                        "listen_port": 2012,
                        "remote_host": "192.168.0.1",
                        "remote_port": 1984,
                        "options":{
                            "rocks": "20",
                            "height": "5.6m"
                        }
                    },
                    "tr2":{
                        "listen_host": "127.0.0.1",
                        "listen_port": 2013,
                        "remote_host": "192.168.100.101",
                        "remote_port": 1984,
                        "options":{
                            "rocks": "10",
                            "height": "2.8m"
                        }
                    }
                },
                "ballista":{
                    "ballista":{
                        "listen_host": "127.0.0.1",
                        "listen_port": 2014,
                        "remote_host": "192.168.0.1",
                        "remote_port": 4891)
                    }
                }
            }
        transports should contain one or more keys corresponding to the
        transports supported by the PT.
        
        Each transports[transport-name][destination-name] is a dict 
        describing one destination to be tunnelled using the specified
        transport. There should be a PT server listening at that
        destination.
        
        transports[][]['options'] is an (optional) dictionary of
        <k>=<v> options to be passed to PT. <k> and <v> should be
        strings. Semicolons and backslashes MUST be escaped with
        a backslash.
        
        access_control_cb: called when an incoming client connection is
        accepted. Should return True to proceed with the connection,
        False to disconnect.
        """
        super().__init__(loop, ptexec, statedir, transports, upstream_proxy)
        self._access_log = logging.getLogger('ptadapter.access')
        self._relays = {}
        for trans, dests in transports.items():
            self._relays[trans] = {}
            for dest_name, dest_conf in dests.items():
                self._relays[trans][dest_name] = self._loop.create_task(
                        self._create_relay(
                            trans, dest_name, dest_conf['listen_host'],
                            dest_conf['listen_port']))
        if access_control_cb is None:
            self._access_control_cb = self._access_control_allow_all
        else:
            self._access_control_cb = access_control_cb
    
    def _access_control_allow_all(self, transport, destination, peername):
        """Example access control callback. Allows all connections.
        
        transport, destination: the names used when configuring this
        tunnel.
        
        peername: the result of socket.socket.getpeername() on the
        client socket. The format of the address returned depends on 
        the address family (a (address, port) 2-tuple for AF_INET, a
        (address, port, flow info, scope id) 4-tuple for AF_INET6). See
        Python docs for details.
        
        Should return True to accept connection, False to close 
        connection.
        """
        return True
    
    @asyncio.coroutine
    def _on_connect(self, transport, destination, negotiator, dreader, dwriter):
        peername = dwriter.get_extra_info('peername')
        ac = self._access_control_cb(transport, destination, peername)
        if asyncio.iscoroutine(ac):
            ac = yield from ac
        
        if ac:
            self._access_log.warning('New connection to %s,%s accepted from %r',
                    transport, destination, peername)
            return (yield from negotiator.open_connection())
        else:
            self._access_log.warning('New connection to %s,%s rejected from %r',
                    transport, destination, peername)
            return (None, None)
    
    @asyncio.coroutine
    def _create_relay(self, transport, destination, listen_host, listen_port):
        negotiator = yield from self._negotiators[transport][destination]
        on_connect_cb = functools.partial(
                self._on_connect, transport, destination, negotiator)
        return StreamRelay(self._loop, listen_host, listen_port, on_connect_cb)
    
    def _cleanup_all_awaitables(self):
        s = super()._cleanup_all_awaitables()
        for trans in self._relays.values():
            for relay in trans.values():
                if not relay.done():
                    relay.cancel()
                    s.append(relay)
                else:
                    try:
                        t = self._loop.create_task(relay.result().close())
                    except Exception:
                        self._logger.debug('Leftover exception in relay',
                                           exc_info=True)
                    s.append(t)
        return s