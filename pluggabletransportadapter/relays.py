import asyncio
import ipaddress
import logging

from .exceptions import ProxyConfigError, ProxyNegotiationError

class StreamRelay:
    """Relay data between streams.
    
    Listen on specified downstream host:port. When new connections come
    in, run a callback that makes a new connection to the specified
    upstream host:port, and relay any received data between them.
    
    The on_connect callback can be used to do any negotiations on the
    upstream or downstream connections before relaying starts, or
    provide access control.
    
    Provides connection tracking and termination.
    """
    
    RELAY_BUFFER_SIZE = 2 ** 16
    
    def __init__(self, loop, listen_host, listen_port, on_connect):
        """Start listening for connections.
        
        loop, listen_host, listen_port are self-explanatory.
        
        on_connect is a coroutine, called when a new connection is
        received, with the downstream reader/writer (dreader, dwriter)
        as arguments. It should either initiate the upstream connection
        and return (ureader, uwriter), in which case the relay will
        commence, or return (None, None), in which case the downstream
        connection will then be terminated.
        """
        self._loop = loop
        self._on_connect = on_connect
        self._logger = logging.getLogger('ptadapter.StreamRelay')
        self._connections = set()
        self._server = None
        self._server_task = loop.create_task(asyncio.start_server(
                self._relay_data, listen_host, listen_port, loop=loop))
        self._server_task.add_done_callback(self._server_done_callback)
        
    def _server_done_callback(self, fut):
        try:
            self._server = fut.result()
        except asyncio.CancelledError:
            self._logger.debug('start_server() cancelled')
        except Exception as e:
            self._logger.error('Creating server failed with %r', e, 
                               exc_info=True)
        else:
            self._logger.info('StreamRelay listening on %r',
                    [s.getsockname() for s in self._server.sockets])
    @property
    def ready(self):
        return self._server_task
    
    @asyncio.coroutine
    def _relay_data(self, dreader, dwriter):
        this_task = asyncio.Task.current_task()
        self._connections.add(this_task)
        self._logger.info('Accepted downstream connection')
        ureader = uwriter = None
        try:
            ureader, uwriter = yield from self._on_connect(dreader, dwriter)
            if ureader is None or uwriter is None:
                dwriter.abort()
                return
            self._logger.info('Opened upstream connection')
            upstream_side = self._loop.create_task(self._relay_data_side(
                    dreader, uwriter))
            downstream_side = self._loop.create_task(self._relay_data_side(
                    ureader, dwriter))
            yield from asyncio.gather(upstream_side, downstream_side)
            self._logger.debug('Both sides of relay sent EOF')
        except asyncio.CancelledError:
            self._logger.debug('Connection cancelled')
            if uwriter is not None:
                uwriter.transport.abort()
            dwriter.abort()
        except Exception as e:
            # Do not print stack trace for some exceptions.
            if (isinstance(e, ConnectionError) or
                isinstance(e, OSError) and e.winerror == 121 or
                isinstance(e, ProxyNegotiationError)):
                self._logger.info('Relay error: %r', e)
            else:
                self._logger.error('Relay error: %r', e, exc_info=True)
            if uwriter is not None:
                uwriter.transport.abort()
            dwriter.transport.abort()
        finally:
            if uwriter is not None:
                uwriter.close()
            dwriter.close()
            self._logger.info('Connection closed')
            self._connections.remove(this_task)
    
    @asyncio.coroutine
    def _relay_data_side(self, reader, writer):
        while True:
            buf = yield from reader.read(self.RELAY_BUFFER_SIZE)
            if not buf:
                break
            self._logger.debug('Relay side received data')
            writer.write(buf)
            yield from writer.drain()
        self._logger.debug('Relay side received EOF')
        writer.write_eof()
        yield from writer.drain()
    
    @asyncio.coroutine
    def close(self):
        """Terminate the server and all active connections."""
        self._logger.debug('StreamRelay closing')
        self._server.close()
        for conn in self._connections:
            conn.cancel()
        yield from asyncio.gather(self._server.wait_closed(), 
                                  *self._connections,
                                  return_exceptions=True)


class ProxyNegotiator():
    """Connect to a proxy server and negotiate the connection.
    
    This class is used specifically to negotiate a connecton to a
    pluggable transport client SOCKS4/5 proxy. In particular,
    username/password authentication is used to pass per-connection
    options to the proxy instead of actual authentication.
    """
    
    PROXY_CONNECT_TIMEOUT = 3
    PROXY_NEGOTIATE_TIMEOUT = None
    
    def __init__(self, loop, proxy_host, proxy_port, remote_host, remote_port,
                 options=None, *, connect_timeout=PROXY_CONNECT_TIMEOUT,
                 negotiate_timeout=PROXY_NEGOTIATE_TIMEOUT):
        """Configure proxy negotiator.
        
        {proxy,remote}_{host,port}: self explanatory.
        
        options: a string passed to the pluggable transport in the 
        username / password fields as necessary.
        """
        self._loop = loop
        self._proxy_host = proxy_host
        self._proxy_port = proxy_port
        self._connect_timeout = connect_timeout
        self._negotiate_timeout = negotiate_timeout
        self._logger = logging.getLogger('ptadapter.ProxyNegotiator')
        self._validate_save_remote_options(remote_host, remote_port, options)
        
    def _validate_save_remote_options(self, remote_host, remote_port, options):
        """Validate and save remote_host, remote_port and options.
        
        Check the proxy type support the provided remote_host. Format options
        into the username/password fields as necessary.
        
        Child classes should implement this method.
        """
        raise NotImplementedError
        
    @asyncio.coroutine
    def open_connection(self, **kwargs):
        """Open a connection to the proxy and do negotiations.
        
        Returns (reader, writer) once negotiations are complete.
        """
        self._logger.debug('Creating new upstream connection')
        ureader = uwriter = None
        try:
            ureader, uwriter = yield from asyncio.wait_for(
                    asyncio.open_connection(
                        self._proxy_host, self._proxy_port, loop=self._loop,
                        **kwargs),
                    self._connect_timeout, loop=self._loop)
            yield from asyncio.wait_for(
                    self._negotiate_proxy(ureader, uwriter),
                    self._negotiate_timeout, loop=self._loop)
        except asyncio.CancelledError:
            self._logger.debug('New connection cancelled')
            if uwriter is not None:
                uwriter.transport.abort()
            raise
        except Exception:
            # Error messages should be printed by the calling coroutine
            # Just make sure to close the new connection here
            if uwriter is not None:
                uwriter.transport.abort()
            raise
        return (ureader, uwriter)
        
    @asyncio.coroutine
    def _negotiate_proxy(self, sreader, swriter):
        """Negotiate the proxy connection."""
        raise NotImplementedError
    
class SOCKS4Negotiator(ProxyNegotiator):
    def _validate_save_remote_options(self, remote_host, remote_port, options):
        try:
            self._remote_ip = ipaddress.IPv4Address(remote_host)
        except ipaddress.AddressValueError:
            raise ProxyConfigError('Remote host {!r} not a valid IPv4 address; '
                    'only IPv4 addresses supported for SOCKS4 pluggable '
                    'transports'.format(self.remote_host))
        self._remote_port = remote_port
        if options is not None:
            self._userid = options.encode('utf-8')
        else:
            self._userid = b''
        
    def _negotiate_proxy(self, sreader, swriter):
        self._logger.debug('Negotiating SOCKS4 proxy connection')
        swriter.write(b''.join([b'\x04\x01',
                                self._remote_port.to_bytes(2, 'big'),
                                self._remote_ip.packed,
                                self._userid,
                                b'\x00']))
        buf = yield from sreader.readexactly(8)
        if buf[0] != 0:
            raise ProxyNegotiationError(
                    'Malformed SOCKS4 reply {!r}'.format(buf))
        if buf[1] != 90:
            raise ProxyNegotiationError('SOCKS4 connect request rejected '
                    'or failed with return code {d}'.format(buf[1]))
        self._logger.debug('SOCKS4 proxy negotiation complete')

class SOCKS5Negotiator(ProxyNegotiator):
    SOCKS5_ERROR_MSG = {
        1: 'general SOCKS server failure',
        2: 'connection not allowed by ruleset',
        3: 'Network unreachable',
        4: 'Host unreachable',
        5: 'Connection refused',
        6: 'TTL expired',
        7: 'Command not supported',
        8: 'Address type not supported'}

    def _validate_save_remote_options(self, remote_host, remote_port, options):
        try:
            self._remote_ip = ipaddress.ip_address(remote_host)
        except ValueError:
            # remote_host is not a valid IPv4 or IPv6 address
            # therefore, treat as a host name
            self._remote_ip = None
            self._remote_hostname = remote_host.encode('idna')
            if len(self._remote_hostname) > 255:
                raise ProxyConfigError('Remote host name {!r} too long for '
                        'SOCKS5; only up to 255 bytes allowed'.format(
                            remote_host))
        self._remote_port = remote_port
        if not options:
            self._username = None
        else:
            userpass_b = options.encode('utf-8')
            if len(userpass_b) > 255*2:
                raise ProxyConfigError('PT options too long for SOCKS5; only '
                        '255*2 bytes allowed {!r}'.format(options))
            self._username = userpass_b[:255]
            self._password = userpass_b[255:] or b'\x00'
    
    def _negotiate_proxy(self, sreader, swriter):
        self._logger.debug('Negotiating SOCKS5 proxy connection')
        if self._username is not None:
            swriter.write(b'\x05\x01\x02')
            buf = yield from sreader.readexactly(2)
            if buf[0] != 5:
                raise ProxyNegotiationError(
                        'Malformed SOCKS5 reply {!r}'.format(buf))
            if buf[1] != 2:
                raise ProxyNegotiationError('SOCKS5 server rejected '
                        'user/pass authentication method')
            swriter.write(b''.join([b'\x01',
                                    len(self._username).to_bytes(1, 'big'),
                                    self._username,
                                    len(self._password).to_bytes(1, 'big'),
                                    self._password]))
            buf = yield from sreader.readexactly(2)
            if buf[1] != 0:
                raise ProxyNegotiationError('SOCKS5 rejected username '
                        '/ password')
        else:
            swriter.write(b'\x05\x01\x00')
            buf = yield from sreader.readexactly(2)
            if buf[0] != 5:
                raise ProxyNegotiationError(
                        'Malformed SOCKS5 reply {!r}'.format(buf))
            if buf[1] != 0:
                raise ProxyNegotiationError('SOCKS5 server rejected '
                        'none authentication method')
        self._logger.debug('SOCKS5 authentication complete')
        
        if self._remote_ip is not None:
            swriter.write(b''.join([
                    b'\x05\x01\x00',
                    b'\x01' if self._remote_ip.version==4 else b'\x04',
                    self._remote_ip.packed,
                    self._remote_port.to_bytes(2, 'big')]))
        else:
            swriter.write(b''.join([
                    b'\x05\x01\x00\x03',
                    len(self._remote_hostname).to_bytes(1, 'big'),
                    self._remote_hostname,
                    self._remote_port.to_bytes(2, 'big')]))
        
        buf = yield from sreader.readexactly(4)
        if buf[0] != 5:
            raise ProxyNegotiationError(
                    'Malformed SOCKS5 reply {!r}'.format(buf))
        if buf[1] != 0:
            raise ProxyNegotiationError('SOCKS5 connection failed with '
                    'code {}, reason: {}'.format(buf[1], 
                        self.SOCKS5_ERROR_MSG.get(buf[1], 'unspecified')))
        if buf[3] == 1: # IPv4 address
            yield from sreader.readexactly(4+2)
        elif buf[3] == 3: # hostname
            hostname_length = yield from sreader.readexactly(1)
            yield from sreader.readexactly(hostname_length + 2)
        elif buf[3] == 4: # IPv6 address
            yield from sreader.readexactly(16+2)
        else:
            raise ProxyNegotiationError(
                    'Malformed SOCKS5 reply {!r}'.format(buf))
        self._logger.debug('SOCKS5 negotiation complete')