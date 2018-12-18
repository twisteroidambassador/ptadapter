"""Adapter classes that run and control Pluggable Transports."""

import asyncio
import contextlib
import hmac
import ipaddress
import logging
import os
import os.path
import secrets
import socket
import string
import tempfile
from typing import List, Union, NamedTuple, Dict, Tuple, Optional, Callable, \
    Awaitable

from . import contexts
from . import enums
from . import log
from . import socks
from . import str_utils

__all__ = [
    'ClientAdapter',
    'ServerAdapter',
    'ExtServerAdapter',
    'ClientTransport',
    'ServerTransport',
    'ExtOrPortClientConnection',
]

AUTH_COOKIE_FILENAME = 'auth_cookie'


class ClientTransport(NamedTuple):
    """:class:`~typing.NamedTuple` describing an initialized client
    transport method."""

    scheme: str
    """The proxy scheme, either "socks4" or "socks5"."""

    host: str
    """Proxy IP address."""

    port: int
    """Proxy port."""


class ServerTransportOptions(NamedTuple):
    """:class:`~typing.NamedTuple` describing a server transport's options."""

    host: Union[None, ipaddress.IPv4Address, ipaddress.IPv6Address]
    port: Optional[int]
    options: Dict[str, str]


class ServerTransport(NamedTuple):
    """:class:`~typing.NamedTuple` describing an initialized server transport
    method."""

    host: str
    """Reverse proxy IP address."""

    port: int
    """Reverse proxy port."""

    options: Optional[str]
    """Per-transport option field returned by PT."""

    def parse_args(self) -> Dict[str, str]:
        """Parse the "ARGS" option in the *options* field into a dict.

        If the options field is not present, or it does not contain an "ARGS"
        option, return an empty dict.

        Raises:
            ValueError: if the "ARGS" option is not well-formed.
        """

        if not self.options:
            return {}
        if not self.options.startswith('ARGS:'):
            return {}
        return str_utils.parse_smethod_args(self.options[5:])


class ExtOrPortClientConnection(NamedTuple):
    """:class:`~typing.NamedTuple` describing an incoming client connection.

    In practice, PTs should provide all the information represented here, but
    the ExtOrPort specs does not explicitly require PT to provide everything,
    so there still might be cases where some of the entries are ``None``.
    """

    transport: Optional[str]
    """Name of transport used by the client."""

    host: Union[None, ipaddress.IPv4Address, ipaddress.IPv6Address]
    """IP address of the client. 
    
    Note: this is not a string, but an instance of either 
    :class:`ipaddress.IPv4Address` or :class:`ipaddress.IPv6Address`.
    Call :func:`str` on it if you need a string.
    """

    port: Optional[int]
    """Port number of the client."""


class _BasePTAdapter:
    """Base class of adapters.

    This object can be used as an async context manager. On entering the
    context, the PT is started, and on exiting the PT is stopped. The adapter
    itself is returned as the "as" variable.
    """
    _logger: logging.Logger = log.pkg_logger.getChild('adapter')
    _stdin_close_timeout = 2
    _terminate_timeout = 2
    _stdio_encoding = 'ascii'
    _kw_chars = set(string.ascii_letters + string.digits + '-_')

    def __init__(
            self,
            pt_exec: Union[List[str], List[bytes]],
            state: Union[str, bytes, os.PathLike],
            *,
            exit_on_stdin_close: bool = True,
    ) -> None:
        """Create the adapter.

        Args:
            pt_exec: The pluggable transport command line to execute. This has
                to be a list of str / bytes, since
                :func:`asyncio.create_subprocess_exec` does not accept an
                entire command line as a string. On non-Windows platforms
                :func:`shlex.split` can be used to split a command line string
                into a list, while on Windows it's a bit more complicated.
            state: The state directory. This is a directory where the PT is
                allowed to store state. Either specify a path (which
                is not required to exist, in which case the PT will create
                the directory), or specify ``None`` to use a temporary
                directory created using :mod:`tempfile`.
            exit_on_stdin_close: Whether closing the PT's STDIN indicates the
                PT should gracefully exit.
        """
        if isinstance(pt_exec, (str, bytes)):
            self._pt_args = [pt_exec]
        else:
            self._pt_args = list(pt_exec)
        if state is not None:
            self._state = os.path.abspath(state)
        else:
            self._state = None
        self._exit_on_stdin_close = exit_on_stdin_close

        self._process: asyncio.subprocess.Process = None
        self._stdout_task: asyncio.Task = None
        self._ready = asyncio.Future()
        self._accepted_version: str = None
        self._transports: Dict[str, asyncio.Future] = {}
        self._stopping = False
        self._stack = contextlib.AsyncExitStack()

    def _build_env(self) -> dict:
        env = os.environ.copy()
        env['TOR_PT_MANAGED_TRANSPORT_VER'] = '1'
        env['TOR_PT_STATE_LOCATION'] = self._state
        env['TOR_PT_EXIT_ON_STDIN_CLOSE'] = str(int(self._exit_on_stdin_close))
        return env

    async def _process_stdout(self) -> None:
        while True:
            line = await self._process.stdout.readline()
            if not line:
                break
            self._logger.debug('PT stdout: %r', line)
            try:
                line = line.decode(self._stdio_encoding)
                kw, _, optargs = line.strip().partition(' ')
                if not all(c in self._kw_chars for c in kw):
                    raise RuntimeError(
                        f'Invalid keyword {kw!r} in PT stdout line: {line!r}')
                if '\0' in optargs:
                    raise RuntimeError(
                        f'NUL character in PT stdout line: {line!r}')
                self._process_stdout_line(kw, optargs)
            except Exception as e:
                self._logger.error(
                    'Error processing PT stdout line: %r', line, exc_info=True)
                if not self._ready.done():
                    self._ready.set_exception(e)
                continue
        self._logger.debug('PT stdout at EOF')

    def _process_stdout_line(
            self,
            kw: str,
            optargs: str,
    ) -> None:
        if kw == 'VERSION-ERROR':
            raise RuntimeError(f'PT VERSION-ERROR: {optargs!r}')
        elif kw == 'VERSION':
            assert self._accepted_version is None
            self._accepted_version = optargs
            self._logger.debug('PT accepted version %r', optargs)
        elif kw == 'ENV-ERROR':
            raise RuntimeError(f'PT ENV-ERROR: {optargs!r}')
        else:
            self._logger.info(
                f'PT stdout unknown keyword {kw!r}; optargs {optargs!r}')

    def _check_not_started(self) -> None:
        if self._process:
            raise asyncio.InvalidStateError('PT has already started')

    def _check_started(self) -> None:
        if not self._process:
            raise asyncio.InvalidStateError('PT has not yet started')

    def _check_running(self) -> None:
        self._check_started()
        if self._stopping:
            raise asyncio.InvalidStateError('PT is stopping or has stopped')

    @property
    def state(self) -> Optional[str]:
        """The state directory.

        If a temporary directory is used, this will be ``None`` before the
        adapter starts, and will be the actual path of the directory after
        the adapter has started. The temporary directory will be deleted
        once the adapter is stopped.
        """
        return self._state

    async def _pre_start(self) -> None:
        if self._state is None:
            self._state = self._stack.enter_context(
                tempfile.TemporaryDirectory(prefix=__package__ + '_state_'))
            self._logger.debug('Created tempdir for state: %s', self._state)

    async def start(self) -> None:
        """(async) Start the PT executable and wait until it's ready.

        "Ready" means that all transports have finished initializing.
        """
        self._check_not_started()
        await self._pre_start()
        env = self._build_env()
        self._logger.debug('PT environment variables: %r', env)
        self._process = await asyncio.create_subprocess_exec(
            *self._pt_args,
            env=env,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=None,
        )
        self._logger.debug('Started PT subprocess: %r', self._process)
        self._stdout_task = asyncio.create_task(self._process_stdout())
        try:
            await self._ready
        except Exception:
            await self.stop()
            raise

    async def stop(self) -> None:
        """(async) Stop the PT executable.

        First try to signal a graceful exit by closing PT's STDIN (if
        enabled) and wait, then call
        :meth:`~asyncio.asyncio.subprocess.Process.terminate` and wait,
        then call
        :meth:`~asyncio.asyncio.subprocess.Process.kill`.
        """
        # Why does cross referencing asyncio.subprocess need
        # "asyncio.asyncio.subprocess"?
        self._check_running()
        self._stopping = True
        try:
            if self._exit_on_stdin_close:
                self._logger.debug('Closing PT stdin')
                self._process.stdin.close()
                try:
                    await asyncio.wait_for(
                        self._process.wait(), self._stdin_close_timeout)
                    self._logger.debug('PT exited after closing stdin')
                    return
                except asyncio.TimeoutError:
                    pass
            try:
                self._logger.debug('Terminating PT')
                self._process.terminate()
                try:
                    await asyncio.wait_for(
                        self._process.wait(), self._terminate_timeout)
                    self._logger.debug('PT exited after calling terminate()')
                    return
                except asyncio.TimeoutError:
                    pass
                self._logger.warning('Calling kill() on PT')
                self._process.kill()
                await self._process.wait()
            except ProcessLookupError:
                self._logger.info('PT process already exited')
        finally:
            await self._stack.aclose()

    async def wait(self) -> None:
        """(async) Block until the PT process exit."""
        self._check_started()
        await self._process.wait()

    async def __aenter__(self):
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.stop()


class ClientAdapter(_BasePTAdapter):
    """Run a pluggable transport as client.

    For each enabled transport, the PT will listen on a port, which can be
    looked up using :meth:`get_transport`.
    Use :meth:`open_transport_connection` to make a connection through a
    transport.

    This object can be used as an async context manager. On entering the
    context, the PT is started, and on exiting the PT is stopped. The adapter
    itself is returned as the "as" variable.
    """

    def __init__(
            self,
            pt_exec: Union[List[str], List[bytes]],
            state: Union[None, str, bytes, os.PathLike],
            transports: List[str],
            proxy: str = None,
            *,
            exit_on_stdin_close: bool = True,
    ) -> None:
        """Create the adapter.

        Args:
            pt_exec: The pluggable transport command line to execute. This has
                to be a list of str / bytes, since
                :func:`asyncio.create_subprocess_exec` does not accept an
                entire command line as a string. On non-Windows platforms
                :func:`shlex.split` can be used to split a command line string
                into a list, while on Windows it's a bit more complicated.
            state: The state directory. This is a directory where the PT is
                allowed to store state. Either specify an absolute path (which
                is not required to exist, in which case the PT will create
                the directory), or specify ``None`` to use a temporary
                directory created using :mod:`tempfile`.
            transports: a list of client transports the PT should initialize.
                PTs will ignore names they don't recognize.
            proxy: The upstream proxy to use. Must be specified in the URI
                format:
                ``<proxy_type>://[<user_name>[:<password>][@]<ip>:<port>``.
            exit_on_stdin_close: Whether closing the PT's STDIN indicates the
                PT should gracefully exit.
        """
        super().__init__(
            pt_exec, state, exit_on_stdin_close=exit_on_stdin_close)
        for transport in transports:
            str_utils.validate_transport_name(transport)
            self._transports[transport] = asyncio.Future()
        self._proxy = proxy

    def _build_env(self) -> dict:
        env = super()._build_env()
        env['TOR_PT_CLIENT_TRANSPORTS'] = ','.join(self._transports.keys())
        if self._proxy is not None:
            env['TOR_PT_PROXY'] = self._proxy
        else:
            env.pop('TOR_PT_PROXY', None)
        return env

    def _process_stdout_line(
            self,
            kw: str,
            optargs: str,
    ) -> None:
        if kw == 'PROXY-ERROR':
            raise RuntimeError(f'PT PROXY-ERROR: {optargs!r}')
        elif kw == 'PROXY':
            assert optargs == 'DONE'
            self._logger.debug('PT upstream proxy accepted')
        elif kw == 'CMETHOD-ERROR':
            transport, _, message = optargs.partition(' ')
            self._transports[transport].set_exception(
                RuntimeError(f'CMETHOD-ERROR: {message!r}'))
        elif kw == 'CMETHOD':
            transport, scheme, hostport = optargs.split(' ', 2)
            result = ClientTransport(
                scheme, *str_utils.parse_hostport(hostport))
            self._transports[transport].set_result(result)
        elif kw == 'CMETHODS':
            assert optargs == 'DONE'
            assert not self._ready.done()
            self._ready.set_result(None)
            self._logger.debug('PT initialization complete')
            for fut in self._transports.values():
                if not fut.done():
                    fut.set_exception('PT ignored transport')
        else:
            super()._process_stdout_line(kw, optargs)

    async def open_transport_connection(
            self,
            transport: str,
            host: Union[str, ipaddress.IPv4Address, ipaddress.IPv6Address],
            port: int,
            args: Optional[Dict[str, str]],
            **kwargs,
    ) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """(async) Open a connection through a client transport.

        This method uses :meth:`get_transport` and
        :func:`asyncio.open_connection`, and their exceptions will not be
        modified. Additional possible exceptions are listed below.

        Args:
            transport: Name of the transport.
            host: Destination IP address or host name. Depending on the PT,
                host names or IPv6 addresses may not be supported.
            port: Destination port number.
            args: Per-connection arguments. Both keys and values should be
                strings. (Backslash, equal signs and semicolons will be
                automatically escaped before passing to PT.)
            kwargs: Any unrecognized keyword arguments are passed to
                :meth:`asyncio.open_connection`. This can be useful for
                specifying *limit* and *local_addr*.

        Returns:
            A (:class:`~asyncio.StreamReader`, :class:`~asyncio.StreamWriter`)
            tuple.

        Raises:
            RuntimeError: If the PT violates PT-spec or SOCKS proxy protocols.
            ValueError: If *host*, *port* or *args* are invalid.
            exceptions.PTConnectError: If the PT reports an error while
                connecting to the destination.
        """
        transport_info = self.get_transport(transport)
        reader, writer = await asyncio.open_connection(
            transport_info.host, transport_info.port, **kwargs)
        if transport_info.scheme == 'socks5':
            await socks.negotiate_socks5_userpass(
                reader, writer, host, port, args)
        elif transport_info.scheme == 'socks4':
            await socks.negotiate_socks4_userid(
                reader, writer, host, port, args)
        else:
            raise RuntimeError(f'Invalid scheme {transport_info.scheme!r}')
        return reader, writer

    def get_transport(self, transport: str) -> ClientTransport:
        """Look up initialized client transport methods.

        Args:
            transport: Name of the transport.

        Returns:
            A :class:`ClientTransport` NamedTuple for the specified transport.

        Raises:
            KeyError: If the specified transport was not provided when calling
                :meth:`__init__`.
            asyncio.InvalidStateError: If PT has not yet started, or if the
                transport is not yet initialized.
            RuntimeError: If the PT returned an error while initializing the
                specified transport.
        """
        self._check_running()
        return self._transports[transport].result()


class _BaseServerAdapter(_BasePTAdapter):
    def __init__(
            self,
            pt_exec: Union[List[str], List[bytes]],
            state: Union[None, str, bytes, os.PathLike],
            *,
            exit_on_stdin_close: bool = True,
    ) -> None:
        super().__init__(
            pt_exec, state, exit_on_stdin_close=exit_on_stdin_close)
        self._transport_opts: Dict[str, ServerTransportOptions] = {}

    def add_transport(
            self,
            transport: str,
            host: Union[None,
                        str,
                        ipaddress.IPv4Address,
                        ipaddress.IPv6Address],
            port: Optional[int],
            options: Dict[str, str] = None,
    ) -> None:
        """Add a server transport.

        This can only be called before PT starts. Unlike when running as
        client, PTs only support one tunnel per transport when running as
        server. Calling this with the same *transport* again will overwrite
        the previous entry.

        Args:
            transport: The transport name. PT will ignore names it does not
                recognize.
            host: The IP address to listen on. This must not be a host name.
                *host* and *port* must be either specified at the same time,
                or set to ``None`` at the same time.
            port: The port number to listen on.
            options: Transport options.
        """
        self._check_not_started()
        str_utils.validate_transport_name(transport)
        if host is not None and port is not None:
            host = ipaddress.ip_address(host)
        elif not (host is None and port is None):
            raise ValueError('Specifying only one of (host, port) not allowed')
        self._transport_opts[transport] = ServerTransportOptions(
            host, port, options)

    def _build_env(self) -> dict:
        env = super()._build_env()
        transport_names = []
        transport_options = []
        transport_addrs = []

        for tname, topts in self._transport_opts.items():
            self._transports[tname] = asyncio.Future()
            transport_names.append(tname)
            if topts.host is not None:
                # topts.port is guaranteed not None
                host = topts.host.compressed
                if topts.host.version == 6:
                    host = f'[{host}]'
                transport_addrs.append(f'{tname}-{host}:{topts.port}')
            if topts.options:
                for key, value in topts.options:
                    key = str_utils.escape_server_options(key)
                    value = str_utils.escape_server_options(value)
                    transport_options.append(f'{tname}:{key}={value}')

        env['TOR_PT_SERVER_TRANSPORTS'] = ','.join(transport_names)
        # pt-spec Section 3.2.3:
        # If there are no arguments that need to be passed to any of
        # PT transport protocols, "TOR_PT_SERVER_TRANSPORT_OPTIONS"
        # MAY be omitted.
        # And likewise for TOR_PT_SERVER_BINDADDR.
        # However, I have decided to include it even when empty, so as to
        # not accidentally inherit these environmental variables.
        env['TOR_PT_SERVER_TRANSPORT_OPTIONS'] = ';'.join(transport_options)
        env['TOR_PT_SERVER_BINDADDR'] = ','.join(transport_addrs)
        return env

    def _process_stdout_line(
            self,
            kw: str,
            optargs: str,
    ) -> None:
        if kw == 'SMETHOD-ERROR':
            transport, _, message = optargs.partition(' ')
            self._transports[transport].set_exception(
                RuntimeError(f'SMETHOD-ERROR: {message!r}'))
        elif kw == 'SMETHOD':
            transport, _, remaining = optargs.partition(' ')
            addrport, _, options = remaining.partition(' ')
            host, port = str_utils.parse_hostport(addrport)
            if not options:
                options = None
            result = ServerTransport(host, port, options)
            self._transports[transport].set_result(result)
        elif kw == 'SMETHODS':
            assert optargs == 'DONE'
            assert not self._ready.done()
            self._ready.set_result(None)
            self._logger.debug('PT initialization complete')
            for fut in self._transports.values():
                if not fut.done():
                    fut.set_exception('PT ignored transport')
        else:
            super()._process_stdout_line(kw, optargs)

    def get_transport(self, transport: str) -> ServerTransport:
        """Look up initialized server transport methods.

        Args:
            transport: Name of the transport.

        Returns:
            A :class:`ServerTransport` NamedTuple for the specified transport.

        Raises:
            KeyError: If the specified transport was not provided when calling
                :meth:`__init__`.
            asyncio.InvalidStateError: If PT has not yet started, or if the
                transport is not yet initialized.
            RuntimeError: If the PT returned an error while initializing the
                specified transport.
        """
        self._check_running()
        return self._transports[transport].result()


class ServerAdapter(_BaseServerAdapter):
    """Run a pluggable transport as server.

    For each enabled transport, the PT will listen on a port, which can be
    either specified or left auto-assigned, and looked up using
    :meth:`get_transport`. The PT will forward unobfuscated traffic directly
    to *forward_host*:*forward_port*.

    This object can be used as an async context manager. On entering the
    context, the PT is started, and on exiting the PT is stopped. The adapter
    itself is returned as the "as" variable.
    """

    def __init__(
            self,
            pt_exec: Union[List[str], List[bytes]],
            state: Union[None, str, bytes, os.PathLike],
            forward_host: Union[str,
                                ipaddress.IPv4Address,
                                ipaddress.IPv6Address],
            forward_port: int,
            *,
            exit_on_stdin_close: bool = True,
    ) -> None:
        """Create the adapter.

        Args:
            pt_exec: The pluggable transport command line to execute. This has
                to be a list of str / bytes, since
                :func:`asyncio.create_subprocess_exec` does not accept an
                entire command line as a string. On non-Windows platforms
                :func:`shlex.split` can be used to split a command line string
                into a list, while on Windows it's a bit more complicated.
            state: The state directory. This is a directory where the PT is
                allowed to store state. Either specify a path (which
                is not required to exist, in which case the PT will create
                the directory), or specify ``None`` to use a temporary
                directory created using :mod:`tempfile`. For servers, using
                an actual persistent location is recommended.
            forward_host: IP address or host name to forward unobfuscated
                traffic to.
            forward_port: Port number to forward unobfuscated traffic to.
            exit_on_stdin_close: Whether closing the PT's STDIN indicates the
                PT should gracefully exit.
        """
        super().__init__(
            pt_exec, state, exit_on_stdin_close=exit_on_stdin_close)
        self._orport_host = forward_host
        self._orport_port = forward_port

    def _build_env(self) -> dict:
        env = super()._build_env()
        env['TOR_PT_ORPORT'] = str_utils.join_hostport(
            self._orport_host, self._orport_port)
        # pt-spec Section 3.2.3 says:
        # If the parent process does not support the ExtORPort protocol,
        # it MUST set "TOR_PT_EXTENDED_SERVER_PORT" to an empty string.
        env['TOR_PT_EXTENDED_SERVER_PORT'] = ''
        env.pop('TOR_PT_AUTH_COOKIE_FILE', None)
        return env


class SafeCookieServerAuthenticator:
    cookie_len = 32
    nonce_len = 32
    digest = 'sha256'
    hash_len = hmac.new(b'', digestmod=digest).digest_size
    assert hash_len == 32

    cookie_static_header = b'! Extended ORPort Auth Cookie !\x0a'
    server_hash_header = b'ExtORPort authentication server-to-client hash'
    client_hash_header = b'ExtORPort authentication client-to-server hash'

    def __init__(self):
        self._cookie = secrets.token_bytes(self.cookie_len)

    def hash(self, msg: bytes) -> bytes:
        return hmac.digest(self._cookie, msg, self.digest)

    def write_cookie_file(self, filename: str) -> None:
        with open(filename, 'wb') as f:
            f.write(self.cookie_static_header)
            f.write(self._cookie)

    async def authenticate(
            self,
            reader: asyncio.StreamReader,
            writer: asyncio.StreamWriter,
    ) -> bool:
        """(async) Authenticate a connecting client.

        Returns:
            True if authentication is successful and False otherwise. The
            caller is responsible for closing the connection in case of
            failure.
        """
        writer.write(enums.ExtOrPortAuthTypes.SAFE_COOKIE
                     + enums.ExtOrPortAuthTypes.END_AUTH_TYPES)
        client_auth_type = await reader.readexactly(1)
        if client_auth_type != enums.ExtOrPortAuthTypes.SAFE_COOKIE:
            return False
        client_nonce = await reader.readexactly(self.nonce_len)
        server_nonce = secrets.token_bytes(self.nonce_len)
        server_hash = self.hash(b''.join((
            self.server_hash_header, client_nonce, server_nonce)))
        writer.write(server_hash + server_nonce)
        client_hash = await reader.readexactly(self.hash_len)
        result = hmac.compare_digest(client_hash, self.hash(b''.join((
            self.client_hash_header, client_nonce, server_nonce))))
        writer.write(int(result).to_bytes(1, 'big'))
        return result


class ExtServerAdapter(_BaseServerAdapter):
    """Run a pluggable transport as server.

    For each enabled transport, the PT will listen on a port, which can be
    either specified or left auto-assigned, and looked up using
    :meth:`get_transport`. The PT will connect to the adapter using the
    ExtOrPort protocol, and a callback will be invoked.

    This object can be used as an async context manager. On entering the
    context, the PT is started, and on exiting the PT is stopped. The adapter
    itself is returned as the "as" variable.
    """

    def __init__(
            self,
            pt_exec: Union[List[str], List[bytes]],
            state: Union[None, str, bytes, os.PathLike],
            client_connected_cb: Callable[
                [asyncio.StreamReader,
                 asyncio.StreamWriter,
                 ExtOrPortClientConnection],
                Awaitable[None],
            ],
            *,
            preconnect_cb: Callable[
                [ExtOrPortClientConnection],
                Awaitable[bool],
            ] = None,
            auth_cookie_file: Union[str, bytes, os.PathLike] = None,
            ext_host: str = 'localhost',
            ext_port: int = 0,
            ext_family: int = socket.AF_UNSPEC,
            exit_on_stdin_close: bool = True,
    ) -> None:
        """Create the adapter.

        Args:
            pt_exec: The pluggable transport command line to execute. This has
                to be a list of str / bytes, since
                :func:`asyncio.create_subprocess_exec` does not accept an
                entire command line as a string. On non-Windows platforms
                :func:`shlex.split` can be used to split a command line string
                into a list, while on Windows it's a bit more complicated.
            state: The state directory. This is a directory where the PT is
                allowed to store state. Either specify a path (which
                is not required to exist, in which case the PT will create
                the directory), or specify ``None`` to use a temporary
                directory created using :mod:`tempfile`. For servers, using
                an actual persistent location is recommended.
            client_connected_cb: Async callback function called to handle
                incoming client connections. It will be called with three
                arguments: *(reader, writer, connection_info)*, where
                *reader* and *writer* are a :class:`~asyncio.StreamReader`,
                :class:`~asyncio.StreamWriter` pair,
                and *connection_info* is a :class:`ExtOrPortClientConnection`
                containing information on the connecting client.
            preconnect_cb: Optional async callback function called before
                *client_connect_cb*, where an incoming connection can be
                rejected. It will be called with a single argument of
                :class:`ExtOrPortClientConnection` containing information on
                the connecting client, and should return a boolean, where
                ``True`` means to allow the connection and ``False`` means
                to reject.
            auth_cookie_file: Path to the ExtOrPort authentication cookie file.
                If specified, this should be a path + filename to a
                writable location that is not readable by other users. If
                unspecified, a temporary directory is created using
                :mod:`tempfile`, and the cookie file created inside.
            ext_host: IP address / host name to bind ExtOrPort to. The ExtOrPort
                is used internally between the PT and the adapter, so this
                should be a loopback address.
            ext_port: Port number to bind ExtOrPort to. ``0`` means a random
                ephemeral port.
            ext_family: The ``family`` flag passed while binding ExtOrPort.
                :data:`socket.AF_INET` or :data:`socket.AF_INET6`
                can be passed to restrict ExtOrPort to IPv4 or IPv6
                respectively.
            exit_on_stdin_close: Whether closing the PT's STDIN indicates the
                PT should gracefully exit.
        """
        super().__init__(
            pt_exec, state, exit_on_stdin_close=exit_on_stdin_close)
        if auth_cookie_file is not None:
            self._auth_cookie_file = os.path.abspath(auth_cookie_file)
        else:
            self._auth_cookie_file = None
        self._cb = client_connected_cb
        self._preconnect_cb = preconnect_cb
        self._ext_host = ext_host
        self._ext_port = ext_port
        self._ext_family = ext_family

        self._authenticator = SafeCookieServerAuthenticator()
        self._server = None

    async def _pre_start(self) -> None:
        await super()._pre_start()
        if self._auth_cookie_file is None:
            cookie_dir = self._stack.enter_context(
                tempfile.TemporaryDirectory(
                    prefix=__package__ + '_authcookie_'))
            self._auth_cookie_file = os.path.join(
                cookie_dir, AUTH_COOKIE_FILENAME)
        self._authenticator.write_cookie_file(self._auth_cookie_file)
        self._server = await asyncio.start_server(
            self._ext_or_port_handler, self._ext_host, self._ext_port,
            family=self._ext_family)
        await self._stack.enter_async_context(self._server)

    @staticmethod
    async def _read_ext_msg(
            reader: asyncio.StreamReader,
    ) -> Tuple[bytes, bytes]:
        command = await reader.readexactly(2)
        body_len = int.from_bytes(await reader.readexactly(2), 'big')
        body = await reader.readexactly(body_len)
        return command, body

    @staticmethod
    async def _write_ext_msg(
            writer: asyncio.StreamWriter,
            command: bytes,
            body: bytes,
    ) -> None:
        assert len(command) == 2
        body_len = len(body).to_bytes(2, 'big')
        writer.write(command + body_len + body)
        await writer.drain()

    async def _ext_or_port_handler(
            self,
            reader: asyncio.StreamReader,
            writer: asyncio.StreamWriter,
    ) -> None:
        # This callback function should not close writer when exiting. After
        # all, the API consumer may decide to stash reader and writer somewhere
        # for use later and return from their supplied callback function early.
        async with contexts.log_unhandled_exc(self._logger):
            try:
                auth_result = await self._authenticator.authenticate(
                    reader, writer)
            except (OSError, asyncio.IncompleteReadError) as e:
                self._logger.warning(
                    'Error during ExtOrPort SafeCookie authentication: %r', e)
                return
            if not auth_result:
                self._logger.warning(
                    'ExtOrPort SafeCookie authentication failed')
                return
            transport = host = port = None
            while True:
                command, body = await self._read_ext_msg(reader)
                if command == enums.ExtOrPortCommand.DONE:
                    break
                elif command == enums.ExtOrPortCommand.USERADDR:
                    host, port = str_utils.parse_hostport(body.decode('ascii'))
                    host = ipaddress.ip_address(host)
                elif command == enums.ExtOrPortCommand.TRANSPORT:
                    transport = body.decode('ascii')
                    str_utils.validate_transport_name(transport)
                else:
                    self._logger.info(
                        'Received unknown ExtOrPort command %r, body %r',
                        command, body)
            connection_info = ExtOrPortClientConnection(transport, host, port)
            if self._preconnect_cb is not None:
                accept = await self._preconnect_cb(connection_info)
            else:
                accept = True
            if not accept:
                await self._write_ext_msg(
                    writer, enums.ExtOrPortReply.DENY, b'')
                writer.write_eof()
                return
            await self._write_ext_msg(writer, enums.ExtOrPortReply.OKAY, b'')

            await self._cb(reader, writer, connection_info)

    def _build_env(self) -> dict:
        env = super()._build_env()
        env.pop('TOR_PT_ORPORT', None)
        env['TOR_PT_EXTENDED_SERVER_PORT'] = str_utils.join_hostport(
            *self._server.sockets[0].getsockname()[:2])
        env['TOR_PT_AUTH_COOKIE_FILE'] = self._auth_cookie_file
        return env
