ptadapter Developer Guide
#########################

The ptadapter module provides several classes to interface with Pluggable
Transports.
:class:`~ptadapter.ClientAdapter` controls a PT client, and can be used to
initiate an obfuscated connection towards a PT server;
:class:`~ptadapter.ServerAdapter` and :class:`~ptadapter.ExtServerAdapter`
controls a PT server, and can be used to receive obfuscated
connection from a PT client.


Common aspects
==============

**Note**: Since ptadapter runs the PT as a subprocess, on Windows platforms
a :class:`~asyncio.ProactorEventLoop` should be used, instead of the default
:class:`~asyncio.SelectorEventLoop`.
To set :class:`~asyncio.ProactorEventLoop` as default::

    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

There are several common arguments when initializing any of the ``*Adapter``
classes:

* ``pt_exec`` is the command line of the PT executable, optionally including
  arguments. This must be a List of ``str`` or ``bytes``, where the first
  element is the path + filename of the executable, and each subsequent element
  is a command line argument. This is the same style as used by the
  :mod:`subprocess` module.

* ``state`` is the path of the PT's state directory. The PT specification
  requires that if the PT saves data, it must be saved in the state directory.
  A location writable by the PT should be specified; if it does not
  exist, the PT will try to create it. Alternatively, ``None`` can be specified,
  in which case a temporary directory will be created as the state directory
  before starting the PT, and deleted once the PT exits.

* ``exit_on_stdin_close`` can usually be left unspecified.


Instances of the ``*Adapter`` classes can be used as async context managers,
like this::

    async with ptadapter.ClientAdapter(...) as adapter:
        # The PT is automatically started

        reader, writer = await adapter.open_transport_connection(...)
        # ... use the adapter, etc.

    # once exiting the `async with` block, the PT is stopped


PT Client
=========

When initializing a :class:`~ptadapter.ClientAdapter`,
a list of transport method names are required,
but not individual upstream destinations or per-connection arguments.
These arguments are specified when making a connection.

::

    # It's possible to add command line arguments
    pt_exec = ['/usr/bin/obfs4proxy', '-enableLogging']
    state = '/var/run/obfs4-state'
    transports = ['obfs4', 'obfs3']
    # An optional upstream proxy server can be specified
    proxy = 'socks5://127.0.0.1:1080'

    async with ptadapter.ClientAdapter(pt_exec, state, transports, proxy=proxy) as adapter:
        # connect to an upstream
        args = {'cert': '...'}
        reader, writer = await adapter.open_transport_connection('obfs4', '127.0.0.1', 7900, args)
        # use reader and writer as usual


PT Server
=========

There are two classes providing PT server functionality:
:class:`~ptadapter.ServerAdapter` and :class:`~ptadapter.ExtServerAdapter`.

With :class:`~ptadapter.ServerAdapter`, when each obfuscated connection is
received, an unobfuscated connection is made to a TCP address:port specified
by you. This is mostly useful for forwarding unobfuscated traffic to something
else, although if you would like to receive the connections, you could simply
listen on a port and direct unobfuscated traffic there.

With :class:`~ptadapter.ExtServerAdapter`, when each obfuscated connection is
received, an async callback function is called where you
can handle the incoming connection. There is also a "pre-connect callback",
where you are provided with client info and can deny the connection quickly.
This class is more useful when you want to handle incoming connections.

The main callback function is called with 3 arguments:
a :class:`~asyncio.StreamReader`, a :class:`~asyncio.StreamWriter`, and a
:class:`ptadapter.ExtOrPortClientConnection` Named Tuple containing information
about the connecting client.

The pre-connect callback is called with a single argument, a
:class:`ptadapter.ExtOrPortClientConnection`, and should return a boolean value.
If ``False`` is returned, then this connection will be terminated, and the
main callback will not be called.

In both these callbacks, the provided
:class:`ptadapter.ExtOrPortClientConnection` Named Tuple has 3 elements:

* *transport* is the name of the transport method the client is connecting
  through;

* *host* is an instance of :class:`ipaddress.IPv4Address` or
  :class:`ipaddress.IPv6Address` containing the peer address of the client;

* *port* is the peer address port number of the client.


As an example, to write a server that only allows connection from localhost::

    pt_exec = ['/usr/bin/obfs4proxy', '-enableLogging']
    state = '/var/run/obfs4-state'
    obfs4_args = {
        'node-id': ...,
        'public-key': ...,
        ...
    }

    async def pre_connect_cb(info):
        # in pre-connect callback, allow connections from loopback addresses,
        # and deny all others
        if info.host.is_loopback:
            return True
        return False

    async def connect_cb(reader, writer, info):
        # this is the main connection callback
        ...


    adapter = ptadapter.ExtServerAdapter(pt_exec, state, connect_cb, preconnect_cb=pre_connect_cb)
    adapter.add_transport('obfs4', '127.0.0.1', 7900, obfs4_args)
    adapter.add_transport('obfs3', '127.0.0.1', 7901)

    async with adapter:
        # now the PT is accepting connections
        await adapter.wait()
