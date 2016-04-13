This repository is home to Pluggable Transport Adapter, a Python 3 package that 
interfaces with Tor's pluggable transports, and obfs4-standalone-tunnel, a set 
of scripts to run pluggable transports as TCP tunnel.

## Motivation
The motivation for this project comes from the desire of running 
[`obfs4proxy`](https://github.com/Yawning/obfs4/tree/master/obfs4proxy) 
independently of Tor. `obfs4proxy` [does not have a standalone mode]
(https://lists.torproject.org/pipermail/tor-relays/2014-September/005372.html), 
so I implemented enough of [Tor's pluggable transport specification]
(https://gitweb.torproject.org/torspec.git/tree/pt-spec.txt "pt-spec.txt") to 
support standalone operation as server or client, in a way that's hopefully 
reusable for other projects.

# pluggabletransportadapter

This package implements Tor's pluggable transport protocol, in order to run 
and control pluggable transports (PT).

This package requires Python 3, and optionally 
[`rsocks`](https://pypi.python.org/pypi/rsocks/0.2.2) 
(only for `PluggableTransportClientTCPAdapter`).

It implements 3 classes: `PluggableTransportServerAdapter`, 
`PluggableTransportClientSOCKSAdapter` and `PluggableTransportClientTCPAdapter`.

`PluggableTransportServerAdapter` runs PT executable as a server, listening on
a TCP port for obfuscated traffic and forwards plaintext traffic to a given
address:port.

`PluggableTransportClientSOCKSAdapter` runs PT executable as a client, where the
PT listens on address:port of its choice, accepts either SOCKS4 or SOCKS5 
connection attempts, obfuscates the traffic and forwards it to a server.

`PluggableTransportClientTCPAdapter` runs PT executable as a client and 
additionally handles SOCKS reverse proxying, accepting plaintext traffic 
directly on a TCP address:port.

`code-example.py` is provided as a usage sample of the ServerAdapter
and ClientTCPAdapter. `config-example.json` is the accompanying config file. 
Just drop a binary of `obfs4proxy` in the same directory and run
`python3 code-example.py config-example.json`. `obfs3` and `obfs4` tunnels will
be established between server 127.0.0.1:7000 and clients 127.0.0.1:8000/8001/8002.

# obfs4-standalone-tunnel

The two scripts, `standalone_server.py` and `standalone_client.py`, are wrappers
around the `pluggabletransportadapter` libary. They allow running pluggable 
transports such as `obfs4proxy` as standalone servers and clients, creating
obfuscated tunnels carrying TCP traffic.

## Requirements

To use these scripts, you'll need:

* The scripts themselves. Check the
[Releases section](https://github.com/twisteroidambassador/pluggabletransportadapter/releases)
for archives containing only the essentials, or do a `git checkout` for everything.

* A compiled binary of the pluggable transport you wish to use. On many Linux
distributions you can install them from the package repository. For Windows, it
might be easiest to extract the binary from Tor Browser Bundle.

* Python 3 for your operating system.

* For the client, [`rsocks`](https://pypi.python.org/pypi/rsocks/0.2.2). Install
it with `pip`.

## Configuration

The provided config files are commented in detail, and intended for testing.
Follow them to write your own config files, but do not use them as-is.

In particular, these provided files contain
matching keys so an `obfs4` clients can authenticate and talk to the server. 
**DO NOT use those keys for your own servers!** For `obfs4`, you *do not* need to
specify keys in the configuration file. Just make sure the states directory is
persistent and writable. After first run, the server will save its keys to the
states directory and read it from there for future runs. It will also write the
appropriate client parameters there.

# Ideas for future work

`rsocks` isn't as portable as I'd like. It depends on `eventlet`, which in turn
depends on `greenlet`, which is "provided as a C extension module for the 
regular unmodified interpreter." Therefore, it is not possible to create a truly
standalone bundle of Python scripts that will run with nothing but the Python 
intepreter + standard libraries. This isn't a problem with full-blown OSes since
`pip` is now included with Python, but it makes deployment on stripped-down OSes
like OpenWrt difficult.

Rewriting the TCP adapter to get rid of the `rsocks` dependency may make deployment
easier. However, if some kind of asynchronous event library is not used, performance
may suffer. Perhaps this is a good place to use Python's new `asyncio` package 
(is it included in OpenWrt's base Python 3 package?)
