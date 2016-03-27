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

Documentation WIP. Use `standalone-server.py` for server and 
`standalone-client.py` for client. Also see respective `-config.ini` files for 
commented example configurations.
