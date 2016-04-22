This repository is home to Pluggable Transport Adapter, a Python 3 package that 
interfaces with Tor's pluggable transports, and obfs4-standalone-tunnel, a set 
of scripts to run pluggable transports as TCP tunnel.

**This project REQUIRES Python 3.4 or higher.** It only depends on the standard
library, not on any optional packages.

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

This package requires Python 3.4 or higher.

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

* Python 3.4 or higher for your operating system.

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
