**Complete rewrite!**

The old code was written for compatibility with Python 3.4, and seemed
to have stopped working when Python 3.7 came out. So I have completely
rewritten the entire package using Python 3.7 idioms.

All the code is here, with inline documentation. PyPI package,
online docs and a new README coming soon. In the mean time, download
the source and try it out:

```
python -m ptadapter --help
```

**The old, outdated README follows.**



This repository is home to Pluggable Transport Adapter, a Python 3 package that
interfaces with Tor's pluggable transports, plus a script to run pluggable 
transports as TCP tunnel.

**This project REQUIRES Python 3.4.2 or higher.** Other than the standard 
library, it has no dependencies.

## Motivation
The motivation for this project comes from the desire of running 
[`obfs4proxy`](https://github.com/Yawning/obfs4/tree/master/obfs4proxy) 
independently of Tor. `obfs4proxy` [does not have a standalone mode]
(https://lists.torproject.org/pipermail/tor-relays/2014-September/005372.html), 
so I implemented enough of [Tor's pluggable transport specification]
(https://gitweb.torproject.org/torspec.git/tree/pt-spec.txt "pt-spec.txt") to 
support standalone operation as server or client, in a way that's hopefully 
reusable for other projects.

# ptadapter

The package used to be called `pluggabletransportadapter`, but that name is 
rather long and cumbersome, so it has been renamed to the shorter version.

This package implements Tor's pluggable transport protocol, in order to run 
and control pluggable transports (PT).

This package requires Python 3.4.2 or higher.

These classes are implemented: `PTServerAdapter`, `PTClientSOCKSAdapter`, 
`PTClientStreamAdapter`, `PTClientListeningAdapter`.

`PTServerAdapter` runs PT executable as a server, listening on TCP ports for 
obfuscated traffic and forwards plaintext traffic to a given address:port. 
Obfuscated traffic hit the PT executable directly, and unobfuscated traffic
is emitted by the PT executable; the script has no idea about client 
connections.

`PTClientSOCKSAdapter` runs PT executable as a client, where the PT listens on 
an address:port of its choice, accepts either SOCKS4 or SOCKS5 connection 
attempts, obfuscates the traffic and forwards it to a server.

`PTClientStreamAdapter` does what `PTClientSOCKSAdapter` does, and provides 
convenient methods for creating StreamReader/Writer pairs that talks through the
PT.

`PTClientListeningAdapter` does what `PTClientStreamAdapter` does. In addition
it listens for plaintext traffic on a TCP address:port and forwards them 
through the PT.

# The script

The script `standalone.py` allows running pluggable transports such as 
`obfs4proxy` as standalone servers and clients. Run one copy as client and
another as server to create obfuscated tunnels.

## Requirements

To use these scripts, you'll need:

* The scripts themselves. Check the
[Releases section](https://github.com/twisteroidambassador/pluggabletransportadapter/releases)
to download a zip package, or just checkout with git.

* A compiled binary of the pluggable transport you wish to use. On many Linux
distributions you can install them from the package repository. For Windows, it
might be easiest to extract the binary from Tor Browser Bundle.

* Python 3.4.2 or higher for your operating system.

## Configuration

The provided config files are commented in detail, and intended for testing.
Follow them to write your own config files, but do not use them as-is.

In particular, these provided files contain
matching keys so an `obfs4` clients can authenticate and talk to the server. 
**DO NOT use those keys for your own servers!** For `obfs4`, you *do not* need to
specify keys in the server configuration file. Make sure the states directory is
persistent and writable and after first run, the server will save its keys to the
states directory and read it from there for future runs. It will also write the
appropriate client parameters there, in `obfs4_bridgeline.txt`. The parameters
can then be copied into the client's configuration file.

## Some notes

The reason I'm targetting Python 3.4.2 is that Debian Jessie has that version
in the official repository, and it has `loop.create_task()` so I don't have to
use `asyncio.async()` where `async` is a reserved keyword in Python 3.5 and 
later.

Since communication to the PT executable is now via `asyncio` subprocess pipes,
on Windows the event loop must be a `ProactorEventLoop`, not the default 
`SelectorEventLoop`.

# Ideas for Future Work

Extended ORPort support is still work in progress. Turns out per-connection
bandwidth control and throttling was never implemented in Tor and PTs, so the
only benefit of ExtORPort is that the server script can know where clients are 
connecting from, and potentially refuse connections.
