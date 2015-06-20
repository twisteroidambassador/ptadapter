# pluggabletransportadapter
A python script that talks to Tor pluggable transports. Use them as standalone TCP tunnels or integrate them into your project.

## Requirements and dependencies
This script is written in a Python 3.4 environment, without paying particular attention to Python 2 or earlier 3.x compatibility.

This script depends on [`rsocks`](https://pypi.python.org/pypi/rsocks/0.2.2) only for the TCP client part.

## Motivation
The motivation for this project comes from the desire of running [`obfs4proxy`](https://github.com/Yawning/obfs4/tree/master/obfs4proxy) independently of Tor. `obfs4proxy` [does not have a standalone mode](https://lists.torproject.org/pipermail/tor-relays/2014-September/005372.html), so I implemented enough of [Tor's pluggable transport specification](https://gitweb.torproject.org/torspec.git/tree/pt-spec.txt "pt-spec.txt") to support standalone operation as server or client, in a way that's hopefully reusable for other projects.

## Using the script
To run a pluggable transport stanalone with this script, you need the following ingredients:

* A working Python environment
* This script
* An executable binary of your pluggable transport
* A configuration file

The config file should be written in JSON. Check the included example.

This script supports running several PT executables in both server and client roles, each executable may support several transports, and for clients each transport can connect to several different destinations. As a result the config file is pretty deeply nested, so be careful.

### Usage
```
$ python pluggabletransportadapter.py -h
usage: pluggabletransportadapter.py [-h] [-v] [-s SERVER] [-S] [-c CLIENT]
                                    [-C]
                                    configfile

Run a Tor pluggable transport (PT) as a standalone TCP tunnel.

positional arguments:
  configfile            Configuration file. See the example config file for
                        details.

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         Set log level to DEBUG.
  -s SERVER, --server SERVER
                        Server PTs to enable.
  -S, --all-servers     Enable all server PTs.
  -c CLIENT, --client CLIENT
                        Client PTs to enable.
  -C, --all-clients     Enable all client PTs.

If no -S, -s, -C or -c arguments are specified, all servers and clients
present in the config file are enabled.
```

To test the setup, put a binary for `obfs4proxy` in the current directory and run `python pluggabletransportadapter.py config-example.json`. Listen on TCP port 7000 (with netcat, socat, etc.) and connect to localhost:8000/8001/8002, and you should be able to talk back and forth.

## Integrating with your own project
Cut out the classes you need and paste them somewhere in your project. One day I may make this into a Python module, but not today. ;-)

It's probably a good idea to talk directly to PT client in SOCKS4/5, instead of using `rsocks` as the middleman TCP-to-SOCKS reverse proxy. `rsocks` pulls in quite a few dependencies.
