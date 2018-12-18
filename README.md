# ptadapter

`ptadapter` is a Python 3
package that interfaces with Pluggable Transports.

Pluggable Transports (PT) are originally created for [Tor] as a modular,
interchangeable (pluggable) method of tunneling and obfuscating
network traffic (transport). This design makes PTs useful not only for
Tor, but many other use cases where traffic obfuscation is desired.
Learn more about Pluggable Transports at the dedicated website,
https://www.pluggabletransports.info/

[Tor]: https://torproject.org/

This package implements Version 1 of the Pluggable Transport
specifications (relevant specs can be found in the `specifications`
directory). Version 2 of the specs is in development: refer to the
website linked above for progress.

(This package also implements Tor's Extended ORPort protocol, which
can be optionally used to receive server connections from PTs.)

**This package REQUIRES Python 3.7 or higher.** It has no 3rd-party
dependencies.

## What's Included

This package implements several Python classes that execute and
communicate with a PT subprocess, allowing connections to be made
through the PT as a client, or received as a server.
The code is built on top of `asyncio`, and uses the familiar
`StreamReader` and `StreamWriter` for connections.

Also included is a ready-made tool that can run PTs as a standalone
tunnel. No coding is necessary to use this.

## What's Required

* Python 3.7 or above.
* The Pluggable Transport to be used, as an executable program. This
  may be installed from the repository, built from source, extracted
  from the Tor Browser Bundle, etc.

## How to get this package

This package is now uploaded to PyPI, so install it the usual way:

    pip install ptadapter

If you don't want to install, you could also
clone this repository or download a source package, and put the
`ptadapter` directory in the working directory or somewhere in your
PYTHONPATH.

## How to use PTs in you own Python program

Start with the [Documentation]. Currently the docs are hosted on
Github Pages and updated manually. When Read The Docs supports building
docs with Python 3.7, the docs will be moved there.

[Documentation]: https://twisteroidambassador.github.io/ptadapter-docs/

## How to create a standalone PT tunnel

If the package is installed via `pip`, an entry script called
`ptadapter` is created, so run the command below to see usage:

    ptadapter --help

Otherwise, run:

    python -m ptadapter --help

A configuration file should be provided to the script.
The [Documentation] contains a detailed guide page, which includes
an example config file with detailed comments; the example config file
can also be found in this repository.
