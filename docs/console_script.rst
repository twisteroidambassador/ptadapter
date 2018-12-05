Console Script Guide
####################


Invocation
==========

If ptadapter is installed via ``pip``, simply run it by name:

.. code-block:: console

   $ ptadapter

Otherwise, ensure the ``ptadapter`` directory is in the working directory or
somewhere else in ``PYTHONPATH``, and run:

.. code-block:: console

   $ python -m ptadapter

(All examples below will use the first format. Add ``python -m`` to the command
line yourself where appropriate.)

Running ptadapter without command line arguments will print a brief usage
message and an error. To see an explanation of the available command line
arguments, run:

.. code-block:: console

   $ ptadapter --help

In most cases, the command line arguments required are pretty simple.
To create the server end of an obfuscated tunnel, run:

.. code-block:: console

   $ ptadapter -S <config-file>

And to create the client end, run:

.. code-block:: console

   $ ptadapter -C <config-file>

But then, what should the config file look like?


Config file
===========

Config files for ptadapter are written in the familiar INI format. For the
client side, a ``[client]`` section is required, while for the server side
a ``[server]`` section is required. In these sections, basic configuration
options about the PT are specified, as well as a list of section names, where
each of the named section describes a single transport to be used.

Below is an example config file. Please read the comments before writing
your own config file, and do not copy the file wholesale.

.. literalinclude:: ../example_config.ini
   :language: ini

To reiterate, do not copy the server and client options in the example config
file and use it in your own production server!
