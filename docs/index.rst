.. ptadapter documentation master file, created by
   sphinx-quickstart on Thu Nov  8 14:01:03 2018.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to ptadapter's documentation!
=====================================

Project home page: https://github.com/twisteroidambassador/ptadapter

For how to use ptadapter to build a standalone Pluggable Transcript tunnel,
check out the :doc:`console_script`.

For how to use Pluggable Transports in your Python program, check out the
:doc:`dev`.


Requirements
============

ptadapter requires Python 3.7 or above. No 3rd-party dependencies.

To actually use a Pluggable Transport, an executable file of the PT appropriate
for the operating system is required. These can often be installed from
a repository on Linux, or extracted from the Tor Browser Bundle.


Installation (or not)
=====================

ptadapter can be installed through ``pip`` and PyPI as usual:

.. code-block:: console

   $ pip install ptadapter

It can also be used without installing. Just download the source code and put
the ``ptadapter`` directory in the current directory, or anywhere in your
``PYTHONPATH``.


.. toctree::
   :maxdepth: 2
   :caption: Contents:

   console_script
   dev
   reference



Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
