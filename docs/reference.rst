API Reference
#############


Note: these docs use ``sphinxcontrib_trio`` to autodetect async methods,
however as of version 1.0.1 it doesn't correctly mark inherited async methods
as async; see https://github.com/python-trio/sphinxcontrib-trio/issues/19 .
For the class methods documented below, if the text starts with "(async)", then
it is an async method and should be awaited, even if the call signature line
does not show "await".


The Main ``ptadapter`` Module
=============================

.. automodule:: ptadapter


Adapters
--------

.. autoclass:: ptadapter.ClientAdapter
   :members:
   :inherited-members:

.. autoclass:: ptadapter.ServerAdapter
   :members:
   :inherited-members:

.. autoclass:: ptadapter.ExtServerAdapter
   :members:
   :inherited-members:


Supporting Classes
------------------

.. autoclass:: ptadapter.ClientTransport
   :members:

.. autoclass:: ptadapter.ServerTransport
   :members:

.. autoclass:: ptadapter.ExtOrPortClientConnection
   :members:


``exceptions`` Submodule
========================

.. automodule:: ptadapter.exceptions
   :members:
   :show-inheritance:
   :undoc-members:
