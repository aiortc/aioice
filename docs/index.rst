aioice
======

|pypi-v| |pypi-pyversions| |pypi-l| |pypi-wheel| |travis| |codecov|

.. |pypi-v| image:: https://img.shields.io/pypi/v/aioice.svg
    :target: https://pypi.python.org/pypi/aioice

.. |pypi-pyversions| image:: https://img.shields.io/pypi/pyversions/aioice.svg
    :target: https://pypi.python.org/pypi/aioice

.. |pypi-l| image:: https://img.shields.io/pypi/l/aioice.svg
    :target: https://pypi.python.org/pypi/aioice

.. |pypi-wheel| image:: https://img.shields.io/pypi/wheel/aioice.svg
    :target: https://pypi.python.org/pypi/aioice

.. |travis| image:: https://img.shields.io/travis/jlaine/aioice.svg
    :target: https://travis-ci.org/jlaine/aioice

.. |codecov| image:: https://img.shields.io/codecov/c/github/jlaine/aioice.svg
    :target: https://codecov.io/gh/jlaine/aioice

``aioice`` is a library for Interactive Connectivity Establishment (RFC 5245)
in Python. It is built on top of :mod:`asyncio`, Python's standard asynchronous
I/O framework.

Interactive Connectivity Establishment (ICE) is useful for applications that
establish peer-to-peer UDP data streams, as it facilitates NAT traversal.
Typical usecases include SIP and WebRTC.

.. toctree::
   :maxdepth: 2

   api
   license
