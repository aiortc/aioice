aioice
======

|rtd| |pypi-v| |pypi-pyversions| |pypi-l| |pypi-wheel| |travis| |coveralls|

.. |rtd| image:: https://readthedocs.org/projects/aioice/badge/?version=latest
   :target: https://aioice.readthedocs.io/

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

.. |coveralls| image:: https://img.shields.io/coveralls/jlaine/aioice.svg
    :target: https://coveralls.io/github/jlaine/aioice

What is ``aioice``?
-------------------

``aioice`` is a library for Interactive Connectivity Establishment (RFC 5245)
in Python. It is built on top of ``asyncio``, Python's standard asynchronous
I/O framework.

Interactive Connectivity Establishment (ICE) is useful for applications that
establish peer-to-peer UDP data streams, as it facilitates NAT traversal.
Typical usecases include SIP and WebRTC.

To learn more about ``aioice`` please `read the documentation`_.

.. _read the documentation: https://aioice.readthedocs.io/en/stable/

Example
-------

.. code:: python

    #!/usr/bin/env python

    import asyncio
    import aioice

    async def connect_using_ice():
        connection = aioice.Connection(ice_controlling=True)

        # gather local candidates
        await connection.gather_candidates()

        # send your information to the remote party using your signaling method
        send_local_info(
            connection.local_candidates,
            connection.local_username,
            connection.local_password)

        # receive remote information using your signaling method
        remote_candidates, remote_username, remote_password = get_remote_info()

        # perform ICE handshake
        connection.remote_candidates = remote_candidates
        connection.remote_username = remote_username
        connection.remote_password = remote_password
        await connection.connect()

        # send and receive data
        await connection.sendto(b'1234', 1)
        data, component = await connection.recvfrom()

        # close connection
        await connection.close()

    asyncio.get_event_loop().run_until_complete(connect_using_ice())

License
-------

``aioice`` is released under the `BSD license`_.

.. _BSD license: https://aioice.readthedocs.io/en/stable/license.html
