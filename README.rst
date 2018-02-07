aioice
======

|pypi-v| |pypi-pyversions| |pypi-l| |pypi-wheel| |travis| |coveralls|

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
in Python. It is built on top of ```asyncio```, Python's standard asynchronous
I/O framework.

.. code:: python

    #!/usr/bin/env python

    import asyncio
    import aioice

    async def connect_using_ice(uri):
        connection = aioice.Connection(ice_controlling=True)

        # gather local candidates
        local_candidates = await connection.get_local_candidates()

        # send your information to the remote party using your signaling method
        send_local_info(
            local_candidates,
            connection.local_username,
            connection.local_password)

        # receive remote information using your signaling method
        remote_candidates, remote_username, remote_password = get_remote_info()

        # perform ICE handshake
        connection.remote_username = remote_username
        connection.remote_password = remote_password
        connection.set_remote_candidates(remote_candidates)
        await connection.connect()

        # send and receive data
        await connection.send(b'1234')
        data = await connection.recv()

        # close connection
        await connection.close()

    asyncio.get_event_loop().run_until_complete(connect_using_ice())
