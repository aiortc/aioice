API Reference
=============

.. automodule:: aioice

   .. autoclass:: Connection

      .. automethod:: connect()
      .. automethod:: recv()
      .. automethod:: recvfrom()
      .. automethod:: send(bytes)
      .. automethod:: sendto(bytes, component)
      .. automethod:: close()

   .. autoclass:: Candidate

      .. automethod:: __str__()

   .. autofunction:: parse_candidate
