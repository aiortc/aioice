API Reference
=============

.. automodule:: aioice

   .. autoclass:: Connection
      :members: local_candidates, local_username, local_password, remote_candidates, remote_username, remote_password

      .. automethod:: get_local_candidates()
      .. automethod:: connect()
      .. automethod:: recv()
      .. automethod:: recvfrom()
      .. automethod:: send(bytes)
      .. automethod:: sendto(bytes, component)
      .. automethod:: close()

   .. autoclass:: Candidate

      .. automethod:: __str__()

   .. autofunction:: parse_candidate
