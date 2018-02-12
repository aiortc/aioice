API Reference
=============

.. automodule:: aioice

   .. autoclass:: Connection
      :members: local_candidates, local_username, local_password, remote_candidates, remote_username, remote_password

      .. autocomethod:: get_local_candidates
      .. autocomethod:: connect
      .. autocomethod:: recv
      .. autocomethod:: recvfrom
      .. autocomethod:: send
      .. autocomethod:: sendto
      .. autocomethod:: close

   .. autoclass:: Candidate

      .. automethod:: from_sdp
      .. automethod:: to_sdp
